use iota_identity::relay_protocol::{
    self,
    sync::{Request, Response, Scope},
};
use iota_storage::{
    storage_error::StorageError,
    util::{db, sync, user_blobs},
};
use rusqlite::params;

#[test]
fn blob_limits_cas_and_sync_capture_share_the_transaction() {
    let directory = tempfile::tempdir().unwrap();
    iota_util::file_util::configure_storage_directory(directory.path().into());
    db::initialize_database().unwrap();
    let authority = format!("omega-key:{}", "a".repeat(64));
    db::with_immediate_transaction(|tx| {
        tx.execute("INSERT INTO principals(principal_pk,authority_kind,authority_id,remote_user_id,descriptor_revision,last_resolved_at) VALUES(101,'omega',?1,42,1,0)", [&authority])?;
        tx.execute("INSERT INTO users(user_id,username,public_key,created_at) VALUES(7,'blob-owner','fixture-key',0)", [])?;
        tx.execute("INSERT INTO hosted_principals(local_user_id,principal_handle) VALUES(7,101)", [])?;
        tx.execute("INSERT INTO hosted_auth_state(local_user_id,generation,enabled) VALUES(7,1,1) ON CONFLICT(local_user_id) DO NOTHING", [])?;
        Ok(())
    }).unwrap();
    let bytes = vec![0xa5; user_blobs::MAX_BLOB_BYTES];
    let blob = user_blobs::put(7, "large", &bytes, Some(0)).unwrap();
    assert_eq!(user_blobs::get(7, "large").unwrap().unwrap().blob, bytes);
    assert!(
        user_blobs::put(
            7,
            "oversized",
            &vec![0; user_blobs::MAX_BLOB_BYTES + 1],
            Some(0)
        )
        .is_err()
    );
    assert!(user_blobs::get(7, "oversized").unwrap().is_none());
    let scope = Scope {
        principal: relay_protocol::Principal::new(authority, 42).unwrap(),
        device_id: "blob-device".into(),
        authorization_generation: iota_storage::hosted_auth::resolve(iota_identity::LocalUserId(7))
            .unwrap()
            .0
            .auth_generation,
        schema: relay_protocol::sync::SCHEMA.into(),
        dictionary: relay_protocol::dictionary_fingerprint("1.0").unwrap(),
    };
    let response = sync::paged::execute(
        7,
        &Request::Snapshot {
            scope,
            page: None,
            limit: 128,
        },
    )
    .unwrap();
    let Response::Snapshot { records, .. } = response else {
        panic!("expected snapshot")
    };
    let metadata = records
        .iter()
        .find(|record| record.value["blob_id"] == "large")
        .unwrap();
    assert_eq!(
        metadata.value["size"],
        user_blobs::MAX_BLOB_BYTES.to_string()
    );
    assert!(metadata.value.get("blob").is_none());
    assert!(serde_json::to_vec(&records).unwrap().len() < 4096);

    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let workers = [b"first".as_slice(), b"second".as_slice()].map(|value| {
        let barrier = barrier.clone();
        std::thread::spawn(move || {
            barrier.wait();
            user_blobs::put(7, "large", value, Some(blob.revision))
        })
    });
    let results = workers.map(|worker| worker.join().unwrap());
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(StorageError::RevisionConflict)))
            .count(),
        1
    );

    let head = sync::head(7).unwrap();
    let failed: Result<(), StorageError> = db::with_immediate_transaction(|tx| {
        sync::record_event(
            tx,
            7,
            sync::EntityType::UserBlob,
            blob.id,
            sync::Operation::Delete,
        )?;
        tx.execute("UPDATE user_blobs SET deleted=1 WHERE id=?1", [blob.id])?;
        Err(StorageError::Other("deliberate rollback".into()))
    });
    assert!(failed.is_err());
    assert_eq!(sync::head(7).unwrap(), head);
    assert!(user_blobs::get(7, "large").unwrap().is_some());
    let current = user_blobs::get(7, "large").unwrap().unwrap();
    assert!(matches!(
        user_blobs::put(7, "large", &current.blob, Some(blob.revision)),
        Err(StorageError::RevisionConflict)
    ));
    let failed_capture = db::with_immediate_transaction(|tx| {
        tx.execute(
            "UPDATE user_blobs SET blob=?2 WHERE id=?1",
            params![blob.id, b"must roll back".as_slice()],
        )?;
        // An upsert without its source row cannot produce a committed projection.
        sync::record_event(
            tx,
            7,
            sync::EntityType::Message,
            i64::MAX,
            sync::Operation::Upsert,
        )?;
        Ok(())
    });
    assert!(failed_capture.is_err());
    assert_eq!(sync::head(7).unwrap(), head);
    assert_eq!(user_blobs::get(7, "large").unwrap().unwrap(), current);
    user_blobs::put(7, "large", b"after rollback", Some(current.revision)).unwrap();
    db::with_db(|connection| {
        let missing: i64 = connection.query_row(
            "SELECT COUNT(*) FROM sync_events WHERE user_id=?1 AND projection IS NULL",
            params![7],
            |row| row.get(0),
        )?;
        assert_eq!(missing, 0);
        Ok(())
    })
    .unwrap();
}
