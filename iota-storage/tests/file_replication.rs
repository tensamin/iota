use iota_identity::relay_protocol::{Principal, canonical_chat_id, files::REPLICA_CHUNK_BYTES};
use iota_storage::util::{db, files::replication, sync, user_assets};
use rusqlite::params;
use std::cell::Cell;

#[test]
fn local_jobs_are_selected_before_the_page_limit_and_share_cancellable_bounded_copy() {
    let directory = tempfile::tempdir().unwrap();
    iota_util::file_util::configure_storage_directory(directory.path().into());
    db::initialize_database().unwrap();
    let recipient = Principal::new(format!("omega-key:{}", "a".repeat(64)), 42).unwrap();
    let author = Principal::new(format!("omega-key:{}", "b".repeat(64)), 73).unwrap();
    let chat = canonical_chat_id(&author, &recipient);
    let local = format!("iota:v1:{}", "c".repeat(64));
    let remote = format!("iota:v1:{}", "d".repeat(64));
    db::with_immediate_transaction(|tx| {
        for (user, handle, principal) in [(7, 101, &recipient), (8, 102, &author)] {
            tx.execute("INSERT INTO principals(principal_pk,authority_kind,authority_id,remote_user_id,descriptor_revision,last_resolved_at) VALUES(?1,'omega',?2,?3,1,0)", params![handle,principal.authority,i64::try_from(principal.user_id).unwrap()])?;
            tx.execute("INSERT INTO users(user_id,username,public_key,created_at) VALUES(?1,?2,'fixture-key',0)", params![user,format!("files-{user}")])?;
            tx.execute("INSERT INTO hosted_principals(local_user_id,principal_handle) VALUES(?1,?2)", params![user,handle])?;
            tx.execute("INSERT INTO hosted_auth_state(local_user_id,generation,enabled) VALUES(?1,1,1) ON CONFLICT(local_user_id) DO NOTHING", [user])?;
        }
        Ok(())
    }).unwrap();

    let bytes = vec![88; 68 * 65576];
    let hash = mtp::crypto::sha256(&bytes);
    let source_upload = uuid::Uuid::new_v4().to_string();
    let source_asset = uuid::Uuid::new_v4().to_string();
    user_assets::start(
        8,
        &source_upload,
        &source_asset,
        bytes.len() as i64,
        &hash,
        "application/octet-stream",
    )
    .unwrap();
    for (index, chunk) in bytes.chunks(REPLICA_CHUNK_BYTES).enumerate() {
        user_assets::append(
            8,
            &source_upload,
            (index * REPLICA_CHUNK_BYTES) as i64,
            chunk,
        )
        .unwrap();
    }
    user_assets::commit(8, &source_upload).unwrap();
    db::with_immediate_transaction(|tx| {
        for index in 0..9 {
            let manifest = serde_json::json!({
                "key":{"origin":author,"file_id":format!("file-{index}"),"version":1},
                "ciphertext_sha256":hash,"ciphertext_size":bytes.len(),"crypto_format":"tensamin-file-chunks-v1",
                "manifest_ciphertext":vec![1;41],"envelope":{"recipient":recipient,"key_id":"recipient-key",
                    "wrapping_scheme":"tensamin-file-dek-kem-v1","kem_ciphertext":[1],"encrypted_dek":vec![1;72]},
            }).to_string();
            tx.execute("INSERT INTO file_versions(id,storage_user_id,origin_principal,file_id,version,manifest,state) VALUES(?1,7,102,?2,1,?3,'transferring')", params![index+1,format!("file-{index}"),manifest])?;
            tx.execute("INSERT INTO file_replication_jobs(version_id,upload_id,asset_id) VALUES(?1,?2,?3)", params![index+1,uuid::Uuid::new_v4().to_string(),uuid::Uuid::new_v4().to_string()])?;
            tx.execute("INSERT INTO file_share_grants(storage_user_id,origin_principal,file_id,version,recipient_principal,chat_id,revision,state,expires_at,manifest,source_node) VALUES(7,102,?1,1,101,?2,1,'accepted',?3,?4,?5)", params![format!("file-{index}"),chat,sync::now_millis()+3_600_000,manifest,if index==8 {&local} else {&remote}])?;
            if index == 8 {
                tx.execute("INSERT INTO file_versions(id,storage_user_id,origin_principal,file_id,version,manifest,asset_id,state) VALUES(100,8,102,'file-8',1,?1,?2,'ready')", params![manifest,source_asset])?;
                tx.execute("INSERT INTO file_share_grants(storage_user_id,origin_principal,file_id,version,recipient_principal,chat_id,revision,state,expires_at,manifest,source_node) VALUES(8,102,'file-8',1,101,?1,1,'offered',?2,?3,?4)", params![chat,sync::now_millis()+3_600_000,manifest,local])?;
            }
        }
        Ok(())
    }).unwrap();
    assert!(
        replication::jobs(None)
            .unwrap()
            .iter()
            .all(|job| job.source_node == remote)
    );
    for _ in 0..3 {
        let jobs = replication::jobs(Some(&local)).unwrap();
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].id, 9);
    }
    let job = replication::jobs(Some(&local)).unwrap().remove(0);
    let checks = Cell::new(0);
    replication::copy_local_batch(&job, || {
        let count = checks.get();
        checks.set(count + 1);
        count > 0
    })
    .unwrap();
    assert_eq!(
        replication::progress(&job).unwrap(),
        REPLICA_CHUNK_BYTES as i64
    );
    replication::copy_local_batch(&job, || false).unwrap();
    assert_eq!(
        replication::progress(&job).unwrap(),
        (17 * REPLICA_CHUNK_BYTES) as i64
    );
    replication::copy_local_batch(&job, || false).unwrap();
    assert!(replication::jobs(Some(&local)).unwrap().is_empty());
    let manifest = iota_storage::util::files::manifest(7, &job.manifest.key).unwrap();
    assert_eq!(manifest["state"], "ready");
    assert_eq!(manifest["asset_id"], job.asset_id);
    assert_eq!(replication::jobs(None).unwrap().len(), 8);
}
