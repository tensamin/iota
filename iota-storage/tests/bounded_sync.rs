use iota_identity::relay_protocol::{
    self,
    sync::{Cursor, Request, Response, Scope, SyncError},
};
use iota_storage::util::{
    db,
    sync::{self, paged},
};
use rusqlite::params;

#[test]
fn large_accounts_are_read_incrementally_at_a_pinned_boundary() {
    let directory = tempfile::tempdir().unwrap();
    iota_util::file_util::configure_storage_directory(directory.path().into());
    db::initialize_database().unwrap();
    let authority = format!("omega-key:{}", "a".repeat(64));
    db::with_immediate_transaction(|tx| {
        tx.execute("INSERT INTO principals(principal_pk,authority_kind,authority_id,remote_user_id,descriptor_revision,last_resolved_at) VALUES(101,'omega',?1,42,1,0)", [&authority])?;
        tx.execute("INSERT INTO users(user_id,username,public_key,created_at) VALUES(7,'sync-owner','fixture-key',0)", [])?;
        tx.execute("INSERT INTO hosted_principals(local_user_id,principal_handle) VALUES(7,101)", [])?;
        tx.execute("INSERT INTO hosted_auth_state(local_user_id,generation,enabled) VALUES(7,1,1) ON CONFLICT(local_user_id) DO NOTHING", [])?;
        Ok(())
    }).unwrap();
    let payload = "x".repeat(512);
    db::with_db(|connection| {
        let mut statement = connection.prepare("EXPLAIN QUERY PLAN SELECT id FROM synced_settings WHERE user_id=7 AND rowid>100 ORDER BY rowid LIMIT 1")?;
        let plan = statement.query_map([], |row| row.get::<_, String>(3))?.collect::<Result<Vec<_>, _>>()?;
        assert!(plan.iter().any(|step| step.contains("sync_snapshot_synced_settings")), "{plan:?}");
        assert!(!plan.iter().any(|step| step.contains("TEMP B-TREE")), "{plan:?}");
        Ok(())
    }).unwrap();
    // Seed an existing account without constructing an unrelated transaction's
    // notification projection. Mutations below use the normal sync journal.
    db::with_db(|connection| {
        let tx = connection.unchecked_transaction()?;
        {
            let mut insert = tx.prepare("INSERT INTO synced_settings(user_id,scope_type,scope_key,name,payload,revision) VALUES(7,'user','',?1,?2,1)")?;
            for id in 1..=100_001 { insert.execute(params![format!("setting-{id}"),payload])?; }
        }
        tx.commit()?;
        Ok(())
    }).unwrap();
    let scope = Scope {
        principal: relay_protocol::Principal::new(authority, 42).unwrap(),
        device_id: "bounded-sync-device".into(),
        authorization_generation: iota_storage::hosted_auth::resolve(iota_identity::LocalUserId(7))
            .unwrap()
            .0
            .auth_generation,
        schema: relay_protocol::sync::SCHEMA.into(),
        dictionary: relay_protocol::dictionary_fingerprint("1.0").unwrap(),
    };
    let first = paged::execute(
        7,
        &Request::Snapshot {
            scope: scope.clone(),
            page: None,
            limit: 128,
        },
    )
    .unwrap();
    let Response::Snapshot {
        head,
        page_id,
        next,
        records,
        ..
    } = first
    else {
        panic!("snapshot")
    };
    assert!(next.is_some());
    assert_eq!(records.len(), 128);
    let materialized: i64 = db::with_db(|connection| {
        Ok(connection.query_row(
            "SELECT COUNT(*) FROM account_sync_page_items WHERE page_id=?1",
            [&page_id],
            |row| row.get(0),
        )?)
    })
    .unwrap();
    assert_eq!(materialized, 128);
    let cursor = Cursor {
        scope: scope.clone(),
        sequence: head,
    };
    assert!(matches!(
        paged::execute(
            7,
            &Request::Acknowledge {
                cursor: cursor.clone(),
                page_id: page_id.clone()
            }
        )
        .unwrap(),
        Response::Unavailable {
            error: SyncError::SnapshotRequired
        }
    ));
    db::with_immediate_transaction(|tx| {
        tx.execute(
            "UPDATE synced_settings SET payload='changed-after-capture',revision=2 WHERE id=100001",
            [],
        )?;
        tx.execute("DELETE FROM synced_settings WHERE id=90000", [])?;
        sync::record_event(
            tx,
            7,
            sync::EntityType::Setting,
            100001,
            sync::Operation::Upsert,
        )?;
        sync::record_event(
            tx,
            7,
            sync::EntityType::Setting,
            90000,
            sync::Operation::Delete,
        )?;
        Ok(())
    })
    .unwrap();
    let request = Request::Snapshot {
        scope: scope.clone(),
        page: next.clone(),
        limit: 128,
    };
    let replay = paged::execute(7, &request).unwrap();
    assert_eq!(
        serde_json::to_value(&replay).unwrap(),
        serde_json::to_value(paged::execute(7, &request).unwrap()).unwrap()
    );
    let mut count = records.len();
    let mut total_bytes = serde_json::to_vec(&records).unwrap().len();
    let mut next = next;
    while let Some(page) = next {
        let response = paged::execute(
            7,
            &Request::Snapshot {
                scope: scope.clone(),
                page: Some(page),
                limit: 128,
            },
        )
        .unwrap();
        let Response::Snapshot {
            head: boundary,
            records,
            next: following,
            ..
        } = response
        else {
            panic!("snapshot page")
        };
        assert_eq!(boundary, head);
        assert!(records.len() <= 128);
        assert!(serde_json::to_vec(&records).unwrap().len() <= relay_protocol::sync::PAGE_BYTES);
        for record in &records {
            if record.key == "100001" || record.key == "90000" {
                assert_eq!(record.value["payload"], payload);
            }
        }
        count += records.len();
        total_bytes += serde_json::to_vec(&records).unwrap().len();
        next = following;
    }
    assert_eq!(count, 100_001);
    assert!(total_bytes > 32 * 1024 * 1024);
    assert!(matches!(
        paged::execute(
            7,
            &Request::Acknowledge {
                cursor: cursor.clone(),
                page_id
            }
        )
        .unwrap(),
        Response::Acknowledged { .. }
    ));
    let delta = paged::execute(
        7,
        &Request::Delta {
            after: cursor.clone(),
            page: None,
            limit: 1,
        },
    )
    .unwrap();
    let Response::Delta {
        head: delta_head,
        page_id: delta_id,
        next: Some(page),
        events,
        ..
    } = delta
    else {
        panic!("delta page: {delta:?}")
    };
    assert_eq!(events.len(), 1);
    let replay_request = Request::Delta {
        after: cursor,
        page: Some(page),
        limit: 128,
    };
    let tail = paged::execute(7, &replay_request).unwrap();
    assert_eq!(
        serde_json::to_value(&tail).unwrap(),
        serde_json::to_value(paged::execute(7, &replay_request).unwrap()).unwrap()
    );
    let Response::Delta {
        events, next: None, ..
    } = tail
    else {
        panic!("final delta")
    };
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].sequence, delta_head);
    assert!(matches!(
        paged::execute(
            7,
            &Request::Acknowledge {
                cursor: Cursor {
                    scope: scope.clone(),
                    sequence: delta_head
                },
                page_id: delta_id
            }
        )
        .unwrap(),
        Response::Acknowledged { .. }
    ));
    let current = paged::execute(
        7,
        &Request::Snapshot {
            scope: scope.clone(),
            page: None,
            limit: 1,
        },
    )
    .unwrap();
    let Response::Snapshot {
        next: Some(page), ..
    } = current
    else {
        panic!("current snapshot")
    };
    db::with_immediate_transaction(|tx| {
        tx.execute(
            "UPDATE hosted_auth_state SET generation=generation+1 WHERE local_user_id=7",
            [],
        )?;
        Ok(())
    })
    .unwrap();
    assert!(matches!(
        paged::execute(
            7,
            &Request::Snapshot {
                scope,
                page: Some(page),
                limit: 1
            }
        )
        .unwrap(),
        Response::Unavailable {
            error: SyncError::IdentityChanged
        }
    ));
}
