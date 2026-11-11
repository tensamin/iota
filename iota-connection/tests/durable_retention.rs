use iota_connection::message_handlers::{handle_account_state_request, handle_message_get};
use iota_storage::util::{chat_files, db, message_storage_policy, sync};
use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataValue};
use tau::sync::{Cursor, Request, Response};

fn exchange(request: Request) -> Response {
    let frame = tau::sync::encode_request(&request, &mtp::codec::TypeMap::latest(), 9)
        .unwrap()
        .with_sender(7);
    tau::sync::decode_response(&handle_account_state_request(&frame), &frame).unwrap()
}

#[test]
fn only_durable_exact_versions_are_pruned_and_pruning_does_not_delete_the_client_copy() {
    let directory =
        std::env::temp_dir().join(format!("durable-retention-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&directory).unwrap();
    iota_util::file_util::configure_storage_directory(directory.clone());
    db::initialize_database().unwrap();
    let authority = format!("omega-key:{}", "a".repeat(64));
    db::with_immediate_transaction(|tx| {
        tx.execute("INSERT INTO principals(principal_pk,authority_kind,authority_id,remote_user_id,descriptor_revision,last_resolved_at) VALUES(101,'omega',?1,42,1,0),(102,'omega',?1,43,1,0)", [&authority])?;
        tx.execute("INSERT INTO users(user_id,username,public_key,created_at) VALUES(7,'owner','fixture',0)", [])?;
        tx.execute("INSERT INTO hosted_principals(local_user_id,principal_handle) VALUES(7,101)", [])?;
        tx.execute("INSERT INTO hosted_auth_state(local_user_id,generation,enabled) VALUES(7,1,1) ON CONFLICT(local_user_id) DO NOTHING", [])?;
        tx.execute("INSERT INTO contacts(storage_owner,user_id,principal_handle,created_at,last_message_at) VALUES(7,8,102,0,20)", [])?;
        for (id, time, relay, signer, own) in [(1,10,"first",102,0), (2,20,"second",102,0), (3,30,"third",101,1)] {
            tx.execute("INSERT INTO messages(id,storage_owner,external_user,external_principal,relay_signer_principal,relay_message_id,message_time,content,sent_by_self,message_state,key_version,stored_at) VALUES(?1,7,8,102,?4,?3,?2,'AQ==',?5,'received',1,0)", rusqlite::params![id,time,relay,signer,own])?;
            sync::record_event(tx, 7, sync::EntityType::Message, id, sync::Operation::Upsert)?;
        }
        Ok(())
    }).unwrap();
    message_storage_policy::set(
        7,
        message_storage_policy::MessageHistoryMode::DeleteAfterClientDelivery,
        message_storage_policy::MessageRetention::Forever,
    )
    .unwrap();
    let Response::Scope { scope } = exchange(Request::Discover {
        device_id: "renderer".into(),
        dictionary: tau::relay_protocol::dictionary_fingerprint("1.3").unwrap(),
    }) else {
        panic!("Expected authenticated scope");
    };
    let Response::Snapshot {
        head,
        page_id,
        next: None,
        records,
        ..
    } = exchange(Request::Snapshot {
        scope: scope.clone(),
        page: None,
        limit: 128,
    })
    else {
        panic!("Expected complete snapshot");
    };
    assert_eq!(
        records
            .iter()
            .filter(|record| record.entity == tau::sync::Entity::Message)
            .count(),
        3
    );
    let retained = |id| {
        db::with_db(|conn| {
            Ok(conn.query_row(
                "SELECT content,history_deleted,delivery_pruned FROM messages WHERE id=?1",
                [id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, bool>(1)?,
                        row.get::<_, bool>(2)?,
                    ))
                },
            )?)
        })
        .unwrap()
    };
    assert_eq!(
        retained(1),
        ("AQ==".into(), false, false),
        "Issuing a page is not durable application acknowledgement"
    );
    chat_files::apply_remote_edit_for_principal(
        7,
        8,
        iota_identity::PrincipalHandle(102),
        20,
        8,
        "Ag==",
    )
    .unwrap();
    let changed_head = sync::head(7).unwrap();
    let cursor = Cursor {
        scope: scope.clone(),
        sequence: head,
    };
    assert!(matches!(
        exchange(Request::Acknowledge {
            cursor: cursor.clone(),
            page_id: page_id.clone()
        }),
        Response::Acknowledged { .. }
    ));
    assert_eq!(retained(1), (String::new(), true, true));
    assert_eq!(
        retained(2),
        ("Ag==".into(), false, false),
        "An edit newer than the saved page must survive"
    );
    assert_eq!(
        sync::head(7).unwrap(),
        changed_head,
        "Pruning is not an application deletion event"
    );
    let lookup = CommunicationValue::new(CommunicationType::MessageGet)
        .with_sender(7)
        .add_typed_default(
            DataType::Principal,
            DataValue::Str(
                serde_json::to_string(
                    &tau::relay_protocol::Principal::new(authority.clone(), 43).unwrap(),
                )
                .unwrap(),
            ),
        )
        .add_typed_default(DataType::RelayMessageId, DataValue::Str("first".into()));
    assert_eq!(
        handle_message_get(&lookup).get_str(DataType::Status),
        Some("pruned")
    );
    chat_files::apply_remote_edit_for_principal(
        7,
        8,
        iota_identity::PrincipalHandle(102),
        10,
        8,
        "Aw==",
    )
    .unwrap();
    assert_eq!(
        retained(1),
        ("Aw==".into(), false, false),
        "A valid edit restores the current body after delivery pruning"
    );
    assert!(matches!(
        exchange(Request::Acknowledge {
            cursor: cursor.clone(),
            page_id
        }),
        Response::Acknowledged { .. }
    ));
    assert_eq!(
        retained(1).0,
        "Aw==",
        "Replaying an old acknowledgement must not prune the new edit"
    );
    let Response::Delta {
        head: next_head,
        page_id,
        next: None,
        ..
    } = exchange(Request::Delta {
        after: cursor,
        page: None,
        limit: 128,
    })
    else {
        panic!("Expected bounded delta");
    };
    assert!(matches!(
        exchange(Request::Acknowledge {
            cursor: Cursor {
                scope: scope.clone(),
                sequence: next_head
            },
            page_id
        }),
        Response::Acknowledged { .. }
    ));
    assert_eq!(retained(1), (String::new(), true, true));
    assert_eq!(retained(2), (String::new(), true, true));
    assert_eq!(retained(3), (String::new(), true, true));
    let receipt = chat_files::record_message_receipt(
        7,
        7,
        iota_identity::PrincipalHandle(101),
        "third",
        8,
        iota_identity::PrincipalHandle(102),
        "read-third",
        chat_files::MessageState::Read,
        1000,
        2000,
    )
    .unwrap();
    assert!(
        receipt.is_some(),
        "Delivery pruning must preserve later read receipts"
    );
    chat_files::add_reaction_for_principal(
        7,
        8,
        iota_identity::PrincipalHandle(102),
        10,
        8,
        iota_identity::PrincipalHandle(102),
        "like",
    )
    .unwrap();
    let Response::Delta {
        head: metadata_head,
        events,
        ..
    } = exchange(Request::Delta {
        after: Cursor {
            scope: scope.clone(),
            sequence: next_head,
        },
        page: None,
        limit: 128,
    })
    else {
        panic!("Expected metadata update");
    };
    let record = events
        .iter()
        .filter_map(|event| event.record.as_ref())
        .find(|record| record.entity == tau::sync::Entity::Message && record.key == "3")
        .unwrap();
    assert_eq!(record.value["delivery_pruned"], "1");
    assert_eq!(record.value["message_state"], "read");
    assert!(record.value.get("content").is_none());
    let reacted = events
        .iter()
        .filter_map(|event| event.record.as_ref())
        .find(|record| record.entity == tau::sync::Entity::Message && record.key == "1")
        .unwrap();
    assert_eq!(reacted.value["reactions"][0]["reaction"], "like");
    assert!(reacted.value.get("content").is_none());
    chat_files::remove_reaction_for_principal(
        7,
        8,
        iota_identity::PrincipalHandle(102),
        10,
        8,
        iota_identity::PrincipalHandle(102),
        "like",
    )
    .unwrap();
    let Response::Delta { events, .. } = exchange(Request::Delta {
        after: Cursor {
            scope: scope.clone(),
            sequence: metadata_head,
        },
        page: None,
        limit: 128,
    }) else {
        panic!("Expected reaction removal update");
    };
    assert_eq!(
        events
            .iter()
            .filter_map(|event| event.record.as_ref())
            .find(|record| record.key == "1")
            .unwrap()
            .value["reactions"],
        serde_json::json!([])
    );
    chat_files::apply_remote_delete_for_principal(7, 8, iota_identity::PrincipalHandle(102), 10, 8)
        .unwrap();
    assert!(handle_message_get(&lookup).is_type(CommunicationType::ErrorNotFound));
    assert_eq!(
        db::with_db(|conn| Ok(conn.query_row(
            "SELECT last_message_at FROM contacts WHERE storage_owner=7 AND principal_handle=102",
            [],
            |row| row.get::<_, Option<i64>>(0)
        )?))
        .unwrap(),
        Some(30),
        "Deleting a message must still count newer delivery-pruned messages in the conversation"
    );
    let deleted_head = sync::head(7).unwrap();
    chat_files::add_reaction_for_principal(
        7,
        8,
        iota_identity::PrincipalHandle(102),
        10,
        8,
        iota_identity::PrincipalHandle(102),
        "like",
    )
    .unwrap();
    chat_files::remove_reaction_for_principal(
        7,
        8,
        iota_identity::PrincipalHandle(102),
        10,
        8,
        iota_identity::PrincipalHandle(102),
        "like",
    )
    .unwrap();
    assert!(
        chat_files::record_message_receipt(
            7,
            8,
            iota_identity::PrincipalHandle(102),
            "first",
            8,
            iota_identity::PrincipalHandle(102),
            "deleted-read",
            chat_files::MessageState::Read,
            1000,
            2000
        )
        .unwrap()
        .is_none()
    );
    assert_eq!(
        sync::head(7).unwrap(),
        deleted_head,
        "Explicitly deleted rows must not resume emitting metadata updates"
    );
    message_storage_policy::set(
        7,
        message_storage_policy::MessageHistoryMode::DeleteAfterClientDelivery,
        message_storage_policy::MessageRetention::Duration {
            duration_ms: 60_000,
        },
    )
    .unwrap();
    iota_storage::util::message_retention::purge_expired_messages(60_001).unwrap();
    assert!(
        chat_files::get_message_by_relay(7, iota_identity::PrincipalHandle(102), "second")
            .unwrap()
            .is_none(),
        "Explicit expiry still removes the retained copy through its deletion event"
    );
    db::with_immediate_transaction(|tx| {
        tx.execute("INSERT INTO messages(id,storage_owner,external_user,external_principal,relay_signer_principal,relay_message_id,message_time,content,sent_by_self,message_state,key_version,stored_at) VALUES(4,7,8,102,102,'compacted',40,'BA==',0,'received',1,0)", [])?;
        sync::record_event(tx, 7, sync::EntityType::Message, 4, sync::Operation::Upsert)?;
        Ok(())
    }).unwrap();
    let Response::Snapshot {
        head: old_head,
        page_id: old_page,
        next: None,
        ..
    } = exchange(Request::Snapshot {
        scope: scope.clone(),
        page: None,
        limit: 128,
    })
    else {
        panic!("Expected pre-edit snapshot");
    };
    chat_files::apply_remote_edit_for_principal(
        7,
        8,
        iota_identity::PrincipalHandle(102),
        40,
        8,
        "BQ==",
    )
    .unwrap();
    db::with_immediate_transaction(|tx| {
        tx.execute(
            "UPDATE client_device_sync_state SET updated_at=0 WHERE user_id=7",
            [],
        )?;
        Ok(())
    })
    .unwrap();
    assert!(sync::compact_user_sync_state(7).unwrap().removed_events > 0);
    assert!(
        db::with_db(|conn| Ok(conn.query_row(
            "SELECT sequence FROM account_sync_floors WHERE user_id=7",
            [],
            |row| row.get::<_, i64>(0)
        )?))
        .unwrap()
            > old_head
    );
    assert!(matches!(
        exchange(Request::Acknowledge {
            cursor: Cursor {
                scope: scope.clone(),
                sequence: old_head
            },
            page_id: old_page
        }),
        Response::Acknowledged { .. }
    ));
    assert_eq!(
        retained(4),
        ("BQ==".into(), false, false),
        "An old acknowledgement cannot prune an edit whose event was compacted"
    );
    let Response::Snapshot {
        head,
        page_id,
        next: None,
        ..
    } = exchange(Request::Snapshot {
        scope: scope.clone(),
        page: None,
        limit: 128,
    })
    else {
        panic!("Expected current snapshot");
    };
    assert!(matches!(
        exchange(Request::Acknowledge {
            cursor: Cursor {
                scope,
                sequence: head
            },
            page_id
        }),
        Response::Acknowledged { .. }
    ));
    assert_eq!(
        retained(4),
        (String::new(), true, true),
        "Pruning resumes once the actual current body has been applied"
    );
    std::fs::remove_dir_all(directory).unwrap();
}
