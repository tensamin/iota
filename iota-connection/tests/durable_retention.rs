use iota_connection::message_handlers::{handle_account_state_request, handle_message_get};
use iota_storage::util::{chat_files, db, message_storage_policy, sync};
use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataValue};
use tau::sync::{Cursor, Request, Response};

fn exchange(request: Request) -> Response {
    let frame = CommunicationValue::new(CommunicationType::AccountStateRequest)
        .with_sender(7)
        .with_id(9)
        .add_typed_default(
            DataType::Json,
            DataValue::Bytes(serde_json::to_vec(&request).unwrap()),
        );
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
        for (id, time, relay) in [(1,10,"first"), (2,20,"second")] {
            tx.execute("INSERT INTO messages(id,storage_owner,external_user,external_principal,relay_signer_principal,relay_message_id,message_time,content,sent_by_self,message_state,key_version,stored_at) VALUES(?1,7,8,102,102,?3,?2,'AQ==',0,'received',1,0)", rusqlite::params![id,time,relay])?;
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
        dictionary: tau::relay_protocol::dictionary_fingerprint("1.0").unwrap(),
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
        2
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
    db::with_immediate_transaction(|tx| {
        tx.execute("UPDATE messages SET message_state='read' WHERE id=1", [])?;
        sync::record_event(tx, 7, sync::EntityType::Message, 1, sync::Operation::Upsert)?;
        Ok(())
    })
    .unwrap();
    let Response::Delta { events, .. } = exchange(Request::Delta {
        after: Cursor {
            scope,
            sequence: next_head,
        },
        page: None,
        limit: 128,
    }) else {
        panic!("Expected metadata update");
    };
    let record = events.last().unwrap().record.as_ref().unwrap();
    assert_eq!(record.value["delivery_pruned"], "1");
    assert_eq!(record.value["message_state"], "read");
    assert!(record.value.get("content").is_none());
    chat_files::apply_remote_delete_for_principal(7, 8, iota_identity::PrincipalHandle(102), 10, 8)
        .unwrap();
    assert!(handle_message_get(&lookup).is_type(CommunicationType::ErrorNotFound));
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
    std::fs::remove_dir_all(directory).unwrap();
}
