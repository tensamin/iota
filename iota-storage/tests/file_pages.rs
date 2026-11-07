use iota_identity::relay_protocol::files::{
    ChangesPage, Folder, ListPage, MAX_CONTROL_BYTES, MAX_METADATA_BYTES, PAGE_SIZE,
};
use iota_storage::util::{db, files};

#[test]
fn large_encrypted_file_metadata_pages_fit_the_wire_budget_without_skipping_rows() {
    let directory = tempfile::tempdir().unwrap();
    iota_util::file_util::configure_storage_directory(directory.path().into());
    db::initialize_database().unwrap();
    let authority = format!("omega-key:{}", "a".repeat(64));
    db::with_immediate_transaction(|tx| {
        tx.execute("INSERT INTO principals(principal_pk,authority_kind,authority_id,remote_user_id,descriptor_revision,last_resolved_at) VALUES(101,'omega',?1,42,1,0)", [&authority])?;
        tx.execute("INSERT INTO users(user_id,username,public_key,created_at) VALUES(7,'files-owner','fixture-key',0)", [])?;
        tx.execute("INSERT INTO hosted_principals(local_user_id,principal_handle) VALUES(7,101)", [])?;
        tx.execute("INSERT INTO hosted_auth_state(local_user_id,generation,enabled) VALUES(7,1,1) ON CONFLICT(local_user_id) DO NOTHING", [])?;
        Ok(())
    }).unwrap();
    for index in 0..70 {
        files::folder_put(
            7,
            &Folder {
                folder_id: format!("folder-{index}"),
                parent_folder_id: "private".into(),
                encrypted_name: vec![255; MAX_METADATA_BYTES],
                revision: 1,
            },
        )
        .unwrap();
    }
    let mut after = 0;
    let mut seen = Vec::new();
    loop {
        let page = files::list_page(
            7,
            &ListPage {
                namespace: "folders".into(),
                folder_id: "private".into(),
                after,
                origin: None,
            },
        )
        .unwrap();
        assert!(serde_json::to_vec(&page).unwrap().len() <= MAX_CONTROL_BYTES);
        let items = page["items"].as_array().unwrap();
        assert!(!items.is_empty() && items.len() <= PAGE_SIZE);
        seen.extend(
            items
                .iter()
                .map(|item| item["folder_id"].as_str().unwrap().to_owned()),
        );
        let Some(next) = page["next"].as_i64() else {
            break;
        };
        assert!(next > after);
        after = next;
    }
    assert_eq!(
        seen,
        (0..70)
            .map(|index| format!("folder-{index}"))
            .collect::<Vec<_>>()
    );
    after = 0;
    let mut upper = None;
    let mut events = 0;
    loop {
        let page = files::changes(7, &ChangesPage { after, upper }).unwrap();
        assert!(serde_json::to_vec(&page).unwrap().len() <= MAX_CONTROL_BYTES);
        let returned_upper = page["upper"].as_i64().unwrap();
        assert!(upper.is_none_or(|upper| upper == returned_upper));
        upper = Some(returned_upper);
        let items = page["events"].as_array().unwrap();
        assert!(items.len() <= PAGE_SIZE);
        for item in items {
            let sequence = item["sequence"].as_i64().unwrap();
            assert!(sequence > after && sequence <= returned_upper);
            after = sequence;
        }
        events += items.len();
        let next = page["next"].as_i64().unwrap();
        if !page["more"].as_bool().unwrap() {
            assert_eq!(next, returned_upper);
            break;
        }
        assert!(!items.is_empty());
        assert_eq!(next, after);
    }
    assert_eq!(events, 70);
}
