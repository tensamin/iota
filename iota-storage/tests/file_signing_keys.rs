use iota_identity::{
    LocalDescriptorPublisher, LocalNodeIdentity, LocalUserId, PrincipalId, PrincipalStore,
    file_signing_key_id,
};
use iota_storage::{
    identity::{SqliteLocalDescriptorPublisher, SqlitePrincipalStore},
    users::{user_manager, user_profile::UserProfile},
    util::{db, sync::now_millis},
};
use mtp::crypto::Keyring;

#[test]
fn historical_file_keys_remain_verifiable_but_never_reenter_current_signing_keys() {
    let directory = tempfile::tempdir().unwrap();
    iota_util::file_util::configure_storage_directory(directory.path().into());
    db::initialize_database().unwrap();
    let identity = LocalNodeIdentity::from_keyring(Keyring::generate()).unwrap();
    let publisher = SqliteLocalDescriptorPublisher::new(identity.clone());
    let old = Keyring::generate();
    let current = Keyring::generate();
    let mut user = UserProfile::new(
        42,
        "alice".into(),
        None,
        old.public_key_bundle().try_to_base64().unwrap(),
        None,
        None,
    );
    user_manager::try_add_user(user.clone()).unwrap();
    assert_eq!(
        publisher
            .principal_descriptor(LocalUserId(42))
            .unwrap()
            .descriptor
            .revision,
        1
    );
    let principal = PrincipalId {
        authority: identity.authority_id().clone(),
        user_id: 42,
    };
    let old_id = file_signing_key_id(&old.public_key_bundle()).unwrap();
    user.public_key = current.public_key_bundle().try_to_base64().unwrap();
    user_manager::update_user(user).unwrap();
    publisher.principal_descriptor(LocalUserId(42)).unwrap();
    let proof = publisher
        .file_signing_key(LocalUserId(42), &old_id)
        .unwrap();
    assert_eq!(
        proof
            .verify_file_key(&principal, &old_id)
            .unwrap()
            .try_as_bytes()
            .unwrap(),
        old.public_key_bundle().try_as_bytes().unwrap()
    );
    let keys = SqlitePrincipalStore.signing_keys(&principal).unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(
        keys[0].try_as_bytes().unwrap(),
        current.public_key_bundle().try_as_bytes().unwrap()
    );
    assert!(
        publisher
            .file_signing_key(LocalUserId(43), &old_id)
            .is_err()
    );
    assert!(
        publisher
            .file_signing_key(LocalUserId(42), &"F".repeat(64))
            .is_err()
    );
    let another = SqliteLocalDescriptorPublisher::new(
        LocalNodeIdentity::from_keyring(Keyring::generate()).unwrap(),
    );
    assert!(another.file_signing_key(LocalUserId(42), &old_id).is_err());
    db::with_db(|conn| {
        let mut statement = conn.prepare("EXPLAIN QUERY PLAN SELECT k.public_key FROM principal_keys k JOIN principals p ON p.principal_pk=k.principal_pk WHERE p.authority_id=?1 AND p.remote_user_id=42 AND p.authority_kind='iota' AND k.key_id=?2")?;
        let plan = statement.query_map(rusqlite::params![principal.authority.as_str(),old_id], |row|row.get::<_,String>(3))?.collect::<Result<Vec<_>,_>>()?;
        assert!(plan.iter().any(|row|row.contains("principal_file_signing_key")), "{plan:?}");
        Ok(())
    }).unwrap();
    SqlitePrincipalStore
        .retire_local_principal(LocalUserId(42), now_millis())
        .unwrap();
    assert!(SqlitePrincipalStore.signing_keys(&principal).is_err());
    publisher
        .file_signing_key(LocalUserId(42), &old_id)
        .unwrap()
        .verify_file_key(&principal, &old_id)
        .unwrap();
}
