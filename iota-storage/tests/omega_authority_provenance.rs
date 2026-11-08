use iota_identity::{
    AuthorityDirectory, AuthorityId, AuthorityKind, AuthorityLocator, LocalNodeIdentity,
    PrincipalDescriptor, PrincipalHome, PrincipalId, SignedPrincipalDescriptor,
};
use iota_storage::{
    authority_directory::SqliteAuthorityDirectory, node_directory::SqliteNodeDirectory, util::db,
};
use mtp::crypto::Keyring;

#[test]
fn omega_authority_provenance_is_durable_and_cannot_replace_iota_or_omega_pins() {
    let directory = tempfile::tempdir().unwrap();
    iota_util::file_util::configure_storage_directory(directory.path().to_path_buf());
    db::initialize_database().unwrap();
    let now = 200;
    let node = LocalNodeIdentity::from_keyring(Keyring::generate()).unwrap();
    SqliteNodeDirectory
        .ensure_local_descriptor(&node, vec![], vec![], now)
        .unwrap();
    let node_locator = AuthorityLocator::new("iota.example.org").unwrap();
    let omega_locator = AuthorityLocator::new("omega.example.org").unwrap();
    let omega = Keyring::generate();
    let authority = AuthorityId::for_omega(&omega.public_key_bundle()).unwrap();
    let signed = SignedPrincipalDescriptor::sign(
        PrincipalDescriptor {
            principal: PrincipalId {
                authority: authority.clone(),
                user_id: 7,
            },
            authority_kind: AuthorityKind::Omega,
            username: Some("alice".into()),
            display_name: None,
            public_keys: vec![Keyring::generate().public_key_bundle()],
            home: PrincipalHome::Iota(node.node_id().clone()),
            revision: 1,
            valid_until: Some(1000),
            issued_at: 100,
        },
        &omega,
    )
    .unwrap();
    let verified = signed
        .verify(&authority, &omega.public_key_bundle(), None, now)
        .unwrap();
    let store = SqliteAuthorityDirectory;
    store
        .record_verified_iota(&node_locator, node.authority_id(), node.node_id(), now)
        .unwrap();
    store
        .record_verified_omega(&omega_locator, &verified)
        .unwrap();
    let restored = SqliteAuthorityDirectory;
    assert_eq!(
        restored.locators_for(&authority).unwrap(),
        vec![omega_locator.clone()]
    );
    assert_eq!(
        restored.locators_for(node.authority_id()).unwrap(),
        vec![node_locator.clone()]
    );
    assert!(
        restored
            .record_verified_omega(&node_locator, &verified)
            .is_err()
    );
    assert!(
        restored
            .record_verified_iota(&omega_locator, node.authority_id(), node.node_id(), now)
            .is_err()
    );
    let replacement = Keyring::generate();
    let replacement_authority = AuthorityId::for_omega(&replacement.public_key_bundle()).unwrap();
    let replacement_signed = SignedPrincipalDescriptor::sign(
        PrincipalDescriptor {
            principal: PrincipalId {
                authority: replacement_authority.clone(),
                user_id: 7,
            },
            authority_kind: AuthorityKind::Omega,
            username: Some("alice".into()),
            display_name: None,
            public_keys: verified.descriptor().public_keys.clone(),
            home: verified.descriptor().home.clone(),
            revision: 1,
            valid_until: Some(1000),
            issued_at: 100,
        },
        &replacement,
    )
    .unwrap();
    let replacement = replacement_signed
        .verify(
            &replacement_authority,
            &replacement.public_key_bundle(),
            None,
            now,
        )
        .unwrap();
    assert!(
        restored
            .record_verified_omega(&omega_locator, &replacement)
            .is_err()
    );
    assert_eq!(
        restored.locators_for(&authority).unwrap(),
        vec![omega_locator]
    );
}
