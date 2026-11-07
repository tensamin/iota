use base64::{Engine as _, engine::general_purpose::STANDARD};
use iota_identity::{
    AuthorityId, AuthorityKind, FileSigningKeyProofV1, IotaNodeId, PrincipalId, PrincipalProofV1,
};
use mtp::crypto::Keyring;

#[test]
fn file_key_association_is_bound_to_authority_subject_key_and_purpose() {
    let authority = Keyring::generate();
    let user = Keyring::generate();
    let principal = PrincipalId {
        authority: AuthorityId::for_omega(&authority.public_key_bundle()).unwrap(),
        user_id: i64::MAX as u64,
    };
    let key = user.public_key_bundle();
    let proof =
        FileSigningKeyProofV1::sign(principal.clone(), AuthorityKind::Omega, &key, &authority)
            .unwrap();
    assert_eq!(proof.key_id.len(), 64);
    assert_eq!(
        proof
            .verify_file_key(&principal, &proof.key_id)
            .unwrap()
            .try_as_bytes()
            .unwrap(),
        key.try_as_bytes().unwrap()
    );
    assert!(proof.verify_file_key(&principal, &"0".repeat(64)).is_err());
    let mut other = principal.clone();
    other.user_id -= 1;
    assert!(proof.verify_file_key(&other, &proof.key_id).is_err());
    assert!(
        serde_json::from_str::<PrincipalProofV1>(&serde_json::to_string(&proof).unwrap()).is_err()
    );
    for offset in [0, 64] {
        let mut damaged = proof.clone();
        let mut signature = STANDARD.decode(&damaged.authority_signature).unwrap();
        signature[offset] ^= 1;
        damaged.authority_signature = STANDARD.encode(signature);
        assert!(
            damaged
                .verify_file_key(&principal, &damaged.key_id)
                .is_err()
        );
    }
    let mut forged = proof.clone();
    forged.version = 2;
    assert!(forged.verify_file_key(&principal, &forged.key_id).is_err());
    let mut forged = proof.clone();
    forged.principal = other.clone();
    assert!(forged.verify_file_key(&other, &forged.key_id).is_err());
    let mut forged = proof.clone();
    forged.authority_public_key = key.try_to_base64().unwrap();
    assert!(forged.verify_file_key(&principal, &forged.key_id).is_err());
}

#[test]
fn standalone_iota_history_requires_the_iota_authority_key() {
    let authority = Keyring::generate();
    let user = Keyring::generate();
    let node = IotaNodeId::from_public_keys(&authority.public_key_bundle()).unwrap();
    let principal = PrincipalId {
        authority: AuthorityId::for_iota(&node),
        user_id: 7,
    };
    let proof = FileSigningKeyProofV1::sign(
        principal.clone(),
        AuthorityKind::Iota,
        &user.public_key_bundle(),
        &authority,
    )
    .unwrap();
    proof.verify_file_key(&principal, &proof.key_id).unwrap();
    assert!(
        FileSigningKeyProofV1::sign(
            principal.clone(),
            AuthorityKind::Omega,
            &user.public_key_bundle(),
            &authority
        )
        .is_err()
    );
    assert!(
        FileSigningKeyProofV1::sign(
            principal,
            AuthorityKind::Iota,
            &user.public_key_bundle(),
            &user
        )
        .is_err()
    );
}
