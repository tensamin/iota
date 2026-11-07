use async_trait::async_trait;
use iota_connection::message_handlers::handle_user_resolve;
use iota_identity::{
    AuthorityId, AuthorityKind, FileSigningKeyProofV1, IdentityError, IdentityResolver,
    PrincipalId, ResolutionContext, ResolvedPrincipal, UserAddress,
};
use mtp::{
    codec::{CommunicationType as C, CommunicationValue, DataType as D, DataValue},
    crypto::{Keyring, PublicKeyBundle},
};

struct History(FileSigningKeyProofV1);
#[async_trait]
impl IdentityResolver for History {
    async fn file_signing_key(
        &self,
        _: &PrincipalId,
        _: &str,
    ) -> Result<FileSigningKeyProofV1, IdentityError> {
        Ok(self.0.clone())
    }
    async fn resolve_address(
        &self,
        _: &UserAddress,
        _: &ResolutionContext,
    ) -> Result<ResolvedPrincipal, IdentityError> {
        Err(IdentityError::NotFound)
    }
    async fn resolve_principal(&self, _: &PrincipalId) -> Result<ResolvedPrincipal, IdentityError> {
        Err(IdentityError::NotFound)
    }
    async fn signing_keys(
        &self,
        _: &PrincipalId,
        _: &ResolutionContext,
    ) -> Result<Vec<PublicKeyBundle>, IdentityError> {
        Err(IdentityError::NotFound)
    }
}

#[tokio::test]
async fn history_lookup_is_bounded_canonical_and_never_reports_active_keys_or_home_routes() {
    let authority = Keyring::generate();
    let user = Keyring::generate();
    let principal = PrincipalId {
        authority: AuthorityId::for_omega(&authority.public_key_bundle()).unwrap(),
        user_id: i64::MAX as u64,
    };
    let proof = FileSigningKeyProofV1::sign(
        principal.clone(),
        AuthorityKind::Omega,
        &user.public_key_bundle(),
        &authority,
    )
    .unwrap();
    let selector = format!("{{\"file_signing_key\":\"{}\"}}", proof.key_id);
    let resolver = History(proof.clone());
    let request = CommunicationValue::new(C::UserResolve)
        .with_id(17)
        .add_typed_default(
            D::UserAddress,
            DataValue::Str(serde_json::to_string(&principal).unwrap()),
        )
        .add_typed_default(D::Json, DataValue::Str(selector.clone()));
    let response = handle_user_resolve(&request, &resolver).await;
    assert!(response.is_type(C::UserResolved));
    assert_eq!(response.id(), Some(17));
    assert!(response.get_data(D::SigningKeys).is_none());
    assert!(response.get_data(D::NodeId).is_none());
    let decoded: FileSigningKeyProofV1 =
        serde_json::from_str(response.get_str(D::Json).unwrap()).unwrap();
    decoded.verify_file_key(&principal, &proof.key_id).unwrap();
    for selector in [
        format!(
            "{{\"file_signing_key\":\"{}\",\"file_signing_key\":\"{}\"}}",
            proof.key_id, proof.key_id
        ),
        "{\"file_signing_key\":\"invalid\"}".into(),
    ] {
        let bad = CommunicationValue::new(C::UserResolve)
            .with_id(18)
            .add_typed_default(
                D::UserAddress,
                DataValue::Str(serde_json::to_string(&principal).unwrap()),
            )
            .add_typed_default(D::Json, DataValue::Str(selector));
        assert!(
            handle_user_resolve(&bad, &resolver)
                .await
                .is_type(C::ErrorInvalidData)
        );
    }
    let mut other = principal;
    other.user_id -= 1;
    let wrong_subject = CommunicationValue::new(C::UserResolve)
        .add_typed_default(
            D::UserAddress,
            DataValue::Str(serde_json::to_string(&other).unwrap()),
        )
        .add_typed_default(D::Json, DataValue::Str(selector));
    assert!(
        handle_user_resolve(&wrong_subject, &resolver)
            .await
            .is_type(C::ErrorInvalidData)
    );
}
