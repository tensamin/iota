use super::*;
use mtp::crypto::{DualSigner, Keyring, SignatureScheme};

/// Historical identity evidence for file signatures, never relay authorization.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileSigningKeyProofV1 {
    pub version: u32,
    pub principal: PrincipalId,
    pub authority_kind: AuthorityKind,
    pub key_id: String,
    pub public_key: String,
    pub authority_public_key: String,
    pub authority_signature: String,
}

pub fn file_signing_key_id(key: &PublicKeyBundle) -> Result<String, IdentityError> {
    key.validate()
        .map_err(|_| IdentityError::InvalidDescriptor("invalid file signing key".into()))?;
    let bytes = key
        .try_as_bytes()
        .map_err(|_| IdentityError::InvalidDescriptor("invalid file signing key".into()))?;
    Ok(mtp::crypto::sha256(&bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

pub fn valid_file_signing_key_id(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn canonical_bundle(value: &str) -> Result<PublicKeyBundle, IdentityError> {
    let key = PublicKeyBundle::from_base64(value)
        .map_err(|_| IdentityError::InvalidDescriptor("invalid historical key encoding".into()))?;
    key.validate()
        .map_err(|_| IdentityError::InvalidDescriptor("invalid historical public key".into()))?;
    if key
        .try_to_base64()
        .map_err(|_| IdentityError::InvalidDescriptor("invalid historical public key".into()))?
        != value
    {
        return Err(IdentityError::InvalidDescriptor(
            "noncanonical historical public key".into(),
        ));
    }
    Ok(key)
}

impl FileSigningKeyProofV1 {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, IdentityError> {
        serde_json::to_vec(&serde_json::json!([
            "tensamin-file-signing-key:v1",
            self.principal.authority.as_str(),
            self.principal.user_id.to_string(),
            match self.authority_kind {
                AuthorityKind::Iota => "iota",
                AuthorityKind::Omega => "omega",
            },
            self.key_id,
            self.public_key,
        ]))
        .map_err(|_| IdentityError::InvalidDescriptor("historical key signing payload".into()))
    }

    pub fn sign(
        principal: PrincipalId,
        authority_kind: AuthorityKind,
        public_key: &PublicKeyBundle,
        authority: &Keyring,
    ) -> Result<Self, IdentityError> {
        let mut proof = Self {
            version: 1,
            principal,
            authority_kind,
            key_id: file_signing_key_id(public_key)?,
            public_key: public_key
                .try_to_base64()
                .map_err(|_| IdentityError::InvalidDescriptor("invalid file signing key".into()))?,
            authority_public_key: authority
                .public_key_bundle()
                .try_to_base64()
                .map_err(|_| IdentityError::InvalidDescriptor("invalid authority key".into()))?,
            authority_signature: String::new(),
        };
        proof.validate(&proof.principal, &proof.key_id)?;
        let signer = DualSigner::new(
            &authority.sig_cl_secret_key,
            &authority.sig_pq_secret_key,
            &authority.sig_pq_public_key,
        )
        .map_err(|_| IdentityError::InvalidDescriptor("invalid authority signer".into()))?;
        proof.authority_signature =
            STANDARD.encode(signer.sign(&proof.signing_bytes()?).map_err(|_| {
                IdentityError::InvalidDescriptor("historical key signing failed".into())
            })?);
        Ok(proof)
    }

    fn validate(
        &self,
        expected: &PrincipalId,
        key_id: &str,
    ) -> Result<(PublicKeyBundle, PublicKeyBundle), IdentityError> {
        relay_protocol::Principal::try_from(&self.principal)?;
        if self.version != 1 || &self.principal != expected || self.key_id != key_id {
            return Err(IdentityError::InvalidDescriptor(
                "historical key scope or version mismatch".into(),
            ));
        }
        let key = canonical_bundle(&self.public_key)?;
        if file_signing_key_id(&key)? != key_id {
            return Err(IdentityError::InvalidDescriptor(
                "historical key fingerprint mismatch".into(),
            ));
        }
        let authority = canonical_bundle(&self.authority_public_key)?;
        let id = match self.authority_kind {
            AuthorityKind::Omega => AuthorityId::for_omega(&authority)?,
            AuthorityKind::Iota => {
                AuthorityId::for_iota(&IotaNodeId::from_public_keys(&authority)?)
            }
        };
        if id != expected.authority {
            return Err(IdentityError::InvalidDescriptor(
                "historical key authority mismatch".into(),
            ));
        }
        Ok((key, authority))
    }

    pub fn verify_file_key(
        &self,
        principal: &PrincipalId,
        key_id: &str,
    ) -> Result<PublicKeyBundle, IdentityError> {
        let (key, authority) = self.validate(principal, key_id)?;
        let signature = STANDARD.decode(&self.authority_signature).map_err(|_| {
            IdentityError::InvalidDescriptor("invalid historical key signature".into())
        })?;
        verify_authority_signature(&authority, &self.signing_bytes()?, &signature)?;
        Ok(key)
    }
}
