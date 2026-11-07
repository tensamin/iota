use super::*;
use mtp::crypto::{DualSigner, Keyring, SignatureScheme};

const LIFETIME_MS: i64 = 60 * 60 * 1000;

/// Omega-signed domain binding, separate from user and hosting-Iota proofs.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OmegaLocatorProofV1 {
    pub version: u32,
    pub authority: AuthorityId,
    pub locator: AuthorityLocator,
    pub public_key: String,
    pub issued_at: i64,
    pub valid_until: i64,
    pub signature: String,
}

impl OmegaLocatorProofV1 {
    fn signing_bytes(&self) -> Result<Vec<u8>, IdentityError> {
        serde_json::to_vec(&serde_json::json!([
            "tensamin-omega-locator:v1",
            self.authority.as_str(),
            self.locator.as_str(),
            self.public_key,
            self.issued_at.to_string(),
            self.valid_until.to_string(),
        ]))
        .map_err(|error| IdentityError::InvalidDescriptor(error.to_string()))
    }

    pub fn sign(
        locator: AuthorityLocator,
        authority: &Keyring,
        now: i64,
    ) -> Result<Self, IdentityError> {
        if now < 0 {
            return Err(IdentityError::InvalidDescriptor(
                "invalid locator proof time".into(),
            ));
        }
        let key = authority.public_key_bundle();
        let mut proof = Self {
            version: 1,
            authority: AuthorityId::for_omega(&key)?,
            locator,
            public_key: key
                .try_to_base64()
                .map_err(|error| IdentityError::InvalidDescriptor(error.to_string()))?,
            issued_at: now,
            valid_until: now.checked_add(LIFETIME_MS).ok_or_else(|| {
                IdentityError::InvalidDescriptor("locator proof expiry overflow".into())
            })?,
            signature: String::new(),
        };
        let signer = DualSigner::new(
            &authority.sig_cl_secret_key,
            &authority.sig_pq_secret_key,
            &authority.sig_pq_public_key,
        )
        .map_err(|error| IdentityError::InvalidDescriptor(error.to_string()))?;
        proof.signature = STANDARD.encode(
            signer
                .sign(&proof.signing_bytes()?)
                .map_err(|error| IdentityError::InvalidDescriptor(error.to_string()))?,
        );
        Ok(proof)
    }

    /// The locator must be the actual HTTPS request target, not a value from discovery.
    pub fn verify(
        &self,
        locator: &AuthorityLocator,
        authority: &AuthorityId,
        now: i64,
    ) -> Result<(), IdentityError> {
        if self.version != 1
            || &self.locator != locator
            || &self.authority != authority
            || AuthorityLocator::new(self.locator.as_str())? != self.locator
            || self.issued_at < 0
            || self.issued_at > now.saturating_add(5 * 60 * 1000)
            || self.valid_until <= now
            || self.valid_until.checked_sub(self.issued_at) != Some(LIFETIME_MS)
        {
            return Err(IdentityError::InvalidDescriptor(
                "Omega locator proof scope or lifetime mismatch".into(),
            ));
        }
        let key = PublicKeyBundle::from_base64(&self.public_key)
            .map_err(|error| IdentityError::InvalidDescriptor(error.to_string()))?;
        key.validate()
            .map_err(|error| IdentityError::InvalidDescriptor(error.to_string()))?;
        if AuthorityId::for_omega(&key)? != *authority
            || key
                .try_to_base64()
                .map_err(|error| IdentityError::InvalidDescriptor(error.to_string()))?
                != self.public_key
        {
            return Err(IdentityError::KeyPinMismatch);
        }
        let signature = STANDARD
            .decode(&self.signature)
            .map_err(|error| IdentityError::InvalidDescriptor(error.to_string()))?;
        verify_authority_signature(&key, &self.signing_bytes()?, &signature)
    }
}
