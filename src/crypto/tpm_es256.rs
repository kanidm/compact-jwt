use crate::compact::{JwaAlg, JwsCompact, ProtectedHeader};
use crate::error::JwtError;
use crate::traits::*;
use base64::{engine::general_purpose, Engine as _};
use kanidm_hsm_crypto::{
    provider::{Tpm, TpmES256},
    structures::ES256Key,
};

/// A JWS signer that uses a TPM protected key for signing operations.
///
/// Due to the construction of TPM's, this struct is intended to be "short lived"
/// relying on references to the TPM rather than taking ownership of it. This means
/// unlike other Signer types, you will need to build this struct each time you want
/// to perform a signing operation in most cases.
pub struct JwsTpmEs256Signer<'a, T: Tpm + TpmES256> {
    kid: String,
    tpm: &'a mut T,
    id_key: &'a ES256Key,
}

impl<'a, T> JwsTpmEs256Signer<'a, T>
where
    T: Tpm + TpmES256,
{
    /// Create a new JwsTpmSigner that will use the provided Identity Key for signing
    /// operations.
    pub fn new(tpm: &'a mut T, id_key: &'a ES256Key) -> Result<Self, JwtError> {
        let kid = tpm
            .es256_fingerprint(id_key)
            .map(hex::encode)
            .map_err(|_err| JwtError::TpmError)?;

        Ok(Self { kid, tpm, id_key })
    }
}

impl<'a, T> JwsMutSigner for JwsTpmEs256Signer<'a, T>
where
    T: Tpm + TpmES256,
{
    fn get_kid(&mut self) -> &str {
        self.kid.as_str()
    }

    fn update_header(&mut self, header: &mut ProtectedHeader) -> Result<(), JwtError> {
        header.alg = JwaAlg::ES256;

        // Only set the kid if it's not already set
        if header.kid.is_none() {
            header.kid = Some(self.kid.clone());
        }

        /*
        if self.sign_option_embed_jwk {
            header.jwk = self.public_key_as_jwk().map(Some)?;
        }
        */

        Ok(())
    }

    fn sign<V: JwsSignable>(&mut self, jws: &V) -> Result<V::Signed, JwtError> {
        let mut sign_data = jws.data()?;

        // Let the signer update the header as required.
        self.update_header(&mut sign_data.header)?;

        let hdr_b64 = serde_json::to_vec(&sign_data.header)
            .map_err(|e| {
                debug!(?e);
                JwtError::InvalidHeaderFormat
            })
            .map(|bytes| general_purpose::URL_SAFE_NO_PAD.encode(bytes))?;

        let mut hash_data = Vec::with_capacity(hdr_b64.len() + 1 + sign_data.payload_b64.len());
        hash_data.extend_from_slice(hdr_b64.as_bytes());
        hash_data.extend_from_slice(".".as_bytes());
        hash_data.extend_from_slice(sign_data.payload_b64.as_bytes());

        let signature = self
            .tpm
            .es256_sign(self.id_key, &hash_data)
            .map_err(|_err| JwtError::TpmError)?;

        let jwsc = JwsCompact {
            header: sign_data.header,
            hdr_b64,
            payload_b64: sign_data.payload_b64,
            signature: signature.to_vec(),
        };

        jws.post_process(jwsc)
    }
}

#[cfg(test)]
mod tests {
    use super::JwsTpmEs256Signer;
    use kanidm_hsm_crypto::{
        provider::SoftTpm,
        provider::{Tpm, TpmES256},
        AuthValue,
    };
    // use crate::compact::{Jwk, JwsCompact};
    use crate::crypto::es256::JwsEs256Verifier;
    use crate::jws::JwsBuilder;
    use crate::traits::*;

    #[test]
    fn tpm_key_generate_cycle() {
        let _ = tracing_subscriber::fmt::try_init();

        // Setup the tpm
        let mut soft_tpm = SoftTpm::default();
        let auth_value = AuthValue::ephemeral().expect("Failed to generate new random secret");

        let loadable_storage_key = soft_tpm
            .root_storage_key_create(&auth_value)
            .expect("Unable to create new storage key");

        let root_storage_key = soft_tpm
            .root_storage_key_load(&auth_value, &loadable_storage_key)
            .expect("Unable to load storage key");

        let loadable_es256_key = soft_tpm
            .es256_create(&root_storage_key)
            .expect("Unable to create es256 key");

        let es256_key = soft_tpm
            .es256_load(&root_storage_key, &loadable_es256_key)
            .expect("Unable to load es256 key");

        let es256_pub_key = soft_tpm
            .es256_public(&es256_key)
            .expect("Unable to access es256 public key");

        let mut jws_tpm_signer =
            JwsTpmEs256Signer::new(&mut soft_tpm, &es256_key).expect("failed to construct signer.");

        // This time we'll add the jwk pubkey and show it being used with the validator.
        let jws = JwsBuilder::from(vec![0, 1, 2, 3, 4])
            .set_kid(Some("abcd"))
            .set_typ(Some("abcd"))
            .set_cty(Some("abcd"))
            .build();

        let jwsc = jws_tpm_signer.sign(&jws).expect("Failed to sign");

        let verifier = JwsEs256Verifier::from(es256_pub_key);

        let released = verifier.verify(&jwsc).expect("Unable to validate jws");

        assert!(released.payload() == &[0, 1, 2, 3, 4]);
    }

    /*
    #[test]
    fn tpm_dyn_trait_object_cycle() {
        let _ = tracing_subscriber::fmt::try_init();

        // Setup the tpm
        let mut softtpm: BoxedDynTpm = BoxedDynTpm::new(SoftTpm::new());
        // let mut softtpm: &mut BoxedDynTpm = &mut box_softtpm;

        let auth_value = AuthValue::ephemeral().unwrap();

        let loadable_machine_key = softtpm.machine_key_create(&auth_value).unwrap();

        let machine_key = softtpm
            .machine_key_load(&auth_value, &loadable_machine_key)
            .unwrap();

        let loadable_id_key = softtpm
            .identity_key_create(&machine_key, KeyAlgorithm::Ecdsa256)
            .unwrap();

        let id_key = softtpm
            .identity_key_load(&machine_key, &loadable_id_key)
            .unwrap();

        let mut jws_tpm_signer =
            JwsTpmSigner::new(&mut softtpm, &id_key).expect("failed to construct signer.");

        // This time we'll add the jwk pubkey and show it being used with the validator.
        let jws = JwsBuilder::from(vec![0, 1, 2, 3, 4])
            .set_kid(Some("abcd"))
            .set_typ(Some("abcd"))
            .set_cty(Some("abcd"))
            .build();

        // jws_tpm_signer.set_sign_option_embed_jwk(true);

        let jwsc = jws_tpm_signer.sign(&jws).expect("Failed to sign");

        let released = jws_tpm_signer
            .verify(&jwsc)
            .expect("Unable to validate jws");
        assert!(released.payload() == &[0, 1, 2, 3, 4]);
    }
    */
}
