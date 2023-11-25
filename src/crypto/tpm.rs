use crate::compact::{JwaAlg, JwsCompact, ProtectedHeader};
use crate::error::JwtError;
use crate::traits::*;
use base64::{engine::general_purpose, Engine as _};
use kanidm_hsm_crypto::{IdentityKey, KeyAlgorithm, Tpm};

/// A JWS signer that uses a TPM protected key for signing operations.
///
/// Due to the construction of TPM's, this struct is intended to be "short lived"
/// relying on references to the TPM rather than taking ownership of it. This means
/// unlike other Signer types, you will need to build this struct each time you want
/// to perform a signing operation in most cases.
pub struct JwsTpmSigner<'a, T: Tpm> {
    kid: String,
    tpm: &'a mut T,
    id_key: &'a IdentityKey,
}

impl<'a, T> JwsTpmSigner<'a, T>
where
    T: Tpm,
{
    /// Create a new JwsTpmSigner that will use the provided Identity Key for signing
    /// operations.
    pub fn new(tpm: &'a mut T, id_key: &'a IdentityKey) -> Result<Self, JwtError> {
        let kid = tpm
            .identity_key_id(id_key)
            .map(hex::encode)
            .map_err(|_err| JwtError::TpmError)?;

        Ok(JwsTpmSigner { kid, tpm, id_key })
    }
}

impl<'a, T> JwsMutSigner for JwsTpmSigner<'a, T>
where
    T: Tpm,
{
    fn get_kid(&mut self) -> &str {
        self.kid.as_str()
    }

    fn update_header(&mut self, header: &mut ProtectedHeader) -> Result<(), JwtError> {
        // Update the alg to match.
        header.alg = JwaAlg::ES256;

        header.kid = Some(self.kid.clone());

        // if were were asked to ember the jwk, do so now.
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
            .identity_key_sign(self.id_key, &hash_data)
            .map_err(|_err| JwtError::TpmError)?;

        let jwsc = JwsCompact {
            header: sign_data.header,
            hdr_b64,
            payload_b64: sign_data.payload_b64,
            signature,
        };

        jws.post_process(jwsc)
    }
}

impl<'a, T> JwsMutVerifier for JwsTpmSigner<'a, T>
where
    T: Tpm,
{
    /// Get the key id from this verifier
    fn get_kid(&mut self) -> Option<&str> {
        Some(JwsMutSigner::get_kid(self))
    }

    /// Perform the signature verification
    fn verify<V: JwsVerifiable>(&mut self, jwsc: &V) -> Result<V::Verified, JwtError> {
        let signed_data = jwsc.data();

        match (signed_data.header.alg, self.id_key.alg()) {
            (JwaAlg::ES256, KeyAlgorithm::Ecdsa256) | (JwaAlg::RS256, KeyAlgorithm::Rsa2048) => {}
            (jwsc_alg, key_alg) => {
                debug!(?jwsc_alg, ?key_alg, "validator algorithm mismatch");
                return Err(JwtError::ValidatorAlgMismatch);
            }
        };

        let mut hash_data =
            Vec::with_capacity(signed_data.hdr_bytes.len() + 1 + signed_data.payload_bytes.len());
        hash_data.extend_from_slice(signed_data.hdr_bytes);
        hash_data.extend_from_slice(".".as_bytes());
        hash_data.extend_from_slice(signed_data.payload_bytes);

        let valid = self
            .tpm
            .identity_key_verify(self.id_key, &hash_data, signed_data.signature_bytes)
            .map_err(|e| {
                debug!(?e);
                JwtError::TpmError
            })?;

        if valid {
            signed_data.release().and_then(|d| jwsc.post_process(d))
        } else {
            debug!("invalid signature");
            Err(JwtError::InvalidSignature)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::JwsTpmSigner;
    use kanidm_hsm_crypto::{soft::SoftTpm, AuthValue, KeyAlgorithm, Tpm};
    // use crate::compact::{Jwk, JwsCompact};
    use crate::jws::JwsBuilder;
    use crate::traits::*;

    #[test]
    fn tpm_key_generate_cycle() {
        let _ = tracing_subscriber::fmt::try_init();

        // Setup the tpm
        let mut softtpm = SoftTpm::new();
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
}
