use crate::compact::{JweCompact, JweEnc};
use crate::jwe::Jwe;
use crate::traits::*;
use crate::JwtError;
use base64::{engine::general_purpose, Engine as _};
use crypto_glue::{
    aes256::{self, Aes256Key},
    aes256gcm::{self, Aes256Gcm, Aes256GcmNonce, Aes256GcmTag},
    traits::{AeadInPlace, KeyInit},
};

/// A JWE inner encipher and decipher for AES 256 GCM.
#[derive(Clone)]
pub struct JweA256GCMEncipher {
    aes_key: Aes256Key,
}

#[cfg(test)]
impl JweA256GCMEncipher {
    pub(crate) fn raw_key(&self) -> Aes256Key {
        self.aes_key.clone()
    }
}

impl From<Aes256Key> for JweA256GCMEncipher {
    fn from(aes_key: Aes256Key) -> Self {
        JweA256GCMEncipher { aes_key }
    }
}

impl JweEncipherInnerA256 for JweA256GCMEncipher {
    fn new_ephemeral() -> Result<Self, JwtError> {
        let aes_key = aes256::new_key();
        Ok(JweA256GCMEncipher { aes_key })
    }

    fn encipher_inner<O: JweEncipherOuterA256>(
        &self,
        outer: &O,
        jwe: &Jwe,
    ) -> Result<JweCompact, JwtError> {
        // Update the header with our details
        let mut header = jwe.header.clone();
        header.enc = JweEnc::A256GCM;
        outer.set_header_alg(&mut header)?;

        // Ensure that our content encryption key can be wrapped before we proceed.
        let wrapped_content_enc_key = outer.wrap_key(self.aes_key.clone())?;

        // base64 it - this is needed for the authentication step of the encryption.
        let hdr_b64 = serde_json::to_vec(&header)
            .map_err(|e| {
                debug!(?e);
                JwtError::InvalidHeaderFormat
            })
            .map(|bytes| general_purpose::URL_SAFE_NO_PAD.encode(bytes))?;

        // Now setup to encrypt.

        let cipher = Aes256Gcm::new(&self.aes_key);
        let nonce = aes256gcm::new_nonce();

        let associated_data = hdr_b64.as_bytes();

        let mut encryption_data = jwe.payload.clone();

        let authentication_tag = cipher
            .encrypt_in_place_detached(&nonce, associated_data, encryption_data.as_mut_slice())
            .map_err(|err| {
                debug!(?err);
                JwtError::CryptoError
            })?;

        Ok(JweCompact {
            header,
            hdr_b64,
            content_enc_key: wrapped_content_enc_key,
            iv: nonce.to_vec(),
            ciphertext: encryption_data,
            authentication_tag: authentication_tag.to_vec(),
        })
    }
}

impl JweA256GCMEncipher {
    pub(crate) fn decipher_inner(&self, jwec: &JweCompact) -> Result<Vec<u8>, JwtError> {
        let cipher = Aes256Gcm::new(&self.aes_key);

        let nonce = Aes256GcmNonce::from_exact_iter(jwec.iv.iter().copied()).ok_or_else(|| {
            debug!("Invalid nonce length");
            JwtError::CryptoError
        })?;

        let tag = Aes256GcmTag::from_exact_iter(jwec.authentication_tag.iter().copied())
            .ok_or_else(|| {
                debug!("Invalid tag length");
                JwtError::CryptoError
            })?;

        let associated_data = jwec.hdr_b64.as_bytes();

        let mut encryption_data = jwec.ciphertext.clone();

        cipher
            .decrypt_in_place_detached(
                &nonce,
                associated_data,
                encryption_data.as_mut_slice(),
                &tag,
            )
            .map_err(|err| {
                debug!(?err);
                JwtError::CryptoError
            })?;

        Ok(encryption_data)
    }
}

#[cfg(test)]
mod tests {
    use super::JweA256GCMEncipher;
    use crate::crypto::a256kw::JweA256KWEncipher;
    use crate::jwe::JweBuilder;

    #[test]
    fn a256kw_outer_a256gcm_inner() {
        let _ = tracing_subscriber::fmt::try_init();

        let input = vec![1; 256];
        let jweb = JweBuilder::from(input.clone()).build();

        let jwe_a256kw =
            JweA256KWEncipher::generate_ephemeral().expect("Unable to build wrap key.");

        let jwe_encrypted = jwe_a256kw
            .encipher::<JweA256GCMEncipher>(&jweb)
            .expect("Unable to encrypt.");

        let decrypted = jwe_a256kw
            .decipher(&jwe_encrypted)
            .expect("Unable to decrypt.");

        assert_eq!(decrypted.payload(), input);
    }
}
