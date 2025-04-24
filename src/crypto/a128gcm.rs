use crate::compact::{JweCompact, JweEnc};
use crate::jwe::Jwe;
use crate::traits::*;
use crate::JwtError;
use base64::{engine::general_purpose, Engine as _};
use crypto_glue::{
    aes128::{self, Aes128Key},
    aes128gcm::{self, Aes128Gcm, Aes128GcmNonce, Aes128GcmTag},
    traits::{AeadInPlace, KeyInit},
};

/// A JWE inner encipher and decipher for AES 128 GCM.
#[derive(Clone)]
pub struct JweA128GCMEncipher {
    aes_key: Aes128Key,
}

#[cfg(all(test, feature = "msextensions"))]
impl JweA128GCMEncipher {
    pub(crate) fn raw_key(&self) -> Aes128Key {
        self.aes_key.clone()
    }
}

impl From<Aes128Key> for JweA128GCMEncipher {
    fn from(aes_key: Aes128Key) -> Self {
        JweA128GCMEncipher { aes_key }
    }
}

impl JweEncipherInnerA128 for JweA128GCMEncipher {
    fn new_ephemeral() -> Result<Self, JwtError> {
        let aes_key = aes128::new_key();
        Ok(JweA128GCMEncipher { aes_key })
    }

    fn encipher_inner<O: JweEncipherOuterA128>(
        &self,
        outer: &O,
        jwe: &Jwe,
    ) -> Result<JweCompact, JwtError> {
        // Update the header with our details
        let mut header = jwe.header.clone();
        header.enc = JweEnc::A128GCM;
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

        let cipher = Aes128Gcm::new(&self.aes_key);
        let nonce = aes128gcm::new_nonce();

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

impl JweA128GCMEncipher {
    pub(crate) fn decipher_inner(&self, jwec: &JweCompact) -> Result<Vec<u8>, JwtError> {
        let cipher = Aes128Gcm::new(&self.aes_key);

        let nonce = Aes128GcmNonce::from_exact_iter(jwec.iv.iter().copied()).ok_or_else(|| {
            debug!("Invalid nonce length");
            JwtError::CryptoError
        })?;

        let tag = Aes128GcmTag::from_exact_iter(jwec.authentication_tag.iter().copied())
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
    use super::JweA128GCMEncipher;
    use crate::crypto::a128kw::JweA128KWEncipher;
    use crate::jwe::JweBuilder;

    #[test]
    fn a128kw_outer_a128gcm_inner() {
        let _ = tracing_subscriber::fmt::try_init();

        let input = vec![1; 128];
        let jweb = JweBuilder::from(input.clone()).build();

        let jwe_a128kw =
            JweA128KWEncipher::generate_ephemeral().expect("Unable to build wrap key.");

        let jwe_encrypted = jwe_a128kw
            .encipher::<JweA128GCMEncipher>(&jweb)
            .expect("Unable to encrypt.");

        let decrypted = jwe_a128kw
            .decipher(&jwe_encrypted)
            .expect("Unable to decrypt.");

        assert_eq!(decrypted.payload(), input);
    }
}
