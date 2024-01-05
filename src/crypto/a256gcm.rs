use crate::compact::{JweCompact, JweEnc, JweProtectedHeader};
use crate::jwe::Jwe;
use crate::traits::*;
use crate::JwtError;

use openssl::aes::{unwrap_key, AesKey};
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::sign::Signer;
use openssl::symm::{Cipher, Crypter, Mode};

use base64::{engine::general_purpose, Engine as _};
use openssl::rand::rand_bytes;

#[derive(Clone)]
pub struct JweA256GCMEncipher {
    aes_key: [u8; 32],
}

impl TryFrom<&[u8]> for JweA256GCMEncipher {
    type Error = JwtError;

    fn try_from(r_aes_key: &[u8]) -> Result<Self, Self::Error> {
        if r_aes_key.len() != 32 {
            return Err(JwtError::InvalidKey);
        }

        let mut aes_key = [0; 32];
        aes_key.copy_from_slice(r_aes_key);

        Ok(JweA256GCMEncipher { aes_key })
    }
}

impl JweEncipherInner for JweA256GCMEncipher {
    fn new_ephemeral() -> Result<Self, JwtError> {
        let mut aes_key = [0; 32];
        rand_bytes(&mut aes_key).map_err(|ossl_err| {
            debug!(?ossl_err);
            JwtError::OpenSSLError
        })?;

        Ok(JweA256GCMEncipher { aes_key })
    }

    fn encipher_inner<O: JweEncipherOuter>(
        &self,
        outer: &O,
        jwe: &Jwe,
    ) -> Result<JweCompact, JwtError> {
        let mut header = jwe.header.clone();
        header.enc = JweEnc::A256GCM;

        // Clone the header and update it with our details.
        let hdr_b64 = serde_json::to_vec(&header)
            .map_err(|e| {
                debug!(?e);
                JwtError::InvalidHeaderFormat
            })
            .map(|bytes| general_purpose::URL_SAFE_NO_PAD.encode(bytes))?;

        let content_enc_key = outer.wrap_key(&self.aes_key)?;

        // 128 bit iv.
        let mut iv = vec![0; 16];
        rand_bytes(&mut iv).map_err(|ossl_err| {
            debug!(?ossl_err);
            JwtError::OpenSSLError
        })?;

        let authentication_tag_bytes = 16;

        let (ciphertext, authentication_tag) = super::a128gcm::aes_gcm_encipher(
            Cipher::aes_256_gcm(),
            authentication_tag_bytes,
            &jwe.payload,
            hdr_b64.as_bytes(),
            &self.aes_key,
            &iv,
        )?;

        Ok(JweCompact {
            header,
            hdr_b64,
            content_enc_key,
            iv,
            ciphertext,
            authentication_tag,
        })
    }
}

impl JweA256GCMEncipher {
    pub fn key_len() -> usize {
        32
    }

    pub fn decipher_inner(&self, jwec: &JweCompact) -> Result<Vec<u8>, JwtError> {
        super::a128gcm::aes_gcm_decipher(
            Cipher::aes_256_gcm(),
            &jwec.ciphertext,
            jwec.hdr_b64.as_bytes(),
            &self.aes_key,
            &jwec.iv,
            &jwec.authentication_tag,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::JweA256GCMEncipher;
    use crate::compact::JweCompact;
    use crate::crypto::a256kw::JweA256KWEncipher;
    use crate::traits::*;

    use crate::compact::JweEnc;
    use crate::jwe::JweBuilder;

    // use base64::{engine::general_purpose, Engine as _};
    // use std::convert::TryFrom;
    // use std::str::FromStr;

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
