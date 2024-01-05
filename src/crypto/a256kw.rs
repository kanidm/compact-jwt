use crate::compact::{JweAlg, JweCompact, JweEnc, JweProtectedHeader};
use crate::jwe::Jwe;
use crate::traits::*;
use crate::JwtError;

use openssl::aes::{unwrap_key, wrap_key, AesKey};
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rand::rand_bytes;
use openssl::sign::Signer;
use openssl::symm::{Cipher, Crypter, Mode};

// Do I need some inner type to handle the enc bit?

#[derive(Clone)]
pub struct JweA256KWEncipher {
    wrap_key: [u8; 32],
}

impl JweEncipherOuter for JweA256KWEncipher {
    fn set_header_alg(&self, hdr: &mut JweProtectedHeader) {
        hdr.alg = JweAlg::A256KW;
    }

    fn wrap_key(&self, key_to_wrap: &[u8]) -> Result<Vec<u8>, JwtError> {
        if key_to_wrap.len() > self.wrap_key.len() {
            debug!(
                "Unable to wrap key - key to wrap is longer than the wrapping key {} > {}",
                key_to_wrap.len(),
                self.wrap_key.len()
            );
            JwtError::InvalidKey;
        }

        let wrapping_key = AesKey::new_encrypt(&self.wrap_key).map_err(|ossl_err| {
            debug!(?ossl_err);
            JwtError::OpenSSLError
        })?;

        // Algorithm requires scratch space.
        let mut wrapped_key = vec![0; key_to_wrap.len() + 8];

        let len =
            wrap_key(&wrapping_key, None, &mut wrapped_key, &key_to_wrap).map_err(|ossl_err| {
                debug!(?ossl_err);
                JwtError::OpenSSLError
            })?;

        Ok(wrapped_key)
    }
}

impl JweA256KWEncipher {
    pub fn generate_ephemeral() -> Result<Self, JwtError> {
        let mut wrap_key = [0; 32];

        rand_bytes(&mut wrap_key).map_err(|ossl_err| {
            debug!(?ossl_err);
            JwtError::OpenSSLError
        })?;

        Ok(JweA256KWEncipher { wrap_key })
    }

    pub fn encipher<E: JweEncipherInner>(&self, jwe: &Jwe) -> Result<JweCompact, JwtError> {
        let encipher = E::new_ephemeral()?;
        encipher.encipher_inner(self, jwe)
    }

    pub fn decipher(&self, jwec: &JweCompact) -> Result<Jwe, JwtError> {
        let wrap_key = AesKey::new_decrypt(&self.wrap_key).map_err(|ossl_err| {
            debug!(?ossl_err);
            JwtError::OpenSSLError
        })?;

        let expected_cek_key_len = jwec.header.enc.key_len();
        let mut unwrapped_key = vec![0; expected_cek_key_len];

        let len = unwrap_key(&wrap_key, None, &mut unwrapped_key, &jwec.content_enc_key).map_err(
            |ossl_err| {
                debug!(?ossl_err);
                JwtError::OpenSSLError
            },
        )?;

        unwrapped_key.truncate(expected_cek_key_len);

        let payload = jwec
            .header
            .enc
            .decipher_inner(unwrapped_key.as_slice(), jwec)?;

        Ok(Jwe {
            header: jwec.header.clone(),
            payload,
        })
    }
}

impl TryFrom<Vec<u8>> for JweA256KWEncipher {
    type Error = JwtError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        if value.len() != 32 {
            // Wrong key size.
            return Err(JwtError::InvalidKey);
        }

        let mut wrap_key = [0; 32];

        wrap_key.copy_from_slice(&value);

        Ok(JweA256KWEncipher { wrap_key })
    }
}
