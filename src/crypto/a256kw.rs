use crate::compact::{JweAlg, JweCompact, JweProtectedHeader};
use crate::jwe::Jwe;
use crate::traits::*;
use crate::JwtError;

use openssl::aes::{unwrap_key, wrap_key, AesKey};
use openssl::rand::rand_bytes;

pub(crate) const KEY_LEN: usize = 32;
const KW_EXTRA: usize = 8;

/// A JWE outer encipher and decipher for RFC3394 AES 256 Key Wrapping.
#[derive(Clone)]
pub struct JweA256KWEncipher {
    wrap_key: [u8; KEY_LEN],
}

impl JweEncipherOuter for JweA256KWEncipher {
    fn set_header_alg(&self, hdr: &mut JweProtectedHeader) -> Result<(), JwtError> {
        hdr.alg = JweAlg::A256KW;
        Ok(())
    }

    fn wrap_key(&self, key_to_wrap: &[u8]) -> Result<Vec<u8>, JwtError> {
        if key_to_wrap.len() > KEY_LEN {
            debug!(
                "Unable to wrap key - key to wrap is longer than the wrapping key {} > {}",
                key_to_wrap.len(),
                self.wrap_key.len()
            );
            return Err(JwtError::InvalidKey);
        }

        let wrapping_key = AesKey::new_encrypt(&self.wrap_key).map_err(|ossl_err| {
            debug!(?ossl_err);
            JwtError::OpenSSLError
        })?;

        // Algorithm requires scratch space.
        let mut wrapped_key = vec![0; key_to_wrap.len() + KW_EXTRA];

        wrap_key(&wrapping_key, None, &mut wrapped_key, key_to_wrap).map_err(|ossl_err| {
            debug!(?ossl_err);
            JwtError::OpenSSLError
        })?;

        Ok(wrapped_key)
    }
}

impl JweA256KWEncipher {
    /// Generate an ephemeral outer key.
    pub fn generate_ephemeral() -> Result<Self, JwtError> {
        let mut wrap_key = [0; KEY_LEN];

        rand_bytes(&mut wrap_key).map_err(|ossl_err| {
            debug!(?ossl_err);
            JwtError::OpenSSLError
        })?;

        Ok(JweA256KWEncipher { wrap_key })
    }

    /// Given a JWE, encipher it's content to a compact form.
    pub fn encipher<E: JweEncipherInner>(&self, jwe: &Jwe) -> Result<JweCompact, JwtError> {
        let encipher = E::new_ephemeral()?;
        encipher.encipher_inner(self, jwe)
    }

    /// Given a JWE in compact form, decipher and authenticate it's content.
    pub fn decipher(&self, jwec: &JweCompact) -> Result<Jwe, JwtError> {
        let wrap_key = AesKey::new_decrypt(&self.wrap_key).map_err(|ossl_err| {
            debug!(?ossl_err);
            JwtError::OpenSSLError
        })?;

        let expected_cek_key_len = jwec.header.enc.key_len();
        let mut unwrapped_key = vec![0; expected_cek_key_len];

        unwrap_key(&wrap_key, None, &mut unwrapped_key, &jwec.content_enc_key).map_err(
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
        if value.len() != KEY_LEN {
            // Wrong key size.
            return Err(JwtError::InvalidKey);
        }

        let mut wrap_key = [0; KEY_LEN];

        wrap_key.copy_from_slice(&value);

        Ok(JweA256KWEncipher { wrap_key })
    }
}
