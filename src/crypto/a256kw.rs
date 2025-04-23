use crate::compact::{JweAlg, JweCompact, JweProtectedHeader};
use crate::jwe::Jwe;
use crate::traits::*;
use crate::JwtError;
use crypto_glue::{
    aes256::{self, Aes256Key},
    aes256kw::{Aes256Kw, Aes256KwWrapped},
};

/// A JWE outer encipher and decipher for RFC3394 AES 256 Key Wrapping.
#[derive(Clone)]
pub struct JweA256KWEncipher {
    wrap_key: Aes256Key,
}

impl From<Aes256Key> for JweA256KWEncipher {
    fn from(wrap_key: Aes256Key) -> Self {
        JweA256KWEncipher { wrap_key }
    }
}

impl JweEncipherOuterA256 for JweA256KWEncipher {
    fn set_header_alg(&self, hdr: &mut JweProtectedHeader) -> Result<(), JwtError> {
        hdr.alg = JweAlg::A256KW;
        Ok(())
    }

    fn wrap_key(&self, key_to_wrap: Aes256Key) -> Result<Vec<u8>, JwtError> {
        let key_wrap = Aes256Kw::new(&self.wrap_key);
        let mut wrapped_key = Aes256KwWrapped::default();

        key_wrap
            .wrap(&key_to_wrap, &mut wrapped_key)
            .map_err(|err| {
                error!(?err);
                JwtError::CryptoError
            })?;

        Ok(wrapped_key.to_vec())
    }
}

impl JweA256KWEncipher {
    /// Generate an ephemeral outer key.
    pub fn generate_ephemeral() -> Result<Self, JwtError> {
        let wrap_key = aes256::new_key();
        Ok(JweA256KWEncipher { wrap_key })
    }

    /// Given a JWE, encipher its content to a compact form.
    pub fn encipher<E: JweEncipherInnerA256>(&self, jwe: &Jwe) -> Result<JweCompact, JwtError> {
        let encipher = E::new_ephemeral()?;
        encipher.encipher_inner(self, jwe)
    }

    /// Given a JWE in compact form, decipher and authenticate its content.
    pub fn decipher(&self, jwec: &JweCompact) -> Result<Jwe, JwtError> {
        let wrapped_key = Aes256KwWrapped::from_exact_iter(jwec.content_enc_key.iter().copied())
            .ok_or_else(|| {
                debug!("Invalid content encryption key length");
                JwtError::CryptoError
            })?;

        let key_wrap = Aes256Kw::new(&self.wrap_key);
        let mut key_unwrapped = aes256::Aes256Key::default();

        key_wrap
            .unwrap(&wrapped_key, &mut key_unwrapped)
            .map_err(|err| {
                error!(?err);
                JwtError::CryptoError
            })?;

        let payload = jwec.header.enc.decipher_inner_a256(key_unwrapped, jwec)?;

        Ok(Jwe {
            header: jwec.header.clone(),
            payload,
        })
    }
}
