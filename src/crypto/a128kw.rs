use crate::compact::{JweAlg, JweCompact, JweProtectedHeader};
use crate::jwe::Jwe;
use crate::traits::*;
use crate::JwtError;
use crypto_glue::{
    aes128::{self, Aes128Key},
    aes128kw::{Aes128Kw, Aes128KwWrapped},
};

/// A JWE outer encipher and decipher for RFC3394 AES 128 Key Wrapping.
#[derive(Clone)]
pub struct JweA128KWEncipher {
    wrap_key: Aes128Key,
}

impl From<Aes128Key> for JweA128KWEncipher {
    fn from(wrap_key: Aes128Key) -> Self {
        JweA128KWEncipher { wrap_key }
    }
}

impl JweEncipherOuterA128 for JweA128KWEncipher {
    fn set_header_alg(&self, hdr: &mut JweProtectedHeader) -> Result<(), JwtError> {
        hdr.alg = JweAlg::A128KW;
        Ok(())
    }

    fn wrap_key(&self, key_to_wrap: Aes128Key) -> Result<Vec<u8>, JwtError> {
        let key_wrap = Aes128Kw::new(&self.wrap_key);
        let mut wrapped_key = Aes128KwWrapped::default();

        key_wrap
            .wrap(&key_to_wrap, &mut wrapped_key)
            .map_err(|err| {
                error!(?err);
                JwtError::CryptoError
            })?;

        Ok(wrapped_key.to_vec())
    }
}

impl JweA128KWEncipher {
    /// Generate an ephemeral outer key.
    pub fn generate_ephemeral() -> Result<Self, JwtError> {
        let wrap_key = aes128::new_key();
        Ok(JweA128KWEncipher { wrap_key })
    }

    /// Given a JWE, encipher its content to a compact form.
    pub fn encipher<E: JweEncipherInnerA128>(&self, jwe: &Jwe) -> Result<JweCompact, JwtError> {
        let encipher = E::new_ephemeral()?;
        encipher.encipher_inner(self, jwe)
    }

    /// Given a JWE in compact form, decipher and authenticate its content.
    pub fn decipher(&self, jwec: &JweCompact) -> Result<Jwe, JwtError> {
        let wrapped_key = Aes128KwWrapped::from_exact_iter(jwec.content_enc_key.iter().copied())
            .ok_or_else(|| {
                debug!("Invalid content encryption key length");
                JwtError::CryptoError
            })?;

        let key_wrap = Aes128Kw::new(&self.wrap_key);
        let mut key_unwrapped = aes128::Aes128Key::default();

        key_wrap
            .unwrap(&wrapped_key, &mut key_unwrapped)
            .map_err(|err| {
                error!(?err);
                JwtError::CryptoError
            })?;

        let payload = jwec.header.enc.decipher_inner_a128(key_unwrapped, jwec)?;

        Ok(Jwe {
            header: jwec.header.clone(),
            payload,
        })
    }
}
