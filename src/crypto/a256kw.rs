use crate::compact::{JweAlg, JweCompact, JweProtectedHeader};
use crate::jwe::Jwe;
use crate::traits::*;
use crate::{JwtError, KID_LEN};
use crypto_glue::{
    aes256::{self, Aes256Key},
    aes256kw::{Aes256Kw, Aes256KwWrapped},
    hmac_s256::{HmacSha256, HmacSha256Key},
    traits::Mac,
};

/// A JWE outer encipher and decipher for RFC3394 AES 256 Key Wrapping.
#[derive(Clone)]
pub struct JweA256KWEncipher {
    kid: Option<String>,
    wrap_key: Aes256Key,
}

impl From<Aes256Key> for JweA256KWEncipher {
    fn from(wrap_key: Aes256Key) -> Self {
        JweA256KWEncipher {
            wrap_key,
            kid: None,
        }
    }
}

impl AsRef<Aes256Key> for JweA256KWEncipher {
    fn as_ref(&self) -> &Aes256Key {
        &self.wrap_key
    }
}

impl JweEncipherOuterA256 for JweA256KWEncipher {
    fn set_header_alg(&self, hdr: &mut JweProtectedHeader) -> Result<(), JwtError> {
        hdr.alg = JweAlg::A256KW;
        // KeyID is an option, so only embeds if present.
        hdr.kid = self.kid.clone();
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
        Ok(JweA256KWEncipher {
            wrap_key,
            kid: None,
        })
    }

    /// Set the key identifier for this wrapping key.
    pub fn set_kid(&mut self, kid: Option<String>) {
        self.kid = kid;
    }

    /// Enable or disable the embeddidng of a key id during encryption
    pub fn set_sign_option_embed_kid(&mut self, value: bool) {
        if value {
            if self.kid.is_none() {
                self.kid = Some(kid(&self.wrap_key));
            }
        } else {
            self.kid = None
        }
    }

    /// Generate and return a key identifier for this wrapping key
    pub fn get_kid(&self) -> String {
        self.kid.clone().unwrap_or_else(|| kid(&self.wrap_key))
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

/// Generate a key identifier for an AES 256 wrapping key
fn kid(wrap_key: &Aes256Key) -> String {
    let mut skey = HmacSha256Key::default();
    let skey_slice = skey.as_mut_slice();
    let wrap_key_slice = wrap_key.as_slice();
    let skey_slice_mut = &mut skey_slice[..wrap_key_slice.len()];
    skey_slice_mut.copy_from_slice(wrap_key_slice);
    // Key is setup
    let mut hmac = HmacSha256::new(&skey);
    hmac.update(b"key identifier");
    let hashout = hmac.finalize();
    let mut kid = hex::encode(hashout.into_bytes());
    kid.truncate(KID_LEN);
    kid
}
