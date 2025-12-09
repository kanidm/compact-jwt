//! JWS Signing and Verification Structures

use crate::compact::{JweCompact, JweEnc, JwsCompact};
use crate::error::JwtError;
use base64::{engine::general_purpose, Engine as _};
use crypto_glue::aes128::Aes128Key;
use crypto_glue::aes256::Aes256Key;

pub use crypto_glue::{
    traits::{DecodeDer, DecodePem},
    x509::Certificate,
};

// JWS types
mod es256;
mod hs256;
mod rs256;
mod tpm_es256;
mod tpm_rs256;
mod x509;

// JWE types
mod a128gcm;
mod a128kw;
mod a256gcm;
mod a256kw;
mod ecdhes_a256kw;
mod rsaes_oaep;

#[cfg(any(feature = "msextensions", test))]
mod ms_oapxbc;

pub use es256::{JwsEs256Signer, JwsEs256Verifier};
pub use hs256::JwsHs256Signer;
pub use rs256::{JwsRs256Signer, JwsRs256Verifier};
pub use x509::{JwsX509Verifier, JwsX509VerifierBuilder};

pub use a128gcm::JweA128GCMEncipher;
pub use a128kw::JweA128KWEncipher;
pub use a256gcm::JweA256GCMEncipher;
pub use a256kw::JweA256KWEncipher;
pub use ecdhes_a256kw::{JweEcdhEsA256KWDecipher, JweEcdhEsA256KWEncipher};
pub use rsaes_oaep::{JweRSAOAEPDecipher, JweRSAOAEPEncipher};

#[cfg(any(feature = "msextensions", test))]
pub use ms_oapxbc::MsOapxbcSessionKey;

pub use tpm_es256::JwsTpmEs256Signer;
pub use tpm_rs256::JwsTpmRs256Signer;

#[cfg(test)]
impl JwsCompact {
    fn check_vectors(&self, chk_input: &[u8], chk_sig: &[u8]) -> bool {
        let sign_input = format!("{}.{}", self.hdr_b64, self.payload_b64);
        chk_input == sign_input.as_bytes() && chk_sig == self.signature
    }
}

impl JwsCompact {
    /// The chain starts from the signing leaf and proceeds up the ca chain
    /// toward the root.
    ///
    /// return [Ok(None)] if the jws object's header's x5c field isn't populated
    pub fn get_x5c_chain(&self) -> Result<Option<(Certificate, Vec<Certificate>)>, JwtError> {
        let Some(fullchain) = &self.header.x5c else {
            return Ok(None);
        };

        let mut chain_iter = fullchain.iter().map(|value| {
            general_purpose::STANDARD
                .decode(value)
                .map_err(|_| JwtError::InvalidBase64)
                .and_then(|bytes| {
                    Certificate::from_der(&bytes).map_err(|e| {
                        debug!(?e);
                        JwtError::CryptoError
                    })
                })
        });

        let Some(leaf) = chain_iter.next().transpose()? else {
            return Ok(None);
        };

        let fullchain = chain_iter.collect::<Result<Vec<_>, _>>()?;

        Ok(Some((leaf, fullchain)))
    }
}

impl JweEnc {
    pub(crate) fn decipher_inner_a256(
        self,
        aes256key: Aes256Key,
        jwec: &JweCompact,
    ) -> Result<Vec<u8>, JwtError> {
        match self {
            JweEnc::A256GCM => a256gcm::JweA256GCMEncipher::from(aes256key).decipher_inner(jwec),
            JweEnc::A128GCM => Err(JwtError::JweEncMismatch),
        }
    }

    pub(crate) fn decipher_inner_a128(
        self,
        aes128key: Aes128Key,
        jwec: &JweCompact,
    ) -> Result<Vec<u8>, JwtError> {
        match self {
            JweEnc::A128GCM => a128gcm::JweA128GCMEncipher::from(aes128key).decipher_inner(jwec),
            JweEnc::A256GCM => Err(JwtError::JweEncMismatch),
        }
    }
}

#[cfg(test)]
impl JweCompact {
    fn check_vectors(
        &self,
        chk_cek: &[u8],
        chk_iv: &[u8],
        chk_cipher: &[u8],
        chk_aad: &[u8],
    ) -> bool {
        chk_cek == self.content_enc_key
            && chk_iv == self.iv
            && chk_cipher == self.ciphertext
            && chk_aad == self.authentication_tag
    }
}
