//! JWS Signing and Verification Structures

use crate::error::JwtError;
use base64::{engine::general_purpose, Engine as _};
use openssl::x509::X509;

use crate::compact::{JweCompact, JweEnc, JwsCompact};

mod es256;
mod hs256;
mod rs256;
mod x509;

mod rsaes_oaep;

mod a128cbc_hs256;
mod a128gcm;
mod a128kw;
mod a256gcm;
mod a256kw;

mod ecdhes_a128kw;

#[cfg(feature = "hsm-crypto")]
mod tpm;

pub use es256::{JwsEs256Signer, JwsEs256Verifier};
pub use hs256::JwsHs256Signer;
pub use rs256::{JwsRs256Signer, JwsRs256Verifier};
pub use x509::{JwsX509Verifier, JwsX509VerifierBuilder};

pub use a128kw::JweA128KWEncipher;
pub use a256kw::JweA256KWEncipher;
pub use ecdhes_a128kw::{JweEcdhEsA128KWDecipher, JweEcdhEsA128KWEncipher};
pub use rsaes_oaep::JweRSAOAEPDecipher;

#[cfg(feature = "hsm-crypto")]
pub use tpm::JwsTpmSigner;

impl JwsCompact {
    #[cfg(test)]
    fn check_vectors(&self, chk_input: &[u8], chk_sig: &[u8]) -> bool {
        let sign_input = format!("{}.{}", self.hdr_b64, self.payload_b64);
        chk_input == sign_input.as_bytes() && chk_sig == &self.signature
    }

    /// The chain starts from the signing leaf and proceeds up the ca chain
    /// toward the root.
    ///
    /// return [Ok(None)] if the jws object's header's x5c field isn't populated
    pub fn get_x5c_chain(&self) -> Result<Option<Vec<X509>>, JwtError> {
        let Some(fullchain) = &self.header.x5c else {
            return Ok(None);
        };

        let fullchain: Result<Vec<_>, _> = fullchain
            .iter()
            .map(|value| {
                general_purpose::STANDARD
                    .decode(value)
                    .map_err(|_| JwtError::InvalidBase64)
                    .and_then(|bytes| {
                        X509::from_der(&bytes).map_err(|e| {
                            debug!(?e);
                            JwtError::OpenSSLError
                        })
                    })
            })
            .collect();

        let fullchain = fullchain?;

        Ok(Some(fullchain))
    }
}

impl JweEnc {
    pub(crate) fn key_len(self) -> usize {
        match self {
            JweEnc::A128GCM => a128gcm::JweA128GCMEncipher::key_len(),
            JweEnc::A256GCM => a256gcm::JweA256GCMEncipher::key_len(),
            JweEnc::A128CBC_HS256 => a128cbc_hs256::JweA128CBCHS256Decipher::key_len(),
        }
    }

    pub(crate) fn decipher_inner(
        self,
        key_buffer: &[u8],
        jwec: &JweCompact,
    ) -> Result<Vec<u8>, JwtError> {
        match self {
            JweEnc::A128GCM => a128gcm::JweA128GCMEncipher::try_from(key_buffer)
                .and_then(|jwe_decipher| jwe_decipher.decipher_inner(jwec)),
            JweEnc::A256GCM => a256gcm::JweA256GCMEncipher::try_from(key_buffer)
                .and_then(|jwe_decipher| jwe_decipher.decipher_inner(jwec)),
            JweEnc::A128CBC_HS256 => a128cbc_hs256::JweA128CBCHS256Decipher::try_from(key_buffer)
                .and_then(|jwe_decipher| jwe_decipher.decipher_inner(jwec)),
        }
    }
}

impl JweCompact {
    #[cfg(test)]
    fn check_vectors(
        &self,
        chk_cek: &[u8],
        chk_iv: &[u8],
        chk_cipher: &[u8],
        chk_aad: &[u8],
    ) -> bool {
        chk_cek == &self.content_enc_key
            && chk_iv == &self.iv
            && chk_cipher == &self.ciphertext
            && chk_aad == &self.authentication_tag
    }
}
