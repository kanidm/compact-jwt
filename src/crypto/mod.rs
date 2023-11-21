//! JWS Signing and Verification Structures

use crate::error::JwtError;
use base64::{engine::general_purpose, Engine as _};
use openssl::x509::X509;

use crate::compact::JwsCompact;
use crate::jws::Jws;
use crate::traits::*;

mod es256;
mod hs256;
mod rs256;
mod x509;

pub use es256::{JwsEs256Signer, JwsEs256Verifier};

pub use hs256::JwsHs256Signer;

pub use rs256::{JwsRs256Signer, JwsRs256Verifier};

pub use x509::{JwsX509Verifier, JwsX509VerifierBuilder};

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
        let fullchain = match &self.header.x5c {
            Some(chain) => chain,
            None => return Ok(None),
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

impl Jws {
    /// Sign the content of this JWS with the provided signer, yielding a compact
    /// signed string.
    pub fn sign<S: JwsSigner>(&self, signer: &mut S) -> Result<JwsCompact, JwtError> {
        let mut header = self.header.clone();

        // Let the signer update the header as required.
        signer.update_header(&mut header)?;

        let hdr_b64 = serde_json::to_vec(&header)
            .map_err(|e| {
                debug!(?e);
                JwtError::InvalidHeaderFormat
            })
            .map(|bytes| general_purpose::URL_SAFE_NO_PAD.encode(&bytes))?;
        let payload_b64 = general_purpose::URL_SAFE_NO_PAD.encode(&self.payload);

        let data = JwsCompactSignData {
            hdr_bytes: hdr_b64.as_bytes(),
            payload_bytes: payload_b64.as_bytes(),
        };

        let signature = signer.sign(data)?;

        Ok(JwsCompact {
            header,
            hdr_b64,
            payload_b64,
            signature,
        })
    }
}
