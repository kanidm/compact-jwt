use crate::compact::JweAlg;
use crate::compact::JweCompact;
use crate::compact::JweEnc;
use crate::compact::JweProtectedHeader;
use crate::compact::ProtectedHeader;
use crate::jwe::Jwe;
use crate::JwtError;

use crate::traits::*;

use super::a256gcm::JweA256GCMEncipher;
use super::hs256::JwsHs256Signer;

/// A [MS-OAPXBC] 3.2.5.1.2.2 yielded session key. This is used as a form of key agreement
/// for MS clients, where this CEK can now be used to encipher and decipher arbitrary
/// content. It may also be used for HS256 signatures for requests.
pub enum MsOapxbcSessionKey {
    A256GCM {
        aes_key: JweA256GCMEncipher,
        hmac_key: JwsHs256Signer,
    },
}

impl MsOapxbcSessionKey {
    pub(crate) fn try_from_key_buffer(
        enc: JweEnc,
        key_buffer: &[u8],
    ) -> Result<MsOapxbcSessionKey, JwtError> {
        match enc {
            JweEnc::A256GCM => {
                let aes_key = JweA256GCMEncipher::try_from(key_buffer)?;
                let hmac_key = JwsHs256Signer::try_from(key_buffer)?;

                Ok(MsOapxbcSessionKey::A256GCM { aes_key, hmac_key })
            }
            _ => Err(JwtError::CipherUnavailable),
        }
    }
}

impl MsOapxbcSessionKey {
    pub fn decipher(&self, jwec: &JweCompact) -> Result<Jwe, JwtError> {
        // Alg must be direct.
        if jwec.header.alg != JweAlg::DIRECT {
            return Err(JwtError::AlgorithmUnavailable);
        }

        match &self {
            MsOapxbcSessionKey::A256GCM { aes_key, .. } => {
                // Enc must be a256gcm
                if jwec.header.enc != JweEnc::A256GCM {
                    return Err(JwtError::CipherUnavailable);
                }

                aes_key.decipher_inner(jwec).map(|payload| Jwe {
                    header: jwec.header.clone(),
                    payload,
                })
            }
        }
    }

    pub fn encipher(&self, jwe: &Jwe) -> Result<JweCompact, JwtError> {
        let outer = JweDirect::default();

        match &self {
            MsOapxbcSessionKey::A256GCM { aes_key, .. } => aes_key.encipher_inner(&outer, jwe),
        }
    }
}

#[derive(Default)]
struct JweDirect {}

impl JweEncipherOuter for JweDirect {
    fn set_header_alg(&self, hdr: &mut JweProtectedHeader) -> Result<(), JwtError> {
        hdr.alg = JweAlg::DIRECT;
        Ok(())
    }

    fn wrap_key(&self, _key_to_wrap: &[u8]) -> Result<Vec<u8>, JwtError> {
        Ok(Vec::with_capacity(0))
    }
}

impl JwsSigner for MsOapxbcSessionKey {
    fn get_kid(&self) -> &str {
        match &self {
            MsOapxbcSessionKey::A256GCM { hmac_key, .. } => JwsSigner::get_kid(hmac_key),
        }
    }

    fn update_header(&self, header: &mut ProtectedHeader) -> Result<(), JwtError> {
        match &self {
            MsOapxbcSessionKey::A256GCM { hmac_key, .. } => hmac_key.update_header(header),
        }
    }

    fn sign<V: JwsSignable>(&self, jws: &V) -> Result<V::Signed, JwtError> {
        match &self {
            MsOapxbcSessionKey::A256GCM { hmac_key, .. } => hmac_key.sign(jws),
        }
    }
}

impl JwsVerifier for MsOapxbcSessionKey {
    fn get_kid(&self) -> Option<&str> {
        match &self {
            MsOapxbcSessionKey::A256GCM { hmac_key, .. } => JwsVerifier::get_kid(hmac_key),
        }
    }

    fn verify<V: JwsVerifiable>(&self, jwsc: &V) -> Result<V::Verified, JwtError> {
        match &self {
            MsOapxbcSessionKey::A256GCM { hmac_key, .. } => hmac_key.verify(jwsc),
        }
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn ms_oapxbc_3_2_5_1_3_prt_request_response() {
        // We need some test parameters here.
    }
}
