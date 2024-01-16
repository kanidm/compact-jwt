use crate::compact::{JweAlg, JweCompact, JweEnc, JweProtectedHeader, ProtectedHeader};
use crate::jwe::Jwe;
use crate::JwtError;

use crate::traits::*;

use super::a256gcm::JweA256GCMEncipher;
use super::hs256::JwsHs256Signer;

use super::rsaes_oaep::{JweRSAOAEPDecipher, JweRSAOAEPEncipher};

use crate::jwe::JweBuilder;

use openssl::pkey::Private;
use openssl::pkey::Public;
use openssl::rsa::Rsa;

/// A [MS-OAPXBC] 3.2.5.1.2.2 yielded session key. This is used as a form of key agreement
/// for MS clients, where this key can now be used to encipher and decipher arbitrary
/// content. It may also be used for HS256 signatures for requests.
pub enum MsOapxbcSessionKey {
    /// An AES-256-GCM + HS256 session key
    A256GCM {
        /// The aes key for this session
        aes_key: JweA256GCMEncipher,
        /// the hmac key for this session
        hmac_key: JwsHs256Signer,
    },
}

impl MsOapxbcSessionKey {
    /// Given a public key, create a derived session key. This is the "server side"
    /// component for this process.
    pub fn begin_rsa_oaep_key_agreement(
        rsa_pub_key: Rsa<Public>,
    ) -> Result<(Self, JweCompact), JwtError> {
        /*
        let rsa_pub_key = PKey::from_rsa(value).map_err(|ossl_err| {
            debug!(?ossl_err);
            JwtError::OpenSSLError
        })?;
        */

        let rsa_oaep = JweRSAOAEPEncipher::try_from(rsa_pub_key)?;

        let aes_key = JweA256GCMEncipher::new_ephemeral()?;
        let hmac_key = JwsHs256Signer::try_from(aes_key.ms_oapxbc_key())?;

        // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-oapxbc/d3f8893c-a715-412a-97d1-5ffed2c3b3d5
        // session_key_jwe does not seem to have many requirements?
        let jweb = JweBuilder::from(Vec::with_capacity(0)).build();

        let jwec = aes_key.encipher_inner(&rsa_oaep, &jweb)?;

        Ok((MsOapxbcSessionKey::A256GCM { aes_key, hmac_key }, jwec))
    }

    /// Given a session jwe, complete the session key derivation with this private key
    pub fn complete_rsa_oaep_key_agreement(
        rsa_priv_key: Rsa<Private>,
        jwec: &JweCompact,
    ) -> Result<Self, JwtError> {
        // May become a trait later?
        let rsa_oaep = JweRSAOAEPDecipher::try_from(rsa_priv_key)?;

        let unwrapped_key = rsa_oaep.unwrap_key(jwec)?;

        // May also need to make this output type a trait too, so we can store
        // this key in some secure way?
        match jwec.header.enc {
            JweEnc::A256GCM => {
                let aes_key = JweA256GCMEncipher::try_from(unwrapped_key.as_slice())?;
                let hmac_key = JwsHs256Signer::try_from(unwrapped_key.as_slice())?;

                Ok(MsOapxbcSessionKey::A256GCM { aes_key, hmac_key })
            }
            _ => Err(JwtError::CipherUnavailable),
        }
    }
}

impl MsOapxbcSessionKey {
    /// Given a JWE in compact form, decipher and authenticate its content.
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

    /// Given a JWE, encipher its content to a compact form.
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
    use super::MsOapxbcSessionKey;
    use crate::jwe::JweBuilder;
    use openssl::rsa::Rsa;

    #[test]
    fn ms_oapxbc_reflexive_test() {
        let _ = tracing_subscriber::fmt::try_init();

        let rsa_priv_key = Rsa::generate(2048).unwrap();
        let rsa_pub_key = Rsa::from_public_components(
            rsa_priv_key.n().to_owned().unwrap(),
            rsa_priv_key.e().to_owned().unwrap(),
        )
        .unwrap();

        let (server_key, jwec) =
            MsOapxbcSessionKey::begin_rsa_oaep_key_agreement(rsa_pub_key).unwrap();

        let client_key =
            MsOapxbcSessionKey::complete_rsa_oaep_key_agreement(rsa_priv_key, &jwec).unwrap();

        let input = vec![1; 256];
        let jweb = JweBuilder::from(input.clone()).build();

        let jwe_encrypted = client_key.encipher(&jweb).expect("Unable to encrypt.");

        // Decrypt with the partner.
        let decrypted = server_key
            .decipher(&jwe_encrypted)
            .expect("Unable to decrypt.");

        assert_eq!(decrypted.payload(), input);
    }

    #[test]
    fn ms_oapxbc_3_2_5_1_3_prt_request_response() {
        // We need some test params!
    }
}
