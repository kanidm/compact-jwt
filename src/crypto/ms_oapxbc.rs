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

#[cfg(test)]
impl MsOapxbcSessionKey {
    pub(crate) fn assert_key(&self, key: &[u8]) -> bool {
        match self {
            MsOapxbcSessionKey::A256GCM { aes_key, .. } => aes_key.assert_key(key),
        }
    }
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
    use crate::compact::JweCompact;
    use crate::jwe::JweBuilder;
    use base64::{engine::general_purpose, Engine as _};
    use openssl::bn;
    use openssl::pkey::Private;
    use openssl::rsa::Rsa;

    use std::str::FromStr;

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

    fn rsa_from_private_components(
        n: &str,
        e: &str,
        d: &str,
        p: &str,
        q: &str,
        dmp1: &str,
        dmq1: &str,
        iqmp: &str,
    ) -> Rsa<Private> {
        let n = general_purpose::STANDARD.decode(n).expect("Invalid Key");

        let e = general_purpose::STANDARD.decode(e).expect("Invalid Key");

        let d = general_purpose::STANDARD.decode(d).expect("Invalid Key");

        let p = general_purpose::STANDARD.decode(p).expect("Invalid Key");

        let q = general_purpose::STANDARD.decode(q).expect("Invalid Key");

        let dmp1 = general_purpose::STANDARD.decode(dmp1).expect("Invalid Key");

        let dmq1 = general_purpose::STANDARD.decode(dmq1).expect("Invalid Key");

        let iqmp = general_purpose::STANDARD.decode(iqmp).expect("Invalid Key");

        let nbn = bn::BigNum::from_slice(&n).expect("Invalid bignumber");
        let ebn = bn::BigNum::from_slice(&e).expect("Invalid bignumber");
        let dbn = bn::BigNum::from_slice(&d).expect("Invalid bignumber");
        let pbn = bn::BigNum::from_slice(&p).expect("Invalid bignumber");
        let qbn = bn::BigNum::from_slice(&q).expect("Invalid bignumber");

        let dpbn = bn::BigNum::from_slice(&dmp1).expect("Invalid bignumber");
        let dqbn = bn::BigNum::from_slice(&dmq1).expect("Invalid bignumber");
        let dibn = bn::BigNum::from_slice(&iqmp).expect("Invalid bignumber");

        Rsa::from_private_components(nbn, ebn, dbn, pbn, qbn, dpbn, dqbn, dibn)
            .expect("Invalid parameters")
    }

    #[test]
    fn ms_oapxbc_3_2_5_1_3_prt_request_response_0() {
        let _ = tracing_subscriber::fmt::try_init();

        let rsa_priv_key = rsa_from_private_components(
"vs0iOntRizG9fLMQPKw7Y0+OoZxMD4zdvqlDOzN/ziZoidOJw0blep7tET0gUzmI6Dlz5eUq9By1gQbOlm5IHU4FBh+kFhwxN6tLVt94ktYWyiRxsDMUfmSqRhQ10ZL5caA0nLpcTZsNfohbNrqB9d0PNWpqeL//l8bLyvHSq5cZxUoUc2QkiGw4dpZfUCo+YKR17Yi5/g2J2zbIFl2lNbe2detKTEUDWTy0j653/OykHKvT+OQZCIz67CGww68Cu70mvXxgpPczQGmuO/4w2LwuFolVx7xTaNwciXTbBz2NmueNq9TIL/rmp361Rt+CfvYEnucQlmqrv6QtZ0LrJQ==",
"AQAB",
"h0anSvFd2iN05jGKhInUPVANnxVSc//6w4/8Q7/6kC15FqbtWI8uaia9i+hbv8XeBE+flVJKhvLH2Of7lnowFN7Y/wN18dshJggDjV85fFnfpIf8NuGwWQCEHNV9Zs4enunoA2q5wKf7BEgm64GGXMvTWZrOTDhMPc7LdGLJa6+nQMxdwusj+5ISsNKlHFMcZseDfwLpAX5IrxBx8tt5bLC/kAFCIlJ0oFuPoaK0v2MQeitqVkW0Y91pyTPtbfcWg678dhXruIMNrmF0iIP2qV7dDJ/IGK1zu2YYCorDYMndO5yezg9JKX3spVR/ZuxJlSFMz1iLmNiOt2WaPHmJTQ==",
"2e3SZdAkIVFEDu8zXFtjIoSGiLGu/dYOAbDq5NzNAwY5t0c8lzc7MX/FJc3KkCdDxLVuql4Ko/5Pibz1Fzhzxdw8IHTvtI57CAZPsET846RWSS0Q72+gqYFpZOXeW6DPh92CHI8Vb6/5mJewyPVWGBVkvV+lNZeQ4+uMPNRBnj8=",
"4CIc1SL9J7Cp4ewSSrkvf9Bv6vumvR5BeAl0FcMV+p4zF+vln4rOgo61D33oCR9lB3Y0EEHdajXtFQdR5VEi2ZklBpYFtkXGRsFynmQt1u93Kgr1R7moGszxWIZM4qaxB3TIE5hsuquAlzc9oryLYTnHThYcNCSYeR07DdAXJZs=",
"UQ3CHjn+5iFqlb9js+sNgQ4XV4n2ktRlWz2o77wrx/8twjwNjhRtwKhL9BaJS3o/G097vIPDo2D3xjvwUFWfwax69HtpmBcSLVbjlqTiBezeZtMLJHK5J7JJN8zDGgNCjL7XILYa+/JQe++XQfb1sXlrgX+sW7Vmn07BVvJ/AVM=",
"CdUVRLhbOLGEUlfj2YlULxw6vKk7gFJidtybThUX0r276hG8KgqR0qJmCP7x/ex1pyUlVY0+JFmnQ+PlUNUFXVxdhnNwXrWi5Bm6aH5mkGZC6QJADlxzpnFVKRgDKXI8k+IooMtwAaRiaL/QoWH6D1LUjnVj2Vm9opqIq6t0SH8=",
"XbuC2tkaN52TeWF92FMG4aTNs0Di+IOv1quDJYI8P6s06idpAjziOVa3NvDLJ713gElvdEWBLW9pcd/y2sImZOOtSuyD/n/rfLP4hSxc5ELZeJJgQ2J7qDe1Hx9DJnDottMGZ1IgrxX1b2pzs7QHhHXbcZQCuST1TRge5XwFmA0=",
        );

        let expected_session_key = general_purpose::STANDARD
            .decode("iABxOd38zjBiQxjtnbE/TXju06nFDYdriG1PldZ8js0=")
            .unwrap();

        let jwec = JweCompact::from_str("eyJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiUlNBLU9BRVAifQ.p5za0qwCunL67BX-KhEugsNQqIfRcuu0Lxbr9Z2Iz512EP-2JITX2orSlAOU69G6JmHLOxDh0bQJnb6YLvRlbw3mGthPCvlbq6klBGkKAkyNGbcO-9DPETC-cECRHvL4k9t1afZdGT1tP-5JE1vGaA7WB75pQHSYcMCGSmUj0fIOIzbzkHlpH7x6CoMDBYmb0MkcuW2alQViOh8Q_c9uShVv-1kVL5wpHoZAAkv5XJkjEVDZzg1GATSCbmjPm-TLYZyqqRp-kE19ZPkzua9yRpTw0jXuZ-8Qr7keN7q9x6QXypDkU4PAMy5d3TcNzFZ3ThhsLZ75KTbaI8q79F9IFw.hzYgfgpIv1vsv1hz.jQ.aRAXYPkc2q7O7M59YxiQ0Q").unwrap();

        let session_key = MsOapxbcSessionKey::complete_rsa_oaep_key_agreement(rsa_priv_key, &jwec)
            .expect("Failed to fetch the session key");

        assert!(session_key.assert_key(&expected_session_key));
    }
}
