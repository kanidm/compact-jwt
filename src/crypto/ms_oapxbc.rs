use crate::compact::{JweAlg, JweCompact, JweEnc, JweProtectedHeader, ProtectedHeader};
use crate::jwe::Jwe;
use crate::JwtError;

use crate::traits::*;

use super::a256gcm::{JweA256GCMEncipher, KEY_LEN as A256_KEY_LEN};
use super::hs256::JwsHs256Signer;

use super::rsaes_oaep::{JweRSAOAEPDecipher, JweRSAOAEPEncipher};

use crate::jwe::JweBuilder;

use openssl::hash::MessageDigest;
use openssl::pkey::Private;
use openssl::pkey::Public;
use openssl::rand;
use openssl::rsa::Rsa;
use openssl::symm::Cipher;

use base64::{engine::general_purpose, Engine as _};

const AAD_KDF_LABEL: &[u8; 26] = b"AzureAD-SecureConversation";
const CTX_NONCE_LEN: usize = 32;

/// A [MS-OAPXBC] 3.2.5.1.2.2 yielded session key. This is used as a form of key agreement
/// for MS clients, where this key can now be used to encipher and decipher arbitrary
/// content. It may also be used for HS256 signatures for requests.
pub enum MsOapxbcSessionKey {
    /// An AES-256-GCM/CBC + HS256 session key
    A256GCM {
        /// The aes key for this session
        aes_key: [u8; A256_KEY_LEN],
    },
}

#[cfg(test)]
impl MsOapxbcSessionKey {
    pub(crate) fn assert_key(&self, key: &[u8]) -> bool {
        match self {
            MsOapxbcSessionKey::A256GCM { aes_key, .. } => aes_key == key,
        }
    }
}

impl MsOapxbcSessionKey {
    /// Given a public key, create a derived session key. This is the "server side"
    /// component for this process.
    pub fn begin_rsa_oaep_key_agreement(
        rsa_pub_key: Rsa<Public>,
    ) -> Result<(Self, JweCompact), JwtError> {
        let rsa_oaep = JweRSAOAEPEncipher::try_from(rsa_pub_key)?;

        let aes_key = JweA256GCMEncipher::new_ephemeral()?;

        // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-oapxbc/d3f8893c-a715-412a-97d1-5ffed2c3b3d5
        // session_key_jwe does not seem to have many requirements?
        let jweb = JweBuilder::from(Vec::with_capacity(0)).build();
        let jwec = aes_key.encipher_inner(&rsa_oaep, &jweb)?;

        // Extract the raw key.
        let aes_key = aes_key.raw_key();

        Ok((MsOapxbcSessionKey::A256GCM { aes_key }, jwec))
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
                if unwrapped_key.len() != A256_KEY_LEN {
                    return Err(JwtError::InvalidKey);
                }

                let mut aes_key = [0u8; A256_KEY_LEN];
                aes_key.copy_from_slice(&unwrapped_key);

                Ok(MsOapxbcSessionKey::A256GCM { aes_key })
            }
            _ => Err(JwtError::CipherUnavailable),
        }
    }
}

impl MsOapxbcSessionKey {
    pub fn decipher_prt_v2(&self, jwec: &JweCompact) -> Result<Jwe, JwtError> {
        let ctx_bytes = if let Some(ctx) = &jwec.header.ctx {
            general_purpose::STANDARD
                .decode(ctx)
                .map_err(|_| JwtError::InvalidBase64)?
        } else {
            return Err(JwtError::InvalidPRT);
        };

        let derived_key = match &self {
            MsOapxbcSessionKey::A256GCM { aes_key } => {
                nist_sp800_108_kdf_hmac_sha256(aes_key, &ctx_bytes, AAD_KDF_LABEL, A256_KEY_LEN)?
            }
        };

        let cipher = Cipher::aes_256_cbc();
        let payload =
            super::a128cbc_hs256::decipher(cipher, &derived_key, &jwec.ciphertext, &jwec.iv)?;

        Ok(Jwe {
            header: jwec.header.clone(),
            payload,
        })
    }

    /// Given a JWE in compact form, decipher and authenticate its content.
    pub fn decipher(&self, jwec: &JweCompact) -> Result<Jwe, JwtError> {
        // Alg must be direct.
        if jwec.header.alg != JweAlg::DIRECT {
            return Err(JwtError::AlgorithmUnavailable);
        }

        match &self {
            MsOapxbcSessionKey::A256GCM { aes_key, .. } => {
                // Seems that this can mean AES256GCM or AES256CBC
                if jwec.header.enc != JweEnc::A256GCM {
                    return Err(JwtError::CipherUnavailable);
                }

                let a256gcm = JweA256GCMEncipher::from(aes_key);

                a256gcm.decipher_inner(jwec).map(|payload| Jwe {
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
            MsOapxbcSessionKey::A256GCM { aes_key } => {
                let a256gcm = JweA256GCMEncipher::from(aes_key);

                a256gcm.encipher_inner(&outer, jwe)
            }
        }
    }

    /// Directly use the session key to perform a HMAC signature over a JWS.
    pub fn sign_direct<V: JwsSignable>(&self, jws: &V) -> Result<V::Signed, JwtError> {
        let hmac_key = match self {
            MsOapxbcSessionKey::A256GCM { aes_key } => {
                JwsHs256Signer::try_from(aes_key.as_slice())?
            }
        };

        hmac_key.sign(jws)
    }

    /// Use the session key to derive a one-time HMAC key for signing this JWS.
    pub fn sign<V: JwsSignable>(&self, jws: &V) -> Result<V::Signed, JwtError> {
        let mut nonce = [0; CTX_NONCE_LEN];
        rand::rand_bytes(&mut nonce).map_err(|e| {
            error!("{:?}", e);
            JwtError::OpenSSLError
        })?;

        let derived_key = match &self {
            MsOapxbcSessionKey::A256GCM { aes_key } => {
                nist_sp800_108_kdf_hmac_sha256(aes_key, &nonce, AAD_KDF_LABEL, A256_KEY_LEN)?
            }
        };

        let hmac_key = JwsHs256Signer::try_from(derived_key.as_slice())?;

        let mut signer = MsOapxbcSessionKeyHs256 { nonce, hmac_key };

        signer.sign(jws)
    }

    pub fn verify<V: JwsVerifiable>(&self, jwsc: &V) -> Result<V::Verified, JwtError> {
        let hmac_key = if let Some(ctx) = &jwsc.data().header.ctx {
            let ctx_bytes = general_purpose::STANDARD
                .decode(ctx)
                .map_err(|_| JwtError::InvalidBase64)?;

            let derived_key = match &self {
                MsOapxbcSessionKey::A256GCM { aes_key } => nist_sp800_108_kdf_hmac_sha256(
                    aes_key,
                    &ctx_bytes,
                    AAD_KDF_LABEL,
                    A256_KEY_LEN,
                )?,
            };

            JwsHs256Signer::try_from(derived_key.as_slice())?
        } else {
            // Assume direct signature.
            match self {
                MsOapxbcSessionKey::A256GCM { aes_key } => {
                    JwsHs256Signer::try_from(aes_key.as_slice())?
                }
            }
        };

        hmac_key.verify(jwsc)
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

struct MsOapxbcSessionKeyHs256 {
    nonce: [u8; CTX_NONCE_LEN],
    hmac_key: JwsHs256Signer,
}

impl JwsSigner for MsOapxbcSessionKeyHs256 {
    fn get_kid(&self) -> &str {
        JwsSigner::get_kid(&self.hmac_key)
    }

    fn update_header(&self, header: &mut ProtectedHeader) -> Result<(), JwtError> {
        let ctx = general_purpose::STANDARD.encode(self.nonce);
        header.ctx = Some(ctx);

        self.hmac_key.update_header(header)
    }

    fn sign<V: JwsSignable>(&self, jws: &V) -> Result<V::Signed, JwtError> {
        let mut sign_data = jws.data()?;

        // Let the signer update the header as required.
        self.update_header(&mut sign_data.header)?;

        self.hmac_key.sign_inner(jws, sign_data)
    }
}

pub(crate) fn nist_sp800_108_kdf_hmac_sha256(
    key: &[u8],
    ctx: &[u8],
    label: &[u8],
    derive_len: usize,
) -> Result<Vec<u8>, JwtError> {
    use openssl_kdf::{perform_kdf, KdfArgument, KdfKbMode, KdfMacType, KdfType};

    let args = [
        &KdfArgument::KbMode(KdfKbMode::Counter),
        &KdfArgument::Mac(KdfMacType::Hmac(MessageDigest::sha256())),
        &KdfArgument::Salt(label),
        &KdfArgument::KbInfo(ctx),
        &KdfArgument::Key(key),
    ];
    perform_kdf(KdfType::KeyBased, &args, derive_len).map_err(|ossl_err| {
        error!(?ossl_err, "Unable to derive session key");
        JwtError::OpenSSLError
    })
}

#[cfg(test)]
mod tests {
    use super::MsOapxbcSessionKey;
    use crate::compact::JweCompact;
    use crate::jwe::JweBuilder;
    use crate::jws::JwsBuilder;
    use base64::{engine::general_purpose, Engine as _};
    use openssl::bn;
    use openssl::pkey::Private;
    use openssl::rsa::Rsa;

    use std::str::FromStr;

    #[test]
    fn ms_oapxbc_reflexive_encryption_test() {
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
    fn ms_oapxbc_reflexive_signature_test() {
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
        let jws = JwsBuilder::from(input.clone()).build();

        let jws_signed = client_key.sign(&jws).expect("Unable to sign.");

        // Decrypt with the partner.
        let verified = server_key.verify(&jws_signed).expect("Unable to verify.");

        assert_eq!(verified.payload(), input);
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

    #[test]
    fn ms_oapxbc_3_2_5_1_3_3_exchange_request_response() {
        let rsa_priv_key = Rsa::private_key_from_der(&[
            48, 130, 4, 162, 2, 1, 0, 2, 130, 1, 1, 0, 180, 132, 214, 68, 242, 2, 15, 193, 241,
            133, 64, 208, 45, 231, 251, 49, 253, 121, 19, 203, 105, 62, 13, 89, 4, 105, 29, 59,
            113, 117, 198, 67, 106, 211, 221, 61, 249, 122, 211, 236, 84, 189, 106, 75, 28, 107,
            115, 188, 182, 42, 206, 247, 212, 184, 20, 194, 255, 198, 140, 134, 182, 45, 103, 203,
            15, 193, 156, 230, 19, 6, 88, 14, 189, 71, 99, 219, 9, 214, 232, 118, 187, 219, 63,
            234, 207, 69, 168, 173, 163, 87, 219, 40, 147, 219, 251, 156, 152, 114, 200, 171, 202,
            111, 25, 161, 92, 74, 98, 62, 156, 184, 187, 239, 19, 236, 177, 65, 214, 18, 140, 30,
            108, 179, 151, 59, 63, 19, 233, 98, 54, 244, 112, 3, 234, 68, 29, 47, 46, 170, 168, 55,
            99, 20, 94, 226, 74, 59, 32, 122, 36, 191, 120, 87, 150, 36, 136, 199, 253, 228, 158,
            170, 131, 52, 228, 224, 150, 94, 135, 157, 151, 133, 135, 49, 16, 208, 49, 192, 156, 7,
            26, 239, 136, 146, 170, 95, 77, 36, 236, 254, 76, 202, 167, 44, 60, 165, 60, 206, 12,
            240, 211, 93, 173, 190, 47, 23, 202, 149, 140, 251, 71, 219, 45, 195, 146, 61, 178, 73,
            174, 79, 63, 6, 204, 252, 183, 57, 128, 111, 122, 249, 83, 217, 196, 226, 128, 153,
            135, 160, 247, 169, 211, 86, 97, 66, 172, 231, 95, 44, 166, 230, 39, 98, 218, 39, 181,
            10, 208, 115, 2, 3, 1, 0, 1, 2, 130, 1, 0, 38, 196, 40, 39, 162, 57, 35, 29, 41, 58,
            206, 146, 102, 105, 93, 30, 125, 42, 149, 63, 167, 152, 53, 209, 154, 10, 224, 198, 53,
            53, 111, 160, 102, 190, 156, 210, 132, 83, 6, 83, 200, 86, 237, 14, 184, 73, 179, 15,
            33, 167, 203, 206, 153, 21, 247, 15, 113, 82, 56, 55, 109, 196, 14, 120, 35, 40, 23, 3,
            169, 174, 65, 22, 217, 59, 13, 140, 170, 110, 70, 121, 201, 25, 234, 126, 8, 137, 19,
            18, 70, 243, 197, 18, 207, 189, 252, 40, 194, 236, 83, 127, 224, 247, 62, 239, 210, 27,
            255, 65, 38, 242, 221, 25, 24, 148, 73, 244, 179, 126, 68, 44, 252, 119, 12, 209, 34,
            88, 170, 83, 154, 209, 107, 228, 80, 231, 39, 249, 205, 103, 213, 138, 133, 245, 83,
            84, 82, 95, 221, 243, 123, 123, 144, 8, 4, 68, 97, 44, 252, 100, 61, 68, 121, 183, 114,
            42, 58, 209, 126, 131, 235, 115, 7, 198, 121, 159, 60, 17, 216, 44, 245, 48, 32, 228,
            130, 67, 242, 51, 217, 179, 77, 179, 231, 30, 178, 230, 206, 3, 102, 22, 168, 111, 225,
            232, 3, 177, 209, 177, 248, 86, 71, 83, 34, 47, 104, 201, 229, 103, 17, 127, 24, 147,
            155, 244, 137, 73, 208, 91, 170, 166, 68, 171, 107, 143, 25, 115, 177, 75, 116, 21, 9,
            190, 66, 172, 24, 124, 243, 6, 118, 200, 49, 111, 202, 99, 88, 123, 48, 65, 2, 129,
            129, 0, 220, 106, 58, 194, 121, 84, 72, 0, 245, 164, 109, 189, 224, 0, 5, 202, 64, 199,
            210, 146, 210, 119, 130, 40, 114, 191, 240, 158, 255, 6, 50, 128, 126, 88, 225, 114,
            227, 76, 215, 152, 181, 71, 210, 247, 117, 126, 193, 94, 175, 139, 243, 136, 194, 7,
            253, 195, 131, 190, 16, 67, 28, 19, 95, 242, 29, 156, 35, 25, 13, 179, 81, 222, 94,
            154, 249, 51, 194, 79, 198, 238, 193, 37, 207, 249, 120, 223, 142, 195, 231, 2, 126,
            87, 115, 233, 156, 67, 239, 73, 154, 180, 6, 231, 109, 207, 154, 69, 172, 204, 250, 82,
            18, 208, 233, 29, 78, 206, 213, 0, 14, 49, 77, 58, 49, 179, 128, 176, 216, 131, 2, 129,
            129, 0, 209, 169, 179, 15, 57, 54, 174, 237, 187, 217, 174, 225, 163, 99, 12, 143, 0,
            136, 185, 199, 146, 157, 229, 228, 216, 188, 89, 218, 173, 221, 216, 190, 44, 94, 92,
            172, 37, 3, 121, 183, 55, 6, 5, 138, 152, 254, 193, 59, 212, 144, 189, 2, 84, 207, 21,
            20, 198, 117, 115, 184, 83, 195, 115, 69, 111, 76, 5, 121, 252, 251, 212, 250, 67, 174,
            19, 178, 136, 10, 56, 107, 160, 159, 0, 138, 51, 25, 180, 196, 85, 147, 92, 254, 71,
            239, 250, 16, 238, 55, 25, 248, 29, 206, 16, 227, 150, 164, 145, 7, 196, 186, 87, 185,
            207, 180, 62, 99, 255, 185, 210, 230, 176, 8, 54, 5, 87, 105, 69, 81, 2, 129, 128, 28,
            62, 136, 149, 15, 19, 27, 190, 243, 187, 68, 76, 198, 125, 122, 64, 118, 152, 164, 133,
            39, 239, 36, 128, 166, 99, 174, 35, 209, 174, 43, 158, 135, 146, 64, 33, 134, 186, 252,
            13, 151, 125, 66, 173, 111, 34, 245, 8, 123, 26, 69, 244, 202, 88, 87, 206, 75, 253,
            120, 252, 0, 135, 3, 14, 117, 120, 226, 142, 125, 80, 243, 54, 185, 140, 198, 78, 57,
            162, 27, 109, 208, 214, 85, 150, 52, 69, 1, 120, 93, 11, 214, 192, 194, 27, 183, 104,
            133, 43, 59, 101, 194, 84, 185, 159, 150, 183, 66, 243, 105, 72, 71, 28, 250, 34, 69,
            76, 255, 194, 104, 15, 45, 68, 61, 198, 48, 193, 120, 157, 2, 129, 128, 117, 136, 159,
            83, 130, 108, 80, 69, 255, 79, 185, 196, 205, 246, 33, 189, 44, 188, 121, 1, 19, 5, 39,
            50, 81, 249, 204, 153, 85, 108, 143, 43, 148, 237, 213, 31, 191, 164, 34, 32, 126, 93,
            6, 208, 58, 146, 93, 186, 239, 159, 176, 5, 85, 139, 189, 50, 167, 74, 130, 115, 171,
            169, 94, 190, 102, 245, 4, 0, 237, 188, 51, 25, 148, 197, 74, 79, 132, 9, 206, 181, 47,
            22, 211, 147, 165, 175, 220, 113, 79, 211, 203, 134, 212, 199, 7, 181, 100, 5, 73, 174,
            152, 238, 194, 243, 2, 169, 0, 144, 141, 77, 53, 14, 122, 12, 126, 9, 74, 251, 93, 234,
            106, 118, 63, 234, 96, 165, 39, 241, 2, 129, 128, 101, 0, 61, 113, 89, 16, 12, 14, 127,
            57, 211, 173, 235, 157, 78, 118, 110, 41, 70, 79, 208, 145, 32, 32, 144, 250, 200, 109,
            90, 66, 201, 50, 25, 170, 48, 225, 118, 175, 228, 0, 102, 86, 95, 123, 111, 120, 121,
            78, 49, 37, 59, 106, 254, 19, 105, 136, 187, 61, 213, 105, 181, 162, 100, 239, 52, 41,
            104, 175, 98, 131, 254, 194, 168, 251, 182, 153, 221, 73, 237, 90, 135, 181, 45, 28,
            104, 197, 69, 216, 9, 96, 115, 85, 165, 103, 109, 134, 177, 135, 173, 7, 86, 36, 75,
            180, 161, 83, 195, 85, 135, 24, 224, 121, 20, 228, 3, 47, 17, 209, 55, 54, 214, 227,
            219, 73, 234, 251, 50, 145,
        ])
        .unwrap();

        let session_key_jwe = JweCompact::from_str("eyJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiUlNBLU9BRVAifQ.U95cslQ5YAV7FuQsTF45pcHpgpKCI8arJlz6IXbsXr2flZ4tpuO39dYHKZUXXrufObnvSe04Yetuk5osnL5E9EX7b3cWKDkLwo-KK7iT6B5i_XVbtUUBE87x3UfL8N-rUxIeW-Pyky5DzbZ7hsEkrbjgM16DTCIFucItvjwfJctL3ZTfUMIUrVDq1FjOhXrwu3Wrodi7sLm84lpLX_VQ7cqfmzPWfr-7FFtmJzj99rWDJPOM6ynucDbTxxjKeoW6Ft4EMna3_qdqw1A9_7PFDXSsprjJSGbbCvYhiSgib3k8JKKXr-uEGqyIERV0ajw-oJLHWUyuuu3EWlQul-urOg.KSGiTmZY4a8E4dRF.Gg.FYVcZT1WdLkRKABMOL5wyA").unwrap();
        let session_key =
            MsOapxbcSessionKey::complete_rsa_oaep_key_agreement(rsa_priv_key, &session_key_jwe)
                .unwrap();

        let enc_access_token = JweCompact::from_str("eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwiY3R4IjoiVVFvcWtvUldYNVFoNnpTbkV2V09aWVgyTXd1QVB4dkQifQ..uAgdAx7E8-rH7xdQDiJVzg.WRDzuK4NGxFjxdKfnzhcWB_Prx5OxkN5b5XLiPoQtkuZIxCaCAqFAe03QmGz60Io6T3e-LKa3mZ2yD62ZY98957_f7yr8ohFeZfCokwl0M5UpsmeVALEB2d-gLUld3hChFJPXcBwexrNkOnIy2gkqrvvvd_L1HooKQbtD7CXuAdKA1Vhpm4zfqSXOjLqoWcAiybdjd8fUwvgY_W0P_giIJh9qkkOGoF_WXXH8zmQ2ZSk9YmjQXH2LH_VzV9UUmpnRzicx6Wp42IpLEf16YNyO62186Z1GVbchxGV7xY4gT-0bVmjvRrXO91XpM-Jf6hmXXnnp-AfQuqISo3D937TjSiBrCE3MVpb5lJFI3M2Sib3ELez71JEVlqKV4vMY9_xRBnRx9qGFKLpI5rZPk660rgD7Uj6UwyMCodJAJWBycjhc2QekDgVFuyMpuG57u8FdV9wyVaE2STTk0in5f5EoYGzXBIo5QzhMJqvXlm_MjyiG4M3YikfcGIIPODpx7dLL15I-CrHGg2ynOPP0_AEUdkfzM0IXN8KxHoyqGh891LqBMvOyfIKg2gj1FA3S919bLBCvFmh4YLdC1xjHoYayxL44dmL-2vrhJS45nG3LhcTShXHZfeP3IM_qbZ-FFqXnBmj-c9tiEqrTfS1ihHyPAgmpBNWjNBgX2BxCWrwxinMLNeXsosrylUvPuCNTcoEJBIzVmrlw03CZldno3Js7Y_MLuLmYXTU6Kblp0dtz-U7HpCZ3H9L2M5UwbLcBXkxng-86vB3wBA77QkRC5lYuBTS0LSvze_bNzDtB8cZ6eFM57iIwa0NnZp2ocGxEXYs6EBxuqlRjIKyrjndowkbkkXAh4pExFdkQPGPbeN6SKaaGeZkFgegEzZIiCNzXvkT33TlYWXYtUzNwdUlqvI56zlQ2-ZtC2D898mekW3ergJoB0vKNxBqux-d0kJLLH6YidZuA4xl7E3aYXgcDUbgLBlS8PXnsxNLU4lqFg-tx8_MYYCVVFrlsp2_uY6GyS0ooEEWI_FvebyqAGhtJRPiCJkrwcHcTEX9byTuOjI7Axt6eSo6Cg6t3pVOfyY5uBM-Z-s1pxeDiEjl-D9GbxoxnTB-oGYq6P6u4uG6OEByT79sHo1flReOoOLh4MQ4dkaR0OHS6bzZyUjeEIuT6vyuzBWGV8uGlzYYXfX4QujsMTQM-20A8X_84OWq6KwsBJC790VaTdSK0AWWPHMRIDfAgNksr9W9Bnn2mGhDcUrquy8sBaFw6S8qlckG2uM7Rm_QvUxHV-4z_tvhdLObRs_3_dSo15qZTO2pPdCYu89tSkuLg6v-NHb9nPgVztcJdePDYw1ZHwIr0ha_HSjO3zIM36aJ16JN0qh9vcaZVe8KrKka2y9JMi0EZPvMnL9t78IIJB3sDU1ZTluq1KdA-4UnCo_BCo82W74oTcF_peKnaEI9VawsLelZuqH6qNAz510wRc72hIiPb6od4h7m8r5OLNAzmzMSKj3tK6OnHbht52ci5jXcNO9Z_0QW6R72HFPvEUlXjzBsNhM6pg8Zap3U8-dTkMfmblFkHSGu4cwvB-uTUsfGJ9q4QZLaTA_fekAVqHYedhsf20jbtbvA3b3ugLqza3Kb0QIAmO7EfeFmg-qSBZP4prLCyMNZ4IQdyOscJ1LGtFm2rkxNwQyOSqFNmvET81C9lud2TnikD4_6k3_vhpl4hvgMrm0uj9U170RgTi9ZCewwxochnf8qmmi8mFc9b6uFHLtdtAbIC4u8vsVwDG_gyBiVVi68saMgpwwT_ZYDLBA4hJvqM3M9sUB2RJYoBATlT_0WjIRXNBzhp8hdkdqrwERvjBC1cKH2XalPqYHI7aQoTZfKXvJnMTsKVraXiQ6TcWBhbfTyscUAc88O3z-0CRUv0Cn0APcgSUyaKtPQuG3bVKmfh0W8RittX3iPyIKMLsQmugQMqHg5SihIMoshvlrMXnmANwQ0L0qJYtHb2nFR4OoPaL7zE8Jo9vwxS4CaxE13VZt3Xj5_FtAgXaPoq0pVm1I0xJ-B3KkMa65mN_PmuORJGfRqODlr_x0JrDPGvByYVvy11prUPBRM9pOQBa9y3Xintx_xiR-0uVDhmPPdhgkarm074Fkfj7sNxicx2NIOT6QMlh6m_VXAwE0fxEUb_PRBQl-El02PgQcOlZZ1_JGrlxERFcX8cchBZQwmbMCGABHrnChuhoR-l_-aU_oeGVHWjXD_dq57MUmsuXoe2s48X073Y4hhXjedvloOGyod7WFc4VSB0uo3ipKnwkwuarw9b_4q0epU3mhybyQpqDys-qSAPucdyOVf9knttKG4s4zNDffdxPxZLKQfSgNKg11oI0zcrQYIfBDerzRW9VECihy64GWEGZvZ88pgHuDhbva8DtZf8MVLEG9kB3ZpuYXu3vvfgoZ209YdOF-9RoQaQuu1pFGGyVcGHWuELIreUw9uRlKKhwcih_jTqLT6e7S4KtS5Dck3t56npdx9iIauxocbos3sWke88faO5ZhUmc7E5Wy-f-jtFTjm9UaZdGsru1izJEuv.").unwrap();

        let decrypted = session_key.decipher_prt_v2(&enc_access_token).unwrap();

        let expected_payload = b"{\"token_type\":\"Bearer\",\"expires_in\":\"1209599\",\"ext_expires_in\":\"0\",\"expires_on\":\"1708017084\",\"refresh_token\":\"0.AbcAblw1aGMKLUSi7HHMa7PiS4c7qjhtoBdIsnV6MWmI2TvJACY.AgABAAEAAAAmoFfGtYxvRrNriQdPKIZ-AgDs_wUA9P8JhDh2ZGgZJMbl8WvzRwn4FQN698G15Fhng20zMjR1OMFAuR65vnyoEvf7kZdIVik54ljWvg7vG7h23Sret_RYtkAS1MnXKy-eHXQDTuZm-Z5JzqfHZO-3JMChedsjVMJkhU_TpS5hFnN1VW8OLifZNaZMDY0W-iWxeKMQ9wnXlBLaCR8ZgLYYGF7k64N5fK3nYSIexeLkom-cGOP0st08M-N4teht4j811BmJIFkl2AzJEpuUU_DmZHPUyOiK_GXopSehpddw3xwCgZ7DF6rxEjKPP33REQE3LjZAtZWuOtH_9QeKzkD_YyExajvU8-liszws8d0yAvi2W4KeMKfAy8LR05CFGQAB0H380xx3IoBsVykiOLVeWU0eBLDePFKqYQCjXY9N_VTmkPovFwyKK-LuPKmJQ_03p30dk6b6xhJIpiy8G1PiHcObIMD6e8WsdlCbdvVhDk5x65G4ReecCLD0wpVpATVO2k9lJcnUTUugySkQtmW-AJDPsH5Yn-SsG75TZ2F1EB2fWG3DOd0k_HBSzvijostQUl6U0hwzwR2KO5Av7i_1SpQDn8MhgClAqyTwqxYU4g4RdqvadhIq6LWzmkq_T-FzkmIrcRV8nDetEtrdNJcbt0MxfryeByPkH_9F8Sql1YMdSFOatURvgb6WXRxqVEvYr4R7MppzTvuSc07jOMjAiI1DVCnxPHjEtd0NsTWFqQ0UIuOehYeT36v7_3CPhIGPjm6NkjlpPf2xOqHpbRGuGC748FadhdocjMXUzGtqQ6c4sk-tv2JXzQ\",\"refresh_token_expires_in\":1209599,\"id_token\":\"eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJhdWQiOiIzOGFhM2I4Ny1hMDZkLTQ4MTctYjI3NS03YTMxNjk4OGQ5M2IiLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC82ODM1NWM2ZS0wYTYzLTQ0MmQtYTJlYy03MWNjNmJiM2UyNGIvIiwiaWF0IjoxNzA2ODA3MTg0LCJuYmYiOjE3MDY4MDcxODQsImV4cCI6MTcwNjgxMTA4NCwiYW1yIjpbInB3ZCIsInJzYSJdLCJpcGFkZHIiOiI2OS4xNjMuNjYuOTYiLCJuYW1lIjoiVHV4Iiwib2lkIjoiOTBkNjc1ZGYtYmZhOC00ZDc4LThmOGYtN2IxMDQzMTgxYmI2IiwicHdkX3VybCI6Imh0dHBzOi8vcG9ydGFsLm1pY3Jvc29mdG9ubGluZS5jb20vQ2hhbmdlUGFzc3dvcmQuYXNweCIsInJoIjoiMC5BYmNBYmx3MWFHTUtMVVNpN0hITWE3UGlTNGM3cWpodG9CZElzblY2TVdtSTJUdkpBQ1kuIiwic3ViIjoiN1JoODRvOXlzSjZ3bjMwNFBFSTl1UDJ6R2Nzc05jb3lwLWp3YmR5VWxlTSIsInRlbmFudF9kaXNwbGF5X25hbWUiOiJNU0ZUIiwidGlkIjoiNjgzNTVjNmUtMGE2My00NDJkLWEyZWMtNzFjYzZiYjNlMjRiIiwidW5pcXVlX25hbWUiOiJ0dXhAMTBmcDd6Lm9ubWljcm9zb2Z0LmNvbSIsInVwbiI6InR1eEAxMGZwN3oub25taWNyb3NvZnQuY29tIiwidmVyIjoiMS4wIn0.\"}";
        assert!(decrypted.payload == expected_payload);
    }

    /*
    #[test]
    fn ms_oapxbc_3_2_5_1_3_prt_request_response_1() {
        let _ = tracing_subscriber::fmt::try_init();

        let rsa_priv_key = Rsa::private_key_from_der(&[
            48, 130, 4, 163, 2, 1, 0, 2, 130, 1, 1, 0, 191, 143, 29, 122, 36, 141, 175, 52, 119,
            240, 95, 222, 55, 208, 8, 107, 72, 65, 77, 191, 241, 26, 139, 79, 181, 67, 75, 0, 18,
            44, 117, 3, 120, 150, 37, 29, 217, 197, 134, 61, 206, 186, 138, 129, 92, 66, 146, 137,
            240, 119, 57, 13, 24, 194, 133, 174, 131, 11, 50, 184, 174, 170, 99, 40, 217, 58, 200,
            202, 59, 179, 164, 199, 10, 27, 15, 74, 6, 67, 154, 209, 38, 53, 166, 148, 86, 109,
            119, 100, 79, 228, 116, 102, 159, 120, 226, 123, 225, 90, 242, 195, 29, 221, 120, 176,
            226, 91, 209, 179, 17, 201, 25, 34, 157, 139, 199, 152, 218, 25, 69, 144, 61, 239, 217,
            191, 223, 242, 94, 89, 180, 62, 148, 107, 106, 251, 96, 74, 23, 243, 145, 66, 164, 233,
            87, 19, 202, 19, 26, 104, 121, 25, 96, 118, 6, 229, 89, 243, 125, 253, 79, 149, 75,
            247, 162, 99, 59, 188, 182, 247, 8, 201, 246, 112, 26, 31, 119, 190, 254, 180, 84, 13,
            250, 50, 117, 236, 82, 31, 160, 223, 185, 220, 64, 118, 169, 64, 107, 54, 205, 141,
            145, 208, 144, 255, 214, 143, 17, 99, 204, 233, 59, 135, 208, 17, 46, 230, 148, 25,
            133, 46, 18, 129, 125, 41, 71, 129, 204, 43, 78, 180, 63, 148, 142, 8, 134, 52, 196,
            210, 186, 246, 120, 143, 7, 251, 205, 217, 156, 30, 70, 150, 218, 42, 84, 160, 177,
            231, 240, 119, 2, 3, 1, 0, 1, 2, 130, 1, 0, 28, 36, 174, 27, 126, 88, 84, 151, 220, 81,
            51, 252, 133, 109, 170, 118, 252, 144, 31, 152, 166, 23, 20, 197, 154, 167, 110, 210,
            237, 88, 155, 190, 109, 78, 125, 216, 131, 96, 170, 70, 213, 99, 1, 171, 92, 191, 41,
            33, 91, 243, 96, 45, 228, 231, 219, 85, 22, 202, 163, 226, 143, 66, 216, 59, 173, 162,
            157, 210, 92, 112, 25, 178, 230, 112, 176, 79, 219, 88, 190, 91, 161, 5, 251, 217, 202,
            82, 221, 218, 30, 132, 189, 119, 64, 81, 181, 208, 166, 124, 194, 178, 216, 229, 235,
            111, 237, 105, 185, 6, 218, 131, 149, 142, 72, 224, 58, 236, 97, 138, 153, 246, 69,
            171, 65, 238, 23, 60, 88, 17, 11, 120, 19, 5, 73, 125, 30, 54, 205, 1, 137, 165, 14,
            185, 105, 27, 121, 181, 105, 237, 137, 5, 121, 84, 155, 176, 108, 9, 113, 13, 195, 105,
            154, 208, 146, 179, 101, 83, 207, 21, 135, 23, 67, 34, 228, 209, 3, 110, 35, 31, 138,
            132, 90, 59, 21, 206, 60, 37, 75, 102, 101, 111, 142, 225, 46, 241, 145, 57, 105, 69,
            157, 43, 22, 16, 202, 172, 4, 103, 161, 232, 151, 228, 105, 206, 94, 207, 1, 81, 177,
            31, 234, 190, 156, 123, 93, 125, 10, 65, 141, 175, 199, 140, 162, 136, 131, 244, 81,
            83, 79, 87, 9, 66, 48, 129, 127, 157, 87, 105, 189, 149, 186, 26, 20, 63, 198, 222, 94,
            49, 2, 129, 129, 0, 243, 33, 60, 82, 189, 78, 48, 104, 168, 181, 202, 9, 229, 45, 245,
            100, 168, 226, 244, 75, 187, 199, 142, 18, 250, 45, 231, 132, 83, 133, 80, 128, 247,
            249, 216, 20, 80, 245, 243, 164, 175, 4, 172, 145, 204, 229, 175, 114, 93, 204, 153,
            66, 198, 182, 168, 1, 165, 51, 100, 133, 22, 121, 155, 44, 38, 245, 96, 52, 207, 120,
            72, 48, 179, 251, 17, 59, 205, 76, 0, 191, 138, 252, 80, 184, 124, 75, 153, 229, 29,
            168, 165, 77, 144, 212, 41, 204, 9, 137, 154, 166, 2, 135, 89, 39, 25, 208, 82, 20, 76,
            245, 14, 58, 9, 85, 17, 71, 199, 248, 12, 27, 24, 26, 216, 76, 197, 223, 142, 145, 2,
            129, 129, 0, 201, 179, 5, 34, 16, 74, 254, 62, 83, 131, 189, 101, 29, 51, 181, 119, 15,
            157, 213, 59, 213, 209, 233, 132, 28, 106, 116, 202, 119, 60, 65, 49, 125, 33, 147,
            178, 169, 4, 254, 113, 160, 97, 69, 210, 168, 81, 88, 140, 13, 90, 17, 5, 70, 130, 64,
            60, 70, 71, 178, 67, 253, 102, 58, 4, 51, 208, 17, 252, 213, 167, 228, 218, 4, 142,
            206, 217, 71, 136, 55, 37, 89, 11, 100, 120, 214, 213, 160, 98, 215, 98, 221, 177, 220,
            253, 242, 238, 207, 161, 108, 250, 78, 0, 232, 84, 154, 15, 173, 216, 82, 95, 37, 214,
            4, 154, 26, 174, 98, 25, 92, 43, 195, 141, 247, 172, 18, 12, 162, 135, 2, 129, 129, 0,
            190, 169, 119, 166, 226, 241, 168, 32, 202, 253, 20, 157, 193, 237, 210, 156, 199, 156,
            131, 59, 200, 220, 107, 92, 18, 121, 97, 47, 114, 87, 255, 147, 195, 227, 88, 66, 70,
            99, 58, 88, 17, 48, 55, 44, 119, 100, 63, 188, 14, 54, 222, 145, 113, 71, 216, 100,
            193, 234, 149, 143, 144, 218, 120, 135, 157, 93, 155, 190, 142, 92, 163, 48, 30, 84,
            107, 101, 92, 79, 151, 222, 157, 221, 212, 103, 120, 129, 201, 3, 213, 200, 101, 41,
            120, 196, 8, 171, 11, 103, 175, 177, 52, 22, 116, 33, 167, 170, 168, 83, 103, 46, 93,
            163, 193, 161, 198, 85, 102, 73, 237, 36, 106, 56, 211, 27, 17, 169, 137, 33, 2, 129,
            128, 40, 193, 13, 86, 118, 168, 80, 122, 211, 113, 25, 1, 167, 70, 221, 113, 179, 44,
            22, 251, 194, 22, 105, 242, 145, 179, 72, 233, 231, 241, 186, 210, 127, 16, 27, 193,
            203, 185, 0, 152, 128, 233, 102, 172, 75, 234, 51, 212, 8, 150, 156, 61, 206, 163, 94,
            203, 79, 0, 9, 155, 7, 70, 114, 142, 138, 209, 141, 240, 226, 82, 204, 64, 233, 14,
            217, 232, 185, 53, 98, 191, 31, 32, 216, 42, 58, 110, 107, 187, 204, 253, 99, 2, 31,
            63, 8, 169, 12, 54, 247, 200, 19, 158, 199, 82, 224, 214, 46, 48, 57, 100, 148, 70,
            140, 35, 127, 36, 161, 25, 178, 175, 253, 17, 96, 107, 218, 49, 199, 93, 2, 129, 128,
            122, 254, 238, 22, 221, 153, 158, 56, 73, 156, 136, 73, 21, 108, 74, 140, 229, 0, 155,
            134, 174, 239, 77, 131, 172, 97, 124, 246, 89, 207, 110, 20, 179, 205, 148, 132, 165,
            192, 71, 32, 119, 164, 250, 59, 194, 33, 167, 180, 178, 204, 158, 140, 8, 218, 157, 20,
            80, 234, 123, 180, 227, 78, 49, 92, 207, 37, 134, 73, 81, 35, 31, 97, 5, 99, 235, 56,
            74, 89, 3, 179, 125, 27, 31, 234, 104, 150, 238, 45, 24, 85, 156, 48, 177, 161, 19,
            124, 122, 43, 156, 253, 219, 220, 25, 178, 136, 248, 211, 151, 19, 198, 129, 239, 28,
            97, 81, 0, 93, 200, 46, 237, 92, 96, 16, 138, 17, 203, 39, 237,
        ])
        .unwrap();

        let mut cek = general_purpose::URL_SAFE_NO_PAD
            .decode("GBxS4SdM29dvIiVaG8ywUqkcvj-n6sd_ypBlpoAZA3bISTeLSA7o5Alf6XXokdQrzb6FwmJ8Fzkdo9l4Q7Bq6Wg6emFyg52_ME_TejQdX9ComlOxsJYYd_-DbMYtTkivV9kgGEKTBRQA1IAKLkVn2cYrubp0aYtuPxXnXkbNjpuGYDHnjh_CDYaoRjjlbfO3mB3D0B3gcYYWE06dZO6uFjVpyQJuBsA4mydqZ73FtRT14SqMO1Szdt43KZvFl339QPr6mJTt1DtGMj5fNFiufI01GzDTqTvm9oWJk7V-BEX2BdMzjUepi9qce6IkWFDji36-Cl-tkghd6pjzkbTNka_Ue4z0ON2PEisftuarS1td1ACTZI1gfe4d4lW8Gn7eAodkPosE")
            .unwrap();

        // Test truncating to a 244/256 byte boundary
        cek.truncate(256);

        let cek = general_purpose::URL_SAFE_NO_PAD
            .encode(&cek);

        let jwe_str = format!("eyJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiUlNBLU9BRVAifQ.{}.Og3wmuWteE9ImPIP.HA.W5OXFtOnLYvIOQRxwdyb2Q", cek);

        let jwec = JweCompact::from_str(jwe_str.as_str()).unwrap();

        let _session_key = MsOapxbcSessionKey::complete_rsa_oaep_key_agreement(rsa_priv_key, &jwec)
            .expect("Failed to fetch the session key");
    }
    */
}
