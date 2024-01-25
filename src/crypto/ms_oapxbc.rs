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
