use crate::compact::{JweAlg, JweCompact};
use crate::jwe::Jwe;
use crate::JwtError;

use crate::compact::JweProtectedHeader;
use crate::traits::{JweEncipherInner, JweEncipherOuter};

use openssl::encrypt::{Decrypter, Encrypter};
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::pkey::Private;
use openssl::pkey::Public;
use openssl::rsa::{Padding, Rsa};

/// A JWE outer decipher for RSA-OAEP.
/// You should prefer [crate::crypto::JweEcdhEsA128KWEncipher] or
/// [crate::crypto::JweA128KWEncipher]
pub struct JweRSAOAEPDecipher {
    rsa_priv_key: PKey<Private>,
}

impl TryFrom<Rsa<Private>> for JweRSAOAEPDecipher {
    type Error = JwtError;

    fn try_from(value: Rsa<Private>) -> Result<Self, Self::Error> {
        let rsa_priv_key = PKey::from_rsa(value).map_err(|ossl_err| {
            debug!(?ossl_err);
            JwtError::OpenSSLError
        })?;

        Ok(JweRSAOAEPDecipher { rsa_priv_key })
    }
}

impl JweRSAOAEPDecipher {
    pub(crate) fn unwrap_key(&self, jwec: &JweCompact) -> Result<Vec<u8>, JwtError> {
        let expected_wrap_key_buffer_len = jwec.header.enc.key_len();

        trace!(?expected_wrap_key_buffer_len);

        // Decrypt cek
        let mut wrap_key_decrypter = Decrypter::new(&self.rsa_priv_key).map_err(|ossl_err| {
            debug!(?ossl_err);
            JwtError::OpenSSLError
        })?;

        wrap_key_decrypter
            .set_rsa_padding(Padding::PKCS1_OAEP)
            .map_err(|ossl_err| {
                debug!(?ossl_err);
                JwtError::OpenSSLError
            })?;

        wrap_key_decrypter
            .set_rsa_mgf1_md(MessageDigest::sha1())
            .map_err(|ossl_err| {
                debug!(?ossl_err);
                JwtError::OpenSSLError
            })?;

        wrap_key_decrypter
            .set_rsa_oaep_md(MessageDigest::sha1())
            .map_err(|ossl_err| {
                debug!(?ossl_err);
                JwtError::OpenSSLError
            })?;

        // Rsa oaep will often work on bigger block sizes, so we need a larger buffer and then we
        // can copy later. First we check the expected length of the decryption.
        let buf_len = wrap_key_decrypter
            .decrypt_len(&jwec.content_enc_key)
            .map_err(|ossl_err| {
                debug!(?ossl_err);
                JwtError::OpenSSLError
            })?;

        trace!(?jwec.content_enc_key);

        trace!(enc_len = ?jwec.content_enc_key.len());

        let mut unwrapped_key = vec![0; buf_len];

        trace!(?buf_len);

        wrap_key_decrypter
            .decrypt(&jwec.content_enc_key, &mut unwrapped_key)
            .map_err(|ossl_err| {
                debug!(?ossl_err);
                JwtError::OpenSSLError
            })?;

        trace!(?unwrapped_key);

        unwrapped_key.truncate(expected_wrap_key_buffer_len);

        Ok(unwrapped_key)
    }

    /// Given a JWE in compact form, decipher and authenticate its content.
    pub fn decipher(&self, jwec: &JweCompact) -> Result<Jwe, JwtError> {
        let unwrapped_key = self.unwrap_key(jwec)?;

        let payload = jwec
            .header
            .enc
            .decipher_inner(unwrapped_key.as_slice(), jwec)?;

        Ok(Jwe {
            header: jwec.header.clone(),
            payload,
        })
    }
}

/// A JWE outer encipher for RSA-OAEP. This type can only encipher.
/// You should prefer [crate::crypto::JweEcdhEsA128KWEncipher] or [crate::crypto::JweA128KWEncipher]
pub struct JweRSAOAEPEncipher {
    rsa_pub_key: PKey<Public>,
}

impl TryFrom<Rsa<Public>> for JweRSAOAEPEncipher {
    type Error = JwtError;

    fn try_from(value: Rsa<Public>) -> Result<Self, Self::Error> {
        let rsa_pub_key = PKey::from_rsa(value).map_err(|ossl_err| {
            debug!(?ossl_err);
            JwtError::OpenSSLError
        })?;

        Ok(JweRSAOAEPEncipher { rsa_pub_key })
    }
}

impl JweRSAOAEPEncipher {
    /// Given a JWE, encipher its content to a compact form.
    pub fn encipher<E: JweEncipherInner>(&self, jwe: &Jwe) -> Result<JweCompact, JwtError> {
        let encipher = E::new_ephemeral()?;
        encipher.encipher_inner(self, jwe)
    }
}

impl JweEncipherOuter for JweRSAOAEPEncipher {
    fn set_header_alg(&self, hdr: &mut JweProtectedHeader) -> Result<(), JwtError> {
        hdr.alg = JweAlg::RSA_OAEP;
        Ok(())
    }

    fn wrap_key(&self, key_to_wrap: &[u8]) -> Result<Vec<u8>, JwtError> {
        let mut wrap_key_encrypter = Encrypter::new(&self.rsa_pub_key).map_err(|ossl_err| {
            debug!(?ossl_err);
            JwtError::OpenSSLError
        })?;

        wrap_key_encrypter
            .set_rsa_padding(Padding::PKCS1_OAEP)
            .map_err(|ossl_err| {
                debug!(?ossl_err);
                JwtError::OpenSSLError
            })?;

        wrap_key_encrypter
            .set_rsa_mgf1_md(MessageDigest::sha1())
            .map_err(|ossl_err| {
                debug!(?ossl_err);
                JwtError::OpenSSLError
            })?;

        wrap_key_encrypter
            .set_rsa_oaep_md(MessageDigest::sha1())
            .map_err(|ossl_err| {
                debug!(?ossl_err);
                JwtError::OpenSSLError
            })?;

        let buf_len = wrap_key_encrypter
            .encrypt_len(key_to_wrap)
            .map_err(|ossl_err| {
                debug!(?ossl_err);
                JwtError::OpenSSLError
            })?;

        let mut wrapped_key = vec![0; buf_len];

        let encoded_len = wrap_key_encrypter
            .encrypt(key_to_wrap, &mut wrapped_key)
            .map_err(|ossl_err| {
                debug!(?ossl_err);
                JwtError::OpenSSLError
            })?;

        wrapped_key.truncate(encoded_len);

        Ok(wrapped_key)
    }
}

#[cfg(test)]
mod tests {
    use super::{JweRSAOAEPDecipher, JweRSAOAEPEncipher};
    use crate::compact::JweCompact;
    use crate::crypto::a256gcm::JweA256GCMEncipher;
    use base64::{engine::general_purpose, Engine as _};
    use std::convert::TryFrom;
    use std::str::FromStr;

    use crate::jwe::JweBuilder;

    use openssl::bn;
    use openssl::pkey::Private;
    use openssl::rsa::Rsa;

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
        let n = general_purpose::URL_SAFE_NO_PAD
            .decode(n)
            .expect("Invalid Key");

        let e = general_purpose::URL_SAFE_NO_PAD
            .decode(e)
            .expect("Invalid Key");

        let d = general_purpose::URL_SAFE_NO_PAD
            .decode(d)
            .expect("Invalid Key");

        let p = general_purpose::URL_SAFE_NO_PAD
            .decode(p)
            .expect("Invalid Key");

        let q = general_purpose::URL_SAFE_NO_PAD
            .decode(q)
            .expect("Invalid Key");

        let dmp1 = general_purpose::URL_SAFE_NO_PAD
            .decode(dmp1)
            .expect("Invalid Key");

        let dmq1 = general_purpose::URL_SAFE_NO_PAD
            .decode(dmq1)
            .expect("Invalid Key");

        let iqmp = general_purpose::URL_SAFE_NO_PAD
            .decode(iqmp)
            .expect("Invalid Key");

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
    fn rfc7516_rsa_oaep_validation_example() {
        // Taken from https://www.rfc-editor.org/rfc/rfc7516.html#appendix-A.3

        let _ = tracing_subscriber::fmt::try_init();

        let test_jwe = "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGeipsEdY3mx_etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDbSv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaVmqgfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je81860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWXRcZ_ZT2LawVCWTIy3brGPi6UklfCpIMfIjf7iGdXKHzg.48V1_ALb6US04U3b.5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6jiSdiwkIr3ajwQzaBtQD_A.XFBoMYUZodetZdvTiFvSkQ";

        let rsa_priv_key = rsa_from_private_components(
"oahUIoWw0K0usKNuOR6H4wkf4oBUXHTxRvgb48E-BVvxkeDNjbC4he8rUWcJoZmds2h7M70imEVhRU5djINXtqllXI4DFqcI1DgjT9LewND8MW2Krf3Spsk_ZkoFnilakGygTwpZ3uesH-PFABNIUYpOiN15dsQRkgr0vEhxN92i2asbOenSZeyaxziK72UwxrrKoExv6kc5twXTq4h-QChLOln0_mtUZwfsRaMStPs6mS6XrgxnxbWhojf663tuEQueGC-FCMfra36C9knDFGzKsNa7LZK2djYgyD3JR_MB_4NUJW_TqOQtwHYbxevoJArm-L5StowjzGy-_bq6Gw",
"AQAB",
"kLdtIj6GbDks_ApCSTYQtelcNttlKiOyPzMrXHeI-yk1F7-kpDxY4-WY5NWV5KntaEeXS1j82E375xxhWMHXyvjYecPT9fpwR_M9gV8n9Hrh2anTpTD93Dt62ypW3yDsJzBnTnrYu1iwWRgBKrEYY46qAZIrA2xAwnm2X7uGR1hghkqDp0Vqj3kbSCz1XyfCs6_LehBwtxHIyh8Ripy40p24moOAbgxVw3rxT_vlt3UVe4WO3JkJOzlpUf-KTVI2Ptgm-dARxTEtE-id-4OJr0h-K-VFs3VSndVTIznSxfyrj8ILL6MG_Uv8YAu7VILSB3lOW085-4qE3DzgrTjgyQ",
"1r52Xk46c-LsfB5P442p7atdPUrxQSy4mti_tZI3Mgf2EuFVbUoDBvaRQ-SWxkbkmoEzL7JXroSBjSrK3YIQgYdMgyAEPTPjXv_hI2_1eTSPVZfzL0lffNn03IXqWF5MDFuoUYE0hzb2vhrlN_rKrbfDIwUbTrjjgieRbwC6Cl0",
"wLb35x7hmQWZsWJmB_vle87ihgZ19S8lBEROLIsZG4ayZVe9Hi9gDVCOBmUDdaDYVTSNx_8Fyw1YYa9XGrGnDew00J28cRUoeBB_jKI1oma0Orv1T9aXIWxKwd4gvxFImOWr3QRL9KEBRzk2RatUBnmDZJTIAfwTs0g68UZHvtc",
"ZK-YwE7diUh0qR1tR7w8WHtolDx3MZ_OTowiFvgfeQ3SiresXjm9gZ5KLhMXvo-uz-KUJWDxS5pFQ_M0evdo1dKiRTjVw_x4NyqyXPM5nULPkcpU827rnpZzAJKpdhWAgqrXGKAECQH0Xt4taznjnd_zVpAmZZq60WPMBMfKcuE",
"Dq0gfgJ1DdFGXiLvQEZnuKEN0UUmsJBxkjydc3j4ZYdBiMRAy86x0vHCjywcMlYYg4yoC4YZa9hNVcsjqA3FeiL19rk8g6Qn29Tt0cj8qqyFpz9vNDBUfCAiJVeESOjJDZPYHdHY8v1b-o-Z2X5tvLx-TCekf7oxyeKDUqKWjis",
"VIMpMYbPf47dT1w_zDUXfPimsSegnMOA1zTaX7aGk_8urY6R8-ZW1FxU7AlWAyLWybqq6t16VFd7hQd0y6flUK4SlOydB61gwanOsXGOAOv82cHq0E3eL4HrtZkUuKvnPrMnsUUFlfUdybVzxyjz9JF_XyaY14ardLSjf4L_FNY"
);

        // Check key parameters
        assert!(rsa_priv_key.check_key().unwrap());

        // let der_bytes = rsa_priv_key.private_key_to_der().unwrap();
        // error!(?der_bytes);

        let jwec = JweCompact::from_str(test_jwe).unwrap();

        assert!(jwec.to_string() == test_jwe);

        // Check vectors
        jwec.check_vectors(
            // Content Encryption Key
            &[
                56, 163, 154, 192, 58, 53, 222, 4, 105, 218, 136, 218, 29, 94, 203, 22, 150, 92,
                129, 94, 211, 232, 53, 89, 41, 60, 138, 56, 196, 216, 82, 98, 168, 76, 37, 73, 70,
                7, 36, 8, 191, 100, 136, 196, 244, 220, 145, 158, 138, 155, 4, 117, 141, 230, 199,
                247, 173, 45, 182, 214, 74, 177, 107, 211, 153, 11, 205, 196, 171, 226, 162, 128,
                171, 182, 13, 237, 239, 99, 193, 4, 91, 219, 121, 223, 107, 167, 61, 119, 228, 173,
                156, 137, 134, 200, 80, 219, 74, 253, 56, 185, 91, 177, 34, 158, 89, 154, 205, 96,
                55, 18, 138, 43, 96, 218, 215, 128, 124, 75, 138, 243, 85, 25, 109, 117, 140, 26,
                155, 249, 67, 167, 149, 231, 100, 6, 41, 65, 214, 251, 232, 87, 72, 40, 182, 149,
                154, 168, 31, 193, 126, 215, 89, 28, 111, 219, 125, 182, 139, 235, 195, 197, 23,
                234, 55, 58, 63, 180, 68, 202, 206, 149, 75, 205, 248, 176, 67, 39, 178, 60, 98,
                193, 32, 238, 122, 96, 158, 222, 57, 183, 111, 210, 55, 188, 215, 206, 180, 166,
                150, 166, 106, 250, 55, 229, 72, 40, 69, 214, 216, 104, 23, 40, 135, 212, 28, 127,
                41, 80, 175, 174, 168, 115, 171, 197, 89, 116, 92, 103, 246, 83, 216, 182, 176, 84,
                37, 147, 35, 45, 219, 172, 99, 226, 233, 73, 37, 124, 42, 72, 49, 242, 35, 127,
                184, 134, 117, 114, 135, 206,
            ],
            // IV
            &[227, 197, 117, 252, 2, 219, 233, 68, 180, 225, 77, 219],
            // Cipher Text
            &[
                229, 236, 166, 241, 53, 191, 115, 196, 174, 43, 73, 109, 39, 122, 233, 96, 140,
                206, 120, 52, 51, 237, 48, 11, 190, 219, 186, 80, 111, 104, 50, 142, 47, 167, 59,
                61, 181, 127, 196, 21, 40, 82, 242, 32, 123, 143, 168, 226, 73, 216, 176, 144, 138,
                247, 106, 60, 16, 205, 160, 109, 64, 63, 192,
            ],
            // Authentication Tag
            &[
                92, 80, 104, 49, 133, 25, 161, 215, 173, 101, 219, 211, 136, 91, 210, 145,
            ],
        );

        assert!(jwec.get_jwk_pubkey_url().is_none());
        assert!(jwec.get_jwk_pubkey().is_none());

        let rsa_oaep_decipher =
            JweRSAOAEPDecipher::try_from(rsa_priv_key).expect("Unable to create decipher");

        let released = rsa_oaep_decipher
            .decipher(&jwec)
            .expect("Unable to decipher jwe");

        assert_eq!(
            released.payload(),
            &[
                84, 104, 101, 32, 116, 114, 117, 101, 32, 115, 105, 103, 110, 32, 111, 102, 32,
                105, 110, 116, 101, 108, 108, 105, 103, 101, 110, 99, 101, 32, 105, 115, 32, 110,
                111, 116, 32, 107, 110, 111, 119, 108, 101, 100, 103, 101, 32, 98, 117, 116, 32,
                105, 109, 97, 103, 105, 110, 97, 116, 105, 111, 110, 46
            ]
        );
    }

    #[test]
    fn reflexive_rsa_oaep_validation() {
        let _ = tracing_subscriber::fmt::try_init();

        let input = vec![1; 256];
        let jweb = JweBuilder::from(input.clone()).build();

        let rsa_priv_key = Rsa::generate(2048).unwrap();

        let rsa_pub_key = Rsa::from_public_components(
            rsa_priv_key.n().to_owned().unwrap(),
            rsa_priv_key.e().to_owned().unwrap(),
        )
        .unwrap();

        let jwe_rsa_oaep_decipher = JweRSAOAEPDecipher::try_from(rsa_priv_key).unwrap();

        let jwe_rsa_oaep_encipher = JweRSAOAEPEncipher::try_from(rsa_pub_key).unwrap();

        let jwe_encrypted = jwe_rsa_oaep_encipher
            .encipher::<JweA256GCMEncipher>(&jweb)
            .expect("Unable to encrypt.");

        // Decrypt with the partner.
        let decrypted = jwe_rsa_oaep_decipher
            .decipher(&jwe_encrypted)
            .expect("Unable to decrypt.");

        assert_eq!(decrypted.payload(), input);
    }

    #[test]
    fn rfc7516_rsa_oaep_validation_example_alt() {
        use pkcs1::DecodeRsaPrivateKey;
        use rsa::oaep::Oaep;
        use rsa::RsaPrivateKey;

        let rsa_priv_key = RsaPrivateKey::from_pkcs1_der(&[
            48, 130, 4, 163, 2, 1, 0, 2, 130, 1, 1, 0, 161, 168, 84, 34, 133, 176, 208, 173, 46,
            176, 163, 110, 57, 30, 135, 227, 9, 31, 226, 128, 84, 92, 116, 241, 70, 248, 27, 227,
            193, 62, 5, 91, 241, 145, 224, 205, 141, 176, 184, 133, 239, 43, 81, 103, 9, 161, 153,
            157, 179, 104, 123, 51, 189, 34, 152, 69, 97, 69, 78, 93, 140, 131, 87, 182, 169, 101,
            92, 142, 3, 22, 167, 8, 212, 56, 35, 79, 210, 222, 192, 208, 252, 49, 109, 138, 173,
            253, 210, 166, 201, 63, 102, 74, 5, 158, 41, 90, 144, 108, 160, 79, 10, 89, 222, 231,
            172, 31, 227, 197, 0, 19, 72, 81, 138, 78, 136, 221, 121, 118, 196, 17, 146, 10, 244,
            188, 72, 113, 55, 221, 162, 217, 171, 27, 57, 233, 210, 101, 236, 154, 199, 56, 138,
            239, 101, 48, 198, 186, 202, 160, 76, 111, 234, 71, 57, 183, 5, 211, 171, 136, 126, 64,
            40, 75, 58, 89, 244, 254, 107, 84, 103, 7, 236, 69, 163, 18, 180, 251, 58, 153, 46,
            151, 174, 12, 103, 197, 181, 161, 162, 55, 250, 235, 123, 110, 17, 11, 158, 24, 47,
            133, 8, 199, 235, 107, 126, 130, 246, 73, 195, 20, 108, 202, 176, 214, 187, 45, 146,
            182, 118, 54, 32, 200, 61, 201, 71, 243, 1, 255, 131, 84, 37, 111, 211, 168, 228, 45,
            192, 118, 27, 197, 235, 232, 36, 10, 230, 248, 190, 82, 182, 140, 35, 204, 108, 190,
            253, 186, 186, 27, 2, 3, 1, 0, 1, 2, 130, 1, 1, 0, 144, 183, 109, 34, 62, 134, 108, 57,
            44, 252, 10, 66, 73, 54, 16, 181, 233, 92, 54, 219, 101, 42, 35, 178, 63, 51, 43, 92,
            119, 136, 251, 41, 53, 23, 191, 164, 164, 60, 88, 227, 229, 152, 228, 213, 149, 228,
            169, 237, 104, 71, 151, 75, 88, 252, 216, 77, 251, 231, 28, 97, 88, 193, 215, 202, 248,
            216, 121, 195, 211, 245, 250, 112, 71, 243, 61, 129, 95, 39, 244, 122, 225, 217, 169,
            211, 165, 48, 253, 220, 59, 122, 219, 42, 86, 223, 32, 236, 39, 48, 103, 78, 122, 216,
            187, 88, 176, 89, 24, 1, 42, 177, 24, 99, 142, 170, 1, 146, 43, 3, 108, 64, 194, 121,
            182, 95, 187, 134, 71, 88, 96, 134, 74, 131, 167, 69, 106, 143, 121, 27, 72, 44, 245,
            95, 39, 194, 179, 175, 203, 122, 16, 112, 183, 17, 200, 202, 31, 17, 138, 156, 184,
            210, 157, 184, 154, 131, 128, 110, 12, 85, 195, 122, 241, 79, 251, 229, 183, 117, 21,
            123, 133, 142, 220, 153, 9, 59, 57, 105, 81, 255, 138, 77, 82, 54, 62, 216, 38, 249,
            208, 17, 197, 49, 45, 19, 232, 157, 251, 131, 137, 175, 72, 126, 43, 229, 69, 179, 117,
            82, 157, 213, 83, 35, 57, 210, 197, 252, 171, 143, 194, 11, 47, 163, 6, 253, 75, 252,
            96, 11, 187, 84, 130, 210, 7, 121, 78, 91, 79, 57, 251, 138, 132, 220, 60, 224, 173,
            56, 224, 201, 2, 129, 129, 0, 214, 190, 118, 94, 78, 58, 115, 226, 236, 124, 30, 79,
            227, 141, 169, 237, 171, 93, 61, 74, 241, 65, 44, 184, 154, 216, 191, 181, 146, 55, 50,
            7, 246, 18, 225, 85, 109, 74, 3, 6, 246, 145, 67, 228, 150, 198, 70, 228, 154, 129, 51,
            47, 178, 87, 174, 132, 129, 141, 42, 202, 221, 130, 16, 129, 135, 76, 131, 32, 4, 61,
            51, 227, 94, 255, 225, 35, 111, 245, 121, 52, 143, 85, 151, 243, 47, 73, 95, 124, 217,
            244, 220, 133, 234, 88, 94, 76, 12, 91, 168, 81, 129, 52, 135, 54, 246, 190, 26, 229,
            55, 250, 202, 173, 183, 195, 35, 5, 27, 78, 184, 227, 130, 39, 145, 111, 0, 186, 10,
            93, 2, 129, 129, 0, 192, 182, 247, 231, 30, 225, 153, 5, 153, 177, 98, 102, 7, 251,
            229, 123, 206, 226, 134, 6, 117, 245, 47, 37, 4, 68, 78, 44, 139, 25, 27, 134, 178,
            101, 87, 189, 30, 47, 96, 13, 80, 142, 6, 101, 3, 117, 160, 216, 85, 52, 141, 199, 255,
            5, 203, 13, 88, 97, 175, 87, 26, 177, 167, 13, 236, 52, 208, 157, 188, 113, 21, 40,
            120, 16, 127, 140, 162, 53, 162, 102, 180, 58, 187, 245, 79, 214, 151, 33, 108, 74,
            193, 222, 32, 191, 17, 72, 152, 229, 171, 221, 4, 75, 244, 161, 1, 71, 57, 54, 69, 171,
            84, 6, 121, 131, 100, 148, 200, 1, 252, 19, 179, 72, 58, 241, 70, 71, 190, 215, 2, 129,
            128, 100, 175, 152, 192, 78, 221, 137, 72, 116, 169, 29, 109, 71, 188, 60, 88, 123,
            104, 148, 60, 119, 49, 159, 206, 78, 140, 34, 22, 248, 31, 121, 13, 210, 138, 183, 172,
            94, 57, 189, 129, 158, 74, 46, 19, 23, 190, 143, 174, 207, 226, 148, 37, 96, 241, 75,
            154, 69, 67, 243, 52, 122, 247, 104, 213, 210, 162, 69, 56, 213, 195, 252, 120, 55, 42,
            178, 92, 243, 57, 157, 66, 207, 145, 202, 84, 243, 110, 235, 158, 150, 115, 0, 146,
            169, 118, 21, 128, 130, 170, 215, 24, 160, 4, 9, 1, 244, 94, 222, 45, 107, 57, 227,
            157, 223, 243, 86, 144, 38, 101, 154, 186, 209, 99, 204, 4, 199, 202, 114, 225, 2, 129,
            128, 14, 173, 32, 126, 2, 117, 13, 209, 70, 94, 34, 239, 64, 70, 103, 184, 161, 13,
            209, 69, 38, 176, 144, 113, 146, 60, 157, 115, 120, 248, 101, 135, 65, 136, 196, 64,
            203, 206, 177, 210, 241, 194, 143, 44, 28, 50, 86, 24, 131, 140, 168, 11, 134, 25, 107,
            216, 77, 85, 203, 35, 168, 13, 197, 122, 34, 245, 246, 185, 60, 131, 164, 39, 219, 212,
            237, 209, 200, 252, 170, 172, 133, 167, 63, 111, 52, 48, 84, 124, 32, 34, 37, 87, 132,
            72, 232, 201, 13, 147, 216, 29, 209, 216, 242, 253, 91, 250, 143, 153, 217, 126, 109,
            188, 188, 126, 76, 39, 164, 127, 186, 49, 201, 226, 131, 82, 162, 150, 142, 43, 2, 129,
            128, 84, 131, 41, 49, 134, 207, 127, 142, 221, 79, 92, 63, 204, 53, 23, 124, 248, 166,
            177, 39, 160, 156, 195, 128, 215, 52, 218, 95, 182, 134, 147, 255, 46, 173, 142, 145,
            243, 230, 86, 212, 92, 84, 236, 9, 86, 3, 34, 214, 201, 186, 170, 234, 221, 122, 84,
            87, 123, 133, 7, 116, 203, 167, 229, 80, 174, 18, 148, 236, 157, 7, 173, 96, 193, 169,
            206, 177, 113, 142, 0, 235, 252, 217, 193, 234, 208, 77, 222, 47, 129, 235, 181, 153,
            20, 184, 171, 231, 62, 179, 39, 177, 69, 5, 149, 245, 29, 201, 181, 115, 199, 40, 243,
            244, 145, 127, 95, 38, 152, 215, 134, 171, 116, 180, 163, 127, 130, 255, 20, 214,
        ])
        .unwrap();

        let enc_cek = [
            56, 163, 154, 192, 58, 53, 222, 4, 105, 218, 136, 218, 29, 94, 203, 22, 150, 92, 129,
            94, 211, 232, 53, 89, 41, 60, 138, 56, 196, 216, 82, 98, 168, 76, 37, 73, 70, 7, 36, 8,
            191, 100, 136, 196, 244, 220, 145, 158, 138, 155, 4, 117, 141, 230, 199, 247, 173, 45,
            182, 214, 74, 177, 107, 211, 153, 11, 205, 196, 171, 226, 162, 128, 171, 182, 13, 237,
            239, 99, 193, 4, 91, 219, 121, 223, 107, 167, 61, 119, 228, 173, 156, 137, 134, 200,
            80, 219, 74, 253, 56, 185, 91, 177, 34, 158, 89, 154, 205, 96, 55, 18, 138, 43, 96,
            218, 215, 128, 124, 75, 138, 243, 85, 25, 109, 117, 140, 26, 155, 249, 67, 167, 149,
            231, 100, 6, 41, 65, 214, 251, 232, 87, 72, 40, 182, 149, 154, 168, 31, 193, 126, 215,
            89, 28, 111, 219, 125, 182, 139, 235, 195, 197, 23, 234, 55, 58, 63, 180, 68, 202, 206,
            149, 75, 205, 248, 176, 67, 39, 178, 60, 98, 193, 32, 238, 122, 96, 158, 222, 57, 183,
            111, 210, 55, 188, 215, 206, 180, 166, 150, 166, 106, 250, 55, 229, 72, 40, 69, 214,
            216, 104, 23, 40, 135, 212, 28, 127, 41, 80, 175, 174, 168, 115, 171, 197, 89, 116, 92,
            103, 246, 83, 216, 182, 176, 84, 37, 147, 35, 45, 219, 172, 99, 226, 233, 73, 37, 124,
            42, 72, 49, 242, 35, 127, 184, 134, 117, 114, 135, 206,
        ];

        let padding = Oaep::new_with_mgf_hash::<sha1::Sha1, sha1::Sha1>();

        let released_cek = rsa_priv_key.decrypt(padding, &enc_cek).unwrap();

        assert_eq!(
            released_cek.as_slice(),
            &[
                177, 161, 244, 128, 84, 143, 225, 115, 63, 180, 3, 255, 107, 154, 212, 246, 138, 7,
                110, 91, 112, 46, 34, 105, 47, 130, 203, 46, 122, 234, 64, 252
            ]
        );
    }
}
