use crate::compact::JweProtectedHeader;
use crate::compact::{JweAlg, JweCompact};
use crate::jwe::Jwe;
use crate::traits::{JweEncipherInnerA256, JweEncipherOuterA256};
use crate::JwtError;

use crypto_glue::{
    aes256::{self, Aes256Key},
    rand,
    rsa::{Oaep, RS256PrivateKey, RS256PublicKey},
    sha1,
};

/// A JWE outer decipher for RSA-OAEP.
/// You should prefer [crate::crypto::JweEcdhEsA256KWEncipher] or
/// [crate::crypto::JweA256KWEncipher]
pub struct JweRSAOAEPDecipher {
    rsa_priv_key: RS256PrivateKey,
}

impl From<RS256PrivateKey> for JweRSAOAEPDecipher {
    fn from(rsa_priv_key: RS256PrivateKey) -> Self {
        JweRSAOAEPDecipher { rsa_priv_key }
    }
}

impl JweRSAOAEPDecipher {
    pub(crate) fn unwrap_key(&self, jwec: &JweCompact) -> Result<Aes256Key, JwtError> {
        // I'm not sure if this needs to be bigger or smaller? Guess we'll see!
        if jwec.content_enc_key.len() > 256 {
            debug!(
                length = jwec.content_enc_key.len(),
                "invalid content key length"
            );
            return Err(JwtError::CryptoError);
        }

        let padding = Oaep::new::<sha1::Sha1>();
        let decrypted_data = self
            .rsa_priv_key
            .decrypt(padding, jwec.content_enc_key.as_slice())
            .map_err(|err| {
                debug!(?err, "failed to decrypt key");
                JwtError::CryptoError
            })?;

        aes256::key_from_vec(decrypted_data).ok_or_else(|| {
            debug!("invalid content key length");
            JwtError::CryptoError
        })
    }

    /// Given a JWE in compact form, decipher and authenticate its content.
    pub fn decipher(&self, jwec: &JweCompact) -> Result<Jwe, JwtError> {
        let unwrapped_key = self.unwrap_key(jwec)?;

        let payload = jwec.header.enc.decipher_inner_a256(unwrapped_key, jwec)?;

        Ok(Jwe {
            header: jwec.header.clone(),
            payload,
        })
    }
}

/// A JWE outer encipher for RSA-OAEP. This type can only encipher.
/// You should prefer [crate::crypto::JweEcdhEsA256KWEncipher] or [crate::crypto::JweA256KWEncipher]
pub struct JweRSAOAEPEncipher {
    rsa_pub_key: RS256PublicKey,
}

impl From<RS256PublicKey> for JweRSAOAEPEncipher {
    fn from(rsa_pub_key: RS256PublicKey) -> Self {
        JweRSAOAEPEncipher { rsa_pub_key }
    }
}

impl JweRSAOAEPEncipher {
    /// Given a JWE, encipher its content to a compact form.
    pub fn encipher<E: JweEncipherInnerA256>(&self, jwe: &Jwe) -> Result<JweCompact, JwtError> {
        let encipher = E::new_ephemeral()?;
        encipher.encipher_inner(self, jwe)
    }
}

impl JweEncipherOuterA256 for JweRSAOAEPEncipher {
    fn set_header_alg(&self, hdr: &mut JweProtectedHeader) -> Result<(), JwtError> {
        hdr.alg = JweAlg::RSA_OAEP;
        Ok(())
    }

    fn wrap_key(&self, key_to_wrap: Aes256Key) -> Result<Vec<u8>, JwtError> {
        let mut rng = rand::thread_rng();
        let padding = Oaep::new::<sha1::Sha1>();
        self.rsa_pub_key
            .encrypt(&mut rng, padding, key_to_wrap.as_slice())
            .map_err(|err| {
                debug!(?err, "failed to encrypt key");
                JwtError::CryptoError
            })
    }
}

#[cfg(test)]
mod tests {
    use super::{JweRSAOAEPDecipher, JweRSAOAEPEncipher};
    use crate::compact::JweCompact;
    use crate::crypto::a256gcm::JweA256GCMEncipher;
    use crate::jwe::JweBuilder;
    use base64::{engine::general_purpose, Engine as _};
    use crypto_glue::rsa::{self, BigUint, RS256PrivateKey, RS256PublicKey};
    use std::convert::TryFrom;
    use std::str::FromStr;

    fn rsa_from_private_components(n: &str, e: &str, d: &str) -> RS256PrivateKey {
        let n = general_purpose::URL_SAFE_NO_PAD
            .decode(n)
            .expect("Invalid Key");

        let e = general_purpose::URL_SAFE_NO_PAD
            .decode(e)
            .expect("Invalid Key");

        let d = general_purpose::URL_SAFE_NO_PAD
            .decode(d)
            .expect("Invalid Key");

        let nbn = BigUint::from_bytes_be(&n);
        let ebn = BigUint::from_bytes_be(&e);
        let dbn = BigUint::from_bytes_be(&d);

        RS256PrivateKey::from_components(nbn, ebn, dbn, vec![]).expect("Invalid parameters")
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
);

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

        let rsa_priv_key = rsa::new_key(0).unwrap();

        let rsa_pub_key = RS256PublicKey::from(&rsa_priv_key);

        let jwe_rsa_oaep_decipher = JweRSAOAEPDecipher::from(rsa_priv_key);

        let jwe_rsa_oaep_encipher = JweRSAOAEPEncipher::from(rsa_pub_key);

        let jwe_encrypted = jwe_rsa_oaep_encipher
            .encipher::<JweA256GCMEncipher>(&jweb)
            .expect("Unable to encrypt.");

        // Decrypt with the partner.
        let decrypted = jwe_rsa_oaep_decipher
            .decipher(&jwe_encrypted)
            .expect("Unable to decrypt.");

        assert_eq!(decrypted.payload(), input);
    }
}
