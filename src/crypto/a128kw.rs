use crate::compact::{JweCompact, JweEnc};
use crate::JwtError;

use super::a128cbc_hs256::JweA128CBCHS256Decipher;

use openssl::aes::{unwrap_key, AesKey};
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::sign::Signer;
use openssl::symm::{Cipher, Crypter, Mode};

// Do I need some inner type to handle the enc bit?

#[derive(Clone)]
pub struct JweA128KWEncipher {
    wrap_key: [u8; 16],
}

impl JweA128KWEncipher {
    pub fn decipher(&self, jwec: &JweCompact) -> Result<Vec<u8>, JwtError> {
        // From what I can see the cek uses the same IV as the ciphertext?
        let wrap_key = AesKey::new_decrypt(&self.wrap_key).map_err(|ossl_err| {
            debug!(?ossl_err);
            JwtError::OpenSSLError
        })?;

        let mut expected_wrap_key_buffer = match jwec.header.enc {
            JweEnc::A128GCM => todo!(),
            JweEnc::A128CBC_HS256 => JweA128CBCHS256Decipher::key_buffer(),
        };

        let len = unwrap_key(
            &wrap_key,
            None,
            &mut expected_wrap_key_buffer,
            &jwec.content_enc_key,
        )
        .map_err(|ossl_err| {
            debug!(?ossl_err);
            JwtError::OpenSSLError
        })?;

        debug!(?len, ?expected_wrap_key_buffer);

        let jwe_decipher = match jwec.header.enc {
            JweEnc::A128GCM => todo!(),
            JweEnc::A128CBC_HS256 => {
                JweA128CBCHS256Decipher::try_from(expected_wrap_key_buffer.as_slice())?
            }
        };

        jwe_decipher.decipher_inner(jwec)
    }
}

impl TryFrom<Vec<u8>> for JweA128KWEncipher {
    type Error = JwtError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        if value.len() != 16 {
            // Wrong key size.
            return Err(JwtError::InvalidKey);
        }

        let mut wrap_key = [0; 16];

        wrap_key.copy_from_slice(&value);

        Ok(JweA128KWEncipher { wrap_key })
    }
}

#[cfg(test)]
mod tests {
    use super::JweA128KWEncipher;
    use crate::compact::JweCompact;
    use crate::traits::*;
    use base64::{engine::general_purpose, Engine as _};
    use std::convert::TryFrom;
    use std::str::FromStr;

    #[test]
    fn rfc7516_a128kw_validation_example() {
        // Taken from https://www.rfc-editor.org/rfc/rfc7516.html#appendix-A.3

        let _ = tracing_subscriber::fmt::try_init();

        let test_jwe = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ.AxY8DCtDaGlsbGljb3RoZQ.KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY.U0m_YmjN04DJvceFICbCVQ";
        let a128kw_key = general_purpose::URL_SAFE_NO_PAD
            .decode("GawgguFyGrWKav7AX4VKUg")
            .expect("Invalid Key");

        let jwec = JweCompact::from_str(test_jwe).unwrap();

        assert!(jwec.to_string() == test_jwe);

        // Check vectors
        jwec.check_vectors(
            // Content Encryption Key
            &[
                232, 160, 123, 211, 183, 76, 245, 132, 200, 128, 123, 75, 190, 216, 22, 67, 201,
                138, 193, 186, 9, 91, 122, 31, 246, 90, 28, 139, 57, 3, 76, 124, 193, 11, 98, 37,
                173, 61, 104, 57,
            ],
            // IV
            &[
                3, 22, 60, 12, 43, 67, 104, 105, 108, 108, 105, 99, 111, 116, 104, 101,
            ],
            // Addition Authenticated Data
            // &[101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 66, 77, 84, 73, 52, 83, 49, 99, 105, 76, 67, 74, 108, 98, 109, 77, 105, 79, 105, 74, 66, 77, 84, 73, 52, 81, 48, 74, 68, 76, 85, 104, 84, 77, 106, 85, 50, 73, 110, 48],
            // Cipher Text
            &[
                40, 57, 83, 181, 119, 33, 133, 148, 198, 185, 243, 24, 152, 230, 6, 75, 129, 223,
                127, 19, 210, 82, 183, 230, 168, 33, 215, 104, 143, 112, 56, 102,
            ],
            // Authentication Tag
            &[
                83, 73, 191, 98, 104, 205, 211, 128, 201, 189, 199, 133, 32, 38, 194, 85,
            ],
        );

        assert!(jwec.get_jwk_pubkey_url().is_none());
        assert!(jwec.get_jwk_pubkey().is_none());

        let a128kw_encipher =
            JweA128KWEncipher::try_from(a128kw_key).expect("Unable to create encipher");

        let released = a128kw_encipher
            .decipher(&jwec)
            .expect("Unable to decipher jwe");

        assert_eq!(
            released.as_slice(),
            &[
                76, 105, 118, 101, 32, 108, 111, 110, 103, 32, 97, 110, 100, 32, 112, 114, 111,
                115, 112, 101, 114, 46
            ]
        );
    }
}
