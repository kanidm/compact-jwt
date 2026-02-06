//! JWS Signing and Verification Structures
use crate::compact::{JwaAlg, JwsCompact, ProtectedHeader};
use crate::error::JwtError;
use crate::jws::JwsCompactSign2Data;
use crate::traits::*;
use crate::KID_LEN;
use base64::{engine::general_purpose, Engine as _};
use crypto_glue::{
    hmac_s256::{self, HmacSha256, HmacSha256Bytes, HmacSha256Key, HmacSha256Output},
    traits::Mac,
};
use std::fmt;
use std::hash::{Hash, Hasher};

/// A JWS signer that creates HMAC SHA256 signatures.
#[derive(Clone)]
pub struct JwsHs256Signer {
    /// If the KID should be embedded during signing
    sign_option_embed_kid: bool,
    /// The KID of this signer. This is a truncated hmac sha256 digest.
    kid: String,
    /// Private Key
    skey: HmacSha256Key,
}

impl fmt::Debug for JwsHs256Signer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JwsHs256Signer")
            .field("kid", &self.kid)
            .finish()
    }
}

impl PartialEq for JwsHs256Signer {
    fn eq(&self, other: &Self) -> bool {
        self.kid == other.kid
    }
}

impl Eq for JwsHs256Signer {}

impl Hash for JwsHs256Signer {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.kid.hash(state);
    }
}

impl JwsHs256Signer {
    /// Create a new secure private key for signing
    pub fn generate_hs256() -> Result<Self, JwtError> {
        let skey = hmac_s256::new_key();
        Ok(Self::from(skey))
    }

    pub(crate) fn sign_inner<V: JwsSignable>(
        &self,
        jws: &V,
        sign_data: JwsCompactSign2Data,
    ) -> Result<V::Signed, JwtError> {
        let hdr_b64 = serde_json::to_vec(&sign_data.header)
            .map_err(|e| {
                debug!(?e);
                JwtError::InvalidHeaderFormat
            })
            .map(|bytes| general_purpose::URL_SAFE_NO_PAD.encode(bytes))?;

        let mut hmac = HmacSha256::new(&self.skey);
        hmac.update(hdr_b64.as_bytes());
        hmac.update(".".as_bytes());
        hmac.update(sign_data.payload_b64.as_bytes());

        let signature = hmac.finalize().into_bytes().to_vec();

        let jwsc = JwsCompact {
            header: sign_data.header,
            hdr_b64,
            payload_b64: sign_data.payload_b64,
            signature,
        };

        jws.post_process(jwsc)
    }
}

impl TryFrom<&[u8]> for JwsHs256Signer {
    type Error = JwtError;

    fn try_from(buf: &[u8]) -> Result<Self, Self::Error> {
        if buf.len() < 32 {
            return Err(JwtError::CryptoError);
        }

        let mut skey = HmacSha256Key::default();
        let key_bytes_mut = skey.as_mut_slice();

        if buf.len() > key_bytes_mut.len() {
            return Err(JwtError::CryptoError);
        }

        key_bytes_mut[..buf.len()].copy_from_slice(buf);

        Ok(Self::from(skey))
    }
}

impl AsRef<HmacSha256Key> for JwsHs256Signer {
    fn as_ref(&self) -> &HmacSha256Key {
        &self.skey
    }
}

impl From<HmacSha256Key> for JwsHs256Signer {
    fn from(skey: HmacSha256Key) -> Self {
        let kid = kid(&skey);

        JwsHs256Signer {
            kid,
            skey,
            sign_option_embed_kid: true,
        }
    }
}

impl JwsSigner for JwsHs256Signer {
    fn get_kid(&self) -> &str {
        self.kid.as_str()
    }

    fn set_kid(&mut self, kid: &str) {
        self.sign_option_embed_kid = true;
        self.kid = kid.to_string();
    }

    fn get_legacy_kid(&self) -> &str {
        self.kid.as_str()
    }

    fn update_header(&self, header: &mut ProtectedHeader) -> Result<(), JwtError> {
        // Update the alg to match.
        header.alg = JwaAlg::HS256;

        // If the signer is configured to include the KID
        if header.kid.is_none() {
            header.kid = self.sign_option_embed_kid.then(|| self.kid.clone());
        }

        Ok(())
    }

    fn sign<V: JwsSignable>(&self, jws: &V) -> Result<V::Signed, JwtError> {
        let mut sign_data = jws.data()?;

        // Let the signer update the header as required.
        self.update_header(&mut sign_data.header)?;

        self.sign_inner(jws, sign_data)
    }

    fn set_sign_option_embed_kid(&self, value: bool) -> Self {
        JwsHs256Signer {
            sign_option_embed_kid: value,
            ..self.to_owned()
        }
    }
}

impl JwsVerifier for JwsHs256Signer {
    fn get_kid(&self) -> &str {
        self.kid.as_str()
    }

    fn verify<V: JwsVerifiable>(&self, jwsc: &V) -> Result<V::Verified, JwtError> {
        let signed_data = jwsc.data();

        if signed_data.header.alg != JwaAlg::HS256 {
            debug!(jwsc_alg = ?signed_data.header.alg, "validator algorithm mismatch");
            return Err(JwtError::ValidatorAlgMismatch);
        }

        let signature =
            HmacSha256Bytes::from_exact_iter(signed_data.signature_bytes.iter().copied())
                .map(HmacSha256Output::new)
                .ok_or_else(|| {
                    debug!("Invalid HMAC signature length");
                    JwtError::CryptoError
                })?;

        let mut hmac = HmacSha256::new(&self.skey);
        hmac.update(signed_data.hdr_bytes);
        hmac.update(".".as_bytes());
        hmac.update(signed_data.payload_bytes);

        let verification_signature = hmac.finalize();

        // This is a constant time check.
        if signature == verification_signature {
            signed_data.release().and_then(|d| jwsc.post_process(d))
        } else {
            debug!("invalid signature");
            Err(JwtError::InvalidSignature)
        }
    }
}

fn kid(skey: &HmacSha256Key) -> String {
    let mut hmac = HmacSha256::new(skey);
    hmac.update(b"key identifier");
    let hashout = hmac.finalize();
    let mut kid = hex::encode(hashout.into_bytes());
    kid.truncate(KID_LEN);
    kid
}

#[cfg(test)]
mod tests {
    use super::{hmac_s256, JwsHs256Signer};
    use crate::compact::JwsCompact;
    use crate::jws::JwsBuilder;
    use crate::traits::*;
    use base64::{engine::general_purpose, Engine as _};
    use std::convert::TryFrom;
    use std::str::FromStr;

    #[test]
    fn rfc7519_hs256_validation_example_legacy() {
        let _ = tracing_subscriber::fmt::try_init();
        let test_jws = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

        let jwsc = JwsCompact::from_str(test_jws).expect("Failed to parse JWS compact");

        assert!(jwsc.check_vectors(
            &[
                101, 121, 74, 48, 101, 88, 65, 105, 79, 105, 74, 75, 86, 49, 81, 105, 76, 65, 48,
                75, 73, 67, 74, 104, 98, 71, 99, 105, 79, 105, 74, 73, 85, 122, 73, 49, 78, 105,
                74, 57, 46, 101, 121, 74, 112, 99, 51, 77, 105, 79, 105, 74, 113, 98, 50, 85, 105,
                76, 65, 48, 75, 73, 67, 74, 108, 101, 72, 65, 105, 79, 106, 69, 122, 77, 68, 65,
                52, 77, 84, 107, 122, 79, 68, 65, 115, 68, 81, 111, 103, 73, 109, 104, 48, 100, 72,
                65, 54, 76, 121, 57, 108, 101, 71, 70, 116, 99, 71, 120, 108, 76, 109, 78, 118, 98,
                83, 57, 112, 99, 49, 57, 121, 98, 50, 57, 48, 73, 106, 112, 48, 99, 110, 86, 108,
                102, 81
            ],
            &[
                116, 24, 223, 180, 151, 153, 224, 37, 79, 250, 96, 125, 216, 173, 187, 186, 22,
                212, 37, 77, 105, 214, 191, 240, 91, 88, 5, 88, 83, 132, 141, 121
            ]
        ));

        assert!(jwsc.get_jwk_pubkey_url().is_none());
        assert!(jwsc.get_jwk_pubkey().is_none());

        let skey = general_purpose::URL_SAFE_NO_PAD.decode(
        "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"
        ).expect("Invalid key");

        let jws_signer =
            JwsHs256Signer::try_from(skey.as_slice()).expect("Unable to create validator");

        let released = jws_signer.verify(&jwsc).expect("Unable to validate jws");
        trace!("rel -> {:?}", released);
    }

    #[test]
    fn rfc7519_hs256_validation_example() {
        let _ = tracing_subscriber::fmt::try_init();
        let test_jws = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

        let jwsc = JwsCompact::from_str(test_jws).expect("Failed to parse JWS compact");

        assert!(jwsc.check_vectors(
            &[
                101, 121, 74, 48, 101, 88, 65, 105, 79, 105, 74, 75, 86, 49, 81, 105, 76, 65, 48,
                75, 73, 67, 74, 104, 98, 71, 99, 105, 79, 105, 74, 73, 85, 122, 73, 49, 78, 105,
                74, 57, 46, 101, 121, 74, 112, 99, 51, 77, 105, 79, 105, 74, 113, 98, 50, 85, 105,
                76, 65, 48, 75, 73, 67, 74, 108, 101, 72, 65, 105, 79, 106, 69, 122, 77, 68, 65,
                52, 77, 84, 107, 122, 79, 68, 65, 115, 68, 81, 111, 103, 73, 109, 104, 48, 100, 72,
                65, 54, 76, 121, 57, 108, 101, 71, 70, 116, 99, 71, 120, 108, 76, 109, 78, 118, 98,
                83, 57, 112, 99, 49, 57, 121, 98, 50, 57, 48, 73, 106, 112, 48, 99, 110, 86, 108,
                102, 81
            ],
            &[
                116, 24, 223, 180, 151, 153, 224, 37, 79, 250, 96, 125, 216, 173, 187, 186, 22,
                212, 37, 77, 105, 214, 191, 240, 91, 88, 5, 88, 83, 132, 141, 121
            ]
        ));

        assert!(jwsc.get_jwk_pubkey_url().is_none());
        assert!(jwsc.get_jwk_pubkey().is_none());

        let skey = general_purpose::URL_SAFE_NO_PAD.decode(
        "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"
        ).expect("Invalid key");

        let jws_signer =
            JwsHs256Signer::try_from(skey.as_slice()).expect("Unable to create validator");

        let released = jws_signer.verify(&jwsc).expect("Unable to validate jws");
        trace!("rel -> {:?}", released);
    }

    #[test]
    fn hs256_shortform() {
        use uuid::Uuid;

        /*
        use serde::{Serialize, Deserialize};
        #[derive(Default, Debug, Serialize, Clone, Deserialize, PartialEq)]
        struct Inner {
            exp: i64,
            id: Uuid,
        }
        */

        let _ = tracing_subscriber::fmt::try_init();

        let skey = hmac_s256::new_key();

        let mut jws_signer = JwsHs256Signer::from(skey);
        let mut kid = crate::traits::JwsSigner::get_kid(&jws_signer).to_string();
        kid.truncate(12);
        jws_signer.set_kid(&kid);

        let id = Uuid::default();
        let payload = id.as_bytes().to_vec();

        let jws = JwsBuilder::from(payload)
            // .set_typ(Some("a1"))
            .build();

        /*
        let inner = Inner { exp: i64::MAX, id };
        let jws = JwsBuilder::into_json(&inner).unwrap()
            .build();
        */

        let jwsc = jws_signer.sign(&jws).expect("Failed to sign");

        warn!(?jwsc, length = %jwsc.to_string().len());
        warn!(%jwsc);

        assert!(jwsc.to_string().len() < 128);
    }
}
