//! JWS Signing and Verification Structures

use crate::error::JwtError;
use openssl::{hash, pkey, rand, sign};

use std::fmt;
use std::hash::{Hash, Hasher};

use crate::compact::{JwaAlg, JwsCompact, ProtectedHeader};
use crate::jws::JwsCompactSign2Data;
use crate::traits::*;
use base64::{engine::general_purpose, Engine as _};

/// A JWS signer that creates HMAC SHA256 signatures.
#[derive(Clone)]
pub struct JwsHs256Signer {
    /// The KID of this signer. This is the sha256 digest of the key.
    kid: String,
    /// Private Key
    skey: pkey::PKey<pkey::Private>,
    /// The matching digest
    digest: hash::MessageDigest,
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
        let digest = hash::MessageDigest::sha256();

        let mut buf = [0; 32];
        rand::rand_bytes(&mut buf).map_err(|e| {
            error!("{:?}", e);
            JwtError::OpenSSLError
        })?;

        // Can it become a pkey?
        let skey = pkey::PKey::hmac(&buf).map_err(|e| {
            error!("{:?}", e);
            JwtError::OpenSSLError
        })?;

        let mut kid = [0; 32];
        rand::rand_bytes(&mut kid).map_err(|e| {
            error!("{:?}", e);
            JwtError::OpenSSLError
        })?;

        let kid = hash::hash(digest, &kid)
            .map(|out| {
                let half = out.len() / 2;
                hex::encode(out.split_at(half).0)
            })
            .map_err(|_| JwtError::OpenSSLError)?;

        Ok(JwsHs256Signer { kid, skey, digest })
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

        let mut signer = sign::Signer::new(self.digest, &self.skey).map_err(|e| {
            debug!(?e);
            JwtError::OpenSSLError
        })?;

        signer
            .update(hdr_b64.as_bytes())
            .and_then(|_| signer.update(".".as_bytes()))
            .and_then(|_| signer.update(sign_data.payload_b64.as_bytes()))
            .map_err(|e| {
                debug!(?e);
                JwtError::OpenSSLError
            })?;

        let signature = signer.sign_to_vec().map_err(|e| {
            debug!(?e);
            JwtError::OpenSSLError
        })?;

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
            return Err(JwtError::OpenSSLError);
        }

        let digest = hash::MessageDigest::sha256();

        let kid = hash::hash(digest, buf)
            .map(hex::encode)
            .map_err(|_| JwtError::OpenSSLError)?;

        let skey = pkey::PKey::hmac(buf).map_err(|e| {
            error!("{:?}", e);
            JwtError::OpenSSLError
        })?;

        Ok(JwsHs256Signer { kid, skey, digest })
    }
}

impl JwsSigner for JwsHs256Signer {
    fn get_kid(&self) -> &str {
        self.kid.as_str()
    }

    fn update_header(&self, header: &mut ProtectedHeader) -> Result<(), JwtError> {
        // Update the alg to match.
        header.alg = JwaAlg::HS256;

        header.kid = Some(self.kid.clone());

        Ok(())
    }

    fn sign<V: JwsSignable>(&self, jws: &V) -> Result<V::Signed, JwtError> {
        let mut sign_data = jws.data()?;

        // Let the signer update the header as required.
        self.update_header(&mut sign_data.header)?;

        self.sign_inner(jws, sign_data)
    }
}

impl JwsVerifier for JwsHs256Signer {
    fn get_kid(&self) -> Option<&str> {
        Some(self.kid.as_str())
    }

    fn verify<V: JwsVerifiable>(&self, jwsc: &V) -> Result<V::Verified, JwtError> {
        let signed_data = jwsc.data();

        if signed_data.header.alg != JwaAlg::HS256 {
            debug!(jwsc_alg = ?signed_data.header.alg, "validator algorithm mismatch");
            return Err(JwtError::ValidatorAlgMismatch);
        }

        let mut signer = sign::Signer::new(self.digest, &self.skey).map_err(|e| {
            debug!(?e);
            JwtError::OpenSSLError
        })?;

        signer
            .update(signed_data.hdr_bytes)
            .and_then(|_| signer.update(".".as_bytes()))
            .and_then(|_| signer.update(signed_data.payload_bytes))
            .map_err(|e| {
                debug!(?e);
                JwtError::OpenSSLError
            })?;

        let ver_sig = signer.sign_to_vec().map_err(|e| {
            debug!(?e);
            JwtError::OpenSSLError
        })?;

        if signed_data.signature_bytes == ver_sig.as_slice() {
            signed_data.release().and_then(|d| jwsc.post_process(d))
        } else {
            debug!("invalid signature");
            Err(JwtError::InvalidSignature)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::JwsHs256Signer;
    use crate::compact::JwsCompact;
    use crate::traits::*;
    use base64::{engine::general_purpose, Engine as _};
    use std::convert::TryFrom;
    use std::str::FromStr;

    #[test]
    fn rfc7519_hs256_validation_example_legacy() {
        let _ = tracing_subscriber::fmt::try_init();
        let test_jws = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

        let jwsc = JwsCompact::from_str(test_jws).unwrap();

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

        let jwsc = JwsCompact::from_str(test_jws).unwrap();

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
}
