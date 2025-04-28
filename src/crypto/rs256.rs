//! JWS Signing and Verification Structures

use crate::compact::{JwaAlg, Jwk, JwkUse, JwsCompact, ProtectedHeader};
use crate::error::JwtError;
use crate::traits::*;
use crate::KID_LEN;
use base64::{engine::general_purpose, Engine as _};
use crypto_glue::{
    rsa::{
        self, BigUint, RS256Digest, RS256PrivateKey, RS256PublicKey, RS256Signature,
        RS256SigningKey, RS256VerifyingKey,
    },
    s256,
    traits::{
        Digest, DigestSigner, DigestVerifier, Pkcs8DecodePrivateKey, Pkcs8EncodePrivateKey,
        PublicKeyParts, SignatureEncoding, SpkiDecodePublicKey, SpkiEncodePublicKey, Zeroizing,
    },
};
use std::fmt;
use std::hash::{Hash, Hasher};

/// A JWS signer that creates RSA SHA256 signatures.
#[derive(Clone)]
pub struct JwsRs256Signer {
    /// If the public jwk should be embeded during signing
    sign_option_embed_jwk: bool,
    /// If the KID should be embedded during signing
    sign_option_embed_kid: bool,
    /// The KID of this validator
    kid: String,
    /// Private Key
    skey: RS256PrivateKey,
}

impl fmt::Debug for JwsRs256Signer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JwsRs256Signer")
            .field("kid", &self.kid)
            .finish()
    }
}

impl PartialEq for JwsRs256Signer {
    fn eq(&self, other: &Self) -> bool {
        self.kid == other.kid
    }
}

impl Eq for JwsRs256Signer {}

impl Hash for JwsRs256Signer {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.kid.hash(state);
    }
}

impl JwsRs256Signer {
    /// Enable or disable embedding of the public jwk into the Jws that are signed
    /// by this signer
    pub fn set_sign_option_embed_jwk(mut self, value: bool) -> Self {
        self.sign_option_embed_jwk = value;
        self
    }

    /// Create a new secure private key for signing
    pub fn generate_rs256() -> Result<Self, JwtError> {
        let skey = rsa::new_key(rsa::MIN_BITS).map_err(|err| {
            debug!(?err);
            JwtError::CryptoError
        })?;

        let public = RS256PublicKey::from(&skey);

        let kid = kid_from_public(&public)?;

        Ok(JwsRs256Signer {
            kid,
            skey,
            sign_option_embed_jwk: false,
            sign_option_embed_kid: true,
        })
    }

    /// Restore this JwsSignerEnum from a DER private key.
    pub fn from_rs256_der(der: &[u8]) -> Result<Self, JwtError> {
        let skey = RS256PrivateKey::from_pkcs8_der(der).map_err(|err| {
            debug!(?err);
            JwtError::CryptoError
        })?;

        let public = RS256PublicKey::from(&skey);

        let kid = kid_from_public(&public)?;

        Ok(JwsRs256Signer {
            kid,
            skey,
            sign_option_embed_jwk: false,
            sign_option_embed_kid: true,
        })
    }

    /// Export this signer to a DER private key.
    pub fn private_key_to_der(&self) -> Result<Zeroizing<Vec<u8>>, JwtError> {
        self.skey
            .to_pkcs8_der()
            .map(|der| der.to_bytes())
            .map_err(|err| {
                debug!(?err);
                JwtError::CryptoError
            })
    }

    /// Get the public Jwk from this signer
    pub fn public_key_as_jwk(&self) -> Result<Jwk, JwtError> {
        let public_key_n = self.skey.n().to_bytes_be();
        let public_key_e = self.skey.e().to_bytes_be();

        Ok(Jwk::RSA {
            n: public_key_n.into(),
            e: public_key_e.into(),
            alg: Some(JwaAlg::RS256),
            use_: Some(JwkUse::Sig),
            kid: Some(self.kid.clone()),
        })
    }
}

impl JwsSignerToVerifier for JwsRs256Signer {
    type Verifier = JwsRs256Verifier;

    fn get_verifier(&self) -> Result<Self::Verifier, JwtError> {
        let pkey = RS256PublicKey::from(&self.skey);

        Ok(JwsRs256Verifier {
            kid: self.kid.clone(),
            pkey,
        })
    }
}

impl JwsSigner for JwsRs256Signer {
    fn get_kid(&self) -> &str {
        self.kid.as_str()
    }

    fn get_legacy_kid(&self) -> &str {
        // self.legacy_kid.as_str()
        "to do"
    }

    fn update_header(&self, header: &mut ProtectedHeader) -> Result<(), JwtError> {
        // Update the alg to match.
        header.alg = JwaAlg::RS256;

        // If the signer is configured to include the KID
        if header.kid.is_none() {
            header.kid = self.sign_option_embed_kid.then(|| self.kid.clone());
        }

        // if were were asked to ember the jwk, do so now.
        if self.sign_option_embed_jwk {
            header.jwk = self.public_key_as_jwk().map(Some)?;
        }

        Ok(())
    }

    fn sign<V: JwsSignable>(&self, jws: &V) -> Result<V::Signed, JwtError> {
        let mut sign_data = jws.data()?;

        // Let the signer update the header as required.
        self.update_header(&mut sign_data.header)?;

        let hdr_b64 = serde_json::to_vec(&sign_data.header)
            .map_err(|e| {
                debug!(?e);
                JwtError::InvalidHeaderFormat
            })
            .map(|bytes| general_purpose::URL_SAFE_NO_PAD.encode(bytes))?;

        let mut hasher = RS256Digest::new();

        hasher.update(hdr_b64.as_bytes());
        hasher.update(".".as_bytes());
        hasher.update(sign_data.payload_b64.as_bytes());

        let signer = RS256SigningKey::new(self.skey.clone());

        let signature: RS256Signature = signer.try_sign_digest(hasher).map_err(|err| {
            debug!(?err);
            JwtError::CryptoError
        })?;

        let jwsc = JwsCompact {
            header: sign_data.header,
            hdr_b64,
            payload_b64: sign_data.payload_b64,
            signature: signature.to_vec(),
        };

        jws.post_process(jwsc)
    }

    fn set_sign_option_embed_kid(&self, value: bool) -> Self {
        JwsRs256Signer {
            sign_option_embed_kid: value,
            ..self.to_owned()
        }
    }
}

/// A JWS verifier that verifies RSA SHA256 signatures.
#[derive(Clone)]
pub struct JwsRs256Verifier {
    /// The KID of this validator
    kid: String,
    /// Public Key
    pkey: RS256PublicKey,
}

impl JwsRs256Verifier {
    /// Create an RSA-SHA256 verifier from a public key in SPKI DER format.
    pub fn from_rs256_der(der: &[u8]) -> Result<Self, JwtError> {
        let pkey = RS256PublicKey::from_public_key_der(der).map_err(|err| {
            debug!(?err);
            JwtError::CryptoError
        })?;

        let kid = kid_from_public(&pkey)?;

        Ok(JwsRs256Verifier { kid, pkey })
    }

    /// Export the content of this verifier as a public JWK
    pub fn public_key_as_jwk(&self) -> Result<Jwk, JwtError> {
        let public_key_n = self.pkey.n().to_bytes_be();
        let public_key_e = self.pkey.e().to_bytes_be();

        Ok(Jwk::RSA {
            n: public_key_n.into(),
            e: public_key_e.into(),
            alg: Some(JwaAlg::RS256),
            use_: Some(JwkUse::Sig),
            kid: Some(self.kid.clone()),
        })
    }

    /// Export the content of this public key in SPKI DER format
    pub fn public_key_to_der(&self) -> Result<Vec<u8>, JwtError> {
        self.pkey
            .to_public_key_der()
            .map_err(|err| {
                debug!(?err);
                JwtError::CryptoError
            })
            .map(|pkey| pkey.into_vec())
    }
}

impl TryFrom<&Jwk> for JwsRs256Verifier {
    type Error = JwtError;

    fn try_from(value: &Jwk) -> Result<Self, Self::Error> {
        match value {
            Jwk::RSA {
                n,
                e,
                alg: _,
                use_: _,
                kid,
            } => {
                let n = BigUint::from_bytes_be(n);
                let e = BigUint::from_bytes_be(e);

                let pkey = RS256PublicKey::new(n, e).map_err(|err| {
                    debug!(?err);
                    JwtError::CryptoError
                })?;

                let kid = if let Some(kid) = kid.clone() {
                    kid
                } else {
                    kid_from_public(&pkey)?
                };

                Ok(JwsRs256Verifier { kid, pkey })
            }
            alg_request => {
                debug!(?alg_request, "validator algorithm mismatch");
                Err(JwtError::ValidatorAlgMismatch)
            }
        }
    }
}

impl JwsVerifier for JwsRs256Verifier {
    fn get_kid(&self) -> &str {
        &self.kid
    }

    fn verify<V: JwsVerifiable>(&self, jwsc: &V) -> Result<V::Verified, JwtError> {
        let signed_data = jwsc.data();

        if signed_data.header.alg != JwaAlg::RS256 {
            debug!(jwsc_alg = ?signed_data.header.alg, "validator algorithm mismatch");
            return Err(JwtError::ValidatorAlgMismatch);
        }

        let signature = RS256Signature::try_from(signed_data.signature_bytes).map_err(|err| {
            debug!(?err, "invalid signature length");
            JwtError::InvalidSignature
        })?;

        let mut hasher = RS256Digest::new();

        hasher.update(signed_data.hdr_bytes);
        hasher.update(".".as_bytes());
        hasher.update(signed_data.payload_bytes);

        let verifier = RS256VerifyingKey::new(self.pkey.clone());

        verifier.verify_digest(hasher, &signature).map_err(|err| {
            debug!(?err, "invalid signature");
            JwtError::InvalidSignature
        })?;

        signed_data.release().and_then(|d| jwsc.post_process(d))
    }
}

fn kid_from_public(pub_key: &RS256PublicKey) -> Result<String, JwtError> {
    let mut hasher = s256::Sha256::new();
    let pkey_der = pub_key.to_public_key_der().map_err(|err| {
        debug!(?err);
        JwtError::CryptoError
    })?;
    hasher.update(&pkey_der);
    let hashout = hasher.finalize();
    let mut kid = hex::encode(hashout);
    kid.truncate(KID_LEN);
    Ok(kid)
}

#[cfg(test)]
mod tests {
    use super::{JwsRs256Signer, JwsRs256Verifier};
    use crate::compact::{Jwk, JwsCompact};
    use crate::jws::JwsBuilder;
    use crate::traits::*;
    use std::convert::TryFrom;
    use std::str::FromStr;

    // RSA3072
    // https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.2
    #[test]
    fn rfc7515_rs256_validation_example() {
        let _ = tracing_subscriber::fmt::try_init();
        let test_jws = "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw";

        let jwsc = JwsCompact::from_str(test_jws).unwrap();

        assert!(jwsc.to_string() == test_jws);

        assert!(jwsc.check_vectors(
            &[
                101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 83, 85, 122, 73, 49, 78, 105, 74,
                57, 46, 101, 121, 74, 112, 99, 51, 77, 105, 79, 105, 74, 113, 98, 50, 85, 105, 76,
                65, 48, 75, 73, 67, 74, 108, 101, 72, 65, 105, 79, 106, 69, 122, 77, 68, 65, 52,
                77, 84, 107, 122, 79, 68, 65, 115, 68, 81, 111, 103, 73, 109, 104, 48, 100, 72, 65,
                54, 76, 121, 57, 108, 101, 71, 70, 116, 99, 71, 120, 108, 76, 109, 78, 118, 98, 83,
                57, 112, 99, 49, 57, 121, 98, 50, 57, 48, 73, 106, 112, 48, 99, 110, 86, 108, 102,
                81
            ],
            &[
                112, 46, 33, 137, 67, 232, 143, 209, 30, 181, 216, 45, 191, 120, 69, 243, 65, 6,
                174, 27, 129, 255, 247, 115, 17, 22, 173, 209, 113, 125, 131, 101, 109, 66, 10,
                253, 60, 150, 238, 221, 115, 162, 102, 62, 81, 102, 104, 123, 0, 11, 135, 34, 110,
                1, 135, 237, 16, 115, 249, 69, 229, 130, 173, 252, 239, 22, 216, 90, 121, 142, 232,
                198, 109, 219, 61, 184, 151, 91, 23, 208, 148, 2, 190, 237, 213, 217, 217, 112, 7,
                16, 141, 178, 129, 96, 213, 248, 4, 12, 167, 68, 87, 98, 184, 31, 190, 127, 249,
                217, 46, 10, 231, 111, 36, 242, 91, 51, 187, 230, 244, 74, 230, 30, 177, 4, 10,
                203, 32, 4, 77, 62, 249, 18, 142, 212, 1, 48, 121, 91, 212, 189, 59, 65, 238, 202,
                208, 102, 171, 101, 25, 129, 253, 228, 141, 247, 127, 55, 45, 195, 139, 159, 175,
                221, 59, 239, 177, 139, 93, 163, 204, 60, 46, 176, 47, 158, 58, 65, 214, 18, 202,
                173, 21, 145, 18, 115, 160, 95, 35, 185, 232, 56, 250, 175, 132, 157, 105, 132, 41,
                239, 90, 30, 136, 121, 130, 54, 195, 212, 14, 96, 69, 34, 165, 68, 200, 242, 122,
                122, 45, 184, 6, 99, 209, 108, 247, 202, 234, 86, 222, 64, 92, 178, 33, 90, 69,
                178, 194, 85, 102, 181, 90, 193, 167, 72, 160, 112, 223, 200, 163, 42, 70, 149, 67,
                208, 25, 238, 251, 71
            ]
        ));

        assert!(jwsc.get_jwk_pubkey_url().is_none());
        assert!(jwsc.get_jwk_pubkey().is_none());

        let pkey = r#"{
            "kty":"RSA",
            "n":"ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ",
            "e":"AQAB"
        }"#;

        let pkey: Jwk = serde_json::from_str(pkey).expect("Invalid JWK");
        trace!("jwk -> {:?}", pkey);

        let jws_validator = JwsRs256Verifier::try_from(&pkey).expect("Unable to create validator");

        let released = jws_validator.verify(&jwsc).expect("Unable to validate jws");
        trace!("rel -> {:?}", released);
    }

    #[test]
    fn rs256_key_generate_cycle() {
        let _ = tracing_subscriber::fmt::try_init();
        let jws_rs256_signer =
            JwsRs256Signer::generate_rs256().expect("failed to construct signer.");

        let der = jws_rs256_signer
            .private_key_to_der()
            .expect("Failed to extract DER");

        let jws_rs256_signer = JwsRs256Signer::from_rs256_der(&der)
            .expect("Failed to restore signer")
            .set_sign_option_embed_jwk(true);

        // This time we'll add the jwk pubkey and show it being used with the validator.
        let jws = JwsBuilder::from(vec![0, 1, 2, 3, 4])
            .set_typ(Some("abcd"))
            .set_cty(Some("abcd"))
            .build();

        let jwsc = jws_rs256_signer.sign(&jws).expect("Failed to sign");

        assert!(jwsc.get_jwk_pubkey_url().is_none());

        let pub_jwk = jwsc.get_jwk_pubkey().expect("No embeded public jwk!");
        assert!(*pub_jwk == jws_rs256_signer.public_key_as_jwk().unwrap());

        let jws_validator = jws_rs256_signer
            .get_verifier()
            .expect("Unable to create validator");

        let released = jws_validator.verify(&jwsc).expect("Unable to validate jws");
        assert!(released.payload() == &[0, 1, 2, 3, 4]);
    }
}
