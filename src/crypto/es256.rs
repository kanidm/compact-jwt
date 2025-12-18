//! JWS Signing and Verification Structures
use crypto_glue::{
    ecdsa_p256::{
        self, EcdsaP256Digest, EcdsaP256FieldBytes, EcdsaP256PrivateKey,
        EcdsaP256PublicEncodedPoint, EcdsaP256PublicKey, EcdsaP256Signature,
        EcdsaP256SignatureBytes, EcdsaP256SigningKey, EcdsaP256VerifyingKey,
    },
    s256,
    traits::{
        Digest, DigestSigner, DigestVerifier, FromEncodedPoint, SpkiDecodePublicKey,
        SpkiEncodePublicKey, Zeroizing,
    },
};

use crate::compact::{EcCurve, JwaAlg, Jwk, JwkUse, JwsCompact, ProtectedHeader};
use crate::error::JwtError;
use crate::traits::*;
use crate::KID_LEN;
use base64::{engine::general_purpose, Engine as _};
use std::fmt;
use std::hash::{Hash, Hasher};

/// A JWS signer that creates ECDSA P-256 signatures.
#[derive(Clone)]
pub struct JwsEs256Signer {
    /// If the public jwk should be embeded during signing
    sign_option_embed_jwk: bool,
    /// If the KID should be embedded during singing
    sign_option_embed_kid: bool,
    /// The KID of this validator
    kid: String,
    /// Private Key
    skey: EcdsaP256PrivateKey,
}

impl fmt::Debug for JwsEs256Signer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JwsEs256Signer")
            .field("kid", &self.kid)
            .finish()
    }
}

impl PartialEq for JwsEs256Signer {
    fn eq(&self, other: &Self) -> bool {
        self.kid == other.kid
    }
}

impl Eq for JwsEs256Signer {}

impl Hash for JwsEs256Signer {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.kid.hash(state);
    }
}

impl JwsEs256Signer {
    #[cfg(test)]
    /// Create a new signer from the JWK components
    pub fn from_es256_jwk_components(x: &str, y: &str, d: &str) -> Result<Self, JwtError> {
        let x = general_purpose::URL_SAFE_NO_PAD.decode(x).map_err(|e| {
            debug!(?e);
            JwtError::InvalidBase64
        })?;
        let y = general_purpose::URL_SAFE_NO_PAD.decode(y).map_err(|e| {
            debug!(?e);
            JwtError::InvalidBase64
        })?;

        let d = general_purpose::URL_SAFE_NO_PAD.decode(d).map_err(|e| {
            debug!(?e);
            JwtError::InvalidBase64
        })?;

        let mut field_x = EcdsaP256FieldBytes::default();
        if x.len() != field_x.len() {
            return Err(JwtError::CryptoError);
        }

        let mut field_y = EcdsaP256FieldBytes::default();
        if y.len() != field_y.len() {
            return Err(JwtError::CryptoError);
        }

        field_x.copy_from_slice(&x);
        field_y.copy_from_slice(&y);

        let ep = EcdsaP256PublicEncodedPoint::from_affine_coordinates(&field_x, &field_y, false);

        let public = EcdsaP256PublicKey::from_encoded_point(&ep)
            .into_option()
            .ok_or(JwtError::CryptoError)?;

        let skey = EcdsaP256PrivateKey::from_slice(&d).map_err(|err| {
            debug!(?err);
            JwtError::CryptoError
        })?;

        let pub_key = skey.public_key();

        if pub_key != public {
            debug!("public key from x/y is not valid");
            return Err(JwtError::CryptoError);
        }

        let kid = kid_from_public(&pub_key);

        Ok(JwsEs256Signer {
            kid,
            skey,
            sign_option_embed_jwk: false,
            sign_option_embed_kid: true,
        })
    }

    /// Enable or disable embedding of the public jwk into the Jws that are signed
    /// by this signer
    pub fn set_sign_option_embed_jwk(mut self, value: bool) -> Self {
        self.sign_option_embed_jwk = value;
        self
    }

    /// Create a new secure private key for signing
    pub fn generate_es256() -> Result<Self, JwtError> {
        let skey = ecdsa_p256::new_key();
        let pub_key = skey.public_key();
        let kid = kid_from_public(&pub_key);

        Ok(JwsEs256Signer {
            kid,
            skey,
            sign_option_embed_jwk: false,
            sign_option_embed_kid: true,
        })
    }

    /// Restore this JwsSigner from a DER private key.
    pub fn from_es256_der(der: &[u8]) -> Result<Self, JwtError> {
        let skey = EcdsaP256PrivateKey::from_sec1_der(der).map_err(|err| {
            debug!(?err);
            JwtError::CryptoError
        })?;

        let pub_key = skey.public_key();
        let kid = kid_from_public(&pub_key);

        Ok(JwsEs256Signer {
            kid,
            skey,
            sign_option_embed_jwk: false,
            sign_option_embed_kid: true,
        })
    }

    /// Export this signer to a DER private key.
    pub fn private_key_to_der(&self) -> Result<Zeroizing<Vec<u8>>, JwtError> {
        self.skey.to_sec1_der().map_err(|err| {
            debug!(?err);
            JwtError::CryptoError
        })
    }

    /// Get the public Jwk from this signer
    pub fn public_key_as_jwk(&self) -> Result<Jwk, JwtError> {
        let pub_key = self.skey.public_key();
        let kid = kid_from_public(&pub_key);

        let encoded_point = EcdsaP256PublicEncodedPoint::from(pub_key);

        let public_key_x = encoded_point
            .x()
            .map(|bytes| bytes.to_vec())
            .unwrap_or_default();

        let public_key_y = encoded_point
            .y()
            .map(|bytes| bytes.to_vec())
            .unwrap_or_default();

        Ok(Jwk::EC {
            crv: EcCurve::P256,
            x: public_key_x.into(),
            y: public_key_y.into(),
            alg: Some(JwaAlg::ES256),
            use_: Some(JwkUse::Sig),
            kid: Some(kid),
        })
    }
}

impl JwsSignerToVerifier for JwsEs256Signer {
    type Verifier = JwsEs256Verifier;

    fn get_verifier(&self) -> Result<Self::Verifier, JwtError> {
        Ok(JwsEs256Verifier {
            kid: self.kid.clone(),
            pkey: self.skey.public_key(),
        })
    }
}

impl JwsSigner for JwsEs256Signer {
    fn get_kid(&self) -> &str {
        self.kid.as_str()
    }

    fn set_kid(&mut self, kid: &str) {
        self.sign_option_embed_kid = true;
        self.kid = kid.to_string();
    }

    fn update_header(&self, header: &mut ProtectedHeader) -> Result<(), JwtError> {
        // Update the alg to match.
        header.alg = JwaAlg::ES256;

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

        let mut hasher = EcdsaP256Digest::new();

        hasher.update(hdr_b64.as_bytes());
        hasher.update(".".as_bytes());
        hasher.update(sign_data.payload_b64.as_bytes());

        let signer = EcdsaP256SigningKey::from(&self.skey);

        let signature: EcdsaP256Signature = signer.try_sign_digest(hasher).map_err(|err| {
            debug!(?err);
            JwtError::CryptoError
        })?;

        let signature: EcdsaP256SignatureBytes = signature.to_bytes();

        let jwsc = JwsCompact {
            header: sign_data.header,
            hdr_b64,
            payload_b64: sign_data.payload_b64,
            signature: signature.to_vec(),
        };

        jws.post_process(jwsc)
    }

    fn set_sign_option_embed_kid(&self, value: bool) -> Self {
        JwsEs256Signer {
            sign_option_embed_kid: value,
            ..self.to_owned()
        }
    }
}

/// A JWS verifier that verifies ECDSA P-256 signatures.
#[derive(Clone)]
pub struct JwsEs256Verifier {
    /// The KID of this validator
    kid: String,
    /// Public Key
    pkey: EcdsaP256PublicKey,
}

impl From<EcdsaP256PublicKey> for JwsEs256Verifier {
    fn from(pkey: EcdsaP256PublicKey) -> Self {
        let kid = kid_from_public(&pkey);
        JwsEs256Verifier { kid, pkey }
    }
}

impl TryFrom<&Jwk> for JwsEs256Verifier {
    type Error = JwtError;

    fn try_from(value: &Jwk) -> Result<Self, Self::Error> {
        match value {
            Jwk::EC {
                crv: EcCurve::P256,
                x,
                y,
                alg: _,
                use_: _,
                kid,
            } => {
                let mut field_x = EcdsaP256FieldBytes::default();
                if x.len() != field_x.len() {
                    debug!("x field len error");
                    return Err(JwtError::CryptoError);
                }

                let mut field_y = EcdsaP256FieldBytes::default();
                if y.len() != field_y.len() {
                    debug!("y field len error");
                    return Err(JwtError::CryptoError);
                }

                field_x.copy_from_slice(x);
                field_y.copy_from_slice(y);

                let encoded_point =
                    EcdsaP256PublicEncodedPoint::from_affine_coordinates(&field_x, &field_y, false);

                let pub_key = EcdsaP256PublicKey::from_encoded_point(&encoded_point)
                    .into_option()
                    .ok_or_else(|| {
                        debug!("invalid encoded point");
                        JwtError::CryptoError
                    })?;

                let kid = if let Some(kid) = kid.clone() {
                    kid
                } else {
                    let mut hasher = s256::Sha256::new();
                    hasher.update(pub_key.to_sec1_bytes());
                    let hashout = hasher.finalize();

                    let mut kid = hex::encode(hashout);
                    kid.truncate(KID_LEN);
                    kid
                };

                Ok(JwsEs256Verifier { kid, pkey: pub_key })
            }
            alg_request => {
                debug!(?alg_request, "validator algorithm mismatch");
                Err(JwtError::ValidatorAlgMismatch)
            }
        }
    }
}

impl JwsEs256Verifier {
    /// Restore this JwsEs256Verifier from a DER public key.
    pub fn from_es256_der(der: &[u8]) -> Result<Self, JwtError> {
        let pkey = EcdsaP256PublicKey::from_public_key_der(der).map_err(|err| {
            debug!(?err);
            JwtError::CryptoError
        })?;

        let kid = kid_from_public(&pkey);

        Ok(JwsEs256Verifier { kid, pkey })
    }

    /// Export this verifier's DER public key.
    pub fn public_key_to_der(&self) -> Result<Vec<u8>, JwtError> {
        self.pkey
            .to_public_key_der()
            .map(|asn1_der| asn1_der.to_vec())
            .map_err(|err| {
                debug!(?err);
                JwtError::CryptoError
            })
    }

    /// Get the public Jwk from this verifier
    pub fn public_key_as_jwk(&self) -> Result<Jwk, JwtError> {
        let encoded_point = EcdsaP256PublicEncodedPoint::from(self.pkey);

        let public_key_x = encoded_point
            .x()
            .map(|bytes| bytes.to_vec())
            .unwrap_or_default();

        let public_key_y = encoded_point
            .y()
            .map(|bytes| bytes.to_vec())
            .unwrap_or_default();

        Ok(Jwk::EC {
            crv: EcCurve::P256,
            x: public_key_x.into(),
            y: public_key_y.into(),
            alg: Some(JwaAlg::ES256),
            use_: Some(JwkUse::Sig),
            kid: Some(self.kid.clone()),
        })
    }
}

impl JwsVerifier for JwsEs256Verifier {
    fn get_kid(&self) -> &str {
        &self.kid
    }

    fn verify<V: JwsVerifiable>(&self, jwsc: &V) -> Result<V::Verified, JwtError> {
        let signed_data = jwsc.data();

        if signed_data.header.alg != JwaAlg::ES256 {
            debug!(jwsc_alg = ?signed_data.header.alg, "validator algorithm mismatch");
            return Err(JwtError::ValidatorAlgMismatch);
        }

        let signature =
            EcdsaP256Signature::from_slice(signed_data.signature_bytes).map_err(|err| {
                debug!(?err, "invalid signature length");
                JwtError::InvalidSignature
            })?;

        let mut hasher = EcdsaP256Digest::new();

        hasher.update(signed_data.hdr_bytes);
        hasher.update(".".as_bytes());
        hasher.update(signed_data.payload_bytes);

        let verifier = EcdsaP256VerifyingKey::from(&self.pkey);

        verifier.verify_digest(hasher, &signature).map_err(|err| {
            debug!(?err, "invalid signature");
            JwtError::InvalidSignature
        })?;

        signed_data.release().and_then(|d| jwsc.post_process(d))
    }
}

fn kid_from_public(pub_key: &EcdsaP256PublicKey) -> String {
    let mut hasher = s256::Sha256::new();
    hasher.update(pub_key.to_sec1_bytes());
    let hashout = hasher.finalize();
    let mut kid = hex::encode(hashout);
    kid.truncate(KID_LEN);
    kid
}

#[cfg(test)]
mod tests {
    use super::{JwsEs256Signer, JwsEs256Verifier};
    use crate::compact::{Jwk, JwsCompact};
    use crate::jws::JwsBuilder;
    use crate::traits::*;
    use std::convert::TryFrom;
    use std::str::FromStr;

    #[test]
    fn rfc7515_es256_validation_example() {
        let _ = tracing_subscriber::fmt::try_init();
        let test_jws = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q";

        let jwsc = JwsCompact::from_str(test_jws).expect("Failed to parse JWS compact");

        assert!(jwsc.to_string() == test_jws);

        assert!(jwsc.check_vectors(
            &[
                101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 70, 85, 122, 73, 49, 78, 105, 74,
                57, 46, 101, 121, 74, 112, 99, 51, 77, 105, 79, 105, 74, 113, 98, 50, 85, 105, 76,
                65, 48, 75, 73, 67, 74, 108, 101, 72, 65, 105, 79, 106, 69, 122, 77, 68, 65, 52,
                77, 84, 107, 122, 79, 68, 65, 115, 68, 81, 111, 103, 73, 109, 104, 48, 100, 72, 65,
                54, 76, 121, 57, 108, 101, 71, 70, 116, 99, 71, 120, 108, 76, 109, 78, 118, 98, 83,
                57, 112, 99, 49, 57, 121, 98, 50, 57, 48, 73, 106, 112, 48, 99, 110, 86, 108, 102,
                81
            ],
            &[
                14, 209, 33, 83, 121, 99, 108, 72, 60, 47, 127, 21, 88, 7, 212, 2, 163, 178, 40, 3,
                58, 249, 124, 126, 23, 129, 154, 195, 22, 158, 166, 101, 197, 10, 7, 211, 140, 60,
                112, 229, 216, 241, 45, 175, 8, 74, 84, 128, 166, 101, 144, 197, 242, 147, 80, 154,
                143, 63, 127, 138, 131, 163, 84, 213
            ]
        ));

        assert!(jwsc.get_jwk_pubkey_url().is_none());
        assert!(jwsc.get_jwk_pubkey().is_none());

        let pkey = r#"{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}"#;

        let pkey: Jwk = serde_json::from_str(pkey).expect("Invalid JWK");
        trace!("jwk -> {:?}", pkey);

        let jwk_es256_verifier =
            JwsEs256Verifier::try_from(&pkey).expect("Unable to create validator");

        let released = jwk_es256_verifier
            .verify(&jwsc)
            .expect("Unable to verify jws");
        trace!("rel -> {:?}", released);
    }

    #[test]
    fn rfc7515_es256_signature_example() {
        let _ = tracing_subscriber::fmt::try_init();
        // https://docs.rs/openssl/0.10.36/openssl/ec/struct.EcKey.html#method.from_private_components
        let jws_es256_signer = JwsEs256Signer::from_es256_jwk_components(
            "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
            "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
            "jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI",
        )
        .expect("failed to construct signer");

        let jws = JwsBuilder::from(vec![
            123, 34, 105, 115, 115, 34, 58, 34, 106, 111, 101, 34, 44, 13, 10, 32, 34, 101, 120,
            112, 34, 58, 49, 51, 48, 48, 56, 49, 57, 51, 56, 48, 44, 13, 10, 32, 34, 104, 116, 116,
            112, 58, 47, 47, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 47, 105, 115, 95,
            114, 111, 111, 116, 34, 58, 116, 114, 117, 101, 125,
        ])
        .build();

        let jwsc = jws_es256_signer.sign(&jws).expect("Failed to sign");

        assert!(jwsc.get_jwk_pubkey_url().is_none());
        assert!(jwsc.get_jwk_pubkey().is_none());

        let pkey = r#"{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}"#;

        let pkey: Jwk = serde_json::from_str(pkey).expect("Invalid JWK");
        trace!("jwk -> {:?}", pkey);

        let jwk_es256_verifier =
            JwsEs256Verifier::try_from(&pkey).expect("Unable to create validator");

        let released = jwk_es256_verifier
            .verify(&jwsc)
            .expect("Unable to verify jws");

        trace!("rel -> {:?}", released);

        // Test the verifier from the signer also works.
        let jwk_es256_verifier = jws_es256_signer
            .get_verifier()
            .expect("failed to get verifier from signer");

        let released = jwk_es256_verifier
            .verify(&jwsc)
            .expect("Unable to verify jws");

        trace!("rel -> {:?}", released);
    }

    #[test]
    fn es256_key_generate_cycle() {
        let _ = tracing_subscriber::fmt::try_init();
        let jws_es256_signer =
            JwsEs256Signer::generate_es256().expect("failed to construct signer.");

        let der = jws_es256_signer
            .private_key_to_der()
            .expect("Failed to extract DER");

        let jws_es256_signer = JwsEs256Signer::from_es256_der(&der)
            .expect("Failed to restore signer")
            .set_sign_option_embed_jwk(true);

        // This time we'll add the jwk pubkey and show it being used with the validator.
        let jws = JwsBuilder::from(vec![0, 1, 2, 3, 4])
            .set_kid(Some("abcd"))
            .set_typ(Some("abcd"))
            .set_cty(Some("abcd"))
            .build();

        let jwsc = jws_es256_signer.sign(&jws).expect("Failed to sign");

        assert!(jwsc.get_jwk_pubkey_url().is_none());
        let pub_jwk = jwsc.get_jwk_pubkey().expect("No embeded public jwk!");
        assert!(
            *pub_jwk
                == jws_es256_signer
                    .public_key_as_jwk()
                    .expect("Failed to get public key as JWK")
        );

        let jwk_es256_verifier =
            JwsEs256Verifier::try_from(pub_jwk).expect("Unable to create validator");

        let released = jwk_es256_verifier
            .verify(&jwsc)
            .expect("Unable to validate jws");
        assert!(released.payload() == [0, 1, 2, 3, 4]);
    }
}
