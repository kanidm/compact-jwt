//! JWS Signing and Verification Structures

use openssl::{bn, ec, ecdsa, hash, nid, pkey};
use std::convert::TryFrom;

use std::fmt;
use std::hash::{Hash, Hasher};

use crate::error::JwtError;

use base64::{engine::general_purpose, Engine as _};
use base64urlsafedata::Base64UrlSafeData;

use crate::compact::{EcCurve, JwaAlg, Jwk, JwkUse, JwsCompact, ProtectedHeader};
use crate::traits::*;

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
    skey: ec::EcKey<pkey::Private>,
    /// The matching digest.
    digest: hash::MessageDigest,
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

        let xbn = bn::BigNum::from_slice(&x).map_err(|e| {
            debug!(?e);
            JwtError::OpenSSLError
        })?;
        let ybn = bn::BigNum::from_slice(&y).map_err(|e| {
            debug!(?e);
            JwtError::OpenSSLError
        })?;
        let dbn = bn::BigNum::from_slice(&d).map_err(|e| {
            debug!(?e);
            JwtError::OpenSSLError
        })?;

        let ec_group = ec::EcGroup::from_curve_name(nid::Nid::X9_62_PRIME256V1).map_err(|e| {
            debug!(?e);
            JwtError::OpenSSLError
        })?;

        let pkey =
            ec::EcKey::from_public_key_affine_coordinates(&ec_group, &xbn, &ybn).map_err(|e| {
                debug!(?e);
                JwtError::OpenSSLError
            })?;

        let digest = hash::MessageDigest::sha256();

        let skey = ec::EcKey::from_private_components(&ec_group, &dbn, pkey.public_key()).map_err(
            |e| {
                debug!(?e);
                JwtError::OpenSSLError
            },
        )?;

        skey.check_key().map_err(|_| JwtError::OpenSSLError)?;

        let kid = skey
            .private_key_to_der()
            .and_then(|der| hash::hash(digest, &der))
            .map(|hashout| hex::encode(hashout))
            .map_err(|e| {
                debug!(?e);
                JwtError::OpenSSLError
            })?;

        Ok(JwsEs256Signer {
            kid,
            skey,
            digest,
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
        let digest = hash::MessageDigest::sha256();
        let ec_group = ec::EcGroup::from_curve_name(nid::Nid::X9_62_PRIME256V1)
            .map_err(|_| JwtError::OpenSSLError)?;

        let skey = ec::EcKey::generate(&ec_group).map_err(|_| JwtError::OpenSSLError)?;

        skey.check_key().map_err(|_| JwtError::OpenSSLError)?;

        let kid = skey
            .private_key_to_der()
            .and_then(|der| hash::hash(digest, &der))
            .map(hex::encode)
            .map_err(|_| JwtError::OpenSSLError)?;

        Ok(JwsEs256Signer {
            kid,
            skey,
            digest,
            sign_option_embed_jwk: false,
            sign_option_embed_kid: true,
        })
    }

    /// Restore this JwsSignerEnum from a DER private key.
    pub fn from_es256_der(der: &[u8]) -> Result<Self, JwtError> {
        let digest = hash::MessageDigest::sha256();

        let kid = hash::hash(digest, der).map(hex::encode).map_err(|e| {
            debug!(?e);
            JwtError::OpenSSLError
        })?;

        let skey = ec::EcKey::private_key_from_der(der).map_err(|e| {
            debug!(?e);
            JwtError::OpenSSLError
        })?;

        Ok(JwsEs256Signer {
            kid,
            skey,
            digest,
            sign_option_embed_jwk: false,
            sign_option_embed_kid: true,
        })
    }

    /// Export this signer to a DER private key.
    pub fn private_key_to_der(&self) -> Result<Vec<u8>, JwtError> {
        self.skey.private_key_to_der().map_err(|e| {
            debug!(?e);
            JwtError::OpenSSLError
        })
    }

    /// Get the public Jwk from this signer
    pub fn public_key_as_jwk(&self) -> Result<Jwk, JwtError> {
        let pkey = self.skey.public_key();
        let ec_group = self.skey.group();

        let mut bnctx = bn::BigNumContext::new().map_err(|e| {
            debug!(?e);
            JwtError::OpenSSLError
        })?;

        let mut xbn = bn::BigNum::new().map_err(|e| {
            debug!(?e);
            JwtError::OpenSSLError
        })?;

        let mut ybn = bn::BigNum::new().map_err(|e| {
            debug!(?e);
            JwtError::OpenSSLError
        })?;

        pkey.affine_coordinates_gfp(ec_group, &mut xbn, &mut ybn, &mut bnctx)
            .map_err(|e| {
                debug!(?e);
                JwtError::OpenSSLError
            })?;

        let mut public_key_x = Vec::with_capacity(32);
        let mut public_key_y = Vec::with_capacity(32);

        public_key_x.resize(32, 0);
        public_key_y.resize(32, 0);

        let xbnv = xbn.to_vec();
        let ybnv = ybn.to_vec();

        let (_pad, x_fill) = public_key_x.split_at_mut(32 - xbnv.len());
        x_fill.copy_from_slice(&xbnv);

        let (_pad, y_fill) = public_key_y.split_at_mut(32 - ybnv.len());
        y_fill.copy_from_slice(&ybnv);

        Ok(Jwk::EC {
            crv: EcCurve::P256,
            x: Base64UrlSafeData(public_key_x),
            y: Base64UrlSafeData(public_key_y),
            alg: Some(JwaAlg::ES256),
            use_: Some(JwkUse::Sig),
            kid: Some(self.kid.clone()),
        })
    }
}

impl JwsSignerToVerifier for JwsEs256Signer {
    type Verifier = JwsEs256Verifier;

    fn get_verifier(&self) -> Result<Self::Verifier, JwtError> {
        ec::EcKey::from_public_key(self.skey.group(), self.skey.public_key())
            .map_err(|e| {
                debug!(?e);
                JwtError::OpenSSLError
            })
            .map_err(|_| JwtError::OpenSSLError)
            .map(|pkey| JwsEs256Verifier {
                kid: Some(self.kid.clone()),
                pkey,
                digest: self.digest,
            })
    }
}

impl JwsSigner for JwsEs256Signer {
    fn get_kid(&self) -> &str {
        self.kid.as_str()
    }

    fn update_header(&self, header: &mut ProtectedHeader) -> Result<(), JwtError> {
        // Update the alg to match.
        header.alg = JwaAlg::ES256;

        // If the signer is configured to include the KID
        header.kid = self.sign_option_embed_kid.then(|| self.kid.clone());

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

        let mut hasher = hash::Hasher::new(self.digest).map_err(|e| {
            debug!(?e);
            JwtError::OpenSSLError
        })?;

        hasher
            .update(hdr_b64.as_bytes())
            .and_then(|_| hasher.update(".".as_bytes()))
            .and_then(|_| hasher.update(sign_data.payload_b64.as_bytes()))
            .map_err(|e| {
                debug!(?e);
                JwtError::OpenSSLError
            })?;

        let hashout = hasher.finish().map_err(|e| {
            debug!(?e);
            JwtError::OpenSSLError
        })?;

        let ec_sig = ecdsa::EcdsaSig::sign(&hashout, &self.skey).map_err(|e| {
            debug!(?e);
            JwtError::OpenSSLError
        })?;

        let mut r = [0; 32];
        let r_vec = ec_sig.r().to_vec();
        let (_left, right) = r.split_at_mut(32 - r_vec.len());
        right.copy_from_slice(r_vec.as_slice());
        let mut s = [0; 32];
        let s_vec = ec_sig.s().to_vec();
        let (_left, right) = s.split_at_mut(32 - s_vec.len());
        right.copy_from_slice(s_vec.as_slice());

        // trace!("r {:?}", r);
        // trace!("s {:?}", s);

        let mut signature = Vec::with_capacity(64);
        signature.extend_from_slice(&r);
        signature.extend_from_slice(&s);

        let jwsc = JwsCompact {
            header: sign_data.header,
            hdr_b64,
            payload_b64: sign_data.payload_b64,
            signature,
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
    kid: Option<String>,
    /// Public Key
    pkey: ec::EcKey<pkey::Public>,
    /// The matching digest.
    digest: hash::MessageDigest,
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
                let curve = nid::Nid::X9_62_PRIME256V1;
                let digest = hash::MessageDigest::sha256();

                let ec_group = ec::EcGroup::from_curve_name(curve).map_err(|e| {
                    debug!(?e);
                    JwtError::OpenSSLError
                })?;

                let xbn = bn::BigNum::from_slice(&x.0).map_err(|e| {
                    debug!(?e);
                    JwtError::OpenSSLError
                })?;
                let ybn = bn::BigNum::from_slice(&y.0).map_err(|e| {
                    debug!(?e);
                    JwtError::OpenSSLError
                })?;

                let pkey = ec::EcKey::from_public_key_affine_coordinates(&ec_group, &xbn, &ybn)
                    .map_err(|e| {
                        debug!(?e);
                        JwtError::OpenSSLError
                    })?;

                pkey.check_key().map_err(|e| {
                    debug!(?e);
                    JwtError::OpenSSLError
                })?;

                let kid = kid.clone();

                Ok(JwsEs256Verifier { kid, pkey, digest })
            }
            alg_request => {
                debug!(?alg_request, "validator algorithm mismatch");
                Err(JwtError::ValidatorAlgMismatch)
            }
        }
    }
}

impl JwsVerifier for JwsEs256Verifier {
    fn get_kid(&self) -> Option<&str> {
        self.kid.as_deref()
    }

    fn verify<V: JwsVerifiable>(&self, jwsc: &V) -> Result<V::Verified, JwtError> {
        let signed_data = jwsc.data();

        if signed_data.header.alg != JwaAlg::ES256 {
            debug!(jwsc_alg = ?signed_data.header.alg, "validator algorithm mismatch");
            return Err(JwtError::ValidatorAlgMismatch);
        }

        if signed_data.signature_bytes.len() != 64 {
            return Err(JwtError::InvalidSignature);
        }

        let r = bn::BigNum::from_slice(&signed_data.signature_bytes[..32]).map_err(|e| {
            debug!(?e);
            JwtError::OpenSSLError
        })?;
        let s = bn::BigNum::from_slice(&signed_data.signature_bytes[32..64]).map_err(|e| {
            debug!(?e);
            JwtError::OpenSSLError
        })?;

        let sig = ecdsa::EcdsaSig::from_private_components(r, s).map_err(|e| {
            debug!(?e);
            JwtError::OpenSSLError
        })?;

        let mut hasher = hash::Hasher::new(self.digest).map_err(|e| {
            debug!(?e);
            JwtError::OpenSSLError
        })?;

        hasher
            .update(signed_data.hdr_bytes)
            .and_then(|_| hasher.update(".".as_bytes()))
            .and_then(|_| hasher.update(signed_data.payload_bytes))
            .map_err(|e| {
                debug!(?e);
                JwtError::OpenSSLError
            })?;

        let hashout = hasher.finish().map_err(|e| {
            debug!(?e);
            JwtError::OpenSSLError
        })?;

        let valid = sig.verify(&hashout, &self.pkey).map_err(|e| {
            debug!(?e);
            JwtError::OpenSSLError
        })?;

        if valid {
            signed_data.release().and_then(|d| jwsc.post_process(d))
        } else {
            debug!("invalid signature");
            Err(JwtError::InvalidSignature)
        }
    }
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

        let jwsc = JwsCompact::from_str(test_jws).unwrap();

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
        assert!(*pub_jwk == jws_es256_signer.public_key_as_jwk().unwrap());

        let jwk_es256_verifier =
            JwsEs256Verifier::try_from(pub_jwk).expect("Unable to create validator");

        let released = jwk_es256_verifier
            .verify(&jwsc)
            .expect("Unable to validate jws");
        assert!(released.payload() == &[0, 1, 2, 3, 4]);
    }
}
