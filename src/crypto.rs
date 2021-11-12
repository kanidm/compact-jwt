//! JWS Cryptographic Operations

use openssl::{bn, ec, ecdsa, hash, nid, pkey};
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use std::fmt;
use std::str::FromStr;
use url::Url;

use crate::base64_data::Base64UrlSafeData;
use crate::error::JwtError;

// https://datatracker.ietf.org/doc/html/rfc7515

#[derive(Debug, Serialize, Clone, Deserialize)]
/// A set of jwk keys
pub struct JwkKeySet {
    /// The set of jwks
    pub keys: Vec<Jwk>,
}

#[derive(Debug, Serialize, Clone, Deserialize, PartialEq)]
#[allow(non_camel_case_types)]
/// Valid Eliptic Curves
pub enum EcCurve {
    #[serde(rename = "P-256")]
    /// Nist P-256
    P256,
}

#[derive(Debug, Serialize, Clone, Deserialize, PartialEq)]
#[allow(non_camel_case_types)]
#[serde(tag = "kty")]
/// A JWK formatted public key that can be used to validate a signature
pub enum Jwk {
    /// An Eliptic Curve Public Key
    EC {
        /// The Eliptic Curve in use
        crv: EcCurve,
        /// The public X component
        x: Base64UrlSafeData,
        /// The public Y component
        y: Base64UrlSafeData,
        // We don't decode d (private key) because that way we error defending from
        // the fact that ... well you leaked your private key.
        // d: Base64UrlSafeData
        /// The algorithm in use for this key
        #[serde(skip_serializing_if = "Option::is_none")]
        alg: Option<JwaAlg>,
        #[serde(rename = "use", skip_serializing_if = "Option::is_none")]
        /// The usage of this key
        use_: Option<JwkUse>,
        #[serde(skip_serializing_if = "Option::is_none")]
        /// The key id
        kid: Option<String>,
    },
}

#[derive(Debug, Serialize, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
/// What this key is used for
pub enum JwkUse {
    /// This key is for signing.
    Sig,
    /// This key is for encryption
    Enc,
}

#[derive(Debug, Serialize, Clone, Deserialize, PartialEq)]
#[allow(non_camel_case_types)]
/// Cryptographic algorithm
pub enum JwaAlg {
    /// ECDSA with P-256 and SHA256
    ES256,
}

#[derive(Clone)]
/// A private key and associated information that can sign Oidc and Jwt data.
pub enum JwsSigner {
    /// Eliptic Curve P-256
    ES256 {
        /// Private Key
        skey: ec::EcKey<pkey::Private>,
        /// The matching digest.
        digest: hash::MessageDigest,
    },
}

#[derive(Clone)]
/// A public key with associated information that can validate the signatures of Oidc and Jwt data.
pub enum JwsValidator {
    /// Eliptic Curve P-256
    ES256 {
        /// Public Key
        pkey: ec::EcKey<pkey::Public>,
        /// The matching digest.
        digest: hash::MessageDigest,
    },
}

impl fmt::Debug for JwsValidator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JwsValidator").finish()
    }
}

#[derive(Debug, Serialize, Clone, Deserialize)]
struct ProtectedHeader {
    alg: JwaAlg,
    #[serde(skip_serializing_if = "Option::is_none")]
    jku: Option<Url>,
    // https://datatracker.ietf.org/doc/html/rfc7517
    #[serde(skip_serializing_if = "Option::is_none")]
    jwk: Option<Jwk>,
    #[serde(skip_serializing_if = "Option::is_none")]
    kid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    crit: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    typ: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cty: Option<String>,

    // We probably don't need these.
    #[serde(skip_deserializing, skip_serializing_if = "Option::is_none")]
    x5u: Option<()>,
    #[serde(skip_deserializing, skip_serializing_if = "Option::is_none")]
    x5c: Option<()>,
    #[serde(skip_deserializing, skip_serializing_if = "Option::is_none")]
    x5t: Option<()>,
    #[serde(
        skip_deserializing,
        rename = "x5t#S256",
        skip_serializing_if = "Option::is_none"
    )]
    x5t_s256: Option<()>,
    // Don't allow extra header names?
}

#[derive(Debug, Clone)]
pub(crate) struct JwsCompact {
    header: ProtectedHeader,
    payload: Vec<u8>,
    sign_input: Vec<u8>,
    signature: Vec<u8>,
}

#[derive(Debug, Clone)]
struct Header {
    kid: Option<String>,
    typ: Option<String>,
    cty: Option<String>,
}

impl From<&ProtectedHeader> for Header {
    fn from(phdr: &ProtectedHeader) -> Self {
        Header {
            kid: phdr.kid.clone(),
            typ: phdr.typ.clone(),
            cty: phdr.cty.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Jws {
    header: Header,
    payload: Vec<u8>,
}

impl Jws {
    pub fn new(payload: Vec<u8>) -> Self {
        Jws {
            header: Header {
                kid: None,
                typ: None,
                cty: None,
            },
            payload,
        }
    }

    pub fn set_kid(mut self, kid: String) -> Self {
        self.header.kid = Some(kid);
        self
    }

    pub fn set_typ(mut self, typ: String) -> Self {
        self.header.typ = Some(typ);
        self
    }

    #[allow(dead_code)]
    pub fn set_cty(mut self, cty: String) -> Self {
        self.header.cty = Some(cty);
        self
    }

    #[cfg(test)]
    pub fn sign_embed_public_jwk(&self, signer: &JwsSigner) -> Result<JwsCompact, JwtError> {
        let jwk = signer.public_key_as_jwk(None)?;
        self.sign_inner(signer, None, Some(jwk))
    }

    #[cfg(test)]
    pub fn sign(&self, signer: &JwsSigner) -> Result<JwsCompact, JwtError> {
        self.sign_inner(signer, None, None)
    }

    pub(crate) fn sign_inner(
        &self,
        signer: &JwsSigner,
        jku: Option<Url>,
        jwk: Option<Jwk>,
    ) -> Result<JwsCompact, JwtError> {
        let alg = match signer {
            JwsSigner::ES256 { skey: _, digest: _ } => JwaAlg::ES256,
        };

        let header = ProtectedHeader {
            alg,
            jku,
            jwk,
            kid: self.header.kid.clone(),
            typ: self.header.typ.clone(),
            cty: self.header.cty.clone(),
            crit: None,
            x5u: None,
            x5c: None,
            x5t: None,
            x5t_s256: None,
        };

        let payload = self.payload.clone();

        let hdr_b64 = serde_json::to_vec(&header)
            .map_err(|_| JwtError::InvalidHeaderFormat)
            .map(|bytes| base64::encode_config(&bytes, base64::URL_SAFE_NO_PAD))?;
        let payload_b64 = base64::encode_config(&self.payload, base64::URL_SAFE_NO_PAD);

        // eprintln!("sinput -> {}", format!("{}.{}", hdr_b64, payload_b64));

        let sign_input = format!("{}.{}", hdr_b64, payload_b64).as_bytes().to_vec();

        // eprintln!("sinput -> {:?}", sign_input);

        // Compute the signature!
        let ec_sig = match signer {
            JwsSigner::ES256 { skey, digest } => {
                let hashout =
                    hash::hash(*digest, &sign_input).map_err(|_| JwtError::OpenSSLError)?;
                ecdsa::EcdsaSig::sign(&hashout, &skey)
            }
        }
        .map_err(|_| JwtError::OpenSSLError)?;

        let mut r = [0; 32];
        let r_vec = ec_sig.r().to_vec();
        let (_left, right) = r.split_at_mut(32 - r_vec.len());
        right.copy_from_slice(r_vec.as_slice());
        let mut s = [0; 32];
        let s_vec = ec_sig.s().to_vec();
        let (_left, right) = s.split_at_mut(32 - s_vec.len());
        right.copy_from_slice(s_vec.as_slice());

        // eprintln!("r {:?}", r);
        // eprintln!("s {:?}", s);

        let mut signature = Vec::with_capacity(64);
        signature.extend_from_slice(&r);
        signature.extend_from_slice(&s);

        Ok(JwsCompact {
            header,
            payload,
            sign_input,
            signature,
        })
    }

    pub(crate) fn payload(&self) -> &[u8] {
        &self.payload
    }
}

impl JwsCompact {
    #[cfg(test)]
    fn check_vectors(&self, chk_input: &[u8], chk_sig: &[u8]) -> bool {
        chk_input == &self.sign_input && chk_sig == &self.signature
    }

    #[allow(dead_code)]
    pub fn get_jwk_kid(&self) -> Option<&str> {
        self.header.kid.as_ref().map(|s| s.as_str())
    }

    #[allow(dead_code)]
    pub fn get_jwk_pubkey_url(&self) -> Option<&Url> {
        self.header.jku.as_ref()
    }

    #[allow(dead_code)]
    pub fn get_jwk_pubkey(&self) -> Option<&Jwk> {
        self.header.jwk.as_ref()
    }

    pub(crate) fn validate(&self, validator: &JwsValidator) -> Result<Jws, JwtError> {
        match (validator, &self.header.alg) {
            (JwsValidator::ES256 { pkey, digest }, JwaAlg::ES256) => {
                if self.signature.len() != 64 {
                    return Err(JwtError::InvalidSignature);
                }

                let r = bn::BigNum::from_slice(&self.signature[..32])
                    .map_err(|_| JwtError::OpenSSLError)?;
                let s = bn::BigNum::from_slice(&self.signature[32..64])
                    .map_err(|_| JwtError::OpenSSLError)?;

                let sig = ecdsa::EcdsaSig::from_private_components(r, s)
                    .map_err(|_| JwtError::OpenSSLError)?;

                let hashout =
                    hash::hash(*digest, &self.sign_input).map_err(|_| JwtError::OpenSSLError)?;

                if sig
                    .verify(&hashout, &pkey)
                    .map_err(|_| JwtError::OpenSSLError)?
                {
                    Ok(Jws {
                        header: (&self.header).into(),
                        payload: self.payload.clone(),
                    })
                } else {
                    Err(JwtError::InvalidSignature)
                }
            } // _ => Err(JwtError::ValidatorAlgMismatch),
        }
    }
}

impl FromStr for JwsCompact {
    type Err = JwtError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // split on the ".".
        let mut siter = s.splitn(3, ".");

        let hdr_str = siter.next().ok_or(JwtError::InvalidCompactFormat)?;

        let header: ProtectedHeader = base64::decode_config(hdr_str, base64::URL_SAFE_NO_PAD)
            .map_err(|_| JwtError::InvalidBase64)
            .and_then(|bytes| {
                serde_json::from_slice(&bytes).map_err(|_| JwtError::InvalidHeaderFormat)
            })?;
        // Assert that from the critical field of the header, we have decoded all the needed types.
        // Remember, anything in rfc7515 can NOT be in the crit field.
        if let Some(crit) = &header.crit {
            if !crit.is_empty() {
                return Err(JwtError::CriticalExtension);
            }
        }

        // Now we have a header, lets get the rest.
        let payload_str = siter.next().ok_or(JwtError::InvalidCompactFormat)?;

        let sig_str = siter.next().ok_or(JwtError::InvalidCompactFormat)?;

        if siter.next().is_some() {
            // Too much data.
            return Err(JwtError::InvalidCompactFormat);
        }

        let payload = base64::decode_config(payload_str, base64::URL_SAFE_NO_PAD)
            .map_err(|_| JwtError::InvalidBase64)?;

        let signature = base64::decode_config(sig_str, base64::URL_SAFE_NO_PAD)
            .map_err(|_| JwtError::InvalidBase64)?;

        let (data_input, _) = s.rsplit_once(".").ok_or(JwtError::InvalidCompactFormat)?;
        let sign_input = data_input.as_bytes().to_vec();

        debug_assert!(data_input == &format!("{}.{}", hdr_str, payload_str));

        Ok(JwsCompact {
            header,
            payload,
            sign_input,
            signature,
        })
    }
}

impl fmt::Display for JwsCompact {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hdr = serde_json::to_vec(&self.header)
            .map_err(|_| fmt::Error)
            .map(|bytes| base64::encode_config(&bytes, base64::URL_SAFE_NO_PAD))?;
        let payload = base64::encode_config(&self.payload, base64::URL_SAFE_NO_PAD);
        let sig = base64::encode_config(&self.signature, base64::URL_SAFE_NO_PAD);
        write!(f, "{}.{}.{}", hdr, payload, sig)
    }
}

impl TryFrom<&Jwk> for JwsValidator {
    type Error = JwtError;

    fn try_from(value: &Jwk) -> Result<Self, Self::Error> {
        match value {
            Jwk::EC {
                crv,
                x,
                y,
                alg: _,
                use_: _,
                kid: _,
            } => {
                let (curve, digest) = match crv {
                    EcCurve::P256 => (nid::Nid::X9_62_PRIME256V1, hash::MessageDigest::sha256()),
                };
                let ec_group =
                    ec::EcGroup::from_curve_name(curve).map_err(|_| JwtError::OpenSSLError)?;

                let xbn = bn::BigNum::from_slice(&x.0).map_err(|_| JwtError::OpenSSLError)?;
                let ybn = bn::BigNum::from_slice(&y.0).map_err(|_| JwtError::OpenSSLError)?;

                let pkey = ec::EcKey::from_public_key_affine_coordinates(&ec_group, &xbn, &ybn)
                    .map_err(|_| JwtError::OpenSSLError)?;

                pkey.check_key().map_err(|_| JwtError::OpenSSLError)?;

                Ok(match crv {
                    EcCurve::P256 => JwsValidator::ES256 { pkey, digest },
                })
            }
        }
    }
}

impl JwsSigner {
    #[cfg(test)]
    pub fn from_es256_jwk_components(x: &str, y: &str, d: &str) -> Result<Self, JwtError> {
        let x = base64::decode_config(x, base64::URL_SAFE_NO_PAD)
            .map_err(|_| JwtError::InvalidBase64)?;
        let y = base64::decode_config(y, base64::URL_SAFE_NO_PAD)
            .map_err(|_| JwtError::InvalidBase64)?;

        let d = base64::decode_config(&d, base64::URL_SAFE_NO_PAD)
            .map_err(|_| JwtError::InvalidBase64)?;

        let xbn = bn::BigNum::from_slice(&x).map_err(|_| JwtError::OpenSSLError)?;
        let ybn = bn::BigNum::from_slice(&y).map_err(|_| JwtError::OpenSSLError)?;
        let dbn = bn::BigNum::from_slice(&d).map_err(|_| JwtError::OpenSSLError)?;

        let ec_group = ec::EcGroup::from_curve_name(nid::Nid::X9_62_PRIME256V1)
            .map_err(|_| JwtError::OpenSSLError)?;

        let pkey = ec::EcKey::from_public_key_affine_coordinates(&ec_group, &xbn, &ybn)
            .map_err(|_| JwtError::OpenSSLError)?;

        let skey = ec::EcKey::from_private_components(&ec_group, &dbn, pkey.public_key())
            .map_err(|_| JwtError::OpenSSLError)?;

        skey.check_key().map_err(|_| JwtError::OpenSSLError)?;
        Ok(JwsSigner::ES256 {
            skey,
            digest: hash::MessageDigest::sha256(),
        })
    }

    /// Given this signer, retrieve the matching validator which can be paired with this.
    pub fn get_validator(&self) -> Result<JwsValidator, JwtError> {
        match self {
            JwsSigner::ES256 { skey, digest } => {
                ec::EcKey::from_public_key(skey.group(), skey.public_key())
                    .map_err(|_| JwtError::OpenSSLError)
                    .map(|pkey| JwsValidator::ES256 {
                        pkey,
                        digest: digest.clone(),
                    })
            }
        }
    }

    /// Restore this JwsSigner from a DER private key.
    pub fn from_es256_der(der: &[u8]) -> Result<Self, JwtError> {
        let skey = ec::EcKey::private_key_from_der(der).map_err(|_| JwtError::OpenSSLError)?;

        Ok(JwsSigner::ES256 {
            skey,
            digest: hash::MessageDigest::sha256(),
        })
    }

    /*
    pub fn public_key_to_der(&self) -> Result<Vec<u8>, JwtError> {
        unimplemented!();
    }
    */

    /// Export this JwsSigner to a DER private key.
    pub fn private_key_to_der(&self) -> Result<Vec<u8>, JwtError> {
        match self {
            JwsSigner::ES256 { skey, digest: _ } => skey
                .private_key_to_der()
                .map_err(|_| JwtError::OpenSSLError),
        }
    }

    /// Create a new secure private key for signing
    pub fn generate_es256() -> Result<Self, JwtError> {
        let ec_group = ec::EcGroup::from_curve_name(nid::Nid::X9_62_PRIME256V1)
            .map_err(|_| JwtError::OpenSSLError)?;

        let skey = ec::EcKey::generate(&ec_group).map_err(|_| JwtError::OpenSSLError)?;

        skey.check_key().map_err(|_| JwtError::OpenSSLError)?;
        Ok(JwsSigner::ES256 {
            skey,
            digest: hash::MessageDigest::sha256(),
        })
    }

    /// Export the public key of this signer as a Jwk
    pub fn public_key_as_jwk(&self, kid: Option<&str>) -> Result<Jwk, JwtError> {
        match self {
            JwsSigner::ES256 { skey, digest: _ } => {
                let pkey = skey.public_key();
                let ec_group = skey.group();

                let mut bnctx = bn::BigNumContext::new().map_err(|_| JwtError::OpenSSLError)?;

                let mut xbn = bn::BigNum::new().map_err(|_| JwtError::OpenSSLError)?;

                let mut ybn = bn::BigNum::new().map_err(|_| JwtError::OpenSSLError)?;

                pkey.affine_coordinates_gfp(&ec_group, &mut xbn, &mut ybn, &mut bnctx)
                    .map_err(|_| JwtError::OpenSSLError)?;

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
                    kid: kid.map(str::to_string),
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Jwk, Jws, JwsCompact, JwsSigner, JwsValidator};
    use std::convert::TryFrom;
    use std::str::FromStr;

    #[test]
    fn rfc7515_validation_example() {
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
        eprintln!("jwk -> {:?}", pkey);

        let jws_validator = JwsValidator::try_from(&pkey).expect("Unable to create validator");
        assert!(jwsc.get_jwk_pubkey_url().is_none());

        let released = jwsc
            .validate(&jws_validator)
            .expect("Unable to validate jws");
        eprintln!("rel -> {:?}", released);
    }

    #[test]
    fn rfc7515_signature_example() {
        // https://docs.rs/openssl/0.10.36/openssl/ec/struct.EcKey.html#method.from_private_components
        let jwss = JwsSigner::from_es256_jwk_components(
            "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
            "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
            "jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI",
        )
        .expect("failed to construct signer");

        let jws = Jws::new(vec![
            123, 34, 105, 115, 115, 34, 58, 34, 106, 111, 101, 34, 44, 13, 10, 32, 34, 101, 120,
            112, 34, 58, 49, 51, 48, 48, 56, 49, 57, 51, 56, 48, 44, 13, 10, 32, 34, 104, 116, 116,
            112, 58, 47, 47, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 47, 105, 115, 95,
            114, 111, 111, 116, 34, 58, 116, 114, 117, 101, 125,
        ]);

        let jwsc = jws.sign(&jwss).expect("Failed to sign");

        assert!(jwsc.get_jwk_pubkey_url().is_none());
        assert!(jwsc.get_jwk_pubkey().is_none());

        let pkey = r#"{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}"#;

        let pkey: Jwk = serde_json::from_str(pkey).expect("Invalid JWK");
        eprintln!("jwk -> {:?}", pkey);

        let jws_validator = JwsValidator::try_from(&pkey).expect("Unable to create validator");

        let released = jwsc
            .validate(&jws_validator)
            .expect("Unable to validate jws");
        eprintln!("rel -> {:?}", released);
    }

    #[test]
    fn key_generate_cycle() {
        let jwss = JwsSigner::generate_es256().expect("failed to construct signer.");

        let der = jwss.private_key_to_der().expect("Failed to extract DER");

        let jwss = JwsSigner::from_es256_der(&der).expect("Failed to restore signer");

        // This time we'll add the jwk pubkey and show it being used with the validator.
        let jws = Jws::new(vec![0, 1, 2, 3, 4])
            .set_kid("abcd".to_string())
            .set_typ("abcd".to_string())
            .set_cty("abcd".to_string());

        let jwsc = jws.sign_embed_public_jwk(&jwss).expect("Failed to sign");

        assert!(jwsc.get_jwk_pubkey_url().is_none());
        let pub_jwk = jwsc.get_jwk_pubkey().expect("No embeded public jwk!");
        assert!(*pub_jwk == jwss.public_key_as_jwk(None).unwrap());

        let jws_validator = JwsValidator::try_from(pub_jwk).expect("Unable to create validator");

        let released = jwsc
            .validate(&jws_validator)
            .expect("Unable to validate jws");
        assert!(released.payload() == &[0, 1, 2, 3, 4]);
    }

    // A test for the signer to/from der.
    // directly get the validator from the signer.
}
