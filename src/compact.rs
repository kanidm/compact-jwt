//!
use base64::{engine::general_purpose, Engine as _};

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use url::Url;

use crate::error::JwtError;
use crate::jws::Jws;
use crate::traits::JwsVerifiable;
use base64urlsafedata::Base64UrlSafeData;

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
    /// Legacy RSA public key
    RSA {
        /// Public n value
        n: Base64UrlSafeData,
        /// Public exponent
        e: Base64UrlSafeData,
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

#[derive(Debug, Serialize, Copy, Clone, Deserialize, PartialEq, Default)]
#[allow(non_camel_case_types)]
/// Cryptographic algorithm
pub enum JwaAlg {
    /// ECDSA with P-256 and SHA256
    ES256,
    /// RSASSA-PKCS1-v1_5 with SHA-256
    RS256,
    /// HMAC SHA256
    #[default]
    HS256,
}

/// A header that will be signed and embedded in the Jws
#[derive(Debug, Serialize, Clone, Deserialize, Default, PartialEq)]
pub struct ProtectedHeader {
    pub(crate) alg: JwaAlg,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) jku: Option<Url>,
    // https://datatracker.ietf.org/doc/html/rfc7517
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) jwk: Option<Jwk>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) kid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) crit: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) typ: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) cty: Option<String>,

    #[serde(skip_deserializing, skip_serializing_if = "Option::is_none")]
    pub(crate) x5u: Option<()>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) x5c: Option<Vec<String>>,
    #[serde(skip_deserializing, skip_serializing_if = "Option::is_none")]
    pub(crate) x5t: Option<()>,
    #[serde(
        skip_deserializing,
        rename = "x5t#S256",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) x5t_s256: Option<()>,
    // Don't allow extra header names?
}

/// A Compact JWS that is able to be verified or stringified for transmission
#[derive(Clone)]
pub struct JwsCompact {
    pub(crate) header: ProtectedHeader,
    pub(crate) hdr_b64: String,
    pub(crate) payload_b64: String,
    pub(crate) signature: Vec<u8>,
}

impl fmt::Debug for JwsCompact {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JwsCompact")
            .field("header", &self.header)
            .field("payload", &self.payload_b64)
            .finish()
    }
}

impl JwsCompact {
    /// Get the KID used to sign this Jws if present
    pub fn get_jwk_kid(&self) -> Option<&str> {
        self.header.kid.as_deref()
    }

    /// Get the embedded Url for the Jwk that signed this Jws.
    ///
    /// You MUST ensure this url uses HTTPS and you MUST ensure that your
    /// client validates the CA's used.
    pub fn get_jwk_pubkey_url(&self) -> Option<&Url> {
        self.header.jku.as_ref()
    }

    /// Get the embedded public key used to sign this Jws, if present.
    pub fn get_jwk_pubkey(&self) -> Option<&Jwk> {
        self.header.jwk.as_ref()
    }
}

impl FromStr for JwsCompact {
    type Err = JwtError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // split on the ".".
        let mut siter = s.splitn(3, '.');

        let hdr_str = siter.next().ok_or_else(|| {
            debug!("invalid compact format - protected header not present");
            JwtError::InvalidCompactFormat
        })?;

        let header: ProtectedHeader = general_purpose::URL_SAFE_NO_PAD
            .decode(hdr_str)
            .map_err(|_| {
                debug!("invalid base64 while decoding header");
                JwtError::InvalidBase64
            })
            .and_then(|bytes| {
                serde_json::from_slice(&bytes).map_err(|e| {
                    debug!(?e, "invalid header format - invalid json");
                    JwtError::InvalidHeaderFormat
                })
            })?;

        let hdr_b64 = hdr_str.to_string();

        // Assert that from the critical field of the header, we have decoded all the needed types.
        // Remember, anything in rfc7515 can NOT be in the crit field.
        if let Some(crit) = &header.crit {
            if !crit.is_empty() {
                error!("critical extension - unable to process critical extensions");
                return Err(JwtError::CriticalExtension);
            }
        }

        // Now we have a header, lets get the rest.
        let payload_str = siter.next().ok_or_else(|| {
            debug!("invalid compact format - payload not present");
            JwtError::InvalidCompactFormat
        })?;

        let sig_str = siter.next().ok_or_else(|| {
            debug!("invalid compact format - signature not present");
            JwtError::InvalidCompactFormat
        })?;

        if siter.next().is_some() {
            // Too much data.
            debug!("invalid compact format - extra fields present");
            return Err(JwtError::InvalidCompactFormat);
        }

        let payload_b64 = payload_str.to_string();

        let signature = general_purpose::URL_SAFE_NO_PAD
            .decode(sig_str)
            .map_err(|_| {
                debug!("invalid base64 when decoding signature");
                JwtError::InvalidBase64
            })?;

        Ok(JwsCompact {
            header,
            hdr_b64,
            payload_b64,
            signature,
        })
    }
}

impl fmt::Display for JwsCompact {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let sig = general_purpose::URL_SAFE_NO_PAD.encode(&self.signature);
        write!(f, "{}.{}.{}", self.hdr_b64, self.payload_b64, sig)
    }
}

impl JwsVerifiable for JwsCompact {
    type Verified = Jws;

    fn data(&self) -> JwsCompactVerifyData {
        JwsCompactVerifyData {
            header: &self.header,
            hdr_bytes: self.hdr_b64.as_bytes(),
            payload_bytes: self.payload_b64.as_bytes(),
            signature_bytes: self.signature.as_slice(),
        }
    }

    fn post_process(&self, value: Jws) -> Result<Self::Verified, JwtError> {
        Ok(value)
    }
}

/// Data that will be verified
pub struct JwsCompactVerifyData<'a> {
    #[allow(dead_code)]
    pub(crate) header: &'a ProtectedHeader,
    #[allow(dead_code)]
    pub(crate) hdr_bytes: &'a [u8],
    #[allow(dead_code)]
    pub(crate) payload_bytes: &'a [u8],
    #[allow(dead_code)]
    pub(crate) signature_bytes: &'a [u8],
}

#[cfg(any(feature = "unsafe_release_without_verify", feature = "openssl"))]
impl<'a> JwsCompactVerifyData<'a> {
    pub(crate) fn release(&self) -> Result<Jws, JwtError> {
        general_purpose::URL_SAFE_NO_PAD
            .decode(self.payload_bytes)
            .map_err(|_| {
                debug!("invalid base64 while decoding payload");
                JwtError::InvalidBase64
            })
            .map(|payload| Jws {
                header: self.header.clone(),
                payload,
            })
    }
}

#[derive(Debug, Serialize, Copy, Clone, Deserialize, PartialEq, Default)]
#[allow(non_camel_case_types)]
/// Cryptographic algorithm
pub enum JweAlg {
    /// AES 128 Key Wrap
    #[default]
    A128KW,
    /// AES 256 Key Wrap
    A256KW,
    /// RSA-OAEP
    #[serde(rename = "RSA-OAEP")]
    RSA_OAEP,
}

#[derive(Debug, Serialize, Copy, Clone, Deserialize, PartialEq, Default)]
#[allow(non_camel_case_types)]
/// Encipherment algorithm
pub enum JweEnc {
    /// AES 128 GCM. Header is authenticated but not encrypted, the payload is
    /// encrypted and authenticated.
    #[default]
    A128GCM,
    /// AES 256 GCM. Header is authenticated but not encrypted, the payload is
    /// encrypted and authenticated.
    A256GCM,
    /// AES 128 CBC with HMAC 256
    /// WARNING: Decrypted values may not be correct as the CEK is not HMACed.
    #[serde(rename = "A128CBC-HS256")]
    A128CBC_HS256,
}

/// A header that will be signed and embedded in the Jws
#[derive(Debug, Serialize, Clone, Deserialize, Default, PartialEq)]
pub struct JweProtectedHeader {
    pub(crate) alg: JweAlg,

    pub(crate) enc: JweEnc,

    // zip
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) jku: Option<Url>,
    // https://datatracker.ietf.org/doc/html/rfc7517
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) jwk: Option<Jwk>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) kid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) crit: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) typ: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) cty: Option<String>,

    #[serde(skip_deserializing, skip_serializing_if = "Option::is_none")]
    pub(crate) x5u: Option<()>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) x5c: Option<Vec<String>>,
    #[serde(skip_deserializing, skip_serializing_if = "Option::is_none")]
    pub(crate) x5t: Option<()>,
    #[serde(
        skip_deserializing,
        rename = "x5t#S256",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) x5t_s256: Option<()>,
    // Don't allow extra header names?
}

#[derive(Clone)]
pub struct JweCompact {
    pub(crate) header: JweProtectedHeader,
    pub(crate) hdr_b64: String,
    pub(crate) content_enc_key: Vec<u8>,
    pub(crate) iv: Vec<u8>,
    pub(crate) ciphertext: Vec<u8>,
    pub(crate) authentication_tag: Vec<u8>,
}

impl JweCompact {
    /// Get the KID used to encipher this Jws if present
    pub fn get_jwk_kid(&self) -> Option<&str> {
        self.header.kid.as_deref()
    }

    /// Get the embedded Url for the Jwk that enciphered this Jwe.
    ///
    /// You MUST ensure this url uses HTTPS and you MUST ensure that your
    /// client validates the CA's used.
    pub fn get_jwk_pubkey_url(&self) -> Option<&Url> {
        self.header.jku.as_ref()
    }

    /// Get the embedded public key used to encipher this Jwe, if present.
    pub fn get_jwk_pubkey(&self) -> Option<&Jwk> {
        self.header.jwk.as_ref()
    }
}

impl FromStr for JweCompact {
    type Err = JwtError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // split on the ".".
        let mut siter = s.splitn(5, '.');

        let hdr_str = siter.next().ok_or_else(|| {
            debug!("invalid compact format - unprotected header not present");
            JwtError::InvalidCompactFormat
        })?;

        let header: JweProtectedHeader = general_purpose::URL_SAFE_NO_PAD
            .decode(hdr_str)
            .map_err(|_| {
                debug!("invalid base64 while decoding header");
                JwtError::InvalidBase64
            })
            .and_then(|bytes| {
                serde_json::from_slice(&bytes).map_err(|e| {
                    debug!(?e, "invalid header format - invalid json");
                    JwtError::InvalidHeaderFormat
                })
            })?;

        let hdr_b64 = hdr_str.to_string();

        // Assert that from the critical field of the header, we have decoded all the needed types.
        // Remember, anything in rfc7515 can NOT be in the crit field.
        if let Some(crit) = &header.crit {
            if !crit.is_empty() {
                error!("critical extension - unable to process critical extensions");
                return Err(JwtError::CriticalExtension);
            }
        }

        // Now we have a header, lets get the rest.
        let content_enc_key_str = siter.next().ok_or_else(|| {
            debug!("invalid compact format - content encryption key not present");
            JwtError::InvalidCompactFormat
        })?;

        let iv_str = siter.next().ok_or_else(|| {
            debug!("invalid compact format - iv not present");
            JwtError::InvalidCompactFormat
        })?;

        let ciphertext_str = siter.next().ok_or_else(|| {
            debug!("invalid compact format - ciphertext not present");
            JwtError::InvalidCompactFormat
        })?;

        let authentication_tag_str = siter.next().ok_or_else(|| {
            debug!("invalid compact format - ciphertext not present");
            JwtError::InvalidCompactFormat
        })?;

        if siter.next().is_some() {
            // Too much data.
            debug!("invalid compact format - extra fields present");
            return Err(JwtError::InvalidCompactFormat);
        }

        let content_enc_key = general_purpose::URL_SAFE_NO_PAD
            .decode(content_enc_key_str)
            .map_err(|_| {
                debug!("invalid base64 when decoding content encryption key");
                JwtError::InvalidBase64
            })?;

        let iv = general_purpose::URL_SAFE_NO_PAD
            .decode(iv_str)
            .map_err(|_| {
                debug!("invalid base64 when decoding iv");
                JwtError::InvalidBase64
            })?;

        let ciphertext = general_purpose::URL_SAFE_NO_PAD
            .decode(ciphertext_str)
            .map_err(|_| {
                debug!("invalid base64 when decoding ciphertext");
                JwtError::InvalidBase64
            })?;

        let authentication_tag = general_purpose::URL_SAFE_NO_PAD
            .decode(authentication_tag_str)
            .map_err(|_| {
                debug!("invalid base64 when decoding authentication tag");
                JwtError::InvalidBase64
            })?;

        Ok(JweCompact {
            header,
            hdr_b64,
            content_enc_key,
            iv,
            ciphertext,
            authentication_tag,
        })
    }
}

impl fmt::Display for JweCompact {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let content_enc_key_b64 = general_purpose::URL_SAFE_NO_PAD.encode(&self.content_enc_key);
        let iv_b64 = general_purpose::URL_SAFE_NO_PAD.encode(&self.iv);
        let cipher_b64 = general_purpose::URL_SAFE_NO_PAD.encode(&self.ciphertext);
        let aad_b64 = general_purpose::URL_SAFE_NO_PAD.encode(&self.authentication_tag);

        write!(
            f,
            "{}.{}.{}.{}.{}",
            self.hdr_b64, content_enc_key_b64, iv_b64, cipher_b64, aad_b64
        )
    }
}
