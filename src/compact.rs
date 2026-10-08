//! Compact serialisation formats
use crate::error::JwtError;
use crate::jws::Jws;
use crate::traits::JwsVerifiable;
use base64::{engine::general_purpose, Engine as _};
use serde::{Deserialize, Serialize};
use serde_with::{
    base64::{Base64, UrlSafe},
    formats::Unpadded,
    serde_as, IfIsHumanReadable,
};
use std::fmt;
use std::str::FromStr;
use url::Url;

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

#[serde_as]
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
        #[serde_as(as = "IfIsHumanReadable<Base64<UrlSafe, Unpadded>>")]
        x: Vec<u8>,
        /// The public Y component
        #[serde_as(as = "IfIsHumanReadable<Base64<UrlSafe, Unpadded>>")]
        y: Vec<u8>,
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
        #[serde_as(as = "IfIsHumanReadable<Base64<UrlSafe, Unpadded>>")]
        n: Vec<u8>,
        /// Public exponent
        #[serde_as(as = "IfIsHumanReadable<Base64<UrlSafe, Unpadded>>")]
        e: Vec<u8>,
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
    /// RSA-OAEP with Sha1
    #[serde(rename = "RSA-OAEP")]
    RSA_OAEP,
    /// HMAC SHA256
    #[default]
    HS256,
}

/// A header that will be signed and embedded in the Jws. For defined claims see
/// the [IANA JOSE Registry](https://www.iana.org/assignments/jose/jose.xhtml)
#[derive(Debug, Serialize, Clone, Deserialize, Default, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct ProtectedHeader {
    /// The encryption algorithm used in this JWS
    pub alg: JwaAlg,
    /// JWS Key Set URL
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jku: Option<Url>,
    /// The JWK that signs this JWS
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwk: Option<Jwk>,
    /// Key Identifier String
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    /// Criticality of this header and processing it's content
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crit: Option<Vec<String>>,
    /// Type
    #[serde(skip_serializing_if = "Option::is_none")]
    pub typ: Option<String>,
    /// Content
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cty: Option<String>,

    /// X509 URL
    #[serde(skip_deserializing, skip_serializing_if = "Option::is_none")]
    pub x5u: Option<()>,
    /// X509 Chain
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5c: Option<Vec<String>>,
    /// X509 S1 Thumbprint
    #[serde(skip_deserializing, skip_serializing_if = "Option::is_none")]
    pub x5t: Option<String>,
    #[serde(
        skip_deserializing,
        rename = "x5t#S256",
        skip_serializing_if = "Option::is_none"
    )]
    /// X509 S256 Thumbprint
    pub x5t_s256: Option<()>,
    /// Context
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ctx: Option<String>,
    /// Microsoft Extension - JWS usage
    #[cfg(feature = "msextensions")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub r#use: Option<String>,
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

    /// View the content of the JWS header. At this point the content is UNVERIFIED
    /// and may NOT BE TRUSTED.
    pub fn header(&self) -> &ProtectedHeader {
        &self.header
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

impl Serialize for JwsCompact {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let self_str = self.to_string();
        serializer.serialize_str(&self_str)
    }
}

struct JwsCompactVisitor;

impl serde::de::Visitor<'_> for JwsCompactVisitor {
    type Value = JwsCompact;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a compact JWS which consists of three base64 url safe unpadded strings separated with '.'")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        JwsCompact::from_str(v)
            .map_err(|_| serde::de::Error::invalid_value(serde::de::Unexpected::Str(v), &self))
    }
}

impl<'de> Deserialize<'de> for JwsCompact {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_str(JwsCompactVisitor)
    }
}

impl JwsVerifiable for JwsCompact {
    type Verified = Jws;

    fn data(&self) -> JwsCompactVerifyData<'_> {
        JwsCompactVerifyData {
            header: &self.header,
            hdr_bytes: self.hdr_b64.as_bytes(),
            payload_bytes: self.payload_b64.as_bytes(),
            signature_bytes: self.signature.as_slice(),
        }
    }

    fn alg(&self) -> JwaAlg {
        self.header.alg
    }

    fn kid(&self) -> Option<&str> {
        self.header.kid.as_deref()
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

impl JwsCompactVerifyData<'_> {
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
    A128KW,
    /// AES 256 Key Wrap
    #[default]
    A256KW,

    // /// ECDH-ES
    // #[serde(rename = "ECDH-ES+A128KW")]
    // ECDH_ES_A128KW,
    /// ECDH-ES
    #[serde(rename = "ECDH-ES+A256KW")]
    ECDH_ES_A256KW,

    /// RSA-OAEP
    #[serde(rename = "RSA-OAEP")]
    RSA_OAEP,

    /// Direct
    #[serde(rename = "dir")]
    DIRECT,
}

#[derive(Debug, Serialize, Copy, Clone, Deserialize, PartialEq, Default)]
#[allow(non_camel_case_types)]
/// Encipherment algorithm
pub enum JweEnc {
    /// AES 256 GCM. Header is authenticated but not encrypted, the payload is
    /// encrypted and authenticated.
    #[default]
    A256GCM,
    /// AES 128 GCM. Header is authenticated but not encrypted, the payload is
    /// encrypted and authenticated.
    A128GCM,
    // /// AES 128 CBC with HMAC 256
    // #[serde(rename = "A128CBC-HS256")]
    // A128CBC_HS256,
}

/// A header that will be signed and embedded in the Jwe. For defined claims see
/// the [IANA JOSE Registry](https://www.iana.org/assignments/jose/jose.xhtml)
#[derive(Debug, Serialize, Clone, Deserialize, Default, PartialEq)]
#[serde(rename_all = "snake_case")]
pub struct JweProtectedHeader {
    /// The key wrap/derivation algorithm in use protecting the payload key
    pub alg: JweAlg,

    /// The inner encryption of this JWE
    pub enc: JweEnc,

    /// Ephemeral Public Key
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epk: Option<Jwk>,

    /// JWS Key Set URL
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jku: Option<Url>,

    /// Embedded JWK
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwk: Option<Jwk>,
    ///Key Identifier String
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    /// Criticality of this header and processing it's content
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crit: Option<Vec<String>>,
    /// Type
    #[serde(skip_serializing_if = "Option::is_none")]
    pub typ: Option<String>,
    /// Content
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cty: Option<String>,

    /// X509 URL
    #[serde(skip_deserializing, skip_serializing_if = "Option::is_none")]
    pub x5u: Option<()>,
    /// X509 Chain
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5c: Option<Vec<String>>,
    /// X509 S1 Thumbprint
    #[serde(skip_deserializing, skip_serializing_if = "Option::is_none")]
    pub x5t: Option<()>,
    /// X509 S256 Thumbprint
    #[serde(
        skip_deserializing,
        rename = "x5t#S256",
        skip_serializing_if = "Option::is_none"
    )]
    pub x5t_s256: Option<()>,
    /// Context
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ctx: Option<String>,
    /// OAuth2 Extension - the client_id that issued this JWE
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
}

/// A Compact JWE that is able to be deciphered or stringified for transmission
#[derive(Clone)]
pub struct JweCompact {
    pub(crate) header: JweProtectedHeader,
    pub(crate) hdr_b64: String,
    pub(crate) content_enc_key: Vec<u8>,
    pub(crate) iv: Vec<u8>,
    pub(crate) ciphertext: Vec<u8>,
    pub(crate) authentication_tag: Vec<u8>,
}

impl fmt::Debug for JweCompact {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JweCompact")
            .field("header", &self.header)
            .field("encrypted_payload_length", &self.ciphertext.len())
            .finish()
    }
}

impl JweCompact {
    /// Get the KID used to encipher this Jwe if present
    pub fn kid(&self) -> Option<&str> {
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

    /// Return the CEK Algorithm and the inner encryption type.
    pub fn get_alg_enc(&self) -> (JweAlg, JweEnc) {
        (self.header.alg, self.header.enc)
    }

    /// View the content of the JWE header. At this point the content is UNVERIFIED
    /// and may NOT BE TRUSTED.
    pub fn header(&self) -> &JweProtectedHeader {
        &self.header
    }
}

impl FromStr for JweCompact {
    type Err = JwtError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // split on the ".". Remember this means to split on '.' 4 times to create
        // 5 string segments.
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

#[cfg(test)]
mod test {
    use crate::JwkKeySet;

    #[test]
    fn test_parse_default_keycloak_keyset() {
        // Keyset taken from local keycloak:26.7 instance.
        let raw_keyset = r#"{
    "keys": [
    {
        "kid": "IDEbmq1HZnQktPXeMFqTYbzTWue8oylRUEhwv4DVQpE",
        "kty": "RSA",
        "alg": "RS256",
        "use": "sig",
        "x5c": [
        "MIIClTCCAX0CBgGhC1JeczANBgkqhkiG9w0BAQsFADAOMQwwCgYDVQQDDANvb28wHhcNMjYxMDA1MDkwNjQ5WhcNMzYxMDA1MDkwODI5WjAOMQwwCgYDVQQDDANvb28wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCb7N7eHfKozp2q8DLyS05uPi5Q9yLUbWxnIJwnDvoTLAiYqOJeqsmI995plnany2vUoSOx3ACRnKj9mAp+Qifoi8f0oSW1Pl9CDxvdQDR8ZHKkmHAhF3r2v6erzH0qEOgv/yQFS42T6StZV7xtsFeyw5hvucXfGH8/b6LmDxpD3ak/npkNQ4zDCc+eX6UZj6OlyyrGeJZYfJe8smfVGB1l0ELGK9WGnE32OED+8CfqsEgvoy4HiPEU6983Bay45m0yWnDihV7zBrNL7tQEGxY4I0ZqFKAzuwlu/4NntPX42zjX7axmMW4IhIcNY7y/KTMBJrIUfxIJFWD9gmBaQxwXAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAI8VRSE1mliJB4cVOVKNY2w8ownej2cXWfz68JmklTi7yiMkIChEcjDMwI7UtmkSqhi4RFCwTOmmNJhP8eZk+R1z6Edk+Pxzhmv5LAbU0c0Y3bPT7KV7gxlpzV6LB+rUkmy5goA4QB5OYSq7vP442HW+wo/5KhYmCq3/bgsE1MDwF3wMNJQHyyt9KE0S51gbBtKaHMjnMq+/21jy+whTbYyO39IZT4nGoKkhgnpciVYAPRVWiYuRPgrTZQNrM+U9Yf164mtktKJRFfeTPRXPNslYQhxYsR+I2ggLetOfsQXf94jWIUOPF6kqY1cUcYCOQoh2HxO203kdQEJPwHPvA8k="
        ],
        "x5t": "cRl3BN1QFJqRN6A4MvOkYnJS5Gk",
        "x5t#S256": "sPPDbz0ebvlOm_8Wrobev-rZuOwAfpakON4eGTuLQ6g",
        "n": "m-ze3h3yqM6dqvAy8ktObj4uUPci1G1sZyCcJw76EywImKjiXqrJiPfeaZZ2p8tr1KEjsdwAkZyo_ZgKfkIn6IvH9KEltT5fQg8b3UA0fGRypJhwIRd69r-nq8x9KhDoL_8kBUuNk-krWVe8bbBXssOYb7nF3xh_P2-i5g8aQ92pP56ZDUOMwwnPnl-lGY-jpcsqxniWWHyXvLJn1RgdZdBCxivVhpxN9jhA_vAn6rBIL6MuB4jxFOvfNwWsuOZtMlpw4oVe8wazS-7UBBsWOCNGahSgM7sJbv-DZ7T1-Ns41-2sZjFuCISHDWO8vykzASayFH8SCRVg_YJgWkMcFw",
        "e": "AQAB"
    },
    {
        "kid": "wXTkmiS3hgeZRASbhhze_RZoEoAi6mrxiFuR9IOonQk",
        "kty": "RSA",
        "alg": "RSA-OAEP",
        "use": "enc",
        "x5c": [
        "MIIClTCCAX0CBgGhC1JeyjANBgkqhkiG9w0BAQsFADAOMQwwCgYDVQQDDANvb28wHhcNMjYxMDA1MDkwNjUwWhcNMzYxMDA1MDkwODMwWjAOMQwwCgYDVQQDDANvb28wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCtAaJ2DI1421i76agGB70eHAziWrWp39Isr0lbizsqzCcli9us1nBYcXbzcbnUbLHcp3NjJbbNz+D8qmh9nVoUbDJRnspTxojGljCPg+lJS7MefY5vU2KGWZNcUfnk5f7VFf7ghC3xAPY0qAlFmwTTXtw2JK3kHl7/4d6djcVt6+xCDSmjyJQBnWgrZX5pIkFGxLy7a1dBai9Cq/DpJVJO3mQBpGS+eAN9ctWAZMr2ze1IKCTP13C58aUpaDiyAQztWXINk11zirIhe7DXdRqAGGhts2um9QTfNWoSCTCJKfBIR1DF4gqjvXLXrP3e+Uxv46+QOMR1l+VHUM+URBubAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAEp6cJiXKmaKcD83Y988/S3R5CSG1WkatMIwWkNpuFbGmuqG6IK+hBeYq0uV2MZhpdG7yei2Lfn9BJQcFlU5TEUGTUBf4EtvLEKOdaFXGmnHbdNGuodBIGCBDnCWzGxvqcABa4U0iU8UHIlQBbzSiKA29r81S8ecPR+Yc7+spzg0lXmxZLWYNyj/9m02PC5aI0r7WV1ZifOHFT3iQFdrhj/osNXdJoE5r4BLVAyuJ9Ws0tMgfCyuarigcMxko8OS9gftumEUDPb5w20ukFlsVAcMKk7B/QTZkyN+s/FK9+A422RLLjjR5tEFIUk18swBxFxJSWdsdXMTXF86A6eHyTE="
        ],
        "x5t": "ohFRY9F1EaI2LDgO9mo2fS3dEBU",
        "x5t#S256": "D_lIHppuzTwx1li5vHa2b450ztAnGfy9fgUczn6-GYo",
        "n": "rQGidgyNeNtYu-moBge9HhwM4lq1qd_SLK9JW4s7KswnJYvbrNZwWHF283G51Gyx3KdzYyW2zc_g_KpofZ1aFGwyUZ7KU8aIxpYwj4PpSUuzHn2Ob1NihlmTXFH55OX-1RX-4IQt8QD2NKgJRZsE017cNiSt5B5e_-HenY3FbevsQg0po8iUAZ1oK2V-aSJBRsS8u2tXQWovQqvw6SVSTt5kAaRkvngDfXLVgGTK9s3tSCgkz9dwufGlKWg4sgEM7VlyDZNdc4qyIXuw13UagBhobbNrpvUE3zVqEgkwiSnwSEdQxeIKo71y16z93vlMb-OvkDjEdZflR1DPlEQbmw",
        "e": "AQAB"
    }
    ]
}"#;

        let _ = serde_json::from_str::<JwkKeySet>(raw_keyset)
            .expect("Compatibility with keycloak algs");
    }
}
