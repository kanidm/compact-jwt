//! Jwt implementation

use crate::btreemap_empty;
use crate::compact::{Jwk, JwsCompact, JwsCompactVerifyData};
use crate::error::JwtError;
use crate::jws::{Jws, JwsCompactSign2Data, JwsSigned};
use crate::traits::{JwsSignable, JwsSigner, JwsVerifiable, JwsVerifier};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::marker::PhantomData;
use std::str::FromStr;

/// An unverified jwt input which is ready to validate
pub struct JwtUnverified<V> {
    jwsc: JwsCompact,
    _v: PhantomData<V>,
}

/// A signed jwt which can be converted to a string.
pub struct JwtSigned {
    jws: JwsSigned,
}

/// A Jwt that is being created or has succeeded in being validated
#[derive(Serialize, Clone, Deserialize)]
pub struct Jwt<V>
where
    V: Clone,
{
    /// The issuer of this token
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    /// Unique id of the subject
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    /// client_id of the oauth2 rp
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,
    /// Expiry in utc epoch seconds
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,
    /// Not valid before.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<i64>,
    /// Issued at time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<i64>,
    /// -- not used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    /// If you wish to include extensions as a struct, you can use this struct. If you do
    /// not have extensions, set this type to () with `Jwt<()>` and it will be skipped.
    #[serde(flatten)]
    pub extensions: V,
    /// Arbitrary custom claims can be inserted or decoded here. These allow you
    /// to add or detect other claims that may or may not be in your extension struct
    #[serde(flatten, skip_serializing_if = "btreemap_empty")]
    pub claims: BTreeMap<String, serde_json::value::Value>,
}

impl<V> Default for Jwt<V>
where
    V: Clone + Default,
{
    fn default() -> Self {
        Jwt {
            iss: None,
            sub: None,
            aud: None,
            exp: None,
            nbf: None,
            iat: None,
            jti: None,
            extensions: V::default(),
            claims: BTreeMap::default(),
        }
    }
}

impl<V> fmt::Debug for Jwt<V>
where
    V: Clone + fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Jwt")
            .field("iss", &self.iss)
            .field("sub", &self.sub)
            .field("aud", &self.aud)
            .field("exp", &self.exp)
            .field("nbf", &self.nbf)
            .field("iat", &self.iat)
            .field("jti", &self.jti)
            .field("extensions", &self.extensions)
            .field("claims", &self.claims)
            .finish()
    }
}

impl<V> PartialEq for Jwt<V>
where
    V: Clone + PartialEq,
{
    fn eq(&self, other: &Jwt<V>) -> bool {
        self.iss == other.iss
            && self.sub == other.sub
            && self.aud == other.aud
            && self.exp == other.exp
            && self.nbf == other.nbf
            && self.iat == other.iat
            && self.jti == other.jti
            && self.extensions == other.extensions
            && self.claims == other.claims
    }
}

impl<V> JwsSignable for Jwt<V>
where
    V: Clone + Serialize,
{
    type Signed = JwtSigned;

    fn data(&self) -> Result<JwsCompactSign2Data, JwtError> {
        let mut jwts = Jws::into_json(self).map_err(|_| JwtError::InvalidJwt)?;

        jwts.set_typ(Some("JWT"));

        jwts.data()
    }

    fn post_process(&self, jwsc: JwsCompact) -> Result<Self::Signed, JwtError> {
        Ok(JwtSigned {
            jws: JwsSigned { jwsc },
        })
    }
}

impl<V> JwsVerifiable for JwtUnverified<V>
where
    V: Clone + DeserializeOwned,
{
    type Verified = Jwt<V>;

    fn data<'a>(&'a self) -> JwsCompactVerifyData<'a> {
        self.jwsc.data()
    }

    fn post_process(&self, value: Jws) -> Result<Self::Verified, JwtError> {
        value.from_json().map_err(|_| JwtError::InvalidJwt)
    }
}

impl<V> JwtUnverified<V>
where
    V: Clone + DeserializeOwned,
{
    /// Get the embedded public key used to sign this jwt, if present.
    pub fn get_jwk_pubkey(&self) -> Option<&Jwk> {
        self.jwsc.get_jwk_pubkey()
    }

    /// Get the KID used to sign this Jws if present
    pub fn get_jwk_kid(&self) -> Option<&str> {
        self.jwsc.get_jwk_kid()
    }
}

impl<V> FromStr for JwtUnverified<V> {
    type Err = JwtError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        JwsCompact::from_str(s).map(|jwsc| JwtUnverified {
            jwsc,
            _v: PhantomData,
        })
    }
}

impl JwtSigned {
    /// Invalidate this signed jwt, causing it to require validation before you can use it
    /// again.
    pub fn invalidate<V>(self) -> JwtUnverified<V> {
        JwtUnverified {
            jwsc: self.jws.jwsc,
            _v: PhantomData,
        }
    }
}

impl fmt::Display for JwtSigned {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.jws.fmt(f)
    }
}

#[cfg(all(feature = "openssl", test))]
mod tests {
    use super::Jwt;
    use crate::crypto::JwsHs256Signer;
    use crate::traits::*;
    use serde::{Deserialize, Serialize};

    #[derive(Default, Debug, Serialize, Clone, Deserialize, PartialEq)]
    struct CustomExtension {
        my_exten: String,
    }

    #[test]
    fn test_sign_and_validate() {
        let _ = tracing_subscriber::fmt::try_init();
        let jwt = Jwt {
            iss: Some("test".to_string()),
            extensions: CustomExtension {
                my_exten: "Hello".to_string(),
            },
            ..Default::default()
        };

        let mut jws_hs256_signer =
            JwsHs256Signer::generate_hs256().expect("failed to construct signer.");

        let jwts = jws_hs256_signer.sign2(&jwt).expect("failed to sign jwt");

        let jwtu = jwts.invalidate();

        let released = jws_hs256_signer
            .verify(&jwtu)
            .expect("Unable to validate jwt");

        assert!(released == jwt);
    }
}
