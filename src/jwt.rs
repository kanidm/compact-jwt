//! Jwt implementation

use crate::btreemap_empty;
use crate::compact::Jwk;
use crate::error::JwtError;
use crate::jws::{Jws, JwsSigned, JwsUnverified};
use crate::traits::{JwsSigner, JwsVerifier};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

/// An unverified jwt input which is ready to validate
pub struct JwtUnverified {
    jws: JwsUnverified,
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

#[cfg(feature = "openssl")]
impl<V> Jwt<V>
where
    V: Clone + Serialize,
{
    /// Sign the content of this JWT token with the provided signer
    pub fn sign<S: JwsSigner>(&self, signer: &mut S) -> Result<JwtSigned, JwtError> {
        let mut jwts = Jws::into_json(self).map_err(|_| JwtError::InvalidJwt)?;

        jwts.set_typ(Some("JWT"));

        jwts.sign(signer).map(|jwsc| JwtSigned {
            jws: JwsSigned { jwsc },
        })
    }
}

impl JwtUnverified {
    /// Using this JwsVerifier, assert the correct signature of the data contained in
    /// this token.
    pub fn verify<K, V>(&self, verifier: &mut K) -> Result<Jwt<V>, JwtError>
    where
        K: JwsVerifier,
        V: Clone + DeserializeOwned,
    {
        let jws = self.jws.verify(verifier)?;

        jws.from_json().map_err(|_| JwtError::InvalidJwt)
    }

    /// Get the embedded public key used to sign this jwt, if present.
    pub fn get_jwk_pubkey(&self) -> Option<&Jwk> {
        self.jws.get_jwk_pubkey()
    }

    /// Get the KID used to sign this Jws if present
    pub fn get_jwk_kid(&self) -> Option<&str> {
        self.jws.get_jwk_kid()
    }
}

impl FromStr for JwtUnverified {
    type Err = JwtError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        JwsUnverified::from_str(s).map(|jws| JwtUnverified { jws })
    }
}

impl JwtSigned {
    /// Invalidate this signed jwt, causing it to require validation before you can use it
    /// again.
    pub fn invalidate(self) -> JwtUnverified {
        JwtUnverified {
            jws: self.jws.invalidate(),
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
    use crate::crypto::JwsEs256Signer;
    use crate::traits::JwsSignerToVerifier;
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

        let mut jws_es256_signer =
            JwsEs256Signer::generate_es256().expect("failed to construct signer.");
        let mut jwk_es256_verifier = jws_es256_signer
            .get_verifier()
            .expect("failed to get verifier from signer");

        let jwts = jwt.sign(&mut jws_es256_signer).expect("failed to sign jwt");

        let jwtu = jwts.invalidate();

        let released = jwtu
            .verify(&mut jwk_es256_verifier)
            .expect("Unable to validate jwt");

        assert!(released == jwt);
    }
}
