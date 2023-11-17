//! Jwt implementation

use crate::btreemap_empty;
use crate::compact::{Jwk, JwsCompact, JwsInner};
#[cfg(feature = "openssl")]
use crate::crypto::{JwsSignerEnum, JwsValidatorEnum};
#[cfg(feature = "openssl")]
use url::Url;

use crate::error::JwtError;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

/// An unverified jwt input which is ready to validate
pub struct JwtUnverified {
    jwsc: JwsCompact,
}

/// A signed jwt which can be converted to a string.
pub struct JwtSigned {
    jwsc: JwsCompact,
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
    fn sign_inner(
        &self,
        signer: &JwsSignerEnum,
        jku: Option<Url>,
        jwk: Option<Jwk>,
    ) -> Result<JwtSigned, JwtError> {
        // We need to convert this payload to a set of bytes.
        // eprintln!("{:?}", serde_json::to_string(&self));
        let payload = serde_json::to_vec(&self).map_err(|_| JwtError::InvalidJwt)?;

        let jws = JwsInner::new(payload)
            .set_kid(signer.get_kid().to_string())
            .set_typ("JWT".to_string());

        jws.sign_inner(signer, jku, jwk)
            .map(|jwsc| JwtSigned { jwsc })
    }

    /// Use this private signer to created a signed jwt.
    pub fn sign(&self, signer: &JwsSignerEnum) -> Result<JwtSigned, JwtError> {
        self.sign_inner(signer, None, None)
    }

    /// Use this to create a signed jwt that includes the public key used in the signing process
    pub fn sign_embed_public_jwk(&self, signer: &JwsSignerEnum) -> Result<JwtSigned, JwtError> {
        let jwk = signer.public_key_as_jwk()?;
        self.sign_inner(signer, None, Some(jwk))
    }
}

#[cfg(feature = "openssl")]
impl JwtUnverified {
    /// Using this JwsValidatorEnum, assert the correct signature of the data contained in
    /// this jwt.
    pub fn validate<V>(&self, validator: &JwsValidatorEnum) -> Result<Jwt<V>, JwtError>
    where
        V: Clone + serde::de::DeserializeOwned,
    {
        let released = self.jwsc.validate(validator)?;

        serde_json::from_slice(released.payload()).map_err(|_| JwtError::InvalidJwt)
    }
}

impl JwtUnverified {
    /// Get the embedded public key used to sign this jwt, if present.
    pub fn get_jwk_pubkey(&self) -> Option<&Jwk> {
        self.jwsc.get_jwk_pubkey()
    }

    /// UNSAFE - release the content of this JWS without verifying it's internal structure.
    ///
    /// THIS MAY LEAD TO SECURITY VULNERABILITIES. YOU SHOULD BE ACUTELY AWARE OF THE RISKS WHEN
    /// CALLING THIS FUNCTION.
    #[cfg(feature = "unsafe_release_without_verify")]
    pub fn unsafe_release_without_verification<V>(&self) -> Result<Jwt<V>, JwtError>
    where
        V: Clone + serde::de::DeserializeOwned,
    {
        let released = self.jwsc.release_without_verification()?;

        serde_json::from_slice(released.payload()).map_err(|_| JwtError::InvalidJwt)
    }
}

impl FromStr for JwtUnverified {
    type Err = JwtError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        JwsCompact::from_str(s).map(|jwsc| JwtUnverified { jwsc })
    }
}

impl JwtSigned {
    /// Invalidate this signed jwt, causing it to require validation before you can use it
    /// again.
    pub fn invalidate(self) -> JwtUnverified {
        JwtUnverified { jwsc: self.jwsc }
    }
}

impl fmt::Display for JwtSigned {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.jwsc.fmt(f)
    }
}

#[cfg(all(feature = "openssl", test))]
mod tests {
    use super::{Jwt, JwtUnverified};
    use crate::crypto::{JwsSignerEnum, JwsValidatorEnum};
    use serde::{Deserialize, Serialize};
    use std::convert::TryFrom;
    use std::str::FromStr;

    #[derive(Default, Debug, Serialize, Clone, Deserialize, PartialEq)]
    struct CustomExtension {
        my_exten: String,
    }

    #[test]
    fn test_sign_and_validate() {
        let _ = tracing_subscriber::fmt::try_init();
        let jwt: Jwt<()> = Jwt {
            iss: Some("test".to_string()),
            ..Default::default()
        };

        let jwss = JwsSignerEnum::generate_es256().expect("failed to construct signer.");
        let pub_jwk = jwss.public_key_as_jwk().unwrap();
        let jws_validator =
            JwsValidatorEnum::try_from(&pub_jwk).expect("Unable to create validator");

        let jwts = jwt.sign(&jwss).expect("failed to sign jwt");

        let jwtu = jwts.invalidate();

        let released = jwtu
            .validate(&jws_validator)
            .expect("Unable to validate jwt");

        assert!(released == jwt);

        let jwt = Jwt {
            iss: Some("test".to_string()),
            extensions: CustomExtension {
                my_exten: "Hello".to_string(),
            },
            ..Default::default()
        };

        let jwts = jwt.sign(&jwss).expect("failed to sign jwt");

        let jwtu = jwts.invalidate();

        let released = jwtu
            .validate(&jws_validator)
            .expect("Unable to validate jwt");

        assert!(released == jwt);
    }

    #[test]
    fn test_sign_and_validate_str() {
        let _ = tracing_subscriber::fmt::try_init();
        let jwt = Jwt::<()> {
            iss: Some("test".to_string()),
            ..Default::default()
        };

        let jwss = JwsSignerEnum::generate_es256().expect("failed to construct signer.");
        let pub_jwk = jwss.public_key_as_jwk().unwrap();
        let jws_validator =
            JwsValidatorEnum::try_from(&pub_jwk).expect("Unable to create validator");

        let jwts = jwt.sign(&jwss).expect("failed to sign jwt");

        let jwt_str = jwts.to_string();
        trace!("{}", jwt_str);
        let jwtu = JwtUnverified::from_str(&jwt_str).expect("Unable to parse jws/jwt");

        let released = jwtu
            .validate(&jws_validator)
            .expect("Unable to validate jwt");

        assert!(released == jwt);
    }
}
