//! Jwt implementation

use crate::btreemap_empty;
use crate::crypto::{Jwk, Jws, JwsCompact, JwsSigner, JwsValidator};
use crate::error::JwtError;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;
use url::Url;

/// An unverified jwt input which is ready to validate
pub struct JwtUnverified {
    jwsc: JwsCompact,
}

/// A signed jwt which can be converted to a string.
pub struct JwtSigned {
    jwsc: JwsCompact,
}

/// A Jwt that is being created or has succeeded in being validated
#[derive(Default, Debug, Serialize, Clone, Deserialize, PartialEq)]
pub struct Jwt {
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
    /// Arbitrary custom claims can be inserted or decoded here.
    #[serde(flatten, skip_serializing_if = "btreemap_empty")]
    pub claims: BTreeMap<String, serde_json::value::Value>,
}

impl Jwt {
    fn sign_inner(
        &self,
        signer: &JwsSigner,
        jku: Option<Url>,
        jwk: Option<Jwk>,
    ) -> Result<JwtSigned, JwtError> {
        // We need to convert this payload to a set of bytes.
        let payload = serde_json::to_vec(&self).map_err(|_| JwtError::InvalidJwt)?;

        let jws = Jws::new(payload).set_typ("JWT".to_string());

        jws.sign_inner(signer, jku, jwk)
            .map(|jwsc| JwtSigned { jwsc })
    }

    /// Use this private signer to created a signed jwt.
    pub fn sign(&self, signer: &JwsSigner) -> Result<JwtSigned, JwtError> {
        self.sign_inner(signer, None, None)
    }
}

impl JwtUnverified {
    /// Using this JwsValidator, assert the correct signature of the data contained in
    /// this jwt.
    pub fn validate(&self, validator: &JwsValidator) -> Result<Jwt, JwtError> {
        let released = self.jwsc.validate(validator)?;

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

#[cfg(test)]
mod tests {
    use super::{Jwt, JwtUnverified};
    use crate::crypto::{JwsSigner, JwsValidator};
    use std::convert::TryFrom;
    use std::str::FromStr;

    #[test]
    fn test_sign_and_validate() {
        let jwt = Jwt {
            iss: Some("test".to_string()),
            ..Default::default()
        };

        let jwss = JwsSigner::generate_es256().expect("failed to construct signer.");
        let pub_jwk = jwss.public_key_as_jwk(None).unwrap();
        let jws_validator = JwsValidator::try_from(&pub_jwk).expect("Unable to create validator");

        let jwts = jwt.sign(&jwss).expect("failed to sign jwt");

        let jwtu = jwts.invalidate();

        let released = jwtu
            .validate(&jws_validator)
            .expect("Unable to validate jwt");

        assert!(released == jwt);
    }

    #[test]
    fn test_sign_and_validate_str() {
        let jwt = Jwt {
            iss: Some("test".to_string()),
            ..Default::default()
        };

        let jwss = JwsSigner::generate_es256().expect("failed to construct signer.");
        let pub_jwk = jwss.public_key_as_jwk(None).unwrap();
        let jws_validator = JwsValidator::try_from(&pub_jwk).expect("Unable to create validator");

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
