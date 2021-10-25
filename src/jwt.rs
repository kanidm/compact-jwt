use crate::crypto::{Jwk, Jws, JwsCompact, JwsSigner, JwsValidator};
use crate::error::JwtError;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;
use url::Url;

pub struct JwtUnverified {
    jwsc: JwsCompact,
}

pub struct JwtSigned {
    jwsc: JwsCompact,
}

#[derive(Debug, Serialize, Clone, Deserialize, PartialEq)]
pub struct Jwt {
    pub iss: Option<String>,
    pub sub: Option<String>,
    pub aud: Option<String>,
    pub exp: Option<i64>,
    pub nbf: Option<i64>,
    pub iat: Option<i64>,
    pub jti: Option<String>,
    #[serde(flatten)]
    pub claims: BTreeMap<String, serde_json::value::Value>,
}

impl Default for Jwt {
    fn default() -> Self {
        Jwt {
            iss: None,
            sub: None,
            aud: None,
            exp: None,
            nbf: None,
            iat: None,
            jti: None,
            claims: BTreeMap::new(),
        }
    }
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

    pub fn sign(&self, signer: &JwsSigner) -> Result<JwtSigned, JwtError> {
        self.sign_inner(signer, None, None)
    }
}

impl JwtUnverified {
    pub fn validate(&self, validator: &JwsValidator) -> Result<Jwt, JwtError> {
        let released = self.jwsc.validate(&validator)?;

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
        let pub_jwk = jwss.public_key_as_jwk().unwrap();
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
        let pub_jwk = jwss.public_key_as_jwk().unwrap();
        let jws_validator = JwsValidator::try_from(&pub_jwk).expect("Unable to create validator");

        let jwts = jwt.sign(&jwss).expect("failed to sign jwt");

        let jwt_str = jwts.to_string();
        eprintln!("{}", jwt_str);
        let jwtu = JwtUnverified::from_str(&jwt_str).expect("Unable to parse jws/jwt");

        let released = jwtu
            .validate(&jws_validator)
            .expect("Unable to validate jwt");

        assert!(released == jwt);
    }
}
