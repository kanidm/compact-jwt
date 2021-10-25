//! Oidc token implementation

use crate::btreemap_empty;
use crate::crypto::{Jwk, Jws, JwsCompact, JwsSigner, JwsValidator};
use crate::error::JwtError;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;
use url::Url;

/// An unverified token input which is ready to validate
pub struct OidcUnverified {
    jwsc: JwsCompact,
}

/// A signed oidc token which can be converted to a string.
pub struct OidcSigned {
    jwsc: JwsCompact,
}

/// An Oidc Token that is being created, or has succeeded in being validated
#[derive(Debug, Serialize, Clone, Deserialize, PartialEq)]
pub struct OidcToken {
    /// Case sensitive URL.
    pub iss: Url,
    /// Unique id of the subject
    pub sub: String,
    /// client_id of the oauth2 rp
    pub aud: String,
    /// Expiry in utc epoch seconds
    pub exp: i64,
    /// Not valid before.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<i64>,
    /// Issued at time.
    pub iat: i64,
    // The time when the authentication of the user occured.
    /// Time when the user originally authenticated.
    pub auth_time: i64,
    /// Comes from authn req
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    /// -- not used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acr: Option<String>,
    /// List of auth methods
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amr: Option<Vec<String>>,
    ///
    #[serde(skip_serializing_if = "Option::is_none")]
    pub azp: Option<String>,
    /// -- not used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    /// Arbitrary custom claims can be inserted or decoded here.
    #[serde(flatten, skip_serializing_if = "btreemap_empty")]
    pub claims: BTreeMap<String, serde_json::value::Value>,
}

impl OidcToken {
    fn sign_inner(
        &self,
        signer: &JwsSigner,
        jku: Option<Url>,
        jwk: Option<Jwk>,
    ) -> Result<OidcSigned, JwtError> {
        // We need to convert this payload to a set of bytes.
        let payload = serde_json::to_vec(&self).map_err(|_| JwtError::InvalidJwt)?;

        let jws = Jws::new(payload).set_typ("JWT".to_string());

        jws.sign_inner(signer, jku, jwk)
            .map(|jwsc| OidcSigned { jwsc })
    }

    /// Use this private signer to created a signed oidc token.
    pub fn sign(&self, signer: &JwsSigner) -> Result<OidcSigned, JwtError> {
        self.sign_inner(signer, None, None)
    }

    /// Use this private signer to created a signed oidc token, which contains the public
    /// key for verification embedded in the header of the token.
    pub fn sign_embed_public_jwk(&self, signer: &JwsSigner) -> Result<OidcSigned, JwtError> {
        let jwk = signer.public_key_as_jwk()?;
        self.sign_inner(signer, None, Some(jwk))
    }
}

impl OidcUnverified {
    /// Using this JwsValidator, assert the correct signature of the data contained in
    /// this token.
    pub fn validate(&self, validator: &JwsValidator) -> Result<OidcToken, JwtError> {
        let released = self.jwsc.validate(&validator)?;

        serde_json::from_slice(released.payload()).map_err(|_| JwtError::InvalidJwt)
    }

    /// Retrieve the URL which holds the public key used to sign this token if it exists
    /// in the JWS header.
    pub fn get_jwk_pubkey_url(&self) -> Option<&Url> {
        self.jwsc.get_jwk_pubkey_url()
    }

    /// Retrieve the public key used to sign this token if it exists in the JWS header.
    pub fn get_jwk_pubkey(&self) -> Option<&Jwk> {
        self.jwsc.get_jwk_pubkey()
    }
}

impl FromStr for OidcUnverified {
    type Err = JwtError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        JwsCompact::from_str(s).map(|jwsc| OidcUnverified { jwsc })
    }
}

impl OidcSigned {
    /// Invalidate this signed oidc token, causing it to require validation before you can use it
    /// again.
    pub fn invalidate(self) -> OidcUnverified {
        OidcUnverified { jwsc: self.jwsc }
    }
}

impl fmt::Display for OidcSigned {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.jwsc.fmt(f)
    }
}

#[cfg(test)]
mod tests {
    use super::{OidcToken, OidcUnverified};
    use crate::crypto::{JwsSigner, JwsValidator};
    use std::convert::TryFrom;
    use std::str::FromStr;
    use url::Url;

    #[test]
    fn test_sign_and_validate() {
        let jwt = OidcToken {
            iss: Url::parse("https://oidc.example.com").unwrap(),
            sub: "6f5ac8d0-8b7b-4a30-8504-e26a43c7a574".to_string(),
            aud: "test".to_string(),
            exp: 0,
            nbf: Some(0),
            iat: 0,
            auth_time: 0,
            nonce: None,
            acr: None,
            amr: None,
            azp: None,
            jti: None,
            claims: Default::default(),
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
        let jwt = OidcToken {
            iss: Url::parse("https://oidc.example.com").unwrap(),
            sub: "6f5ac8d0-8b7b-4a30-8504-e26a43c7a574".to_string(),
            aud: "test".to_string(),
            exp: 0,
            nbf: Some(0),
            iat: 0,
            auth_time: 0,
            nonce: None,
            acr: None,
            amr: None,
            azp: None,
            jti: None,
            claims: Default::default(),
        };

        let jwss = JwsSigner::generate_es256().expect("failed to construct signer.");
        let pub_jwk = jwss.public_key_as_jwk().unwrap();
        let jws_validator = JwsValidator::try_from(&pub_jwk).expect("Unable to create validator");

        let jwts = jwt.sign(&jwss).expect("failed to sign jwt");

        let jwt_str = jwts.to_string();
        eprintln!("{}", jwt_str);
        let jwtu = OidcUnverified::from_str(&jwt_str).expect("Unable to parse jws/jwt");

        let released = jwtu
            .validate(&jws_validator)
            .expect("Unable to validate jwt");

        assert!(released == jwt);
    }
}
