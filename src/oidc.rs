//! Oidc token implementation

use crate::crypto::{Jws, JwsCompact, JwsSigner, JwsValidator};
use crate::error::JwtError;
use crate::{btreemap_empty, vec_empty};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;
use url::Url;
use uuid::Uuid;

/// An unverified token input which is ready to validate
pub struct OidcUnverified {
    jwsc: JwsCompact,
}

/// A signed oidc token which can be converted to a string.
pub struct OidcSigned {
    jwsc: JwsCompact,
}

#[derive(Debug, Serialize, Clone, Deserialize, PartialEq)]
#[serde(untagged)]
/// The subject of the oidc token. This is intended to be a unique identifier which is
/// why we have special handling for a number of possible unique formats.
pub enum OidcSubject {
    /// A uuid of the subject.
    U(Uuid),
    /// An arbitrary string
    S(String),
}

impl fmt::Display for OidcSubject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OidcSubject::U(u) => write!(f, "{}", u),
            OidcSubject::S(s) => write!(f, "{}", s),
        }
    }
}

/// Standardised or common claims that are used in oidc.
/// `https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims`
#[derive(Debug, Serialize, Clone, Deserialize, PartialEq, Default)]
pub struct OidcClaims {
    /// This is equivalent to a display name, and how the user wishes to be seen or known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The displayed username. Ie claire or c.example
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preferred_username: Option<String>,
    /// email - the primary mail address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// If the email has been validated.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
    /// The users timezone
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zoneinfo: Option<String>,
    /// The users locale
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locale: Option<String>,
    /// The scopes assigned to this token
    #[serde(skip_serializing_if = "vec_empty", default)]
    pub scopes: Vec<String>,
}

/// An Oidc Token that is being created, or has succeeded in being validated
#[derive(Debug, Serialize, Clone, Deserialize, PartialEq)]
pub struct OidcToken {
    /// Case sensitive URL.
    pub iss: Url,
    /// Unique id of the subject
    pub sub: OidcSubject,
    /// client_id of the oauth2 rp
    pub aud: String,
    /// Expiry in utc epoch seconds
    pub exp: i64,
    /// Not valid before.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<i64>,
    /// Issued at time.
    pub iat: i64,
    /// Time when the user originally authenticated.
    pub auth_time: Option<i64>,
    /// Comes from authn req
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    /// -- not used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub at_hash: Option<String>,
    /// -- not used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acr: Option<String>,
    /// List of auth methods
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amr: Option<Vec<String>>,
    /// Do not use.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub azp: Option<String>,
    /// -- not used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    /// Standardised or common claims
    #[serde(flatten)]
    pub s_claims: OidcClaims,
    /// Arbitrary custom claims can be inserted or decoded here.
    #[serde(flatten, skip_serializing_if = "btreemap_empty")]
    pub claims: BTreeMap<String, serde_json::value::Value>,
}

impl OidcToken {
    fn sign_inner(&self, signer: &JwsSigner, kid: Option<&str>) -> Result<OidcSigned, JwtError> {
        // We need to convert this payload to a set of bytes.
        trace!(
            "✅ {}",
            serde_json::to_string(&self).map_err(|_| JwtError::InvalidJwt)?
        );
        let payload = serde_json::to_vec(&self).map_err(|_| JwtError::InvalidJwt)?;

        let jws = Jws::new(payload).set_typ("JWT".to_string());

        let jws = if let Some(k) = kid {
            jws.set_kid(k.to_string())
        } else {
            jws
        };

        jws.sign_inner(signer, None, None)
            .map(|jwsc| OidcSigned { jwsc })
    }

    /// Use this private signer to created a signed oidc token.
    pub fn sign(&self, signer: &JwsSigner) -> Result<OidcSigned, JwtError> {
        self.sign_inner(signer, None)
    }

    /// set the key id (kid) into the header.
    /// use set_kid on jws.
    pub fn sign_with_kid(&self, signer: &JwsSigner, kid: &str) -> Result<OidcSigned, JwtError> {
        self.sign_inner(signer, Some(kid))
    }

    /*
    /// Use this private signer to created a signed oidc token, which contains the public
    /// key for verification embedded in the header of the token.
    pub fn sign_embed_public_jwk(&self, signer: &JwsSigner) -> Result<OidcSigned, JwtError> {
        let jwk = signer.public_key_as_jwk()?;
        self.sign_inner(signer, None, Some(jwk))
    }
    */
}

impl OidcUnverified {
    /// Using this JwsValidator, assert the correct signature of the data contained in
    /// this token. The current time is represented by seconds since the epoch. You may
    /// choose to ignore exp validation by setting this to 0, but this is DANGEROUS.
    pub fn validate(&self, validator: &JwsValidator, curtime: i64) -> Result<OidcToken, JwtError> {
        let released = self.jwsc.validate(validator)?;

        let tok: OidcToken =
            serde_json::from_slice(released.payload()).map_err(|_| JwtError::InvalidJwt)?;

        // Check the exp
        if tok.exp != 0 && tok.exp < curtime {
            Err(JwtError::OidcTokenExpired)
        } else {
            Ok(tok)
        }
    }

    /// Retrieve the Key ID used to sign this jwt, if any.
    pub fn get_jwk_kid(&self) -> Option<&str> {
        self.jwsc.get_jwk_kid()
    }

    /*
    /// Retrieve the URL which holds the public key used to sign this token if it exists
    /// in the JWS header.
    pub fn get_jwk_pubkey_url(&self) -> Option<&Url> {
        self.jwsc.get_jwk_pubkey_url()
    }

    /// Retrieve the public key used to sign this token if it exists in the JWS header.
    pub fn get_jwk_pubkey(&self) -> Option<&Jwk> {
        self.jwsc.get_jwk_pubkey()
    }
    */
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
    use super::{OidcSubject, OidcToken, OidcUnverified};
    use crate::crypto::{JwsSigner, JwsValidator};
    use std::convert::TryFrom;
    use std::str::FromStr;
    use url::Url;

    #[test]
    fn test_sign_and_validate() {
        let jwt = OidcToken {
            iss: Url::parse("https://oidc.example.com").unwrap(),
            sub: OidcSubject::S("a unique id".to_string()),
            aud: "test".to_string(),
            exp: 0,
            nbf: Some(0),
            iat: 0,
            auth_time: None,
            nonce: None,
            at_hash: None,
            acr: None,
            amr: None,
            azp: None,
            jti: None,
            s_claims: Default::default(),
            claims: Default::default(),
        };

        let jwss = JwsSigner::generate_es256().expect("failed to construct signer.");
        let pub_jwk = jwss.public_key_as_jwk(None).unwrap();
        let jws_validator = JwsValidator::try_from(&pub_jwk).expect("Unable to create validator");

        let jwts = jwt.sign(&jwss).expect("failed to sign jwt");

        let jwtu = jwts.invalidate();

        let released = jwtu
            .validate(&jws_validator, 0)
            .expect("Unable to validate jwt");

        assert!(released == jwt);
    }

    #[test]
    fn test_sign_and_validate_str() {
        let jwt = OidcToken {
            iss: Url::parse("https://oidc.example.com").unwrap(),
            sub: OidcSubject::S("a unique id".to_string()),
            aud: "test".to_string(),
            exp: 0,
            nbf: Some(0),
            iat: 0,
            auth_time: None,
            nonce: None,
            at_hash: None,
            acr: None,
            amr: None,
            azp: None,
            jti: None,
            s_claims: Default::default(),
            claims: Default::default(),
        };

        let jwss = JwsSigner::generate_es256().expect("failed to construct signer.");
        let pub_jwk = jwss.public_key_as_jwk(None).unwrap();
        let jws_validator = JwsValidator::try_from(&pub_jwk).expect("Unable to create validator");

        let jwts = jwt.sign(&jwss).expect("failed to sign jwt");

        let jwt_str = jwts.to_string();
        trace!("{}", jwt_str);
        let jwtu = OidcUnverified::from_str(&jwt_str).expect("Unable to parse jws/jwt");

        let released = jwtu
            .validate(&jws_validator, 0)
            .expect("Unable to validate jwt");

        assert!(released == jwt);
    }
}
