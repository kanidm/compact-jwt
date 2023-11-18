//! Oidc token implementation

use crate::compact::{Jwk, JwsCompact};
use crate::jws::{Jws, JwsSigned, JwsUnverified};

use crate::traits::{JwsSigner, JwsVerifier};

use crate::error::JwtError;
use crate::{btreemap_empty, vec_empty};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;
use url::Url;
use uuid::Uuid;

/// An unverified token input which is ready to validate
pub struct OidcUnverified {
    jws: JwsUnverified,
}

/// A signed oidc token which can be converted to a string.
pub struct OidcSigned {
    jws: JwsSigned,
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
    #[serde(skip_serializing_if = "Option::is_none")]
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

#[cfg(feature = "openssl")]
impl OidcToken {
    pub fn sign<S: JwsSigner>(&self, signer: &mut S) -> Result<OidcSigned, JwtError> {
        let jwts = Jws::into_json(self).map_err(|_| JwtError::InvalidJwt)?;

        jwts.sign(signer).map(|jwsc| OidcSigned {
            jws: JwsSigned { jwsc },
        })
    }
}

impl OidcUnverified {
    /// Using this JwsVerifier, assert the correct signature of the data contained in
    /// this token. The current time is represented by seconds since the epoch. You may
    /// choose to ignore exp validation by setting this to 0, but this is DANGEROUS.
    pub fn verify<K>(&self, verifier: &mut K, curtime: i64) -> Result<OidcToken, JwtError>
    where
        K: JwsVerifier,
    {
        let jws = self.jws.verify(verifier)?;

        let tok: OidcToken = jws.from_json().map_err(|_| JwtError::InvalidJwt)?;

        // Check the exp
        if tok.exp != 0 && tok.exp < curtime {
            Err(JwtError::OidcTokenExpired)
        } else {
            Ok(tok)
        }
    }
}

impl OidcUnverified {
    /// Get the embedded public key used to sign this jwt, if present.
    pub fn get_jwk_pubkey(&self) -> Option<&Jwk> {
        self.jws.get_jwk_pubkey()
    }

    /// Get the KID used to sign this Jws if present
    pub fn get_jwk_kid(&self) -> Option<&str> {
        self.jws.get_jwk_kid()
    }
}

impl FromStr for OidcUnverified {
    type Err = JwtError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        JwsCompact::from_str(s).map(|jwsc| OidcUnverified {
            jws: JwsUnverified { jwsc },
        })
    }
}

impl OidcSigned {
    /// Invalidate this signed oidc token, causing it to require validation before you can use it
    /// again.
    pub fn invalidate(self) -> OidcUnverified {
        OidcUnverified {
            jws: self.jws.invalidate(),
        }
    }
}

impl fmt::Display for OidcSigned {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.jws.fmt(f)
    }
}

#[cfg(all(feature = "openssl", test))]
mod tests {
    use super::{OidcSubject, OidcToken, OidcUnverified};
    use crate::crypto::JwsEs256Signer;
    use crate::traits::{JwsSigner, JwsSignerToVerifier, JwsVerifier};
    use std::convert::TryFrom;
    use std::str::FromStr;
    use url::Url;

    #[test]
    fn test_sign_and_validate() {
        let _ = tracing_subscriber::fmt::try_init();
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

        let mut jws_es256_signer =
            JwsEs256Signer::generate_es256().expect("failed to construct signer.");
        let mut jwk_es256_verifier = jws_es256_signer
            .get_verifier()
            .expect("failed to get verifier from signer");

        let jwts = jwt.sign(&mut jws_es256_signer).expect("failed to sign jwt");

        let jwtu = jwts.invalidate();

        let released = jwtu
            .verify(&mut jwk_es256_verifier, 0)
            .expect("Unable to validate jwt");

        assert!(released == jwt);
    }
}
