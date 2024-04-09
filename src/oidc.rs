//! Oidc token implementation

use crate::compact::{JwaAlg, Jwk, JwsCompact, JwsCompactVerifyData};
use crate::jws::{Jws, JwsCompactSign2Data, JwsSigned};

use crate::traits::{JwsSignable, JwsVerifiable};

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

/// An verified token that is awaiting expiry verification
pub struct OidcExpUnverified {
    oidc: OidcToken,
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

impl JwsSignable for OidcToken {
    type Signed = OidcSigned;

    fn data(&self) -> Result<JwsCompactSign2Data, JwtError> {
        let mut jwts = Jws::into_json(self).map_err(|_| JwtError::InvalidJwt)?;

        jwts.set_typ(Some("JWT"));

        jwts.data()
    }

    fn post_process(&self, jwsc: JwsCompact) -> Result<Self::Signed, JwtError> {
        Ok(OidcSigned {
            jws: JwsSigned { jwsc },
        })
    }
}

impl OidcUnverified {
    /// Get the embedded public key used to sign this jwt, if present.
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

impl JwsVerifiable for OidcUnverified {
    type Verified = OidcExpUnverified;

    fn data(&self) -> JwsCompactVerifyData<'_> {
        self.jwsc.data()
    }

    fn alg(&self) -> JwaAlg {
        self.jwsc.alg()
    }

    fn kid(&self) -> Option<&str> {
        self.jwsc.kid()
    }

    fn post_process(&self, value: Jws) -> Result<Self::Verified, JwtError> {
        let oidc: OidcToken = value.from_json().map_err(|_| JwtError::InvalidJwt)?;
        Ok(OidcExpUnverified { oidc })
    }
}

impl OidcExpUnverified {
    /// Verify the expiry of this OIDC Token. The token at this point has passed cryptographic
    /// verification, and should have it's expiry validated.
    ///
    /// curtime represents the current time in seconds since the unix epoch.
    ///
    /// A curtime of `0` means that the exp will not be checked. This is not recommended.
    pub fn verify_exp(self, curtime: i64) -> Result<OidcToken, JwtError> {
        if self.oidc.exp != 0 && self.oidc.exp < curtime {
            Err(JwtError::OidcTokenExpired)
        } else {
            Ok(self.oidc)
        }
    }
}

impl OidcSigned {
    /// Invalidate this signed oidc token, causing it to require validation before you can use it
    /// again.
    pub fn invalidate(self) -> OidcUnverified {
        OidcUnverified {
            jwsc: self.jws.jwsc,
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
    use super::{OidcSubject, OidcToken};
    use crate::crypto::JwsEs256Signer;
    use crate::traits::{JwsSigner, JwsSignerToVerifier, JwsVerifier};
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

        let jws_es256_signer =
            JwsEs256Signer::generate_es256().expect("failed to construct signer.");
        let jwk_es256_verifier = jws_es256_signer
            .get_verifier()
            .expect("failed to get verifier from signer");

        let jwts = jws_es256_signer.sign(&jwt).expect("failed to sign jwt");

        let jwtu = jwts.invalidate();

        let released = jwk_es256_verifier
            .verify(&jwtu)
            .expect("Unable to validate jwt")
            .verify_exp(0)
            .expect("Unable to validate oidc exp");

        assert!(released == jwt);
    }
}
