// #![deny(warnings)]
// #![warn(unused_extern_crates)]
// #![warn(missing_docs)]

#![forbid(unsafe_code)]

//! Json Web Tokens (JWT) are a popular method for creating signed transparent tokens that can be verified
//! by clients and servers. They are enshrined in standards like OpenID Connect which causes them to
//! be a widespread and required component of many modern web authentication system.
//!
//! This is a minimal implementation of JWTs and Oidc Tokens that aims for auditability and correctness.
//!
//! # Examples
//! ```
//! # #[cfg(feature = "openssl")]
//! # {
//! use std::str::FromStr;
//! use std::convert::TryFrom;
//! use std::time::SystemTime;
//! use url::Url;
//! use compact_jwt::{JwsValidatorEnum, JwsSignerEnum, OidcToken, OidcSubject, OidcUnverified};
//!
//! let oidc = OidcToken {
//!         iss: Url::parse("https://oidc.example.com").unwrap(),
//!         sub: OidcSubject::S("UniqueId".to_string()),
//! #       aud: "test".to_string(),
//! #       exp: 0,
//! #       nbf: Some(0),
//! #       iat: 0,
//! #       auth_time: Some(0),
//! #       nonce: None,
//! #       at_hash: None,
//! #       acr: None,
//! #       amr: None,
//! #       azp: None,
//! #       jti: None,
//! #       s_claims: Default::default(),
//! #       claims: Default::default(),
//!     };
//!
//! let jws_signer = JwsSignerEnum::generate_es256()
//!     .unwrap();
//!
//! let oidc_signed = oidc.sign(&jws_signer)
//!     .unwrap();
//!
//! // Get the signed formatted token string
//! let token_str = oidc_signed.to_string();
//!
//! // Build a validator from the public key of the signer. In a client scenario
//! // you would get this public jwk from the oidc authorisation server.
//! let public_jwk = jws_signer.public_key_as_jwk()
//!     .unwrap();
//! let jws_validator = JwsValidatorEnum::try_from(&public_jwk)
//!     .unwrap();
//!
//! // Assuming we have the token_str, start to validate it.
//! let oidc_unverified = OidcUnverified::from_str(&token_str)
//!     .unwrap();
//!
//! let curtime = SystemTime::now()
//!     .duration_since(SystemTime::UNIX_EPOCH)
//!     .expect("Failed to retrieve current time")
//!     .as_secs() as i64;
//!
//! let oidc_validated = oidc_unverified
//!     .validate(&jws_validator, curtime)
//!     .unwrap();
//!
//! // Prove we got back the same content.
//! assert!(oidc_validated == oidc);
//! # }
//! ```

#[allow(unused_imports)]
#[macro_use]
extern crate tracing;

#[cfg(feature = "openssl")]
pub mod crypto;

#[cfg(feature = "unsafe_release_without_verify")]
pub mod dangernoverify;

pub mod compact;

pub mod traits;

pub mod error;
pub mod jws;
pub mod jwt;
pub mod oidc;

// pub use crate::compact::{JwaAlg, Jwk, JwkKeySet, JwkUse};
// pub use crate::error::JwtError;
// pub use crate::jws::{Jws, JwsSigned, JwsUnverified};
// pub use crate::jwt::{Jwt, JwtSigned, JwtUnverified};
// pub use crate::oidc::{OidcClaims, OidcSigned, OidcSubject, OidcToken, OidcUnverified};

pub(crate) fn btreemap_empty(
    m: &std::collections::BTreeMap<String, serde_json::value::Value>,
) -> bool {
    m.is_empty()
}

pub(crate) fn vec_empty(m: &[String]) -> bool {
    m.is_empty()
}
