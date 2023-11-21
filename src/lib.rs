// #![deny(warnings)]
// #![warn(unused_extern_crates)]
// #![warn(missing_docs)]

#![forbid(unsafe_code)]
// Enable some groups of clippy lints.
#![deny(clippy::suspicious)]
#![deny(clippy::perf)]
// Specific lints to enforce.
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::trivially_copy_pass_by_ref)]
#![deny(clippy::disallowed_types)]
#![deny(clippy::manual_let_else)]
#![allow(clippy::unreachable)]

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
//! use compact_jwt::{
//!     OidcToken,
//!     OidcSubject,
//!     OidcUnverified,
//!     JwsEs256Signer,
//!     // Traits
//!     JwsSigner,
//!     JwsSignerToVerifier,
//!     JwsVerifier,
//! };
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
//! let mut jws_es256_signer =
//!     JwsEs256Signer::generate_es256().unwrap();
//!
//! let oidc_signed = jws_es256_signer.sign2(&oidc)
//!     .unwrap();
//!
//! // Get the signed formatted token string
//! let token_str = oidc_signed.to_string();
//!
//! // Build a validator from the public key of the signer. In a client scenario
//! // you would get this public jwk from the oidc authorisation server.
//! let mut jwk_es256_verifier = jws_es256_signer
//!     .get_verifier()
//!     .expect("failed to get verifier from signer");
//!
//! // Assuming we have the token_str, we parse it to an unverified state.
//! let oidc_unverified = OidcUnverified::from_str(&token_str)
//!     .unwrap();
//!
//! let curtime = SystemTime::now()
//!     .duration_since(SystemTime::UNIX_EPOCH)
//!     .expect("Failed to retrieve current time")
//!     .as_secs() as i64;
//!
//! let oidc_validated = jwk_es256_verifier
//!     .verify(&oidc_unverified)
//!     .and_then(|oidc_exp| oidc_exp.verify_exp(curtime))
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

#[cfg(feature = "openssl")]
pub use crate::crypto::{JwsEs256Signer, JwsEs256Verifier, JwsHs256Signer};

pub use crate::compact::{JwaAlg, Jwk, JwsCompact};
pub use crate::error::JwtError;
pub use crate::jws::{Jws, JwsSigned};
pub use crate::jwt::{Jwt, JwtSigned, JwtUnverified};
pub use crate::oidc::{OidcClaims, OidcSigned, OidcSubject, OidcToken, OidcUnverified};

pub use crate::traits::{JwsSigner, JwsSignerToVerifier, JwsVerifier};

pub(crate) fn btreemap_empty(
    m: &std::collections::BTreeMap<String, serde_json::value::Value>,
) -> bool {
    m.is_empty()
}

pub(crate) fn vec_empty(m: &[String]) -> bool {
    m.is_empty()
}
