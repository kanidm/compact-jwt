#![deny(warnings)]
#![warn(unused_extern_crates)]
#![warn(missing_docs)]
#![forbid(unsafe_code)]

//! Json Web Tokens (JWT) are a popular method for creating signed transparent tokens that can be verified
//! by clients and servers. They are enshrined in standards like OpenID Connect which causes them to
//! be a widespread and required component of many modern web authentication system.
//!
//! This is a minimal implementation of JWTs and Oidc Tokens that aims for auditability and correctness.

pub mod base64_data;
pub mod crypto;
pub mod error;
pub mod jwt;
pub mod oidc;

pub use crate::crypto::{Jwk, JwsSigner, JwsValidator};
pub use crate::jwt::{Jwt, JwtSigned, JwtUnverified};
pub use crate::oidc::{OidcSigned, OidcToken, OidcUnverified};

pub(crate) fn btreemap_empty(
    m: &std::collections::BTreeMap<String, serde_json::value::Value>,
) -> bool {
    m.is_empty()
}
