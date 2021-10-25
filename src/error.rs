//! Error types.

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Clone, Deserialize)]
/// An error in the JWT library
pub enum JwtError {
    /// Invalid Token - May not be in correct compact form
    InvalidCompactFormat,
    /// Invalid Base64 encodidng of the token content
    InvalidBase64,
    /// Invalid token header
    InvalidHeaderFormat,
    /// Invalid signature over the header and payload
    InvalidSignature,
    /// Invalid JWT content
    InvalidJwt,
    /// Invalid Critical Extension present
    CriticalExtension,
    /// OpenSSL failure
    OpenSSLError,
    /// Incorrect Algorithm for verification
    ValidatorAlgMismatch,
}
