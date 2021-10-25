use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Clone, Deserialize)]
pub enum JwtError {
    InvalidCompactFormat,
    InvalidBase64,
    InvalidHeaderFormat,
    InvalidSignature,
    InvalidJwt,
    CriticalExtension,
    OpenSSLError,
    ValidatorAlgMismatch,
}
