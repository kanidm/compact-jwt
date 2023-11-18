//! Traits that define behaviour of JWS signing and verification types.

use crate::compact::{JwsCompact, ProtectedHeader};
use crate::error::JwtError;

/// Data that will be signed
pub struct JwsCompactSignData<'a> {
    pub(crate) hdr_bytes: &'a [u8],
    pub(crate) payload_bytes: &'a [u8],
}

/// A trait defining how a JwsSigner will operate.
///
/// Note that due to the design of this api, you can NOT defined your own.
pub trait JwsSigner {
    /// Get the key id from this signer
    fn get_kid(&mut self) -> &str;

    /// Update thee content of the header with signer specific data
    fn update_header(&mut self, header: &mut ProtectedHeader) -> Result<(), JwtError>;

    /// Perform the signature operation
    fn sign(&mut self, jwsc: JwsCompactSignData<'_>) -> Result<Vec<u8>, JwtError>;
}

/// A trait allowing a signer to create it's corresponding verifier.
///
/// Note that due to the design of this api, you can NOT defined your own.
pub trait JwsSignerToVerifier {
    /// The associated verifier
    type Verifier;

    /// Retrieve the verifier corresponding to this signer
    fn get_verifier(&mut self) -> Result<Self::Verifier, JwtError>;
}

/// A trait defining how a JwsVerifier will operate.
///
/// Note that due to the design of this api, you can NOT defined your own.
pub trait JwsVerifier {
    /// Get the key id from this verifier
    fn get_kid(&mut self) -> Option<&str>;

    /// Perform the signature verification
    fn verify_signature(&mut self, jwsc: &JwsCompact) -> Result<bool, JwtError>;
}
