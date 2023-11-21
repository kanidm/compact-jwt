//! Traits that define behaviour of JWS signing and verification types.

use crate::compact::{JwsCompact, JwsCompactVerifyData, ProtectedHeader};
use crate::error::JwtError;
use crate::jws::{Jws, JwsCompactSign2Data};

/// Data that will be signed
pub struct JwsCompactSignData<'a> {
    pub(crate) hdr_bytes: &'a [u8],
    pub(crate) payload_bytes: &'a [u8],
}

/// A trait defining how a JwsSigner will operate.
///
/// Note that due to the design of this api, you can NOT define your own signer.
pub trait JwsSigner {
    /// Get the key id from this signer
    fn get_kid(&mut self) -> &str;

    /// Update thee content of the header with signer specific data
    fn update_header(&mut self, header: &mut ProtectedHeader) -> Result<(), JwtError>;

    /// Perform the signature operation
    fn sign<V: JwsSignable>(&mut self, _jws: &V) -> Result<V::Signed, JwtError>;
}

/// A trait allowing a signer to create it's corresponding verifier.
///
/// Note that due to the design of this api, you can NOT define your own signer or verifier.
pub trait JwsSignerToVerifier {
    /// The associated verifier
    type Verifier;

    /// Retrieve the verifier corresponding to this signer
    fn get_verifier(&mut self) -> Result<Self::Verifier, JwtError>;
}

/// A trait defining how a JwsVerifier will operate.
///
/// Note that due to the design of this api, you can NOT define your own verifier.
pub trait JwsVerifier {
    /// Get the key id from this verifier
    fn get_kid(&mut self) -> Option<&str>;

    /// Perform the signature verification
    fn verify<V: JwsVerifiable>(&self, _jwsc: &V) -> Result<V::Verified, JwtError>;
}

pub trait JwsVerifiable {
    type Verified;

    fn data<'a>(&'a self) -> JwsCompactVerifyData<'a>;

    fn post_process(&self, value: Jws) -> Result<Self::Verified, JwtError>;
}

pub trait JwsSignable {
    type Signed;

    fn data(&self) -> Result<JwsCompactSign2Data, JwtError>;

    fn post_process(&self, value: JwsCompact) -> Result<Self::Signed, JwtError>;
}
