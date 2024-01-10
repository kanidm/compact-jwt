//! Traits that define behaviour of JWS signing and verification types.

use crate::compact::{JweCompact, JweProtectedHeader};
use crate::compact::{JwsCompact, JwsCompactVerifyData, ProtectedHeader};
use crate::error::JwtError;
use crate::jwe::Jwe;
use crate::jws::{Jws, JwsCompactSign2Data};

/// A trait defining how a JwsSigner will operate.
///
/// Note that due to the design of this api, you can NOT define your own signer.
pub trait JwsSigner {
    /// Get the key id from this signer
    fn get_kid(&self) -> &str;

    /// Update thee content of the header with signer specific data
    fn update_header(&self, header: &mut ProtectedHeader) -> Result<(), JwtError>;

    /// Perform the signature operation
    fn sign<V: JwsSignable>(&self, _jws: &V) -> Result<V::Signed, JwtError>;
}

/// A trait defining how a JwsSigner will operate.
///
/// Note that due to the design of this api, you can NOT define your own signer.
pub trait JwsMutSigner {
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
    fn get_verifier(&self) -> Result<Self::Verifier, JwtError>;
}

/// A trait defining how a JwsVerifier will operate.
///
/// Note that due to the design of this api, you can NOT define your own verifier.
pub trait JwsVerifier {
    /// Get the key id from this verifier
    fn get_kid(&self) -> Option<&str>;

    /// Perform the signature verification
    fn verify<V: JwsVerifiable>(&self, _jwsc: &V) -> Result<V::Verified, JwtError>;
}

/// A trait defining how a JwsVerifier will operate.
///
/// Note that due to the design of this api, you can NOT define your own verifier.
pub trait JwsMutVerifier {
    /// Get the key id from this verifier
    fn get_kid(&mut self) -> Option<&str>;

    /// Perform the signature verification
    fn verify<V: JwsVerifiable>(&mut self, _jwsc: &V) -> Result<V::Verified, JwtError>;
}

/// A trait defining types that can be verified by a [JwsVerifier]
pub trait JwsVerifiable {
    /// The type that should be emitted when the verification is complete
    type Verified;

    /// Retrieve the inner data from the JwsCompact that is to be verified
    fn data(&self) -> JwsCompactVerifyData<'_>;

    /// After the verification is complete, allow post-processing of the released payload
    fn post_process(&self, value: Jws) -> Result<Self::Verified, JwtError>;
}

/// A trait defining types that can be signed by a [JwsSigner]
pub trait JwsSignable {
    /// The type that should be emitted when the signature is completed
    type Signed;

    /// Retrieve the inner data from the Jws that is to be signed.
    fn data(&self) -> Result<JwsCompactSign2Data, JwtError>;

    /// After the signature is complete, allow post-processing of the compact jws
    fn post_process(&self, value: JwsCompact) -> Result<Self::Signed, JwtError>;
}

/// A trait defining types that provide outer content encryption key wrapping.
pub trait JweEncipherOuter {
    /// Given a protected header, set the algorithm used by this outer key wrap
    fn set_header_alg(&self, hdr: &mut JweProtectedHeader) -> Result<(), JwtError>;

    /// Wrap the provided ephemeral key
    fn wrap_key(&self, key_to_wrap: &[u8]) -> Result<Vec<u8>, JwtError>;
}

/// A marker trait indicating that this type uses 128 bit keys.
pub trait JweEncipherInnerK128 {}

/// A marker trait indicating that this type uses 256 bit keys.
pub trait JweEncipherInnerK256 {}

/// A trait defining types that provide inner content encryption
pub trait JweEncipherInner {
    /// Generate a new ephemeral key for this inner encipher. Keys are always
    /// ephemeral with inner types as they are "one use" only.
    fn new_ephemeral() -> Result<Self, JwtError>
    where
        Self: Sized;

    /// Encipher the inner content of a jwe
    fn encipher_inner<O: JweEncipherOuter>(
        &self,
        outer: &O,
        jwe: &Jwe,
    ) -> Result<JweCompact, JwtError>;
}
