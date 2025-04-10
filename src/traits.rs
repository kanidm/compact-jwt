//! Traits that define behaviour of JWS signing and verification types.

use crate::compact::{JwaAlg, JweCompact, JweProtectedHeader};
use crate::compact::{JwsCompact, JwsCompactVerifyData, ProtectedHeader};
use crate::error::JwtError;
use crate::jwe::Jwe;
use crate::jws::{Jws, JwsCompactSign2Data};
use crypto_glue::aes256::Aes256Key;

/// A trait defining how a JwsSigner will operate.
///
/// Note that due to the design of this api, you can NOT define your own signer.
pub trait JwsSigner {
    /// Get the key id from this signer
    fn get_kid(&self) -> &str;

    /// Get the legacy format key id from this signer. This value will be removed
    /// in a future release.
    fn get_legacy_kid(&self) -> &str {
        "no legacy kid"
    }

    /// Update thee content of the header with signer specific data
    fn update_header(&self, header: &mut ProtectedHeader) -> Result<(), JwtError>;

    /// Perform the signature operation
    fn sign<V: JwsSignable>(&self, _jws: &V) -> Result<V::Signed, JwtError>;

    /// Enable or disable embedding the KID in the Jws header
    fn set_sign_option_embed_kid(&self, value: bool) -> Self;
}

/// A trait defining how a JwsSigner will operate.
///
/// Note that due to the design of this api, you can NOT define your own signer.
pub trait JwsMutSigner {
    /// Get the key id from this signer
    fn get_kid(&mut self) -> &str;

    /// Get the legacy format key id from this signer. This value will be removed
    /// in a future release.
    fn get_legacy_kid(&mut self) -> &str {
        "no legacy kid"
    }

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
    fn get_kid(&self) -> &str;

    /// Perform the signature verification
    fn verify<V: JwsVerifiable>(&self, _jwsc: &V) -> Result<V::Verified, JwtError>;
}

/// A trait defining types that can be verified by a [JwsVerifier]
pub trait JwsVerifiable {
    /// The type that should be emitted when the verification is complete
    type Verified;

    /// Retrieve the inner data from the JwsCompact that is to be verified
    fn data(&self) -> JwsCompactVerifyData<'_>;

    /// Access the algorithm that was used to sign this JWS
    fn alg(&self) -> JwaAlg;

    /// Access the optional Key ID that signed this JWS
    fn kid(&self) -> Option<&str>;

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

/// A trait defining types that provide outer content encryption key wrapping supporting
/// AES256 Keys used for the inner encryption
pub trait JweEncipherOuterA256 {
    /// Given a protected header, set the algorithm used by this outer key wrap
    fn set_header_alg(&self, hdr: &mut JweProtectedHeader) -> Result<(), JwtError>;

    /// Wrap the provided ephemeral key
    fn wrap_key(&self, wrapping_key: Aes256Key) -> Result<Vec<u8>, JwtError>;
}

/// A trait defining types that provide inner content encryption with AES256 Keys
pub trait JweEncipherInnerA256 {
    /// Generate a new ephemeral key for this inner encipher. Keys are always
    /// ephemeral with inner types as they are "one use" only.
    fn new_ephemeral() -> Result<Self, JwtError>
    where
        Self: Sized;

    /// Encipher the inner content of a jwe
    fn encipher_inner<O: JweEncipherOuterA256>(
        &self,
        outer: &O,
        jwe: &Jwe,
    ) -> Result<JweCompact, JwtError>;
}
