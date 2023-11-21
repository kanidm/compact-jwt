//! JWS Signing and Verification Structures

use openssl::{hash, pkey, rsa, sign, x509};

use crate::error::JwtError;

use crate::compact::{JwaAlg, JwsCompact};
use crate::traits::*;

/// A builder for a verifier that will be rooted in a trusted ca chain.
#[derive(Default)]
pub struct JwsX509VerifierBuilder {
    kid: Option<String>,
    leaf: Option<x509::X509>,
    chain: Vec<x509::X509>,
    trust_roots: Vec<x509::X509>,
    #[cfg(test)]
    disable_time_checks: bool,
}

impl JwsX509VerifierBuilder {
    /// Create a new X509 Verifier Builder
    pub fn new() -> Self {
        JwsX509VerifierBuilder::default()
    }

    #[cfg(test)]
    pub fn set_kid(mut self, kid: Option<&str>) -> Self {
        self.kid = kid.map(|s| s.to_string());
        self
    }

    /// Add the CA trust roots that you trust to anchor signature chains.
    pub fn add_trust_root(mut self, root: x509::X509) -> Self {
        self.trust_roots.push(root);
        self
    }

    #[cfg(test)]
    pub(crate) fn yolo(mut self) -> Self {
        self.disable_time_checks = true;
        self
    }

    /// Add the full chain of certificates to this verifier. The expected
    /// Vec should start with the leaf certificate, and end with the root.
    ///
    /// By default, the x5c content of a Jws should have this in the correct
    /// order.
    pub fn add_fullchain(mut self, mut chain: Vec<x509::X509>) -> Self {
        // Normally the chains are leaf -> root. We need to reverse it
        // so we can pop from the right.
        chain.reverse();

        // Now we can pop() which gives us the leaf
        // If there is no leaf, we'll error in the build phase.
        self.leaf = chain.pop();
        self.chain = chain;
        self
    }

    /// Build this X509 Verifier.
    pub fn build(self) -> Result<JwsX509Verifier, JwtError> {
        use openssl::stack;
        use openssl::x509::store;

        let JwsX509VerifierBuilder {
            kid,
            leaf,
            mut chain,
            mut trust_roots,
            #[cfg(test)]
            disable_time_checks,
        } = self;

        let leaf = leaf.ok_or_else(|| {
            error!("No leaf certificate available in chain");
            JwtError::X5cChainMissingLeaf
        })?;

        // Now verify the whole thing back to the trust roots.

        // Convert the chain to a stackref for openssl.
        let mut chain_stack = stack::Stack::new().map_err(|ossl_err| {
            error!(?ossl_err);
            JwtError::OpenSSLError
        })?;

        while let Some(crt) = chain.pop() {
            chain_stack.push(crt).map_err(|ossl_err| {
                error!(?ossl_err);
                JwtError::OpenSSLError
            })?;
        }

        // Setup a CA store we plan to verify against.
        let mut ca_store = store::X509StoreBuilder::new().map_err(|ossl_err| {
            error!(?ossl_err);
            JwtError::OpenSSLError
        })?;

        while let Some(ca_crt) = trust_roots.pop() {
            ca_store.add_cert(ca_crt).map_err(|ossl_err| {
                error!(?ossl_err);
                JwtError::OpenSSLError
            })?;
        }

        #[cfg(test)]
        if disable_time_checks {
            ca_store
                .set_flags(x509::verify::X509VerifyFlags::NO_CHECK_TIME)
                .map_err(|ossl_err| {
                    error!(?ossl_err);
                    JwtError::OpenSSLError
                })?;
        }

        let ca_store = ca_store.build();

        let mut ca_ctx = x509::X509StoreContext::new().map_err(|ossl_err| {
            error!(?ossl_err);
            JwtError::OpenSSLError
        })?;

        let out = ca_ctx
            .init(&ca_store, &leaf, &chain_stack, |ca_ctx_ref| {
                ca_ctx_ref.verify_cert().map(|_| {
                    let verify_cert_result = ca_ctx_ref.error();
                    trace!(?verify_cert_result);
                    if verify_cert_result == x509::X509VerifyResult::OK {
                        Ok(())
                    } else {
                        error!(
                            "ca_ctx_ref verify cert - error depth={}, sn={:?}",
                            ca_ctx_ref.error_depth(),
                            ca_ctx_ref.current_cert().map(|crt| crt.subject_name())
                        );
                        Err(JwtError::X5cChainNotTrusted)
                    }
                })
            })
            .map_err(|ossl_err| {
                error!(?ossl_err);
                JwtError::OpenSSLError
            })?;

        trace!(?out);

        out.map(|()| JwsX509Verifier { kid, pkey: leaf })
    }
}

/// A verifier for a Jws that is trusted by a certificate chain. This verifier represents the leaf
/// certificate that will be used to verify a Jws.
///
/// If you have multiple trust roots and chains, you will need to build this verifier for each
/// Jws that you need to validate since this type verifies a single leaf.
pub struct JwsX509Verifier {
    /// The KID of this validator
    kid: Option<String>,
    /// Public Key
    pkey: x509::X509,
}

impl JwsVerifier for JwsX509Verifier {
    fn get_kid(&mut self) -> Option<&str> {
        self.kid.as_deref()
    }

    fn verify<V: JwsVerifiable>(&self, jwsc: &V) -> Result<V::Verified, JwtError> {
        let signed_data = jwsc.data();

        let pkey = self.pkey.public_key().map_err(|e| {
            debug!(?e);
            JwtError::OpenSSLError
        })?;

        // Okay, the cert is valid, lets do this.
        let digest = match (signed_data.header.alg, pkey.id()) {
            (JwaAlg::RS256, pkey::Id::RSA) | (JwaAlg::ES256, pkey::Id::EC) => {
                Ok(hash::MessageDigest::sha256())
            }
            _ => {
                debug!(jwsc_alg = ?signed_data.header.alg, "validator algorithm mismatch");
                return Err(JwtError::ValidatorAlgMismatch);
            }
        }?;

        let mut verifier = sign::Verifier::new(digest, &pkey).map_err(|e| {
            debug!(?e);
            JwtError::OpenSSLError
        })?;

        if signed_data.header.alg == JwaAlg::RS256 {
            verifier.set_rsa_padding(rsa::Padding::PKCS1).map_err(|e| {
                debug!(?e);
                JwtError::OpenSSLError
            })?;
        }

        verifier
            .update(signed_data.hdr_bytes)
            .and_then(|_| verifier.update(".".as_bytes()))
            .and_then(|_| verifier.update(signed_data.payload_bytes))
            .map_err(|e| {
                debug!(?e);
                JwtError::OpenSSLError
            })?;

        let valid = verifier.verify(&signed_data.signature_bytes).map_err(|e| {
            debug!(?e);
            JwtError::OpenSSLError
        })?;

        if valid {
            signed_data.release().and_then(|d| jwsc.post_process(d))
        } else {
            debug!("invalid signature");
            Err(JwtError::InvalidSignature)
        }
    }
}
