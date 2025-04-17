//! JWS Signing and Verification Structures

use crate::compact::JwaAlg;
use crate::error::JwtError;
use crate::traits::*;

use crypto_glue::x509::chain::X509Store;
use crypto_glue::x509::Certificate;

/// A builder for a verifier that will be rooted in a trusted ca chain.
pub struct JwsX509VerifierBuilder {
    kid: Option<String>,
    leaf: Certificate,
    chain: Vec<Certificate>,
    trust_roots: Vec<Certificate>,
}

impl JwsX509VerifierBuilder {
    /// Create a new X509 Verifier Builder. You must pass in the fullchain
    pub fn new(
        leaf: &Certificate,
        chain: &[Certificate],
    ) -> Self {
        JwsX509VerifierBuilder {
            kid: None,
            leaf: leaf.clone(),
            chain: chain.iter().cloned().collect(),
            trust_roots: Vec::new(),
        }
    }

    #[cfg(test)]
    /// Test only function
    pub fn set_kid(mut self, kid: Option<&str>) -> Self {
        self.kid = kid.map(|s| s.to_string());
        self
    }

    /// Add the CA trust roots that you trust to anchor signature chains.
    pub fn add_trust_root(mut self, ca_root: Certificate) -> Self {
        self.trust_roots.push(ca_root);
        self
    }

    /// Build this X509 Verifier.
    pub fn build(self, current_time: SystemTime) -> Result<JwsX509Verifier, JwtError> {

        let store = X509Store::new(
            self.trust_roots.as_slice()
        );

        ca_store.verify(&self.leaf, &self.chain, current_time)
            .map_err(|err| {
                error!(?err, "error during chain verification");
                JwtError::X5cChainNotTrusted
            })?;

        Ok(JwsX509Verifier { kid, pkey: self.leaf })
    }
}

/// A verifier for a Jws that is trusted by a certificate chain. This verifier represents the leaf
/// certificate that will be used to verify a Jws.
///
/// If you have multiple trust roots and chains, you will need to build this verifier for each
/// Jws that you need to validate since this type verifies a single leaf.
pub struct JwsX509Verifier {
    /// The KID of this validator
    kid: String,
    /// Public Key
    pkey: Certificate,
}

impl JwsX509Verifier {
    /// Create a new Jws Verifier directly from an x509 certificate. Note that this bypasses
    /// any verification of the trust chain in the x5c attribute. If possible, you should use
    /// [JwsX509VerifierBuilder] instead.
    pub fn from_x509(certificate: Certificate) -> Result<Self, JwtError> {
        // let kid = pkey

        Ok(JwsX509Verifier { kid, pkey })
    }
}

impl JwsVerifier for JwsX509Verifier {
    fn get_kid(&self) -> &str {
        &self.kid
    }

    fn verify<V: JwsVerifiable>(&self, jwsc: &V) -> Result<V::Verified, JwtError> {
        let signed_data = jwsc.data();

        verifier
            .update(signed_data.hdr_bytes)
            .and_then(|_| verifier.update(".".as_bytes()))
            .and_then(|_| verifier.update(signed_data.payload_bytes))
            .map_err(|e| {
                debug!(?e);
                JwtError::OpenSSLError
            })?;



        let valid = verifier.verify(signed_data.signature_bytes).map_err(|e| {
            debug!(?e);
            JwtError::OpenSSLError
        })?;

        if valid {
        } else {
            debug!("invalid signature");
            Err(JwtError::InvalidSignature)
        }

        let subject_public_key_info = self.leaf
            .tbs_certificate
            .subject_public_key_info
            .owned_to_ref();

        match certificate.tbs_certificate.signature.oid {
            oiddb::rfc5912::ECDSA_WITH_SHA_256 => {
                let signature = EcdsaP256DerSignature::try_from(signature)
                    .map_err(|_err| X509VerificationError::DerSignatureInvalid)?;

                let verifier = EcdsaP256PublicKey::try_from(subject_public_key_info)
                    .map(EcdsaP256VerifyingKey::from)
                    .map_err(|_err| X509VerificationError::VerifyingKeyFromSpki)?;

                verifier
                    .verify(data, &signature)
                    .map_err(|_err| X509VerificationError::SignatureVerificationFailed)?;
            }
            oiddb::rfc5912::SHA_256_WITH_RSA_ENCRYPTION => {
                let signature = RS256Signature::try_from(signature)
                    .map_err(|_err| X509VerificationError::DerSignatureInvalid)?;

                let verifier = RS256PublicKey::try_from(subject_public_key_info)
                    .map(RS256VerifyingKey::new)
                    .map_err(|_err| X509VerificationError::VerifyingKeyFromSpki)?;

                verifier
                    .verify(data, &signature)
                    .map_err(|_err| X509VerificationError::SignatureVerificationFailed)?;
            }
            algo_oid => {
                error!(?algo_oid);
                return Err(X509VerificationError::SignatureAlgorithmNotImplemented);
            }
        };

        signed_data.release().and_then(|d| jwsc.post_process(d))
    }
}
