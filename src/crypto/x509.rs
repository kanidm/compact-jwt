//! JWS Signing and Verification Structures

// use crate::compact::JwaAlg;

use crate::compact::ProtectedHeader;
use crate::error::JwtError;
use crate::traits::*;
use crate::{JwsCompact, KID_LEN};
use base64::engine::general_purpose;
use base64::Engine;
use crypto_glue::{
    ecdsa_p384::{EcdsaP384Digest, EcdsaP384PrivateKey, EcdsaP384Signature, EcdsaP384SigningKey},
    s256,
    traits::{Digest, DigestSigner, EncodeDer, SignatureEncoding},
    x509::{x509_verify_signature, Certificate, SubjectKeyIdentifier, X509Store},
};
use std::time::SystemTime;

/// A builder for a verifier that will be rooted in a trusted ca chain.
pub struct JwsX509VerifierBuilder {
    kid: Option<String>,
    leaf: Certificate,
    chain: Vec<Certificate>,
    trust_roots: Vec<Certificate>,
}

impl JwsX509VerifierBuilder {
    /// Create a new X509 Verifier Builder. You must pass in the fullchain
    pub fn new(leaf: &Certificate, chain: &[Certificate]) -> Self {
        JwsX509VerifierBuilder {
            kid: None,
            leaf: leaf.clone(),
            chain: chain.to_vec(),
            trust_roots: Vec::new(),
        }
    }

    #[cfg(test)]
    /// Set the KID to use for this verifier.
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
        let ca_store = X509Store::new(self.trust_roots.as_slice());

        ca_store
            .verify(&self.leaf, self.chain.as_slice(), current_time)
            .map_err(|err| {
                error!(?err, "error during chain verification");
                JwtError::X5cChainNotTrusted
            })?;

        let kid = self.kid.unwrap_or_else(|| certificate_to_kid(&self.leaf));

        Ok(JwsX509Verifier {
            kid,
            pkey: self.leaf,
        })
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
        let kid = certificate_to_kid(&certificate);

        Ok(JwsX509Verifier {
            kid,
            pkey: certificate,
        })
    }
}

impl JwsVerifier for JwsX509Verifier {
    fn get_kid(&self) -> &str {
        &self.kid
    }

    fn verify<V: JwsVerifiable>(&self, jwsc: &V) -> Result<V::Verified, JwtError> {
        let signed_data = jwsc.data();

        let data = signed_data
            .hdr_bytes
            .iter()
            .chain(b".".iter())
            .chain(signed_data.payload_bytes.iter())
            .copied()
            .collect::<Vec<u8>>();

        x509_verify_signature(&data, signed_data.signature_bytes, &self.pkey).map_err(|err| {
            debug!(?err, "invalid signature");
            JwtError::InvalidSignature
        })?;

        signed_data.release().and_then(|d| jwsc.post_process(d))
    }
}

/// A builder for a verifier that will be rooted in a trusted ca chain.
#[derive(Clone)]
pub struct JwsX509Signer<K> {
    kid: String,
    signer: K,
    leaf: Certificate,
    chain: Vec<Certificate>,
}

impl<K> JwsX509Signer<K> {
    /// Create a new X509 JWS Signer using this Key and Certificate.
    pub fn new(signer: K, leaf: &Certificate, chain: &[Certificate]) -> Self {
        let kid = certificate_to_kid(leaf);

        Self {
            kid,
            signer,
            leaf: leaf.clone(),
            chain: chain.to_vec(),
        }
    }
}

impl JwsSigner for JwsX509Signer<EcdsaP384PrivateKey> {
    fn get_kid(&self) -> &str {
        self.kid.as_str()
    }

    fn set_kid(&mut self, kid: &str) {
        self.kid = kid.to_string();
    }

    fn update_header(&self, header: &mut ProtectedHeader) -> Result<(), JwtError> {
        // Embed the x5c/leaf
        let x5c = std::iter::once(&self.leaf)
            .chain(self.chain.iter())
            .map(|cert| {
                Certificate::to_der(cert)
                    .map(|bytes| general_purpose::STANDARD.encode(bytes))
                    .map_err(|err| {
                        debug!(?err);
                        JwtError::CryptoError
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;

        header.x5c = Some(x5c);

        Ok(())
    }

    fn sign<V: JwsSignable>(&self, jws: &V) -> Result<V::Signed, JwtError> {
        let mut sign_data = jws.data()?;

        // Let the signer update the header as required.
        self.update_header(&mut sign_data.header)?;

        let hdr_b64 = serde_json::to_vec(&sign_data.header)
            .map_err(|e| {
                debug!(?e);
                JwtError::InvalidHeaderFormat
            })
            .map(|bytes| general_purpose::URL_SAFE_NO_PAD.encode(bytes))?;

        let mut hasher = EcdsaP384Digest::new();

        hasher.update(hdr_b64.as_bytes());
        hasher.update(".".as_bytes());
        hasher.update(sign_data.payload_b64.as_bytes());

        let signer = EcdsaP384SigningKey::from(&self.signer);

        let signature: EcdsaP384Signature = signer.try_sign_digest(hasher).map_err(|err| {
            debug!(?err);
            JwtError::CryptoError
        })?;

        let jwsc = JwsCompact {
            header: sign_data.header,
            hdr_b64,
            payload_b64: sign_data.payload_b64,
            signature: signature.to_der().to_vec(),
        };

        jws.post_process(jwsc)
    }

    fn set_sign_option_embed_kid(&self, _value: bool) -> Self {
        self.clone()
    }
}

fn certificate_to_kid(cert: &Certificate) -> String {
    let maybe_subject_key_id = cert
        .tbs_certificate
        .get::<SubjectKeyIdentifier>()
        .ok()
        .flatten();

    // Does the cert have a subject key id?
    let mut kid = if let Some((_, subject_key_id)) = maybe_subject_key_id {
        hex::encode(subject_key_id.as_ref().as_bytes())
    } else {
        let pub_key = &cert
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key;

        // If not, hash the publickey
        let mut hasher = s256::Sha256::new();
        hasher.update(pub_key.raw_bytes());
        let hashout = hasher.finalize();
        hex::encode(hashout)
    };
    kid.truncate(KID_LEN);

    kid
}
