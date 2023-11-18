use crate::compact::{JwsCompact, ProtectedHeader};
use crate::JwtError;

pub struct JwsCompactSignData<'a> {
    pub(crate) hdr_bytes: &'a [u8],
    pub(crate) payload_bytes: &'a [u8],
}

pub trait JwsSigner {
    fn get_kid(&mut self) -> &str;

    fn update_header(&mut self, header: &mut ProtectedHeader) -> Result<(), JwtError>;

    fn sign(&mut self, jwsc: JwsCompactSignData<'_>) -> Result<Vec<u8>, JwtError>;
}

pub trait JwsSignerToVerifier {
    type Verifier;

    fn get_verifier(&mut self) -> Result<Self::Verifier, JwtError>;
}

pub trait JwsVerifier {
    fn verify_signature(&mut self, jwsc: &JwsCompact) -> Result<bool, JwtError>;
}
