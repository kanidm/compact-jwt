//! Jws Implementation
use crate::crypto::{Jwk, JwsCompact, JwsInner, JwsSigner, JwsValidator};
use crate::error::JwtError;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use url::Url;

/// An unverified jws input which is ready to validate
#[derive(Debug)]
pub struct JwsUnverified {
    jwsc: JwsCompact,
}

/// A signed jwt which can be converted to a string.
pub struct JwsSigned {
    jwsc: JwsCompact,
}

/// A Jwt that is being created or has succeeded in being validated
#[derive(Serialize, Clone, Deserialize)]
pub struct Jws<V>
where
    V: Clone,
{
    /// These are the fields that this JWT will contain.
    #[serde(flatten)]
    pub inner: V,
}

impl<V> Default for Jws<V>
where
    V: Clone + Default,
{
    fn default() -> Self {
        Jws {
            inner: V::default(),
        }
    }
}

impl<V> fmt::Debug for Jws<V>
where
    V: Clone + fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Jws").field("inner", &self.inner).finish()
    }
}

impl<V> PartialEq for Jws<V>
where
    V: Clone + PartialEq,
{
    fn eq(&self, other: &Jws<V>) -> bool {
        self.inner == other.inner
    }
}

impl<V> Jws<V>
where
    V: Clone + Serialize,
{
    fn sign_inner(
        &self,
        signer: &JwsSigner,
        jku: Option<Url>,
        jwk: Option<Jwk>,
    ) -> Result<JwsSigned, JwtError> {
        // We need to convert this payload to a set of bytes.
        // eprintln!("{:?}", serde_json::to_string(&self));
        let payload = serde_json::to_vec(&self).map_err(|e| {
            error!(?e);
            JwtError::InvalidJwt
        })?;

        let jws = JwsInner::new(payload).set_typ("JWT".to_string());

        jws.sign_inner(signer, jku, jwk)
            .map(|jwsc| JwsSigned { jwsc })
    }

    /// Use this private signer to created a signed jwt.
    pub fn sign(&self, signer: &JwsSigner) -> Result<JwsSigned, JwtError> {
        self.sign_inner(signer, None, None)
    }

    /// Use this to create a signed jwt that includes the public key used in the signing process
    pub fn sign_embed_public_jwk(&self, signer: &JwsSigner) -> Result<JwsSigned, JwtError> {
        let jwk = signer.public_key_as_jwk(None)?;
        self.sign_inner(signer, None, Some(jwk))
    }
}

impl JwsUnverified {
    /// Using this JwsValidator, assert the correct signature of the data contained in
    /// this jwt.
    pub fn validate<V>(&self, validator: &JwsValidator) -> Result<Jws<V>, JwtError>
    where
        V: Clone + DeserializeOwned,
    {
        let released = self.jwsc.validate(validator)?;

        serde_json::from_slice(released.payload()).map_err(|_| JwtError::InvalidJwt)
    }

    /// Using this JwsValidator, assert the correct signature of the data contained in
    /// this jwt.
    pub fn validate_embeded<V>(&self) -> Result<Jws<V>, JwtError>
    where
        V: Clone + DeserializeOwned,
    {
        // If possible, validate using the embedded JWK
        let pub_jwk = self.get_jwk_pubkey();
        let pub_x5c = self.get_x5c_pubkey();
        let jwsv = match (pub_jwk, pub_x5c) {
            (None, Ok(None)) => Err(JwtError::EmbededJwkNotAvailable),
            // fix this error
            (Some(_), Ok(Some(_)) | Err(_)) => Err(JwtError::PrivateKeyDenied),
            (None, Err(err)) => Err(err),
            (Some(jwk), Ok(None)) => jwk.try_into(),
            (None, Ok(Some(x5c))) => x5c.try_into(),
        }?;

        self.validate(&jwsv)
    }

    /// Get the embedded public key used to sign this jwt, if present.
    pub fn get_jwk_pubkey(&self) -> Option<&Jwk> {
        self.jwsc.get_jwk_pubkey()
    }

    /// Get the embedded public key used to sign this jwt, if present.
    pub fn get_x5c_pubkey(&self) -> Result<Option<&openssl::x509::X509Ref>, JwtError> {
        self.jwsc.get_x5c_pubkey()
    }
}

impl FromStr for JwsUnverified {
    type Err = JwtError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        JwsCompact::from_str(s).map(|jwsc| JwsUnverified { jwsc })
    }
}

impl JwsSigned {
    /// Invalidate this signed jwt, causing it to require validation before you can use it
    /// again.
    pub fn invalidate(self) -> JwsUnverified {
        JwsUnverified { jwsc: self.jwsc }
    }
}

impl fmt::Display for JwsSigned {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.jwsc.fmt(f)
    }
}

#[cfg(test)]
mod tests {
    use super::Jws;
    use crate::crypto::{JwsSigner, JwsValidator};
    use serde::{Deserialize, Serialize};
    use std::convert::TryFrom;

    #[derive(Default, Debug, Serialize, Clone, Deserialize, PartialEq)]
    struct CustomExtension {
        my_exten: String,
    }

    #[test]
    fn test_sign_and_validate_es256() {
        let jwss = JwsSigner::generate_es256().expect("failed to construct signer.");
        let pub_jwk = jwss.public_key_as_jwk(None).unwrap();
        let jws_validator = JwsValidator::try_from(&pub_jwk).expect("Unable to create validator");

        let jwt = Jws {
            inner: CustomExtension {
                my_exten: "Hello".to_string(),
            },
        };

        let jwts = jwt.sign(&jwss).expect("failed to sign jwt");

        let jwtu = jwts.invalidate();

        let released = jwtu
            .validate(&jws_validator)
            .expect("Unable to validate jwt");

        assert!(released == jwt);
    }

    #[test]
    fn test_sign_and_validate_hs256() {
        let jwss = JwsSigner::generate_hs256().expect("failed to construct signer.");
        let jws_validator = jwss.get_validator().expect("Unable to create validator");

        let jwt = Jws {
            inner: CustomExtension {
                my_exten: "Hello".to_string(),
            },
        };

        let jwts = jwt.sign(&jwss).expect("failed to sign jwt");

        let jwtu = jwts.invalidate();

        let released = jwtu
            .validate(&jws_validator)
            .expect("Unable to validate jwt");

        assert!(released == jwt);
    }
}
