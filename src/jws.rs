//! Jws Implementation

use crate::crypto::{Jwk, JwsCompact};
#[cfg(feature = "openssl")]
use crate::crypto::{JwsInner, JwsSigner, JwsValidator};
#[cfg(feature = "openssl")]
use url::Url;

use crate::error::JwtError;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// An unverified jws input which is ready to validate
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

#[cfg(feature = "openssl")]
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

#[cfg(feature = "openssl")]
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
        let pub_jwk = self
            .get_jwk_pubkey()
            .ok_or(JwtError::EmbededJwkNotAvailable)?;

        let jwsv = JwsValidator::try_from(pub_jwk)?;

        self.validate(&jwsv)
    }
}

impl JwsUnverified {
    /// Get the embedded public key used to sign this jwt, if present.
    pub fn get_jwk_pubkey(&self) -> Option<&Jwk> {
        self.jwsc.get_jwk_pubkey()
    }

    /// UNSAFE - release the content of this JWS without verifying it's internal structure.
    ///
    /// THIS MAY LEAD TO SECURITY VULNERABILITIES. YOU SHOULD BE ACUTELY AWARE OF THE RISKS WHEN
    /// CALLING THIS FUNCTION.
    #[cfg(feature = "unsafe_release_without_verify")]
    pub fn unsafe_release_without_verification<V>(&self) -> Result<Jws<V>, JwtError>
    where
        V: Clone + DeserializeOwned,
    {
        let released = self.jwsc.release_without_verification()?;

        serde_json::from_slice(released.payload()).map_err(|_| JwtError::InvalidJwt)
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

#[cfg(all(feature = "openssl", test))]
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
        let _ = tracing_subscriber::fmt::try_init();
        let jwss = JwsSigner::generate_es256().expect("failed to construct signer.");
        let pub_jwk = jwss.public_key_as_jwk(None).unwrap();
        let jws_validator = JwsValidator::try_from(&pub_jwk).expect("Unable to create validator");

        let jwt = Jws {
            inner: CustomExtension {
                my_exten: "Hello".to_string(),
            },
        };

        let jwts = jwt.sign(&jwss).expect("failed to sign jwt");

        let jwt_str = jwts.to_string();
        trace!("{}", jwt_str);

        let jwtu = jwts.invalidate();

        let released = jwtu
            .validate(&jws_validator)
            .expect("Unable to validate jwt");

        assert!(released == jwt);
    }

    #[test]
    fn test_sign_and_validate_hs256() {
        let _ = tracing_subscriber::fmt::try_init();
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

    #[test]
    #[cfg(feature = "unsafe_release_without_verify")]
    fn test_unsafe_release_without_verification() {
        use std::str::FromStr;

        let jwt = Jws {
            inner: CustomExtension {
                my_exten: "Hello".to_string(),
            },
        };

        let jwtu = super::JwsUnverified::from_str("eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJteV9leHRlbiI6IkhlbGxvIn0.VNG9R9oitdzadh327cDo4Jcww7l_IGGVrsnRrKfdW-VzqNVjbrjLhyhZ6QmYT7uBBwcVxPuBKv5idyBapo_AlA")
            .expect("Invalid jwtu");

        let released = jwtu
            .unsafe_release_without_verification()
            .expect("Unable to validate jwt");

        assert!(released == jwt);
    }
}
