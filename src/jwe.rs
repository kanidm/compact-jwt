//! JWE Implementation

use crate::compact::JweProtectedHeader;
use serde::{Deserialize, Serialize};

/// A builder to create a new JWS that can be enciphered.
pub struct JweBuilder {
    pub(crate) header: JweProtectedHeader,
    pub(crate) payload: Vec<u8>,
}

impl From<Vec<u8>> for JweBuilder {
    fn from(payload: Vec<u8>) -> Self {
        JweBuilder {
            header: JweProtectedHeader::default(),
            payload,
        }
    }
}

impl JweBuilder {
    /// Set the content type of this JWE
    pub fn set_typ(mut self, typ: Option<&str>) -> Self {
        self.header.typ = typ.map(|s| s.to_string());
        self
    }

    /// Set the content type of the payload
    pub fn set_cty(mut self, cty: Option<&str>) -> Self {
        self.header.cty = cty.map(|s| s.to_string());
        self
    }

    /// Finalise this builder
    pub fn build(self) -> Jwe {
        let JweBuilder { header, payload } = self;
        Jwe { header, payload }
    }
}

/// A Jws that is being created or has succeeded in being validated
#[derive(Debug, Clone, PartialEq)]
pub struct Jwe {
    pub(crate) header: JweProtectedHeader,
    pub(crate) payload: Vec<u8>,
}

impl Jwe {
    /// Get the bytes of the payload of this JWS
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Create a JWE from a serialisable type. This assumes you want to encode
    /// the input value with json.
    pub fn into_json<T: Serialize>(value: &T) -> Result<Jwe, serde_json::Error> {
        serde_json::to_vec(value).map(|payload| Jwe {
            header: JweProtectedHeader::default(),
            payload,
        })
    }

    /// Deserialise the inner payload of this JWE assuming it contains json.
    pub fn from_json<'a, T: Deserialize<'a>>(&'a self) -> Result<T, serde_json::Error> {
        serde_json::from_slice(self.payload())
    }
}

mod tests {
    use serde::{Deserialize, Serialize};

    #[derive(Default, Debug, Serialize, Clone, Deserialize, PartialEq)]
    struct CustomExtension {
        my_exten: String,
    }

    #[test]
    fn test_encrypt_and_decrypt() {}
}
