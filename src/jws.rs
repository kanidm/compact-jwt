//! JWS Implementation

use crate::compact::{JwsCompact, ProtectedHeader};
use crate::error::JwtError;
use crate::traits::JwsSignable;
use base64::{engine::general_purpose, Engine as _};
use serde::{Deserialize, Serialize};
use std::fmt;

/// A signed jwt which can be converted to a string.
pub struct JwsSigned {
    pub(crate) jwsc: JwsCompact,
}

/// A builder to create a new JWS that can be signed
pub struct JwsBuilder {
    pub(crate) header: ProtectedHeader,
    pub(crate) payload: Vec<u8>,
}

impl From<Vec<u8>> for JwsBuilder {
    fn from(payload: Vec<u8>) -> Self {
        JwsBuilder {
            header: ProtectedHeader::default(),
            payload,
        }
    }
}

impl JwsBuilder {
    /// Create a new builder from a serialisable type
    pub fn into_json<T: Serialize>(value: &T) -> Result<Self, serde_json::Error> {
        serde_json::to_vec(value).map(|payload| JwsBuilder {
            header: ProtectedHeader::default(),
            payload,
        })
    }

    /// Set the content type of this JWS
    pub fn set_typ(mut self, typ: Option<&str>) -> Self {
        self.header.typ = typ.map(|s| s.to_string());
        self
    }

    /// Set the content type of the payload
    pub fn set_cty(mut self, cty: Option<&str>) -> Self {
        self.header.cty = cty.map(|s| s.to_string());
        self
    }

    #[cfg(test)]
    /// Test function : Set the algorithm to use for this JWS
    pub fn set_alg(mut self, alg: crate::compact::JwaAlg) -> Self {
        self.header.alg = alg;
        self
    }

    /// Set the kid (required for Windows Hello/MS Extensions)
    pub fn set_kid(mut self, kid: Option<&str>) -> Self {
        self.header.kid = kid.map(|s| s.to_string());
        self
    }

    /// Set the chain of certificates
    pub fn set_x5c(mut self, x5c: Option<Vec<Vec<u8>>>) -> Self {
        self.header.x5c = x5c.map(|v| {
            v.into_iter()
                .map(|c| general_purpose::STANDARD.encode(c))
                .collect()
        });
        self
    }

    /// Set the content use header
    #[cfg(feature = "msextensions")]
    pub fn set_use(mut self, r#use: Option<&str>) -> Self {
        self.header.r#use = r#use.map(|s| s.to_string());
        self
    }

    /// Set the certificate thumbprint
    pub fn set_x5t(mut self, thumbprint: &str) -> Self {
        self.header.x5t = Some(thumbprint.to_string());
        self
    }

    /// Finalise this builder
    pub fn build(self) -> Jws {
        let JwsBuilder { header, payload } = self;
        Jws { header, payload }
    }
}

/// A Jws that is being created or has succeeded in being validated
#[derive(Debug, Clone, PartialEq)]
pub struct Jws {
    pub(crate) header: ProtectedHeader,
    pub(crate) payload: Vec<u8>,
}

impl Jws {
    /// Get the bytes of the payload of this JWS
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Create a JWS from a serialisable type. This assumes you want to encode
    /// the input value with json.
    pub fn into_json<T: Serialize>(value: &T) -> Result<Jws, serde_json::Error> {
        serde_json::to_vec(value).map(|payload| Jws {
            header: ProtectedHeader::default(),
            payload,
        })
    }

    /// Deserialise the inner payload of this JWS assuming it contains json.
    pub fn from_json<'a, T: Deserialize<'a>>(&'a self) -> Result<T, serde_json::Error> {
        serde_json::from_slice(self.payload())
    }

    pub(crate) fn set_typ(&mut self, typ: Option<&str>) {
        self.header.typ = typ.map(|s| s.to_string());
    }
}

impl JwsSignable for Jws {
    type Signed = JwsCompact;

    fn data(&self) -> Result<JwsCompactSign2Data, JwtError> {
        let payload_b64 = general_purpose::URL_SAFE_NO_PAD.encode(&self.payload);
        Ok(JwsCompactSign2Data {
            header: self.header.clone(),
            payload_b64,
        })
    }

    fn post_process(&self, value: JwsCompact) -> Result<Self::Signed, JwtError> {
        Ok(value)
    }
}

/// Data that will be signed
pub struct JwsCompactSign2Data {
    #[allow(dead_code)]
    pub(crate) header: ProtectedHeader,
    #[allow(dead_code)]
    pub(crate) payload_b64: String,
}

impl JwsSigned {
    /// Invalidate this signed jwt, causing it to require validation before you can use it
    /// again.
    pub fn invalidate(self) -> JwsCompact {
        self.jwsc
    }
}

impl fmt::Display for JwsSigned {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.jwsc.fmt(f)
    }
}

#[cfg(test)]
mod tests {
    use super::JwsBuilder;
    use crate::compact::JwaAlg;
    use crate::crypto::{
        JwsEs256Signer, JwsEs256Verifier, JwsHs256Signer, JwsX509Signer, JwsX509VerifierBuilder,
    };
    use crate::traits::*;
    use crypto_glue::{ecdsa_p384::EcdsaP384PrivateKey, traits::DecodePem, x509::Certificate};
    use serde::{Deserialize, Serialize};
    use std::convert::TryFrom;
    use std::time::{Duration, SystemTime};

    #[derive(Default, Debug, Serialize, Clone, Deserialize, PartialEq)]
    struct CustomExtension {
        my_exten: String,
    }

    #[test]
    fn test_sign_and_validate_es256() {
        let _ = tracing_subscriber::fmt::try_init();
        let jws_es256_signer =
            JwsEs256Signer::generate_es256().expect("failed to construct signer.");
        let jwk_es256_verifier = jws_es256_signer
            .get_verifier()
            .expect("failed to get verifier from signer");

        let inner = CustomExtension {
            my_exten: "Hello".to_string(),
        };

        let payload = serde_json::to_vec(&inner).expect("Unable to serialise");

        let jwt = JwsBuilder::from(payload)
            .set_typ(Some("JWT"))
            .set_kid(Some(jws_es256_signer.get_kid()))
            .set_alg(JwaAlg::ES256)
            .build();

        let jwts = jws_es256_signer.sign(&jwt).expect("failed to sign jwt");

        let jwt_str = jwts.to_string();
        trace!("{}", jwt_str);

        let released = jwk_es256_verifier
            .verify(&jwts)
            .expect("Unable to validate jwt");

        trace!(?released);
        trace!(?jwt);

        assert!(released == jwt);
    }

    #[test]
    fn test_sign_and_validate_hs256() {
        let _ = tracing_subscriber::fmt::try_init();
        let jws_hs256_verifier =
            JwsHs256Signer::generate_hs256().expect("failed to construct signer.");

        let inner = CustomExtension {
            my_exten: "Hello".to_string(),
        };

        let payload = serde_json::to_vec(&inner).expect("Unable to serialise");

        let jwt = JwsBuilder::from(payload)
            .set_typ(Some("JWT"))
            .set_kid(Some(JwsSigner::get_kid(&jws_hs256_verifier)))
            .set_alg(JwaAlg::HS256)
            .build();

        let jwts = jws_hs256_verifier.sign(&jwt).expect("failed to sign jwt");

        let released = jws_hs256_verifier
            .verify(&jwts)
            .expect("Unable to validate jwt");

        trace!(?released);
        trace!(?jwt);

        assert!(released == jwt);
    }

    #[test]
    fn test_verification_jws_x5c() {
        let current_time = SystemTime::UNIX_EPOCH + Duration::from_secs(1770691587);

        const ROOT_CERT: &str = r#"-----BEGIN CERTIFICATE-----
MIICLjCCAbSgAwIBAgIRAU8Kb4rRT0mUsQf9rVbLAhowCgYIKoZIzj0EAwMwQzEL
MAkGA1UEBhMCQVUxETAPBgNVBAoMCFBscyBIZWxwMSEwHwYDVQQDDBhPaCBubyBo
ZSBpcyB3cml0aW5nIGEgQ0EwHhcNMjYwMjEwMDI0NTQyWhcNMjYwMjEwMDM0NTQy
WjBDMQswCQYDVQQGEwJBVTERMA8GA1UECgwIUGxzIEhlbHAxITAfBgNVBAMMGE9o
IG5vIGhlIGlzIHdyaXRpbmcgYSBDQTB2MBAGByqGSM49AgEGBSuBBAAiA2IABFPu
aQn2tzNSL6ooAmYXhcqHbY8pBNis0LckMMytB1bsCdbS9JWGvxZnSSaDVgENFNvf
64G5Sh+eicjrUcAJLGfmdc7YBdZ3o5NcCWh/C6XiBw3XgnGWw/ZDj4OchlFbNqNs
MGowHQYDVR0OBBYEFAXszmYwxKgrhDYVy/GVodMtQNGhMA8GA1UdEwEB/wQFMAMB
Af8wDgYDVR0PAQH/BAQDAgEGMCgGA1UdHwQhMB8wHaAboBmGF2h0dHBzOi8vZXhh
bXBsZS5jb20vY3JsMAoGCCqGSM49BAMDA2gAMGUCMHQ6Nef4ENwiudXQMcH4DzuB
0zzgF9RIH5GvhcYNZ+13pZtHbiAO8AnHuSYquLFvdgIxAMgLk9X9KxTPcym41pGt
L9Ytm2ZPCfNpWL9qBqy3qPyGtfxpMclA3ck3JKlkGepD/g==
-----END CERTIFICATE-----"#;
        const INT_CERT: &str = r#"-----BEGIN CERTIFICATE-----
MIICZjCCAeugAwIBAgIRAQ1mUzLJHEbjtJrFkwzt2xMwCgYIKoZIzj0EAwMwQzEL
MAkGA1UEBhMCQVUxETAPBgNVBAoMCFBscyBIZWxwMSEwHwYDVQQDDBhPaCBubyBo
ZSBpcyB3cml0aW5nIGEgQ0EwHhcNMjYwMjEwMDI0NTQyWhcNMjYwMjEwMDM0NTQy
WjAxMQswCQYDVQQGEwJBVTEiMCAGA1UEAwwZT2ggbm8gaXRzIGFuIGludGVybWVk
aWF0ZTB2MBAGByqGSM49AgEGBSuBBAAiA2IABI198gNal5U9+eMmEs8dlUdURuJU
nn33eysYelGNuWYDYiuPjYlsucHTKkdsNZuY9FicElQewzK7Cr47WZwChoRpOS9B
2r8i10tI2/ipmPIAlqWshSIlPN2UZ+NZ7EDGqqOBtDCBsTAdBgNVHQ4EFgQU7gqP
RZ82etk0XzGfbLWnZa5NEIowHwYDVR0jBBgwFoAUBezOZjDEqCuENhXL8ZWh0y1A
0aEwEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAQYwLAYDVR0fBCUw
IzAhoB+gHYYbaHR0cHM6Ly9leGFtcGxlLmNvbS9pbnQvY3JsMB0GA1UdHgEB/wQT
MBGgDzANggtleGFtcGxlLmNvbTAKBggqhkjOPQQDAwNpADBmAjEA9VvAuOTw9192
/Djj7/iOAHbGmjk6a2PUS8CDUwjxL4qBjyRB3dmZNnF2wHPLE/oKAjEAmqhFqxWb
wtlOkqPmniGR103gurd3/alkHcxkqyU0KeQLAJ6gjVtm9wD3qhbDlJpX
-----END CERTIFICATE-----"#;
        const LEAF_CERT: &str = r#"-----BEGIN CERTIFICATE-----
MIICEjCCAZegAwIBAgIRAV1zkh2XSE0wiN+axloUuo0wCgYIKoZIzj0EAwMwMTEL
MAkGA1UEBhMCQVUxIjAgBgNVBAMMGU9oIG5vIGl0cyBhbiBpbnRlcm1lZGlhdGUw
HhcNMjYwMjEwMDI0NTQyWhcNMjYwMjEwMDM0NTQyWjAUMRIwEAYDVQQDDAlsb2Nh
bGhvc3QwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAARpZJM5KB3fqb4q9wJLZWq+JH5i
JbM5yZMVKJ6GS7XZDw/cRizVtcDPYiAaiIk76Cg83IPeAZmdOruulkRb5QmMiBJW
PSS2jxMcdE5pwLVvL0p7CS/hOmUS/WHhuS5Pop+jgY8wgYwwHQYDVR0OBBYEFO5A
oPdFRbBrkkBZpzl1k1Aps6FLMB8GA1UdIwQYMBaAFO4Kj0WfNnrZNF8xn2y1p2Wu
TRCKMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgPoMBYGA1UdJQEB/wQMMAoG
CCsGAQUFBwMBMBQGA1UdEQQNMAuCCWxvY2FsaG9zdDAKBggqhkjOPQQDAwNpADBm
AjEAy1u1GsYeRUnJxSbuUveiN0rubXgk/y0EnESIM8f2lXe84ofElUXTozNFdWm9
Sr4mAjEAvklqw0mWwQKgr5ypJFj6duCe1QMO0ff1Jv+6Z3NpbFABNquuyi+3H6vV
xH0SEy1Z
-----END CERTIFICATE-----"#;
        const LEAF_KEY: &str = r#"-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDA949NqEFqlXON4L0/8AQuILa53B2JOE14xkWsp3lg0ywWPJ0FzXA0O
UWwCFT564PmgBwYFK4EEACKhZANiAARpZJM5KB3fqb4q9wJLZWq+JH5iJbM5yZMV
KJ6GS7XZDw/cRizVtcDPYiAaiIk76Cg83IPeAZmdOruulkRb5QmMiBJWPSS2jxMc
dE5pwLVvL0p7CS/hOmUS/WHhuS5Pop8=
-----END EC PRIVATE KEY-----"#;

        let _ = tracing_subscriber::fmt::try_init();

        let root_cert =
            Certificate::from_pem(ROOT_CERT.as_bytes()).expect("Failed to parse trust root");
        let int_cert =
            Certificate::from_pem(INT_CERT.as_bytes()).expect("Failed to parse trust int root");
        let leaf_cert = Certificate::from_pem(LEAF_CERT.as_bytes()).expect("Failed to parse leaf");
        let leaf_key =
            EcdsaP384PrivateKey::from_sec1_pem(LEAF_KEY).expect("Failed to parse leaf key");

        let signer = JwsX509Signer::new(leaf_key, &leaf_cert, &[int_cert]);

        let claims_original: std::collections::BTreeMap<String, serde_json::value::Value> =
            std::collections::BTreeMap::from([("a".to_string(), serde_json::value::Value::Null)]);

        let jws = JwsBuilder::into_json(&claims_original)
            .expect("Failed to serialise json")
            .build();

        let jwsu: crate::JwsCompact = signer.sign(&jws).expect("Failed to sign");

        let (leaf, chain) = jwsu
            .get_x5c_chain()
            .expect("Failed to get x5c chain")
            .expect("x5c chain is empty");

        assert!(chain.len() == 1);

        let jws_x509_verifier = JwsX509VerifierBuilder::new(&leaf, &chain)
            .add_trust_root(root_cert)
            .build(current_time)
            .expect("Failed to construct verifier");

        let claims: std::collections::BTreeMap<String, serde_json::value::Value> =
            jws_x509_verifier
                .verify(&jwsu)
                .expect("Failed to verify")
                .from_json()
                .expect("Failed to deserialise contents");

        assert_eq!(claims_original, claims);
    }

    #[test]
    fn test_verification_jws_embedded() {
        use std::str::FromStr;

        let _ = tracing_subscriber::fmt::try_init();

        let jwsu = super::JwsCompact::from_str(
  "eyJhbGciOiJFUzI1NiIsImp3ayI6eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6IjhyaFRhVElJMHRzY1MyX2QtWUNYRm92RGpRUkxEUTEzbWhHV3d5UTBibWMiLCJ5IjoiYmoyakNkSXkxU3lpcHBkU2lEWmxHZEhMUTR0TG40NjMzTFk2dUJHUWU1NCIsImFsZyI6IkVTMjU2IiwidXNlIjoic2lnIn0sInR5cCI6IkpXVCJ9.eyJzZXNzaW9uX2lkIjoiYTNkYjczYTctNzc3Zi00NzI2LTliZGUtNjBkMjEwOTJlNTFmIiwiYXV0aF90eXBlIjoiZ2VuZXJhdGVkcGFzc3dvcmQiLCJleHBpcnkiOlsyMDIyLDI2MCwyMTk5OCw2NTc4MDM0NjhdLCJ1dWlkIjoiMDAwMDAwMDAtMDAwMC0wMDAwLTAwMDAtMDAwMDAwMDAwMDAwIiwiZGlzcGxheW5hbWUiOiJTeXN0ZW0gQWRtaW5pc3RyYXRvciIsInNwbiI6ImFkbWluQGlkbS5jb3JlZm9ybS5jb20iLCJtYWlsX3ByaW1hcnkiOm51bGwsImxpbV91aWR4IjpmYWxzZSwibGltX3JtYXgiOjEyOCwibGltX3BtYXgiOjI1NiwibGltX2ZtYXgiOjMyfQ.Y9CeMWwGX4xS4O2Yy9vlTjW-6dL_Ncoo-nWd2344O_SwWdBneDpUE35aA_kuLRg1ssVceyVvCDhlxYOyXwzAjQ"
        )
            .expect("Invalid jwsu");

        let jwk = jwsu.get_jwk_pubkey().expect("Failed to get JWK public key");

        let jws_es256_verifier =
            JwsEs256Verifier::try_from(jwk).expect("Failed to construct verifier");

        let _claims: std::collections::BTreeMap<String, serde_json::value::Value> =
            jws_es256_verifier
                .verify(&jwsu)
                .expect("Failed to verify")
                .from_json()
                .expect("Failed to deserialise contents");
    }
}
