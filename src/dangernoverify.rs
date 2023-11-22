//! A dangerous verification type that allows bypassing cryptographic
//! checking of the content of JWS tokens.

use crate::error::JwtError;
use crate::traits::{JwsVerifiable, JwsVerifier};

/// A dangerous verification type that allows bypassing cryptographic
/// checking of the content of JWS tokens.
#[derive(Default)]
pub struct JwsDangerReleaseWithoutVerify {}

impl JwsVerifier for JwsDangerReleaseWithoutVerify {
    fn get_kid(&self) -> Option<&str> {
        None
    }

    fn verify<V: JwsVerifiable>(&self, jwsc: &V) -> Result<V::Verified, JwtError> {
        let signed_data = jwsc.data();

        signed_data.release().and_then(|d| jwsc.post_process(d))
    }
}

#[cfg(test)]
mod tests {
    use super::JwsDangerReleaseWithoutVerify;
    use crate::compact::{JwaAlg, JwsCompact};
    use crate::jws::JwsBuilder;
    use crate::traits::*;
    use serde::{Deserialize, Serialize};
    use std::str::FromStr;

    #[derive(Default, Debug, Serialize, Clone, Deserialize, PartialEq)]
    struct CustomExtension {
        my_exten: String,
    }

    #[test]
    fn test_unsafe_release_without_verification() {
        let _ = tracing_subscriber::fmt::try_init();

        let inner = CustomExtension {
            my_exten: "Hello".to_string(),
        };

        let payload = serde_json::to_vec(&inner).expect("Unable to serialise");

        let jwt = JwsBuilder::from(payload)
            .set_typ(Some("JWT"))
            .set_alg(JwaAlg::ES256)
            .build();

        let jwtu = JwsCompact::from_str("eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJteV9leHRlbiI6IkhlbGxvIn0.VNG9R9oitdzadh327cDo4Jcww7l_IGGVrsnRrKfdW-VzqNVjbrjLhyhZ6QmYT7uBBwcVxPuBKv5idyBapo_AlA")
            .expect("Invalid jwtu");

        let jws_danger_no_verification = JwsDangerReleaseWithoutVerify::default();

        let released = jws_danger_no_verification
            .verify(&jwtu)
            .expect("Unable to validate jwt");

        trace!(?released);
        trace!(?jwt);

        assert!(released == jwt);
    }
}
