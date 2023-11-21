//! A dangerous verification type that allows bypassing cryptographic
//! checking of the content of JWS tokens.

use crate::compact::JwsCompact;
use crate::error::JwtError;
use crate::traits::JwsVerifier;

/// A dangerous verification type that allows bypassing cryptographic
/// checking of the content of JWS tokens.
#[derive(Default)]
pub struct JwsDangerReleaseWithoutVerify {}

impl JwsVerifier for JwsDangerReleaseWithoutVerify {
    fn get_kid(&mut self) -> Option<&str> {
        None
    }

    fn verify_signature(&mut self, _jwsc: &JwsCompact) -> Result<bool, JwtError> {
        warn!("releasing without signature check.");
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::JwsDangerReleaseWithoutVerify;
    use crate::compact::JwaAlg;
    use crate::jws::{JwsBuilder, JwsUnverified};
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

        let jwtu = JwsUnverified::from_str("eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJteV9leHRlbiI6IkhlbGxvIn0.VNG9R9oitdzadh327cDo4Jcww7l_IGGVrsnRrKfdW-VzqNVjbrjLhyhZ6QmYT7uBBwcVxPuBKv5idyBapo_AlA")
            .expect("Invalid jwtu");

        let mut jws_danger_no_verification = JwsDangerReleaseWithoutVerify::default();

        let released = jwtu
            .verify(&mut jws_danger_no_verification)
            .expect("Unable to validate jwt");

        trace!(?released);
        trace!(?jwt);

        assert!(released == jwt);
    }
}
