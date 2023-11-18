use crate::compact::JwsCompact;
use crate::error::JwtError;
use crate::traits::JwsVerifier;

#[derive(Default)]
pub struct JwsDangerReleaseWithoutVerify {}

impl JwsVerifier for JwsDangerReleaseWithoutVerify {
    fn verify_signature(&mut self, jwsc: &JwsCompact) -> Result<bool, JwtError> {
        warn!("releasing without signature check.");
        Ok(true)
    }
}

mod tests {
    use crate::compact::JwaAlg;
    use crate::jws::{JwsBuilder, JwsUnverified};
    use crate::traits::JwsVerifier;
    use serde::{Deserialize, Serialize};
    use std::convert::TryFrom;

    use crate::dangernoverify::JwsDangerReleaseWithoutVerify;

    #[derive(Default, Debug, Serialize, Clone, Deserialize, PartialEq)]
    struct CustomExtension {
        my_exten: String,
    }

    #[test]
    fn test_unsafe_release_without_verification() {
        let _ = tracing_subscriber::fmt::try_init();

        use std::str::FromStr;

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
