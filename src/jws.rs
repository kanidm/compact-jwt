//! Jws Implementation

use crate::compact::{Jwk, JwsCompact, JwsInner};
#[cfg(feature = "openssl")]
use crate::crypto::{JwsSignerEnum, JwsValidatorEnum};
#[cfg(feature = "openssl")]
use openssl::x509;
#[cfg(feature = "openssl")]
use url::Url;

use crate::error::JwtError;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// An unverified jws input which is ready to validate
#[derive(Debug)]
pub struct JwsUnverified {
    jwsc: JwsCompact,
}

/// A signed jwt which can be converted to a string.
pub struct JwsSigned {
    jwsc: JwsCompact,
}

/// A Jws that is being created or has succeeded in being validated
#[derive(Debug, Clone)]
pub struct Jws {
    #[allow(dead_code)]
    pub(crate) header: ProtectedHeader,
    #[allow(dead_code)]
    pub(crate) payload: Vec<u8>,
}

impl Jws {
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

#[cfg(feature = "openssl")]
impl JwsUnverified {
    /// Using this [JwsVerifier], assert the correct signature of the data contained in
    /// this jwt.
    pub fn verify<K: JwsVerifier>(&self, verifier: &mut K) -> Result<Jws, JwtError> {
        self.jwsc.verify(verifier)
    }

    /// Get the embedded public key used to sign this jwt, if present.
    pub fn get_x5c_pubkey(&self) -> Result<Option<x509::X509>, JwtError> {
        self.jwsc.get_x5c_pubkey()
    }

    /// Get the embedded certificate chain (if any) in DER forms
    pub fn get_x5c_chain(&self) -> Result<Option<Vec<x509::X509>>, JwtError> {
        self.jwsc.get_x5c_chain()
    }
}

impl JwsUnverified {
    /// Get the embedded public key used to sign this jwt, if present.
    pub fn get_jwk_pubkey(&self) -> Option<&Jwk> {
        self.jwsc.get_jwk_pubkey()
    }

    /// Get the KID used to sign this Jws if present
    pub fn get_jwk_kid(&self) -> Option<&str> {
        self.jwsc.get_jwk_kid()
    }

    /// UNSAFE - release the content of this JWS without verifying it's internal structure.
    ///
    /// THIS MAY LEAD TO SECURITY VULNERABILITIES. YOU SHOULD BE ACUTELY AWARE OF THE RISKS WHEN
    /// CALLING THIS FUNCTION.
    #[cfg(feature = "unsafe_release_without_verify")]
    pub fn unsafe_release_without_verification<V>(&self) -> Result<Jws<V>, JwtError>
    where
        V: Clone + serde::de::DeserializeOwned,
    {
        let released = self.jwsc.release_without_verification()?;

        serde_json::from_slice(released.payload()).map_err(|e| {
            error!(?e, "Invalid Jws - Serde Error");
            JwtError::InvalidJwt
        })
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
    use crate::crypto::{JwsSignerEnum, JwsValidatorEnum};
    use serde::{Deserialize, Serialize};
    use std::convert::TryFrom;

    #[derive(Default, Debug, Serialize, Clone, Deserialize, PartialEq)]
    struct CustomExtension {
        my_exten: String,
    }

    #[test]
    fn test_sign_and_validate_es256() {
        let _ = tracing_subscriber::fmt::try_init();
        let jwss = JwsSignerEnum::generate_es256().expect("failed to construct signer.");
        let pub_jwk = jwss.public_key_as_jwk().unwrap();
        let jws_validator =
            JwsValidatorEnum::try_from(&pub_jwk).expect("Unable to create validator");

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
        let jwss = JwsSignerEnum::generate_hs256().expect("failed to construct signer.");
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

    #[test]
    fn test_verification_jws_x5c() {
        use std::str::FromStr;
        let jwsu = super::JwsUnverified::from_str("eyJhbGciOiJSUzI1NiIsIng1YyI6WyJNSUlGYmpDQ0JGYWdBd0lCQWdJUUFhM09LT2RvVFk0UUFBQUFBQTNYWERBTkJna3Foa2lHOXcwQkFRc0ZBREJHTVFzd0NRWURWUVFHRXdKVlV6RWlNQ0FHQTFVRUNoTVpSMjl2WjJ4bElGUnlkWE4wSUZObGNuWnBZMlZ6SUV4TVF6RVRNQkVHQTFVRUF4TUtSMVJUSUVOQklERkVOREFlRncweU1qQXpNakF5TVRFMU1qRmFGdzB5TWpBMk1UZ3lNVEUxTWpCYU1CMHhHekFaQmdOVkJBTVRFbUYwZEdWemRDNWhibVJ5YjJsa0xtTnZiVENDQVNJd0RRWUpLb1pJaHZjTkFRRUJCUUFEZ2dFUEFEQ0NBUW9DZ2dFQkFMbXFMQlhWNENaQTVzVDVjVGZ1WGN3MTFXRDJZVVczZUFKdmRxK1hJYkhEZ01OTUJyc3gvWER4NkxtOU9tSkNVNHZDcFdJTjRXQ0gyMFQ5T2ZlNkhkeU52RWVpM3pobHpOMFovWVR5b1RlcFdwNUgvbXJuR29zU3NtcEp1NDV3OVJYbm5KbElrRzU5dDN0V1JoYXNZZW5GY0hlY0ZobG1odm5UQnRHa01Vb0VGREZnanltZ2twUUdkMmxoaU9YWGJwMzE1SXlGbEdUVFpvNERBYTZiMHp2VGZQOXV6R1FJZHhma3N5TUlGZmJDYVd6TjNPanB1bVIwMHg2SVZjZDdyOUxvOVBlVWw5a296cjhFaDRDWS9PQitEOVEvVjZ4RVpiVHNHeXc0aUFxQ0tvMTRDRXpDRVFIMEZWWTQ1cFg3b2IrbWhmL1pKbWNzL014blZGbkx6bDBDQXdFQUFhT0NBbjh3Z2dKN01BNEdBMVVkRHdFQi93UUVBd0lGb0RBVEJnTlZIU1VFRERBS0JnZ3JCZ0VGQlFjREFUQU1CZ05WSFJNQkFmOEVBakFBTUIwR0ExVWREZ1FXQkJUOVI3Z21PZUQxdlpRVkNIYzBUdGh2T1lpMzlEQWZCZ05WSFNNRUdEQVdnQlFsNGhnT3NsZVJsQ3JsMUYyR2tJUGVVN080a2pCN0JnZ3JCZ0VGQlFjQkFRUnZNRzB3T0FZSUt3WUJCUVVITUFHR0xHaDBkSEE2THk5dlkzTndMbkJyYVM1bmIyOW5MM012WjNSek1XUTBhVzUwTDNoT0xWOHdkRE4zV1Rrd01ERUdDQ3NHQVFVRkJ6QUNoaVZvZEhSd09pOHZjR3RwTG1kdmIyY3ZjbVZ3Ynk5alpYSjBjeTluZEhNeFpEUXVaR1Z5TUIwR0ExVWRFUVFXTUJTQ0VtRjBkR1Z6ZEM1aGJtUnliMmxrTG1OdmJUQWhCZ05WSFNBRUdqQVlNQWdHQm1lQkRBRUNBVEFNQmdvckJnRUVBZFo1QWdVRE1EOEdBMVVkSHdRNE1EWXdOS0F5b0RDR0xtaDBkSEE2THk5amNteHpMbkJyYVM1bmIyOW5MMmQwY3pGa05HbHVkQzlZTWtveVNISmZOMUJwVFM1amNtd3dnZ0VFQmdvckJnRUVBZFo1QWdRQ0JJSDFCSUh5QVBBQWRnQlJvN0QxL1FGNW5GWnR1RGQ0and5a2Vzd2JKOHYzbm9oQ21nMysxSXNGNVFBQUFYK3Baa0pyQUFBRUF3QkhNRVVDSVFDb2RWRnpPQ1VubHVRUzB0MG9HdUEzdlZFR0Zxb2I4SVJiQ3BZeTdVZmNBUUlnRi9NZVVSdG9EN1FraFhCTjB1cmlDdEwvTENsMW1zRE5oWjFtMUhKeEpRb0FkZ0FwZWI3d25qazVJZkJXYzU5anBYZmx2bGQ5bkdBSytQbE5YU1pjSlYzSGhBQUFBWCtwWmtKWUFBQUVBd0JITUVVQ0lRQ1pvRW1Bbzc0UitGT0pQeVJLYkkyRSs2S0NYNkF1WG1oZnNXa2h0aUFLYWdJZ1p1dmZIcUE2UE9sM0JkV3RlU1l4TzA2QmNwT3dUYTV6NjVqSkw0dExEckl3RFFZSktvWklodmNOQVFFTEJRQURnZ0VCQURJcC93blFsZnE3dVZ6dDU3MHlRRTJOQVA1ajh5OGFzWWhKTXcrUTBYZ3M2a3pqZnpGL2g3OVpmRlhLOTh3QVJhVnI2amVSQXo2Y3E4cUVIMU8yQkQ5eDVEQ09UZzJxclNnSldiTU5VWkR5TXV6RmVyQ2EyNzloQklQVXBqNzg0YUdsYWp4Y2M3VHRYSHpacnhmbGM0d1BzZ2JnQ2twd3VqNmowandDNjdRNGJrOVVYKzNxcGw3MmFKMnpWbzFmT2s3U0ZwSTU4RjNJL1c4bkkva2Nwb1BvcDJCNkoxR3RxTURIRnByc3RnZUpMbFkzQWVmZWoyeW9Fd3UyajIrYzEvSjZ3SDV4YWRES3hnM052aDIreGhaUkZab0FUYjJlNllzeDRSMEJ0eWVYNEhaTWc0OFFhQk40N2xBeEFjZzR1YVNqRy8vQkhXTjM0cE1FYWNJeEdOMD0iLCJNSUlGakRDQ0EzU2dBd0lCQWdJTkFnQ09zZ0l6Tm1XTFpNM2JtekFOQmdrcWhraUc5dzBCQVFzRkFEQkhNUXN3Q1FZRFZRUUdFd0pWVXpFaU1DQUdBMVVFQ2hNWlIyOXZaMnhsSUZSeWRYTjBJRk5sY25acFkyVnpJRXhNUXpFVU1CSUdBMVVFQXhNTFIxUlRJRkp2YjNRZ1VqRXdIaGNOTWpBd09ERXpNREF3TURReVdoY05NamN3T1RNd01EQXdNRFF5V2pCR01Rc3dDUVlEVlFRR0V3SlZVekVpTUNBR0ExVUVDaE1aUjI5dloyeGxJRlJ5ZFhOMElGTmxjblpwWTJWeklFeE1RekVUTUJFR0ExVUVBeE1LUjFSVElFTkJJREZFTkRDQ0FTSXdEUVlKS29aSWh2Y05BUUVCQlFBRGdnRVBBRENDQVFvQ2dnRUJBS3ZBcXFQQ0UyN2wwdzl6QzhkVFBJRTg5YkEreFRtRGFHN3k3VmZRNGMrbU9XaGxVZWJVUXBLMHl2MnI2NzhSSkV4SzBIV0RqZXErbkxJSE4xRW01ajZyQVJaaXhteVJTamhJUjBLT1FQR0JNVWxkc2F6dElJSjdPMGcvODJxai92R0RsLy8zdDR0VHF4aVJoTFFuVExYSmRlQisyRGhrZFU2SUlneDZ3TjdFNU5jVUgzUmNzZWpjcWo4cDVTajE5dkJtNmkxRmhxTEd5bWhNRnJvV1ZVR08zeHRJSDkxZHNneTRlRktjZktWTFdLM28yMTkwUTBMbS9TaUttTGJSSjVBdTR5MWV1RkptMkpNOWVCODRGa3FhM2l2clhXVWVWdHllMENRZEt2c1kyRmthenZ4dHh2dXNMSnpMV1lIazU1emNSQWFjREEyU2VFdEJiUWZEMXFzQ0F3RUFBYU9DQVhZd2dnRnlNQTRHQTFVZER3RUIvd1FFQXdJQmhqQWRCZ05WSFNVRUZqQVVCZ2dyQmdFRkJRY0RBUVlJS3dZQkJRVUhBd0l3RWdZRFZSMFRBUUgvQkFnd0JnRUIvd0lCQURBZEJnTlZIUTRFRmdRVUplSVlEckpYa1pRcTVkUmRocENEM2xPenVKSXdId1lEVlIwakJCZ3dGb0FVNUs4ckpuRWFLMGduaFM5U1ppenY4SWtUY1Q0d2FBWUlLd1lCQlFVSEFRRUVYREJhTUNZR0NDc0dBUVVGQnpBQmhocG9kSFJ3T2k4dmIyTnpjQzV3YTJrdVoyOXZaeTluZEhOeU1UQXdCZ2dyQmdFRkJRY3dBb1lrYUhSMGNEb3ZMM0JyYVM1bmIyOW5MM0psY0c4dlkyVnlkSE12WjNSemNqRXVaR1Z5TURRR0ExVWRId1F0TUNzd0thQW5vQ1dHSTJoMGRIQTZMeTlqY213dWNHdHBMbWR2YjJjdlozUnpjakV2WjNSemNqRXVZM0pzTUUwR0ExVWRJQVJHTUVRd0NBWUdaNEVNQVFJQk1EZ0dDaXNHQVFRQjFua0NCUU13S2pBb0JnZ3JCZ0VGQlFjQ0FSWWNhSFIwY0hNNkx5OXdhMmt1WjI5dlp5OXlaWEJ2YzJsMGIzSjVMekFOQmdrcWhraUc5dzBCQVFzRkFBT0NBZ0VBSVZUb3kyNGp3WFVyMHJBUGM5MjR2dVNWYktRdVl3M25MZmxMZkxoNUFZV0VlVmwvRHUxOFFBV1VNZGNKNm8vcUZaYmhYa0JIMFBOY3c5N3RoYWYyQmVvRFlZOUNrL2IrVUdsdWh4MDZ6ZDRFQmY3SDlQODRubnJ3cFIrNEdCRFpLK1hoM0kwdHFKeTJyZ09xTkRmbHI1SU1ROFpUV0EzeWx0YWt6U0JLWjZYcEYwUHBxeUNSdnAvTkNHdjJLWDJUdVBDSnZzY3AxL20ycFZUdHlCallQUlErUXVDUUdBSktqdE43UjVERnJmVHFNV3ZZZ1ZscENKQmt3bHU3KzdLWTNjVElmekU3Y21BTHNrTUtOTHVEeitSekNjc1lUc1ZhVTdWcDN4TDYwT1locUZrdUFPT3hEWjZwSE9qOStPSm1ZZ1BtT1Q0WDMrN0w1MWZYSnlSSDlLZkxSUDZuVDMxRDVubXNHQU9nWjI2LzhUOWhzQlcxdW85anU1ZlpMWlhWVlM1SDBIeUlCTUVLeUdNSVBoRldybHQvaEZTMjhOMXphS0kwWkJHRDNnWWdETGJpRFQ5ZkdYc3RwaytGbWM0b2xWbFdQelhlODF2ZG9FbkZicjVNMjcySGRnSldvK1doVDlCWU0wSmkrd2RWbW5SZmZYZ2xvRW9sdVROY1d6YzQxZEZwZ0p1OGZGM0xHMGdsMmliU1lpQ2k5YTZodlUwVHBwakp5SVdYaGtKVGNNSmxQcld4MVZ5dEVVR3JYMmwwSkR3UmpXLzY1NnIwS1ZCMDJ4SFJLdm0yWktJMDNUZ2xMSXBtVkNLM2tCS2tLTnBCTmtGdDhyaGFmY0NLT2I5SngvOXRwTkZsUVRsN0IzOXJKbEpXa1IxN1FuWnFWcHRGZVBGT1JvWm1Gek09IiwiTUlJRllqQ0NCRXFnQXdJQkFnSVFkNzBOYk5zMitScnFJUS9FOEZqVERUQU5CZ2txaGtpRzl3MEJBUXNGQURCWE1Rc3dDUVlEVlFRR0V3SkNSVEVaTUJjR0ExVUVDaE1RUjJ4dlltRnNVMmxuYmlCdWRpMXpZVEVRTUE0R0ExVUVDeE1IVW05dmRDQkRRVEViTUJrR0ExVUVBeE1TUjJ4dlltRnNVMmxuYmlCU2IyOTBJRU5CTUI0WERUSXdNRFl4T1RBd01EQTBNbG9YRFRJNE1ERXlPREF3TURBME1sb3dSekVMTUFrR0ExVUVCaE1DVlZNeElqQWdCZ05WQkFvVEdVZHZiMmRzWlNCVWNuVnpkQ0JUWlhKMmFXTmxjeUJNVEVNeEZEQVNCZ05WQkFNVEMwZFVVeUJTYjI5MElGSXhNSUlDSWpBTkJna3Foa2lHOXcwQkFRRUZBQU9DQWc4QU1JSUNDZ0tDQWdFQXRoRUNpeDdqb1hlYk85eS9sRDYzbGFkQVBLSDlndmw5TWdhQ2NmYjJqSC83Nk51OGFpNlhsNk9NUy9rcjlySDV6b1Fkc2ZuRmw5N3Z1ZktqNmJ3U2lWNm5xbEtyK0NNbnk2U3huR1BiMTVsKzhBcGU2MmltOU1aYVJ3MU5FRFBqVHJFVG84Z1liRXZzL0FtUTM1MWtLU1VqQjZHMDBqMHVZT0RQMGdtSHU4MUk4RTNDd25xSWlydTZ6MWtaMXErUHNBZXduakh4Z3NIQTN5Nm1iV3daRHJYWWZpWWFSUU05c0hta2xDaXREMzhtNWFnSS9wYm9QR2lVVSs2RE9vZ3JGWllKc3VCNmpDNTExcHpycDFaa2o1WlBhSzQ5bDhLRWo4QzhRTUFMWEwzMmg3TTFiS3dZVUgrRTRFek5rdE1nNlRPOFVwbXZNclVwc3lVcXRFajVjdUhLWlBmbWdoQ042SjNDaW9qNk9HYUsvR1A1QWZsNC9YdGNkL3AyaC9yczM3RU9lWlZYdEwwbTc5WUIwZXNXQ3J1T0M3WEZ4WXBWcTlPczZwRkxLY3dacERJbFRpcnhaVVRRQXM2cXprbTA2cDk4ZzdCQWUrZERxNmRzbzQ5OWlZSDZUS1gvMVk3RHprdmd0ZGl6amtYUGRzRHRRQ3Y5VXcrd3A5VTdEYkdLb2dQZU1hM01kK3B2ZXo3VzM1RWlFdWErK3RneS9CQmpGRkZ5M2wzV0ZwTzlLV2d6N3pwbTdBZUtKdDhUMTFkbGVDZmVYa2tVQUtJQWY1cW9JYmFwc1pXd3Bia05GaEhheDJ4SVBFRGdmZzFhelZZODBaY0Z1Y3RMN1RsTG5NUS8wbFVUYmlTdzFuSDY5TUc2ek8wYjlmNkJRZGdBbUQwNnlLNTZtRGNZQlpVQ0F3RUFBYU9DQVRnd2dnRTBNQTRHQTFVZER3RUIvd1FFQXdJQmhqQVBCZ05WSFJNQkFmOEVCVEFEQVFIL01CMEdBMVVkRGdRV0JCVGtyeXNtY1JvclNDZUZMMUptTE8vd2lSTnhQakFmQmdOVkhTTUVHREFXZ0JSZ2UyWWFSUTJYeW9sUUwzMEV6VFNvLy96OVN6QmdCZ2dyQmdFRkJRY0JBUVJVTUZJd0pRWUlLd1lCQlFVSE1BR0dHV2gwZEhBNkx5OXZZM053TG5CcmFTNW5iMjluTDJkemNqRXdLUVlJS3dZQkJRVUhNQUtHSFdoMGRIQTZMeTl3YTJrdVoyOXZaeTluYzNJeEwyZHpjakV1WTNKME1ESUdBMVVkSHdRck1Da3dKNkFsb0NPR0lXaDBkSEE2THk5amNtd3VjR3RwTG1kdmIyY3ZaM055TVM5bmMzSXhMbU55YkRBN0JnTlZIU0FFTkRBeU1BZ0dCbWVCREFFQ0FUQUlCZ1puZ1F3QkFnSXdEUVlMS3dZQkJBSFdlUUlGQXdJd0RRWUxLd1lCQkFIV2VRSUZBd013RFFZSktvWklodmNOQVFFTEJRQURnZ0VCQURTa0hyRW9vOUMwZGhlbU1Yb2g2ZEZTUHNqYmRCWkJpTGc5TlIzdDVQK1Q0VnhmcTd2cWZNL2I1QTNSaTFmeUptOWJ2aGRHYUpRM2IydDZ5TUFZTi9vbFVhenNhTCt5eUVuOVdwcktBU09zaElBckFveVpsK3RKYW94MTE4ZmVzc21YbjFoSVZ3NDFvZVFhMXYxdmc0RnY3NHpQbDYvQWhTcnc5VTVwQ1pFdDRXaTR3U3R6NmRUWi9DTEFOeDhMWmgxSjdRSlZqMmZoTXRmVEpyOXc0ejMwWjIwOWZPVTBpT015K3FkdUJtcHZ2WXVSN2haTDZEdXBzemZudzBTa2Z0aHMxOGRHOVpLYjU5VWh2bWFTR1pSVmJOUXBzZzNCWmx2aWQwbElLTzJkMXhvemNsT3pnalhQWW92SkpJdWx0emtNdTM0cVFiOVN6L3lpbHJiQ2dqOD0iXX0.eyJub25jZSI6IkprblpTb1p1TnE4K09ydFB4MERmc0xVWEZWckozQ0M5U216RURjbGJHbms9IiwidGltZXN0YW1wTXMiOjE2NTQ1MjkzNTYwMTcsImFwa1BhY2thZ2VOYW1lIjoiY29tLmdvb2dsZS5hbmRyb2lkLmdtcyIsImFwa0RpZ2VzdFNoYTI1NiI6IlJZdkx3Vm1nRjJYYXMxMUREOTI1SXVzc0p1eEtEL3dCN2pjT01qbU1UR0E9IiwiY3RzUHJvZmlsZU1hdGNoIjp0cnVlLCJhcGtDZXJ0aWZpY2F0ZURpZ2VzdFNoYTI1NiI6WyI4UDFzVzBFUEpjc2x3N1V6UnNpWEw2NHcrTzUwRWQrUkJJQ3RheTFnMjRNPSJdLCJiYXNpY0ludGVncml0eSI6dHJ1ZSwiZXZhbHVhdGlvblR5cGUiOiJCQVNJQyJ9.QGm9B8pw6wwy0Zyly_lkLPw_56y9vzFggS7z6J0u9nLglFBc-VnDUgeZEBzYiSrU5bXsKFn9lF6MbjvmpVgnYgBFLEYAlNFDe-2CPf0UdNR1wS-cMep1IKsdkhCQGL7LVzucLvSMPJt4QvqEScQrsjw9X-zCKiKuEsrDfrBoVhvYEJjSNzMtIG8k1gAtJJ-QcdcoLU1ImJEvmU-5VdYfoiOuxyGULaBbjIQ7o190FEXtQuyHIxUUknVsADvDK9loQA0lp38sl1Ec4ddbsyNMFCctnNFdCrosp9PSmQLNMv1_bhIgctdYVTkr9CR59LJur4PWGmOGS_3bjot5IB5Qrg")
            .expect("Invalid jwsu");

        let certs = jwsu.get_x5c_chain().expect("Invalid x5c chain");

        assert!(certs.unwrap().len() == 3);

        let _claims: std::collections::BTreeMap<String, serde_json::value::Value> = jwsu
            .validate_embeded()
            .expect("Failed to verify")
            .into_inner();
    }

    #[test]
    fn test_verification_jws_embedded() {
        use std::str::FromStr;

        let _ = tracing_subscriber::fmt::try_init();

        let jwsu = super::JwsUnverified::from_str(
  "eyJhbGciOiJFUzI1NiIsImp3ayI6eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6IjhyaFRhVElJMHRzY1MyX2QtWUNYRm92RGpRUkxEUTEzbWhHV3d5UTBibWMiLCJ5IjoiYmoyakNkSXkxU3lpcHBkU2lEWmxHZEhMUTR0TG40NjMzTFk2dUJHUWU1NCIsImFsZyI6IkVTMjU2IiwidXNlIjoic2lnIn0sInR5cCI6IkpXVCJ9.eyJzZXNzaW9uX2lkIjoiYTNkYjczYTctNzc3Zi00NzI2LTliZGUtNjBkMjEwOTJlNTFmIiwiYXV0aF90eXBlIjoiZ2VuZXJhdGVkcGFzc3dvcmQiLCJleHBpcnkiOlsyMDIyLDI2MCwyMTk5OCw2NTc4MDM0NjhdLCJ1dWlkIjoiMDAwMDAwMDAtMDAwMC0wMDAwLTAwMDAtMDAwMDAwMDAwMDAwIiwiZGlzcGxheW5hbWUiOiJTeXN0ZW0gQWRtaW5pc3RyYXRvciIsInNwbiI6ImFkbWluQGlkbS5jb3JlZm9ybS5jb20iLCJtYWlsX3ByaW1hcnkiOm51bGwsImxpbV91aWR4IjpmYWxzZSwibGltX3JtYXgiOjEyOCwibGltX3BtYXgiOjI1NiwibGltX2ZtYXgiOjMyfQ.Y9CeMWwGX4xS4O2Yy9vlTjW-6dL_Ncoo-nWd2344O_SwWdBneDpUE35aA_kuLRg1ssVceyVvCDhlxYOyXwzAjQ"
        )
            .expect("Invalid jwsu");

        let _claims: std::collections::BTreeMap<String, serde_json::value::Value> = jwsu
            .validate_embeded()
            .expect("Failed to verify")
            .into_inner();
    }
}
