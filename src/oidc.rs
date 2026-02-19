//! Oidc token implementation

use crate::compact::{JwaAlg, Jwk, JwsCompact, JwsCompactVerifyData};
use crate::jws::{Jws, JwsCompactSign2Data, JwsSigned};

use crate::traits::{JwsSignable, JwsVerifiable};

use crate::error::JwtError;
use crate::{btreemap_empty, vec_empty};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;
use time::OffsetDateTime;
use time::{macros::format_description, Date};
use url::Url;
use uuid::Uuid;

/// An unverified token input which is ready to validate
pub struct OidcUnverified {
    jwsc: JwsCompact,
}

/// An verified token that is awaiting expiry verification
pub struct OidcExpUnverified {
    oidc: OidcToken,
}

/// A signed oidc token which can be converted to a string.
pub struct OidcSigned {
    jws: JwsSigned,
}

#[derive(Debug, Serialize, Clone, Deserialize, PartialEq)]
#[serde(untagged)]
/// The subject of the oidc token. This is intended to be a unique identifier which is
/// why we have special handling for a number of possible unique formats.
pub enum OidcSubject {
    /// A uuid of the subject.
    U(Uuid),
    /// An arbitrary string
    S(String),
}

impl fmt::Display for OidcSubject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OidcSubject::U(u) => write!(f, "{u}"),
            OidcSubject::S(s) => write!(f, "{s}"),
        }
    }
}

/// Standardised or common claims that are used in oidc.
/// `https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims`
#[derive(Debug, Serialize, Clone, Deserialize, PartialEq, Default)]
pub struct OidcClaims {
    /// The scopes assigned to this token
    #[serde(skip_serializing_if = "vec_empty", default)]
    pub scopes: Vec<String>,
    /// This is equivalent to a display name, and how the user wishes to be seen or known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The displayed username. Ie claire or c.example
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preferred_username: Option<String>,
    /// email - the primary mail address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// If the email has been validated.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
    /// The users timezone
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zoneinfo: Option<String>,
    /// The users locale
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locale: Option<String>,

    /// Given name(s) or first name(s) of the End-User. Note that in some cultures, people can have multiple given names; all can be present, with the names being separated by space characters.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub given_name: Option<String>,

    /// Surname(s) or last name(s) of the End-User. Note that in some cultures, people can have multiple family names or no family name; all can be present, with the names being separated by space characters.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub family_name: Option<String>,

    /// Middle name(s) of the End-User. Note that in some cultures, people can have multiple middle names; all can be present, with the names being separated by space characters. Also note that in some cultures, middle names are not used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub middle_name: Option<String>,

    /// Casual name of the End-User that may or may not be the same as the given_name. For instance, a nickname value of Mike might be returned alongside a given_name value of Michael.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nickname: Option<String>,

    /// URL of the End-User's profile page. The contents of this Web page SHOULD be about the End-User.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<Url>,

    /// URL of the End-User's profile picture. This URL MUST refer to an image file (for example, a PNG, JPEG, or GIF image file), rather than to a Web page containing an image. Note that this URL SHOULD specifically reference a profile photo of the End-User suitable for displaying when describing the End-User, rather than an arbitrary photo taken by the End-User.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub picture: Option<Url>,

    /// URL of the End-User's Web page or blog. This Web page SHOULD contain information published by the End-User or an organization that the End-User is affiliated with.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub website: Option<Url>,

    /// End-User's birthday, represented as an [ISO 8601-1](https://openid.net/specs/openid-connect-core-1_0.html#ISO8601-1). Date and time - Representations for information interchange - Part 1: Basic rules,” October 2022. ISO8601‑1 YYYY-MM-DD format. The year MAY be 0000, indicating that it is omitted. To represent only the year, YYYY format is allowed. Note that depending on the underlying platform's date related function, providing just year can result in varying month and day, so the implementers need to take this factor into account to correctly process the dates.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub birthdate: Option<OidcDate>,

    /// End-User's preferred telephone number. [E.164](https://openid.net/specs/openid-connect-core-1_0.html#E.164) is RECOMMENDED as the format of this Claim, for example, +1 (425) 555-1212 or +56 (2) 687 2400. If the phone number contains an extension, it is RECOMMENDED that the extension be represented using the RFC 3966 [RFC3966](https://openid.net/specs/openid-connect-core-1_0.html#RFC3966) extension syntax, for example, +1 (604) 555-1234;ext=5678.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone_number: Option<String>,

    /// True if the End-User's phone number has been verified; otherwise false. When this Claim Value is true, this means that the OP took affirmative steps to ensure that this phone number was controlled by the End-User at the time the verification was performed. The means by which a phone number is verified is context specific, and dependent upon the trust framework or contractual agreements within which the parties are operating. When true, the phone_number Claim MUST be in E.164 format and any extensions MUST be represented in RFC 3966 format.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone_number_verified: Option<bool>,

    /// End-User's preferred postal address. The value of the address member is a JSON [RFC8259] structure containing some or all of the members defined in [Section 5.1.1](https://openid.net/specs/openid-connect-core-1_0.html#AddressClaim).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<OidcAddress>,

    /// Time the End-User's information was last updated. Its value is a JSON number representing the number of seconds from 1970-01-01T00:00:00Z as measured in UTC until the date/time.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "time::serde::timestamp::option"
    )]
    pub updated_at: Option<OffsetDateTime>,

    /// End-User's gender. Values defined by this specification are `female` and `male`. Other values MAY be used when neither of the defined values are applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gender: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
/// An OIDC date which can either be a full date, or just a year.
pub enum OidcDate {
    /// A full date
    Date(Date),
    /// A year only
    Year(u16),
}

impl<'de> Deserialize<'de> for OidcDate {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s: String = Deserialize::deserialize(deserializer)?;
        if s.len() == 4 {
            let year: u16 = s.parse().map_err(serde::de::Error::custom)?;
            Ok(OidcDate::Year(year))
        } else {
            let date = Date::parse(&s, format_description!("[year]-[month]-[day]"))
                .map_err(serde::de::Error::custom)?;
            Ok(OidcDate::Date(date))
        }
    }
}

impl Serialize for OidcDate {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            OidcDate::Date(d) => serializer.serialize_str(format!("{}", &d).as_str()),
            OidcDate::Year(y) => serializer.serialize_str(&format!("{:04}", y)),
        }
    }
}

/// From <https://openid.net/specs/openid-connect-core-1_0.html#AddressClaim>
/// The Address Claim represents a physical mailing address. Implementations MAY return only a subset of the fields of an address, depending upon the information available and the End-User's privacy preferences. For example, the country and region might be returned without returning more fine-grained address information.
///
/// Implementations MAY return just the full address as a single string in the formatted sub-field, or they MAY return just the individual component fields using the other sub-fields, or they MAY return both. If both variants are returned, they SHOULD represent the same address, with the formatted address indicating how the component fields are combined.
#[derive(Debug, Serialize, Clone, Deserialize, PartialEq, Default)]
pub struct OidcAddress {
    /// Full mailing address, formatted for display or use on a mailing label. This field MAY contain multiple lines, separated by newlines. Newlines can be represented either as a carriage return/line feed pair ("\r\n") or as a single line feed character ("\n").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub formatted: Option<String>,
    /// Full street address component, which MAY include house number, street name, Post Office Box, and multi-line extended street address information. This field MAY contain multiple lines, separated by newlines. Newlines can be represented either as a carriage return/line feed pair ("\r\n") or as a single line feed character ("\n").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub street_address: Option<String>,
    /// City or locality component.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locality: Option<String>,
    /// State, province, prefecture, or region component.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    /// Zip code or postal code component.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub postal_code: Option<String>,
    /// Country name component.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
}

/// An Oidc Token that is being created, or has succeeded in being validated
#[derive(Debug, Serialize, Clone, Deserialize, PartialEq)]
pub struct OidcToken {
    /// Case sensitive URL.
    pub iss: Url,
    /// Unique id of the subject
    pub sub: OidcSubject,
    /// client_id of the oauth2 rp
    pub aud: String,
    /// Expiry in utc epoch seconds
    pub exp: i64,
    /// Not valid before.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<i64>,
    /// Issued at time.
    pub iat: i64,
    /// Time when the user originally authenticated.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_time: Option<i64>,
    /// Comes from authn req
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    /// -- not used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub at_hash: Option<String>,
    /// -- not used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acr: Option<String>,
    /// List of auth methods
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amr: Option<Vec<String>>,
    /// Do not use.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub azp: Option<String>,
    /// -- not used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    /// Standardised or common claims
    #[serde(flatten)]
    pub s_claims: OidcClaims,
    /// Arbitrary custom claims can be inserted or decoded here.
    #[serde(flatten, skip_serializing_if = "btreemap_empty")]
    pub claims: BTreeMap<String, serde_json::value::Value>,
}

impl JwsSignable for OidcToken {
    type Signed = OidcSigned;

    fn data(&self) -> Result<JwsCompactSign2Data, JwtError> {
        let mut jwts = Jws::into_json(self).map_err(|err| {
            debug!(?err, "Failed to serialise OIDC token");
            JwtError::InvalidJwt
        })?;

        jwts.set_typ(Some("JWT"));

        jwts.data()
    }

    fn post_process(&self, jwsc: JwsCompact) -> Result<Self::Signed, JwtError> {
        Ok(OidcSigned {
            jws: JwsSigned { jwsc },
        })
    }
}

impl OidcUnverified {
    /// Get the embedded public key used to sign this jwt, if present.
    pub fn get_jwk_pubkey(&self) -> Option<&Jwk> {
        self.jwsc.get_jwk_pubkey()
    }
}

impl FromStr for OidcUnverified {
    type Err = JwtError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        JwsCompact::from_str(s).map(|jwsc| OidcUnverified { jwsc })
    }
}

impl JwsVerifiable for OidcUnverified {
    type Verified = OidcExpUnverified;

    fn data(&self) -> JwsCompactVerifyData<'_> {
        self.jwsc.data()
    }

    fn alg(&self) -> JwaAlg {
        self.jwsc.alg()
    }

    fn kid(&self) -> Option<&str> {
        self.jwsc.kid()
    }

    fn post_process(&self, value: Jws) -> Result<Self::Verified, JwtError> {
        let oidc: OidcToken = value.from_json().map_err(|err| {
            debug!(?err, "Failed to deserialise OIDC token");
            JwtError::InvalidJwt
        })?;
        Ok(OidcExpUnverified { oidc })
    }
}

impl OidcExpUnverified {
    /// Verify the expiry of this OIDC Token. The token at this point has passed cryptographic
    /// verification, and should have it's expiry validated.
    ///
    /// curtime represents the current time in seconds since the unix epoch.
    ///
    /// A curtime of `0` means that the exp will not be checked. This is not recommended.
    pub fn verify_exp(self, curtime: i64) -> Result<OidcToken, JwtError> {
        if self.oidc.exp != 0 && self.oidc.exp < curtime {
            Err(JwtError::OidcTokenExpired)
        } else {
            Ok(self.oidc)
        }
    }
}

impl OidcSigned {
    /// Invalidate this signed oidc token, causing it to require validation before you can use it
    /// again.
    pub fn invalidate(self) -> OidcUnverified {
        OidcUnverified {
            jwsc: self.jws.jwsc,
        }
    }
}

impl fmt::Display for OidcSigned {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.jws.fmt(f)
    }
}

impl fmt::Display for OidcUnverified {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.jwsc.fmt(f)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::crypto::JwsEs256Signer;
    use crate::oidc::OidcAddress;
    use crate::traits::{JwsSigner, JwsSignerToVerifier, JwsVerifier};
    use crate::OidcClaims;
    use time::OffsetDateTime;
    use url::Url;

    #[test]
    fn test_sign_and_validate() {
        let _ = tracing_subscriber::fmt::try_init();
        let jwt = OidcToken {
            iss: Url::parse("https://oidc.example.com").expect("Failed to parse URL"),
            sub: OidcSubject::S("a unique id".to_string()),
            aud: "test".to_string(),
            exp: 0,
            nbf: Some(0),
            iat: 0,
            auth_time: None,
            nonce: None,
            at_hash: None,
            acr: None,
            amr: None,
            azp: None,
            jti: None,
            s_claims: Default::default(),
            claims: Default::default(),
        };

        debug!(?jwt);

        let jws_es256_signer =
            JwsEs256Signer::generate_es256().expect("failed to construct signer.");
        let jwk_es256_verifier = jws_es256_signer
            .get_verifier()
            .expect("failed to get verifier from signer");

        let jwts = jws_es256_signer.sign(&jwt).expect("failed to sign jwt");

        debug!(%jwts);

        let jwtu = jwts.invalidate();

        debug!(%jwtu);

        let released = jwk_es256_verifier
            .verify(&jwtu)
            .expect("Unable to validate jwt")
            .verify_exp(0)
            .expect("Unable to validate oidc exp");

        assert!(released == jwt);
    }

    #[test]
    fn test_serde_oidc_claims() {
        let _ = tracing_subscriber::fmt::try_init();
        let updated_at = Some(OffsetDateTime::UNIX_EPOCH + Duration::from_hours(1));
        dbg!(&updated_at);
        let claims = OidcClaims {
            scopes: vec!["openid".to_string(), "email".to_string()],
            name: None,
            preferred_username: None,
            email: None,
            email_verified: None,
            zoneinfo: None,
            locale: None,
            given_name: None,
            family_name: None,
            middle_name: None,
            nickname: None,
            profile: None,
            picture: None,
            website: None,
            birthdate: None,
            phone_number: None,
            phone_number_verified: Some(false),
            address: Some(OidcAddress {
                formatted: Some("123 Test St\nTestville".to_string()),
                street_address: None,
                locality: None,
                region: None,
                postal_code: None,
                country: None,
            }),
            updated_at,
            gender: Some("Test".to_string()),
        };
        let ser = serde_json::to_string_pretty(&claims).expect("Failed to serialise claims");
        tracing::info!("Serialized claims: {}", ser);
        assert!(
            !ser.contains(r#""updated_at": ["#),
            "updated_at should be a number not an array"
        );
        assert!(ser.contains(r#""updated_at": 3600,"#));
        assert!(!ser.contains("region"));
    }

    #[test]
    fn test_serialize_oidc_date() {
        let d1 = OidcDate::Date(
            Date::parse("1980-05-12", format_description!("[year]-[month]-[day]"))
                .expect("Failed to parse date"),
        );
        let s1 = serde_json::to_string(&d1).expect("Failed to serialise to JSON");
        assert_eq!(s1, "\"1980-05-12\"");

        let d2 = OidcDate::Year(1995);
        let s2 = serde_json::to_string(&d2).expect("Failed to serialise to JSON");
        assert_eq!(s2, "\"1995\"");
    }
}
