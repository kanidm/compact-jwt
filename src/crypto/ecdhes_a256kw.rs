use crate::compact::{EcCurve, JweAlg, JweCompact, JweProtectedHeader, Jwk};
use crate::jwe::Jwe;
use crate::traits::*;
use crate::JwtError;

use super::a256kw::JweA256KWEncipher;
use crypto_glue::{
    aes256::Aes256Key,
    aes256kw::Aes256KwWrapped,
    traits::FromEncodedPoint,
    ecdh_p256::{
        self,
        EcdhP256EphemeralSecret,
        EcdhP256Hkdf,
        EcdhP256PublicEncodedPoint,
        EcdhP256PublicKey,
        EcdhP256FieldBytes,
    },
};

/// An ephemeral private key that can create enciphered JWE's. This type must only be used *once*.
pub struct JweEcdhEsA256KWEncipher {
    priv_key: EcdhP256EphemeralSecret,
    peer_public_key: EcdhP256PublicKey,
}

impl JweEncipherOuterA256 for JweEcdhEsA256KWEncipher {
    fn set_header_alg(&self, hdr: &mut JweProtectedHeader) -> Result<(), JwtError> {
        hdr.alg = JweAlg::ECDH_ES_A256KW;

        let pub_key = self.priv_key.public_key();

        let encoded_point = EcdhP256PublicEncodedPoint::from(pub_key);

        let public_key_x = encoded_point
            .x()
            .map(|bytes| bytes.to_vec())
            .unwrap_or_default();

        let public_key_y = encoded_point
            .y()
            .map(|bytes| bytes.to_vec())
            .unwrap_or_default();

        hdr.epk = Some(Jwk::EC {
            crv: EcCurve::P256,
            x: public_key_x.into(),
            y: public_key_y.into(),
            alg: None,
            use_: None,
            kid: None,
        });

        Ok(())
    }

    fn wrap_key(&self, key_to_wrap: Aes256Key) -> Result<Aes256KwWrapped, JwtError> {
        let wrapping_key = derive_key(&self.priv_key, &self.peer_public_key)?;
        JweA256KWEncipher::from(wrapping_key).wrap_key(key_to_wrap)
    }
}

impl JweEcdhEsA256KWEncipher {
    /// Generate a one-time private key pair used to derive a shared secret for the provided
    /// public key.
    pub fn generate_ephemeral(peer_public_key: EcdhP256PublicKey) -> Result<Self, JwtError> {
        let priv_key = ecdh_p256::new_secret();

        Ok(JweEcdhEsA256KWEncipher {
            priv_key,
            peer_public_key,
        })
    }

    /// Given a JWE, encipher its content to a compact form.
    pub fn encipher<E: JweEncipherInnerA256 + JweEncipherInnerA256>(
        &self,
        jwe: &Jwe,
    ) -> Result<JweCompact, JwtError> {
        let encipher = E::new_ephemeral()?;
        encipher.encipher_inner(self, jwe)
    }
}

/// A Private Key that can recieve enciphered JWE's. The Encipher will use an ephemeral key
/// for key agreement with this deciphers public key.
pub struct JweEcdhEsA256KWDecipher {
    priv_key: EcdhP256EphemeralSecret,
}

impl JweEcdhEsA256KWDecipher {
    /// Generate a private/public key pair that others can wrap content to. This keypair *may*
    /// be long lived.
    pub fn generate() -> Result<Self, JwtError> {
        let priv_key = ecdh_p256::new_secret();

        Ok(JweEcdhEsA256KWDecipher { priv_key })
    }

    /// Retrieve the public key of this decipher. This should be sent to the encipher
    /// to use with its ephemeral key for key agreement
    pub fn public_key(&self) -> Result<EcdhP256PublicKey, JwtError> {
        Ok(self.priv_key.public_key())
    }

    /// Given a JWE in compact form, decipher and authenticate its content.
    pub fn decipher(&self, jwec: &JweCompact) -> Result<Jwe, JwtError> {
        // Derive the shared secret from our private key + the JWE header public key.

        // Get the epk - if not set, error.
        let Some(epk_jwk) = &jwec.header.epk else {
            error!("epk not found in header, unable to proceed");
            return Err(JwtError::CriticalMissingHeaderValue);
        };

        let ephemeral_public_key = match epk_jwk {
            Jwk::EC {
                crv: EcCurve::P256,
                x,
                y,
                alg: _,
                use_: _,
                kid: _,
            } => {
                let mut field_x = EcdhP256FieldBytes::default();
                if x.len() != field_x.len() {
                    debug!("x field len error");
                    return Err(JwtError::CryptoError);
                }

                let mut field_y = EcdhP256FieldBytes::default();
                if y.len() != field_y.len() {
                    debug!("y field len error");
                    return Err(JwtError::CryptoError);
                }

                field_x.copy_from_slice(x);
                field_y.copy_from_slice(y);

                let encoded_point =
                    EcdhP256PublicEncodedPoint::from_affine_coordinates(&field_x, &field_y, false);

                let pub_key = EcdhP256PublicKey::from_encoded_point(&encoded_point)
                    .into_option()
                    .ok_or_else(|| {
                        debug!("invalid encoded point");
                        JwtError::CryptoError
                    })?;

                pub_key
            }
            _ => {
                error!("Invalid JWK in epk");
                return Err(JwtError::InvalidKey);
            }
        };

        derive_key(&self.priv_key, &ephemeral_public_key)
            .and_then(|wrapping_key| JweA256KWEncipher::from(wrapping_key).decipher(jwec))
    }
}

fn derive_key(
    priv_key: &EcdhP256EphemeralSecret,
    pub_key: &EcdhP256PublicKey,
) -> Result<Aes256Key, JwtError> {

    let shared_secret = priv_key.diffie_hellman(pub_key);

    let mut new_key = Aes256Key::default();

    let kdf: EcdhP256Hkdf = shared_secret.extract(None);

    kdf.expand(&[], &mut new_key)
        .map_err(|err| {
            debug!(?err);
            JwtError::CryptoError
        })?;

    Ok(new_key)
}

#[cfg(test)]
mod tests {
    use super::{JweEcdhEsA256KWDecipher, JweEcdhEsA256KWEncipher};
    use crate::crypto::a256gcm::JweA256GCMEncipher;
    use crate::jwe::JweBuilder;

    #[test]
    fn ecdh_a256kw_outer_a256gcm_inner() {
        let _ = tracing_subscriber::fmt::try_init();

        let input = vec![1; 256];
        let jweb = JweBuilder::from(input.clone()).build();

        // Create a new decipher from a private key.

        let jwe_ecds_a256_de =
            JweEcdhEsA256KWDecipher::generate().expect("Unable to create ecdh es256 decipher");

        let public_key = jwe_ecds_a256_de.public_key().unwrap();

        let jwe_ecds_a256_en = JweEcdhEsA256KWEncipher::generate_ephemeral(public_key)
            .expect("Unable to build wrap key.");

        let jwe_encrypted = jwe_ecds_a256_en
            .encipher::<JweA256GCMEncipher>(&jweb)
            .expect("Unable to encrypt.");

        // Decrypt with the partner.
        let decrypted = jwe_ecds_a256_de
            .decipher(&jwe_encrypted)
            .expect("Unable to decrypt.");

        assert_eq!(decrypted.payload(), input);
    }
}
