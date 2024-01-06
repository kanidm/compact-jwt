use crate::compact::{EcCurve, JweAlg, JweCompact, JweProtectedHeader, Jwk};
use crate::jwe::Jwe;
use crate::traits::*;
use crate::JwtError;

use super::a128kw::{self, JweA128KWEncipher};

use base64urlsafedata::Base64UrlSafeData;

use openssl::bn;
use openssl::ec::{EcGroup, EcKey};
use openssl::nid::Nid;
use openssl::pkey::{PKey, PKeyRef, Private, Public};
use openssl::pkey_ctx::PkeyCtx;

const COORD_SIZE: usize = 32;

/// An ephemeral private key that can create enciphered JWE's. This type must only be used *once*.
pub struct JweEcdhEsA128KWEncipher {
    priv_key: PKey<Private>,
    peer_public_key: PKey<Public>,
}

impl JweEncipherOuter for JweEcdhEsA128KWEncipher {
    fn set_header_alg(&self, hdr: &mut JweProtectedHeader) -> Result<(), JwtError> {
        hdr.alg = JweAlg::ECDH_ES_A128KW;

        // Set epk to the public jwk of the outer encipher here.
        let ec_key = self.priv_key.ec_key().map_err(|e| {
            debug!(?e);
            JwtError::OpenSSLError
        })?;

        let pkey = ec_key.public_key();
        let ec_group = ec_key.group();

        let mut bnctx = bn::BigNumContext::new().map_err(|e| {
            debug!(?e);
            JwtError::OpenSSLError
        })?;

        let mut xbn = bn::BigNum::new().map_err(|e| {
            debug!(?e);
            JwtError::OpenSSLError
        })?;

        let mut ybn = bn::BigNum::new().map_err(|e| {
            debug!(?e);
            JwtError::OpenSSLError
        })?;

        pkey.affine_coordinates_gfp(ec_group, &mut xbn, &mut ybn, &mut bnctx)
            .map_err(|e| {
                debug!(?e);
                JwtError::OpenSSLError
            })?;

        let mut public_key_x = vec![0; COORD_SIZE];
        let mut public_key_y = vec![0; COORD_SIZE];

        let xbnv = xbn.to_vec();
        let ybnv = ybn.to_vec();

        let (_pad, x_fill) = public_key_x.split_at_mut(COORD_SIZE - xbnv.len());
        x_fill.copy_from_slice(&xbnv);

        let (_pad, y_fill) = public_key_y.split_at_mut(COORD_SIZE - ybnv.len());
        y_fill.copy_from_slice(&ybnv);

        hdr.epk = Some(Jwk::EC {
            crv: EcCurve::P256,
            x: Base64UrlSafeData(public_key_x),
            y: Base64UrlSafeData(public_key_y),
            alg: None,
            use_: None,
            kid: None,
        });

        Ok(())
    }

    fn wrap_key(&self, key_to_wrap: &[u8]) -> Result<Vec<u8>, JwtError> {
        if key_to_wrap.len() > a128kw::KEY_LEN {
            debug!(
                "Unable to wrap key - key to wrap is longer than the wrapping key {} > {}",
                key_to_wrap.len(),
                a128kw::KEY_LEN
            );
            return Err(JwtError::InvalidKey);
        }

        derive_key(&self.priv_key, &self.peer_public_key).and_then(|wrapping_key|
                // use A128KW with the derived wrap key as usual.
                JweA128KWEncipher::from(wrapping_key)
                    .wrap_key(key_to_wrap))
    }
}

impl JweEcdhEsA128KWEncipher {
    /// Generate a one-time private key pair used to derive a shared secret for the provided
    /// public key.
    pub fn generate_ephemeral(peer_public_key: PKey<Public>) -> Result<Self, JwtError> {
        // Create a new private key for one-shot derivation to this peer.
        let ec_key = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)
            .and_then(|group| EcKey::generate(&group))
            .map_err(|ossl_err| {
                debug!(?ossl_err);
                JwtError::OpenSSLError
            })?;

        let priv_key = PKey::from_ec_key(ec_key).map_err(|ossl_err| {
            debug!(?ossl_err);
            JwtError::OpenSSLError
        })?;

        Ok(JweEcdhEsA128KWEncipher {
            priv_key,
            peer_public_key,
        })
    }

    /// Given a JWE, encipher it's content to a compact form.
    pub fn encipher<E: JweEncipherInner>(&self, jwe: &Jwe) -> Result<JweCompact, JwtError> {
        let encipher = E::new_ephemeral()?;
        encipher.encipher_inner(self, jwe)
    }
}

/// A Private Key that can recieve enciphered JWE's. The Encipher will use an ephemeral key
/// for key agreement with this deciphers public key.
pub struct JweEcdhEsA128KWDecipher {
    priv_key: PKey<Private>,
}

impl JweEcdhEsA128KWDecipher {
    /// Generate a private/public key pair that others can wrap content to. This keypair *may*
    /// be long lived.
    pub fn generate() -> Result<Self, JwtError> {
        let ec_key = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)
            .and_then(|group| EcKey::generate(&group))
            .map_err(|ossl_err| {
                debug!(?ossl_err);
                JwtError::OpenSSLError
            })?;

        let priv_key = PKey::from_ec_key(ec_key).map_err(|ossl_err| {
            debug!(?ossl_err);
            JwtError::OpenSSLError
        })?;

        Ok(JweEcdhEsA128KWDecipher { priv_key })
    }

    /// Retrieve the public key of this decipher. This should be sent to the encipher
    /// to use with it's ephemeral key for key agreement
    pub fn public_key(&self) -> Result<PKey<Public>, JwtError> {
        self.priv_key
            .ec_key()
            .and_then(|ec_key| {
                let public = ec_key.public_key();
                let ecgroup = ec_key.group();

                EcKey::from_public_key(ecgroup, public)
            })
            .and_then(|ec_public: EcKey<Public>| PKey::from_ec_key(ec_public))
            .map_err(|ossl_err| {
                debug!(?ossl_err);
                JwtError::OpenSSLError
            })
    }

    /// Given a JWE in compact form, decipher and authenticate it's content.
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
                let curve = Nid::X9_62_PRIME256V1;
                let ec_group = EcGroup::from_curve_name(curve).map_err(|e| {
                    debug!(?e);
                    JwtError::OpenSSLError
                })?;

                let xbn = bn::BigNum::from_slice(&x.0).map_err(|e| {
                    debug!(?e);
                    JwtError::OpenSSLError
                })?;
                let ybn = bn::BigNum::from_slice(&y.0).map_err(|e| {
                    debug!(?e);
                    JwtError::OpenSSLError
                })?;

                let ec_pkey = EcKey::from_public_key_affine_coordinates(&ec_group, &xbn, &ybn)
                    .map_err(|e| {
                        debug!(?e);
                        JwtError::OpenSSLError
                    })?;

                ec_pkey.check_key().map_err(|e| {
                    debug!(?e);
                    JwtError::OpenSSLError
                })?;

                PKey::from_ec_key(ec_pkey).map_err(|e| {
                    debug!(?e);
                    JwtError::OpenSSLError
                })?
            }
            _ => {
                error!("Invalid JWK in epk");
                return Err(JwtError::InvalidKey);
            }
        };

        derive_key(&self.priv_key, &ephemeral_public_key).and_then(|wrapping_key|
                // use A128KW with the derived wrap key as usual.
                JweA128KWEncipher::from(wrapping_key)
                    .decipher(jwec))
    }
}

fn derive_key(
    priv_key: &PKeyRef<Private>,
    pub_key: &PKeyRef<Public>,
) -> Result<[u8; a128kw::KEY_LEN], JwtError> {
    // derive the wrap key.
    let mut priv_key_ctx = PkeyCtx::new(priv_key).map_err(|ossl_err| {
        debug!(?ossl_err);
        JwtError::OpenSSLError
    })?;

    priv_key_ctx.derive_init().map_err(|ossl_err| {
        debug!(?ossl_err);
        JwtError::OpenSSLError
    })?;

    priv_key_ctx.derive_set_peer(pub_key).map_err(|ossl_err| {
        debug!(?ossl_err);
        JwtError::OpenSSLError
    })?;

    let mut wrapping_key = [0; a128kw::KEY_LEN];

    priv_key_ctx
        .derive(Some(&mut wrapping_key))
        .map_err(|ossl_err| {
            debug!(?ossl_err);
            JwtError::OpenSSLError
        })?;

    Ok(wrapping_key)
}

#[cfg(test)]
mod tests {
    use super::{JweEcdhEsA128KWDecipher, JweEcdhEsA128KWEncipher};
    use crate::crypto::a128gcm::JweA128GCMEncipher;
    use crate::jwe::JweBuilder;

    #[test]
    fn ecdh_a128kw_outer_a128gcm_inner() {
        let _ = tracing_subscriber::fmt::try_init();

        let input = vec![1; 256];
        let jweb = JweBuilder::from(input.clone()).build();

        // Create a new decipher from a private key.

        let jwe_ecds_a128_de =
            JweEcdhEsA128KWDecipher::generate().expect("Unable to create ecdh es128 decipher");

        let public_key = jwe_ecds_a128_de.public_key().unwrap();

        let jwe_ecds_a128_en = JweEcdhEsA128KWEncipher::generate_ephemeral(public_key)
            .expect("Unable to build wrap key.");

        let jwe_encrypted = jwe_ecds_a128_en
            .encipher::<JweA128GCMEncipher>(&jweb)
            .expect("Unable to encrypt.");

        // Decrypt with the partner.
        let decrypted = jwe_ecds_a128_de
            .decipher(&jwe_encrypted)
            .expect("Unable to decrypt.");

        assert_eq!(decrypted.payload(), input);
    }
}
