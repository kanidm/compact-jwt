use openssl::{bn, ec, ecdsa, hash, nid, pkey, rand, rsa, sign, x509};
use std::convert::TryFrom;

use base64::{engine::general_purpose, Engine as _};

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use url::Url;

use crate::error::JwtError;
use base64urlsafedata::Base64UrlSafeData;

use crate::compact::{EcCurve, JwaAlg, Jwk, JwkUse, JwsCompact, ProtectedHeader};
use crate::jws::Jws;
use crate::traits::*;

const RSA_MIN_SIZE: u32 = 3072;
const RSA_SIG_SIZE: i32 = 384;

impl JwsCompact {
    #[cfg(test)]
    fn check_vectors(&self, chk_input: &[u8], chk_sig: &[u8]) -> bool {
        let sign_input = format!("{}.{}", self.hdr_b64, self.payload_b64);
        chk_input == sign_input.as_bytes() && chk_sig == &self.signature
    }

    /// The chain starts from the signing leaf and proceeds up the ca chain
    /// toward the root.
    ///
    /// return [Ok(None)] if the jws object's header's x5c field isn't populated
    pub fn get_x5c_chain(&self) -> Result<Option<Vec<x509::X509>>, JwtError> {
        let fullchain = match &self.header.x5c {
            Some(chain) => chain,
            None => return Ok(None),
        };

        let fullchain: Result<Vec<_>, _> = fullchain
            .iter()
            .map(|value| {
                general_purpose::STANDARD
                    .decode(value)
                    .map_err(|_| JwtError::InvalidBase64)
                    .and_then(|bytes| {
                        x509::X509::from_der(&bytes).map_err(|e| {
                            debug!(?e);
                            JwtError::OpenSSLError
                        })
                    })
            })
            .collect();

        let fullchain = fullchain?;

        Ok(Some(fullchain))
    }
}

impl JwsCompact {
    pub fn verify<K: JwsVerifier>(&self, verifier: &mut K) -> Result<Jws, JwtError> {
        if verifier.verify_signature(self)? {
            general_purpose::URL_SAFE_NO_PAD
                .decode(&self.payload_b64)
                .map_err(|_| {
                    debug!("invalid base64");
                    JwtError::InvalidBase64
                })
                .map(|payload| Jws {
                    header: self.header.clone(),
                    payload,
                })
        } else {
            debug!("invalid signature");
            Err(JwtError::InvalidSignature)
        }
    }
}

impl Jws {
    pub fn new(payload: Vec<u8>) -> Self {
        Jws {
            header: ProtectedHeader::default(),
            payload,
        }
    }

    pub fn set_kid(mut self, kid: String) -> Self {
        self.header.kid = Some(kid);
        self
    }

    pub fn set_typ(mut self, typ: String) -> Self {
        self.header.typ = Some(typ);
        self
    }

    #[allow(dead_code)]
    pub fn set_cty(mut self, cty: String) -> Self {
        self.header.cty = Some(cty);
        self
    }

    pub fn sign<S: JwsSigner>(&self, signer: &mut S) -> Result<JwsCompact, JwtError> {
        let mut header = self.header.clone();

        // Let the signer update the header as required.
        signer.update_header(&mut header);

        // TODO: Future, we can tell the signer to have options like embeding
        // the jwk or the uri.

        let hdr_b64 = serde_json::to_vec(&header)
            .map_err(|e| {
                debug!(?e);
                JwtError::InvalidHeaderFormat
            })
            .map(|bytes| general_purpose::URL_SAFE_NO_PAD.encode(&bytes))?;
        let payload_b64 = general_purpose::URL_SAFE_NO_PAD.encode(&self.payload);

        let data = JwsCompactSignData {
            hdr_bytes: hdr_b64.as_bytes(),
            payload_bytes: payload_b64.as_bytes(),
        };

        let signature = signer.sign(data)?;

        Ok(JwsCompact {
            header,
            hdr_b64,
            payload_b64,
            signature,
        })
    }
}

pub struct JwsEs256Signer {
    /// If the public jwk should be embeded during signing
    sign_option_embed_jwk: bool,
    /// The KID of this validator
    kid: String,
    /// Private Key
    skey: ec::EcKey<pkey::Private>,
    /// The matching digest.
    digest: hash::MessageDigest,
}

impl JwsEs256Signer {
    #[cfg(test)]
    pub fn from_es256_jwk_components(x: &str, y: &str, d: &str) -> Result<Self, JwtError> {
        let x = general_purpose::URL_SAFE_NO_PAD.decode(x).map_err(|e| {
            debug!(?e);
            JwtError::InvalidBase64
        })?;
        let y = general_purpose::URL_SAFE_NO_PAD.decode(y).map_err(|e| {
            debug!(?e);
            JwtError::InvalidBase64
        })?;

        let d = general_purpose::URL_SAFE_NO_PAD.decode(d).map_err(|e| {
            debug!(?e);
            JwtError::InvalidBase64
        })?;

        let xbn = bn::BigNum::from_slice(&x).map_err(|e| {
            debug!(?e);
            JwtError::OpenSSLError
        })?;
        let ybn = bn::BigNum::from_slice(&y).map_err(|e| {
            debug!(?e);
            JwtError::OpenSSLError
        })?;
        let dbn = bn::BigNum::from_slice(&d).map_err(|e| {
            debug!(?e);
            JwtError::OpenSSLError
        })?;

        let ec_group = ec::EcGroup::from_curve_name(nid::Nid::X9_62_PRIME256V1).map_err(|e| {
            debug!(?e);
            JwtError::OpenSSLError
        })?;

        let pkey =
            ec::EcKey::from_public_key_affine_coordinates(&ec_group, &xbn, &ybn).map_err(|e| {
                debug!(?e);
                JwtError::OpenSSLError
            })?;

        let digest = hash::MessageDigest::sha256();

        let skey = ec::EcKey::from_private_components(&ec_group, &dbn, pkey.public_key()).map_err(
            |e| {
                debug!(?e);
                JwtError::OpenSSLError
            },
        )?;

        skey.check_key().map_err(|_| JwtError::OpenSSLError)?;

        let kid = skey
            .private_key_to_der()
            .and_then(|der| hash::hash(digest, &der))
            .map(|hashout| hex::encode(hashout))
            .map_err(|e| {
                debug!(?e);
                JwtError::OpenSSLError
            })?;

        Ok(JwsEs256Signer {
            kid,
            skey,
            digest,
            sign_option_embed_jwk: false,
        })
    }

    pub fn set_sign_option_embed_jwk(&mut self, value: bool) {
        self.sign_option_embed_jwk = value;
    }

    /// Create a new secure private key for signing
    pub fn generate_es256() -> Result<Self, JwtError> {
        let digest = hash::MessageDigest::sha256();
        let ec_group = ec::EcGroup::from_curve_name(nid::Nid::X9_62_PRIME256V1)
            .map_err(|_| JwtError::OpenSSLError)?;

        let skey = ec::EcKey::generate(&ec_group).map_err(|_| JwtError::OpenSSLError)?;

        skey.check_key().map_err(|_| JwtError::OpenSSLError)?;

        let kid = skey
            .private_key_to_der()
            .and_then(|der| hash::hash(digest, &der))
            .map(|hashout| hex::encode(hashout))
            .map_err(|_| JwtError::OpenSSLError)?;

        Ok(JwsEs256Signer {
            kid,
            skey,
            digest,
            sign_option_embed_jwk: false,
        })
    }

    /// Restore this JwsSignerEnum from a DER private key.
    pub fn from_es256_der(der: &[u8]) -> Result<Self, JwtError> {
        let digest = hash::MessageDigest::sha256();

        let kid = hash::hash(digest, der)
            .map(|hashout| hex::encode(hashout))
            .map_err(|e| {
                debug!(?e);
                JwtError::OpenSSLError
            })?;

        let skey = ec::EcKey::private_key_from_der(der).map_err(|e| {
            debug!(?e);
            JwtError::OpenSSLError
        })?;

        Ok(JwsEs256Signer {
            kid,
            skey,
            digest,
            sign_option_embed_jwk: false,
        })
    }

    /// Export this signer to a DER private key.
    pub fn private_key_to_der(&self) -> Result<Vec<u8>, JwtError> {
        self.skey.private_key_to_der().map_err(|e| {
            debug!(?e);
            JwtError::OpenSSLError
        })
    }

    pub fn public_key_as_jwk(&self) -> Result<Jwk, JwtError> {
        let pkey = self.skey.public_key();
        let ec_group = self.skey.group();

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

        let mut public_key_x = Vec::with_capacity(32);
        let mut public_key_y = Vec::with_capacity(32);

        public_key_x.resize(32, 0);
        public_key_y.resize(32, 0);

        let xbnv = xbn.to_vec();
        let ybnv = ybn.to_vec();

        let (_pad, x_fill) = public_key_x.split_at_mut(32 - xbnv.len());
        x_fill.copy_from_slice(&xbnv);

        let (_pad, y_fill) = public_key_y.split_at_mut(32 - ybnv.len());
        y_fill.copy_from_slice(&ybnv);

        Ok(Jwk::EC {
            crv: EcCurve::P256,
            x: Base64UrlSafeData(public_key_x),
            y: Base64UrlSafeData(public_key_y),
            alg: Some(JwaAlg::ES256),
            use_: Some(JwkUse::Sig),
            kid: Some(self.kid.clone()),
        })
    }
}

impl JwsSignerToVerifier for JwsEs256Signer {
    type Verifier = JwsEs256Verifier;

    fn get_verifier(&mut self) -> Result<Self::Verifier, JwtError> {
        ec::EcKey::from_public_key(self.skey.group(), self.skey.public_key())
            .map_err(|e| {
                debug!(?e);
                JwtError::OpenSSLError
            })
            .map_err(|_| JwtError::OpenSSLError)
            .map(|pkey| JwsEs256Verifier {
                kid: Some(self.kid.clone()),
                pkey,
                digest: self.digest,
            })
    }
}

impl JwsSigner for JwsEs256Signer {
    fn update_header(&mut self, header: &mut ProtectedHeader) -> Result<(), JwtError> {
        // Update the alg to match.
        header.alg = JwaAlg::ES256;

        header.kid = Some(self.kid.clone());

        // if were were asked to ember the jwk, do so now.
        if self.sign_option_embed_jwk {
            header.jwk = self.public_key_as_jwk().map(Some)?;
        }

        Ok(())
    }

    fn sign(&mut self, jwsc: JwsCompactSignData<'_>) -> Result<Vec<u8>, JwtError> {
        let mut hasher = hash::Hasher::new(self.digest).map_err(|e| {
            debug!(?e);
            JwtError::OpenSSLError
        })?;

        hasher
            .update(jwsc.hdr_bytes)
            .and_then(|_| hasher.update(".".as_bytes()))
            .and_then(|_| hasher.update(jwsc.payload_bytes))
            .map_err(|e| {
                debug!(?e);
                JwtError::OpenSSLError
            })?;

        let hashout = hasher.finish().map_err(|e| {
            debug!(?e);
            JwtError::OpenSSLError
        })?;

        let ec_sig = ecdsa::EcdsaSig::sign(&hashout, &self.skey).map_err(|e| {
            debug!(?e);
            JwtError::OpenSSLError
        })?;

        let mut r = [0; 32];
        let r_vec = ec_sig.r().to_vec();
        let (_left, right) = r.split_at_mut(32 - r_vec.len());
        right.copy_from_slice(r_vec.as_slice());
        let mut s = [0; 32];
        let s_vec = ec_sig.s().to_vec();
        let (_left, right) = s.split_at_mut(32 - s_vec.len());
        right.copy_from_slice(s_vec.as_slice());

        // trace!("r {:?}", r);
        // trace!("s {:?}", s);

        let mut signature = Vec::with_capacity(64);
        signature.extend_from_slice(&r);
        signature.extend_from_slice(&s);
        Ok(signature)
    }
}

pub struct JwsEs256Verifier {
    /// The KID of this validator
    kid: Option<String>,
    /// Public Key
    pkey: ec::EcKey<pkey::Public>,
    /// The matching digest.
    digest: hash::MessageDigest,
}

/*
impl TryFrom<x509::X509> for JwsEs256Verifier {
    type Error = JwtError;

    fn try_from(value: x509::X509) -> Result<Self, Self::Error> {
        let pkey = value.public_key().map_err(|e| {
            debug!(?e);
            JwtError::OpenSSLError
        })?;
        let digest = hash::MessageDigest::sha256();
        pkey.ec_key()
            .map(|pkey| JwsEs256Verifier {
                kid: None,
                pkey,
                digest,
            })
            .map_err(|e| {
                debug!(?e);
                JwtError::OpenSSLError
            })
    }
}
*/

impl TryFrom<&Jwk> for JwsEs256Verifier {
    type Error = JwtError;

    fn try_from(value: &Jwk) -> Result<Self, Self::Error> {
        match value {
            Jwk::EC {
                crv: EcCurve::P256,
                x,
                y,
                alg: _,
                use_: _,
                kid,
            } => {
                let curve = nid::Nid::X9_62_PRIME256V1;
                let digest = hash::MessageDigest::sha256();

                let ec_group = ec::EcGroup::from_curve_name(curve).map_err(|e| {
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

                let pkey = ec::EcKey::from_public_key_affine_coordinates(&ec_group, &xbn, &ybn)
                    .map_err(|e| {
                        debug!(?e);
                        JwtError::OpenSSLError
                    })?;

                pkey.check_key().map_err(|e| {
                    debug!(?e);
                    JwtError::OpenSSLError
                })?;

                let kid = kid.clone();

                Ok(JwsEs256Verifier { kid, pkey, digest })
            }
            alg_request => {
                debug!(?alg_request, "validator algorithm mismatch");
                Err(JwtError::ValidatorAlgMismatch)
            }
        }
    }
}

impl JwsVerifier for JwsEs256Verifier {
    fn verify_signature(&mut self, jwsc: &JwsCompact) -> Result<bool, JwtError> {
        if jwsc.header.alg != JwaAlg::ES256 {
            debug!(jwsc_alg = ?jwsc.header.alg, "validator algorithm mismatch");
            return Err(JwtError::ValidatorAlgMismatch);
        }

        if jwsc.signature.len() != 64 {
            return Err(JwtError::InvalidSignature);
        }

        let r = bn::BigNum::from_slice(&jwsc.signature[..32]).map_err(|e| {
            debug!(?e);
            JwtError::OpenSSLError
        })?;
        let s = bn::BigNum::from_slice(&jwsc.signature[32..64]).map_err(|e| {
            debug!(?e);
            JwtError::OpenSSLError
        })?;

        let sig = ecdsa::EcdsaSig::from_private_components(r, s).map_err(|e| {
            debug!(?e);
            JwtError::OpenSSLError
        })?;

        let mut hasher = hash::Hasher::new(self.digest).map_err(|e| {
            debug!(?e);
            JwtError::OpenSSLError
        })?;

        hasher
            .update(jwsc.hdr_b64.as_bytes())
            .and_then(|_| hasher.update(".".as_bytes()))
            .and_then(|_| hasher.update(jwsc.payload_b64.as_bytes()))
            .map_err(|e| {
                debug!(?e);
                JwtError::OpenSSLError
            })?;

        let hashout = hasher.finish().map_err(|e| {
            debug!(?e);
            JwtError::OpenSSLError
        })?;

        sig.verify(&hashout, &self.pkey).map_err(|e| {
            debug!(?e);
            JwtError::OpenSSLError
        })
    }
}

pub struct JwsRs256Signer {
    /// If the public jwk should be embeded during signing
    sign_option_embed_jwk: bool,
    /// The KID of this validator
    kid: String,
    /// Private Key
    skey: rsa::Rsa<pkey::Private>,
    /// The matching digest.
    digest: hash::MessageDigest,
}

impl JwsRs256Signer {
    pub fn set_sign_option_embed_jwk(&mut self, value: bool) {
        self.sign_option_embed_jwk = value;
    }

    /// Restore this JwsSignerEnum from a DER private key.
    pub fn from_rs256_der(der: &[u8]) -> Result<Self, JwtError> {
        let digest = hash::MessageDigest::sha256();

        let kid = hash::hash(digest, der)
            .map(|hashout| hex::encode(hashout))
            .map_err(|e| {
                debug!(?e);
                JwtError::OpenSSLError
            })?;

        let skey = rsa::Rsa::private_key_from_der(der).map_err(|e| {
            debug!(?e);
            JwtError::OpenSSLError
        })?;

        Ok(JwsRs256Signer {
            kid,
            skey,
            digest,
            sign_option_embed_jwk: false,
        })
    }

    /// Export this signer to a DER private key.
    pub fn private_key_to_der(&self) -> Result<Vec<u8>, JwtError> {
        self.skey.private_key_to_der().map_err(|e| {
            debug!(?e);
            JwtError::OpenSSLError
        })
    }

    /// Create a new legacy (RSA) private key for signing
    pub fn generate_legacy_rs256() -> Result<Self, JwtError> {
        let digest = hash::MessageDigest::sha256();

        let skey = rsa::Rsa::generate(RSA_MIN_SIZE).map_err(|_| JwtError::OpenSSLError)?;

        skey.check_key().map_err(|_| JwtError::OpenSSLError)?;

        let kid = skey
            .private_key_to_der()
            .and_then(|der| hash::hash(digest, &der))
            .map(|hashout| hex::encode(hashout))
            .map_err(|_| JwtError::OpenSSLError)?;

        Ok(JwsRs256Signer {
            kid,
            skey,
            digest,
            sign_option_embed_jwk: false,
        })
    }

    pub fn public_key_as_jwk(&self) -> Result<Jwk, JwtError> {
        let public_key_n = self.skey.n().to_vec_padded(RSA_SIG_SIZE).map_err(|e| {
            debug!(?e);
            JwtError::OpenSSLError
        })?;

        let public_key_e = self.skey.e().to_vec_padded(3).map_err(|e| {
            debug!(?e);
            JwtError::OpenSSLError
        })?;

        Ok(Jwk::RSA {
            n: Base64UrlSafeData(public_key_n),
            e: Base64UrlSafeData(public_key_e),
            alg: Some(JwaAlg::RS256),
            use_: Some(JwkUse::Sig),
            kid: Some(self.kid.clone()),
        })
    }
}

impl JwsSignerToVerifier for JwsRs256Signer {
    type Verifier = JwsRs256Verifier;

    fn get_verifier(&mut self) -> Result<Self::Verifier, JwtError> {
        todo!();
    }
}

impl JwsSigner for JwsRs256Signer {
    fn update_header(&mut self, header: &mut ProtectedHeader) -> Result<(), JwtError> {
        // Update the alg to match.
        header.alg = JwaAlg::RS256;

        header.kid = Some(self.kid.clone());

        // if were were asked to ember the jwk, do so now.
        if self.sign_option_embed_jwk {
            header.jwk = self.public_key_as_jwk().map(Some)?;
        }

        Ok(())
    }

    fn sign(&mut self, jwsc: JwsCompactSignData<'_>) -> Result<Vec<u8>, JwtError> {
        let key = pkey::PKey::from_rsa(self.skey.clone()).map_err(|e| {
            debug!(?e);
            JwtError::OpenSSLError
        })?;

        let mut signer = sign::Signer::new(self.digest, &key).map_err(|e| {
            debug!(?e);
            JwtError::OpenSSLError
        })?;

        signer.set_rsa_padding(rsa::Padding::PKCS1).map_err(|e| {
            debug!(?e);
            JwtError::OpenSSLError
        })?;

        signer
            .update(jwsc.hdr_bytes)
            .and_then(|_| signer.update(".".as_bytes()))
            .and_then(|_| signer.update(jwsc.payload_bytes))
            .map_err(|e| {
                debug!(?e);
                JwtError::OpenSSLError
            })?;

        signer.sign_to_vec().map_err(|e| {
            debug!(?e);
            JwtError::OpenSSLError
        })
    }
}

pub struct JwsRs256Verifier {
    /// The KID of this validator
    kid: Option<String>,
    /// Public Key
    pkey: rsa::Rsa<pkey::Public>,
    /// The matching digest.
    digest: hash::MessageDigest,
}

/*
impl TryFrom<x509::X509> for JwsRs256Verifier {
    type Error = JwtError;

    fn try_from(value: x509::X509) -> Result<Self, Self::Error> {
        let pkey = value.public_key().map_err(|e| {
            debug!(?e);
            JwtError::OpenSSLError
        })?;
        let digest = hash::MessageDigest::sha256();
        pkey.rsa()
            .map(|pkey| JwsRs256Verifier {
                kid: None,
                pkey,
                digest,
            })
            .map_err(|e| {
                debug!(?e);
                JwtError::OpenSSLError
            })
    }
}
*/

impl TryFrom<&Jwk> for JwsRs256Verifier {
    type Error = JwtError;

    fn try_from(value: &Jwk) -> Result<Self, Self::Error> {
        match value {
            Jwk::RSA {
                n,
                e,
                alg: _,
                use_: _,
                kid,
            } => {
                let digest = hash::MessageDigest::sha256();

                let nbn = bn::BigNum::from_slice(&n.0).map_err(|e| {
                    debug!(?e);
                    JwtError::OpenSSLError
                })?;
                let ebn = bn::BigNum::from_slice(&e.0).map_err(|e| {
                    debug!(?e);
                    JwtError::OpenSSLError
                })?;

                let pkey = rsa::Rsa::from_public_components(nbn, ebn).map_err(|e| {
                    debug!(?e);
                    JwtError::OpenSSLError
                })?;

                let kid = kid.clone();

                Ok(JwsRs256Verifier { kid, pkey, digest })
            }
            alg_request => {
                debug!(?alg_request, "validator algorithm mismatch");
                Err(JwtError::ValidatorAlgMismatch)
            }
        }
    }
}

impl JwsVerifier for JwsRs256Verifier {
    fn verify_signature(&mut self, jwsc: &JwsCompact) -> Result<bool, JwtError> {
        if jwsc.header.alg != JwaAlg::RS256 {
            debug!(jwsc_alg = ?jwsc.header.alg, "validator algorithm mismatch");
            return Err(JwtError::ValidatorAlgMismatch);
        }

        if jwsc.signature.len() < 256 {
            debug!("invalid signature length");
            return Err(JwtError::InvalidSignature);
        }

        let p = pkey::PKey::from_rsa(self.pkey.clone()).map_err(|e| {
            debug!(?e);
            JwtError::OpenSSLError
        })?;

        let mut verifier = sign::Verifier::new(self.digest, &p).map_err(|e| {
            debug!(?e);
            JwtError::OpenSSLError
        })?;

        verifier.set_rsa_padding(rsa::Padding::PKCS1).map_err(|e| {
            debug!(?e);
            JwtError::OpenSSLError
        })?;

        verifier
            .update(jwsc.hdr_b64.as_bytes())
            .and_then(|_| verifier.update(".".as_bytes()))
            .and_then(|_| verifier.update(jwsc.payload_b64.as_bytes()))
            .map_err(|e| {
                debug!(?e);
                JwtError::OpenSSLError
            })?;

        verifier.verify(&jwsc.signature).map_err(|e| {
            debug!(?e);
            JwtError::OpenSSLError
        })
    }
}

pub struct JwsHs256Signer {
    /// The KID of this signer. This is the sha256 digest of the key.
    kid: String,
    /// Private Key
    skey: pkey::PKey<pkey::Private>,
    /// The matching digest
    digest: hash::MessageDigest,
}

impl JwsHs256Signer {
    /// Create a new secure private key for signing
    pub fn generate_hs256() -> Result<Self, JwtError> {
        let digest = hash::MessageDigest::sha256();

        let mut buf = [0; 32];
        rand::rand_bytes(&mut buf).map_err(|e| {
            error!("{:?}", e);
            JwtError::OpenSSLError
        })?;

        // Can it become a pkey?
        let skey = pkey::PKey::hmac(&buf).map_err(|e| {
            error!("{:?}", e);
            JwtError::OpenSSLError
        })?;

        let mut kid = [0; 32];
        rand::rand_bytes(&mut kid).map_err(|e| {
            error!("{:?}", e);
            JwtError::OpenSSLError
        })?;

        let kid = hash::hash(digest, &kid)
            .map(|hashout| hex::encode(hashout))
            .map_err(|_| JwtError::OpenSSLError)?;

        Ok(JwsHs256Signer { kid, skey, digest })
    }
}

#[cfg(test)]
impl TryFrom<&[u8]> for JwsHs256Signer {
    type Error = JwtError;

    fn try_from(buf: &[u8]) -> Result<Self, Self::Error> {
        if buf.len() < 32 {
            return Err(JwtError::OpenSSLError);
        }

        let digest = hash::MessageDigest::sha256();

        let kid = hash::hash(digest, buf)
            .map(|hashout| hex::encode(hashout))
            .map_err(|_| JwtError::OpenSSLError)?;

        let skey = pkey::PKey::hmac(buf).map_err(|e| {
            error!("{:?}", e);
            JwtError::OpenSSLError
        })?;

        Ok(JwsHs256Signer { kid, skey, digest })
    }
}

impl JwsSigner for JwsHs256Signer {
    fn update_header(&mut self, header: &mut ProtectedHeader) -> Result<(), JwtError> {
        // Update the alg to match.
        header.alg = JwaAlg::HS256;

        header.kid = Some(self.kid.clone());

        Ok(())
    }

    fn sign(&mut self, jwsc: JwsCompactSignData<'_>) -> Result<Vec<u8>, JwtError> {
        todo!();
    }
}

impl JwsVerifier for JwsHs256Signer {
    fn verify_signature(&mut self, jwsc: &JwsCompact) -> Result<bool, JwtError> {
        if jwsc.header.alg != JwaAlg::HS256 {
            debug!(jwsc_alg = ?jwsc.header.alg, "validator algorithm mismatch");
            return Err(JwtError::ValidatorAlgMismatch);
        }

        let mut signer = sign::Signer::new(self.digest, &self.skey).map_err(|e| {
            debug!(?e);
            JwtError::OpenSSLError
        })?;

        signer
            .update(jwsc.hdr_b64.as_bytes())
            .and_then(|_| signer.update(".".as_bytes()))
            .and_then(|_| signer.update(jwsc.payload_b64.as_bytes()))
            .map_err(|e| {
                debug!(?e);
                JwtError::OpenSSLError
            })?;

        let ver_sig = signer.sign_to_vec().map_err(|e| {
            debug!(?e);
            JwtError::OpenSSLError
        })?;

        Ok(jwsc.signature == ver_sig)
    }
}

#[derive(Default)]
pub struct JwsX509VerifierBuilder {
    leaf: Option<x509::X509>,
    chain: Vec<x509::X509>,
    trust_roots: Vec<x509::X509>,
}

impl JwsX509VerifierBuilder {
    pub fn new() -> Self {
        JwsX509VerifierBuilder::default()
    }

    pub fn add_fullchain(mut self, chain: Vec<x509::X509>) -> Self {
        todo!();
    }

    pub fn build(self) -> Result<JwsX509Verifier, JwtError> {
        todo!();
    }
}

pub struct JwsX509Verifier {
    /// The KID of this validator
    kid: Option<String>,
    /// Public Key
    pkey: x509::X509,
}

impl JwsVerifier for JwsX509Verifier {
    fn verify_signature(&mut self, jwsc: &JwsCompact) -> Result<bool, JwtError> {
        todo!();
    }
}

#[cfg(all(feature = "openssl", test))]
mod tests {
    use super::{
        JwsEs256Signer, JwsEs256Verifier, JwsHs256Signer, JwsRs256Signer, JwsRs256Verifier,
        JwsSignerToVerifier,
    };
    use crate::compact::{Jwk, JwsCompact};
    use crate::jws::Jws;
    use base64::{engine::general_purpose, Engine as _};
    use std::convert::TryFrom;
    use std::str::FromStr;

    #[test]
    fn rfc7515_es256_validation_example() {
        let _ = tracing_subscriber::fmt::try_init();
        let test_jws = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q";

        let jwsc = JwsCompact::from_str(test_jws).unwrap();

        assert!(jwsc.to_string() == test_jws);

        assert!(jwsc.check_vectors(
            &[
                101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 70, 85, 122, 73, 49, 78, 105, 74,
                57, 46, 101, 121, 74, 112, 99, 51, 77, 105, 79, 105, 74, 113, 98, 50, 85, 105, 76,
                65, 48, 75, 73, 67, 74, 108, 101, 72, 65, 105, 79, 106, 69, 122, 77, 68, 65, 52,
                77, 84, 107, 122, 79, 68, 65, 115, 68, 81, 111, 103, 73, 109, 104, 48, 100, 72, 65,
                54, 76, 121, 57, 108, 101, 71, 70, 116, 99, 71, 120, 108, 76, 109, 78, 118, 98, 83,
                57, 112, 99, 49, 57, 121, 98, 50, 57, 48, 73, 106, 112, 48, 99, 110, 86, 108, 102,
                81
            ],
            &[
                14, 209, 33, 83, 121, 99, 108, 72, 60, 47, 127, 21, 88, 7, 212, 2, 163, 178, 40, 3,
                58, 249, 124, 126, 23, 129, 154, 195, 22, 158, 166, 101, 197, 10, 7, 211, 140, 60,
                112, 229, 216, 241, 45, 175, 8, 74, 84, 128, 166, 101, 144, 197, 242, 147, 80, 154,
                143, 63, 127, 138, 131, 163, 84, 213
            ]
        ));

        assert!(jwsc.get_jwk_pubkey_url().is_none());
        assert!(jwsc.get_jwk_pubkey().is_none());

        let pkey = r#"{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}"#;

        let pkey: Jwk = serde_json::from_str(pkey).expect("Invalid JWK");
        trace!("jwk -> {:?}", pkey);

        let mut jwk_es256_verifier =
            JwsEs256Verifier::try_from(&pkey).expect("Unable to create validator");

        let released = jwsc
            .verify(&mut jwk_es256_verifier)
            .expect("Unable to verify jws");
        trace!("rel -> {:?}", released);
    }

    #[test]
    fn rfc7515_es256_signature_example() {
        let _ = tracing_subscriber::fmt::try_init();
        // https://docs.rs/openssl/0.10.36/openssl/ec/struct.EcKey.html#method.from_private_components
        let mut jws_es256_signer = JwsEs256Signer::from_es256_jwk_components(
            "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
            "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
            "jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI",
        )
        .expect("failed to construct signer");

        let jws = Jws::new(vec![
            123, 34, 105, 115, 115, 34, 58, 34, 106, 111, 101, 34, 44, 13, 10, 32, 34, 101, 120,
            112, 34, 58, 49, 51, 48, 48, 56, 49, 57, 51, 56, 48, 44, 13, 10, 32, 34, 104, 116, 116,
            112, 58, 47, 47, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 47, 105, 115, 95,
            114, 111, 111, 116, 34, 58, 116, 114, 117, 101, 125,
        ]);

        let jwsc = jws.sign(&mut jws_es256_signer).expect("Failed to sign");

        assert!(jwsc.get_jwk_pubkey_url().is_none());
        assert!(jwsc.get_jwk_pubkey().is_none());

        let pkey = r#"{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}"#;

        let pkey: Jwk = serde_json::from_str(pkey).expect("Invalid JWK");
        trace!("jwk -> {:?}", pkey);

        let mut jwk_es256_verifier =
            JwsEs256Verifier::try_from(&pkey).expect("Unable to create validator");

        let released = jwsc
            .verify(&mut jwk_es256_verifier)
            .expect("Unable to verify jws");

        trace!("rel -> {:?}", released);

        // Test the verifier from the signer also works.
        let mut jwk_es256_verifier = jws_es256_signer
            .get_verifier()
            .expect("failed to get verifier from signer");

        let released = jwsc
            .verify(&mut jwk_es256_verifier)
            .expect("Unable to verify jws");

        trace!("rel -> {:?}", released);
    }

    #[test]
    fn es256_key_generate_cycle() {
        let _ = tracing_subscriber::fmt::try_init();
        let jws_es256_signer =
            JwsEs256Signer::generate_es256().expect("failed to construct signer.");

        let der = jws_es256_signer
            .private_key_to_der()
            .expect("Failed to extract DER");

        let mut jws_es256_signer =
            JwsEs256Signer::from_es256_der(&der).expect("Failed to restore signer");

        // This time we'll add the jwk pubkey and show it being used with the validator.
        let jws = Jws::new(vec![0, 1, 2, 3, 4])
            .set_kid("abcd".to_string())
            .set_typ("abcd".to_string())
            .set_cty("abcd".to_string());

        jws_es256_signer.set_sign_option_embed_jwk(true);

        let jwsc = jws.sign(&mut jws_es256_signer).expect("Failed to sign");

        assert!(jwsc.get_jwk_pubkey_url().is_none());
        let pub_jwk = jwsc.get_jwk_pubkey().expect("No embeded public jwk!");
        assert!(*pub_jwk == jws_es256_signer.public_key_as_jwk().unwrap());

        let mut jwk_es256_verifier =
            JwsEs256Verifier::try_from(pub_jwk).expect("Unable to create validator");

        let released = jwsc
            .verify(&mut jwk_es256_verifier)
            .expect("Unable to validate jws");
        assert!(released.payload() == &[0, 1, 2, 3, 4]);
    }

    // RSA3072
    // https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.2
    #[test]
    fn rfc7515_rs256_validation_example() {
        let _ = tracing_subscriber::fmt::try_init();
        let test_jws = "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw";

        let jwsc = JwsCompact::from_str(test_jws).unwrap();

        assert!(jwsc.to_string() == test_jws);

        assert!(jwsc.check_vectors(
            &[
                101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 83, 85, 122, 73, 49, 78, 105, 74,
                57, 46, 101, 121, 74, 112, 99, 51, 77, 105, 79, 105, 74, 113, 98, 50, 85, 105, 76,
                65, 48, 75, 73, 67, 74, 108, 101, 72, 65, 105, 79, 106, 69, 122, 77, 68, 65, 52,
                77, 84, 107, 122, 79, 68, 65, 115, 68, 81, 111, 103, 73, 109, 104, 48, 100, 72, 65,
                54, 76, 121, 57, 108, 101, 71, 70, 116, 99, 71, 120, 108, 76, 109, 78, 118, 98, 83,
                57, 112, 99, 49, 57, 121, 98, 50, 57, 48, 73, 106, 112, 48, 99, 110, 86, 108, 102,
                81
            ],
            &[
                112, 46, 33, 137, 67, 232, 143, 209, 30, 181, 216, 45, 191, 120, 69, 243, 65, 6,
                174, 27, 129, 255, 247, 115, 17, 22, 173, 209, 113, 125, 131, 101, 109, 66, 10,
                253, 60, 150, 238, 221, 115, 162, 102, 62, 81, 102, 104, 123, 0, 11, 135, 34, 110,
                1, 135, 237, 16, 115, 249, 69, 229, 130, 173, 252, 239, 22, 216, 90, 121, 142, 232,
                198, 109, 219, 61, 184, 151, 91, 23, 208, 148, 2, 190, 237, 213, 217, 217, 112, 7,
                16, 141, 178, 129, 96, 213, 248, 4, 12, 167, 68, 87, 98, 184, 31, 190, 127, 249,
                217, 46, 10, 231, 111, 36, 242, 91, 51, 187, 230, 244, 74, 230, 30, 177, 4, 10,
                203, 32, 4, 77, 62, 249, 18, 142, 212, 1, 48, 121, 91, 212, 189, 59, 65, 238, 202,
                208, 102, 171, 101, 25, 129, 253, 228, 141, 247, 127, 55, 45, 195, 139, 159, 175,
                221, 59, 239, 177, 139, 93, 163, 204, 60, 46, 176, 47, 158, 58, 65, 214, 18, 202,
                173, 21, 145, 18, 115, 160, 95, 35, 185, 232, 56, 250, 175, 132, 157, 105, 132, 41,
                239, 90, 30, 136, 121, 130, 54, 195, 212, 14, 96, 69, 34, 165, 68, 200, 242, 122,
                122, 45, 184, 6, 99, 209, 108, 247, 202, 234, 86, 222, 64, 92, 178, 33, 90, 69,
                178, 194, 85, 102, 181, 90, 193, 167, 72, 160, 112, 223, 200, 163, 42, 70, 149, 67,
                208, 25, 238, 251, 71
            ]
        ));

        assert!(jwsc.get_jwk_pubkey_url().is_none());
        assert!(jwsc.get_jwk_pubkey().is_none());

        let pkey = r#"{
            "kty":"RSA",
            "n":"ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ",
            "e":"AQAB"
        }"#;

        let pkey: Jwk = serde_json::from_str(pkey).expect("Invalid JWK");
        trace!("jwk -> {:?}", pkey);

        let mut jws_validator =
            JwsRs256Verifier::try_from(&pkey).expect("Unable to create validator");

        let released = jwsc
            .verify(&mut jws_validator)
            .expect("Unable to validate jws");
        trace!("rel -> {:?}", released);
    }

    #[test]
    fn rs256_key_generate_cycle() {
        let _ = tracing_subscriber::fmt::try_init();
        let jws_rs256_signer =
            JwsRs256Signer::generate_legacy_rs256().expect("failed to construct signer.");

        let der = jws_rs256_signer
            .private_key_to_der()
            .expect("Failed to extract DER");

        let mut jws_rs256_signer =
            JwsRs256Signer::from_rs256_der(&der).expect("Failed to restore signer");

        // This time we'll add the jwk pubkey and show it being used with the validator.
        let jws = Jws::new(vec![0, 1, 2, 3, 4])
            .set_typ("abcd".to_string())
            .set_cty("abcd".to_string());

        jws_rs256_signer.set_sign_option_embed_jwk(true);

        let jwsc = jws.sign(&mut jws_rs256_signer).expect("Failed to sign");

        assert!(jwsc.get_jwk_pubkey_url().is_none());

        let pub_jwk = jwsc.get_jwk_pubkey().expect("No embeded public jwk!");
        assert!(*pub_jwk == jws_rs256_signer.public_key_as_jwk().unwrap());

        let mut jws_validator =
            JwsRs256Verifier::try_from(pub_jwk).expect("Unable to create validator");

        let released = jwsc
            .verify(&mut jws_validator)
            .expect("Unable to validate jws");
        assert!(released.payload() == &[0, 1, 2, 3, 4]);
    }

    #[test]
    fn rfc7519_hs256_validation_example() {
        let _ = tracing_subscriber::fmt::try_init();
        let test_jws = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

        let jwsc = JwsCompact::from_str(test_jws).unwrap();

        assert!(jwsc.check_vectors(
            &[
                101, 121, 74, 48, 101, 88, 65, 105, 79, 105, 74, 75, 86, 49, 81, 105, 76, 65, 48,
                75, 73, 67, 74, 104, 98, 71, 99, 105, 79, 105, 74, 73, 85, 122, 73, 49, 78, 105,
                74, 57, 46, 101, 121, 74, 112, 99, 51, 77, 105, 79, 105, 74, 113, 98, 50, 85, 105,
                76, 65, 48, 75, 73, 67, 74, 108, 101, 72, 65, 105, 79, 106, 69, 122, 77, 68, 65,
                52, 77, 84, 107, 122, 79, 68, 65, 115, 68, 81, 111, 103, 73, 109, 104, 48, 100, 72,
                65, 54, 76, 121, 57, 108, 101, 71, 70, 116, 99, 71, 120, 108, 76, 109, 78, 118, 98,
                83, 57, 112, 99, 49, 57, 121, 98, 50, 57, 48, 73, 106, 112, 48, 99, 110, 86, 108,
                102, 81
            ],
            &[
                116, 24, 223, 180, 151, 153, 224, 37, 79, 250, 96, 125, 216, 173, 187, 186, 22,
                212, 37, 77, 105, 214, 191, 240, 91, 88, 5, 88, 83, 132, 141, 121
            ]
        ));

        assert!(jwsc.get_jwk_pubkey_url().is_none());
        assert!(jwsc.get_jwk_pubkey().is_none());

        let skey = general_purpose::URL_SAFE_NO_PAD.decode(
        "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"
        ).expect("Invalid key");

        let mut jws_signer =
            JwsHs256Signer::try_from(skey.as_slice()).expect("Unable to create validator");

        let released = jwsc
            .verify(&mut jws_signer)
            .expect("Unable to validate jws");
        trace!("rel -> {:?}", released);
    }
}
