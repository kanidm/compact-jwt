use crate::compact::{JweAlg, JweCompact, JweEnc, JweProtectedHeader, ProtectedHeader};
use crate::jwe::Jwe;
use crate::JwtError;

use crate::traits::*;

use super::a256gcm::{JweA256GCMEncipher, KEY_LEN as A256_KEY_LEN};
use super::hs256::JwsHs256Signer;

use openssl::hash::MessageDigest;
use openssl::rand;
use openssl::symm::Cipher;

use base64::{engine::general_purpose, Engine as _};

use kanidm_hsm_crypto::{LoadableMsOapxbcSessionKey, MsOapxbcRsaKey, Tpm};

const AAD_KDF_LABEL: &[u8; 26] = b"AzureAD-SecureConversation";
const CTX_NONCE_LEN: usize = 32;

/// A [MS-OAPXBC] 3.2.5.1.2.2 yielded session key. This is used as a form of key agreement
/// for MS clients, where this key can now be used to encipher and decipher arbitrary
/// content. It may also be used for HS256 signatures for requests.
pub enum MsOapxbcSessionKey {
    /// An AES-256-GCM/CBC + HS256 session key
    A256GCM {
        /// The encrypted session key which can be loaded as required for individual operations
        loadable_session_key: LoadableMsOapxbcSessionKey,
    },
}

impl MsOapxbcSessionKey {
    /// Given a session jwe, complete the session key derivation with this private key
    pub fn complete_tpm_rsa_oaep_key_agreement<T>(
        tpm: &mut T,
        msrsa_key: &MsOapxbcRsaKey,
        jwec: &JweCompact,
    ) -> Result<Self, JwtError>
    where
        T: Tpm,
    {
        let expected_wrap_key_buffer_len = jwec.header.enc.key_len();

        let loadable_session_key = tpm
            .msoapxbc_rsa_decipher_session_key(
                msrsa_key,
                &jwec.content_enc_key,
                expected_wrap_key_buffer_len,
            )
            .map_err(|tpm_err| {
                error!(?tpm_err);
                JwtError::TpmError
            })?;

        // May also need to make this output type a trait too, so we can store
        // this key in some secure way?
        match jwec.header.enc {
            JweEnc::A256GCM => Ok(MsOapxbcSessionKey::A256GCM {
                loadable_session_key,
            }),
            _ => Err(JwtError::CipherUnavailable),
        }
    }
}

impl MsOapxbcSessionKey {
    /// Given a PRTv2 JWE in compact form, decipher and authenticate its content.
    pub fn decipher_prt_v2<T>(
        &self,
        tpm: &mut T,
        msrsa_key: &MsOapxbcRsaKey,
        jwec: &JweCompact,
    ) -> Result<Jwe, JwtError>
    where
        T: Tpm,
    {
        let ctx_bytes = if let Some(ctx) = &jwec.header.ctx {
            general_purpose::STANDARD
                .decode(ctx)
                .map_err(|_| JwtError::InvalidBase64)?
        } else {
            return Err(JwtError::InvalidPRT);
        };

        let derived_key = match &self {
            MsOapxbcSessionKey::A256GCM {
                loadable_session_key,
            } => {
                let aes_key = tpm
                    .msoapxbc_rsa_yield_session_key(msrsa_key, loadable_session_key)
                    .map_err(|tpm_err| {
                        error!(?tpm_err);
                        JwtError::TpmError
                    })?;

                nist_sp800_108_kdf_hmac_sha256(&aes_key, &ctx_bytes, AAD_KDF_LABEL, A256_KEY_LEN)?
            }
        };

        let cipher = Cipher::aes_256_cbc();
        let payload =
            super::a128cbc_hs256::decipher(cipher, &derived_key, &jwec.ciphertext, &jwec.iv)?;

        Ok(Jwe {
            header: jwec.header.clone(),
            payload,
        })
    }

    /// Given a JWE in compact form, decipher and authenticate its content.
    pub fn decipher<T>(
        &self,
        tpm: &mut T,
        msrsa_key: &MsOapxbcRsaKey,

        jwec: &JweCompact,
    ) -> Result<Jwe, JwtError>
    where
        T: Tpm,
    {
        // Alg must be direct.
        if jwec.header.alg != JweAlg::DIRECT {
            return Err(JwtError::AlgorithmUnavailable);
        }

        match &self {
            MsOapxbcSessionKey::A256GCM {
                loadable_session_key,
            } => {
                // Seems that this can mean AES256GCM or AES256CBC
                if jwec.header.enc != JweEnc::A256GCM {
                    return Err(JwtError::CipherUnavailable);
                }

                let aes_key = tpm
                    .msoapxbc_rsa_yield_session_key(msrsa_key, loadable_session_key)
                    .map_err(|tpm_err| {
                        error!(?tpm_err);
                        JwtError::TpmError
                    })?;

                let a256gcm = JweA256GCMEncipher::try_from(aes_key.as_slice())?;

                a256gcm.decipher_inner(jwec).map(|payload| Jwe {
                    header: jwec.header.clone(),
                    payload,
                })
            }
        }
    }

    /// Given a JWE, encipher its content to a compact form.
    pub fn encipher<T>(
        &self,
        tpm: &mut T,
        msrsa_key: &MsOapxbcRsaKey,
        jwe: &Jwe,
    ) -> Result<JweCompact, JwtError>
    where
        T: Tpm,
    {
        let outer = JweDirect::default();

        match &self {
            MsOapxbcSessionKey::A256GCM {
                loadable_session_key,
            } => {
                let aes_key = tpm
                    .msoapxbc_rsa_yield_session_key(msrsa_key, loadable_session_key)
                    .map_err(|tpm_err| {
                        error!(?tpm_err);
                        JwtError::TpmError
                    })?;

                let a256gcm = JweA256GCMEncipher::try_from(aes_key.as_slice())?;

                a256gcm.encipher_inner(&outer, jwe)
            }
        }
    }

    /// Directly use the session key to perform a HMAC signature over a JWS.
    pub fn sign_direct<T, V: JwsSignable>(
        &self,
        tpm: &mut T,
        msrsa_key: &MsOapxbcRsaKey,
        jws: &V,
    ) -> Result<V::Signed, JwtError>
    where
        T: Tpm,
    {
        let hmac_key = match self {
            MsOapxbcSessionKey::A256GCM {
                loadable_session_key,
            } => {
                let aes_key = tpm
                    .msoapxbc_rsa_yield_session_key(msrsa_key, loadable_session_key)
                    .map_err(|tpm_err| {
                        error!(?tpm_err);
                        JwtError::TpmError
                    })?;

                JwsHs256Signer::try_from(aes_key.as_slice())?
            }
        };

        hmac_key.sign(jws)
    }

    /// Use the session key to derive a one-time HMAC key for signing this JWS.
    pub fn sign<T, V: JwsSignable>(
        &self,

        tpm: &mut T,
        msrsa_key: &MsOapxbcRsaKey,

        jws: &V,
    ) -> Result<V::Signed, JwtError>
    where
        T: Tpm,
    {
        let mut nonce = [0; CTX_NONCE_LEN];
        rand::rand_bytes(&mut nonce).map_err(|e| {
            error!("{:?}", e);
            JwtError::OpenSSLError
        })?;

        let derived_key = match &self {
            MsOapxbcSessionKey::A256GCM {
                loadable_session_key,
            } => {
                let aes_key = tpm
                    .msoapxbc_rsa_yield_session_key(msrsa_key, loadable_session_key)
                    .map_err(|tpm_err| {
                        error!(?tpm_err);
                        JwtError::TpmError
                    })?;

                nist_sp800_108_kdf_hmac_sha256(&aes_key, &nonce, AAD_KDF_LABEL, A256_KEY_LEN)?
            }
        };

        let hmac_key = JwsHs256Signer::try_from(derived_key.as_slice())?;

        let signer = MsOapxbcSessionKeyHs256 { nonce, hmac_key };

        signer.sign(jws)
    }

    /// Verify a JWS has been signed either directly (HS256) or with a derived key if
    /// the ctx field is present.
    pub fn verify<T, V: JwsVerifiable>(
        &self,
        tpm: &mut T,
        msrsa_key: &MsOapxbcRsaKey,
        jwsc: &V,
    ) -> Result<V::Verified, JwtError>
    where
        T: Tpm,
    {
        let hmac_key = if let Some(ctx) = &jwsc.data().header.ctx {
            let ctx_bytes = general_purpose::STANDARD
                .decode(ctx)
                .map_err(|_| JwtError::InvalidBase64)?;

            let derived_key = match &self {
                MsOapxbcSessionKey::A256GCM {
                    loadable_session_key,
                } => {
                    let aes_key = tpm
                        .msoapxbc_rsa_yield_session_key(msrsa_key, loadable_session_key)
                        .map_err(|tpm_err| {
                            error!(?tpm_err);
                            JwtError::TpmError
                        })?;

                    nist_sp800_108_kdf_hmac_sha256(
                        aes_key.as_ref(),
                        &ctx_bytes,
                        AAD_KDF_LABEL,
                        A256_KEY_LEN,
                    )?
                }
            };

            JwsHs256Signer::try_from(derived_key.as_slice())?
        } else {
            // Assume direct signature.
            match self {
                MsOapxbcSessionKey::A256GCM {
                    loadable_session_key,
                } => {
                    let aes_key = tpm
                        .msoapxbc_rsa_yield_session_key(msrsa_key, loadable_session_key)
                        .map_err(|tpm_err| {
                            error!(?tpm_err);
                            JwtError::TpmError
                        })?;

                    JwsHs256Signer::try_from(aes_key.as_slice())?
                }
            }
        };

        hmac_key.verify(jwsc)
    }
}

#[derive(Default)]
struct JweDirect {}

impl JweEncipherOuter for JweDirect {
    fn set_header_alg(&self, hdr: &mut JweProtectedHeader) -> Result<(), JwtError> {
        hdr.alg = JweAlg::DIRECT;
        Ok(())
    }

    fn wrap_key(&self, _key_to_wrap: &[u8]) -> Result<Vec<u8>, JwtError> {
        Ok(Vec::with_capacity(0))
    }
}

struct MsOapxbcSessionKeyHs256 {
    nonce: [u8; CTX_NONCE_LEN],
    hmac_key: JwsHs256Signer,
}

impl JwsSigner for MsOapxbcSessionKeyHs256 {
    fn get_kid(&self) -> &str {
        JwsSigner::get_kid(&self.hmac_key)
    }

    fn update_header(&self, header: &mut ProtectedHeader) -> Result<(), JwtError> {
        let ctx = general_purpose::STANDARD.encode(self.nonce);
        header.ctx = Some(ctx);

        self.hmac_key.update_header(header)
    }

    fn sign<V: JwsSignable>(&self, jws: &V) -> Result<V::Signed, JwtError> {
        let mut sign_data = jws.data()?;

        // Let the signer update the header as required.
        self.update_header(&mut sign_data.header)?;

        self.hmac_key.sign_inner(jws, sign_data)
    }
    fn set_sign_option_embed_kid(&self, value: bool) -> Self {
        MsOapxbcSessionKeyHs256 {
            hmac_key: self.hmac_key.set_sign_option_embed_kid(value),
            nonce: self.nonce,
        }
    }
}

pub(crate) fn nist_sp800_108_kdf_hmac_sha256(
    key: &[u8],
    ctx: &[u8],
    label: &[u8],
    derive_len: usize,
) -> Result<Vec<u8>, JwtError> {
    use openssl_kdf::{perform_kdf, KdfArgument, KdfKbMode, KdfMacType, KdfType};

    let args = [
        &KdfArgument::KbMode(KdfKbMode::Counter),
        &KdfArgument::Mac(KdfMacType::Hmac(MessageDigest::sha256())),
        &KdfArgument::Salt(label),
        &KdfArgument::KbInfo(ctx),
        &KdfArgument::Key(key),
    ];
    perform_kdf(KdfType::KeyBased, &args, derive_len).map_err(|ossl_err| {
        error!(?ossl_err, "Unable to derive session key");
        JwtError::OpenSSLError
    })
}

#[cfg(test)]
mod tests {
    use super::MsOapxbcSessionKey;
    use crate::compact::JweCompact;
    use crate::jwe::JweBuilder;
    use crate::jws::JwsBuilder;
    use base64::{engine::general_purpose, Engine as _};
    use openssl::rsa::Rsa;

    use std::str::FromStr;

    use kanidm_hsm_crypto::{soft::SoftTpm, AuthValue, BoxedDynTpm, Tpm};

    use super::{nist_sp800_108_kdf_hmac_sha256, AAD_KDF_LABEL};
    use crate::compact::JweAlg;
    use crate::compact::JweEnc;
    use crate::crypto::ms_oapxbc::JweA256GCMEncipher;
    use crate::crypto::ms_oapxbc::A256_KEY_LEN;
    use crate::crypto::JweRSAOAEPEncipher;
    use crate::jwe::Jwe;
    use crate::traits::JweEncipherInner;
    use crate::traits::JwsVerifiable;
    use crate::traits::JwsVerifier;
    use crate::JwtError;
    use openssl::pkey::Public;

    use crate::crypto::hs256::JwsHs256Signer;

    struct MsOapxbcServerKey {
        aes_key: [u8; A256_KEY_LEN],
    }

    impl MsOapxbcServerKey {
        pub fn begin_rsa_oaep_key_agreement(
            rsa_pub_key: Rsa<Public>,
        ) -> Result<(Self, JweCompact), JwtError> {
            let rsa_oaep = JweRSAOAEPEncipher::try_from(rsa_pub_key)?;

            let aes_key = JweA256GCMEncipher::new_ephemeral()?;

            // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-oapxbc/d3f8893c-a715-412a-97d1-5ffed2c3b3d5
            // session_key_jwe does not seem to have many requirements?
            let jweb = JweBuilder::from(Vec::with_capacity(0)).build();
            let jwec = aes_key.encipher_inner(&rsa_oaep, &jweb)?;

            // Extract the raw key.
            let aes_key = aes_key.raw_key();

            Ok((MsOapxbcServerKey { aes_key }, jwec))
        }

        /// Given a JWE in compact form, decipher and authenticate its content.
        pub fn decipher(&self, jwec: &JweCompact) -> Result<Jwe, JwtError> {
            // Alg must be direct.
            if jwec.header.alg != JweAlg::DIRECT {
                return Err(JwtError::AlgorithmUnavailable);
            }

            // Seems that this can mean AES256GCM or AES256CBC
            if jwec.header.enc != JweEnc::A256GCM {
                return Err(JwtError::CipherUnavailable);
            }

            let a256gcm = JweA256GCMEncipher::try_from(self.aes_key.as_slice())?;

            a256gcm.decipher_inner(jwec).map(|payload| Jwe {
                header: jwec.header.clone(),
                payload,
            })
        }

        /// Verify a JWS has been signed either directly (HS256) or with a derived key if
        /// the ctx field is present.
        pub fn verify<V: JwsVerifiable>(&self, jwsc: &V) -> Result<V::Verified, JwtError> {
            let hmac_key = if let Some(ctx) = &jwsc.data().header.ctx {
                let ctx_bytes = general_purpose::STANDARD
                    .decode(ctx)
                    .map_err(|_| JwtError::InvalidBase64)?;

                let derived_key = nist_sp800_108_kdf_hmac_sha256(
                    self.aes_key.as_ref(),
                    &ctx_bytes,
                    AAD_KDF_LABEL,
                    A256_KEY_LEN,
                )?;

                JwsHs256Signer::try_from(derived_key.as_slice())?
            } else {
                JwsHs256Signer::try_from(self.aes_key.as_slice())?
            };

            hmac_key.verify(jwsc)
        }
    }

    #[test]
    fn ms_oapxbc_reflexive_encryption_test() {
        let _ = tracing_subscriber::fmt::try_init();

        let mut softtpm: BoxedDynTpm = BoxedDynTpm::new(SoftTpm::new());
        let auth_value = AuthValue::ephemeral().unwrap();
        let loadable_machine_key = softtpm.machine_key_create(&auth_value).unwrap();

        let machine_key = softtpm
            .machine_key_load(&auth_value, &loadable_machine_key)
            .unwrap();

        let loadable_msrsa_key = softtpm.msoapxbc_rsa_key_create(&machine_key).unwrap();

        let msrsa_key = softtpm
            .msoapxbc_rsa_key_load(&machine_key, &loadable_msrsa_key)
            .unwrap();

        let msrsa_public_key_der = softtpm.msoapxbc_rsa_public_as_der(&msrsa_key).unwrap();

        let rsa_pub_key = Rsa::public_key_from_der(&msrsa_public_key_der).unwrap();

        let (server_key, jwec) =
            MsOapxbcServerKey::begin_rsa_oaep_key_agreement(rsa_pub_key).unwrap();

        let client_key = MsOapxbcSessionKey::complete_tpm_rsa_oaep_key_agreement(
            &mut softtpm,
            &msrsa_key,
            &jwec,
        )
        .unwrap();

        let input = vec![1; 256];
        let jweb = JweBuilder::from(input.clone()).build();

        let jwe_encrypted = client_key
            .encipher(&mut softtpm, &msrsa_key, &jweb)
            .expect("Unable to encrypt.");

        // Decrypt with the partner.
        let decrypted = server_key
            .decipher(&jwe_encrypted)
            .expect("Unable to decrypt.");

        assert_eq!(decrypted.payload(), input);
    }

    #[test]
    fn ms_oapxbc_reflexive_signature_test() {
        let _ = tracing_subscriber::fmt::try_init();

        let mut softtpm: BoxedDynTpm = BoxedDynTpm::new(SoftTpm::new());
        let auth_value = AuthValue::ephemeral().unwrap();
        let loadable_machine_key = softtpm.machine_key_create(&auth_value).unwrap();

        let machine_key = softtpm
            .machine_key_load(&auth_value, &loadable_machine_key)
            .unwrap();

        let loadable_msrsa_key = softtpm.msoapxbc_rsa_key_create(&machine_key).unwrap();

        let msrsa_key = softtpm
            .msoapxbc_rsa_key_load(&machine_key, &loadable_msrsa_key)
            .unwrap();

        let msrsa_public_key_der = softtpm.msoapxbc_rsa_public_as_der(&msrsa_key).unwrap();

        let rsa_pub_key = Rsa::public_key_from_der(&msrsa_public_key_der).unwrap();

        let (server_key, jwec) =
            MsOapxbcServerKey::begin_rsa_oaep_key_agreement(rsa_pub_key).unwrap();

        let client_key = MsOapxbcSessionKey::complete_tpm_rsa_oaep_key_agreement(
            &mut softtpm,
            &msrsa_key,
            &jwec,
        )
        .unwrap();

        let input = vec![1; 256];
        let jws = JwsBuilder::from(input.clone()).build();

        let jws_signed = client_key
            .sign(&mut softtpm, &msrsa_key, &jws)
            .expect("Unable to sign.");

        // Decrypt with the partner.
        let verified = server_key.verify(&jws_signed).expect("Unable to verify.");

        assert_eq!(verified.payload(), input);
    }

    #[test]
    fn ms_oapxbc_3_2_5_1_3_3_exchange_request_response() {
        let rsa_priv_key = Rsa::private_key_from_der(&[
            48, 130, 4, 162, 2, 1, 0, 2, 130, 1, 1, 0, 180, 132, 214, 68, 242, 2, 15, 193, 241,
            133, 64, 208, 45, 231, 251, 49, 253, 121, 19, 203, 105, 62, 13, 89, 4, 105, 29, 59,
            113, 117, 198, 67, 106, 211, 221, 61, 249, 122, 211, 236, 84, 189, 106, 75, 28, 107,
            115, 188, 182, 42, 206, 247, 212, 184, 20, 194, 255, 198, 140, 134, 182, 45, 103, 203,
            15, 193, 156, 230, 19, 6, 88, 14, 189, 71, 99, 219, 9, 214, 232, 118, 187, 219, 63,
            234, 207, 69, 168, 173, 163, 87, 219, 40, 147, 219, 251, 156, 152, 114, 200, 171, 202,
            111, 25, 161, 92, 74, 98, 62, 156, 184, 187, 239, 19, 236, 177, 65, 214, 18, 140, 30,
            108, 179, 151, 59, 63, 19, 233, 98, 54, 244, 112, 3, 234, 68, 29, 47, 46, 170, 168, 55,
            99, 20, 94, 226, 74, 59, 32, 122, 36, 191, 120, 87, 150, 36, 136, 199, 253, 228, 158,
            170, 131, 52, 228, 224, 150, 94, 135, 157, 151, 133, 135, 49, 16, 208, 49, 192, 156, 7,
            26, 239, 136, 146, 170, 95, 77, 36, 236, 254, 76, 202, 167, 44, 60, 165, 60, 206, 12,
            240, 211, 93, 173, 190, 47, 23, 202, 149, 140, 251, 71, 219, 45, 195, 146, 61, 178, 73,
            174, 79, 63, 6, 204, 252, 183, 57, 128, 111, 122, 249, 83, 217, 196, 226, 128, 153,
            135, 160, 247, 169, 211, 86, 97, 66, 172, 231, 95, 44, 166, 230, 39, 98, 218, 39, 181,
            10, 208, 115, 2, 3, 1, 0, 1, 2, 130, 1, 0, 38, 196, 40, 39, 162, 57, 35, 29, 41, 58,
            206, 146, 102, 105, 93, 30, 125, 42, 149, 63, 167, 152, 53, 209, 154, 10, 224, 198, 53,
            53, 111, 160, 102, 190, 156, 210, 132, 83, 6, 83, 200, 86, 237, 14, 184, 73, 179, 15,
            33, 167, 203, 206, 153, 21, 247, 15, 113, 82, 56, 55, 109, 196, 14, 120, 35, 40, 23, 3,
            169, 174, 65, 22, 217, 59, 13, 140, 170, 110, 70, 121, 201, 25, 234, 126, 8, 137, 19,
            18, 70, 243, 197, 18, 207, 189, 252, 40, 194, 236, 83, 127, 224, 247, 62, 239, 210, 27,
            255, 65, 38, 242, 221, 25, 24, 148, 73, 244, 179, 126, 68, 44, 252, 119, 12, 209, 34,
            88, 170, 83, 154, 209, 107, 228, 80, 231, 39, 249, 205, 103, 213, 138, 133, 245, 83,
            84, 82, 95, 221, 243, 123, 123, 144, 8, 4, 68, 97, 44, 252, 100, 61, 68, 121, 183, 114,
            42, 58, 209, 126, 131, 235, 115, 7, 198, 121, 159, 60, 17, 216, 44, 245, 48, 32, 228,
            130, 67, 242, 51, 217, 179, 77, 179, 231, 30, 178, 230, 206, 3, 102, 22, 168, 111, 225,
            232, 3, 177, 209, 177, 248, 86, 71, 83, 34, 47, 104, 201, 229, 103, 17, 127, 24, 147,
            155, 244, 137, 73, 208, 91, 170, 166, 68, 171, 107, 143, 25, 115, 177, 75, 116, 21, 9,
            190, 66, 172, 24, 124, 243, 6, 118, 200, 49, 111, 202, 99, 88, 123, 48, 65, 2, 129,
            129, 0, 220, 106, 58, 194, 121, 84, 72, 0, 245, 164, 109, 189, 224, 0, 5, 202, 64, 199,
            210, 146, 210, 119, 130, 40, 114, 191, 240, 158, 255, 6, 50, 128, 126, 88, 225, 114,
            227, 76, 215, 152, 181, 71, 210, 247, 117, 126, 193, 94, 175, 139, 243, 136, 194, 7,
            253, 195, 131, 190, 16, 67, 28, 19, 95, 242, 29, 156, 35, 25, 13, 179, 81, 222, 94,
            154, 249, 51, 194, 79, 198, 238, 193, 37, 207, 249, 120, 223, 142, 195, 231, 2, 126,
            87, 115, 233, 156, 67, 239, 73, 154, 180, 6, 231, 109, 207, 154, 69, 172, 204, 250, 82,
            18, 208, 233, 29, 78, 206, 213, 0, 14, 49, 77, 58, 49, 179, 128, 176, 216, 131, 2, 129,
            129, 0, 209, 169, 179, 15, 57, 54, 174, 237, 187, 217, 174, 225, 163, 99, 12, 143, 0,
            136, 185, 199, 146, 157, 229, 228, 216, 188, 89, 218, 173, 221, 216, 190, 44, 94, 92,
            172, 37, 3, 121, 183, 55, 6, 5, 138, 152, 254, 193, 59, 212, 144, 189, 2, 84, 207, 21,
            20, 198, 117, 115, 184, 83, 195, 115, 69, 111, 76, 5, 121, 252, 251, 212, 250, 67, 174,
            19, 178, 136, 10, 56, 107, 160, 159, 0, 138, 51, 25, 180, 196, 85, 147, 92, 254, 71,
            239, 250, 16, 238, 55, 25, 248, 29, 206, 16, 227, 150, 164, 145, 7, 196, 186, 87, 185,
            207, 180, 62, 99, 255, 185, 210, 230, 176, 8, 54, 5, 87, 105, 69, 81, 2, 129, 128, 28,
            62, 136, 149, 15, 19, 27, 190, 243, 187, 68, 76, 198, 125, 122, 64, 118, 152, 164, 133,
            39, 239, 36, 128, 166, 99, 174, 35, 209, 174, 43, 158, 135, 146, 64, 33, 134, 186, 252,
            13, 151, 125, 66, 173, 111, 34, 245, 8, 123, 26, 69, 244, 202, 88, 87, 206, 75, 253,
            120, 252, 0, 135, 3, 14, 117, 120, 226, 142, 125, 80, 243, 54, 185, 140, 198, 78, 57,
            162, 27, 109, 208, 214, 85, 150, 52, 69, 1, 120, 93, 11, 214, 192, 194, 27, 183, 104,
            133, 43, 59, 101, 194, 84, 185, 159, 150, 183, 66, 243, 105, 72, 71, 28, 250, 34, 69,
            76, 255, 194, 104, 15, 45, 68, 61, 198, 48, 193, 120, 157, 2, 129, 128, 117, 136, 159,
            83, 130, 108, 80, 69, 255, 79, 185, 196, 205, 246, 33, 189, 44, 188, 121, 1, 19, 5, 39,
            50, 81, 249, 204, 153, 85, 108, 143, 43, 148, 237, 213, 31, 191, 164, 34, 32, 126, 93,
            6, 208, 58, 146, 93, 186, 239, 159, 176, 5, 85, 139, 189, 50, 167, 74, 130, 115, 171,
            169, 94, 190, 102, 245, 4, 0, 237, 188, 51, 25, 148, 197, 74, 79, 132, 9, 206, 181, 47,
            22, 211, 147, 165, 175, 220, 113, 79, 211, 203, 134, 212, 199, 7, 181, 100, 5, 73, 174,
            152, 238, 194, 243, 2, 169, 0, 144, 141, 77, 53, 14, 122, 12, 126, 9, 74, 251, 93, 234,
            106, 118, 63, 234, 96, 165, 39, 241, 2, 129, 128, 101, 0, 61, 113, 89, 16, 12, 14, 127,
            57, 211, 173, 235, 157, 78, 118, 110, 41, 70, 79, 208, 145, 32, 32, 144, 250, 200, 109,
            90, 66, 201, 50, 25, 170, 48, 225, 118, 175, 228, 0, 102, 86, 95, 123, 111, 120, 121,
            78, 49, 37, 59, 106, 254, 19, 105, 136, 187, 61, 213, 105, 181, 162, 100, 239, 52, 41,
            104, 175, 98, 131, 254, 194, 168, 251, 182, 153, 221, 73, 237, 90, 135, 181, 45, 28,
            104, 197, 69, 216, 9, 96, 115, 85, 165, 103, 109, 134, 177, 135, 173, 7, 86, 36, 75,
            180, 161, 83, 195, 85, 135, 24, 224, 121, 20, 228, 3, 47, 17, 209, 55, 54, 214, 227,
            219, 73, 234, 251, 50, 145,
        ])
        .unwrap();

        let session_key_jwe = JweCompact::from_str("eyJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiUlNBLU9BRVAifQ.U95cslQ5YAV7FuQsTF45pcHpgpKCI8arJlz6IXbsXr2flZ4tpuO39dYHKZUXXrufObnvSe04Yetuk5osnL5E9EX7b3cWKDkLwo-KK7iT6B5i_XVbtUUBE87x3UfL8N-rUxIeW-Pyky5DzbZ7hsEkrbjgM16DTCIFucItvjwfJctL3ZTfUMIUrVDq1FjOhXrwu3Wrodi7sLm84lpLX_VQ7cqfmzPWfr-7FFtmJzj99rWDJPOM6ynucDbTxxjKeoW6Ft4EMna3_qdqw1A9_7PFDXSsprjJSGbbCvYhiSgib3k8JKKXr-uEGqyIERV0ajw-oJLHWUyuuu3EWlQul-urOg.KSGiTmZY4a8E4dRF.Gg.FYVcZT1WdLkRKABMOL5wyA").unwrap();

        let mut softtpm: BoxedDynTpm = BoxedDynTpm::new(SoftTpm::new());
        let auth_value = AuthValue::ephemeral().unwrap();
        let loadable_machine_key = softtpm.machine_key_create(&auth_value).unwrap();

        let machine_key = softtpm
            .machine_key_load(&auth_value, &loadable_machine_key)
            .unwrap();

        let loadable_msrsa_key = softtpm
            .msoapxbc_rsa_key_import(&machine_key, rsa_priv_key)
            .unwrap();

        let msrsa_key = softtpm
            .msoapxbc_rsa_key_load(&machine_key, &loadable_msrsa_key)
            .unwrap();

        let session_key = MsOapxbcSessionKey::complete_tpm_rsa_oaep_key_agreement(
            &mut softtpm,
            &msrsa_key,
            &session_key_jwe,
        )
        .unwrap();

        let enc_access_token = JweCompact::from_str("eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwiY3R4IjoiVVFvcWtvUldYNVFoNnpTbkV2V09aWVgyTXd1QVB4dkQifQ..uAgdAx7E8-rH7xdQDiJVzg.WRDzuK4NGxFjxdKfnzhcWB_Prx5OxkN5b5XLiPoQtkuZIxCaCAqFAe03QmGz60Io6T3e-LKa3mZ2yD62ZY98957_f7yr8ohFeZfCokwl0M5UpsmeVALEB2d-gLUld3hChFJPXcBwexrNkOnIy2gkqrvvvd_L1HooKQbtD7CXuAdKA1Vhpm4zfqSXOjLqoWcAiybdjd8fUwvgY_W0P_giIJh9qkkOGoF_WXXH8zmQ2ZSk9YmjQXH2LH_VzV9UUmpnRzicx6Wp42IpLEf16YNyO62186Z1GVbchxGV7xY4gT-0bVmjvRrXO91XpM-Jf6hmXXnnp-AfQuqISo3D937TjSiBrCE3MVpb5lJFI3M2Sib3ELez71JEVlqKV4vMY9_xRBnRx9qGFKLpI5rZPk660rgD7Uj6UwyMCodJAJWBycjhc2QekDgVFuyMpuG57u8FdV9wyVaE2STTk0in5f5EoYGzXBIo5QzhMJqvXlm_MjyiG4M3YikfcGIIPODpx7dLL15I-CrHGg2ynOPP0_AEUdkfzM0IXN8KxHoyqGh891LqBMvOyfIKg2gj1FA3S919bLBCvFmh4YLdC1xjHoYayxL44dmL-2vrhJS45nG3LhcTShXHZfeP3IM_qbZ-FFqXnBmj-c9tiEqrTfS1ihHyPAgmpBNWjNBgX2BxCWrwxinMLNeXsosrylUvPuCNTcoEJBIzVmrlw03CZldno3Js7Y_MLuLmYXTU6Kblp0dtz-U7HpCZ3H9L2M5UwbLcBXkxng-86vB3wBA77QkRC5lYuBTS0LSvze_bNzDtB8cZ6eFM57iIwa0NnZp2ocGxEXYs6EBxuqlRjIKyrjndowkbkkXAh4pExFdkQPGPbeN6SKaaGeZkFgegEzZIiCNzXvkT33TlYWXYtUzNwdUlqvI56zlQ2-ZtC2D898mekW3ergJoB0vKNxBqux-d0kJLLH6YidZuA4xl7E3aYXgcDUbgLBlS8PXnsxNLU4lqFg-tx8_MYYCVVFrlsp2_uY6GyS0ooEEWI_FvebyqAGhtJRPiCJkrwcHcTEX9byTuOjI7Axt6eSo6Cg6t3pVOfyY5uBM-Z-s1pxeDiEjl-D9GbxoxnTB-oGYq6P6u4uG6OEByT79sHo1flReOoOLh4MQ4dkaR0OHS6bzZyUjeEIuT6vyuzBWGV8uGlzYYXfX4QujsMTQM-20A8X_84OWq6KwsBJC790VaTdSK0AWWPHMRIDfAgNksr9W9Bnn2mGhDcUrquy8sBaFw6S8qlckG2uM7Rm_QvUxHV-4z_tvhdLObRs_3_dSo15qZTO2pPdCYu89tSkuLg6v-NHb9nPgVztcJdePDYw1ZHwIr0ha_HSjO3zIM36aJ16JN0qh9vcaZVe8KrKka2y9JMi0EZPvMnL9t78IIJB3sDU1ZTluq1KdA-4UnCo_BCo82W74oTcF_peKnaEI9VawsLelZuqH6qNAz510wRc72hIiPb6od4h7m8r5OLNAzmzMSKj3tK6OnHbht52ci5jXcNO9Z_0QW6R72HFPvEUlXjzBsNhM6pg8Zap3U8-dTkMfmblFkHSGu4cwvB-uTUsfGJ9q4QZLaTA_fekAVqHYedhsf20jbtbvA3b3ugLqza3Kb0QIAmO7EfeFmg-qSBZP4prLCyMNZ4IQdyOscJ1LGtFm2rkxNwQyOSqFNmvET81C9lud2TnikD4_6k3_vhpl4hvgMrm0uj9U170RgTi9ZCewwxochnf8qmmi8mFc9b6uFHLtdtAbIC4u8vsVwDG_gyBiVVi68saMgpwwT_ZYDLBA4hJvqM3M9sUB2RJYoBATlT_0WjIRXNBzhp8hdkdqrwERvjBC1cKH2XalPqYHI7aQoTZfKXvJnMTsKVraXiQ6TcWBhbfTyscUAc88O3z-0CRUv0Cn0APcgSUyaKtPQuG3bVKmfh0W8RittX3iPyIKMLsQmugQMqHg5SihIMoshvlrMXnmANwQ0L0qJYtHb2nFR4OoPaL7zE8Jo9vwxS4CaxE13VZt3Xj5_FtAgXaPoq0pVm1I0xJ-B3KkMa65mN_PmuORJGfRqODlr_x0JrDPGvByYVvy11prUPBRM9pOQBa9y3Xintx_xiR-0uVDhmPPdhgkarm074Fkfj7sNxicx2NIOT6QMlh6m_VXAwE0fxEUb_PRBQl-El02PgQcOlZZ1_JGrlxERFcX8cchBZQwmbMCGABHrnChuhoR-l_-aU_oeGVHWjXD_dq57MUmsuXoe2s48X073Y4hhXjedvloOGyod7WFc4VSB0uo3ipKnwkwuarw9b_4q0epU3mhybyQpqDys-qSAPucdyOVf9knttKG4s4zNDffdxPxZLKQfSgNKg11oI0zcrQYIfBDerzRW9VECihy64GWEGZvZ88pgHuDhbva8DtZf8MVLEG9kB3ZpuYXu3vvfgoZ209YdOF-9RoQaQuu1pFGGyVcGHWuELIreUw9uRlKKhwcih_jTqLT6e7S4KtS5Dck3t56npdx9iIauxocbos3sWke88faO5ZhUmc7E5Wy-f-jtFTjm9UaZdGsru1izJEuv.").unwrap();

        let decrypted = session_key
            .decipher_prt_v2(&mut softtpm, &msrsa_key, &enc_access_token)
            .unwrap();

        let expected_payload = b"{\"token_type\":\"Bearer\",\"expires_in\":\"1209599\",\"ext_expires_in\":\"0\",\"expires_on\":\"1708017084\",\"refresh_token\":\"0.AbcAblw1aGMKLUSi7HHMa7PiS4c7qjhtoBdIsnV6MWmI2TvJACY.AgABAAEAAAAmoFfGtYxvRrNriQdPKIZ-AgDs_wUA9P8JhDh2ZGgZJMbl8WvzRwn4FQN698G15Fhng20zMjR1OMFAuR65vnyoEvf7kZdIVik54ljWvg7vG7h23Sret_RYtkAS1MnXKy-eHXQDTuZm-Z5JzqfHZO-3JMChedsjVMJkhU_TpS5hFnN1VW8OLifZNaZMDY0W-iWxeKMQ9wnXlBLaCR8ZgLYYGF7k64N5fK3nYSIexeLkom-cGOP0st08M-N4teht4j811BmJIFkl2AzJEpuUU_DmZHPUyOiK_GXopSehpddw3xwCgZ7DF6rxEjKPP33REQE3LjZAtZWuOtH_9QeKzkD_YyExajvU8-liszws8d0yAvi2W4KeMKfAy8LR05CFGQAB0H380xx3IoBsVykiOLVeWU0eBLDePFKqYQCjXY9N_VTmkPovFwyKK-LuPKmJQ_03p30dk6b6xhJIpiy8G1PiHcObIMD6e8WsdlCbdvVhDk5x65G4ReecCLD0wpVpATVO2k9lJcnUTUugySkQtmW-AJDPsH5Yn-SsG75TZ2F1EB2fWG3DOd0k_HBSzvijostQUl6U0hwzwR2KO5Av7i_1SpQDn8MhgClAqyTwqxYU4g4RdqvadhIq6LWzmkq_T-FzkmIrcRV8nDetEtrdNJcbt0MxfryeByPkH_9F8Sql1YMdSFOatURvgb6WXRxqVEvYr4R7MppzTvuSc07jOMjAiI1DVCnxPHjEtd0NsTWFqQ0UIuOehYeT36v7_3CPhIGPjm6NkjlpPf2xOqHpbRGuGC748FadhdocjMXUzGtqQ6c4sk-tv2JXzQ\",\"refresh_token_expires_in\":1209599,\"id_token\":\"eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJhdWQiOiIzOGFhM2I4Ny1hMDZkLTQ4MTctYjI3NS03YTMxNjk4OGQ5M2IiLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC82ODM1NWM2ZS0wYTYzLTQ0MmQtYTJlYy03MWNjNmJiM2UyNGIvIiwiaWF0IjoxNzA2ODA3MTg0LCJuYmYiOjE3MDY4MDcxODQsImV4cCI6MTcwNjgxMTA4NCwiYW1yIjpbInB3ZCIsInJzYSJdLCJpcGFkZHIiOiI2OS4xNjMuNjYuOTYiLCJuYW1lIjoiVHV4Iiwib2lkIjoiOTBkNjc1ZGYtYmZhOC00ZDc4LThmOGYtN2IxMDQzMTgxYmI2IiwicHdkX3VybCI6Imh0dHBzOi8vcG9ydGFsLm1pY3Jvc29mdG9ubGluZS5jb20vQ2hhbmdlUGFzc3dvcmQuYXNweCIsInJoIjoiMC5BYmNBYmx3MWFHTUtMVVNpN0hITWE3UGlTNGM3cWpodG9CZElzblY2TVdtSTJUdkpBQ1kuIiwic3ViIjoiN1JoODRvOXlzSjZ3bjMwNFBFSTl1UDJ6R2Nzc05jb3lwLWp3YmR5VWxlTSIsInRlbmFudF9kaXNwbGF5X25hbWUiOiJNU0ZUIiwidGlkIjoiNjgzNTVjNmUtMGE2My00NDJkLWEyZWMtNzFjYzZiYjNlMjRiIiwidW5pcXVlX25hbWUiOiJ0dXhAMTBmcDd6Lm9ubWljcm9zb2Z0LmNvbSIsInVwbiI6InR1eEAxMGZwN3oub25taWNyb3NvZnQuY29tIiwidmVyIjoiMS4wIn0.\"}";
        assert!(decrypted.payload == expected_payload);
    }
}
