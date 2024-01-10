use crate::compact::{JweCompact, JweEnc};
use crate::jwe::Jwe;
use crate::traits::*;
use crate::JwtError;

use openssl::symm::{Cipher, Crypter, Mode};

use base64::{engine::general_purpose, Engine as _};
use openssl::rand::rand_bytes;

pub(crate) const KEY_LEN: usize = 16;
// 96 bit iv per Cipher::aes_128_gcm().iv_len()
const IV_LEN: usize = 12;
const AUTH_TAG_LEN: usize = 16;

#[derive(Clone)]
pub struct JweA128GCMEncipher {
    aes_key: [u8; KEY_LEN],
}

impl TryFrom<&[u8]> for JweA128GCMEncipher {
    type Error = JwtError;

    fn try_from(r_aes_key: &[u8]) -> Result<Self, Self::Error> {
        if r_aes_key.len() != KEY_LEN {
            return Err(JwtError::InvalidKey);
        }

        let mut aes_key = [0; KEY_LEN];
        aes_key.copy_from_slice(r_aes_key);

        Ok(JweA128GCMEncipher { aes_key })
    }
}

impl JweEncipherInnerK128 for JweA128GCMEncipher {}

impl JweEncipherInner for JweA128GCMEncipher {
    fn new_ephemeral() -> Result<Self, JwtError> {
        let mut aes_key = [0; KEY_LEN];
        rand_bytes(&mut aes_key).map_err(|ossl_err| {
            debug!(?ossl_err);
            JwtError::OpenSSLError
        })?;

        Ok(JweA128GCMEncipher { aes_key })
    }

    fn encipher_inner<O: JweEncipherOuter>(
        &self,
        outer: &O,
        jwe: &Jwe,
    ) -> Result<JweCompact, JwtError> {
        let mut header = jwe.header.clone();
        header.enc = JweEnc::A128GCM;

        outer.set_header_alg(&mut header)?;

        // Clone the header and update it with our details.
        let hdr_b64 = serde_json::to_vec(&header)
            .map_err(|e| {
                debug!(?e);
                JwtError::InvalidHeaderFormat
            })
            .map(|bytes| general_purpose::URL_SAFE_NO_PAD.encode(bytes))?;

        let content_enc_key = outer.wrap_key(&self.aes_key)?;

        let mut iv = vec![0; IV_LEN];
        rand_bytes(&mut iv).map_err(|ossl_err| {
            debug!(?ossl_err);
            JwtError::OpenSSLError
        })?;

        let (ciphertext, authentication_tag) = aes_gcm_encipher(
            Cipher::aes_128_gcm(),
            AUTH_TAG_LEN,
            &jwe.payload,
            hdr_b64.as_bytes(),
            &self.aes_key,
            &iv,
        )?;

        Ok(JweCompact {
            header,
            hdr_b64,
            content_enc_key,
            iv,
            ciphertext,
            authentication_tag,
        })
    }
}

impl JweA128GCMEncipher {
    pub fn key_len() -> usize {
        16
    }

    pub fn decipher_inner(&self, jwec: &JweCompact) -> Result<Vec<u8>, JwtError> {
        aes_gcm_decipher(
            Cipher::aes_128_gcm(),
            &jwec.ciphertext,
            jwec.hdr_b64.as_bytes(),
            &self.aes_key,
            &jwec.iv,
            &jwec.authentication_tag,
        )
    }
}

pub(crate) fn aes_gcm_encipher(
    cipher: Cipher,
    authentication_tag_bytes: usize,
    plaintext: &[u8],
    authenticated_data: &[u8],
    aes_key: &[u8],
    iv: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), JwtError> {
    let block_size = cipher.block_size();
    let mut ciphertext = vec![0; plaintext.len() + block_size];

    let mut encrypter =
        Crypter::new(cipher, Mode::Encrypt, aes_key, Some(iv)).map_err(|ossl_err| {
            error!(?ossl_err);
            JwtError::OpenSSLError
        })?;

    // Feed in additional data to be checked. Must be called before update.
    encrypter
        .aad_update(authenticated_data)
        .map_err(|ossl_err| {
            error!(?ossl_err);
            JwtError::OpenSSLError
        })?;

    let mut count = encrypter
        .update(plaintext, &mut ciphertext)
        .map_err(|ossl_err| {
            error!(?ossl_err);
            JwtError::OpenSSLError
        })?;

    count += encrypter.finalize(&mut ciphertext).map_err(|ossl_err| {
        error!(?ossl_err);
        JwtError::OpenSSLError
    })?;

    let mut authentication_tag = vec![0; authentication_tag_bytes];

    encrypter
        .get_tag(&mut authentication_tag)
        .map_err(|ossl_err| {
            error!(?ossl_err);
            JwtError::OpenSSLError
        })?;

    ciphertext.truncate(count);

    Ok((ciphertext, authentication_tag))
}

pub(crate) fn aes_gcm_decipher(
    cipher: Cipher,
    ciphertext: &[u8],
    authenticated_data: &[u8],
    aes_key: &[u8],
    iv: &[u8],
    authentication_tag: &[u8],
) -> Result<Vec<u8>, JwtError> {
    let block_size = cipher.block_size();
    let mut plaintext = vec![0; ciphertext.len() + block_size];

    let mut decrypter =
        Crypter::new(cipher, Mode::Decrypt, aes_key, Some(iv)).map_err(|ossl_err| {
            error!(?ossl_err);
            JwtError::OpenSSLError
        })?;

    decrypter.pad(true);
    decrypter.set_tag(authentication_tag).map_err(|ossl_err| {
        error!(?ossl_err);
        JwtError::OpenSSLError
    })?;

    // Feed in additional data to be checked. Must be called before update.
    decrypter
        .aad_update(authenticated_data)
        .map_err(|ossl_err| {
            error!(?ossl_err);
            JwtError::OpenSSLError
        })?;

    let mut count = decrypter
        .update(ciphertext, &mut plaintext)
        .map_err(|ossl_err| {
            error!(?ossl_err);
            JwtError::OpenSSLError
        })?;

    count += decrypter.finalize(&mut plaintext).map_err(|ossl_err| {
        error!(?ossl_err);
        JwtError::OpenSSLError
    })?;

    plaintext.truncate(count);

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::JweA128GCMEncipher;
    use crate::crypto::a128kw::JweA128KWEncipher;
    use crate::jwe::JweBuilder;

    #[test]
    fn a128kw_outer_a128gcm_inner() {
        let _ = tracing_subscriber::fmt::try_init();

        let input = vec![1; 128];
        let jweb = JweBuilder::from(input.clone()).build();

        let jwe_a128kw =
            JweA128KWEncipher::generate_ephemeral().expect("Unable to build wrap key.");

        let jwe_encrypted = jwe_a128kw
            .encipher::<JweA128GCMEncipher>(&jweb)
            .expect("Unable to encrypt.");

        let decrypted = jwe_a128kw
            .decipher(&jwe_encrypted)
            .expect("Unable to decrypt.");

        assert_eq!(decrypted.payload(), input);
    }
}
