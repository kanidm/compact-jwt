use crate::compact::JweCompact;
use crate::JwtError;

use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::sign::Signer;
use openssl::symm::{Cipher, Crypter, Mode};

const AES_KEY_LEN: usize = 16;
pub const HMAC_KEY_LEN: usize = 16;
const HMAC_SIG_LEN: usize = 32;
const HMAC_TRUNC_SIG_LEN: usize = 16;

#[derive(Clone)]
pub struct JweA128CBCHS256Decipher {
    hmac_key: [u8; HMAC_KEY_LEN],
    aes_cbc_key: [u8; AES_KEY_LEN],
}

impl TryFrom<&[u8]> for JweA128CBCHS256Decipher {
    type Error = JwtError;

    fn try_from(aes_cbc_hmac_key: &[u8]) -> Result<Self, Self::Error> {
        if aes_cbc_hmac_key.len() != AES_KEY_LEN + HMAC_KEY_LEN {
            return Err(JwtError::InvalidKey);
        }

        // https://www.rfc-editor.org/rfc/rfc7516.html#appendix-B
        let (r_hmac_key, r_aes_cbc_key) = aes_cbc_hmac_key.split_at(HMAC_KEY_LEN);

        let mut hmac_key = [0; HMAC_KEY_LEN];
        hmac_key.copy_from_slice(r_hmac_key);
        let mut aes_cbc_key = [0; AES_KEY_LEN];
        aes_cbc_key.copy_from_slice(r_aes_cbc_key);

        Ok(JweA128CBCHS256Decipher {
            hmac_key,
            aes_cbc_key,
        })
    }
}

impl JweA128CBCHS256Decipher {
    pub fn key_len() -> usize {
        AES_KEY_LEN + HMAC_KEY_LEN
    }

    pub fn decipher_inner(&self, jwec: &JweCompact) -> Result<Vec<u8>, JwtError> {
        // hmac
        let hmac_key = PKey::hmac(&self.hmac_key).map_err(|ossl_err| {
            debug!(?ossl_err);
            JwtError::OpenSSLError
        })?;

        let mut hmac_signer =
            Signer::new(MessageDigest::sha256(), &hmac_key).map_err(|ossl_err| {
                debug!(?ossl_err);
                JwtError::OpenSSLError
            })?;

        let additional_auth_data = jwec.hdr_b64.as_bytes();

        // This is the number of *bits* which is why we mul by 8 here.
        let additional_auth_data_length = ((additional_auth_data.len() * 8) as u64).to_be_bytes();

        let mut hmac_data = additional_auth_data.to_vec();
        hmac_data.extend_from_slice(&jwec.iv);
        hmac_data.extend_from_slice(&jwec.ciphertext);
        hmac_data.extend_from_slice(&additional_auth_data_length);

        // Create the hmac.
        let mut hmac_sig = hmac_signer
            .sign_oneshot_to_vec(hmac_data.as_slice())
            .map_err(|ossl_err| {
                debug!(?ossl_err);
                JwtError::OpenSSLError
            })?;

        // trunc the hmac to 16 bytes.
        if hmac_sig.len() != HMAC_SIG_LEN {
            debug!("Invalid hmac signature was generated");
            return Err(JwtError::OpenSSLError);
        }

        hmac_sig.truncate(HMAC_TRUNC_SIG_LEN);

        if hmac_sig != jwec.authentication_tag {
            debug!("Invalid hmac over authenticated data");
            return Err(JwtError::InvalidSignature);
        }

        // Header and other bits have been authed now. Decrypt the payload.
        // Seems weird that the keys aren't maced?

        let cipher = Cipher::aes_128_cbc();

        decipher(cipher, &self.aes_cbc_key, &jwec.ciphertext, &jwec.iv)
    }
}

pub(crate) fn decipher(
    cipher: Cipher,
    aes_cbc_key: &[u8],
    ciphertext: &[u8],
    iv: &[u8],
) -> Result<Vec<u8>, JwtError> {
    let block_size = cipher.block_size();
    let plaintext_len = ciphertext.len() + block_size;
    let mut plaintext = vec![0; plaintext_len];

    let mut decrypter =
        Crypter::new(cipher, Mode::Decrypt, aes_cbc_key, Some(iv)).map_err(|ossl_err| {
            debug!(?ossl_err);
            JwtError::OpenSSLError
        })?;

    decrypter.pad(true);

    let mut count = 0;

    let mut idx = 0;
    let mut cipher_boundary = idx + block_size;
    let mut plaintext_boundary = count + (block_size * 2);

    // Only works because of CBC mode - cipher text will be block_size * N, and
    // plaintext_len will be block_size * (N + 1).
    //
    // Unclear if padding is needed?
    while idx < ciphertext.len() {
        let cipher_chunk = &ciphertext[idx..cipher_boundary];
        let mut_plaintext_chunk = &mut plaintext[count..plaintext_boundary];

        count += decrypter
            .update(cipher_chunk, mut_plaintext_chunk)
            .map_err(|ossl_err| {
                debug!(?ossl_err);
                JwtError::OpenSSLError
            })?;

        idx += block_size;
        cipher_boundary = idx + block_size;
        plaintext_boundary = count + (block_size * 2);
    }

    let mut_plaintext_chunk = &mut plaintext[count..plaintext_boundary];

    count += decrypter
        .finalize(mut_plaintext_chunk)
        .map_err(|ossl_err| {
            debug!(?ossl_err);
            JwtError::OpenSSLError
        })?;

    plaintext.truncate(count);

    Ok(plaintext)
}
