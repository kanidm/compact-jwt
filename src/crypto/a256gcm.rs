use crate::compact::{JweCompact, JweEnc};
use crate::jwe::Jwe;
use crate::traits::*;
use crate::JwtError;

use openssl::symm::Cipher;

use base64::{engine::general_purpose, Engine as _};
use openssl::rand::rand_bytes;

pub(crate) const KEY_LEN: usize = 32;

// 96 bit iv per Cipher::aes_256_gcm().iv_len()
const IV_LEN: usize = 12;
const AUTH_TAG_LEN: usize = 16;

/// A JWE inner encipher and decipher for AES 256 GCM.
#[derive(Clone)]
pub struct JweA256GCMEncipher {
    aes_key: [u8; KEY_LEN],
}

#[cfg(all(test, feature = "msextensions"))]
impl JweA256GCMEncipher {
    pub(crate) fn raw_key(&self) -> [u8; KEY_LEN] {
        self.aes_key
    }
}

impl TryFrom<&[u8]> for JweA256GCMEncipher {
    type Error = JwtError;

    fn try_from(r_aes_key: &[u8]) -> Result<Self, Self::Error> {
        if r_aes_key.len() != KEY_LEN {
            return Err(JwtError::InvalidKey);
        }

        let mut aes_key = [0; KEY_LEN];
        aes_key.copy_from_slice(r_aes_key);

        Ok(JweA256GCMEncipher { aes_key })
    }
}

impl From<&[u8; 32]> for JweA256GCMEncipher {
    fn from(r_aes_key: &[u8; 32]) -> Self {
        let mut aes_key = [0; KEY_LEN];
        aes_key.copy_from_slice(r_aes_key);

        JweA256GCMEncipher { aes_key }
    }
}

impl JweEncipherInnerK256 for JweA256GCMEncipher {}

impl JweEncipherInner for JweA256GCMEncipher {
    fn new_ephemeral() -> Result<Self, JwtError> {
        let mut aes_key = [0; KEY_LEN];
        rand_bytes(&mut aes_key).map_err(|ossl_err| {
            debug!(?ossl_err);
            JwtError::OpenSSLError
        })?;

        Ok(JweA256GCMEncipher { aes_key })
    }

    fn encipher_inner<O: JweEncipherOuter>(
        &self,
        outer: &O,
        jwe: &Jwe,
    ) -> Result<JweCompact, JwtError> {
        let mut header = jwe.header.clone();
        header.enc = JweEnc::A256GCM;

        outer.set_header_alg(&mut header)?;

        // Clone the header and update it with our details.
        let hdr_b64 = serde_json::to_vec(&header)
            .map_err(|e| {
                debug!(?e);
                JwtError::InvalidHeaderFormat
            })
            .map(|bytes| general_purpose::URL_SAFE_NO_PAD.encode(bytes))?;

        let content_enc_key = outer.wrap_key(&self.aes_key)?;

        // IV must always be random!
        let mut iv = vec![0; IV_LEN];
        rand_bytes(&mut iv).map_err(|ossl_err| {
            debug!(?ossl_err);
            JwtError::OpenSSLError
        })?;

        let (ciphertext, authentication_tag) = super::a128gcm::aes_gcm_encipher(
            Cipher::aes_256_gcm(),
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

impl JweA256GCMEncipher {
    /// The required length for this cipher key
    pub fn key_len() -> usize {
        KEY_LEN
    }

    pub(crate) fn decipher_inner(&self, jwec: &JweCompact) -> Result<Vec<u8>, JwtError> {
        super::a128gcm::aes_gcm_decipher(
            Cipher::aes_256_gcm(),
            &jwec.ciphertext,
            jwec.hdr_b64.as_bytes(),
            &self.aes_key,
            &jwec.iv,
            &jwec.authentication_tag,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::JweA256GCMEncipher;
    use crate::crypto::a256kw::JweA256KWEncipher;
    use crate::jwe::JweBuilder;
    use crate::JweCompact;
    use std::str::FromStr;
    use crate::compact::JweEnc;
    use crate::jwe::Jwe;

    #[test]
    fn a256kw_outer_a256gcm_inner() {
        let _ = tracing_subscriber::fmt::try_init();

        let input = vec![1; 256];
        let jweb = JweBuilder::from(input.clone()).build();

        let jwe_a256kw =
            JweA256KWEncipher::generate_ephemeral().expect("Unable to build wrap key.");

        let jwe_encrypted = jwe_a256kw
            .encipher::<JweA256GCMEncipher>(&jweb)
            .expect("Unable to encrypt.");

        let decrypted = jwe_a256kw
            .decipher(&jwe_encrypted)
            .expect("Unable to decrypt.");

        assert_eq!(decrypted.payload(), input);
    }

    #[test]
    fn a256gcm_decipher_msextensions_token() {
        let raw = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIiwiY3R4IjoiWkpkUXJpQkpxZlM3VUZBMmI4RWQrYU9xZWVsVER3UG0ifQ..8ZwlCF-0chKR7h_z.NbejWx9LqnWRGWSSANQCLfy8KPal7TJ-6ss9VsoLo1bWbVDkhkpVen1zv2SrnNzcZxNUTHW3eOBXDRfuDgw-AI3XtHdiSEex868EwIH4D4aPW31NNGYF2lZr67F2rtPymrqfNFKBdR8dFptlmWd54sCpWj2lMXX-GFNZ9P5kPLXMKes84UMbdFHA3Agz4Mg79n9_JwETvCWV9DPUQ_AAq7QVRuUcZpnrKj0AEtUO98wqxXe4EDZ2LAEneB1IfzOsn9UJCwp7xQ1AXCECBYsAe5X6kFao3va3lkmLddGtxomCSEJg8XfakXkYgi7HnsTM_VvFUASyZyOK5g-kNkmER5RkSwPmusAvYis9GY0udbn1o8CHkeSVK2MPZv75W3Ux7oWP0QbV9vasO2jxdxkpJSaZqxnRIy7Z47XhnfisDcRlpg5uDStrHPVKDWGq2iwrL2zeLY1XdOtjMJDfJOEwZQE-FeDBGrDvyng0X45WBrFd9_nR3Qvuh8SOPKdbeLoPNWx-4L6z9o5cdRsgaZ4HOZQboB_mDr0UhD8P1A4DUWRCdz8u5hB6MR25npBcnrttnOwJ5vvvrivYoLdq-uq1-qRujy8NWVQ6pcTnHkukRYnMQgPmJvAc-yqevWl035n1Xv6IqIN9emExlZKwU_P--scDJQ4KF5hn8XX_q3X8InBge1mXFSsPHtVmg-KtkDpanEhgoKIGqS4Gjbwhhjtxx1vdyG2WwHQQT_JM7hcvG5r_9D6eAjqUAN_FCQQswwlXGFD4MxVX841Pb6xhPt8NzIXqe0e-NR4vw0sfgG0o-6T0FgPfLi8LpGfet7M8ct5j68YfOpz5kWtt2hNf98FTfZ6sPLVj7nelshWrYngYFReqBcePVLN-Jul8De074ko4brl23gvpw2l3aXe862ctHFGil7HClPIwGMqB5iIleNKWa_HxilAGPuBlfDQGNjkEP5SJp6TyZZt4_q2ALgzWs9fd-BJ-P0rLLkaVH2mxyBuJjqhDcSSVDuSoZejE17G4oYuKntEbeWDQs2gGEMmn2aPzbLQhw9kMN3WvWiCdl-c3j-oOmIWrrmpcOk3mMcLIKFthXkJ7g-baap7LP0dEwS3YpDXvkpCgE2coJ6Twpj4Y38hxlRACWmFU8_I2baKNN04UjHp2xJwUNFM898LlHM8iOc96LXBNXYmoaN4FymVIoYwvP0XKJ8WYXm_T4k1d-7pgPlEda1ovpm3QPhxlRPjodXSDW4Q4O10EtNjX616J07qDcdKzrjIXKrzf79f6_Yqxn36z3EGQiIDGppc4g5SyGcaw56aYHu0lNnTK9ACOf-c5OiObg06TKICc5FZmJ7_Cvmazav87fHpW03e6alyJe_WZPV8FJvghNRXaY3DUrLB5gOV1CVMhpZniR5FOclEcWAhx2CUpbnCktlRzlD8xHcYXia1iaUAdWMD08gxoPhCOt6ZbnKK9gmUMP93BtDUUIf7mC8oFcKfjn0ovBl2hyZElwa8ViEYN_lw3EjN-oIDMb8WlYHeGvGoXqwBZqU2FhPsx5WBSks6v9eYm-jcXNbhC1g1eXeVd9PQ0l2ifEhpaLqt5JP2gjQGLPB6ft8ZtH0nvlSIeRZwBejBvuxBq8dUWetqL83cAceZ-DxO2zWEHp_sW6oJp8M16-pBW3B9RMwAln8KODBFwnpT8sOKZ_39YKXC36c33euce58U1wxXp2kWksRk77U_pRV18re2Ufms2IbWcd6nmfBSYAxzfv6EjTpsHcu2PkK5pEHBNG2_aUob90k0eu0HYYAK_d_FozpyUd3ieF0AV6dxnyOc8CeqJ7GMkD3QRInnKfAhdMRP1Ld9pU2LabHJg5O6g_TZvtSrI0EalZtpDGCZmv9aIcgEAGrQCtWeHULBA1nC4wAOM4usIMIW3PxF-CeEqrfU6k4UVZ7QRfYCpfP1bLlwHsUyScur0VUx92eqx1GCy-t-eCKLlDUrqn0v5IaMNI0iQd2HDR68ktvFcdnerDyK1n-mq4c8ljDvS-Jlo1_zqew9wPaZC0H1ddTLg55DAHvoKaE6sit7tx_QgMBBMSYxcT-EqurtLC3TTbfpd6MYZaXdGKL3EIfUCWMH_rBtt_P6xZdqOQ0kNWl4F0udRRrsOg4OEkBlc_HUT4bkiAXicS2vKQqfDxm2bmKSYVzkiO_LhTsfYgjQswhHF8hRo-oYlUHEIzR7y69PCpkVSwnQPUCBWArIeIrVxrk9KyHxSOL_JNOlUNKgBHZtFlb3G3zKOZhr1Ep8GnHhoFTJ8BCwaduP9q_b0kGpOcfT-fsGLy9bLyw8bpDdxOQYCZNmg-CP5S33mI5ldcQLHmgR1DDr86Z6QJTkFaNsX51HtL7ZW9nZt-IwzObZamL4xKbVJBoQPWThX7dX_p_bE-UyjeoxZ_zxoNuFRJobIa8GFGmxqTOIEDlxfoNiIp0PPkepzQOYrKzPrDI51A357CdwYs8FEFNuYecRxGwIC5iN8-MaBMjI-PChnbvxYIe1sCrI3VbEcxCt00dLEOmkhkrGvk0qulIEsOa-18t4gubqzrIeOPj7utawJA7fewzCuPg9zZZD0PB0lZ0Mc7DeVs5HTMHkXk3y0SBDMolWuwlnY0jE69-teBRwFQyDEmcuGCuaa0a0rTXZHs2u5rkxTQVIazMGPXgBf3bijYxNzuXiwEneQAsT-7ws1x6QZLTvOFIRshl6tXUzCkopNx90qN_Rxo0FS-9LeFds_zYfsyOFTXJs4GODfGbG7qKGojR_PY5nAb5h0AHvZWmWxq0WBAXmjoJgEXk-ilrpKWacF0luJFlkzUDvJR7uEaELpVi_vHTzwG5CCqol974QpaadinjRgHVOA0pJsUsaGctz8AI1eXockb4ybM6iBycMR1OWGvkIMpqaL7MKHJU2BDd_Ar27jHjVXxVzXyLi2K0p4MEjJs4U3LPm6koZuqiFdEgFBBxsLdQ8mPmnoBnvN3i0y2h_gatfvz-0hWvPyhtt3OnEKB6wrXs7ukyJh5pAFa0NMXSFUdMnnG9fI_q5ABpEhfM3i4WZAIP_CWAgCXXJhLnVYQGEeOw4Lavv3bNBDh9_x8U61ObrAC158v-LTrEq0LZk2jHBq-obCUCGt6gEMw3iPsTznZMtsYLt2fLpu7aRtUeJ0uka1UZhFFUfQltnM_uYZuUOKbxGyf5uZQCopSgPbtN6ZmeH1YKRqf8i6VOsIDONLuNhbUbg3UtimCcoLD88LFIXejOX1cbriiWzrlMu6cpiny_HCQuo0lezcPb0sinCTaAqwl1YFT2043CKyxF7NYvUF-9GN8wzueHAiZLKbdw3Nb7d7ZFz2DUNYvnWnZlHKGFR8NnkO75QSpkwd2XEGu2gj1lr7qjFQJUcOHue77fsmsICHiGS0PC23ElW8oDcvTG6kM4qLgOJj60tBuu2Sxzvdd7anTpMtrhLyekGnSqsCX3EwLZJ45hggaXr97OF31MNFABt2Wqtae7Z-S_u4xEGPmaxU36NjtEjAheeWovYyG6pJ9cke6sUVGR02n3wuw9LzjiH0M7i0ohrw2h6-zqreteS1dFEObHrb2nCk4CdfroedzBLlMaHOt0S1ynnSyDkVDSot--Q0biM1D-QuvOWOAESM13MjljtWXXTYOCnSJOdlEWNNax-i654D8usVXq1kHgzddStEI1ad4jWHMjNawt5zPM1fTB1xoi9jn6QVeCLYBt6Wb6KsStXBKSEj6REBfU1upbSd52yIJZOqCLJyMAh4607zNS6jJkp9pf_fgHesTk0bPGv-Dozp6vP3jhpaGzKmdorM4GBZoHE9jlXJ-CzCkbmtDSk1bfl-tUln8R6fJtpHuyftbXCj3vP-kaJ2kicou5XIlU67Ih91ENyF2JhTMv4PbvrJBaY2MZZSlz-lnvUvx7Z2-blzRxAZLsV4YJVd3lVmPXDKjCZueq_9eqCwYtzQn2A_eK0hPA-zLaSBO_g7p-9ohpoGfBIaOzWSdFtlR16LuUx6EgwUAFx-qxg4I0i-mhBtABHP6aqyy6hWujXd770ygaNyyvb75ZYOdfRRHW6r2kj2rhrIudchALimbsxOwN9f5-ucGXsOPXuQiDFEo5lH1MfWbOb5g9r8Rak77TicFd2vHYnqfND0KKQUpM2iFhSHrrLboNrLtV0u4NNBwAD02hgZQihzNilDy6aJNLUn0vy_L-7aV_LN2ywQ7Mt-jTrnm1uBnGs_gmgoiv4vG-qpu9EV5KwA02oty-0-m8A-Fal4-Dm6lT8eMzcsm8zKllsmM_PqLzvavwHkpk9e8BdWLFcxwXDHFNb2IuDKVHX7vshBx-Zm_5Gqz7hWbP5Ua0XXHvD288hV6qx4NfjcGhWM1HbIC8zHkkDqyDYq8weBvr2H8mhqLOP4b6ED0C3kFd8_TmsMSo6RRmYreXT3gwjFQeOMZwlvi7670Hy_RrjfCbsR46HaWrkxAzMJwhvOoar7_zHojuOzuV7srAAIHdDivNb8y7KFyaYubJWP8yQTKcmwPWXV8LtFwv7m2v92XlBBBY2PQCuXEQyhGfm1cOv_LZT0lrMg4op7fvbZKrfvcjJNZdIfVk5gE9fWY_UFjk3GNYu6ubw_ntoOMvbxSsJKjcgtaJyf2AqBKbu05uaD1KhcRMgE9vtwqihLvKFvEKiMBvq0T8W_ZWaqsa7kT1HijvTyGo_ajFYno6Kt9zP2ilI2iQMSheEnFcKS8Oyi_8dJkZREh69H3cnAyBe7JcVty8PxOWUw6SR78QmM2-eTo3N4xaWVL2f-xSo1cEd5Fk5U-frbhzkL4dF8XRIaEvXgmJfmFSOa_jzQmdD6zAXL43ncUncHmjCd4lDZPRITfhb4U-pYVX_fGiNrCFyyVq2wK4kvY4TCZHAZ5bgRljjzHSpjxRqInsM2xCzc_GKzTWy5-o9hh6-kYzGCtke_rHT1W3o9eiHACDGwbI14ghOsXSRQkfMAGPZp0ELKRqkgAEvbkpbxwkBtzjfX0H7Xcn4VaB0_lHNV40kZVgd4rRZj9nRYg6tN1S7xuZaXeYvEI8z5Ejvc0q_aTBWsGTDEPX0o558i2Ws.4DgHGHnRuyofwS5wAHWD4g";
        let jwec = JweCompact::from_str(&raw).expect("Failed loading jwe");
        assert_eq!(jwec.header.enc, JweEnc::A256GCM);
        let aes_key = [
            231, 208, 197, 235, 235, 47, 87, 113, 191, 167, 33, 252, 192, 50, 217, 86, 39, 107,
            251, 93, 135, 147, 219, 91, 44, 142, 21, 142, 236, 14, 24, 216,
        ];
        let a256gcm = JweA256GCMEncipher::try_from(aes_key.as_slice())
            .expect("Failed loading JweA256GCMEncipher");
        a256gcm.decipher_inner(&jwec).map(|payload| Jwe {
            header: jwec.header.clone(),
            payload,
        }).expect("Failed decrypting JWE!");
    }
}
