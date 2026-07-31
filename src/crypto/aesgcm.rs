//! AES-256-GCM + GMAC 核心实现

use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{AeadInPlace, NewAead};
use generic_array::typenum::U12;
use generic_array::GenericArray;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::ZeroizeOnDrop;

type HmacSha256 = Hmac<Sha256>;
type NonceArray = GenericArray<u8, U12>;

/// Nonce 结构：96-bit (12 bytes)
#[derive(Clone, ZeroizeOnDrop)]
pub struct NonceData([u8; 12]);

impl NonceData {
    /// Nonce_Base XOR 消息计数器（低8字节）
    pub fn with_counter(base: &[u8; 12], counter: u64) -> Self {
        let mut n = *base;
        let c_bytes = counter.to_le_bytes();
        for i in 0..8 {
            n[4 + i] ^= c_bytes[i];
        }
        NonceData(n)
    }

    pub fn as_bytes(&self) -> &[u8; 12] {
        &self.0
    }

    fn to_generic(&self) -> NonceArray {
        GenericArray::from_slice(&self.0).clone()
    }
}

impl From<[u8; 12]> for NonceData {
    fn from(arr: [u8; 12]) -> Self {
        NonceData(arr)
    }
}

/// AES-256-GCM 加密/解密（支持AAD）
pub struct AeadCipher {
    key: [u8; 32],
}

impl AeadCipher {
    pub fn new(key: &[u8; 32]) -> Self {
        Self { key: *key }
    }

    /// 加密：K2 用于内容加密
    /// 输出：ciphertext || GCM tag (16 bytes)
    pub fn encrypt(&self, nonce: &NonceData, aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let cipher = Aes256Gcm::new_from_slice(&self.key).expect("valid key");
        let nonce_arr = nonce.to_generic();
        let mut buffer = plaintext.to_vec();
        let tag = cipher
            .encrypt_in_place_detached(&nonce_arr, aad, &mut buffer)
            .expect("encryption should not fail");
        buffer.extend_from_slice(&tag);
        buffer
    }

    /// 解密：验证 GCM tag，失败返回 None
    pub fn decrypt(&self, nonce: &NonceData, aad: &[u8], ciphertext: &[u8]) -> Option<Vec<u8>> {
        if ciphertext.len() < 16 {
            return None;
        }
        let cipher = Aes256Gcm::new_from_slice(&self.key).expect("valid key");
        let nonce_arr = nonce.to_generic();
        let ct_len = ciphertext.len() - 16;
        let mut buffer = ciphertext[..ct_len].to_vec();
        let tag = GenericArray::from_slice(&ciphertext[ct_len..]);
        cipher
            .decrypt_in_place_detached(&nonce_arr, aad, &mut buffer, tag)
            .ok()?;
        Some(buffer)
    }
}

/// GMAC（8字节截断）
pub struct BlockAuth {
    key: [u8; 32],
}

impl BlockAuth {
    pub fn new(key: &[u8; 32]) -> Self {
        Self { key: *key }
    }

    /// 计算 8 字节截断 GMAC
    pub fn compute_tag(&self, data: &[u8]) -> [u8; 8] {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&self.key)
            .expect("HMAC accepts any key size");
        mac.update(data);
        let result = mac.finalize().into_bytes();
        let mut tag = [0u8; 8];
        tag.copy_from_slice(&result[..8]);
        tag
    }

    /// 恒定时间验证标签
    #[inline(always)]
    pub fn verify_tag(&self, data: &[u8], expected: &[u8; 8]) -> bool {
        let computed = self.compute_tag(data);
        let mut diff = 0u8;
        for i in 0..8 {
            diff |= computed[i] ^ expected[i];
        }
        diff == 0
    }
}

/// 传输层 HMAC（K4）
pub struct HmacTransport {
    key: [u8; 32],
}

impl HmacTransport {
    pub fn new(key: &[u8; 32]) -> Self {
        Self { key: *key }
    }

    pub fn compute(&self, data: &[u8]) -> [u8; 32] {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&self.key)
            .expect("HMAC accepts any key size");
        mac.update(data);
        let result = mac.finalize().into_bytes();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        out
    }

    #[inline(always)]
    pub fn verify(&self, data: &[u8], expected: &[u8; 32]) -> bool {
        let computed = self.compute(data);
        let mut diff = 0u8;
        for i in 0..32 {
            diff |= computed[i] ^ expected[i];
        }
        diff == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nonce_counter() {
        let base = [0x01u8; 12];
        let n1 = NonceData::with_counter(&base, 0);
        let n2 = NonceData::with_counter(&base, 1);
        assert_ne!(n1.0, n2.0);
    }

    #[test]
    fn test_gcm_encrypt_decrypt() {
        let key = [0x42u8; 32];
        let cipher = AeadCipher::new(&key);
        let nonce_base = [0xAAu8; 12];
        let nonce = NonceData::with_counter(&nonce_base, 0);
        let aad = b"session_id_123";
        let plaintext = b"Hello, Star Compass!";
        let ciphertext = cipher.encrypt(&nonce, aad, plaintext);
        let decrypted = cipher.decrypt(&nonce, aad, &ciphertext);
        assert_eq!(decrypted, Some(plaintext.to_vec()));
    }

    #[test]
    fn test_block_auth() {
        let key = [0x55u8; 32];
        let auth = BlockAuth::new(&key);
        let data = b"test block data";
        let tag = auth.compute_tag(data);
        assert!(auth.verify_tag(data, &tag));
        assert!(!auth.verify_tag(b"wrong data", &tag));
    }
}
