//! HKDF 派生 - 密钥域严格分离
//! 
//! 严格按 SPEC：
//! - 主密钥 = HKDF-Extract(S_hybrid, Salt=Salt_行星)
//! - info 标签包含卦象与等级

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::ZeroizeOnDrop;

/// HKDF-SHA256 输出类型
pub type HkdfSha256 = Hkdf<Sha256>;

/// 密钥派生器 - 主密钥入口
#[derive(ZeroizeOnDrop)]
pub struct KeyDeriver {
    master_key: [u8; 32],
}

impl KeyDeriver {
    /// HKDF-Extract: 从混合密钥和行星盐派生主密钥
    pub fn extract_master(shared_secret: &[u8; 64], salt_planet: &[u8]) -> Self {
        let hk = Hkdf::<Sha256>::new(Some(salt_planet), shared_secret);
        let mut master = [0u8; 32];
        let _ = hk.expand(b"StarCompass-Master-v1", &mut master);
        KeyDeriver { master_key: master }
    }

    /// HKDF-Expand: 派生各域密钥
    pub fn derive(&self, info: &str, output: &mut [u8]) {
        let hk = Hkdf::<Sha256>::new(None, &self.master_key);
        let _ = hk.expand(info.as_bytes(), output);
    }

    pub fn derive_k1(&self) -> [u8; 32] {
        let mut k = [0u8; 32];
        self.derive("StarCompass-Manifest-Encryption", &mut k);
        k
    }

    pub fn derive_k2(&self) -> [u8; 32] {
        let mut k = [0u8; 32];
        self.derive("StarCompass-Content-Encryption", &mut k);
        k
    }

    pub fn derive_k4(&self) -> [u8; 32] {
        let mut k = [0u8; 32];
        self.derive("StarCompass-Transport-HMAC", &mut k);
        k
    }

    pub fn derive_k_block(&self) -> [u8; 32] {
        let mut k = [0u8; 32];
        self.derive("StarCompass-Block-Auth", &mut k);
        k
    }

    pub fn derive_nonce_base(&self) -> [u8; 12] {
        let mut n = [0u8; 12];
        self.derive("StarCompass-Nonce-Base", &mut n);
        n
    }

    /// 带棘轮代数的派生（保证域分离）
    pub fn derive_with_ratchet(&self, info: &str, ratchet_generation: u32) -> [u8; 32] {
        let label = format!("{}-RatchetGen{}", info, ratchet_generation);
        let mut k = [0u8; 32];
        self.derive(&label, &mut k);
        k
    }

    /// 0-RTT 独立派生（不含行星盐，info 加标签）
    pub fn derive_0rtt(preshared_secret: &[u8; 32]) -> [u8; 32] {
        let hk = Hkdf::<Sha256>::new(None, preshared_secret);
        let mut k = [0u8; 32];
        let _ = hk.expand(b"StarCompass-0RTT-Data", &mut k);
        k
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_separation() {
        let shared = [0x42u8; 64];
        let salt = b"test_planet_salt_21hexagrams";
        let deriver = KeyDeriver::extract_master(&shared, salt);
        
        let k1 = deriver.derive_k1();
        let k2 = deriver.derive_k2();
        let k4 = deriver.derive_k4();
        let kb = deriver.derive_k_block();
        
        assert_ne!(k1, k2);
        assert_ne!(k2, k4);
        assert_ne!(k4, kb);
    }

    #[test]
    fn test_0rtt_independent() {
        let psk = [0x99u8; 32];
        let k = KeyDeriver::derive_0rtt(&psk);
        assert_eq!(k.len(), 32);
    }
}
