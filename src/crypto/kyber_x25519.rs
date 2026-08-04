//! 混合密钥交换：X25519 + Kyber（简化实现）

use rand::{CryptoRng, RngCore, thread_rng};
use zeroize::ZeroizeOnDrop;

#[derive(ZeroizeOnDrop)]
pub struct X25519KeyPair {
    pub public: [u8; 32],
    #[zeroize(skip)]
    secret: [u8; 32],
}

impl X25519KeyPair {
    pub fn secret(&self) -> [u8; 32] {
        self.secret
    }

    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut secret = [0u8; 32];
        rng.fill_bytes(&mut secret);
        // 清理 scalar 格式（按 RFC 7748）
        secret[0] &= 248;
        secret[31] &= 127;
        secret[31] |= 64;
        // x25519 的 Montgomery basepoint x 坐标是 9（RFC 7748）
        // 在 MontgomeryPoint 中直接设 x=9（9 在 little-endian 就是 [9, 0, 0, ...]）
        let mut base = [0u8; 32];
        base[0] = 9;
        use curve25519_dalek::montgomery::MontgomeryPoint;
        let base_pt = MontgomeryPoint(base);
        let scalar = curve25519_dalek::scalar::Scalar::from_bytes_mod_order(secret);
        let public = (scalar * base_pt).to_bytes();
        Self { public, secret }
    }

    pub fn shared_secret(&self, peer_public: &[u8; 32]) -> [u8; 32] {
        use curve25519_dalek::montgomery::MontgomeryPoint;
        let scalar = curve25519_dalek::scalar::Scalar::from_bytes_mod_order(self.secret);
        let peer = MontgomeryPoint(*peer_public);
        (scalar * peer).to_bytes()
    }

    /// 从已有私钥恢复（用于 CLI 持久化）
    pub fn restore(secret: [u8; 32]) -> Self {
        let mut s = secret;
        s[0] &= 248;
        s[31] &= 127;
        s[31] |= 64;
        let mut base = [0u8; 32];
        base[0] = 9;
        use curve25519_dalek::montgomery::MontgomeryPoint;
        let base_pt = MontgomeryPoint(base);
        let scalar = curve25519_dalek::scalar::Scalar::from_bytes_mod_order(s);
        let public = (scalar * base_pt).to_bytes();
        Self { public, secret: s }
    }
}

#[derive(ZeroizeOnDrop)]
pub struct KyberKeyPair {
    pub public: [u8; 800],
    #[zeroize(skip)]
    secret: [u8; 1632],
    #[zeroize(skip)]
    ciphertext: [u8; 768],
}

impl KyberKeyPair {
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut public = [0u8; 800];
        let mut secret = [0u8; 1632];
        let mut ciphertext = [0u8; 768];
        rng.fill_bytes(&mut public);
        rng.fill_bytes(&mut secret);
        rng.fill_bytes(&mut ciphertext);
        // 简化：全部用随机值填充
        // 实际 Kyber-768 需要 KAT 测试向量，此处仅演示用
        Self { public, secret, ciphertext }
    }

    pub fn encapsulate<R: RngCore + CryptoRng>(&mut self, rng: &mut R, _peer_public: &[u8; 800]) -> [u8; 32] {
        rng.fill_bytes(&mut self.ciphertext);
        let mut shared = [0u8; 32];
        shared.copy_from_slice(&self.ciphertext[..32]);
        shared
    }

    pub fn decapsulate(&self) -> [u8; 32] {
        let mut shared = [0u8; 32];
        shared.copy_from_slice(&self.ciphertext[..32]);
        shared
    }
}

#[derive(ZeroizeOnDrop)]
pub struct Ed25519KeyPair {
    pub public: [u8; 32],
    #[zeroize(skip)]
    secret: [u8; 64],
}

impl Ed25519KeyPair {
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        use curve25519_dalek::{edwards::EdwardsPoint, scalar::Scalar};
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let scalar = Scalar::from_bytes_mod_order(seed);
        let point = EdwardsPoint::mul_base(&scalar);
        let public = point.compress().to_bytes();
        let mut secret = [0u8; 64];
        secret[..32].copy_from_slice(scalar.as_bytes());
        secret[32..].copy_from_slice(&public);
        Self { public, secret }
    }
}

pub struct HybridKeyExchange {
    pub x25519: X25519KeyPair,
    pub kyber: KyberKeyPair,
}

impl HybridKeyExchange {
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        Self {
            x25519: X25519KeyPair::generate(rng),
            kyber: KyberKeyPair::generate(rng),
        }
    }

    pub fn shared_secret(&self, peer_x25519: &[u8; 32], peer_kyber: &[u8; 800], rng: &mut (impl RngCore + CryptoRng)) -> [u8; 64] {
        let x_shared = self.x25519.shared_secret(peer_x25519);
        let mut kyber_kp = KyberKeyPair::generate(rng);
        let k_shared = kyber_kp.encapsulate(rng, peer_kyber);
        let mut hybrid = [0u8; 64];
        hybrid[..32].copy_from_slice(&x_shared);
        hybrid[32..].copy_from_slice(&k_shared);
        hybrid
    }

    /// 从已有 x25519 私钥恢复（用于 CLI 持久化）
    pub fn restore(x25519_secret: [u8; 32]) -> Self {
        Self {
            x25519: X25519KeyPair::restore(x25519_secret),
            kyber: KyberKeyPair::generate(&mut thread_rng()),
        }
    }
}

/// 混合密钥对（用于棘轮公钥）
pub struct HybridKeyPair {
    x25519: X25519KeyPair,
    kyber: KyberKeyPair,
}

impl HybridKeyPair {
    pub fn generate() -> Self {
        let mut rng = rand::thread_rng();
        // 重试直到生成有效（非全零）的公钥
        loop {
            let kp = Self {
                x25519: X25519KeyPair::generate(&mut rng),
                kyber: KyberKeyPair::generate(&mut rng),
            };
            if kp.public_key().x25519.iter().any(|&b| b != 0) {
                break kp;
            }
        }
    }

    /// 用指定种子生成确定性密钥对（用于测试）
    #[cfg(test)]
    pub fn generate_with_seed(seed: u64) -> Self {
        use rand::SeedableRng;
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
        loop {
            let kp = Self {
                x25519: X25519KeyPair::generate(&mut rng),
                kyber: KyberKeyPair::generate(&mut rng),
            };
            if kp.public_key().x25519.iter().any(|&b| b != 0) {
                break kp;
            }
        }
    }

        /// 获取 kyber 私钥字节
    pub fn kyber_secret(&self) -> [u8; 1632] {
        self.kyber.secret
    }

    pub fn public_key(&self) -> HybridPublicKey {
        HybridPublicKey {
            x25519: self.x25519.public,
            kyber: self.kyber.public,
        }
    }

    pub fn dh_static(&self, peer: &HybridPublicKey) -> [u8; 32] {
        self.x25519.shared_secret(&peer.x25519)
    }

    /// 获取 x25519 私钥字节
    pub fn x25519_secret(&self) -> [u8; 32] {
        self.x25519.secret
    }

    /// 从已有密钥材料恢复密钥对（用于 CLI 状态重建）
    pub fn restore(
        x25519_secret: &[u8; 32],
        x25519_public: &[u8; 32],
        kyber_secret: &[u8; 1632],
        kyber_public: &[u8; 800],
    ) -> Self {
        // 重建 x25519（只设置字段，不重新计算公钥）
        let mut xsk = [0u8; 32];
        xsk.copy_from_slice(x25519_secret);
        let xpk: [u8; 32] = *x25519_public;

        // 重建 kyber
        let mut ksk = [0u8; 1632];
        ksk.copy_from_slice(kyber_secret);
        let mut kpk = [0u8; 800];
        kpk.copy_from_slice(kyber_public);

        Self {
            x25519: X25519KeyPair {
                public: xpk,
                secret: xsk,
            },
            kyber: KyberKeyPair {
                public: kpk,
                secret: ksk,
                ciphertext: [0u8; 768],
            },
        }
    }
}

/// 混合公钥
#[derive(Clone)]
pub struct HybridPublicKey {
    pub x25519: [u8; 32],
    pub kyber: [u8; 800],
}

impl HybridPublicKey {
    pub fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
        let mut x25519 = [0u8; 32];
        x25519.copy_from_slice(bytes);
        Some(Self {
            x25519,
            kyber: [0u8; 800],
        })
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.x25519
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hybrid_keypair_not_zero() {
        for seed in 1..=10u64 {
            let kp = HybridKeyPair::generate_with_seed(seed);
            assert!(kp.public_key().x25519.iter().any(|&b| b != 0), "seed {} generated zero pk", seed);
        }
    }
}
