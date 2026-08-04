//! 星枢加密体系 (Star Compass) - 精密校准版 · 三才合一

pub mod crypto;
pub mod astro;
pub mod keyring;
pub mod pipeline;
pub mod tiers;
pub mod error;

pub use error::CryptoError;
pub use astro::planets::{Planet, Hexagram, PlanetCalculator, ThreeCaSalt, GeoLocation};
pub use crypto::{AeadCipher, BlockAuth, HmacTransport, NonceData, KeyDeriver, HybridKeyExchange, MerkleTree, VERSION};
pub use keyring::{ThreeCaKeyRing, RatchetCounters, SkipBuffer};
pub use pipeline::{Chunker, MatrixObfuscator, TrafficOrchestrator, MimicProtocol, PacketScheduler, Block, ManifestBlock};
pub use tiers::{SecurityTier, TierConfig};

use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};

pub struct StarCompass {
    tier: SecurityTier,
    keyring: Option<ThreeCaKeyRing>,
    tier_config: TierConfig,
}

impl StarCompass {
    pub fn new(tier: SecurityTier) -> Self {
        Self {
            tier,
            keyring: None,
            tier_config: tier.default_config(),
        }
    }

    pub fn init(
        &mut self,
        observation_time: DateTime<Utc>,
        _location: Option<GeoLocation>,
        event_description: &str,
        personal_hexagrams: &[u8; 64],
    ) -> Result<(), CryptoError> {
        let calc = PlanetCalculator::new();
        let planet_bits = calc.calc_planet_hexagram(&observation_time);
        let event_hash = Sha256::digest(event_description.as_bytes());
        let mut event_hash_arr = [0u8; 32];
        event_hash_arr.copy_from_slice(&event_hash[..32]);
        let salt = ThreeCaSalt {
            planet_bits,
            event_hash: event_hash_arr,
            personal_hex: *personal_hexagrams,
        };
        self.keyring = Some(ThreeCaKeyRing::new(self.tier, salt));
        Ok(())
    }

    pub fn init_with_shared_secret(&mut self, shared: &[u8; 64]) {
        if self.keyring.is_none() {
            // 用默认盐初始化 keyring（用于 CLI 密钥交换模式，无天文数据）
            let default_salt = ThreeCaSalt::default_for_tier(self.tier);
            self.keyring = Some(ThreeCaKeyRing::new(self.tier, default_salt));
        }
        if let Some(ref mut kr) = self.keyring {
            kr.init(shared);
        }
    }

    pub fn tier(&self) -> SecurityTier {
        self.tier
    }

    pub fn config(&self) -> &TierConfig {
        &self.tier_config
    }

    pub fn keyring(&self) -> Option<&ThreeCaKeyRing> {
        self.keyring.as_ref()
    }

    pub fn salt(&self) -> Option<&ThreeCaSalt> {
        self.keyring.as_ref().map(|k| k.salt())
    }
}

pub const VERSION_MAJOR: u16 = 0;
pub const VERSION_MINOR: u8 = 1;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_flow() {
        let mut star = StarCompass::new(SecurityTier::LiFire);
        let dt = Utc::now();
        let hexagrams = [0x42u8; 64];
        star.init(dt, None, "test", &hexagrams).unwrap();
        let shared = [0x99u8; 64];
        star.init_with_shared_secret(&shared);
        assert_eq!(star.tier(), SecurityTier::LiFire);
        assert!(star.keyring().is_some());
    }
}
