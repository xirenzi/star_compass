//! 密钥环 - 双棘轮 + 三才盐

use crate::crypto::{KeyDeriver, NonceData};
use crate::tiers::SecurityTier;
use crate::astro::planets::ThreeCaSalt;

#[derive(Debug, Clone, Default)]
pub struct RatchetCounters {
    pub symmetric_generation: u32,
    pub dh_generation: u32,
    pub message_counter: u64,
}

pub struct ThreeCaKeyRing {
    tier: SecurityTier,
    salt: ThreeCaSalt,
    deriver: Option<KeyDeriver>,
    counters: RatchetCounters,
}

impl ThreeCaKeyRing {
    pub fn new(tier: SecurityTier, salt: ThreeCaSalt) -> Self {
        Self {
            tier,
            salt,
            deriver: None,
            counters: RatchetCounters::default(),
        }
    }

    pub fn init(&mut self, shared_secret: &[u8; 64]) {
        let salt_bytes = self.salt.synthesize();
        self.deriver = Some(KeyDeriver::extract_master(shared_secret, &salt_bytes));
    }

    pub fn k2(&self) -> [u8; 32] {
        self.deriver.as_ref().map(|d| d.derive_k2()).unwrap_or([0u8; 32])
    }

    pub fn k_block(&self) -> [u8; 32] {
        self.deriver.as_ref().map(|d| d.derive_k_block()).unwrap_or([0u8; 32])
    }

    pub fn k4(&self) -> [u8; 32] {
        self.deriver.as_ref().map(|d| d.derive_k4()).unwrap_or([0u8; 32])
    }

    pub fn k1(&self) -> [u8; 32] {
        self.deriver.as_ref().map(|d| d.derive_k1()).unwrap_or([0u8; 32])
    }

    pub fn nonce_base(&self) -> [u8; 12] {
        self.deriver.as_ref().map(|d| d.derive_nonce_base()).unwrap_or([0u8; 12])
    }

    pub fn message_nonce(&self) -> NonceData {
        let base = self.nonce_base();
        NonceData::with_counter(&base, self.counters.message_counter)
    }

    pub fn symmetric_ratchet(&mut self) {
        self.counters.message_counter += 1;
        let update_interval = match self.tier {
            SecurityTier::KanWater => u64::MAX,
            SecurityTier::XunWind => 1000,
            SecurityTier::LiFire => 500,
            SecurityTier::QianHeaven => 100,
        };
        if self.counters.message_counter % update_interval == 0 {
            self.counters.symmetric_generation += 1;
        }
    }

    pub fn dh_ratchet(&mut self, new_shared: &[u8; 64]) {
        self.counters.dh_generation += 1;
        let salt_bytes = self.salt.synthesize();
        self.deriver = Some(KeyDeriver::extract_master(new_shared, &salt_bytes));
    }

    pub fn salt(&self) -> &ThreeCaSalt {
        &self.salt
    }

    pub fn counters(&self) -> &RatchetCounters {
        &self.counters
    }
}

impl Drop for ThreeCaKeyRing {
    fn drop(&mut self) {
        self.deriver = None;
    }
}

pub struct SkipBuffer {
    buffer: std::collections::HashMap<u64, [u8; 32]>,
    max_size: usize,
}

impl SkipBuffer {
    pub fn new(max_size: usize) -> Self {
        Self { buffer: std::collections::HashMap::new(), max_size }
    }
    pub fn store(&mut self, message_num: u64, key: [u8; 32]) {
        if self.buffer.len() >= self.max_size {
            if let Some(&min) = self.buffer.keys().min() {
                self.buffer.remove(&min);
            }
        }
        self.buffer.insert(message_num, key);
    }
    pub fn get(&mut self, message_num: u64) -> Option<[u8; 32]> {
        self.buffer.remove(&message_num)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::astro::planets::ThreeCaSalt;

    #[test]
    fn test_keyring() {
        let salt = ThreeCaSalt {
            planet_bits: [0x42u8; 21],
            event_hash: [0xAAu8; 32],
            personal_hex: [0x55u8; 64],
        };
        let mut ring = ThreeCaKeyRing::new(SecurityTier::LiFire, salt);
        ring.init(&[0x99u8; 64]);
        let n1 = ring.message_nonce();
        ring.symmetric_ratchet();
        let n2 = ring.message_nonce();
        assert_ne!(n1.as_bytes(), n2.as_bytes());
    }
}
