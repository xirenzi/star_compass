//! 四版分级体系 - 八卦命名

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum SecurityTier {
    KanWater = 0,   // 坎水级·艮渊
    XunWind = 1,    // 巽风级·巽翎
    LiFire = 2,     // 离火级·离曜
    QianHeaven = 3, // 乾天级·乾极
}

impl SecurityTier {
    pub fn name_cn(&self) -> &'static str {
        match self {
            SecurityTier::KanWater => "坎水级·艮渊",
            SecurityTier::XunWind => "巽风级·巽翎",
            SecurityTier::LiFire => "离火级·离曜",
            SecurityTier::QianHeaven => "乾天级·乾极",
        }
    }

    pub fn symbol(&self) -> &'static str {
        match self {
            SecurityTier::KanWater => "☵",
            SecurityTier::XunWind => "☴",
            SecurityTier::LiFire => "☲",
            SecurityTier::QianHeaven => "☰",
        }
    }

    pub fn planet_count(&self) -> usize {
        match self {
            SecurityTier::KanWater => 3,
            SecurityTier::XunWind => 5,
            SecurityTier::LiFire => 7,
            SecurityTier::QianHeaven => 8,
        }
    }

    pub fn has_ratchet(&self) -> bool {
        *self as u8 >= SecurityTier::XunWind as u8
    }

    pub fn has_matrix_obfuscation(&self) -> bool {
        *self as u8 >= SecurityTier::LiFire as u8
    }

    pub fn has_traffic_mimicry(&self) -> bool {
        *self as u8 >= SecurityTier::LiFire as u8
    }

    pub fn has_reordering(&self) -> bool {
        *self as u8 >= SecurityTier::LiFire as u8
    }

    pub fn has_identity_hiding(&self) -> bool {
        *self as u8 >= SecurityTier::LiFire as u8
    }

    pub fn has_deniable_auth(&self) -> bool {
        *self as u8 >= SecurityTier::LiFire as u8
    }

    pub fn padding_range(&self) -> (usize, usize) {
        match self {
            SecurityTier::KanWater => (0, 0),
            SecurityTier::XunWind => (0, 63),
            SecurityTier::LiFire => (0, 127),
            SecurityTier::QianHeaven => (0, 255),
        }
    }

    pub fn default_config(&self) -> TierConfig {
        TierConfig {
            tier: *self,
            use_ed25519: *self as u8 >= SecurityTier::XunWind as u8,
            use_x25519: *self as u8 >= SecurityTier::XunWind as u8,
            use_kyber: *self as u8 >= SecurityTier::LiFire as u8,
            planet_count: self.planet_count(),
            ratchet: self.has_ratchet(),
            matrix_obfuscation: self.has_matrix_obfuscation(),
            traffic_mimicry: self.has_traffic_mimicry(),
            reordering: self.has_reordering(),
            identity_hiding: self.has_identity_hiding(),
            deniable_auth: self.has_deniable_auth(),
            padding_max: self.padding_range().1,
            mimic_protocol: match self {
                SecurityTier::KanWater => "none",
                _ => "tls",
            }.to_string(),
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name.to_lowercase().as_str() {
            "kan" | "坎水" | "坎" | "艮渊" => Some(SecurityTier::KanWater),
            "xun" | "巽风" | "巽" | "巽翎" => Some(SecurityTier::XunWind),
            "li" | "离火" | "离" | "离曜" => Some(SecurityTier::LiFire),
            "qian" | "乾天" | "乾" | "乾极" => Some(SecurityTier::QianHeaven),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TierConfig {
    pub tier: SecurityTier,
    pub use_ed25519: bool,
    pub use_x25519: bool,
    pub use_kyber: bool,
    pub planet_count: usize,
    pub ratchet: bool,
    pub matrix_obfuscation: bool,
    pub traffic_mimicry: bool,
    pub reordering: bool,
    pub identity_hiding: bool,
    pub deniable_auth: bool,
    pub padding_max: usize,
    pub mimic_protocol: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tier() {
        assert_eq!(SecurityTier::from_name("坎水"), Some(SecurityTier::KanWater));
        assert_eq!(SecurityTier::from_name("乾极"), Some(SecurityTier::QianHeaven));
        assert!(SecurityTier::QianHeaven.has_ratchet());
        assert!(!SecurityTier::KanWater.has_ratchet());
    }
}
