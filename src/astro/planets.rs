//! 七曜黄经计算 + 卦象映射
//! 
//! 【天时】核心：
//! - 七曜黄经计算（☉日 ☿水 ♀金 ♂火 ♃木 ♄土 ☽月）
//! - 黄经宫位 mod 8 → 七经卦 → 21爻二进制
//! - 行星本卦 = 七曜21爻序列

use chrono::{DateTime, Utc};


/// 行星枚举（七曜）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Planet {
    Sun     = 0, // ☉ 日
    Moon    = 1, // ☽ 月
    Mercury = 2, // ☿ 水星
    Venus   = 3, // ♀ 金星
    Mars    = 4, // ♂ 火星
    Jupiter = 5, // ♃ 木星
    Saturn  = 6, // ♄ 土星
}

impl Planet {
    pub fn all() -> [Planet; 7] {
        [
            Planet::Sun,
            Planet::Moon,
            Planet::Mercury,
            Planet::Venus,
            Planet::Mars,
            Planet::Jupiter,
            Planet::Saturn,
        ]
    }

    /// 行星名称（用于 HKDF info）
    pub fn name(&self) -> &'static str {
        match self {
            Planet::Sun => "Sun",
            Planet::Moon => "Moon",
            Planet::Mercury => "Mercury",
            Planet::Venus => "Venus",
            Planet::Mars => "Mars",
            Planet::Jupiter => "Jupiter",
            Planet::Saturn => "Saturn",
        }
    }
}

/// 八卦枚举
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Hexagram {
    Qian  = 0, // 乾 ☰
    Kun   = 1, // 坤 ☷
    Zhen  = 2, // 震 ☳
    Xun   = 3, // 巽 ☴
    Kan   = 4, // 坎 ☵
    Li    = 5, // 离 ☲
    Gen   = 6, // 艮 ☶
    Dui   = 7, // 兑 ☱
}

impl Hexagram {
    /// 从 3 位二进制还原八卦
    pub fn from_bits(bits: u8) -> Option<Hexagram> {
        match bits & 0x7 {
            0 => Some(Hexagram::Qian),
            1 => Some(Hexagram::Kun),
            2 => Some(Hexagram::Zhen),
            3 => Some(Hexagram::Xun),
            4 => Some(Hexagram::Kan),
            5 => Some(Hexagram::Li),
            6 => Some(Hexagram::Gen),
            7 => Some(Hexagram::Dui),
            _ => None,
        }
    }

    /// 八卦转3位二进制
    pub fn to_bits(&self) -> u8 {
        *self as u8
    }

    pub fn name_cn(&self) -> &'static str {
        match self {
            Hexagram::Qian => "乾",
            Hexagram::Kun => "坤",
            Hexagram::Zhen => "震",
            Hexagram::Xun => "巽",
            Hexagram::Kan => "坎",
            Hexagram::Li => "离",
            Hexagram::Gen => "艮",
            Hexagram::Dui => "兑",
        }
    }

    pub fn symbol(&self) -> &'static str {
        match self {
            Hexagram::Qian => "☰",
            Hexagram::Kun => "☷",
            Hexagram::Zhen => "☳",
            Hexagram::Xun => "☴",
            Hexagram::Kan => "☵",
            Hexagram::Li => "☲",
            Hexagram::Gen => "☶",
            Hexagram::Dui => "☱",
        }
    }
}

/// 地平坐标（可选，用于精确行星位置）
#[derive(Debug, Clone, Default)]
pub struct GeoLocation {
    pub lat: f64, // 纬度 度
    pub lon: f64, // 经度 度
}

impl GeoLocation {
    pub fn new(lat: f64, lon: f64) -> Self {
        Self { lat, lon }
    }
}

/// 七曜黄经计算器
pub struct PlanetCalculator {
    epoch_jd: f64, // J2000.0 儒略日 = 2451545.0
}

impl PlanetCalculator {
    pub fn new() -> Self {
        Self { epoch_jd: 2451545.0 }
    }

    /// 将 DateTime<Utc> 转为儒略日
    fn datetime_to_jd(dt: &DateTime<Utc>) -> f64 {
        let secs = dt.timestamp() as f64;
        let nanos = dt.timestamp_subsec_nanos() as f64 / 1e9;
        let days = (secs + nanos) / 86400.0;
        2440587.5 + days  // 儒略日
    }

    /// 计算某行星在给定时间的黄经（度）
    /// 使用简化行星公式（精度足够用于加密用途）
    pub fn ecliptic_longitude(&self, planet: Planet, dt: &DateTime<Utc>) -> f64 {
        let jd = Self::datetime_to_jd(dt);
        let t = (jd - self.epoch_jd) / 36525.0; // 世纪数

        // 平均轨道参数（简化版）
        let (l0, l, _e, _a) = match planet {
            Planet::Sun => (280.46646, 36000.76983, 0.016709, 1.0),
            Planet::Moon => (218.3165, 481267.8813, 0.0549, 0.00257),
            Planet::Mercury => (252.2509, 149472.6746, 0.205635, 0.387),
            Planet::Venus => (181.9798, 58517.8157, 0.006773, 0.723),
            Planet::Mars => (355.4330, 19140.2993, 0.093405, 1.524),
            Planet::Jupiter => (34.3515, 3034.9057, 0.048774, 5.203),
            Planet::Saturn => (50.0774, 1222.1138, 0.055509, 9.537),
        };

        // 平黄经
        let mean_long = (l0 + l * t).rem_euclid(360.0);
        
        // 简化摄动修正
        let perturbation = match planet {
            Planet::Moon => 6.29 * ((134.9 + 13.064 * t).to_radians()).sin(),
            Planet::Mercury => 23.4 * ((l0 + 48.0 * t).to_radians()).sin(),
            Planet::Venus => 0.77 * ((l0 + 32.0 * t).to_radians()).sin(),
            Planet::Mars => 10.2 * ((l0 + 72.0 * t).to_radians()).sin(),
            Planet::Jupiter => 0.3 * ((l0 + 100.0 * t).to_radians()).sin(),
            Planet::Saturn => 0.3 * ((l0 + 100.0 * t).to_radians()).sin(),
            Planet::Sun => 0.0,
        };

        (mean_long + perturbation).rem_euclid(360.0)
    }

    /// 黄经转宫位（360° 分 8 宫，每宫 45°）
    /// 宫位 0-7 对应八卦：0=乾, 1=坤, 2=震, 3=巽, 4=坎, 5=离, 6=艮, 7=兑
    pub fn longitude_to_hexagram(longitude_deg: f64) -> Hexagram {
        let palace = ((longitude_deg / 45.0) as u8) & 0x7;
        Hexagram::from_bits(palace).unwrap_or(Hexagram::Qian)
    }

    /// 计算完整行星本卦：七曜黄经 → 七经卦 → 21爻二进制
    /// 
    /// 返回：21字节二进制序列，每字节0/1代表一爻
    pub fn calc_planet_hexagram(&self, dt: &DateTime<Utc>) -> [u8; 21] {
        let mut bits = [0u8; 21];
        
        for (i, planet) in Planet::all().iter().enumerate() {
            let long = self.ecliptic_longitude(*planet, dt);
            let hex = Self::longitude_to_hexagram(long);
            let hex_bits = hex.to_bits(); // 0-7 的 3 位表示
            
            // 每个行星3爻：从低位到高位
            bits[i * 3]     = (hex_bits >> 0) & 1;
            bits[i * 3 + 1] = (hex_bits >> 1) & 1;
            bits[i * 3 + 2] = (hex_bits >> 2) & 1;
        }
        
        bits
    }

    /// 行星本卦转十六进制字符串（21字节 = 42个十六进制字符）
    pub fn hexagram_to_hex_string(bits: &[u8; 21]) -> String {
        let mut hex = String::with_capacity(42);
        for (_i, chunk) in bits.chunks(2).enumerate() {
            let nibble0 = chunk[0] & 0xF;
            let nibble1 = if chunk.len() > 1 { chunk[1] } else { 0 };
            let byte = (nibble1 << 4) | nibble0;
            hex.push_str(&format!("{:02x}", byte));
        }
        hex
    }

    /// 将 21 爻序列转为字节数组（用于 HKDF Salt）
    pub fn hexagram_to_bytes(bits: &[u8; 21]) -> [u8; 21] {
        *bits
    }
}

impl Default for PlanetCalculator {
    fn default() -> Self {
        Self::new()
    }
}

/// 三才秘钥合成：行星本卦 || 事件哈希 || 私密八卦序列
///
/// 输入：
/// - planet_bits: 七曜21爻二进制
/// - event_hash: SHA-256(event_description) - 永不线上传输
/// - personal_hex: 用户私密八卦序列（64卦二进制，永不入网）
#[derive(Clone)]
pub struct ThreeCaSalt {
    pub planet_bits: [u8; 21],  // 行星本卦
    pub event_hash: [u8; 32],   // 事件哈希
    pub personal_hex: [u8; 64], // 私密八卦（64位）
}

impl ThreeCaSalt {
    /// 合成三才盐
    pub fn synthesize(&self) -> Vec<u8> {
        let mut salt = Vec::with_capacity(21 + 32 + 64);
        salt.extend_from_slice(&self.planet_bits);
        salt.extend_from_slice(&self.event_hash);
        salt.extend_from_slice(&self.personal_hex);
        salt
    }

    /// 盐的字节长度
    /// 获取盐值字节表示（用于密钥派生）
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(21 + 32 + 64);
        out.extend_from_slice(&self.planet_bits);
        out.extend_from_slice(&self.event_hash);
        out.extend_from_slice(&self.personal_hex);
        out
    }

    pub fn salt_len(&self) -> usize {
        21 + 32 + 64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn test_planet_calc() {
        let calc = PlanetCalculator::new();
        // 2024-01-01 00:00:00 UTC
        let dt = Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap();
        
        let bits = calc.calc_planet_hexagram(&dt);
        assert_eq!(bits.len(), 21);
        
        // 每次计算应产生确定结果
        let bits2 = calc.calc_planet_hexagram(&dt);
        assert_eq!(bits, bits2);
        
        // 不同时间应产生不同结果（概率上）
        let dt2 = Utc.with_ymd_and_hms(2024, 7, 1, 12, 0, 0).unwrap();
        let bits3 = calc.calc_planet_hexagram(&dt2);
        // 21字节中至少有一些不同（大概率）
        let diffs: usize = bits.iter().zip(bits3.iter()).filter(|(a,b)| a!=b).count();
        assert!(diffs > 0, "Different times should produce different hexagrams");
    }

    #[test]
    fn test_hex_conversion() {
        let bits = [1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 1, 1, 0];
        let hex = PlanetCalculator::hexagram_to_hex_string(&bits);
        assert_eq!(hex.len(), 22);
        assert_eq!(&hex[..2], "01"); // bits[0]=1(low nibble), bits[1]=0(high nibble)
    }
}
