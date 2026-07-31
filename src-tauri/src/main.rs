// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use star_compass::{
    SecurityTier, StarCompass,
    astro::planets::{PlanetCalculator, GeoLocation},
    crypto::{HybridKeyExchange, ratchet::{DoubleRatchetSession, RatchetHeader, RatchetTier}},
    VERSION,
};
use chrono::DateTime;
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use tauri::State;
use rand::thread_rng;

/// 会话角色：发起方用 sender（发第一条消息），响应方用 receiver
#[derive(Clone, Copy, Debug)]
enum SessionRole {
    Initiator,
    Responder,
}

impl SessionRole {
    fn from_str(s: &str) -> Self {
        match s.trim().to_lowercase().as_str() {
            "responder" | "响应方" | "接收方" => SessionRole::Responder,
            _ => SessionRole::Initiator,
        }
    }
}

/// 跨命令保存的会话状态
struct AppState {
    star: Mutex<Option<StarCompass>>,
    kx: Mutex<Option<HybridKeyExchange>>,
    /// 双棘轮会话（用于消息加解密）
    ratchet: Mutex<Option<DoubleRatchetSession>>,
    /// 32 字节 X25519 共享密钥（用于自测时重新派生会话）
    shared_x: Mutex<Option<[u8; 32]>>,
    role: Mutex<Option<SessionRole>>,
}

impl AppState {
    fn new() -> Self {
        Self {
            star: Mutex::new(None),
            kx: Mutex::new(None),
            ratchet: Mutex::new(None),
            shared_x: Mutex::new(None),
            role: Mutex::new(None),
        }
    }
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .init();

    tracing::info!("星枢加密体系 v{} 启动中...", VERSION);

    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .manage(AppState::new())
        .invoke_handler(tauri::generate_handler![
            create_compass,
            init_encryption,
            get_tier_info,
            calc_planet_hexagram,
            generate_keypair,
            establish_session,
            establish_session_self,
            encrypt_message,
            decrypt_message,
            self_test_message,
        ])
        .run(tauri::generate_context!())
        .expect("启动失败");
}

// ============================================================================
// SecurityTier → RatchetTier 映射（按序号 0→Kan, 1→Zhi, 2→Ren, 3→Tian）
// ============================================================================

fn map_tier(tier: SecurityTier) -> RatchetTier {
    match tier {
        SecurityTier::KanWater => RatchetTier::Kan,
        SecurityTier::XunWind  => RatchetTier::Zhi,
        SecurityTier::LiFire   => RatchetTier::Ren,
        SecurityTier::QianHeaven => RatchetTier::Tian,
    }
}

// ============================================================================
// 工具
// ============================================================================

/// 将 32 字节 X25519 共享密钥扩展为 64 字节（供 keyring 作为根密钥）
fn expand_shared(x: &[u8; 32]) -> [u8; 64] {
    let mut s = [0u8; 64];
    for i in 0..64 {
        s[i] = x[i % 32];
    }
    s
}

// ============================================================================
// 命令
// ============================================================================

#[derive(Debug, Serialize, Deserialize)]
pub struct CompassInstance {
    tier: u8,
    tier_name: String,
    tier_symbol: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PlanetHexagramResult {
    bits: Vec<u8>,
    hex_string: String,
    hexagrams: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TierInfo {
    name: String,
    symbol: String,
    planet_count: usize,
    has_ratchet: bool,
    has_obfuscation: bool,
    has_mimicry: bool,
    padding_max: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptResult {
    /// 完整数据包（40 字节头部 + 密文 + 16 字节 GCM tag），hex 编码
    packet: String,
    /// 头部信息（公钥前 8 字符）
    header_pk_preview: String,
    /// 消息序号
    msg_num: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DecryptResult {
    plaintext: String,
    /// 发送方公钥前 8 字符
    from_pk_preview: String,
    msg_num: usize,
}

/// 创建星枢实例
#[tauri::command]
fn create_compass(tier_name: String) -> Result<CompassInstance, String> {
    let tier = SecurityTier::from_name(&tier_name)
        .ok_or_else(|| format!("未知等级: {}", tier_name))?;
    Ok(CompassInstance {
        tier: tier as u8,
        tier_name: tier.name_cn().to_string(),
        tier_symbol: tier.symbol().to_string(),
    })
}

/// 初始化加密
#[tauri::command]
fn init_encryption(
    state: State<AppState>,
    tier_name: String,
    timestamp_secs: i64,
    lat: f64,
    lon: f64,
    event_hash: String,
    personal_hex: String,
) -> Result<String, String> {
    let tier = SecurityTier::from_name(&tier_name)
        .ok_or_else(|| format!("未知等级: {}", tier_name))?;

    let mut star = StarCompass::new(tier);
    let dt = DateTime::from_timestamp(timestamp_secs, 0)
        .ok_or("无效时间戳")?;
    let location = GeoLocation::new(lat, lon);

    let clean_event = event_hash.trim().trim_start_matches("0x");
    let hex_bytes = hex::decode(clean_event)
        .map_err(|e| format!("事件哈希解析失败: {}", e))?;
    if hex_bytes.len() < 32 {
        return Err(format!("事件哈希长度不足，需要 32 字节，实际 {}", hex_bytes.len()));
    }
    let mut event_arr = [0u8; 32];
    event_arr.copy_from_slice(&hex_bytes[..32]);

    let clean_personal = personal_hex.trim().trim_start_matches("0x");
    let mut hex_arr = [0u8; 64];
    if clean_personal.len() == 64 && clean_personal.chars().all(|c| c == '0' || c == '1') {
        for (i, c) in clean_personal.chars().enumerate() {
            hex_arr[i] = if c == '1' { 1 } else { 0 };
        }
    } else {
        let pb = hex::decode(clean_personal)
            .map_err(|e| format!("八卦序列解析失败（需 64 位 0/1 或十六进制）: {}", e))?;
        let n = pb.len().min(64);
        hex_arr[..n].copy_from_slice(&pb[..n]);
    }

    star.init(dt, Some(location), "encrypted_event", &hex_arr)
        .map_err(|e| format!("初始化失败: {:?}", e))?;

    *state.star.lock().unwrap() = Some(star);
    Ok("加密已初始化".to_string())
}

/// 获取等级信息
#[tauri::command]
fn get_tier_info(tier_name: String) -> Result<TierInfo, String> {
    let tier = SecurityTier::from_name(&tier_name)
        .ok_or_else(|| format!("未知等级: {}", tier_name))?;

    let cfg = tier.default_config();
    Ok(TierInfo {
        name: tier.name_cn().to_string(),
        symbol: tier.symbol().to_string(),
        planet_count: cfg.planet_count,
        has_ratchet: cfg.ratchet,
        has_obfuscation: cfg.matrix_obfuscation,
        has_mimicry: cfg.traffic_mimicry,
        padding_max: cfg.padding_max,
    })
}

/// 计算行星本卦
#[tauri::command]
fn calc_planet_hexagram(timestamp_secs: i64) -> Result<PlanetHexagramResult, String> {
    let dt = DateTime::from_timestamp(timestamp_secs, 0)
        .ok_or("无效时间戳")?;

    let calc = PlanetCalculator::new();
    let bits = calc.calc_planet_hexagram(&dt);
    let hex_str = PlanetCalculator::hexagram_to_hex_string(&bits);

    let hexagrams: Vec<String> = bits.chunks(3)
        .map(|chunk| {
            let val = (chunk[0] | (chunk[1] << 1) | (chunk[2] << 2)) & 0x7;
            match val {
                0 => "☰".to_string(),
                1 => "☷".to_string(),
                2 => "☳".to_string(),
                3 => "☴".to_string(),
                4 => "☵".to_string(),
                5 => "☲".to_string(),
                6 => "☶".to_string(),
                7 => "☱".to_string(),
                _ => "?".to_string(),
            }
        })
        .collect();

    Ok(PlanetHexagramResult {
        bits: bits.to_vec(),
        hex_string: hex_str,
        hexagrams,
    })
}

/// 生成本地密钥对，返回我的公钥（X25519，64 字符 hex）
#[tauri::command]
fn generate_keypair(state: State<AppState>) -> Result<String, String> {
    let mut rng = thread_rng();
    let kx = HybridKeyExchange::generate(&mut rng);
    let my_pub = kx.x25519.public;
    *state.kx.lock().unwrap() = Some(kx);
    Ok(hex::encode(my_pub))
}

/// 与真实对端建立会话
///
/// role: "initiator"（默认，发起方）或 "responder"（响应方）
/// - 发起方：本地用 sender 角色，双棘轮用 send-chain 发送、recv-chain 接收
/// - 响应方：本地用 receiver 角色，双棘轮用 recv-chain 接收、send-chain 发送
///
/// 真实双机测试：双方需协商好角色（各选其一），双方都初始化后才能互发消息。
#[tauri::command]
fn establish_session(
    state: State<AppState>,
    peer_public_hex: String,
    role: Option<String>,
) -> Result<String, String> {
    let kx_guard = state.kx.lock().unwrap();
    let kx = kx_guard.as_ref().ok_or("请先生成密钥对")?;

    let clean = peer_public_hex.trim().trim_start_matches("0x");
    let peer_bytes = hex::decode(clean)
        .map_err(|e| format!("对方公钥解析失败: {}", e))?;
    if peer_bytes.len() != 32 {
        return Err(format!("对方公钥长度错误，需 32 字节，实际 {}", peer_bytes.len()));
    }
    let mut peer = [0u8; 32];
    peer.copy_from_slice(&peer_bytes[..32]);

    let x_shared = kx.x25519.shared_secret(&peer);
    drop(kx_guard);

    let shared64 = expand_shared(&x_shared);
    let mut star_guard = state.star.lock().unwrap();
    let star = star_guard.as_mut().ok_or("请先完成初始化（点击初始化加密）")?;
    star.init_with_shared_secret(&shared64);

    // 创建双棘轮会话
    let ratchet_tier = map_tier(star.tier());
    let salt = star.salt().cloned();
    let sess_role = SessionRole::from_str(role.as_deref().unwrap_or("initiator"));

    let ratchet = match sess_role {
        SessionRole::Initiator => {
            DoubleRatchetSession::new_sender(x_shared, ratchet_tier.clone(), salt)
        }
        SessionRole::Responder => {
            DoubleRatchetSession::new_receiver(x_shared, ratchet_tier, salt)
        }
    };

    *state.shared_x.lock().unwrap() = Some(x_shared);
    *state.ratchet.lock().unwrap() = Some(ratchet);
    *state.role.lock().unwrap() = Some(sess_role);

    let role_str = match sess_role {
        SessionRole::Initiator => "发起方",
        SessionRole::Responder => "响应方",
    };
    Ok(format!(
        "已与对端建立会话（角色={}），共享密钥已注入，可以加解密了。",
        role_str
    ))
}

/// 自测：本地模拟对端，演示完整密钥协商 + 加密解密收发
#[tauri::command]
fn establish_session_self(state: State<AppState>) -> Result<String, String> {
    let mut rng = thread_rng();
    let alice_kx = HybridKeyExchange::generate(&mut rng);
    let bob_kx = HybridKeyExchange::generate(&mut rng);

    let x_shared = alice_kx.x25519.shared_secret(&bob_kx.x25519.public);
    let shared64 = expand_shared(&x_shared);

    let mut star_guard = state.star.lock().unwrap();
    let star = star_guard.as_mut().ok_or("请先完成初始化（点击初始化加密）")?;
    star.init_with_shared_secret(&shared64);

    let ratchet_tier = map_tier(star.tier());
    let salt = star.salt().cloned();

    // 创建 sender（Alice）作为本地会话
    let ratchet = DoubleRatchetSession::new_sender(x_shared, ratchet_tier.clone(), salt.clone());

    *state.shared_x.lock().unwrap() = Some(x_shared);
    *state.ratchet.lock().unwrap() = Some(ratchet);
    *state.role.lock().unwrap() = Some(SessionRole::Initiator);

    Ok("已与模拟对端建立会话（角色=发起方），共享密钥已注入，现在可以加解密了。".to_string())
}

/// 加密消息：使用当前双棘轮会话的发送链加密
///
/// 返回 hex 编码的数据包（40 字节头部 + 密文 + 16 字节 GCM tag）。
/// 该包可直接发送给对端，对端用 decrypt_message 解密。
#[tauri::command]
fn encrypt_message(state: State<AppState>, plaintext: String) -> Result<EncryptResult, String> {
    let mut guard = state.ratchet.lock().unwrap();
    let ratchet = guard.as_mut().ok_or("请先建立会话（点击「建立会话」或「自测」）")?;

    let pt_bytes = plaintext.as_bytes();
    let (ct, header) = ratchet.encrypt(pt_bytes, &[]);

    // 组装完整包：header(40B) + ciphertext + GCM tag
    let mut packet = header.serialize();
    packet.extend_from_slice(&ct);

    Ok(EncryptResult {
        packet: hex::encode(&packet),
        header_pk_preview: hex::encode(&header.public_key[..4]),
        msg_num: header.message_number,
    })
}

/// 解密消息：使用当前双棘轮会话的接收链解密
///
/// 输入 hex 编码的数据包（由 encrypt_message 生成）。
/// 适用于来自对端（角色与我方互补）的消息。
#[tauri::command]
fn decrypt_message(state: State<AppState>, packet_hex: String) -> Result<DecryptResult, String> {
    let clean = packet_hex.trim().trim_start_matches("0x");
    let bytes = hex::decode(clean)
        .map_err(|e| format!("数据包不是有效的 hex: {}", e))?;

    if bytes.len() < 40 {
        return Err(format!("数据包太短（需至少 40 字节头部，实际 {} 字节）", bytes.len()));
    }

    let header = RatchetHeader::deserialize(&bytes)
        .ok_or("数据包头部解析失败（非法的棘轮头部）")?;

    let ct = &bytes[40..];
    let mut guard = state.ratchet.lock().unwrap();
    let ratchet = guard.as_mut().ok_or("请先建立会话（点击「建立会话」或「自测」）")?;

    let pt = ratchet.decrypt(&header, ct, &[])
        .ok_or("解密失败（序号不匹配或密钥错误，请确认双方角色已正确协商）")?;

    let plaintext = String::from_utf8(pt)
        .map_err(|_| "解密结果不是有效的 UTF-8 文本".to_string())?;

    Ok(DecryptResult {
        plaintext,
        from_pk_preview: hex::encode(&header.public_key[..4]),
        msg_num: header.message_number,
    })
}

/// 自测收发：本地创建 Alice(sender) + Bob(receiver)，完整走一遍加密→解密流程
///
/// 证明消息加解密端到端正确，用于验证双方角色/密钥一致性。
#[tauri::command]
fn self_test_message(state: State<AppState>) -> Result<String, String> {
    let shared_guard = state.shared_x.lock().unwrap();
    let x_shared = shared_guard.ok_or("请先建立会话（点击「建立会话」或「自测」）")?;

    let star_guard = state.star.lock().unwrap();
    let star = star_guard.as_ref().ok_or("请先完成初始化")?;
    let ratchet_tier = map_tier(star.tier());
    let salt = star.salt().cloned();
    drop(star_guard);
    drop(shared_guard);

    let mut alice = DoubleRatchetSession::new_sender(x_shared, ratchet_tier.clone(), salt.clone());
    let mut bob = DoubleRatchetSession::new_receiver(x_shared, ratchet_tier, salt);

    let sample = "星枢自测消息：双棘轮收发成功 ✅";
    let (ct, hdr) = alice.encrypt(sample.as_bytes(), &[]);

    let pt = bob.decrypt(&hdr, &ct, &[])
        .ok_or("自测解密失败（棘轮内部逻辑异常）")?;

    let pt_str = String::from_utf8(pt)
        .map_err(|_| "自测解密结果非 UTF-8".to_string())?;

    if pt_str == sample {
        Ok(format!("✅ 自测通过：Alice 加密「{}」→ Bob 解密得到「{}」", sample, pt_str))
    } else {
        Ok(format!("❌ 自测失败：期望「{}」，实际「{}」", sample, pt_str))
    }
}
