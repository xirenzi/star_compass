// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use clap::{Parser, Subcommand, ValueEnum};
use star_compass::{
    SecurityTier, StarCompass,
    astro::planets::{PlanetCalculator, GeoLocation},
    crypto::{HybridKeyExchange, ratchet::{DoubleRatchetSession, RatchetHeader, RatchetTier, RatchetState}},
    VERSION,
};
use hex;
use chrono::DateTime;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::fs;
use std::io;
use std::path::Path;
use std::sync::Mutex;
use tauri::State;
use rand::thread_rng;

// ============================================================================
// SessionRole
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
pub enum SessionRole {
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
    fn as_str(&self) -> &'static str {
        match self {
            SessionRole::Initiator => "initiator",
            SessionRole::Responder => "responder",
        }
    }
}

// ============================================================================
// 持久化状态
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistentState {
    tier: Option<String>,
    tier_name: Option<String>,
    tier_symbol: Option<String>,
    salt: Option<String>,
    public_key: Option<String>,
    shared_x: Option<String>,
    role: Option<String>,
    peer_public: Option<String>,
    private_key: Option<String>,
}

impl PersistentState {
    fn new() -> Self {
        Self {
            tier: None,
            tier_name: None,
            tier_symbol: None,
            salt: None,
            public_key: None,
            shared_x: None,
            role: None,
            peer_public: None,
            private_key: None,
        }
    }
}

// ============================================================================
// Ratchet 状态持久化
// ============================================================================

fn ratchet_state_path(state_file: &str) -> String {
    let p = Path::new(state_file);
    let stem = p.file_stem().and_then(|s| s.to_str()).unwrap_or("state");
    if stem.ends_with("_ratchet") {
        return state_file.to_string();
    }
    let ext = p.extension().and_then(|s| s.to_str()).unwrap_or("json");
    let new_name = format!("{}_ratchet.{}", stem, ext);
    p.parent()
        .map(|par| par.join(&new_name))
        .unwrap_or_else(|| Path::new(&new_name).to_path_buf())
        .to_str()
        .unwrap_or(&new_name)
        .to_string()
}

fn load_ratchet_state(state_file: &str) -> Option<RatchetState> {
    let path = ratchet_state_path(state_file);
    fs::read_to_string(&path).ok()
        .and_then(|data| serde_json::from_str(&data).ok())
}

fn save_ratchet_state(state_file: &str, state: &RatchetState) -> io::Result<()> {
    let path = ratchet_state_path(state_file);
    let json = serde_json::to_string_pretty(state)?;
    fs::write(path, json)
}

// ============================================================================
// CLI 参数
// ============================================================================

#[derive(Parser, Debug)]
#[command(
    name = "星枢",
    about = format!("星枢加密体系 v{}\n\n无参数时启动 GUI（Tauri 窗口模式）。\n提供子命令进入纯命令行模式。\n\n状态通过 --state 文件持久化，命令可链式调用。", VERSION),
    long_about = None,
)]
struct Cli {
    #[arg(long, global = true, default_value = ".star_state.json")]
    state: String,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// 计算行星本卦（无需状态）
    Planet {
        timestamp: i64,
        #[arg(long, short)]
        symbols: bool,
    },

    /// 初始化加密
    Init {
        tier: String,
        timestamp: i64,
        lat: f64,
        lon: f64,
        event_hash: String,
        #[arg(default_value = "0")]
        personal_hex: String,
    },

    /// 生成本地密钥对
    Keygen,

    /// 与对端建立会话
    Session {
        peer_public: String,
        #[arg(long, default_value = "initiator")]
        role: SessionRole,
    },

    /// 自测：完整密钥协商 + 加解密演示
    SelfTest,

    /// 加密消息
    Encrypt {
        plaintext: String,
    },

    /// 解密消息
    Decrypt {
        packet: String,
    },

    /// 打印当前状态
    Status,
}

// ============================================================================
// 辅助函数
// ============================================================================

fn map_tier(tier: SecurityTier) -> RatchetTier {
    match tier {
        SecurityTier::KanWater => RatchetTier::Kan,
        SecurityTier::XunWind => RatchetTier::Zhi,
        SecurityTier::LiFire => RatchetTier::Ren,
        SecurityTier::QianHeaven => RatchetTier::Tian,
    }
}

fn expand_shared(x: &[u8; 32]) -> [u8; 64] {
    let mut s = [0u8; 64];
    for i in 0..64 {
        s[i] = x[i % 32];
    }
    s
}

fn load_state(path: &str) -> PersistentState {
    fs::read_to_string(path)
        .ok()
        .and_then(|data| serde_json::from_str(&data).ok())
        .unwrap_or_else(PersistentState::new)
}

fn save_state(path: &str, state: &PersistentState) -> io::Result<()> {
    let json = serde_json::to_string_pretty(state)?;
    fs::write(path, json)
}

fn out_json<T: serde::Serialize>(v: &T) {
    let s = serde_json::to_string_pretty(v).unwrap();
    println!("{}", s);
}

fn parse_event_hash(raw: &str) -> [u8; 32] {
    let clean = raw.trim().trim_start_matches("0x");
    let bytes = hex::decode(clean).expect("事件哈希解析失败");
    let mut arr = [0u8; 32];
    let n = 32.min(bytes.len());
    arr[..n].copy_from_slice(&bytes[..n]);
    arr
}

fn parse_personal_hex(raw: &str) -> [u8; 64] {
    let clean = raw.trim().trim_start_matches("0x");
    let mut arr = [0u8; 64];
    if clean.len() == 64 && clean.chars().all(|c| c == '0' || c == '1') {
        for (i, c) in clean.chars().enumerate() {
            arr[i] = if c == '1' { 1 } else { 0 };
        }
    } else if let Ok(bytes) = hex::decode(clean) {
        let n = 64.min(bytes.len());
        arr[..n].copy_from_slice(&bytes[..n]);
    }
    arr
}

fn hex32(s: &str) -> [u8; 32] {
    let clean = s.trim().trim_start_matches("0x");
    let bytes = hex::decode(clean).expect("hex 解析失败");
    let mut arr = [0u8; 32];
    let n = 32.min(bytes.len());
    arr[..n].copy_from_slice(&bytes[..n]);
    arr
}

fn tier_from_u8(n: u8) -> SecurityTier {
    match n {
        0 => SecurityTier::KanWater,
        1 => SecurityTier::XunWind,
        2 => SecurityTier::LiFire,
        _ => SecurityTier::QianHeaven,
    }
}

fn tier_u8(tier: SecurityTier) -> u8 {
    match tier {
        SecurityTier::KanWater => 0,
        SecurityTier::XunWind => 1,
        SecurityTier::LiFire => 2,
        SecurityTier::QianHeaven => 3,
    }
}

// 构建 RatchetSession（优先从文件恢复，否则新建）
fn get_or_create_ratchet(
    state: &PersistentState,
    state_path: &str,
    shared_x: [u8; 32],
) -> (DoubleRatchetSession, bool) {
    let sec_tier = tier_from_u8(state.tier.as_ref().map(|t| t.parse::<u8>().unwrap_or(0)).unwrap_or(0));
    let ratchet_tier = map_tier(sec_tier);
    let role = SessionRole::from_str(state.role.as_deref().unwrap_or("initiator"));

    let mut star = StarCompass::new(sec_tier);
    star.init_with_shared_secret(&expand_shared(&shared_x));
    let salt = star.salt().cloned();

    if let Some(rs) = load_ratchet_state(state_path) {
        if let Some(sess) = rs.to_session() {
            return (sess, false); // 恢复的，不新建
        }
    }

    let sess = match role {
        SessionRole::Initiator => DoubleRatchetSession::new_sender(shared_x, ratchet_tier.clone(), salt),
        SessionRole::Responder => DoubleRatchetSession::new_receiver(shared_x, ratchet_tier, salt),
    };
    (sess, true) // 新建的
}

// ============================================================================
// CLI 主逻辑
// ============================================================================

fn run_cli(cli: &Cli) {
    let state_path = &cli.state;

    match &cli.command {
        Some(Commands::Planet { timestamp, symbols }) => {
            let dt = DateTime::from_timestamp(*timestamp, 0)
                .expect("无效时间戳");
            let calc = PlanetCalculator::new();
            let bits = calc.calc_planet_hexagram(&dt);

            #[derive(Serialize)]
            struct PlanetOut {
                timestamp: i64,
                hex_string: String,
                hexagrams: Option<String>,
            }

            if *symbols {
                let hexagrams: String = bits.chunks(3)
                    .map(|chunk| {
                        let val = (chunk[0] | (chunk[1] << 1) | (chunk[2] << 2)) & 0x7;
                        match val {
                            0 => "☰", 1 => "☷", 2 => "☳", 3 => "☴",
                            4 => "☵", 5 => "☲", 6 => "☶", 7 => "☱",
                            _ => "?",
                        }
                    })
                    .collect();
                out_json(&PlanetOut {
                    timestamp: *timestamp,
                    hex_string: PlanetCalculator::hexagram_to_hex_string(&bits),
                    hexagrams: Some(hexagrams),
                });
            } else {
                out_json(&PlanetOut {
                    timestamp: *timestamp,
                    hex_string: PlanetCalculator::hexagram_to_hex_string(&bits),
                    hexagrams: None,
                });
            }
        }

        Some(Commands::Init { tier, timestamp, lat, lon, event_hash, personal_hex }) => {
            let sec_tier = SecurityTier::from_name(tier)
                .expect(&format!("未知等级: {}，可选: kan/zhi/ren/tian", tier));
            let dt = DateTime::from_timestamp(*timestamp, 0)
                .expect("无效时间戳");
            let location = GeoLocation::new(*lat, *lon);
            let _event_arr = parse_event_hash(event_hash);
            let hex_arr = parse_personal_hex(personal_hex);

            let mut star = StarCompass::new(sec_tier);
            star.init(dt, Some(location), "cli_event", &hex_arr)
                .expect("初始化失败");

            let salt_bytes = star.salt()
                .map(|s| hex::encode(s.as_bytes()))
                .unwrap_or_default();

            let mut state = load_state(state_path);
            state.tier = Some(tier_u8(sec_tier).to_string());
            state.tier_name = Some(sec_tier.name_cn().to_string());
            state.tier_symbol = Some(sec_tier.symbol().to_string());
            state.salt = Some(salt_bytes);
            state.shared_x = None;
            state.role = None;
            save_state(state_path, &state).expect("保存状态失败");

            #[derive(Serialize)]
            struct InitOut {
                status: String,
                tier: String,
                tier_symbol: String,
                salt: String,
            }
            out_json(&InitOut {
                status: "ok".to_string(),
                tier: sec_tier.name_cn().to_string(),
                tier_symbol: sec_tier.symbol().to_string(),
                salt: state.salt.clone().unwrap(),
            });
        }

        Some(Commands::Keygen) => {
            let kx = HybridKeyExchange::generate(&mut thread_rng());
            let pub_hex = hex::encode(kx.x25519.public);
            let priv_hex = hex::encode(kx.x25519.secret());

            let mut state = load_state(state_path);
            state.public_key = Some(pub_hex.clone());
            state.private_key = Some(priv_hex);
            save_state(state_path, &state).expect("保存状态失败");

            #[derive(Serialize)]
            struct KeygenOut {
                status: String,
                public_key: String,
                hint: String,
            }
            out_json(&KeygenOut {
                status: "ok".to_string(),
                public_key: pub_hex,
                hint: "保存公钥发给对方，用 session 建立会话".to_string(),
            });
        }

        Some(Commands::Session { peer_public, role }) => {
            let state = load_state(state_path);

            state.public_key.as_ref()
                .expect("请先运行 keygen 生成密钥对");

            let peer = hex32(peer_public);
            let my_priv = state.private_key.as_ref()
                .map(|h| hex32(h))
                .expect("请先运行 keygen 生成密钥对");

            // 用保存的私钥重建 HybridKeyExchange
            let kx = HybridKeyExchange::restore(my_priv);
            let x_shared = kx.x25519.shared_secret(&peer);
            let shared64 = expand_shared(&x_shared);

            let sec_tier = tier_from_u8(state.tier.as_ref().map(|t| t.parse::<u8>().unwrap_or(0)).unwrap_or(0));
            let mut star = StarCompass::new(sec_tier);
            star.init_with_shared_secret(&shared64);

            let mut state = load_state(state_path);
            state.shared_x = Some(hex::encode(x_shared));
            state.role = Some(role.as_str().to_string());
            state.peer_public = Some(peer_public.clone());
            save_state(state_path, &state).expect("保存状态失败");

            #[derive(Serialize)]
            struct SessionOut {
                status: String,
                role: String,
                shared_x: String,
                hint: String,
            }
            out_json(&SessionOut {
                status: "ok".to_string(),
                role: role.as_str().to_string(),
                shared_x: hex::encode(x_shared),
                hint: "会话建立成功。运行 encrypt <明文> 加密消息".to_string(),
            });
        }

        Some(Commands::SelfTest) => {
            let alice_kx = HybridKeyExchange::generate(&mut thread_rng());
            let bob_kx = HybridKeyExchange::generate(&mut thread_rng());
            let x_shared = alice_kx.x25519.shared_secret(&bob_kx.x25519.public);
            let shared64 = expand_shared(&x_shared);

            let star = StarCompass::new(SecurityTier::KanWater);
            let mut star = star;
            star.init_with_shared_secret(&shared64);

            let ratchet_tier = map_tier(SecurityTier::KanWater);
            let salt = star.salt().cloned();
            let mut alice = DoubleRatchetSession::new_sender(x_shared, ratchet_tier.clone(), salt.clone());
            let mut bob = DoubleRatchetSession::new_receiver(x_shared, ratchet_tier, salt.clone());

            let sample = "星枢自测：双棘轮加密通信";
            let (ct, hdr) = alice.encrypt(sample.as_bytes(), &[]);
            let pt = bob.decrypt(&hdr, &ct, &[]).expect("解密失败");
            let pt_str = String::from_utf8(pt).unwrap();
            let passed = pt_str == sample;

            let mut state = load_state(state_path);
            state.shared_x = Some(hex::encode(x_shared));
            state.role = Some("initiator".to_string());
            state.tier = Some("0".to_string());
            save_state(state_path, &state).expect("保存状态失败");

            #[derive(Serialize)]
            struct SelfTestOut {
                status: String,
                result: String,
                sent: String,
                received: String,
            }
            out_json(&SelfTestOut {
                status: "ok".to_string(),
                result: if passed { "pass".to_string() } else { "fail".to_string() },
                sent: sample.to_string(),
                received: pt_str,
            });
        }

        Some(Commands::Encrypt { plaintext }) => {
            let state = load_state(state_path);
            let shared_x_hex = state.shared_x.as_ref()
                .expect("请先运行 session 或 self-test 建立会话");
            let shared_x = hex32(shared_x_hex);

            let (mut ratchet, is_new) = get_or_create_ratchet(&state, state_path, shared_x);

            let (ct, header) = ratchet.encrypt(plaintext.as_bytes(), &[]);
            let mut packet = header.serialize();
            packet.extend_from_slice(&ct);

            // 立即保存棘轮状态（新建或更新后都要保存）
            let rs = RatchetState::from_session(&ratchet);
            save_ratchet_state(state_path, &rs).expect("保存棘轮状态失败");
            let _ = save_state(state_path, &state);

            #[derive(Serialize)]
            struct EncryptOut {
                status: String,
                packet: String,
                msg_num: usize,
                restored: bool,
                hint: String,
            }
            out_json(&EncryptOut {
                status: "ok".to_string(),
                packet: hex::encode(&packet),
                msg_num: header.message_number,
                restored: !is_new,
                hint: "将 packet 字段值发给对方，用 decrypt 解密".to_string(),
            });
        }

        Some(Commands::Decrypt { packet }) => {
            let state = load_state(state_path);
            let shared_x_hex = state.shared_x.as_ref()
                .unwrap_or_else(|| panic!("请先运行 session 或 self-test 建立会话"));
            let shared_x = hex32(shared_x_hex);

            let bytes = match hex::decode(packet.trim().trim_start_matches("0x")) {
                Ok(b) => b,
                Err(e) => {
                    out_json(&json!({"status": "error", "message": format!("数据包不是有效的 hex: {}", e)}));
                    return;
                }
            };
            let header = match RatchetHeader::deserialize(&bytes) {
                Some(h) => h,
                None => {
                    out_json(&json!({"status": "error", "message": "数据包头部解析失败"}));
                    return;
                }
            };
            let ct = &bytes[40..];

            // 检测自解密场景（header.public_key == state.public_key）
            if let Some(ref my_pk_hex) = state.public_key {
                let my_pk = hex32(my_pk_hex);
                if header.public_key == my_pk {
                    out_json(&json!({
                        "status": "error",
                        "message": "自解密不支持：无法解密自己发送的消息（需要 message-key history）",
                        "hint": "请让对方运行 decrypt 命令解密此消息"
                    }));
                    return;
                }
            }

            // 解密方始终以 responder 角色重建会话
            let mut dec_state = state.clone();
            dec_state.role = Some("responder".to_string());
            let (mut ratchet, _is_new) = get_or_create_ratchet(&dec_state, state_path, shared_x);

            let pt = match ratchet.decrypt(&header, ct, &[]) {
                Some(p) => p,
                None => {
                    out_json(&json!({"status": "error", "message": "解密失败（序号不匹配或密钥错误）"}));
                    return;
                }
            };
            let plaintext = match String::from_utf8(pt) {
                Ok(s) => s,
                Err(e) => {
                    out_json(&json!({"status": "error", "message": format!("解密结果非 UTF-8: {}", e)}));
                    return;
                }
            };

            // 解密后保存状态
            let rs = RatchetState::from_session(&ratchet);
            let _ = save_ratchet_state(state_path, &rs);

            #[derive(Serialize)]
            struct DecryptOut {
                status: String,
                plaintext: String,
                msg_num: usize,
            }
            out_json(&DecryptOut {
                status: "ok".to_string(),
                plaintext,
                msg_num: header.message_number,
            });
        }

        Some(Commands::Status) => {
            let state = load_state(state_path);
            out_json(&state);
        }

        None => {
            println!("星枢加密体系 v{} - CLI 模式\n", VERSION);
            println!("状态文件: {}", cli.state);
            println!("\n运行 <command> --help 查看子命令帮助");
            println!("\n示例流程：");
            println!("  planet <timestamp>                          # 计算本卦");
            println!("  init kan <ts> <lat> <lon> <event_hash>     # 初始化");
            println!("  keygen                                      # 生成密钥对");
            println!("  session <peer_public>                       # 建立会话");
            println!("  encrypt <plaintext>                         # 加密");
            println!("  decrypt <packet>                            # 解密");
            println!("  selftest                                    # 自测");
        }
    }
}

// ============================================================================
// Tauri 模式
// ============================================================================

struct AppState {
    star: Mutex<Option<StarCompass>>,
    kx: Mutex<Option<HybridKeyExchange>>,
    ratchet: Mutex<Option<DoubleRatchetSession>>,
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

fn run_tauri() {
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

fn main() {
    let cli = Cli::parse();

    if cli.command.is_some() {
        run_cli(&cli);
    } else {
        run_tauri();
    }
}

// ============================================================================
// Tauri 命令
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
    packet: String,
    header_pk_preview: String,
    msg_num: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DecryptResult {
    plaintext: String,
    from_pk_preview: String,
    msg_num: usize,
}

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

    let _event_arr = parse_event_hash(&event_hash);
    let hex_arr = parse_personal_hex(&personal_hex);

    star.init(dt, Some(location), "encrypted_event", &hex_arr)
        .map_err(|e| format!("初始化失败: {:?}", e))?;

    *state.star.lock().unwrap() = Some(star);
    Ok("加密已初始化".to_string())
}

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

#[tauri::command]
fn calc_planet_hexagram(timestamp_secs: i64) -> Result<PlanetHexagramResult, String> {
    let dt = DateTime::from_timestamp(timestamp_secs, 0)
        .ok_or("无效时间戳")?;

    let calc = PlanetCalculator::new();
    let bits = calc.calc_planet_hexagram(&dt);

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
        hex_string: PlanetCalculator::hexagram_to_hex_string(&bits),
        hexagrams,
    })
}

#[tauri::command]
fn generate_keypair(state: State<AppState>) -> Result<String, String> {
    let kx = HybridKeyExchange::generate(&mut thread_rng());
    let my_pub = kx.x25519.public;
    *state.kx.lock().unwrap() = Some(kx);
    Ok(hex::encode(my_pub))
}

fn tauri_map_tier(tier: SecurityTier) -> RatchetTier {
    match tier {
        SecurityTier::KanWater => RatchetTier::Kan,
        SecurityTier::XunWind => RatchetTier::Zhi,
        SecurityTier::LiFire => RatchetTier::Ren,
        SecurityTier::QianHeaven => RatchetTier::Tian,
    }
}

fn tauri_expand_shared(x: &[u8; 32]) -> [u8; 64] {
    let mut s = [0u8; 64];
    for i in 0..64 {
        s[i] = x[i % 32];
    }
    s
}

#[tauri::command]
fn establish_session(
    state: State<AppState>,
    peer_public_hex: String,
    role: Option<String>,
) -> Result<String, String> {
    let kx_guard = state.kx.lock().unwrap();
    let kx = kx_guard.as_ref().ok_or("请先生成密钥对")?;

    let peer = hex32(&peer_public_hex);
    let x_shared = kx.x25519.shared_secret(&peer);
    drop(kx_guard);

    let shared64 = tauri_expand_shared(&x_shared);
    let mut star_guard = state.star.lock().unwrap();
    let star = star_guard.as_mut().ok_or("请先完成初始化（点击初始化加密）")?;
    star.init_with_shared_secret(&shared64);

    let ratchet_tier = tauri_map_tier(star.tier());
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
    Ok(format!("已与对端建立会话（角色={}），共享密钥已注入，可以加解密了。", role_str))
}

#[tauri::command]
fn establish_session_self(state: State<AppState>) -> Result<String, String> {
    let alice_kx = HybridKeyExchange::generate(&mut thread_rng());
    let bob_kx = HybridKeyExchange::generate(&mut thread_rng());

    let x_shared = alice_kx.x25519.shared_secret(&bob_kx.x25519.public);
    let shared64 = tauri_expand_shared(&x_shared);

    let mut star_guard = state.star.lock().unwrap();
    let star = star_guard.as_mut().ok_or("请先完成初始化（点击初始化加密）")?;
    star.init_with_shared_secret(&shared64);

    let ratchet_tier = tauri_map_tier(star.tier());
    let salt = star.salt().cloned();

    let ratchet = DoubleRatchetSession::new_sender(x_shared, ratchet_tier.clone(), salt.clone());

    *state.shared_x.lock().unwrap() = Some(x_shared);
    *state.ratchet.lock().unwrap() = Some(ratchet);
    *state.role.lock().unwrap() = Some(SessionRole::Initiator);

    Ok("已与模拟对端建立会话（角色=发起方），共享密钥已注入，现在可以加解密了。".to_string())
}

#[tauri::command]
fn encrypt_message(state: State<AppState>, plaintext: String) -> Result<EncryptResult, String> {
    let mut guard = state.ratchet.lock().unwrap();
    let ratchet = guard.as_mut().ok_or("请先建立会话（点击「建立会话」或「自测」）")?;

    let (ct, header) = ratchet.encrypt(plaintext.as_bytes(), &[]);

    let mut packet = header.serialize();
    packet.extend_from_slice(&ct);

    Ok(EncryptResult {
        packet: hex::encode(&packet),
        header_pk_preview: hex::encode(&header.public_key[..4]),
        msg_num: header.message_number,
    })
}

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

#[tauri::command]
fn self_test_message(state: State<AppState>) -> Result<String, String> {
    let shared_guard = state.shared_x.lock().unwrap();
    let x_shared = shared_guard.ok_or("请先建立会话（点击「建立会话」或「自测」）")?;

    let star_guard = state.star.lock().unwrap();
    let star = star_guard.as_ref().ok_or("请先完成初始化")?;
    let ratchet_tier = tauri_map_tier(star.tier());
    let salt = star.salt().cloned();
    drop(star_guard);
    drop(shared_guard);

    let mut alice = DoubleRatchetSession::new_sender(x_shared, ratchet_tier.clone(), salt.clone());
    let mut bob = DoubleRatchetSession::new_receiver(x_shared, ratchet_tier, salt);

    let sample = "星枢自测消息：双棘轮收发成功";
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
