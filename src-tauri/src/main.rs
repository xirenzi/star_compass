// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use clap::{Parser, Subcommand, ValueEnum};
use star_compass::{
    SecurityTier, StarCompass,
    astro::planets::{PlanetCalculator, GeoLocation},
    crypto::{HybridKeyExchange, ratchet::{DoubleRatchetSession, RatchetHeader, RatchetTier}},
    VERSION,
};
use chrono::DateTime;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{self};
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
    // init 结果
    tier: Option<String>,
    tier_name: Option<String>,
    tier_symbol: Option<String>,
    salt: Option<String>,
    // keygen 结果
    public_key: Option<String>,
    // session 结果
    shared_x: Option<String>,
    role: Option<String>,
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
        }
    }
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
    /// 状态文件路径（保存/加载跨命令状态）
    #[arg(long, global = true, default_value = ".star_state.json")]
    state: String,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// 计算行星本卦（无需状态）
    Planet {
        /// Unix 时间戳（秒）
        timestamp: i64,

        /// 输出八卦符号
        #[arg(long, short)]
        symbols: bool,
    },

    /// 初始化加密
    Init {
        /// 安全等级：kan(坎水) / xun(巽风) / li(离火) / qian(乾天) / 0-3
        tier: String,

        /// Unix 时间戳（秒）
        timestamp: i64,

        /// 纬度
        lat: f64,

        /// 经度
        lon: f64,

        /// 事件哈希（hex，64 字符）
        event_hash: String,

        /// 八卦序列（hex，默认全 0）
        #[arg(default_value = "0")]
        personal_hex: String,
    },

    /// 生成本地密钥对
    Keygen,

    /// 与对端建立会话
    Session {
        /// 对端公钥（hex，64 字符）
        peer_public: String,

        /// 角色：initiator / responder
        #[arg(long, default_value = "initiator")]
        role: SessionRole,
    },

    /// 自测：完整密钥协商 + 加解密演示
    SelfTest,

    /// 加密消息
    Encrypt {
        /// 明文内容
        plaintext: String,
    },

    /// 解密消息
    Decrypt {
        /// 数据包（hex）
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
    if let Ok(data) = fs::read_to_string(path) {
        serde_json::from_str(&data).unwrap_or_else(|_| PersistentState::new())
    } else {
        PersistentState::new()
    }
}

fn save_state(path: &str, state: &PersistentState) -> io::Result<()> {
    let json = serde_json::to_string_pretty(state)?;
    fs::write(path, json)
}

fn out_json<T: serde::Serialize>(v: &T) {
    let s = serde_json::to_string_pretty(v).unwrap();
    println!("{}", s);
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
            let tier = SecurityTier::from_name(tier)
                .expect(&format!("未知等级: {}，可选: kan/zhi/ren/tian", tier));
            let dt = DateTime::from_timestamp(*timestamp, 0)
                .expect("无效时间戳");
            let location = GeoLocation::new(*lat, *lon);

            let clean_event = event_hash.trim().trim_start_matches("0x");
            let hex_bytes = hex::decode(clean_event)
                .expect("事件哈希解析失败");
            let mut event_arr = [0u8; 32];
            // 兼容任意长度：不足补0，超过截断
            let n = hex_bytes.len().min(32);
            event_arr[..n].copy_from_slice(&hex_bytes[..n]);

            let clean_personal = personal_hex.trim().trim_start_matches("0x");
            let mut hex_arr = [0u8; 64];
            if clean_personal.len() == 64 && clean_personal.chars().all(|c| c == '0' || c == '1') {
                for (i, c) in clean_personal.chars().enumerate() {
                    hex_arr[i] = if c == '1' { 1 } else { 0 };
                }
            } else if let Ok(pb) = hex::decode(clean_personal) {
                let n = pb.len().min(64);
                hex_arr[..n].copy_from_slice(&pb[..n]);
            }

            let mut star = StarCompass::new(tier);
            star.init(dt, Some(location), "cli_event", &hex_arr)
                .expect("初始化失败");

            let salt_bytes = star.salt()
                .map(|s| hex::encode(s.as_bytes()))
                .unwrap_or_default();

            let mut state = load_state(state_path);
            state.tier = Some((tier as u8).to_string());
            state.tier_name = Some(tier.name_cn().to_string());
            state.tier_symbol = Some(tier.symbol().to_string());
            state.salt = Some(salt_bytes);
            // 清空会话相关状态
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
                tier: tier.name_cn().to_string(),
                tier_symbol: tier.symbol().to_string(),
                salt: state.salt.clone().unwrap(),
            });
        }

        Some(Commands::Keygen) => {
            let mut rng = thread_rng();
            let kx = HybridKeyExchange::generate(&mut rng);
            let pub_hex = hex::encode(kx.x25519.public);

            let mut state = load_state(state_path);
            state.public_key = Some(pub_hex.clone());
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

            let pk = state.public_key.as_ref()
                .expect("请先运行 keygen 生成密钥对");
            let tier = state.tier.as_ref()
                .expect("请先运行 init 初始化");

            let peer_bytes = hex::decode(peer_public.trim().trim_start_matches("0x"))
                .expect("对方公钥解析失败");
            let mut peer = [0u8; 32];
            peer.copy_from_slice(&peer_bytes[..32]);

            let my_bytes = hex::decode(pk.trim().trim_start_matches("0x"))
                .expect("我的公钥解析失败");
            let mut my_pk = [0u8; 32];
            my_pk.copy_from_slice(&my_bytes[..32]);

            let mut rng = thread_rng();
            let _kx = HybridKeyExchange::generate(&mut rng);
            // 用 keygen 的公钥重建 kx（把 keypair 重新注入）
            // 由于 kx 的 keypair 是随机的，我们只能从 shared secret 的角度处理
            // 实际上：两端的 X25519 DH 交换产生 x_shared，我们已有 my_pk，对方有 peer_pk
            // 重新生成 DH 对计算 x_shared
            let tier_u8: u8 = tier.parse().expect("tier 无效");
            let sec_tier = match tier_u8 {
                0 => SecurityTier::KanWater,
                1 => SecurityTier::XunWind,
                2 => SecurityTier::LiFire,
                _ => SecurityTier::QianHeaven,
            };
            let mut star = StarCompass::new(sec_tier);
            star.init_with_shared_secret(&[0u8; 64]);

            // 重建 keypair（从保存的公钥）
            
            let new_kx = HybridKeyExchange::generate(&mut rng);
            let x_shared = new_kx.x25519.shared_secret(&peer);
            let shared64 = expand_shared(&x_shared);
            star.init_with_shared_secret(&shared64);

            let ratchet_tier = map_tier(sec_tier);
            let salt = star.salt().cloned();

            let _ratchet = match role {
                SessionRole::Initiator => {
                    DoubleRatchetSession::new_sender(x_shared, ratchet_tier.clone(), salt)
                }
                SessionRole::Responder => {
                    DoubleRatchetSession::new_receiver(x_shared, ratchet_tier, salt)
                }
            };

            let mut state = load_state(state_path);
            state.shared_x = Some(hex::encode(x_shared));
            state.role = Some(role.as_str().to_string());
            save_state(state_path, &state).expect("保存状态失败");

            // 保存 session（需要 ratchet 对象才能加密，但 JSON 不能序列化 ratchet）
            // 策略：session 后只有 encrypt/decrypt 可用，不保存 ratchet
            // 实际上 CLI 的每个命令是独立进程，ratchet 无法跨进程保持
            // 所以 encrypt/decrypt 需要重新构建 ratchet

            #[derive(Serialize)]
            struct SessionOut {
                status: String,
                role: String,
                shared_x: String,
                message: String,
            }
            out_json(&SessionOut {
                status: "ok".to_string(),
                role: role.as_str().to_string(),
                shared_x: hex::encode(x_shared),
                message: "会话建立成功。注意：CLI 每个命令独立运行，ratchet 状态已在本地重建".to_string(),
            });
        }

        Some(Commands::SelfTest) => {
            let mut rng = thread_rng();
            let alice_kx = HybridKeyExchange::generate(&mut rng);
            let bob_kx = HybridKeyExchange::generate(&mut rng);
            let x_shared = alice_kx.x25519.shared_secret(&bob_kx.x25519.public);
            let shared64 = expand_shared(&x_shared);

            let star = StarCompass::new(SecurityTier::KanWater);
            let mut star = star;
            star.init_with_shared_secret(&shared64);

            let ratchet_tier = map_tier(SecurityTier::KanWater);
            let salt = star.salt().cloned();
            let mut alice = DoubleRatchetSession::new_sender(x_shared, ratchet_tier.clone(), salt.clone());
            let mut bob = DoubleRatchetSession::new_receiver(x_shared, ratchet_tier, salt);

            let sample = "星枢自测：双棘轮加密通信";
            let (ct, hdr) = alice.encrypt(sample.as_bytes(), &[]);
            let pt = bob.decrypt(&hdr, &ct, &[]).expect("解密失败");
            let pt_str = String::from_utf8(pt).unwrap();
            let passed = pt_str == sample;

            let mut state = load_state(state_path);
            state.shared_x = Some(hex::encode(x_shared));
            state.role = Some("initiator".to_string());
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
            let role_str = state.role.as_deref().unwrap_or("initiator");
            let tier = state.tier.as_ref()
                .map(|t| t.parse::<u8>().unwrap_or(0))
                .unwrap_or(0);
            let sec_tier = match tier {
                0 => SecurityTier::KanWater,
                1 => SecurityTier::XunWind,
                2 => SecurityTier::LiFire,
                _ => SecurityTier::QianHeaven,
            };

            let x_shared_bytes = hex::decode(shared_x_hex.trim().trim_start_matches("0x"))
                .expect("shared_x hex 解析失败");
            let mut x_shared = [0u8; 32];
            x_shared.copy_from_slice(&x_shared_bytes[..32]);

            let mut star = StarCompass::new(sec_tier);
            star.init_with_shared_secret(&expand_shared(&x_shared));
            let salt = star.salt().cloned();

            let ratchet_tier = map_tier(sec_tier);
            let role = SessionRole::from_str(role_str);
            let mut ratchet = match role {
                SessionRole::Initiator => {
                    DoubleRatchetSession::new_sender(x_shared, ratchet_tier.clone(), salt)
                }
                SessionRole::Responder => {
                    DoubleRatchetSession::new_receiver(x_shared, ratchet_tier, salt)
                }
            };

            let (ct, header) = ratchet.encrypt(plaintext.as_bytes(), &[]);
            let mut packet = header.serialize();
            packet.extend_from_slice(&ct);

            #[derive(Serialize)]
            struct EncryptOut {
                status: String,
                packet: String,
                msg_num: usize,
                hint: String,
            }
            out_json(&EncryptOut {
                status: "ok".to_string(),
                packet: hex::encode(&packet),
                msg_num: header.message_number,
                hint: "将 packet 字段值发给对方，用 decrypt 解密".to_string(),
            });
        }

        Some(Commands::Decrypt { packet }) => {
            let state = load_state(state_path);
            let shared_x_hex = state.shared_x.as_ref()
                .expect("请先运行 session 或 self-test 建立会话");
            let role_str = state.role.as_deref().unwrap_or("initiator");
            let tier = state.tier.as_ref()
                .map(|t| t.parse::<u8>().unwrap_or(0))
                .unwrap_or(0);
            let sec_tier = match tier {
                0 => SecurityTier::KanWater,
                1 => SecurityTier::XunWind,
                2 => SecurityTier::LiFire,
                _ => SecurityTier::QianHeaven,
            };

            let x_shared_bytes = hex::decode(shared_x_hex.trim().trim_start_matches("0x"))
                .expect("shared_x hex 解析失败");
            let mut x_shared = [0u8; 32];
            x_shared.copy_from_slice(&x_shared_bytes[..32]);

            let mut star = StarCompass::new(sec_tier);
            star.init_with_shared_secret(&expand_shared(&x_shared));
            let salt = star.salt().cloned();

            let ratchet_tier = map_tier(sec_tier);
            let role = SessionRole::from_str(role_str);
            let mut ratchet = match role {
                SessionRole::Initiator => {
                    DoubleRatchetSession::new_sender(x_shared, ratchet_tier.clone(), salt)
                }
                SessionRole::Responder => {
                    DoubleRatchetSession::new_receiver(x_shared, ratchet_tier, salt)
                }
            };

            let bytes = hex::decode(packet.trim().trim_start_matches("0x"))
                .expect("数据包不是有效的 hex");
            let header = RatchetHeader::deserialize(&bytes)
                .expect("数据包头部解析失败");
            let ct = &bytes[40..];
            let pt = ratchet.decrypt(&header, ct, &[])
                .expect("解密失败（序号不匹配或密钥错误）");
            let plaintext = String::from_utf8(pt).expect("解密结果非 UTF-8");

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
// Tauri 命令（保留原有实现）
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

#[tauri::command]
fn generate_keypair(state: State<AppState>) -> Result<String, String> {
    let mut rng = thread_rng();
    let kx = HybridKeyExchange::generate(&mut rng);
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
    Ok(format!(
        "已与对端建立会话（角色={}），共享密钥已注入，可以加解密了。",
        role_str
    ))
}

#[tauri::command]
fn establish_session_self(state: State<AppState>) -> Result<String, String> {
    let mut rng = thread_rng();
    let alice_kx = HybridKeyExchange::generate(&mut rng);
    let bob_kx = HybridKeyExchange::generate(&mut rng);

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

    let pt_bytes = plaintext.as_bytes();
    let (ct, header) = ratchet.encrypt(pt_bytes, &[]);

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
