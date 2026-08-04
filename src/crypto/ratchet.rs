//! 双棘轮协议（Double Ratchet）
//!
//! 基于 Signal Double Ratchet Algorithm。
//!
//! 协议流程：
//! - Alice 初始化：dh_key_pair = A1（只用 shared_secret 派初始链，不做 DH）
//! - Alice→Bob m1：header={A1, 0}，用 send_chain_0 加密
//! - Bob 收到 m1：recv_chain_0 = derive(shared, "send-chain")，解密，然后 DH(A1, B1)
//! - Bob→Bob m2：header={B1, 0}，用 send_chain_1 加密
//! - Alice 收到 m2：用 recv_chain_0 解密，然后 DH(A1, B1) → recv_chain_1
//!   （⚠️ 注意：Alice 执行 DH 时复用初始化时的 A1，不是生成新的！）
//! - Alice→Alice m3：header={A2, 0}，用 send_chain_2 加密（A2 = DH棘轮后新生成的密钥对）
//!
//! 集成星枢体系特点：七曜黄经、三才盐、四版分级

use crate::crypto::aesgcm::{AeadCipher, NonceData};
use crate::crypto::kyber_x25519::HybridKeyPair;
use crate::astro::planets::ThreeCaSalt;
use hkdf::Hkdf;
use sha2::{Sha256, Digest};
use zeroize::ZeroizeOnDrop;
use serde::{Serialize, Deserialize};
use std::collections::BTreeMap;
use hex;

type HkdfSha256 = Hkdf<Sha256>;

// ============================================================================
// 消息密钥 & 根密钥
// ============================================================================

#[derive(ZeroizeOnDrop, PartialEq, Debug, Clone)]
pub struct MessageKey([u8; 32]);

impl MessageKey {
    pub fn as_bytes(&self) -> &[u8; 32] { &self.0 }
    pub fn from_slice(s: &[u8]) -> Self {
        let mut k = [0u8; 32];
        k.copy_from_slice(&s[..32]);
        Self(k)
    }
}

#[derive(ZeroizeOnDrop, Clone)]
pub struct RootKey([u8; 32]);

impl RootKey {
    pub fn as_bytes(&self) -> &[u8; 32] { &self.0 }
}

// ============================================================================
// 可序列化的 Ratchet 状态（用于 CLI 持久化）
// ============================================================================

/// 可序列化的双棘轮状态，供 CLI 模式持久化到文件
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RatchetState {
    /// 根密钥（hex，64 字符）
    pub root_key: String,
    /// 发送链密钥（hex）
    pub send_chain_key: String,
    pub send_message_number: usize,
    pub send_prev_chain_length: usize,
    /// 接收链密钥（hex）
    pub recv_chain_key: String,
    pub recv_message_number: usize,
    /// 我方 DH 密钥对（hex）
    pub dh_private_x25519: String,
    pub dh_public_x25519: String,
    pub dh_private_kyber: String,
    pub dh_public_kyber: String,
    /// 对端 DH 公钥（hex，可选）
    pub remote_dh_public: Option<String>,
    /// 已跳过密钥缓存（序号 → 消息密钥，hex）
    pub skipped_keys: Vec<(usize, String)>,
    /// 棘轮等级 0=Kan 1=Zhi 2=Ren 3=Tian
    pub tier: u8,
    /// 是否已完成首次 DH 棘轮
    pub dh_ratcheted: bool,
    /// 三才盐（hex 编码）
    pub salt: Option<String>,
}

impl RatchetState {
    /// 从当前 DoubleRatchetSession 导出状态
    pub fn from_session(s: &DoubleRatchetSession) -> Self {
        let dh = s.dh_key_pair.public_key();
        let tier = match &s.tier {
            RatchetTier::Kan => 0,
            RatchetTier::Zhi => 1,
            RatchetTier::Ren => 2,
            RatchetTier::Tian => 3,
        };
        Self {
            root_key: hex::encode(s.root_key.as_bytes()),
            send_chain_key: hex::encode(&s.sending.chain_key),
            send_message_number: s.sending.message_number,
            send_prev_chain_length: s.sending.previous_chain_length,
            recv_chain_key: hex::encode(&s.receiving.chain_key),
            recv_message_number: s.receiving.message_number,
            dh_private_x25519: hex::encode(s.dh_key_pair.x25519_secret()),
            dh_public_x25519: hex::encode(&dh.x25519),
            dh_private_kyber: hex::encode(s.dh_key_pair.kyber_secret()),
            dh_public_kyber: hex::encode(&dh.kyber),
            remote_dh_public: s.remote_dh_public.map(|pk| hex::encode(pk)),
            skipped_keys: s.skip_buffer.iter()
                .map(|(n, k)| (*n, hex::encode(k.as_bytes())))
                .collect(),
            tier,
            dh_ratcheted: s.dh_ratcheted,
            salt: s.salt.as_ref().map(|sl| hex::encode(sl.as_bytes())),
        }
    }

    /// 恢复为 DoubleRatchetSession
    #[allow(deprecated)]
    pub fn to_session(&self) -> Option<DoubleRatchetSession> {
        let ratchet_tier = match self.tier {
            0 => RatchetTier::Kan,
            1 => RatchetTier::Zhi,
            2 => RatchetTier::Ren,
            3 => RatchetTier::Tian,
            _ => return None,
        };

        // 解析 hex
        let root_key = hex::decode(&self.root_key).ok()?;
        let send_chain_key = hex::decode(&self.send_chain_key).ok()?;
        let recv_chain_key = hex::decode(&self.recv_chain_key).ok()?;
        let dh_xs = hex::decode(&self.dh_private_x25519).ok()?;
        let dh_xp = hex::decode(&self.dh_public_x25519).ok()?;
        let dh_ks = hex::decode(&self.dh_private_kyber).ok()?;
        let dh_kp = hex::decode(&self.dh_public_kyber).ok()?;
        let remote_pk = self.remote_dh_public.as_ref()
            .and_then(|h| hex::decode(h).ok());

        // 转为定长数组
        let mut rk = [0u8; 32]; rk.copy_from_slice(&root_key);
        let mut sck = [0u8; 32]; sck.copy_from_slice(&send_chain_key);
        let mut rck = [0u8; 32]; rck.copy_from_slice(&recv_chain_key);
        let mut dxs = [0u8; 32]; dxs.copy_from_slice(&dh_xs);
        let mut dxp = [0u8; 32]; dxp.copy_from_slice(&dh_xp);
        let mut dks = [0u8; 1632]; dks.copy_from_slice(&dh_ks);
        let mut dkp = [0u8; 800]; dkp.copy_from_slice(&dh_kp);
        let remote_pk = remote_pk.map(|v| { let mut a = [0u8; 32]; a.copy_from_slice(&v); a });

        // 重建 DH 密钥对
        let dh_kp = HybridKeyPair::restore(&dxs, &dxp, &dks, &dkp);

        // 重建链状态
        let tier_clone = ratchet_tier.clone();
        let mut sending = ChainState::new(sck, ratchet_tier.clone());
        sending.message_number = self.send_message_number;
        sending.previous_chain_length = self.send_prev_chain_length;

        let mut receiving = ChainState::new(rck, ratchet_tier.clone());
        receiving.message_number = self.recv_message_number;

        // 重建跳过缓存
        let mut skip_buf = SkipBuffer::new(ratchet_tier.max_skip());
        for (num, key_hex) in &self.skipped_keys {
            if let Ok(key_bytes) = hex::decode(key_hex) {
                let mut kb = [0u8; 32];
                kb.copy_from_slice(&key_bytes);
                let _ = skip_buf.store(*num, MessageKey(kb));
            }
        }

        // 重建盐
        let salt = self.salt.as_ref().and_then(|h| {
            hex::decode(h).ok().map(|bytes| {
                let mut arr = [0u8; 256];
                let n = 256.min(bytes.len());
                arr[..n].copy_from_slice(&bytes[..n]);
                let sl = ThreeCaSalt::from_bytes(&arr);

                sl
            })
        });

        Some(DoubleRatchetSession {
            root_key: RootKey(rk),
            sending,
            receiving,
            dh_key_pair: dh_kp,
            remote_dh_public: remote_pk,
            skip_buffer: skip_buf,
            tier: tier_clone,
            salt,
            dh_ratcheted: self.dh_ratcheted,
        })
    }
}

// ============================================================================
// SkipBuffer
// ============================================================================

pub struct SkipBuffer {
    skipped_keys: BTreeMap<usize, MessageKey>,
    max_skip: usize,
}

impl SkipBuffer {
    pub fn new(max_skip: usize) -> Self {
        Self { skipped_keys: BTreeMap::new(), max_skip }
    }
    pub fn store(&mut self, msg_num: usize, key: MessageKey) -> bool {
        if self.skipped_keys.len() >= self.max_skip { return false; }
        self.skipped_keys.insert(msg_num, key);
        true
    }
    pub fn get(&self, msg_num: usize) -> Option<&MessageKey> {
        self.skipped_keys.get(&msg_num)
    }
    /// 迭代所有缓存的跳过密钥
    pub fn iter(&self) -> impl Iterator<Item = (&usize, &MessageKey)> {
        self.skipped_keys.iter()
    }
}

// ============================================================================
// RatchetTier
// ============================================================================

#[derive(Clone, PartialEq, Eq)]
pub enum RatchetTier {
    Kan,
    Zhi,
    Ren,
    Tian,
}

impl RatchetTier {
    pub fn info_label(&self) -> Option<&'static [u8]> {
        match self {
            RatchetTier::Kan  => Some(b"StarCompass-Kan"),
            RatchetTier::Zhi  => Some(b"StarCompass-Zhi"),
            RatchetTier::Ren  => Some(b"StarCompass-Ren"),
            RatchetTier::Tian => Some(b"StarCompass-Tian"),
        }
    }
    pub fn max_skip(&self) -> usize {
        match self {
            RatchetTier::Kan  => 100,
            RatchetTier::Zhi  => 500,
            RatchetTier::Ren  => 1000,
            RatchetTier::Tian => 5000,
        }
    }
}

// ============================================================================
// ChainState
// ============================================================================

#[derive(Clone)]
struct ChainState {
    chain_key: [u8; 32],
    message_number: usize,
    previous_chain_length: usize,
    tier: RatchetTier,
}

impl ChainState {
    fn new(chain_key: [u8; 32], tier: RatchetTier) -> Self {
        Self { chain_key, message_number: 0, previous_chain_length: 0, tier }
    }

    fn derive_message_key(&mut self, salt: &[u8]) -> MessageKey {
        let label = self.tier.info_label().unwrap_or(b"StarCompass");

        let mut msg_info = label.to_vec();
        msg_info.extend_from_slice(&self.message_number.to_le_bytes());
        let mut msg_key_out = [0u8; 32];
        let hk = HkdfSha256::new(Some(salt), &self.chain_key);
        let _ = hk.expand(&msg_info, &mut msg_key_out);

        let mut step_info = label.to_vec();
        step_info.extend_from_slice(b"ratchet-step");
        let mut step_out = [0u8; 32];
        let hk2 = HkdfSha256::new(Some(salt), &self.chain_key);
        let _ = hk2.expand(&step_info, &mut step_out);

        self.chain_key = step_out;
        self.message_number += 1;
        MessageKey::from_slice(&msg_key_out)
    }
}

// ============================================================================
// DH 辅助
// ============================================================================

fn x25519_scalar_mult(secret: &[u8; 32], public: &[u8; 32]) -> [u8; 32] {
    use curve25519_dalek::montgomery::MontgomeryPoint;
    use curve25519_dalek::scalar::Scalar;

    let mut sk = *secret;
    sk[0] &= 248;
    sk[31] &= 127;
    sk[31] |= 64;

    let scalar = Scalar::from_bytes_mod_order(sk);
    let point = MontgomeryPoint(*public);
    (scalar * point).to_bytes()
}

fn dh_output_hash(dh_raw: &[u8; 32]) -> [u8; 32] {
    let h = Sha256::digest(dh_raw);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h);
    out
}

// ============================================================================
// 头部
// ============================================================================

#[derive(Clone, PartialEq, Eq)]
pub struct RatchetHeader {
    pub public_key: [u8; 32],
    pub message_number: usize,
    pub previous_chain_length: usize,
}

impl RatchetHeader {
    pub fn new(public_key: [u8; 32], message_number: usize, previous_chain_length: usize) -> Self {
        Self { public_key, message_number, previous_chain_length }
    }
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(40);
        buf.extend_from_slice(&self.public_key);
        buf.extend_from_slice(&(self.message_number as u32).to_le_bytes());
        buf.extend_from_slice(&(self.previous_chain_length as u32).to_le_bytes());
        buf
    }
    pub fn deserialize(data: &[u8]) -> Option<Self> {
        if data.len() < 40 { return None; }
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&data[..32]);
        let msg_num = u32::from_le_bytes(data[32..36].try_into().ok()?) as usize;
        let prev_len = u32::from_le_bytes(data[36..40].try_into().ok()?) as usize;
        Some(Self::new(pk, msg_num, prev_len))
    }
}

// ============================================================================
// 密钥派生辅助
// ============================================================================

fn derive_chain(secret: &[u8; 32], label: &[u8], tier: &RatchetTier, salt: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let tier_label = tier.info_label().unwrap_or(b"StarCompass");
    let mut info = tier_label.to_vec();
    info.extend_from_slice(label);
    let hk = HkdfSha256::new(Some(salt), secret);
    let _ = hk.expand(&info, &mut out);
    out
}

fn get_salt(salt: &Option<ThreeCaSalt>) -> Vec<u8> {
    salt.as_ref()
        .map(|s| s.synthesize())
        .unwrap_or_else(|| vec![0u8; 40])
}

// ============================================================================
// DoubleRatchetSession
// ============================================================================

/// 双棘轮会话
pub struct DoubleRatchetSession {
    root_key: RootKey,
    sending: ChainState,
    receiving: ChainState,
    dh_key_pair: HybridKeyPair,
    remote_dh_public: Option<[u8; 32]>,
    skip_buffer: SkipBuffer,
    tier: RatchetTier,
    salt: Option<ThreeCaSalt>,
    dh_ratcheted: bool,
}

impl DoubleRatchetSession {
    /// 创建发送方（Alice）
    /// 初始化：生成一个 ephemeral 密钥对；用 shared_secret 派初始发送链
    pub fn new_sender(shared_secret: [u8; 32], tier: RatchetTier, salt: Option<ThreeCaSalt>) -> Self {
        let salt_data = get_salt(&salt);
        let dh_kp = HybridKeyPair::generate();

        let send_chain = derive_chain(&shared_secret, b"send-chain", &tier, &salt_data);
        let recv_chain = derive_chain(&shared_secret, b"recv-chain", &tier, &salt_data);

        Self {
            root_key: RootKey(shared_secret),
            sending: ChainState::new(send_chain, tier.clone()),
            receiving: ChainState::new(recv_chain, tier.clone()),
            dh_key_pair: dh_kp,
            remote_dh_public: None,
            skip_buffer: SkipBuffer::new(tier.max_skip()),
            tier,
            salt,
            dh_ratcheted: false,
        }
    }

    /// 创建接收方（Bob）
    /// 初始化：仅用 shared_secret 派初始接收链
    /// 创建发送方（Alice）—— 使用指定的 DH keypair
    pub fn new_sender_with(shared_secret: [u8; 32], tier: RatchetTier, salt: Option<ThreeCaSalt>, dh_kp: HybridKeyPair) -> Self {
        let salt_data = get_salt(&salt);
        let send_chain = derive_chain(&shared_secret, b"send-chain", &tier, &salt_data);
        let recv_chain = derive_chain(&shared_secret, b"recv-chain", &tier, &salt_data);
        Self {
            root_key: RootKey(shared_secret),
            sending: ChainState::new(send_chain, tier.clone()),
            receiving: ChainState::new(recv_chain, tier.clone()),
            dh_key_pair: dh_kp,
            remote_dh_public: None,
            skip_buffer: SkipBuffer::new(tier.max_skip()),
            tier,
            salt,
            dh_ratcheted: false,
        }
    }

    /// 创建接收方（Bob）—— 使用指定的 DH keypair
    pub fn new_receiver_with(shared_secret: [u8; 32], tier: RatchetTier, salt: Option<ThreeCaSalt>, dh_kp: HybridKeyPair) -> Self {
        let salt_data = get_salt(&salt);
        let recv_chain = derive_chain(&shared_secret, b"send-chain", &tier, &salt_data);
        let send_chain = derive_chain(&shared_secret, b"recv-chain", &tier, &salt_data);
        Self {
            root_key: RootKey(shared_secret),
            sending: ChainState::new(send_chain, tier.clone()),
            receiving: ChainState::new(recv_chain, tier.clone()),
            dh_key_pair: dh_kp,
            remote_dh_public: None,
            skip_buffer: SkipBuffer::new(tier.max_skip()),
            tier,
            salt,
            dh_ratcheted: false,
        }
    }

    /// 创建接收方（Bob）—— 内部生成 DH keypair
    pub fn new_receiver(shared_secret: [u8; 32], tier: RatchetTier, salt: Option<ThreeCaSalt>) -> Self {
        Self::new_receiver_with(shared_secret, tier, salt, HybridKeyPair::generate())
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.dh_key_pair.public_key().x25519
    }

    /// 执行 DH 棘轮（复用现有 dh_key_pair）
    ///
    /// 协议：
    /// 1. 计算 DH(dh_key_pair.secret, remote_pk)
    /// 2. 用 DH 输出更新 root_key 和链密钥
    /// 3. 生成新的 dh_key_pair（用于下一轮）
    /// 4. 设置 remote_dh_public
    fn perform_dh_ratchet(&mut self, remote_pk: &[u8; 32]) {
        let our_secret = self.dh_key_pair.x25519_secret();

        let dh_raw = x25519_scalar_mult(&our_secret, remote_pk);
        let dh_hash = dh_output_hash(&dh_raw);

        let salt_data = get_salt(&self.salt);

        // 更新 root_key：HKDF(root_key || dh_hash)
        let tier_label = self.tier.info_label().unwrap_or(b"StarCompass");
        let mut ikm = self.root_key.as_bytes().to_vec();
        ikm.extend_from_slice(&dh_hash);
        ikm.extend_from_slice(&salt_data);

        let hk = HkdfSha256::new(Some(&ikm), &[]);

        let mut new_root = [0u8; 32];
        let mut recv_new = [0u8; 32];
        let mut send_new = [0u8; 32];

        let mut lbl1 = tier_label.to_vec();
        lbl1.extend_from_slice(b"recv-ratchet");
        let _ = hk.expand(&lbl1, &mut recv_new);

        let mut lbl2 = tier_label.to_vec();
        lbl2.extend_from_slice(b"send-ratchet");
        let hk2 = HkdfSha256::new(Some(&ikm), &[]);
        let _ = hk2.expand(&lbl2, &mut send_new);

        let mut root_info = tier_label.to_vec();
        root_info.extend_from_slice(b"root");
        let hk3 = HkdfSha256::new(Some(&ikm), &[]);
        let _ = hk3.expand(&root_info, &mut new_root);

        self.root_key = RootKey(new_root);

        // Signal 规范：DH 棘轮后的链密钥从 HKDF 派生的 recv_new/send_new 来
        self.receiving = ChainState::new(recv_new, self.tier.clone());
        self.sending = ChainState::new(send_new, self.tier.clone());

        self.dh_key_pair = HybridKeyPair::generate();
        self.remote_dh_public = Some(*remote_pk);
        self.dh_ratcheted = true;
    }

    // =========================================================================
    // 加密
    // =========================================================================

    /// 加密消息
    pub fn encrypt(&mut self, plaintext: &[u8], aad: &[u8]) -> (Vec<u8>, RatchetHeader) {
        let salt_data = get_salt(&self.salt);
        let prev_chain_length = self.sending.previous_chain_length;
        let msg_num = self.sending.message_number;
        let pk = self.dh_key_pair.public_key().x25519;

        let header = RatchetHeader::new(pk, msg_num, prev_chain_length);
        let msg_key = self.sending.derive_message_key(&salt_data);
        let nonce = self.derive_nonce_send(msg_num, &salt_data);
        let cipher = AeadCipher::new(msg_key.as_bytes());
        let mut full_aad = header.serialize();
        full_aad.extend_from_slice(aad);
        let ciphertext = cipher.encrypt(&nonce, &full_aad, plaintext);

        self.sending.previous_chain_length += 1;

        (ciphertext, header)
    }

    // =========================================================================
    // 解密
    // =========================================================================

    /// 解密消息
    /// Signal 规范：先解密，失败 + peer_pk 改变才触发 DH 棘轮
    pub fn decrypt(&mut self, header: &RatchetHeader, ciphertext: &[u8], aad: &[u8]) -> Option<Vec<u8>> {
        let salt_data = get_salt(&self.salt);
        let msg_num = header.message_number;

        // 构建 full_aad（与 encrypt 保持一致：header.serialize + aad）
        let mut full_aad = header.serialize();
        full_aad.extend_from_slice(aad);

        // 先检查 skip buffer
        if let Some(key) = self.skip_buffer.get(msg_num) {
            let nonce = self.derive_nonce_recv(msg_num, &salt_data);
            let cipher = AeadCipher::new(key.as_bytes());
            return cipher.decrypt(&nonce, &full_aad, ciphertext);
        }

        // 尝试用当前 recv_chain 解密
        let pt = self.try_decrypt_with_current_chain(header, ciphertext, &full_aad, &salt_data);

        if pt.is_some() {
            return pt;
        }

        // 解密失败 + 收到新 DH 公钥 → 执行 DH 棘轮
        let peer_pk = header.public_key;

        // 如果 remote_dh_public 为 None（首次消息），先存储 peer key，不触发棘轮
        if self.remote_dh_public.is_none() {
            self.remote_dh_public = Some(peer_pk);
            return None;
        }

        // remote_dh_public 已有值且与 header 不匹配 → 触发 DH 棘轮
        let need_dh = self.remote_dh_public.as_ref().map_or(false, |prev| *prev != peer_pk);

        if need_dh {
            self.perform_dh_ratchet(&peer_pk);

            return self.try_decrypt_with_current_chain(header, ciphertext, &full_aad, &salt_data);
        }

        None
    }

    /// 用当前 recv_chain 尝试解密（不触发 DH 棘轮）
    /// aad 参数已是完整的 full_aad（header.serialize + app_aad）
    fn try_decrypt_with_current_chain(&mut self, header: &RatchetHeader,
                                      ciphertext: &[u8], aad: &[u8],
                                      salt: &[u8]) -> Option<Vec<u8>> {
        let msg_num = header.message_number;


        // Signal 对称性：Alice send-chain = Bob recv-chain，用 receiving chain
        // 跳过中间消息密钥（仅当 msg_num > receiving.message_number 时）
        if msg_num > self.receiving.message_number {
            let skip_count = msg_num - self.receiving.message_number;
            for i in 0..skip_count {
                let sn = self.receiving.message_number + i;
                // skip key 用 receiving chain（= Alice 的 sending chain，与加密方一致）
                let skip_key = self.receiving.derive_message_key(salt);
                let _ = self.skip_buffer.store(sn, skip_key);
            }
        } else if msg_num < self.receiving.message_number {
            // msg_num < receiving.message_number：消息已解密过（重复/乱序），不处理
            return None;
        }

        // 跳过逻辑已推进链至 msg_num 位置，现在派生对应消息密钥
        let msg_key = self.receiving.derive_message_key(salt);
        let nonce = self.derive_nonce_recv(msg_num, salt);
        let cipher = AeadCipher::new(msg_key.as_bytes());

        cipher.decrypt(&nonce, aad, ciphertext)
    }

    /// 从当前发送链密钥派生 Nonce
    fn derive_nonce_send(&self, msg_num: usize, salt: &[u8]) -> NonceData {
        let tier_label = self.tier.info_label().unwrap_or(b"StarCompass");
        let mut info = tier_label.to_vec();
        info.extend_from_slice(b"nonce");
        info.extend_from_slice(&msg_num.to_le_bytes());

        let mut nonce_bytes = [0u8; 12];
        let hk = HkdfSha256::new(Some(salt), &self.sending.chain_key);
        let _ = hk.expand(&info, &mut nonce_bytes);
        NonceData::from(nonce_bytes)
    }

    /// 从发送链密钥派生 Nonce（接收方解密也用此链——对称性：Alice发/Bob收共享同一send链）
    fn derive_nonce_recv(&self, msg_num: usize, salt: &[u8]) -> NonceData {
        let tier_label = self.tier.info_label().unwrap_or(b"StarCompass");
        let mut info = tier_label.to_vec();
        info.extend_from_slice(b"nonce");
        info.extend_from_slice(&msg_num.to_le_bytes());

        let mut nonce_bytes = [0u8; 12];
        // 用 receiving chain（= Alice 的 sending chain），与 derive_message_key 一致
        let hk = HkdfSha256::new(Some(salt), &self.receiving.chain_key);
        let _ = hk.expand(&info, &mut nonce_bytes);
        NonceData::from(nonce_bytes)
    }
}

// ============================================================================
// 测试
// ============================================================================

    /// 极简测试：手动派生密钥和 nonce，看解密是否工作
    #[test]
    fn test_minimal_aead() {
        use crate::crypto::aesgcm::{AeadCipher, NonceData};
        use hkdf::Hkdf;
        use sha2::Sha256;
        type HkdfSha256 = Hkdf<Sha256>;

        // 固定的 shared_secret, salt, tier_label
        let shared = [0x01u8; 32];
        let salt = vec![0u8; 40];
        let tier_label = b"StarCompass-Kan";

        // 派生 Alice 的发送链 (alice_send_chain = derive_chain(shared, "send-chain"))
        let mut send_info = tier_label.to_vec();
        send_info.extend_from_slice(b"send-chain");
        let mut alice_send_ck = [0u8; 32];
        let hk = HkdfSha256::new(Some(&salt), &shared);
        let _ = hk.expand(&send_info, &mut alice_send_ck);

        // 派生 Bob 的接收链 (bob_recv_chain = derive_chain(shared, "send-chain") = alice_send_ck)
        let bob_recv_ck = alice_send_ck;

        // Alice 派生 msg_key (msg_num=0)
        let mut alice_msg_info = tier_label.to_vec();
        alice_msg_info.extend_from_slice(&0usize.to_le_bytes());
        let mut alice_msg_key = [0u8; 32];
        let hk_a = HkdfSha256::new(Some(&salt), &alice_send_ck);
        let _ = hk_a.expand(&alice_msg_info, &mut alice_msg_key);
        // Alice step (链前进)
        let mut step_info = tier_label.to_vec();
        step_info.extend_from_slice(b"ratchet-step");
        let mut alice_send_ck_after = [0u8; 32];
        let hk_as = HkdfSha256::new(Some(&salt), &alice_send_ck);
        let _ = hk_as.expand(&step_info, &mut alice_send_ck_after);

        // Alice 派生 nonce
        let mut alice_nonce_info = tier_label.to_vec();
        alice_nonce_info.extend_from_slice(b"nonce");
        alice_nonce_info.extend_from_slice(&0usize.to_le_bytes());
        let mut alice_nonce = [0u8; 12];
        let hk_an = HkdfSha256::new(Some(&salt), &alice_send_ck);
        let _ = hk_an.expand(&alice_nonce_info, &mut alice_nonce);



        // Alice 加密（no AAD for minimal test）
        let pt = b"test";
        let cipher = AeadCipher::new(&alice_msg_key);
        let ct = cipher.encrypt(&NonceData::from(alice_nonce), &[], pt);


        // Bob derives same msg_key and nonce
        let mut bob_msg_info = tier_label.to_vec();
        bob_msg_info.extend_from_slice(&0usize.to_le_bytes());
        let mut bob_msg_key = [0u8; 32];
        let hk_b = HkdfSha256::new(Some(&salt), &bob_recv_ck);
        let _ = hk_b.expand(&bob_msg_info, &mut bob_msg_key);
        let mut bob_nonce_info = tier_label.to_vec();
        bob_nonce_info.extend_from_slice(b"nonce");
        bob_nonce_info.extend_from_slice(&0usize.to_le_bytes());
        let mut bob_nonce = [0u8; 12];
        let hk_bn = HkdfSha256::new(Some(&salt), &bob_recv_ck);
        let _ = hk_bn.expand(&bob_nonce_info, &mut bob_nonce);



        assert_eq!(alice_msg_key, bob_msg_key, "msg_keys must match");
        assert_eq!(alice_nonce, bob_nonce, "nonces must match");

        // Bob decrypts
        let bob_cipher = AeadCipher::new(&bob_msg_key);
        let pt2 = bob_cipher.decrypt(&NonceData::from(bob_nonce), &[], &ct);
        assert!(pt2.is_some(), "decrypt must succeed, got {:?}", pt2);
        assert_eq!(pt2.unwrap(), pt);
    }

    /// 模拟 main.rs self-test 的场景：shared=[u8;32], salt=Some(ThreeCaSalt零值)
    #[test]
    fn test_self_test_scenario() {
        use crate::StarCompass;
        use crate::tiers::SecurityTier;
        use crate::crypto::kyber_x25519::HybridKeyPair;

        // 生成 shared secret（32字节 X25519）
        let alice_kx = HybridKeyPair::generate();
        let bob_kx = HybridKeyPair::generate();
        let bob_pk = bob_kx.public_key();
        let x_shared = alice_kx.dh_static(&bob_pk);

        // 模拟 star.init_with_shared_secret(shared64)
        let mut shared64 = [0u8; 64];
        shared64[..32].copy_from_slice(&x_shared);
        shared64[32..].copy_from_slice(&x_shared);

        let star_tier = SecurityTier::KanWater;
        let mut star = StarCompass::new(star_tier);
        star.init_with_shared_secret(&shared64);
        let salt = star.salt().cloned();

        let ratchet_tier = match star_tier {
            SecurityTier::KanWater => RatchetTier::Kan,
            SecurityTier::XunWind => RatchetTier::Zhi,
            SecurityTier::LiFire => RatchetTier::Ren,
            SecurityTier::QianHeaven => RatchetTier::Tian,
        };

        let mut alice = DoubleRatchetSession::new_sender(x_shared, ratchet_tier.clone(), salt.clone());
        let mut bob = DoubleRatchetSession::new_receiver(x_shared, ratchet_tier.clone(), salt.clone());

        // Alice encrypts
        let sample = b"Star Compass self-test: Double Ratchet Communication";
        let (ct, hdr) = alice.encrypt(sample, &[]);

        // Bob decrypts
        let pt = bob.decrypt(&hdr, &ct, &[]);
        assert!(pt.is_some(), "Bob should decrypt Alice's message");
        assert_eq!(pt.unwrap(), sample);
    }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_ratchet() {
        let shared = [0x01u8; 32];
        let tier = RatchetTier::Kan;

        let mut alice = DoubleRatchetSession::new_sender(shared, tier.clone(), None);
        let mut bob = DoubleRatchetSession::new_receiver(shared, tier.clone(), None);

        // Alice → Bob m1
        let (ct1, hdr1) = alice.encrypt(b"Hello, Bob!", &[]);
        assert!(hdr1.public_key == alice.public_key());

        // Bob 接收
        let pt1 = bob.decrypt(&hdr1, &ct1, &[]);
        assert!(pt1.is_some(), "Bob should decrypt Alice's message");
        assert_eq!(pt1.unwrap(), b"Hello, Bob!");

        // Bob → Alice m2
        let (ct2, hdr2) = bob.encrypt(b"Hi, Alice!", &[]);

        // Alice 接收
        let pt2 = alice.decrypt(&hdr2, &ct2, &[]);
        assert!(pt2.is_some(), "Alice should decrypt Bob's reply");
        assert_eq!(pt2.unwrap(), b"Hi, Alice!");

        // Alice → Bob m3
        let (ct3, hdr3) = alice.encrypt(b"Round 3!", &[]);
        let pt3 = bob.decrypt(&hdr3, &ct3, &[]);
        assert!(pt3.is_some(), "Bob should decrypt message 3");
        assert_eq!(pt3.unwrap(), b"Round 3!");
    }

    #[test]
    fn test_multiple_ratchet_cycles() {
        let shared = [0xABu8, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89,
                       0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
                       0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                       0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00];
        let tier = RatchetTier::Zhi;

        let mut alice = DoubleRatchetSession::new_sender(shared, tier.clone(), None);
        let mut bob = DoubleRatchetSession::new_receiver(shared, tier.clone(), None);

        // 交换 5 轮
        for i in 0..5 {
            let (ct, hdr) = alice.encrypt(format!("Alice msg {}", i).as_bytes(), &[]);
            let dec = bob.decrypt(&hdr, &ct, &[]);
            assert!(dec.is_some(), "Bob should decrypt msg {}", i);
        }

        for i in 0..3 {
            let (ct, hdr) = bob.encrypt(format!("Bob msg {}", i).as_bytes(), &[]);
            let dec = alice.decrypt(&hdr, &ct, &[]);
            assert!(dec.is_some(), "Alice should decrypt msg {}", i);
        }
    }

    #[test]
    fn test_chain_keys_differ_between_parties() {
        let shared = [0x01u8; 32];
        let tier = RatchetTier::Kan;

        let alice = DoubleRatchetSession::new_sender(shared, tier.clone(), None);
        let bob = DoubleRatchetSession::new_receiver(shared, tier.clone(), None);

        // 初始链密钥方向不同
        assert_ne!(alice.sending.chain_key, alice.receiving.chain_key);
        assert_ne!(bob.sending.chain_key, bob.receiving.chain_key);
    }
}
