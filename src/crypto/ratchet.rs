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
use std::collections::BTreeMap;

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
    pub fn new_receiver(shared_secret: [u8; 32], tier: RatchetTier, salt: Option<ThreeCaSalt>) -> Self {
        let salt_data = get_salt(&salt);

        let recv_chain = derive_chain(&shared_secret, b"send-chain", &tier, &salt_data);
        let send_chain = derive_chain(&shared_secret, b"recv-chain", &tier, &salt_data);

        Self {
            root_key: RootKey(shared_secret),
            sending: ChainState::new(send_chain, tier.clone()),
            receiving: ChainState::new(recv_chain, tier.clone()),
            dh_key_pair: HybridKeyPair::generate(),
            remote_dh_public: None,
            skip_buffer: SkipBuffer::new(tier.max_skip()),
            tier,
            salt,
            dh_ratcheted: false,
        }
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

        // 先检查 skip buffer
        if let Some(key) = self.skip_buffer.get(msg_num) {
            let nonce = self.derive_nonce_recv(msg_num, &salt_data);
            let cipher = AeadCipher::new(key.as_bytes());
            let mut full_aad = header.serialize();
            full_aad.extend_from_slice(aad);
            return cipher.decrypt(&nonce, &full_aad, ciphertext);
        }

        // 尝试用当前 recv_chain 解密
        let pt = self.try_decrypt_with_current_chain(header, ciphertext, aad, &salt_data);

        if pt.is_some() {
            return pt;
        }

        // 解密失败 + 收到新 DH 公钥 → 执行 DH 棘轮
        let peer_pk = header.public_key;
        let need_dh = self.remote_dh_public.map_or(true, |prev| prev != peer_pk);

        if need_dh {
            self.perform_dh_ratchet(&peer_pk);
            return self.try_decrypt_with_current_chain(header, ciphertext, aad, &salt_data);
        }

        None
    }

    /// 用当前 recv_chain 尝试解密（不触发 DH 棘轮）
    fn try_decrypt_with_current_chain(&mut self, header: &RatchetHeader,
                                      ciphertext: &[u8], aad: &[u8],
                                      salt: &[u8]) -> Option<Vec<u8>> {
        let msg_num = header.message_number;

        // 跳过中间消息密钥
        if msg_num > self.receiving.message_number {
            let skip_count = msg_num - self.receiving.message_number;
            for i in 0..skip_count {
                let sn = self.receiving.message_number + i;
                let skip_key = self.receiving.derive_message_key(salt);
                let _ = self.skip_buffer.store(sn, skip_key);
            }
        }

        let msg_key = self.receiving.derive_message_key(salt);
        let nonce = self.derive_nonce_recv(msg_num, salt);
        let cipher = AeadCipher::new(msg_key.as_bytes());
        let mut full_aad = header.serialize();
        full_aad.extend_from_slice(aad);

        cipher.decrypt(&nonce, &full_aad, ciphertext)
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

    /// 从当前接收链密钥派生 Nonce
    fn derive_nonce_recv(&self, msg_num: usize, salt: &[u8]) -> NonceData {
        let tier_label = self.tier.info_label().unwrap_or(b"StarCompass");
        let mut info = tier_label.to_vec();
        info.extend_from_slice(b"nonce");
        info.extend_from_slice(&msg_num.to_le_bytes());

        let mut nonce_bytes = [0u8; 12];
        let hk = HkdfSha256::new(Some(salt), &self.receiving.chain_key);
        let _ = hk.expand(&info, &mut nonce_bytes);
        NonceData::from(nonce_bytes)
    }
}

// ============================================================================
// 测试
// ============================================================================

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
