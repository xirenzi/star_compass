//! 混淆与流量管道

use rand::{CryptoRng, RngCore, Rng};

/// 16×8 矩阵混淆器
pub struct MatrixObfuscator {
    transform: [[u8; 2]; 16],
    inv_transform: [[u8; 2]; 16],
    enabled: bool,
}

impl MatrixObfuscator {
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut transform = [[0u8; 2]; 16];
        let inv_transform;
        // 生成随机可逆 16×16 GF(2) 矩阵
        loop {
            for i in 0..16 { rng.fill_bytes(&mut transform[i]); }
            let inv = Self::compute_inverse_16x16_gf2(&transform);
            if inv != transform {
                inv_transform = inv;
                break;
            }
        }
        Self { transform, inv_transform, enabled: true }
    }

    pub fn set_enabled(&mut self, enabled: bool) { self.enabled = enabled; }

    /// GF(2) 矩阵乘法: out[i] = XOR_j (M[i][j] & in[j])
    fn mat_mul_gf2(m: &[[u8; 2]; 16], col: &[u8; 16]) -> [u8; 16] {
        let mut out = [0u8; 16];
        for i in 0..16 {
            let mut acc: u8 = 0;
            for j in 0..16 {
                if (m[i][j / 8] >> (j % 8)) & 1 != 0 {
                    acc ^= col[j];
                }
            }
            out[i] = acc;
        }
        out
    }

    /// GF(2) 16×16 矩阵求逆（高斯消元）
    fn compute_inverse_16x16_gf2(m: &[[u8; 2]; 16]) -> [[u8; 2]; 16] {
        // augmented: (matrix_row as u16, identity_row as u16)
        let mut aug: [(u16, u16); 16] = [(0, 0); 16];
        for i in 0..16 {
            let mut row = 0u16;
            for j in 0..16 {
                if (m[i][j / 8] >> (j % 8)) & 1 != 0 {
                    row |= 1 << j;
                }
            }
            aug[i] = (row, 1u16 << i);
        }

        // 高斯-若尔当消元
        for col in 0..16 {
            let pivot = match (col..16).find(|&r| (aug[r].0 >> col) & 1 == 1) {
                Some(p) => p,
                None => return *m, // 不可逆，返回原矩阵（退化情况）
            };
            aug.swap(col, pivot);
            for row in 0..16 {
                if row != col && ((aug[row].0 >> col) & 1) == 1 {
                    aug[row].0 ^= aug[col].0;
                    aug[row].1 ^= aug[col].1;
                }
            }
        }

        let mut inv = [[0u8; 2]; 16];
        for i in 0..16 {
            inv[i][0] = (aug[i].1 & 0xFF) as u8;
            inv[i][1] = ((aug[i].1 >> 8) & 0xFF) as u8;
        }
        inv
    }

    pub fn obfuscate(&self, block: &[u8; 128]) -> [u8; 128] {
        if !self.enabled { return *block; }
        let mut out = [0u8; 128];
        for col in 0..8 {
            let mut col_bits = [0u8; 16];
            for row in 0..16 { col_bits[row] = block[row * 8 + col]; }
            let out_col = Self::mat_mul_gf2(&self.transform, &col_bits);
            for row in 0..16 { out[row * 8 + col] = out_col[row]; }
        }
        out
    }

    pub fn deobfuscate(&self, block: &[u8; 128]) -> [u8; 128] {
        if !self.enabled { return *block; }
        let mut out = [0u8; 128];
        for col in 0..8 {
            let mut col_bits = [0u8; 16];
            for row in 0..16 { col_bits[row] = block[row * 8 + col]; }
            let out_col = Self::mat_mul_gf2(&self.inv_transform, &col_bits);
            for row in 0..16 { out[row * 8 + col] = out_col[row]; }
        }
        out
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MimicProtocol { TLS, HTTP2, DNS, WebSocket, Custom }

pub struct TrafficOrchestrator {
    protocol: MimicProtocol,
    prefix_enabled: bool,
}

impl TrafficOrchestrator {
    pub fn new(protocol: MimicProtocol) -> Self {
        Self { protocol, prefix_enabled: true }
    }

    pub fn add_padding<R: RngCore + CryptoRng>(&self, rng: &mut R, data: &mut Vec<u8>, target_len: usize) {
        if data.len() < target_len {
            let diff = target_len - data.len();
            let actual = diff.min(127);
            match rng.gen_range(0..3) {
                0 => data.extend(vec![0x00; actual]),
                1 => data.extend(vec![0x80; actual]),
                _ => { let mut pad = vec![0u8; actual]; rng.fill_bytes(&mut pad); data.extend(pad); }
            }
        }
    }

    pub fn add_prefix<R: RngCore + CryptoRng>(&self, _rng: &mut R, data: &mut Vec<u8>) {
        if !self.prefix_enabled { return; }
        let prefix = match self.protocol {
            MimicProtocol::TLS => { let mut p = vec![0x17, 0x03, 0x03]; p.extend_from_slice(&(data.len() as u16).to_be_bytes()); p }
            MimicProtocol::HTTP2 => vec![0x00, 0x00, 0x01, 0x01, 0x04, 0x00, 0x00, 0x00, 0x01],
            MimicProtocol::DNS => { let mut p = vec![0x00; 6]; p[2] = 0x01; p[3] = 0x00; p }
            _ => vec![],
        };
        if !prefix.is_empty() { data.splice(0..0, prefix); }
    }

    pub fn strip_prefix(&self, data: &mut Vec<u8>) {
        if data.len() < 5 { return; }
        match self.protocol {
            MimicProtocol::TLS => { if data[0] == 0x17 && data.len() >= 5 { data.drain(0..5); } }
            MimicProtocol::HTTP2 => { if data.len() >= 9 { data.drain(0..9); } }
            MimicProtocol::DNS => { if data.len() >= 12 { data.drain(0..12); } }
            _ => {}
        }
    }

    pub fn gen_heartbeat<R: RngCore + CryptoRng>(&self, rng: &mut R) -> Vec<u8> {
        let size = rng.gen_range(40..=1400);
        let mut data = vec![0u8; size];
        rng.fill_bytes(&mut data);
        if self.protocol == MimicProtocol::TLS && data.len() >= 5 {
            data[0] = 0x17; data[1] = 0x03; data[2] = 0x03;
            let len = ((data.len() - 5) as u16).to_be_bytes();
            data[3] = len[0]; data[4] = len[1];
        }
        data
    }
}

pub struct PacketScheduler {
    queue: std::collections::VecDeque<Vec<u8>>,
    max_size: usize,
}

impl PacketScheduler {
    pub fn new(max_size: usize) -> Self { Self { queue: std::collections::VecDeque::new(), max_size } }
    pub fn enqueue(&mut self, packet: Vec<u8>) { if self.queue.len() < self.max_size { self.queue.push_back(packet); } }
    pub fn dequeue<R: RngCore + CryptoRng>(&mut self, rng: &mut R) -> Option<Vec<u8>> {
        if self.queue.is_empty() { return None; }
        Some(self.queue.remove(rng.gen_range(0..self.queue.len())).unwrap())
    }
    pub fn flush(&mut self) -> Vec<Vec<u8>> { self.queue.drain(..).collect() }
    pub fn is_empty(&self) -> bool { self.queue.is_empty() }
}

pub struct Chunker { auth_key: [u8; 32] }

impl Chunker {
    pub fn new(block_key: &[u8; 32]) -> Self { Self { auth_key: *block_key } }

    pub fn chunk(&self, msg_id: u64, payload: &[u8]) -> Vec<[u8; 128]> {
        use crate::crypto::BlockAuth;
        let auth = BlockAuth::new(&self.auth_key);
        let mut blocks = Vec::new();
        let mut offset = 0u32;

        for chunk in payload.chunks(107) {
            let mut pl = [0u8; 107];
            pl[..chunk.len()].copy_from_slice(chunk);
            let mut header = [0u8; 13];
            header[..8].copy_from_slice(&msg_id.to_le_bytes());
            header[8..12].copy_from_slice(&offset.to_le_bytes());
            header[12] = 0x01;
            let mut data_for_auth = Vec::with_capacity(120);
            data_for_auth.extend_from_slice(&header);
            data_for_auth.extend_from_slice(&pl);
            let tag = auth.compute_tag(&data_for_auth);
            let mut block = [0u8; 128];
            block[..13].copy_from_slice(&header);
            block[13..120].copy_from_slice(&pl);
            block[120..128].copy_from_slice(&tag);
            blocks.push(block);
            offset += chunk.len() as u32;
        }
        blocks
    }
}

#[derive(Clone)]
pub struct Block {
    pub msg_id: u64,
    pub offset: u32,
    pub flags: u8,
    pub payload: [u8; 107],
    pub tag: [u8; 8],
}

impl Block {
    pub fn from_bytes(data: &[u8; 128]) -> Self {
        let msg_id = u64::from_le_bytes(data[..8].try_into().unwrap());
        let offset = u32::from_le_bytes(data[8..12].try_into().unwrap());
        let flags = data[12];
        let mut payload = [0u8; 107];
        payload.copy_from_slice(&data[13..120]);
        let mut tag = [0u8; 8];
        tag.copy_from_slice(&data[120..128]);
        Block { msg_id, offset, flags, payload, tag }
    }
}

pub struct ManifestBlock {
    pub msg_id: u64,
    pub total_blocks: u32,
    pub nonce: [u8; 12],
    pub merkle_root: [u8; 32],
    pub tier: u8,
}

impl ManifestBlock {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(65);
        v.extend_from_slice(&self.msg_id.to_le_bytes());
        v.extend_from_slice(&self.total_blocks.to_le_bytes());
        v.extend_from_slice(&self.nonce);
        v.extend_from_slice(&self.merkle_root);
        v.push(self.tier);
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chunker() {
        let key = [0x42u8; 32];
        let c = Chunker::new(&key);
        let blocks = c.chunk(123, b"Hello");
        assert!(!blocks.is_empty());
    }

    #[test]
    fn test_matrix_obfuscate_changes() {
        let mut rng = rand::thread_rng();
        let obf = MatrixObfuscator::generate(&mut rng);
        let input = [0x42u8; 128];
        let out = obf.obfuscate(&input);
        assert_ne!(out, input);
    }

    #[test]
    fn test_matrix_roundtrip() {
        let mut rng = rand::thread_rng();
        let obf = MatrixObfuscator::generate(&mut rng);
        let input = [0x42u8; 128];
        let obfuscated = obf.obfuscate(&input);
        let deobfuscated = obf.deobfuscate(&obfuscated);
        assert_eq!(input, deobfuscated, "deobfuscate(obfuscate(x)) != x");
    }

    #[test]
    fn test_matrix_roundtrip_random() {
        let mut rng = rand::thread_rng();
        let obf = MatrixObfuscator::generate(&mut rng);
        let mut input = [0u8; 128];
        rng.fill_bytes(&mut input);
        let obfuscated = obf.obfuscate(&input);
        let deobfuscated = obf.deobfuscate(&obfuscated);
        assert_eq!(input, deobfuscated, "deobfuscate(obfuscate(random)) != random");
    }
}
