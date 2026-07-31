//! 分块封装 - 原子块处理管道
//! 
//! - 原子块大小：128 字节（SIMD 友好）
//! - 块结构：明文头(13B) + 密文载荷(107B) + 块标签(8B)
//! - 明文头：msg_id(8B) || offset(4B) || flags(1B)
//! - 块标签：K_block GMAC

use crate::crypto::{AeadCipher, BlockAuth, NonceData, GMAC_TAG_SIZE};
use crate::error::CryptoError;
use rand::{CryptoRng, RngCore};

/// 块标志
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BlockFlag {
    Data = 0x01,       // 普通数据块
    Manifest = 0x02,   // 说明书块
    Padding = 0x04,    // 填充伪块
    Heartbeat = 0x08,  // 心跳块
}

/// 原子块结构（128 字节）
/// 
/// ```
/// [ 明文头 (13B) ][ 密文载荷 (107B) ][ 块标签 (8B) ]
/// ```
/// 
/// 明文头：
/// ```
/// [ msg_id: u64 (8B) ][ offset: u32 (4B) ][ flags: u8 (1B) ]
/// ```
#[derive(Clone)]
pub struct Block {
    pub msg_id: u64,
    pub offset: u32,
    pub flags: BlockFlag,
    pub payload: [u8; 107], // 密文载荷
    pub tag: [u8; 8],      // K_block GMAC
}

impl Block {
    /// 打包为 128 字节
    pub fn serialize(&self) -> [u8; 128] {
        let mut buf = [0u8; 128];
        buf[..8].copy_from_slice(&self.msg_id.to_le_bytes());
        buf[8..12].copy_from_slice(&self.offset.to_le_bytes());
        buf[12] = self.flags as u8;
        buf[13..120].copy_from_slice(&self.payload);
        buf[120..128].copy_from_slice(&self.tag);
        buf
    }

    /// 从 128 字节解包
    pub fn deserialize(data: &[u8; 128]) -> Self {
        let msg_id = u64::from_le_bytes(data[..8].try_into().unwrap());
        let offset = u32::from_le_bytes(data[8..12].try_into().unwrap());
        let flags = match data[12] & 0x0F {
            0x01 => BlockFlag::Data,
            0x02 => BlockFlag::Manifest,
            0x04 => BlockFlag::Padding,
            0x08 => BlockFlag::Heartbeat,
            _ => BlockFlag::Data,
        };
        let mut payload = [0u8; 107];
        payload.copy_from_slice(&data[13..120]);
        let mut tag = [0u8; 8];
        tag.copy_from_slice(&data[120..128]);
        Block { msg_id, offset, flags, payload, tag }
    }
}

/// 分块器
pub struct Chunker {
    block_auth: BlockAuth,
}

impl Chunker {
    pub fn new(block_key: &[u8; 32]) -> Self {
        Self {
            block_auth: BlockAuth::new(block_key),
        }
    }

    /// 将密文分块封装
    /// 
    /// 输入：密文数据
    /// 输出：Block 列表
    pub fn chunk(&self, msg_id: u64, plaintext: &[u8]) -> Vec<Block> {
        let mut blocks = Vec::new();
        let mut offset = 0u32;

        // 按 107 字节切分
        for chunk in plaintext.chunks(107) {
            let mut payload = [0u8; 107];
            let len = chunk.len();
            payload[..len].copy_from_slice(chunk);

            // 计算块标签：对 明文头 || 密文载荷 计算 GMAC
            let mut header = [0u8; 13];
            header[..8].copy_from_slice(&msg_id.to_le_bytes());
            header[8..12].copy_from_slice(&offset.to_le_bytes());
            header[12] = BlockFlag::Data as u8;

            let mut data_for_auth = Vec::with_capacity(13 + 107);
            data_for_auth.extend_from_slice(&header);
            data_for_auth.extend_from_slice(&payload);
            let tag = self.block_auth.compute_tag(&data_for_auth);

            blocks.push(Block {
                msg_id,
                offset,
                flags: BlockFlag::Data,
                payload,
                tag,
            });

            offset += len as u32;
        }

        blocks
    }

    /// 验证并重组块
    pub fn reassemble(&self, blocks: Vec<Block>) -> Result<Vec<u8>, CryptoError> {
        let mut payload = Vec::new();
        
        // 排序
        let mut sorted: Vec<_> = blocks.into_iter()
            .filter(|b| b.flags != BlockFlag::Padding) // 丢弃填充块
            .collect();
        sorted.sort_by_key(|b| b.offset);

        for block in sorted {
            // 验证块标签
            let mut header = [0u8; 13];
            header[..8].copy_from_slice(&block.msg_id.to_le_bytes());
            header[8..12].copy_from_slice(&block.offset.to_le_bytes());
            header[12] = block.flags as u8;

            let mut data_for_auth = Vec::with_capacity(13 + 107);
            data_for_auth.extend_from_slice(&header);
            data_for_auth.extend_from_slice(&block.payload);

            if !self.block_auth.verify_tag(&data_for_auth, &block.tag) {
                return Err(CryptoError::BlockTagVerificationFailed);
            }

            // 找到有效载荷末尾（非零）
            let payload_end = block.payload.iter().rposition(|&x| x != 0).map(|p| p + 1).unwrap_or(0);
            payload.extend_from_slice(&block.payload[..payload_end]);
        }

        Ok(payload)
    }

    /// 生成填充伪块
    pub fn gen_padding_block<R: RngCore + CryptoRng>(&self, rng: &mut R) -> Block {
        let mut payload = [0u8; 107];
        rng.fill_bytes(&mut payload);

        let mut header = [0u8; 13];
        header[12] = BlockFlag::Padding as u8;

        let mut data_for_auth = Vec::with_capacity(120);
        data_for_auth.extend_from_slice(&header);
        data_for_auth.extend_from_slice(&payload);
        let tag = self.block_auth.compute_tag(&data_for_auth);

        Block {
            msg_id: 0,
            offset: 0,
            flags: BlockFlag::Padding,
            payload,
            tag,
        }
    }
}

/// 说明书块
pub struct ManifestBlock {
    pub msg_id: u64,
    pub total_blocks: u32,
    pub nonce: [u8; 12],
    pub merkle_root: [u8; 32],
    pub tier: u8,
    pub timestamp: u64,
}

impl ManifestBlock {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(8 + 4 + 12 + 32 + 1 + 8);
        v.extend_from_slice(&self.msg_id.to_le_bytes());
        v.extend_from_slice(&self.total_blocks.to_le_bytes());
        v.extend_from_slice(&self.nonce);
        v.extend_from_slice(&self.merkle_root);
        v.push(self.tier);
        v.extend_from_slice(&self.timestamp.to_le_bytes());
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chunk_reassemble() {
        let key = [0x42u8; 32];
        let chunker = Chunker::new(&key);
        
        let msg_id = 12345;
        let plaintext = b"Hello, Star Compass! This is a test message for the chunker.".to_vec();
        
        let blocks = chunker.chunk(msg_id, &plaintext);
        assert!(!blocks.is_empty());
        
        // 序列化/反序列化
        let serialized: Vec<[u8; 128]> = blocks.iter().map(|b| b.serialize()).collect();
        let deserialized: Vec<Block> = serialized.iter().map(|d| Block::deserialize(d)).collect();
        
        let result = chunker.reassemble(deserialized).unwrap();
        assert_eq!(result, plaintext);
    }
}
