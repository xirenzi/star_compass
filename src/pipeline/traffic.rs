//! 流量编排器 - 拟态伪装 + 去特征化
//! 
//! - 拟态目标库：TLS / HTTP/2 / DNS 等包长分布
//! - 字节微调：包尾随机追加 0~127 字节
//! - 前缀污染：伪协议头片段

use rand::{CryptoRng, RngCore};

/// 拟态协议类型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MimicProtocol {
    TLS,        // TLS 记录层 16KB max
    HTTP2,      // HTTP/2 帧
    DNS,        // DNS 查询/响应
    WebSocket,  // WebSocket 帧
    Custom,     // 自定义分布
}

/// 包长分布参数
#[derive(Debug, Clone)]
pub struct LengthDistribution {
    pub min: usize,
    pub max: usize,
    pub buckets: Vec<(usize, usize)>, // (起始, 概率权重)
}

impl Default for LengthDistribution {
    fn default() -> Self {
        // TLS 典型记录层大小分布
        Self {
            min: 40,
            max: 16400,
            buckets: vec![
                (64, 10),      // 小包
                (128, 20),     // 短记录
                (256, 25),     // 中等
                (512, 20),     // 中长
                (1024, 15),    // 长记录
                (1400, 10),    // MTU 边界
            ],
        }
    }
}

/// 流量编排器
pub struct TrafficOrchestrator {
    protocol: MimicProtocol,
    distribution: LengthDistribution,
    padding_range: (usize, usize), // 0~127 字节
    prefix_enabled: bool,
}

impl TrafficOrchestrator {
    pub fn new(protocol: MimicProtocol) -> Self {
        let distribution = match protocol {
            MimicProtocol::TLS => LengthDistribution::default(),
            MimicProtocol::HTTP2 => LengthDistribution {
                min: 24,
                max: 16384,
                buckets: vec![
                    (24, 30),    // HEADERS 帧
                    (64, 25),    // 小帧
                    (256, 25),   // 中等
                    (1400, 20),  // 大帧
                ],
            },
            MimicProtocol::DNS => LengthDistribution {
                min: 29,
                max: 512,
                buckets: vec![
                    (29, 40),    // 标准查询
                    (64, 30),    // TXT 记录
                    (128, 20),   // 较长查询
                    (512, 10),   // EDNS
                ],
            },
            MimicProtocol::WebSocket => LengthDistribution {
                min: 2,
                max: 65535,
                buckets: vec![
                    (2, 30),     // 控制帧
                    (64, 30),    // 短消息
                    (1024, 25),  // 中等
                    (1400, 15),  // 长消息
                ],
            },
            MimicProtocol::Custom => LengthDistribution::default(),
        };

        Self {
            protocol,
            distribution,
            padding_range: (0, 127),
            prefix_enabled: true,
        }
    }

    /// 计算目标包长
    pub fn target_length<R: RngCore + CryptoRng>(&self, rng: &mut R, payload_size: usize) -> usize {
        let total = payload_size;
        
        // 填充到最近的桶
        let bucket = self.distribution.buckets.iter()
            .min_by_key(|(start, _)| {
                if total <= *start {
                    *start - total
                } else {
                    total - *start
                }
            })
            .map(|(s, _)| *s)
            .unwrap_or(self.distribution.max);
        
        // 随机微调 ±10%
        let jitter = (bucket / 10) as i32;
        let adjustment = if jitter > 0 {
            rng.gen_range(-jitter..=jitter)
        } else {
            0
        };
        
        (bucket as i32 + adjustment).max(self.distribution.min.min(total) as i32) as usize
    }

    /// 添加尾部填充
    pub fn add_padding<R: RngCore + CryptoRng>(&self, rng: &mut R, data: &mut Vec<u8>, target_len: usize) {
        if data.len() < target_len {
            let padding_len = target_len - data.len();
            let actual = rng.gen_range(padding_len.saturating_sub(64)..=padding_len.min(127));
            let fill = rng.gen_range(0..=2);
            match fill {
                0 => data.extend(vec![0x00; actual]),
                1 => data.extend(vec![0x80; actual]),
                _ => {
                    let mut pad = vec![0u8; actual];
                    rng.fill_bytes(&mut pad);
                    data.extend(pad);
                }
            }
        }
    }

    /// 添加前缀污染
    pub fn add_prefix<R: RngCore + CryptoRng>(&self, rng: &mut R, data: &mut Vec<u8>) {
        if !self.prefix_enabled {
            return;
        }

        let prefix = match self.protocol {
            MimicProtocol::TLS => {
                // TLS 记录头：ContentType(1) + Version(2) + Length(2)
                let mut p = vec![0x17, 0x03, 0x03]; // Application Data, TLS 1.2
                let len = (data.len() as u16).to_be_bytes();
                p.extend_from_slice(&len);
                p
            }
            MimicProtocol::HTTP2 => {
                // HTTP/2 帧头：Length(3) + Type(1) + Flags(1) + StreamID(4)
                let mut p = vec![0x00, 0x00, 0x01]; // Length = 1
                p.push(0x01); // HEADERS
                p.push(0x04); // END_HEADERS
                p.extend_from_slice(&0x00000001u32.to_be_bytes()); // Stream 1
                p
            }
            MimicProtocol::DNS => {
                // DNS 头部：ID(2) + Flags(2) + QDCOUNT(2)
                let mut p = vec![0x00; 6];
                rng.fill_bytes(&mut p[2..]); // 随机 flags
                p[2] = 0x01; p[3] = 0x00; // 标准查询
                p
            }
            _ => vec![],
        };

        if !prefix.is_empty() {
            data.splice(0..0, prefix);
        }
    }

    /// 剥离前缀（接收方）
    pub fn strip_prefix(&self, data: &mut Vec<u8>) {
        if data.len() < 5 {
            return;
        }

        match self.protocol {
            MimicProtocol::TLS => {
                if data[0] == 0x17 && data[1] == 0x03 && data[2] == 0x03 {
                    let len = u16::from_be_bytes([data[3], data[4]]) as usize;
                    if data.len() >= 5 + len {
                        data.drain(0..5);
                    }
                }
            }
            MimicProtocol::HTTP2 => {
                if data.len() >= 9 && (data[3] == 0x01 || data[3] == 0x00) {
                    data.drain(0..9);
                }
            }
            MimicProtocol::DNS => {
                if data.len() >= 12 {
                    data.drain(0..12);
                }
            }
            _ => {}
        }
    }

    /// 生成随机心跳包
    pub fn gen_heartbeat<R: RngCore + CryptoRng>(&self, rng: &mut R) -> Vec<u8> {
        let size = rng.gen_range(40..=1400);
        let mut data = vec![0u8; size];
        rng.fill_bytes(&mut data);
        
        // TLS 头伪装
        if self.protocol == MimicProtocol::TLS && data.len() >= 5 {
            data[0] = 0x17; // Application Data
            data[1] = 0x03;
            data[2] = 0x03;
            let len = ((data.len() - 5) as u16).to_be_bytes();
            data[3] = len[0];
            data[4] = len[1];
        }
        
        data
    }
}

/// 包调度器 - 处理乱序发送
pub struct PacketScheduler {
    reorder_queue: std::collections::VecDeque<Vec<u8>>,
    max_queue_size: usize,
}

impl PacketScheduler {
    pub fn new(max_queue: usize) -> Self {
        Self {
            reorder_queue: std::collections::VecDeque::new(),
            max_queue_size: max_queue,
        }
    }

    /// 入队（可延迟发送）
    pub fn enqueue(&mut self, packet: Vec<u8>) {
        if self.reorder_queue.len() < self.max_queue_size {
            self.reorder_queue.push_back(packet);
        }
    }

    /// 随机出队（模拟网络延迟）
    pub fn dequeue<R: RngCore + CryptoRng>(&mut self, rng: &mut R) -> Option<Vec<u8>> {
        if self.reorder_queue.is_empty() {
            return None;
        }

        let idx = rng.gen_range(0..self.reorder_queue.len());
        Some(self.reorder_queue.remove(idx).unwrap())
    }

    /// 清空队列
    pub fn flush(&mut self) -> Vec<Vec<u8>> {
        self.reorder_queue.drain(..).collect()
    }

    pub fn is_empty(&self) -> bool {
        self.reorder_queue.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_mimic() {
        let orch = TrafficOrchestrator::new(MimicProtocol::TLS);
        let mut rng = rand::thread_rng();
        
        let target = orch.target_length(&mut rng, 256);
        assert!(target >= orch.distribution.min);
        
        let mut data = vec![0x42u8; 100];
        orch.add_padding(&mut rng, &mut data, target);
        assert!(data.len() >= target);
    }

    #[test]
    fn test_prefix_strip() {
        let orch = TrafficOrchestrator::new(MimicProtocol::TLS);
        let mut data = vec![0x17, 0x03, 0x03, 0x00, 0x64, 0x42, 0x42, 0x42];
        orch.strip_prefix(&mut data);
        assert!(data.starts_with(&[0x42, 0x42, 0x42]));
    }
}
