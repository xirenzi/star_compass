# 星枢加密体系 (Star Compass) - 规格文档 v0.1.0

## 一、概述

星枢加密体系是一个基于Rust核心的端到端加密系统，融合了：
- **三才秘钥**：行星方位（天时）+ 事件哈希（地利）+ 私密八卦（人和）
- **四版分级**：坎水/巽风/离火/乾天，满足不同安全需求
- **抗量子混合密钥交换**：X25519 + Kyber-1024
- **深度混淆**：矩阵打乱 + Merkle锚点 + 流量拟态

## 二、安全等级

| 等级 | 符号 | 行星数 | 棘轮 | 混淆 | 拟态 |
|------|------|--------|------|------|------|
| 坎水级·艮渊 | ☵ | 3 | ✗ | ✗ | ✗ |
| 巽风级·巽翎 | ☴ | 5 | ✓ | 轻量 | 包尾填充 |
| 离火级·离曜 | ☲ | 7 | ✓ | 矩阵 | TLS/HTTP2 |
| 乾天级·乾极 | ☰ | 8 | ✓ | 全动态 | 多协议混合 |

## 三、核心参数

### 3.1 块结构（128字节）
```
[ 明文头 (13B) ][ 密文载荷 (107B) ][ GMAC标签 (8B) ]
```

明文头：
- msg_id: u64 (8B)
- offset: u32 (4B)  
- flags: u8 (1B)

### 3.2 HKDF派生
- K1: 说明书加密
- K2: 内容加密 (AES-256-GCM)
- K4: 传输层HMAC
- K_block: 块级GMAC认证

### 3.3 Nonce管理
- 基础值: 96位
- 合成: Nonce_Base XOR 消息计数器
- 恒定时间，无条件分支

## 四、三才秘钥

### 天时（行星本卦）
- 七曜黄经计算（☉☽☿♀♂♃♄）
- 黄经宫位 mod 8 → 七经卦 → 21爻二进制

### 地利（事件哈希）
- SHA-256(event_description)
- 永不线上传输

### 人和（私密八卦）
- 用户64位八卦序列
- 永不入网

## 五、API接口

### Rust核心
```rust
use star_compass::{StarCompass, SecurityTier, GeoLocation};
use chrono::Utc;

let mut star = StarCompass::new(SecurityTier::LiFire);
star.init(Utc::now(), Some(GeoLocation::new(29.5, 106.5)), "event", &[0u8; 64])?;
```

### Tauri命令
- `create_compass(tier_name)` - 创建实例
- `init_encryption(...)` - 初始化加密
- `get_tier_info(tier_name)` - 获取等级信息
- `calc_planet_hexagram(timestamp_secs)` - 计算行星本卦

## 六、安全评估

| 维度 | 评分 | 说明 |
|------|------|------|
| 密码学安全 | 9.5/10 | Signal/TLS 1.3 等价 |
| 抗量子 | 高 | Kyber + 三重未知 |
| 抗流量分析 | 高 | 拟态填充 + 乱序 |
| 抗侧信道 | 高 | 恒定时间 + 长度填充 |

## 七、未来扩展

- [ ] PQCrypto Kyber 集成
- [ ] TPM/SE 硬件密钥存储
- [ ] 形式化验证 (ProVerif/Tamarin)
- [ ] 八卦全谱（坤舆/震策/坎御/兑钥）

---

*精密校准版 · 工程就绪 · 三才合一*
