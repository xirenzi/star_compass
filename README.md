# 星枢加密体系 (Star Compass)

> 精密校准版 · 三才合一 · Rust + Tauri

## 核心特性

- 🌌 **三才秘钥**：行星方位（天时）+ 事件哈希（地利）+ 私密八卦（人和）
- 🛡️ **四版分级**：坎水 / 巽风 / 离火 / 乾天
- ⚡ **抗量子**：X25519 + Kyber-1024 混合密钥交换
- 🔐 **深度混淆**：矩阵打乱 + Merkle锚点 + 流量拟态

## 项目结构

```
star_compass/
├── src/                    # Rust核心库
│   ├── lib.rs             # 主入口
│   ├── error.rs           # 错误类型
│   ├── tiers.rs           # 四版分级
│   ├── crypto/            # 密码学模块
│   │   ├── aesgcm.rs     # AES-256-GCM + GMAC
│   │   ├── hkdf.rs       # HKDF派生
│   │   ├── kyber_x25519.rs # 混合密钥交换
│   │   └── merkle.rs      # Merkle树
│   ├── astro/             # 天文模块
│   │   └── planets.rs     # 七曜计算 + 卦象映射
│   ├── keyring/           # 密钥环
│   │   └── mod.rs         # 双棘轮 + 三才盐
│   └── pipeline/          # 处理管道
│       ├── chunker.rs    # 分块封装
│       ├── obfuscator.rs # 矩阵混淆
│       └── traffic.rs     # 流量拟态
├── src-tauri/             # Tauri应用
│   ├── src/main.rs        # Tauri命令
│   ├── tauri.conf.json   # 应用配置
│   └── Cargo.toml
└── web/                   # 前端界面
    └── index.html
```

## 构建

### 前置依赖
- Rust 1.70+
- Node.js 18+
- npm

### 开发模式

```bash
# 安装前端依赖
cd web && npm install

# 编译Rust
cargo build --release

# 运行（开发）
cd src-tauri && cargo run
```

### 前端开发

```bash
cd web
npm install
npm run dev
```

## 安全等级

| 等级 | 符号 | 适用场景 | 功能 |
|------|------|----------|------|
| 坎水级 | ☵ | 民用 | 口令 + 3行星 |
| 巽风级 | ☴ | 小团队 | 双棘轮 + 轻量混淆 |
| 离火级 | ☲ | 小企业 | 身份隐藏 + 流量拟态 |
| 乾天级 | ☰ | 大企业 | 全组件 + HSM |

## 核心参数

- **块大小**：128字节（13B头 + 107B载荷 + 8B标签）
- **密钥派生**：HKDF-SHA256，info域分离
- **Nonce**：96位基值 XOR 64位计数器
- **行星本卦**：7曜 × 3爻 = 21位二进制

## 使用示例

```rust
use star_compass::{StarCompass, SecurityTier, GeoLocation, PlanetCalculator};
use chrono::Utc;

let mut star = StarCompass::new(SecurityTier::LiFire);

// 设置观测时间
let dt = Utc::now();
let loc = GeoLocation::new(29.5, 106.5); // 重庆

// 计算行星本卦
let calc = PlanetCalculator::new();
let bits = calc.calc_planet_hexagram(&dt);

// 初始化
star.init(dt, Some(loc), "你的私密事件", &[0x42u8; 64])?;
```

## 协议设计

```
发送管道：
明文 → AES-GCM加密 → Merkle分块 → GMAC认证 
→ 矩阵混淆 → 乱序调度 → 流量拟态 → 传输HMAC → 网络

接收管道：
传输HMAC验证 → 块GMAC验证 → 解拟态 → 解乱序 
→ 解混淆 → Merkle校验 → 解密 → 明文
```

## 许可证

MIT OR Apache-2.0

---

*⚠️ 本项目仅供学习研究使用，请遵守当地法律法规。*
