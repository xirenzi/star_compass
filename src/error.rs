//! 统一错误类型

use thiserror::Error;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("密钥长度不匹配：期望 {expected} 字节，得到 {actual}")]
    KeyLengthMismatch { expected: usize, actual: usize },

    #[error("加密失败：{0}")]
    EncryptionFailed(String),

    #[error("解密失败：认证标签验证失败")]
    DecryptionFailed,

    #[error("HMAC 验证失败")]
    HmacVerificationFailed,

    #[error("GMAC 块标签验证失败")]
    BlockTagVerificationFailed,

    #[error("密钥派生失败：{0}")]
    KeyDerivationFailed(String),

    #[error("行星计算失败：{0}")]
    PlanetCalculationFailed(String),

    #[error("三才盐合成失败：{0}")]
    SaltSynthesisFailed(String),

    #[error("Merkle 树验证失败")]
    MerkleVerificationFailed,

    #[error("棘轮状态错误：{0}")]
    RatchetStateError(String),

    #[error("分块错误：{0}")]
    ChunkingError(String),

    #[error("混淆/反混淆失败：{0}")]
    ObfuscationFailed(String),

    #[error("握手协议错误：{0}")]
    HandshakeError(String),

    #[error("传输层错误：{0}")]
    TransportError(String),

    #[error("无效参数：{0}")]
    InvalidParameter(String),

    #[error("未知等级：{0}")]
    UnknownTier(String),
}

#[derive(Error, Debug)]
pub enum SystemError {
    #[error("IO 错误：{0}")]
    Io(#[from] std::io::Error),

    #[error("序列化错误：{0}")]
    Serialization(String),

    #[error("Tauri 命令错误：{0}")]
    TauriCommand(String),

    #[error("前端通信错误：{0}")]
    FrontendComm(String),
}
