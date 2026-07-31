//! 密码学核心模块

pub mod aesgcm;
pub mod hkdf;
pub mod kyber_x25519;
pub mod merkle;
pub mod ratchet;

pub use aesgcm::{AeadCipher, BlockAuth, HmacTransport, NonceData};
pub use hkdf::KeyDeriver;
pub use kyber_x25519::{HybridKeyExchange, X25519KeyPair, KyberKeyPair, Ed25519KeyPair};
pub use merkle::{MerkleProof, MerkleTree, LeafNode};

pub const BLOCK_SIZE: usize = 128;
pub const PAYLOAD_SIZE: usize = 107;
pub const GMAC_TAG_SIZE: usize = 8;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
