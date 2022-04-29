//! Symmetric (secret-key) cryptographic operations.

pub mod aead;
pub mod auth;
pub mod cipher;
pub mod cipher_stream;
#[cfg(feature = "onetimeauth")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "hazmat")))]
pub mod one_time_auth;
#[cfg(feature = "stream")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "hazmat")))]
pub mod stream;
