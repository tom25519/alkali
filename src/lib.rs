//! **Please note**: This is currently a work-in-progress, and isn't yet complete, nor is it
//! suitable for production usage.
//!
//! Safe, idiomatic Rust bindings to the [Sodium](https://libsodium.org) cryptographic library.
//!
//! Sodium is a fast, modern cryptographic library written in C. This crate intends to provide a
//! higher-level API for making use of the cryptographic constructions Sodium provides. These
//! constructions include simple-to-use symmetric and asymmetric authenticated encryption,
//! signatures, hashing, password derivation, and key exchange: In short, the majority of
//! operations required for many modern cryptographic protocols.
//!
//! The intention for this library is to be a spiritual successor to
//! [sodiumoxide](https://github.com/sodiumoxide/sodiumoxide), which is now deprecated. Lots of
//! design decisions here were inspired by this library, so thanks to all of its contributors!
//!
//! # Which API Should I Use?
//! The cryptographic operations in this crate are mostly split into two main modules:
//! [`symmetric`] and [`asymmetric`]. Symmetric (sometimes called secret-key) operations use a
//! single secret key, shared between every party to a communication. In asymmetric (public-key)
//! operations, every party has their own secret key, used to derive a public-key which is shared
//! with all other parties. Parties need to know each others' public keys to communicate.
//!
//! There are also hashing algorithms available in the [`hash`] module, and tools for generating
//! unpredictable (random) data in the [`random`] module.
//!
//! <!-- big ugly table -->
//! | Alkali API | Corresponding Sodium API | Purpose |
//! | ---------- | ------------------------ | ------- |
//! | [`asymmetric::cipher`] | [`crypto_box`](https://doc.libsodium.org/public-key_cryptography/authenticated_encryption) | Encrypt a message for a specific party, so only you + they can decrypt it |
//! | [`asymmetric::kx`] | [`crypto_kx`](https://doc.libsodium.org/key_exchange) | Establish a secret key with another party over an insecure channel |
//! | [`asymmetric::sign`] | [`crypto_sign`](https://doc.libsodium.org/public-key_cryptography/public-key_signatures) | Sign a message, so that anyone can verify you sent it |
//! | [`asymmetric::seal`] | [`crypto_box_seal`](https://doc.libsodium.org/public-key_cryptography/sealed_boxes) | Anonymously encrypt a message for a specific party, so only they can decrypt it |
//! | [`hash::generic`] | [`crypto_generichash`](https://doc.libsodium.org/hashing/generic_hashing) | Calculate the "fingerprint" of a file or message |
//! | [`hash::kdf`] | [`crypto_kdf`](https://doc.libsodium.org/key_derivation) | Derive multiple subkeys from a single high-entropy key |
//! | [`hash::pbkdf`] | [`crypto_pwhash`](https://doc.libsodium.org/password_hashing/default_phf) | Store a user's password to verify their identity at a later time, or derive a cryptographic key from a password |
//! | [`hash::short`] | [`crypto_shorthash`](https://doc.libsodium.org/hashing/short-input_hashing) | Calculate a hash for use in a hash table/bloom filter/etc. |
//! | [`symmetric::auth`] | [`crypto_auth`](https://doc.libsodium.org/secret-key_cryptography/secret-key_authentication) | Produce an authentication tag for a message which can be verified by trusted parties with whom you share a secret key |
//! | [`symmetric::cipher`] | [`crypto_secretbox`](https://doc.libsodium.org/secret-key_cryptography/secretbox) | Encrypt a message so that trusted parties, with whom you share a secret key, can decrypt it |
//! | [`symmetric::cipher_stream`] | [`crypto_secretstream`](https://doc.libsodium.org/secret-key_cryptography/secretstream) | Encrypt a sequence of messages, or an arbitrarily-long data stream |
//! | [`random`] | [`randombytes`](https://doc.libsodium.org/generating_random_data) | Generate unpredictable data suitable for cryptographic use |
//!
//! # Build Options
//! On non-Windows platforms, by default Sodium is compiled from source as part of alkali's build
//! process (on Windows, pre-compiled binaries are downloaded). This build process can be customised
//! via features and environment variables.
//!
//! * Sodium is compiled from source included in the [libsodium-sys-stable
//!   crate](https://github.com/jedisct1/libsodium-sys-stable), maintained by Frank Denis, who is
//!   also the maintainer of Sodium itself. This source may be out of date compared to the latest
//!   stable release, so alternatively, the library can be built from the latest stable downloaded
//!   from [download.libsodium.org](https://download.libsodium.org/) by enabling the `fetch-latest`
//!   feature.
//! * Deprecated and uncommon APIs can be disabled using the `minimal` feature. Any APIs or
//!   algorithms which will be disabled by enabling minimal builds will be marked as such in this
//!   documentation.
//! * Sodium can be built with optimisations for the current platform by enabling the `optimized`
//!   feature.
//! * [Position-Independent Code](https://en.wikipedia.org/wiki/Position-independent_code) can be
//!   disabled for Sodium's build by setting the `SODIUM_DISABLE_PIE` environment variable.
//!
//! Rather than building Sodium from source, you can also link to an existing shared/static build of
//! Sodium on your system. The `use-pkg-config` feature will use
//! [pkg-config](https://www.freedesktop.org/wiki/Software/pkg-config/) to find libsodium.
//! Alternatively, you can set the `SODIUM_LIB_DIR` environment variable to specify the location of
//! libsodium on your system. Sodium will be statically linked by default, but you can set
//! `SODIUM_SHARED` to dynamically link the library.
//!
//! # Hardened Buffer Types
//! Throughout this crate, a number of types used to store secret data (keys, seeds, etc.) use a
//! custom allocator from Sodium to manage their memory. They can be used like standard array/slice
//! types, as they implement [`std::ops::Deref`], [`AsRef`], etc., so anywhere where you might be
//! able to use a `&[u8]`, a hardened buffer can also be used. The benefit to using these structs
//! over just using normal arrays/vectors is that they have a number of protections implemented
//! intended to prevent leakage of their contents via side channels.
//!
//! When these hardened buffer types are dropped, their memory is securely zeroed, so that secrets
//! cannot later be recovered from uninitialised memory. This operation is done in such a way that
//! the compiler will not remove it during optimisation. Memory for these types is allocated at the
//! end of a page, immediately followed by a guard page, so any buffer overflow should be
//! immediately detected and prevented. A canary is also placed before the allocated memory region
//! to detect potential overflows, and another guard page is placed before the canary. The entire
//! region is "locked", which advises the operating system not to swap it to disk if it would
//! normally do so, and not to include the memory contents in crash reports/core dumps.
//!
//! Custom hardened types can be created using the [`hardened_buffer`] macro, or the [`anon_buffer`]
//! macro to produce an anonymous array-like buffer backed by hardened memory.
//!
//! In the future, we should be able to use the [Allocator
//! API](https://doc.rust-lang.org/std/alloc/trait.Allocator.html) to simplify these types, but for
//! the time being, we have to do a fair amount of manual memory management under the hood to
//! enable them to work. Regardless, these implementation details do not require you to do anything
//! differently yourself.
//!
//! # The `hazmat` Feature
//! Sodium is generally intended to be difficult to misuse, but some constructions are inherently
//! more prone to misuse/misunderstanding than others, and more care is required to use them
//! securely. As an example, for the [`crypto_onetimeauth`
//! API](https://doc.libsodium.org/advanced/poly1305), using a given key to authenticate more than
//! one message can result in an attacker recovering the key.
//!
//! In alkali, these modules are feature-gated behind the `hazmat` feature, and will not be
//! available unless it is enabled. This can be done from `Cargo.toml`, and is just intended as an
//! extra step to confirm, "Yes, I know what I am doing is error-prone, and I have thoroughly read
//! the accompanying documentation":
//!
//! ```toml
//! alkali = { version = "0.1", features = ["hazmat"] }
//! ```

#![cfg_attr(doc_cfg, feature(doc_cfg))]
#![cfg_attr(feature = "alloc", feature(allocator_api))]
#![cfg_attr(feature = "alloc", feature(nonnull_slice_from_raw_parts))]

use libsodium_sys as sodium;
use thiserror::Error;

pub mod asymmetric;
pub mod encode;
pub mod hash;
pub mod mem;
pub mod random;
pub mod symmetric;
pub mod util;

/// General error type used in alkali.
///
/// This type is returned by functions which can possibly fail throughout alkali.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum AlkaliError {
    /// Failed to initialise Sodium.
    ///
    /// This corresponds to a call to `sodium_init` returning -1, indicating initialisation
    /// failure. In such a case, Sodium is unsafe to use.
    #[error("failed to initialise libsodium")]
    SodiumInitFailed,

    /// Memory management error.
    ///
    /// This could indicate a number of possible issues. In the worst case, it indicates a buffer
    /// overflow or similar error occurred and was detected by Sodium, but it could also indicate
    /// any other reason secure memory allocation may fail. Sodium's allocator is less likely to
    /// succeed in general than the standard operating system allocator, since there are limits
    /// placed on how much memory can be locked, etc.
    #[error("memory management error")]
    MemoryManagement,

    /// Tried to create a hardened buffer from an incorrectly sized slice.
    #[error("incorrect slice length")]
    IncorrectSliceLength,

    /// The slices supplied to [`util::add_le`], [`util::sub_le`], or [`util::compare_le`] differ
    /// in length.
    #[error("numbers differ in length")]
    NumberLengthsDiffer,

    /// Could not add padding to the provided buffer.
    ///
    /// This should only occur if `blocksize` was set to zero.
    #[error("failed to pad the provided buffer")]
    PaddingError,

    /// Could not calculate the unpadded buffer size.
    ///
    /// This can occur if `blocksize` was set to zero, or if `buf` does not appear to be correctly
    /// padded.
    #[error("failed to unpad the provided buffer")]
    UnpaddingError,

    /// Failed to decode the provided hex/base64 string.
    ///
    /// This could occur if the string contains invalid characters which were not marked to be
    /// ignored, or if the output was insufficient to store the decoded bytes.
    #[error("could not decode provided hex/base64")]
    DecodeError,

    /// An error occurred in the [`asymmetric::cipher`] module.
    #[error("asymmetric cipher error")]
    AsymmetricCipherError(#[from] asymmetric::cipher::CipherError),

    /// An error occurred in the [`asymmetric::kx`] module.
    #[error("key exchange error")]
    KeyExchangeError(#[from] asymmetric::kx::KeyExchangeError),

    /// An error occurred in the [`asymmetric::seal`] module.
    #[error("seal error")]
    SealError(#[from] asymmetric::seal::SealError),

    /// An error occurred in the [`asymmetric::sign`] module.
    #[error("signing error")]
    SignError(#[from] asymmetric::sign::SignError),

    /// An error occurred in the [`hash::generic`] module.
    #[error("hash error")]
    GenericHashError(#[from] hash::generic::GenericHashError),

    /// An error occurred in the [`hash::kdf`] module.
    #[error("KDF error")]
    KDFError(#[from] hash::kdf::KDFError),

    /// An error occurred in the [`hash::pbkdf`] module.
    #[error("PBKDF error")]
    PasswordHashError(#[from] hash::pbkdf::PasswordHashError),

    /// An error occurred in the [`random`] module.
    #[error("PRNG error")]
    RandomError(#[from] random::RandomError),

    #[error("symmetric AEAD error")]
    AEADError(#[from] symmetric::aead::AEADError),

    /// An error occurred in the [`symmetric::auth`] module.
    #[error("authentication error")]
    AuthError(#[from] symmetric::auth::AuthError),

    /// An error occurred in the [`symmetric::cipher`] module.
    #[error("symmetric cipher error")]
    SymmetricCipherError(#[from] symmetric::cipher::CipherError),

    /// An error occurred in the [`symmetric::cipher_stream`] module.
    #[error("symmetric cipher stream error")]
    CipherStreamError(#[from] symmetric::cipher_stream::CipherStreamError),

    /// An error occurred in the [`symmetric::one_time_auth`] module.
    #[cfg(feature = "onetimeauth")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "hazmat")))]
    #[error("one-time authentication error")]
    OneTimeAuthError(#[from] symmetric::one_time_auth::OneTimeAuthError),
}

/// Used where Sodium returns an error which we didn't expect.
///
/// This indicates the implementation has changed, and is now fallible where it previously always
/// succeeded, so we need to handle the error individually.
macro_rules! unexpected_err {
    ($source:expr) => {
        panic!(
            "An unexpected error occurred in `{}`. Please report this bug to \
            https://github.com/tom25519/alkali/issues.",
            $source
        )
    };
}

pub(crate) use unexpected_err;

/// Assert than `$result` is not a C-style indicator of error (i.e: ensure it is equal to zero).
///
/// Calls `unexpected_err!($source)` if an error did occur.
macro_rules! assert_not_err {
    ($result:expr, $source:expr) => {
        if $result != 0 {
            $crate::unexpected_err!($source);
        }
    };
}

pub(crate) use assert_not_err;

/// Attempt to initialise Sodium.
///
/// n.b: Crates making use of alkali do not have to call this function, it is only used internally
/// wherever initialisation may be necessary.
///
/// This function should be called in any scenario where a function from Sodium will be used
/// internally. Returns `Ok(0)` if Sodium was initialised successfully, `Ok(1)` if Sodium has
/// already been initialised, or [`AlkaliError::SodiumInitFailed`] if the initialisation was
/// unsuccessful.
#[doc(hidden)]
pub fn require_init() -> Result<libc::c_int, AlkaliError> {
    let init_status = unsafe {
        // SAFETY: This function can safely be called multiple times from multiple threads. Once it
        // has been called, all other Sodium functions are also thread-safe.
        sodium::sodium_init()
    };

    // sodium_init() returns -1 on init failure, 0 on success, or 1 if Sodium is already
    // initialised
    if init_status < 0 {
        return Err(AlkaliError::SodiumInitFailed);
    }

    Ok(init_status)
}

#[cfg(test)]
mod tests {
    use super::{require_init, AlkaliError};

    #[test]
    fn can_initialise() -> Result<(), AlkaliError> {
        require_init().map(|_| ())
    }
}
