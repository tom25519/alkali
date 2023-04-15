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
//! `SODIUM_SHARED` to dynamically link the library. Note that alkali is built assuming that it is
//! linked against Sodium 1.0.18 stable.
//!
//! Support for `no_std` environments can be enabled by disabling the `std` feature. Note that some
//! APIs will be disabled: Those which require `std` support are marked as such in the
//! documentation.
//!
//! [Serde](https://serde.rs) support can be enabled using the `use-serde` feature (enabled by
//! default).
//!
//! # Hardened Buffer Types
//! Throughout this crate, a number of types used to store secret data (keys, seeds, etc.) use a
//! custom allocator from Sodium to manage their memory. They can be used like standard array/slice
//! types, as they implement [`core::ops::Deref`], [`AsRef`], etc., so anywhere where you might be
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
//! API](https://doc.rust-lang.org/core/alloc/trait.Allocator.html) to simplify these types, but for
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

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(doc_cfg, feature(doc_cfg))]
#![cfg_attr(feature = "alloc", feature(allocator_api))]
#![deny(clippy::all)]
#![deny(clippy::pedantic)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::manual_let_else)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]

// Hidden re-exports used in macros
#[doc(hidden)]
pub use libc;
#[doc(hidden)]
pub use libsodium_sys;
#[doc(hidden)]
#[cfg(feature = "use-serde")]
pub use serde;

pub mod asymmetric;
#[cfg(feature = "curve")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "hazmat")))]
pub mod curve;
#[cfg(feature = "std")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "std")))]
pub mod encode;
pub mod hash;
pub mod mem;
pub mod random;
pub mod symmetric;
pub mod util;

pub use libsodium_sys::{
    SODIUM_LIBRARY_VERSION_MAJOR, SODIUM_LIBRARY_VERSION_MINOR, SODIUM_VERSION_STRING,
};

/// Implements the `AlkaliError` enum.
macro_rules! define_alkali_error {
    (
        $(
            basic
            $(#[$basicmeta:meta])*
            $basicvar:ident,
        )*
        $(
            compound
            $(#[$meta:meta])*
            $var:ident($source:path),
        )*
        $(
            gated($feat:expr, $show:expr)
            $(#[$gatedmeta:meta])*
            $gatedvar:ident($gatedsource:path),
        )*
    ) => {
        /// General error type used in alkali.
        ///
        /// This type is returned by functions which can possibly fail throughout alkali.
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        pub enum AlkaliError {
            $(
                $(#[$basicmeta])*
                $basicvar,
            )*
            $(
                $(#[$meta])*
                $var($source),
            )*
            $(
                $(#[$gatedmeta])*
                #[cfg(feature = $feat)]
                #[cfg_attr(doc_cfg, doc(cfg(feature = $show)))]
                $gatedvar($gatedsource),
            )*
        }

        #[cfg(feature = "std")]
        impl std::error::Error for AlkaliError {}

        impl core::fmt::Display for AlkaliError {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                match self {
                    $(
                        Self::$basicvar => {
                            f.write_str("AlkaliError::")?;
                            f.write_str(stringify!($basicvar))
                        }
                    )*
                    $(
                        Self::$var(source) => {
                            f.write_str("AlkaliError::")?;
                            f.write_str(stringify!($var))?;
                            f.write_str("(")?;
                            source.fmt(f)?;
                            f.write_str(")")
                        }
                    )*
                    $(
                        #[cfg(feature = $feat)]
                        Self::$gatedvar(source) => {
                            f.write_str("AlkaliError::")?;
                            f.write_str(stringify!($gatedvar))?;
                            f.write_str("(")?;
                            source.fmt(f)?;
                            f.write_str(")")
                        }
                    )*
                }
            }
        }
    }
}

define_alkali_error! {
    basic
    /// Failed to initialise Sodium.
    ///
    /// This corresponds to a call to `sodium_init` returning -1, indicating initialisation failure.
    /// In such a case, Sodium is unsafe to use.
    SodiumInitFailed,

    basic
    /// Memory management error.
    ///
    /// This could indicate a number of possible issues. In the worst case, it indicates a buffer
    /// overflow or similar error occurred and was detected by Sodium, but it could also indicate
    /// any other reason secure memory allocation may fail. Sodium's allocator is less likely to
    /// succeed in general than the standard operating system allocator, since there are limits
    /// placed on how much memory can be locked, etc.
    MemoryManagement,

    basic
    /// Failed to protect a region of memory.
    ///
    /// This will result from calling `into_readonly` or `into_noaccess` on a hardened buffer type.
    /// This can occur if the current platform does not support `mprotect`/`VirtualProtect`, or if
    /// an internal error occurred in the underlying `mprotect`/`VirtualProtect` call.
    MprotectFailed,

    basic
    /// Tried to create a hardened buffer from an incorrectly sized slice.
    IncorrectSliceLength,

    basic
    /// The slices supplied to [`util::add_le`], [`util::sub_le`], or [`util::compare_le`] differ
    /// in length.
    NumberLengthsDiffer,

    basic
    /// Could not add padding to the provided buffer.
    ///
    /// This should only occur if `blocksize` was set to zero.
    PaddingError,

    basic
    /// Could not calculate the unpadded buffer size.
    ///
    /// This can occur if `blocksize` was set to zero, or if `buf` does not appear to be correctly
    /// padded.
    UnpaddingError,

    basic
    /// Failed to decode the provided hex/base64 string.
    ///
    /// This could occur if the string contains invalid characters which were not marked to be
    /// ignored, or if the output was insufficient to store the decoded bytes.
    DecodeError,

    compound
    /// An error occurred in the [`asymmetric::cipher`] module.
    AsymmetricCipherError(asymmetric::cipher::AsymmetricCipherError),

    compound
    /// An error occurred in the [`asymmetric::kx`] module.
    KeyExchangeError(asymmetric::kx::KeyExchangeError),

    compound
    /// An error occurred in the [`asymmetric::seal`] module.
    SealError(asymmetric::seal::SealError),

    compound
    /// An error occurred in the [`asymmetric::sign`] module.
    SignError(asymmetric::sign::SignError),

    compound
    /// An error occurred in the [`hash::generic`] module.
    GenericHashError(hash::generic::GenericHashError),

    compound
    /// An error occurred in the [`hash::pbkdf`] module.
    PasswordHashError(hash::pbkdf::PasswordHashError),

    compound
    /// An error occurred in the [`random`] module.
    RandomError(random::RandomError),

    compound
    /// An error occurred in the [`symmetric::aead`] module.
    AEADError(symmetric::aead::AEADError),

    compound
    /// An error occurred in the [`symmetric::auth`] module.
    AuthError(symmetric::auth::AuthError),

    compound
    /// An error occurred in the [`symmetric::cipher`] module.
    SymmetricCipherError(symmetric::cipher::SymmetricCipherError),

    compound
    /// An error occurred in the [`symmetric::cipher_stream`] module.
    CipherStreamError(symmetric::cipher_stream::CipherStreamError),

    gated("curve", "hazmat")
    /// An error occurred in the [`curve`] module.
    CurveError(curve::CurveError),

    gated("std", "std")
    /// An error occurred in the [`hash::kdf`] module.
    KDFError(hash::kdf::KDFError),

    gated("onetimeauth", "hazmat")
    /// An error occurred in the [`symmetric::one_time_auth`] module.
    OneTimeAuthError(symmetric::one_time_auth::OneTimeAuthError),

    gated("stream", "hazmat")
    /// An error occurred in the [`symmetric::stream`] module.
    StreamCipherError(symmetric::stream::StreamCipherError),
}

/// Implement an error enum.
macro_rules! error_type {
    (
        $(#[$tymeta:meta])*
        $name:ident {
            $(
                $(#[$varmeta:meta])*
                $varname:ident,
            )*
        }
    ) => {
        $(#[$tymeta])*
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        pub enum $name {
            $(
                $(#[$varmeta])*
                $varname,
            )*
        }

        #[cfg(feature = "std")]
        impl std::error::Error for $name {}

        impl core::fmt::Display for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                match self {
                    $(
                        Self::$varname => {
                            f.write_str(stringify!($name))?;
                            f.write_str("::")?;
                            f.write_str(stringify!($varname))
                        }
                    )*
                }
            }
        }

        impl From<$name> for $crate::AlkaliError {
            fn from(e: $name) -> Self {
                Self::$name(e)
            }
        }
    }
}

pub(crate) use error_type;

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
        libsodium_sys::sodium_init()
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
