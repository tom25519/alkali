//! Subkey derivation from a high-entropy key.
//!
//! This module corresponds to the [`crypto_kdf` API](https://doc.libsodium.org/key_derivation)
//! from Sodium.
//!
//! Key derivation is used to derive multiple subkeys from a single high-entropy key. This is often
//! useful if you need to derive a key of some specific format from a key obtained via key exchange.
//! With this API, up to `(2^64) - 1` subkeys can be derived from a given [`Key`]. The key
//! derivation is a one-way function: it should not be feasible to calculate the original key given
//! just a subkey.
//!
//! Subkeys derived via this algorithm must be at least [`SUBKEY_LENGTH_MIN`] bytes, and can be up
//! to [`SUBKEY_LENGTH_MAX`] bytes.
//!
//! # Algorithm Details
//! The [BLAKE2b](https://www.blake2.net/) hash function is used here with an empty message, a salt
//! of `subkey_id` (padded with zeroes), a personalisation value of `ctx` (padded with zeroes), and
//! the key set to the original key from which subkeys are to be derived:
//!
//! ```text
//! BLAKE2B-subkeylen(key=key, message={}, salt=subkey_id || {0}, personal=ctx || {0})
//! ```
//!
//! # Security Considerations
//! ## Secret Data
//! * Keys ([`Key`]) from which subkeys are derived must be kept secret. Exposure of a [`Key`] will
//!   allow an attacker to compute any subkey
//!
//! ## Non-Secret Data
//! * The `context` parameter to the [`derive_subkey`] function is not sensitive, and has no entropy
//!   requirements
//!
//! # Examples
//! This example shows the derivation of a few subkeys from one original key. Use of the same
//! context + subkey ID produces the same subkey, but varying these parameters produces a different
//! subkey:
//!
//! ```rust
//! use alkali::hash::kdf;
//!
//! // Randomly generate an original key from which subkeys can be derived.
//! let original_key = kdf::Key::generate().unwrap();
//!
//! let mut subkey_a = [0u8; 32];
//! let mut subkey_b = [0u8; 32];
//! let mut subkey_c = [0u8; 32];
//! let mut subkey_d = [0u8; 32];
//!
//! // Generate two subkeys with the same ID + context, and demonstrate that they are equal.
//! kdf::derive_subkey(&original_key, "Context!", 1, &mut subkey_a).unwrap();
//! kdf::derive_subkey(&original_key, "Context!", 1, &mut subkey_b).unwrap();
//! assert_eq!(subkey_a, subkey_b);
//!
//! // Using a different subkey ID will produce a different key.
//! kdf::derive_subkey(&original_key, "Context!", 2, &mut subkey_c).unwrap();
//! assert_ne!(subkey_a, subkey_c);
//!
//! // Using a different context will also (very likely) produce a different key.
//! kdf::derive_subkey(&original_key, "Example?", 1, &mut subkey_d).unwrap();
//! assert_ne!(subkey_a, subkey_d);
//! ```

use thiserror::Error;

/// Error type returned if something went wrong in the KDF module.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum KDFError {
    /// The provided context is of the incorrect length: It must be [`CONTEXT_LENGTH`] bytes.
    #[error("context length is incorrect")]
    ContextLengthIncorrect,

    /// The requested subkey size is too short or too long for use with this algorithm.
    ///
    /// The derived subkey size must be at least [`SUBKEY_LENGTH_MIN`] bytes, and at most
    /// [`SUBKEY_LENGTH_MAX`] bytes.
    #[error("subkey length outside acceptable range")]
    SubkeyLengthInvalid,
}

/// Key derivation based on the [BLAKE2b](https://www.blake2.net) hash function.
pub mod blake2b {
    use super::KDFError;
    use crate::{assert_not_err, hardened_buffer, require_init, AlkaliError};
    use libsodium_sys as sodium;
    use std::ffi::CString;

    /// The length of an original key from which subkeys will be derived, in bytes.
    pub const KEY_LENGTH: usize = sodium::crypto_kdf_blake2b_KEYBYTES as usize;

    /// The length of a context string for subkey derivation, in bytes.
    pub const CONTEXT_LENGTH: usize = sodium::crypto_kdf_blake2b_CONTEXTBYTES as usize;

    /// The minimum subkey length which can be derived using this API, in bytes.
    pub const SUBKEY_LENGTH_MIN: usize = sodium::crypto_kdf_blake2b_BYTES_MIN as usize;

    /// The maximum subkey length which can be derived using this API, in bytes.
    pub const SUBKEY_LENGTH_MAX: usize = sodium::crypto_kdf_blake2b_BYTES_MAX as usize;

    hardened_buffer! {
        /// An original secret key from which subkeys can be derived.
        ///
        /// There are no *technical* constraints on the contents of a key, but it should be
        /// indistinguishable from random noise. A random key can be securely generated via
        /// [`Key::generate`].
        ///
        /// A secret key must not be made public.
        ///
        /// This is a [hardened buffer type](https://docs.rs/alkali#hardened-buffer-types), and will
        /// be zeroed on drop. A number of other security measures are taken to protect its
        /// contents. This type in particular can be thought of as roughly equivalent to a `[u8;
        /// KEY_LENGTH]`, and implements [`std::ops::Deref`], so it can be used like it is an
        /// `&[u8]`. This struct uses heap memory while in scope, allocated using Sodium's [secure
        /// memory utilities](https://doc.libsodium.org/memory_management).
        Key(KEY_LENGTH);
    }

    impl Key {
        /// Generate a new, random key from which subkeys can be derived.
        pub fn generate() -> Result<Self, AlkaliError> {
            require_init()?;

            let mut key = Self::new_empty()?;
            unsafe {
                // SAFETY: This function expects a pointer to a region of memory sufficient to
                // store a key. The `Key` type allocates `crypto_kdf_KEYBYTES`, the length of a key
                // for this algorithm. It is therefore valid for writes of the required length. The
                // `Key::inner_mut` method simply returns a mutable pointer to the struct's backing
                // memory.
                sodium::crypto_kdf_keygen(key.inner_mut() as *mut libc::c_uchar);
            }
            Ok(key)
        }
    }

    /// Derive a subkey from `key`.
    ///
    /// `key` should be the original key from which the subkey is to be derived. The subkey will be
    /// written to `subkey`, which must be between [`SUBKEY_LENGTH_MIN`] and [`SUBKEY_LENGTH_MAX`]
    /// bytes.
    ///
    /// `context` is an identifier used to prevent key reuse across different domains. It does not
    /// need to be kept secret, nor does it have any entropy requirements, but it must be
    /// [`CONTEXT_LENGTH`] = 8 bytes long. For example, it could be set to something like
    /// `"UserName"`, `"__auth__"`, `"pictures"`, `"userdata"`, etc. A different context will
    /// produce different subkeys from the same original key.
    ///
    /// `subkey_id` is a numeric ID for this subkey. Using the same ID with the same original key
    /// and context will produce the same subkey. This can just be set to a counter value,
    /// incrementing for each subkey you need. So `1` would produce the first subkey, `2` the
    /// second, and so on.
    pub fn derive_subkey(
        key: &Key,
        context: &str,
        subkey_id: u64,
        subkey: &mut [u8],
    ) -> Result<(), AlkaliError> {
        require_init()?;

        let context = CString::new(context).unwrap();

        if context.as_bytes().len() != CONTEXT_LENGTH {
            return Err(KDFError::ContextLengthIncorrect.into());
        } else if subkey.len() < SUBKEY_LENGTH_MIN || subkey.len() > SUBKEY_LENGTH_MAX {
            return Err(KDFError::SubkeyLengthInvalid.into());
        }

        let context_ptr = context.into_raw();

        let derive_result = unsafe {
            // SAFETY: The first argument to this function is the destination to which the derived
            // subkey will be written, and the second argument is the number of bytes which should
            // be written to this destination. We use `subkey.len()` to specify the number of bytes
            // to write, so `subkey` is definitely valid for writes of this length. The next
            // argument is the subkey ID, which can be any 64-bit integer. The next argument is the
            // context to use for the subkey derivation, which must be an C-style string (which does
            // not need to be null terminated) of length `crypto_kdf_CONTEXTBYTES`. We construct
            // `context_ptr` by initialising a CString from the user-specified context, and
            // verifying its binary representation (without null character) is indeed
            // `crypto_kdf_CONTEXTBYTES`. `context_ptr` is the result of calling `CString::into_raw`
            // on this context, which will produce a pointer to a valid C representation of the
            // string. The final argument should be a pointer to the key from which the subkey
            // should be derived. The `Key` type allocates `crypto_kdf_KEYBYTES`, the length of a
            // key for this algorithm, so `key` is valid for reads of the required length. The
            // `Key::inner` method simply returns an immutable pointer to its backing memory.
            sodium::crypto_kdf_blake2b_derive_from_key(
                subkey.as_mut_ptr(),
                subkey.len(),
                subkey_id,
                context_ptr,
                key.inner() as *const libc::c_uchar,
            )
        };

        // Make sure we free the context string's memory
        let _context = unsafe {
            // SAFETY: The `context_ptr` pointer was created using `CString::into_raw`, and has not
            // yet been freed, so it is safe to use it to initialise a `CString`.
            CString::from_raw(context_ptr)
        };

        assert_not_err!(derive_result, "crypto_kdf_blake2b_derive_from_key");

        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::{derive_subkey, Key, SUBKEY_LENGTH_MAX, SUBKEY_LENGTH_MIN};
        use crate::AlkaliError;

        #[test]
        fn key_generation() -> Result<(), AlkaliError> {
            let _key = Key::generate()?;
            Ok(())
        }

        #[test]
        fn test_vectors_fixed_len() -> Result<(), AlkaliError> {
            let mut key = Key::new_empty()?;
            key.copy_from_slice(&[
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
                0x1c, 0x1d, 0x1e, 0x1f,
            ]);
            let mut subkey = [0u8; SUBKEY_LENGTH_MAX];
            let expected = [
                [
                    0xa0, 0xc7, 0x24, 0x40, 0x47, 0x28, 0xc8, 0xbb, 0x95, 0xe5, 0x43, 0x3e, 0xb6,
                    0xa9, 0x71, 0x61, 0x71, 0x14, 0x4d, 0x61, 0xef, 0xb2, 0x3e, 0x74, 0xb8, 0x73,
                    0xfc, 0xbe, 0xda, 0x51, 0xd8, 0x07, 0x1b, 0x5d, 0x70, 0xaa, 0xe1, 0x20, 0x66,
                    0xdf, 0xc9, 0x4c, 0xe9, 0x43, 0xf1, 0x45, 0xaa, 0x17, 0x6c, 0x05, 0x50, 0x40,
                    0xc3, 0xdd, 0x73, 0xb0, 0xa1, 0x5e, 0x36, 0x25, 0x4d, 0x45, 0x06, 0x14,
                ],
                [
                    0x02, 0x50, 0x7f, 0x14, 0x4f, 0xa9, 0xbf, 0x19, 0x01, 0x0b, 0xf7, 0xc7, 0x0b,
                    0x23, 0x5b, 0x4c, 0x26, 0x63, 0xcc, 0x00, 0xe0, 0x74, 0xf9, 0x29, 0x60, 0x2a,
                    0x5e, 0x2c, 0x10, 0xa7, 0x80, 0x75, 0x7d, 0x2a, 0x39, 0x93, 0xd0, 0x6d, 0xeb,
                    0xc3, 0x78, 0xa9, 0x0e, 0xfd, 0xac, 0x19, 0x6d, 0xd8, 0x41, 0x81, 0x7b, 0x97,
                    0x7d, 0x67, 0xb7, 0x86, 0x80, 0x4f, 0x6d, 0x3c, 0xd5, 0x85, 0xba, 0xb5,
                ],
                [
                    0x19, 0x44, 0xda, 0x61, 0xff, 0x18, 0xdc, 0x20, 0x28, 0xc3, 0x57, 0x8a, 0xc8,
                    0x5b, 0xe9, 0x04, 0x93, 0x1b, 0x83, 0x86, 0x08, 0x96, 0x59, 0x8f, 0x62, 0x46,
                    0x8f, 0x1c, 0xb5, 0x47, 0x1c, 0x6a, 0x34, 0x4c, 0x94, 0x5d, 0xbc, 0x62, 0xc9,
                    0xaa, 0xf7, 0x0f, 0xeb, 0x62, 0x47, 0x2d, 0x17, 0x77, 0x5e, 0xa5, 0xdb, 0x6e,
                    0xd5, 0x49, 0x4c, 0x68, 0xb7, 0xa9, 0xa5, 0x97, 0x61, 0xf3, 0x96, 0x14,
                ],
                [
                    0x13, 0x1c, 0x0c, 0xa1, 0x63, 0x3e, 0xd0, 0x74, 0x98, 0x62, 0x15, 0xb2, 0x64,
                    0xf6, 0xe0, 0x47, 0x4f, 0x36, 0x2c, 0x52, 0xb0, 0x29, 0xef, 0xfc, 0x7b, 0x0f,
                    0x75, 0x97, 0x7e, 0xe8, 0x9c, 0xc9, 0x5d, 0x85, 0xc3, 0xdb, 0x87, 0xf7, 0xe3,
                    0x99, 0x19, 0x7a, 0x25, 0x41, 0x15, 0x92, 0xbe, 0xee, 0xb7, 0xe5, 0x12, 0x8a,
                    0x74, 0x64, 0x6a, 0x46, 0x0e, 0xcd, 0x6d, 0xeb, 0x49, 0x94, 0xb7, 0x1e,
                ],
                [
                    0xa7, 0x02, 0x3a, 0x0b, 0xf9, 0xbe, 0x24, 0x5d, 0x07, 0x8a, 0xed, 0x26, 0xbc,
                    0xde, 0x04, 0x65, 0xff, 0x0c, 0xc0, 0x96, 0x11, 0x96, 0xa5, 0x48, 0x2a, 0x0f,
                    0xf4, 0xff, 0x8b, 0x40, 0x15, 0x97, 0x1e, 0x13, 0x61, 0x1f, 0x50, 0x52, 0x9c,
                    0xb4, 0x08, 0xf5, 0x77, 0x6b, 0x14, 0xa9, 0x0e, 0x7c, 0x3d, 0xd9, 0x16, 0x0a,
                    0x22, 0x21, 0x1d, 0xb6, 0x4f, 0xf4, 0xb5, 0xc0, 0xb9, 0x95, 0x36, 0x80,
                ],
                [
                    0x50, 0xf4, 0x93, 0x13, 0xf3, 0xa0, 0x5b, 0x2e, 0x56, 0x5c, 0x13, 0xfe, 0xed,
                    0xb4, 0x4d, 0xaa, 0x67, 0x5c, 0xaf, 0xd4, 0x2c, 0x2b, 0x2c, 0xf9, 0xed, 0xbc,
                    0xe9, 0xc9, 0x49, 0xfb, 0xfc, 0x3f, 0x17, 0x5d, 0xcb, 0x73, 0x86, 0x71, 0x50,
                    0x9a, 0xe2, 0xea, 0x66, 0xfb, 0x85, 0xe5, 0x52, 0x39, 0x4d, 0x47, 0x9a, 0xfa,
                    0x7f, 0xa3, 0xaf, 0xfe, 0x87, 0x91, 0x74, 0x47, 0x96, 0xb9, 0x41, 0x76,
                ],
                [
                    0x13, 0xb5, 0x8d, 0x6d, 0x69, 0x78, 0x00, 0x89, 0x29, 0x38, 0x62, 0xcd, 0x59,
                    0xa1, 0xa8, 0xa4, 0xef, 0x79, 0xbb, 0x85, 0x0e, 0x3f, 0x3b, 0xa4, 0x1f, 0xb2,
                    0x24, 0x46, 0xa7, 0xdd, 0x1d, 0xc4, 0xda, 0x46, 0x67, 0xd3, 0x7b, 0x33, 0xbf,
                    0x12, 0x25, 0xdc, 0xf8, 0x17, 0x3c, 0x4c, 0x34, 0x9a, 0x5d, 0x91, 0x1c, 0x5b,
                    0xd2, 0xdb, 0x9c, 0x59, 0x05, 0xed, 0x70, 0xc1, 0x1e, 0x80, 0x9e, 0x3b,
                ],
                [
                    0x15, 0xd4, 0x4b, 0x4b, 0x44, 0xff, 0xa0, 0x06, 0xee, 0xce, 0xeb, 0x50, 0x8c,
                    0x98, 0xa9, 0x70, 0xaa, 0xa5, 0x73, 0xd6, 0x59, 0x05, 0x68, 0x7b, 0x9e, 0x15,
                    0x85, 0x4d, 0xec, 0x6d, 0x49, 0xc6, 0x12, 0x75, 0x7e, 0x14, 0x9f, 0x78, 0x26,
                    0x8f, 0x72, 0x76, 0x60, 0xde, 0xdf, 0x9a, 0xbc, 0xe2, 0x2a, 0x96, 0x91, 0xfe,
                    0xb2, 0x0a, 0x01, 0xb0, 0x52, 0x5f, 0x4b, 0x47, 0xa3, 0xcf, 0x19, 0xdb,
                ],
                [
                    0x9a, 0xeb, 0xba, 0x11, 0xc5, 0x42, 0x8a, 0xe8, 0x22, 0x57, 0x16, 0x36, 0x9e,
                    0x30, 0xa4, 0x89, 0x43, 0xbe, 0x39, 0x15, 0x9a, 0x89, 0x9f, 0x80, 0x4e, 0x99,
                    0x63, 0xef, 0x78, 0x82, 0x2e, 0x18, 0x6c, 0x21, 0xfe, 0x95, 0xbb, 0x0b, 0x85,
                    0xe6, 0x0e, 0xf0, 0x3a, 0x6f, 0x58, 0xd0, 0xb9, 0xd0, 0x6e, 0x91, 0xf7, 0x9d,
                    0x0a, 0xb9, 0x98, 0x45, 0x0b, 0x88, 0x10, 0xc7, 0x3c, 0xa9, 0x35, 0xb4,
                ],
                [
                    0x70, 0xf9, 0xb8, 0x3e, 0x46, 0x3f, 0xb4, 0x41, 0xe7, 0xa4, 0xc4, 0x32, 0x75,
                    0x12, 0x5c, 0xd5, 0xb1, 0x9d, 0x8e, 0x2e, 0x4a, 0x5d, 0x17, 0x9a, 0x39, 0xf5,
                    0xdb, 0x10, 0xbb, 0xce, 0x74, 0x5a, 0x19, 0x91, 0x04, 0x56, 0x3d, 0x30, 0x8c,
                    0xf8, 0xd4, 0xc6, 0xb2, 0x7b, 0xbb, 0x75, 0x9d, 0xed, 0x23, 0x2f, 0x5b, 0xdb,
                    0x7c, 0x36, 0x7d, 0xd6, 0x32, 0xa9, 0x67, 0x73, 0x20, 0xdf, 0xe4, 0x16,
                ],
            ];

            for (i, exp) in expected.iter().enumerate() {
                derive_subkey(&key, "KDF test", i as u64, &mut subkey)?;
                assert_eq!(&subkey, exp);
            }

            Ok(())
        }

        #[test]
        fn test_vectors_variable_len() -> Result<(), AlkaliError> {
            let mut key = Key::new_empty()?;
            key.copy_from_slice(&[
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
                0x1c, 0x1d, 0x1e, 0x1f,
            ]);
            let mut subkey = [0u8; SUBKEY_LENGTH_MAX + 1];
            let expected = [
                (15, &[][..]),
                (
                    16,
                    &[
                        0xa5, 0x29, 0x21, 0x66, 0x24, 0xef, 0x91, 0x61, 0xe4, 0xcf, 0x11, 0x72,
                        0x72, 0xaa, 0xff, 0xf2,
                    ][..],
                ),
                (
                    17,
                    &[
                        0x06, 0x8b, 0xd6, 0x94, 0x0b, 0x80, 0xc6, 0xcc, 0x25, 0x30, 0xa6, 0x8c,
                        0x31, 0xd9, 0xf4, 0xe3, 0x23,
                    ][..],
                ),
                (
                    31,
                    &[
                        0xd6, 0x56, 0x5b, 0xd3, 0x26, 0x5b, 0x63, 0x73, 0xf4, 0xf6, 0xa6, 0xb6,
                        0x45, 0x8e, 0x98, 0x10, 0x06, 0xda, 0x5e, 0x9d, 0x53, 0x2c, 0xe9, 0x4c,
                        0xa4, 0x73, 0x7e, 0x18, 0x89, 0x95, 0xe9,
                    ][..],
                ),
                (
                    32,
                    &[
                        0x15, 0x4b, 0x29, 0x1f, 0x11, 0x19, 0x67, 0x37, 0xf8, 0xb7, 0xf4, 0x91,
                        0xe4, 0xca, 0x11, 0x76, 0x4e, 0x02, 0x27, 0xd3, 0x4f, 0x94, 0x29, 0x54,
                        0x08, 0xa8, 0x69, 0xf0, 0x07, 0xaa, 0x86, 0x18,
                    ][..],
                ),
                (
                    33,
                    &[
                        0xe9, 0xdd, 0x39, 0x55, 0x70, 0xe0, 0x9e, 0xbb, 0x52, 0x3f, 0xfc, 0x6b,
                        0xa0, 0x98, 0xa3, 0x8b, 0x17, 0xbc, 0x49, 0x44, 0xf1, 0x4b, 0xd3, 0x72,
                        0x5b, 0xdd, 0x7e, 0xdb, 0xd8, 0xbc, 0xff, 0x54, 0xfb,
                    ][..],
                ),
                (
                    64,
                    &[
                        0x06, 0xae, 0x14, 0x30, 0x8e, 0xee, 0xda, 0x62, 0xa0, 0x0c, 0xb6, 0xd5,
                        0xed, 0xf1, 0x8d, 0x17, 0x07, 0x02, 0x95, 0x15, 0xdb, 0x98, 0xf4, 0x72,
                        0xbb, 0xf0, 0x61, 0x74, 0x19, 0x30, 0x1b, 0x1d, 0x4f, 0x4f, 0x2a, 0xb6,
                        0x58, 0x49, 0x44, 0x6b, 0xe4, 0x6f, 0x87, 0xe1, 0xd3, 0x1c, 0x6c, 0x74,
                        0x28, 0x38, 0x97, 0xb9, 0x97, 0x6f, 0x70, 0xd8, 0xa1, 0x62, 0x53, 0xac,
                        0x92, 0x7e, 0x0d, 0x9f,
                    ][..],
                ),
                (65, &[][..]),
            ];

            for v in expected {
                if v.0 < SUBKEY_LENGTH_MIN || v.0 > SUBKEY_LENGTH_MAX {
                    assert!(
                        derive_subkey(&key, "KDF test", v.0 as u64, &mut subkey[..v.0]).is_err()
                    );
                    continue;
                }

                derive_subkey(&key, "KDF test", v.0 as u64, &mut subkey[..v.0])?;
                assert_eq!(&subkey[..v.0], v.1);
            }

            Ok(())
        }
    }
}

pub use blake2b::*;
