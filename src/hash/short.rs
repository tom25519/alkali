//! Short-input/output hash function for hash-based data structures.
//!
//! This module corresponds to the [`crypto_shorthash`
//! API](https://doc.libsodium.org/hashing/short-input_hashing) from Sodium.
//!
//! This is a fast, keyed hash function, intended for use in hash-based data structures such as hash
//! tables and bloom filters. This specifically addresses a class of Denial of Service (DOS) attacks
//! which exploit predictable collisions in many hash functions which would previously have been
//! used for this task. In hash tables for example, if many keys hash to the same value, the
//! computational complexity of all operations increases. An attacker can easily find cause the
//! insertion of many keys which hash to the same value, they can cause greatly increased load
//! compared to normal operation.
//!
//! The hash function in this API resists this attack as it uses a secret key in the hash
//! calculation. While the short output of the hash means it is not collision-resistant, as long as
//! an attacker does not know the key, they should not be able to find collisions any faster than
//! brute-force search.
//!
//! The hash function in this module is optimised for small input sizes.
//!
//! # Algorithm Details
//! [SipHash-2-4](siphash24) ([SipHash](https://en.wikipedia.org/wiki/SipHash) with 2 rounds per
//! message block and 4 finalisation rounds) is the default algorithm used in this API.
//! [SiphashX-2-4](siphashx24), which has a longer output size, is also available.
//!
//! # Security Considerations
//! This hash function is not suitable as a general-purpose hash function due to the short output
//! size. Instead consider using [`hash::generic`](super::generic).
//!
//! ## Secret Data
//! * The [`Key`] used with this hash function must be kept secret. If an attacker knows the key,
//!   this function provides no defense against DOS attacks.
//!
//! ## Non-Secret Data
//! * The output of the hash function (the [`Digest`]) is not secret. It is not possible to find the
//!   key from the output.
//!
//! # Examples
//! ```rust
//! use alkali::hash::short;
//!
//! let message = b"Here's some message we wish to hash :)";
//!
//! let key_a = short::Key::generate().unwrap();
//! let hash_a = short::hash(message, &key_a).unwrap();
//! let key_b = key_a.try_clone().unwrap();
//! let hash_b = short::hash(message, &key_b).unwrap();
//! assert_eq!(hash_a, hash_b);
//!
//! let key_c = short::Key::generate().unwrap();
//! let hash_c = short::hash(message, &key_c).unwrap();
//! assert_ne!(hash_a, hash_c);
//! ```

/// Implements the API for a `short` module
macro_rules! short_module {
    (
        $digest_len:expr,   // crypto_shorthash_BYTES
        $key_len:expr,      // crypto_shorthash_KEYBYTES
        $shorthash:path,    // crypto_shorthash
    ) => {
        use $crate::{assert_not_err, hardened_buffer, random, require_init, AlkaliError};
        /// The length of a key for this hash function, in bytes.
        pub const KEY_LENGTH: usize = $key_len as usize;

        /// The output size of this hash function, in bytes.
        pub const DIGEST_LENGTH: usize = $digest_len as usize;

        hardened_buffer! {
            /// Secret key used to secure the hash function.
            ///
            /// There are no *technical* constraints on the contents of a key, but it should be
            /// indistinguishable from random noise. A random key can be securely generated using
            /// [`Key::generate`].
            ///
            /// A secret key should not be made public.
            ///
            /// This is a [hardened buffer type](https://docs.rs/alkali#hardened-buffer-types), and
            /// will be zeroed on drop. A number of other security measures are taken to protect
            /// its contents. This type in particular can be thought of as roughly equivalent to a
            /// `[u8; KEY_LENGTH]`, and implements [`std::ops::Deref`], so it can be used like it is
            /// an `&[u8]`. This struct uses heap memory while in scope, allocated using Sodium's
            /// [secure memory utilities](https://doc.libsodium.org/memory_management).
            Key(KEY_LENGTH);
        }

        impl Key {
            /// Generate a new, random key for use with this hash.
            pub fn generate() -> Result<Self, AlkaliError> {
                let mut key = Self::new_empty()?;
                random::fill_random(&mut key[..])?;
                Ok(key)
            }
        }

        /// The output of the hash function.
        pub type Digest = [u8; DIGEST_LENGTH];

        /// Calculate the hash of the provided message, using the provided key as part of the hash
        /// calculation.
        ///
        /// This function returns the hash of the given message, dependent on the provided `key`.
        /// The same `(message, key)` combination will always produce the same hash. A different
        /// key will produce a different hash for the same message.
        pub fn hash(message: &[u8], key: &Key) -> Result<Digest, AlkaliError> {
            require_init()?;

            let mut digest = [0u8; DIGEST_LENGTH];

            let hash_result = unsafe {
                // SAFETY: The first argument to this function is the destination to which the
                // digest, of length `crypto_shorthash_BYTES`, will be written. We have defined the
                // `digest` array to be `crypto_shorthash_BYTES` bytes in length, so it is valid for
                // writes of the required length. The next two arguments specify a pointer to the
                // message to hash, and the message length. We use `message.len()` to specify the
                // length of the message, so `message` is definitely valid for reads of the required
                // length. The final argument is a pointer to the key. The `Key` type is defined to
                // allocate `crypto_shorthash_KEYBYTES`, the length of a key for this algorithm, so
                // `key` is valid for reads of the required length. The `Key::inner` method simply
                // returns a pointer to its backing memory.
                $shorthash(
                    digest.as_mut_ptr(),
                    message.as_ptr(),
                    message.len() as libc::c_ulonglong,
                    key.inner() as *const libc::c_uchar,
                )
            };
            assert_not_err!(hash_result, stringify!($shorthash));

            Ok(digest)
        }
    };
}

/// Generates tests for a `short` implementation.
#[allow(unused_macros)]
macro_rules! short_module_tests {
    ( $( {
        msg:  $msg:expr,
        key:  $key:expr,
        hash: $hash:expr,
    }, )* ) => {
        use $crate::AlkaliError;

        #[test]
        fn key_generation() -> Result<(), AlkaliError> {
            let _key = super::Key::generate()?;
            Ok(())
        }

        #[test]
        fn test_vectors() -> Result<(), AlkaliError> {
            let mut key = super::Key::new_empty()?;

            $(
                key.copy_from_slice(&$key);

                let actual_hash = super::hash(&$msg, &key)?;
                assert_eq!(&actual_hash, &$hash);
            )*

            Ok(())
        }
    };
}

/// The SipHash-2-4 hash function.
pub mod siphash24 {
    use libsodium_sys as sodium;

    short_module! {
        sodium::crypto_shorthash_siphash24_BYTES,
        sodium::crypto_shorthash_siphash24_KEYBYTES,
        sodium::crypto_shorthash_siphash24,
    }

    #[cfg(test)]
    mod tests {
        short_module_tests! [
            {
                msg:  [],
                key:  [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                       0x0d, 0x0e, 0x0f],
                hash: [0x31, 0x0e, 0x0e, 0xdd, 0x47, 0xdb, 0x6f, 0x72],
            },
            {
                msg:  [0x00],
                key:  [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                       0x0d, 0x0e, 0x0f],
                hash: [0xfd, 0x67, 0xdc, 0x93, 0xc5, 0x39, 0xf8, 0x74],
            },
            {
                msg:  [0x00, 0x01],
                key:  [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                       0x0d, 0x0e, 0x0f],
                hash: [0x5a, 0x4f, 0xa9, 0xd9, 0x09, 0x80, 0x6c, 0x0d],
            },
            {
                msg:  [0x00, 0x01, 0x02],
                key:  [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                       0x0d, 0x0e, 0x0f],
                hash: [0x2d, 0x7e, 0xfb, 0xd7, 0x96, 0x66, 0x67, 0x85],
            },
            {
                msg:  [0x00, 0x01, 0x02, 0x03],
                key:  [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                       0x0d, 0x0e, 0x0f],
                hash: [0xb7, 0x87, 0x71, 0x27, 0xe0, 0x94, 0x27, 0xcf],
            },
            {
                msg:  [0x00, 0x01, 0x02, 0x03, 0x04],
                key:  [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                       0x0d, 0x0e, 0x0f],
                hash: [0x8d, 0xa6, 0x99, 0xcd, 0x64, 0x55, 0x76, 0x18],
            },
            {
                msg:  [0x00, 0x01, 0x02, 0x03, 0x04, 0x05],
                key:  [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                       0x0d, 0x0e, 0x0f],
                hash: [0xce, 0xe3, 0xfe, 0x58, 0x6e, 0x46, 0xc9, 0xcb],
            },
            {
                msg:  [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06],
                key:  [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                       0x0d, 0x0e, 0x0f],
                hash: [0x37, 0xd1, 0x01, 0x8b, 0xf5, 0x00, 0x02, 0xab],
            },
            {
                msg:  [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07],
                key:  [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                       0x0d, 0x0e, 0x0f],
                hash: [0x62, 0x24, 0x93, 0x9a, 0x79, 0xf5, 0xf5, 0x93],
            },
            {
                msg:  [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
                key:  [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                       0x0d, 0x0e, 0x0f],
                hash: [0xb0, 0xe4, 0xa9, 0x0b, 0xdf, 0x82, 0x00, 0x9e],
            },
            {
                msg:  [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                       0x0d, 0x0e, 0x0f],
                key:  [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                       0x0d, 0x0e, 0x0f],
                hash: [0xdb, 0x9b, 0xc2, 0x57, 0x7f, 0xcc, 0x2a, 0x3f],
            },
            {
                msg:  [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                       0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
                       0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26,
                       0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33,
                       0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40,
                       0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d,
                       0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a,
                       0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
                       0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74,
                       0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80, 0x81,
                       0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e,
                       0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b,
                       0x9c, 0x9d, 0x9e, 0x9f, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
                       0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5,
                       0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xc0, 0xc1, 0xc2,
                       0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
                       0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc,
                       0xdd, 0xde, 0xdf, 0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9,
                       0xea, 0xeb, 0xec, 0xed, 0xee, 0xef, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6,
                       0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe],
                key:  [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                       0x0d, 0x0e, 0x0f],
                hash: [0x1a, 0xb2, 0x4d, 0xc7, 0xfe, 0x69, 0xc1, 0xa9],
            },
        ];
    }
}

/// The SipHashX-2-4 hash function (extended output size).
pub mod siphashx24 {
    use libsodium_sys as sodium;

    short_module! {
        sodium::crypto_shorthash_siphashx24_BYTES,
        sodium::crypto_shorthash_siphashx24_KEYBYTES,
        sodium::crypto_shorthash_siphashx24,
    }

    #[cfg(test)]
    mod tests {
        short_module_tests! [
            {
                msg:  [],
                key:  [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                       0x0d, 0x0e, 0x0f],
                hash: [0xa3, 0x81, 0x7f, 0x04, 0xba, 0x25, 0xa8, 0xe6, 0x6d, 0xf6, 0x72, 0x14, 0xc7,
                       0x55, 0x02, 0x93],
            },
            {
                msg:  [0x00],
                key:  [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                       0x0d, 0x0e, 0x0f],
                hash: [0xda, 0x87, 0xc1, 0xd8, 0x6b, 0x99, 0xaf, 0x44, 0x34, 0x76, 0x59, 0x11, 0x9b,
                       0x22, 0xfc, 0x45],
            },
            {
                msg:  [0x00, 0x01],
                key:  [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                       0x0d, 0x0e, 0x0f],
                hash: [0x81, 0x77, 0x22, 0x8d, 0xa4, 0xa4, 0x5d, 0xc7, 0xfc, 0xa3, 0x8b, 0xde, 0xf6,
                       0x0a, 0xff, 0xe4],
            },
            {
                msg:  [0x00, 0x01, 0x02],
                key:  [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                       0x0d, 0x0e, 0x0f],
                hash: [0x9c, 0x70, 0xb6, 0x0c, 0x52, 0x67, 0xa9, 0x4e, 0x5f, 0x33, 0xb6, 0xb0, 0x29,
                       0x85, 0xed, 0x51],
            },
            {
                msg:  [0x00, 0x01, 0x02, 0x03],
                key:  [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                       0x0d, 0x0e, 0x0f],
                hash: [0xf8, 0x81, 0x64, 0xc1, 0x2d, 0x9c, 0x8f, 0xaf, 0x7d, 0x0f, 0x6e, 0x7c, 0x7b,
                       0xcd, 0x55, 0x79],
            },
            {
                msg:  [0x00, 0x01, 0x02, 0x03, 0x04],
                key:  [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                       0x0d, 0x0e, 0x0f],
                hash: [0x13, 0x68, 0x87, 0x59, 0x80, 0x77, 0x6f, 0x88, 0x54, 0x52, 0x7a, 0x07, 0x69,
                       0x0e, 0x96, 0x27],
            },
            {
                msg:  [0x00, 0x01, 0x02, 0x03, 0x04, 0x05],
                key:  [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                       0x0d, 0x0e, 0x0f],
                hash: [0x14, 0xee, 0xca, 0x33, 0x8b, 0x20, 0x86, 0x13, 0x48, 0x5e, 0xa0, 0x30, 0x8f,
                       0xd7, 0xa1, 0x5e],
            },
            {
                msg:  [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06],
                key:  [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                       0x0d, 0x0e, 0x0f],
                hash: [0xa1, 0xf1, 0xeb, 0xbe, 0xd8, 0xdb, 0xc1, 0x53, 0xc0, 0xb8, 0x4a, 0xa6, 0x1f,
                       0xf0, 0x82, 0x39],
            },
            {
                msg:  [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07],
                key:  [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                       0x0d, 0x0e, 0x0f],
                hash: [0x3b, 0x62, 0xa9, 0xba, 0x62, 0x58, 0xf5, 0x61, 0x0f, 0x83, 0xe2, 0x64, 0xf3,
                       0x14, 0x97, 0xb4],
            },
            {
                msg:  [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
                key:  [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                       0x0d, 0x0e, 0x0f],
                hash: [0x26, 0x44, 0x99, 0x06, 0x0a, 0xd9, 0xba, 0xab, 0xc4, 0x7f, 0x8b, 0x02, 0xbb,
                       0x6d, 0x71, 0xed],
            },
            {
                msg:  [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                       0x0d, 0x0e],
                key:  [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                       0x0d, 0x0e, 0x0f],
                hash: [0x54, 0x93, 0xe9, 0x99, 0x33, 0xb0, 0xa8, 0x11, 0x7e, 0x08, 0xec, 0x0f, 0x97,
                       0xcf, 0xc3, 0xd9],
            },
            {
                msg:  [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                       0x0d, 0x0e, 0x0f],
                key:  [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                       0x0d, 0x0e, 0x0f],
                hash: [0x6e, 0xe2, 0xa4, 0xca, 0x67, 0xb0, 0x54, 0xbb, 0xfd, 0x33, 0x15, 0xbf, 0x85,
                       0x23, 0x05, 0x77],
            },
            {
                msg:  [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                       0x0d, 0x0e, 0x0f, 0x10],
                key:  [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                       0x0d, 0x0e, 0x0f],
                hash: [0x47, 0x3d, 0x06, 0xe8, 0x73, 0x8d, 0xb8, 0x98, 0x54, 0xc0, 0x66, 0xc4, 0x7a,
                       0xe4, 0x77, 0x40],
            },
            {
                msg:  [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                       0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
                       0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26,
                       0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33,
                       0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40,
                       0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d,
                       0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a,
                       0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
                       0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74,
                       0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80, 0x81,
                       0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e,
                       0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b,
                       0x9c, 0x9d, 0x9e, 0x9f, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
                       0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5,
                       0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xc0, 0xc1, 0xc2,
                       0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
                       0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc,
                       0xdd, 0xde, 0xdf, 0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9,
                       0xea, 0xeb, 0xec, 0xed, 0xee, 0xef, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6,
                       0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe],
                key:  [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                       0x0d, 0x0e, 0x0f],
                hash: [0x1c, 0x9b, 0xb6, 0x75, 0x28, 0x16, 0x5f, 0x8e, 0x46, 0x82, 0x48, 0xe3, 0x79,
                       0x9b, 0x0e, 0xab],
            },
        ];
    }
}

pub use siphash24::*;
