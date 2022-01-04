//! Generic hash function.
//!
//! This module corresponds to the [`crypto_generichash`
//! API](https://doc.libsodium.org/hashing/generic_hashing) from Sodium.
//!
//! This is a fast [cryptographic hash
//! function](https://en.wikipedia.org/wiki/Cryptographic_hash_function), suitable for use in the
//! standard applications where such a function is necessary. Given an arbitrarily-long input, a
//! cryptographic hash function produces a fixed-length fingerprint (the *digest*). This digest can
//! then be used to identify the original input, as it should be infeasible to find another input
//! which hashes to the same value. See the [`hash` docs](super) for more information on the
//! properties of a cryptographic hash function.
//!
//! This generic hash function can be used in cases such as file integrity checking or generating
//! unique identifiers to index arbitrarily-long data. Please note that the [`hash`](super) module
//! has a number of alternative members which are better suited to certain tasks: For example, the
//! [`hash::pbkdf`](crate::hash::pbkdf) module should be used for password hashing, and the
//! [`hash::short`](crate::hash::short) module is better suited to the construction of hash
//! tables/bloom filters.
//!
//! # Algorithm Details
//! [BLAKE2b](https://www.blake2.net/) is used in this API, a fast, modern hash algorithm optimised
//! for 64-bit platforms.
//!
//! # Security Considerations
//! Generic hash functions *must not* be used for password hashing, they are not sufficiently
//! computationally intensive. Instead, use a [Password-Based Key Derivation
//! Function](https://en.wikipedia.org/wiki/Key_derivation_function#Password_hashing) (PBKDF) such
//! as those available in the [`hash::pbkdf`](crate::hash::pbkdf) module.

// TODO: Multi-part hashing
// TODO: Consider how/if we wish to expose the salt/personalisation parameters of the hash.

use crate::{hardened_buffer, require_init, AlkaliError};
use libsodium_sys as sodium;
use std::ptr;
use thiserror::Error;

/// Error type returned if something went wrong in the generic module.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum GenericHashError {
    /// The desired digest length was too short or too long for use with this algorithm.
    ///
    /// The output size of this hash must be at least [`DIGEST_LENGTH_MIN`], and at most
    /// [`DIGEST_LENGTH_MAX`] bytes. A minimum of [`DIGEST_LENGTH_DEFAULT`] should be used if
    /// collisions should be avoided.
    #[error("digest length outside acceptable range")]
    DigestLengthInvalid,

    /// The provided key was too long for use with this algorithm.
    ///
    /// A key for use with this hash must be at most [`KEY_LENGTH_MAX`] bytes. Using a key size of
    /// [`KEY_LENGTH_DEFAULT`] is recommended, and a key shorter than [`KEY_LENGTH_MIN`] should not
    /// be used if it is intended to be secret.
    #[error("key length outsize acceptable range")]
    KeyLengthInvalid,
}

/// The minimum output length of the hash function, in bytes.
///
/// Below the [default output length](DIGEST_LENGTH_DEFAULT), the hash function may not satisfy the
/// expected property of collision resistance, and as such, using a lower output size than
/// [`DIGEST_LENGTH_DEFAULT`] is not recommended.
pub const DIGEST_LENGTH_MIN: usize = sodium::crypto_generichash_blake2b_BYTES_MIN as usize;

/// The default length of the output of the hash function, in bytes.
///
/// This is the default length of the output of the hash function, and is the recommended minimum
/// size for security. At this size, it is computationally infeasible to find two inputs with the
/// same digest. Below the default output length, the hash function may not satisfy the expected
/// property of collision resistance, and as such, using a lower output size than this constant is
/// not recommended.
pub const DIGEST_LENGTH_DEFAULT: usize = sodium::crypto_generichash_blake2b_BYTES as usize;

/// The maximum output length of the hash function, in bytes.
///
/// Below the [default output length](DIGEST_LENGTH_DEFAULT), the hash function may not satisfy the
/// expected property of collision resistance, and as such, using a lower output size than
/// [`DIGEST_LENGTH_DEFAULT`] is not recommended.
pub const DIGEST_LENGTH_MAX: usize = sodium::crypto_generichash_blake2b_BYTES_MAX as usize;

/// The minimum recommended key size for use with the keyed variant of the hash function, in bytes.
///
/// If the key is intended to be a secret value, a key length below this size should not be used.
pub const KEY_LENGTH_MIN: usize = sodium::crypto_generichash_blake2b_KEYBYTES_MIN as usize;

/// The recommended key size for use with the keyed variant of the hash function, in bytes.
///
/// This length should always be sufficient if the key is intended to be a secret value. A key
/// length below [`KEY_LENGTH_MIN`] should not be used.
pub const KEY_LENGTH_DEFAULT: usize = sodium::crypto_generichash_blake2b_KEYBYTES as usize;

/// The maximum key size for use with the keyed variant of the hash function, in bytes.
///
/// A key length below [`KEY_LENGTH_MIN`] should not be used.
pub const KEY_LENGTH_MAX: usize = sodium::crypto_generichash_blake2b_KEYBYTES_MAX as usize;

hardened_buffer! {
    /// Secret key for the keyed variant of the hash function.
    ///
    /// This key is the default (recommended) length, [`KEY_LENGTH_DEFAULT`].
    ///
    /// There are no technical constraints on the contents of a key, but it should be generated
    /// randomly using [`Key::generate`].
    ///
    /// A secret key must not be made public.
    ///
    /// This is a [hardened buffer type](https://docs.rs/alkali#hardened-buffer-types), and will be
    /// zeroed on drop. A number of other security measures are taken to protect its contents.
    Key(KEY_LENGTH_DEFAULT);
}

impl Key {
    /// Generate a new, random key for use with the keyed variant of the hash function.
    pub fn generate() -> Result<Self, AlkaliError> {
        require_init()?;

        let mut key = Self::new_empty()?;
        unsafe {
            // SAFETY: This function expects a pointer to a region of memory sufficient to store a
            // key for BLAKE2b of the default size. We have defined this type based on the
            // crypto_generichash_blake2b_KEYBYTES constant from Sodium, so it definitely has the
            // correct amount of space allocated to store the key. The Key::inner_mut method simply
            // gives a mutable pointer to the backing memory.
            sodium::crypto_generichash_blake2b_keygen(key.inner_mut() as *mut libc::c_uchar);
        }
        Ok(key)
    }
}

/// The digest generated by this hash function, of the default length.
pub type Digest = [u8; DIGEST_LENGTH_DEFAULT];

/// Calculate the hash of the provided message.
///
/// This function returns the hash of the given message, of the default output size, given by
/// [`DIGEST_LENGTH_DEFAULT`]. No key is used. The same message will always produce the same hash.
pub fn hash(message: &[u8]) -> Result<Digest, AlkaliError> {
    let mut digest = [0u8; DIGEST_LENGTH_DEFAULT];
    hash_custom(message, &mut digest)?;
    Ok(digest)
}

/// Calculate the hash of the provided message, outputting a hash of a custom length.
///
/// The [`hash`] function always outputs a hash of the default size, [`DIGEST_LENGTH_DEFAULT`].
/// This function allows a custom digest length to be specified, if this is necessary for your
/// use-case.
///
/// The hash of `message` will be written to `digest`, which must be between [`DIGEST_LENGTH_MIN`]
/// and [`DIGEST_LENGTH_MAX`] bytes. No key is used. The same message will always produce the same
/// hash.
///
/// # Security Considerations
/// An output size less than [`DIGEST_LENGTH_DEFAULT`] is not guaranteed to preserve the expected
/// property of collision resistance. It is recommended to just use [`hash`] unless you have a
/// specific use-case which requires a different output size.
pub fn hash_custom(message: &[u8], digest: &mut [u8]) -> Result<(), AlkaliError> {
    require_init()?;

    if digest.len() < DIGEST_LENGTH_MIN || digest.len() > DIGEST_LENGTH_MAX {
        return Err(GenericHashError::DigestLengthInvalid.into());
    }

    unsafe {
        // SAFETY: The first two parameters to this function specify the destination pointer to
        // which the calculated digest will be written, and the size for this digest. We ensure the
        // `digest` buffer is of appropriate size above, then specify its length using
        // `digest.len()`, so the length provided is correct for the slice. The next two parameters
        // specify the message to hash and its length. We use `message.len()` to specify the size,
        // so it is correct for this slice. The final two parameters specify the key to use in the
        // hash calculation, and its length. It is documented that if the key is set to be a NULL
        // pointer, then Sodium will ignore the key in the hash calculation, which is our desired
        // behaviour here. Therefore, we pass a NULL pointer for the key's location. Sodium will
        // then also ignore the provided key length, so it can be set to any value.
        sodium::crypto_generichash_blake2b(
            digest.as_mut_ptr(),
            digest.len(),
            message.as_ptr(),
            message.len() as libc::c_ulonglong,
            ptr::null::<libc::c_uchar>(),
            0,
        );
    }

    Ok(())
}

/// Calculate the hash of the provided message, using the provided key as part of the hash
/// calculation.
///
/// This function returns the hash of the given message, of the default output size
/// ([`DIGEST_LENGTH_DEFAULT`]), dependent upon the provided `key`. The same `(message, key)`
/// combination will always produce the same hash. A different key will produce a different hash
/// for the same message.
///
/// This can be used to ensure different applications generate different hashes even when
/// processing the same data, or as a
/// [MAC](https://en.wikipedia.org/wiki/Message_authentication_code).
///
/// # Security Considerations
/// With the default key size as used in this function, this function should be secure for use in
/// [message authentication](https://en.wikipedia.org/wiki/Message_authentication_code). However,
/// it is easier to use the [`symmetric::auth`](crate::symmetric::auth) API, which is specifically
/// intended for this purpose.
pub fn hash_keyed(message: &[u8], key: &Key) -> Result<Digest, AlkaliError> {
    let mut digest = [0u8; DIGEST_LENGTH_DEFAULT];
    hash_keyed_custom(message, key.as_ref(), &mut digest)?;
    Ok(digest)
}

/// Calculate the hash of the provided message, using the provided key as part of the hash
/// calculation, outputting a hash of a custom length. **Read the security considerations before
/// use**.
///
/// The [`hash_keyed`] function always outputs a hash of the default size,
/// [`DIGEST_LENGTH_DEFAULT`], and expects a key of the default size, [`KEY_LENGTH_DEFAULT`].
/// This function allows custom digest & key lengths to be specified, if this is necessary for your
/// use-case.
///
/// The hash of `message` will be written to `digest`, which must be between [`DIGEST_LENGTH_MIN`]
/// and [`DIGEST_LENGTH_MAX`] bytes. The key `key` will be used as part of the hash calculation,
/// and must be at most [`KEY_LENGTH_MAX`] bytes. The same `(message, key)` combination will always
/// produce the same hash. A different key will produce a different hash for the same message.
///
/// This can be used to ensure different applications generate different hashes even when
/// processing the same data. For a **sufficiently sized key**, this can also be used as a
/// [MAC](https://en.wikipedia.org/wiki/Message_authentication_code), but **if the key used is too
/// short, this is insecure**.
///
/// # Security Considerations
/// Great care should be taken if the key used for this function is intended to be a secret value,
/// and is not just being used for non-cryptographic purposes. If you are unsure what key size to
/// use, you should be using [`hash_keyed`].
///
/// If the key used is intended to be secret, it must be at least [`KEY_LENGTH_MIN`] bytes, and
/// should ideally be [`KEY_LENGTH_DEFAULT`] bytes or more. Shorter keys are insufficient for
/// cryptographic applications.
///
/// Secret keys must be generated randomly, use the [`random`](crate::random) API to generate
/// random data suitable for this use.
///
/// Keys should immediately be securely erased from memory when they are no longer required for
/// hash calculation. The [`Key`] type from this module does just this, and can be passed as an
/// argument to this function using `key.as_ref()` to obtain a `&[u8]` slice. If you are using a
/// key of a different size, you can use the [zeroize](https://crates.io/crates/zeroize) crate to
/// clear memory very simply, or use the [hard](https://crates.io/crates/hard) crate if you want to
/// make use of the other memory hardening utilities from Sodium.
///
/// For keys of at least [`KEY_LENGTH_MIN`] bytes, this function should be secure for use in
/// [message authentication](https://en.wikipedia.org/wiki/Message_authentication_code). However,
/// it is easier to use the [`symmetric::auth`](crate::symmetric::auth) API, which is specifically
/// intended for this purpose.
///
/// An output size less than [`DIGEST_LENGTH_DEFAULT`] is not guaranteed to preserve the expected
/// property of collision resistance. It is recommended to just use [`hash_keyed`] unless you have
/// a specific use-case which requires a different output size.
pub fn hash_keyed_custom(message: &[u8], key: &[u8], digest: &mut [u8]) -> Result<(), AlkaliError> {
    require_init()?;

    if digest.len() < DIGEST_LENGTH_MIN || digest.len() > DIGEST_LENGTH_MAX {
        return Err(GenericHashError::DigestLengthInvalid.into());
    } else if key.len() > KEY_LENGTH_MAX {
        return Err(GenericHashError::KeyLengthInvalid.into());
    }

    unsafe {
        // SAFETY: The first two parameters to this function specify the destination pointer to
        // which the calculated digest will be written, and the size for this digest. We ensure the
        // `digest` buffer is of appropriate size above, then specify its length using
        // `digest.len()`, so the length provided is correct for the slice. The next two parameters
        // specify the message to hash and its length. We use `message.len()` to specify the size,
        // so it is correct for this slice. The final two parameters specify the key to use in the
        // hash calculation, and its length. We ensure the `key` buffer is of appropriate size
        // above, then specify its length using `key.len()`, so the length provided is correct for
        // the slice.
        sodium::crypto_generichash_blake2b(
            digest.as_mut_ptr(),
            digest.len(),
            message.as_ptr(),
            message.len() as libc::c_ulonglong,
            key.as_ptr(),
            key.len(),
        );
    }

    Ok(())
}
