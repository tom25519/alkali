//! [AES-256](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) in the [Galois/Counter
//! Mode of Operation (GCM)](https://en.wikipedia.org/wiki/Galois/Counter_Mode).
//!
//! This module corresponds to the [`crypto_aead_aes256gcm`
//! API](https://doc.libsodium.org/secret-key_cryptography/aead/aes-256-gcm) from Sodium.
//!
//! Sodium's AES implementation is only supported on modern x86 processors with Intel's SSSE3
//! extensions, and the `aesni` and `pclmul` instructions. You can test for whether the current
//! platform supports the AES implementation with the [`aes_available`] function, which returns true
//! if AES is supported, and false otherwise. Trying to use the cipher on an unsupported platform
//! will result in errors.
//!
//! # Security Considerations
//! For this algorithm, nonces must *never* be used more than once with the same key. Furthermore,
//! the nonce length for AES-GCM is not sufficient that random nonces can be used without the
//! possibility of collisions, also leading to nonce reuse, so it is unsafe to use random nonces
//! with this construction. Therefore, careful attention is needed to ensure nonces are only used
//! once. If a key is being reused for multiple messages, it is recommended to increment the nonce
//! for the previous message using [`increment_nonce`] for each message sent. The initial nonce can
//! be any value.
//!
//! In client-server protocols, where both parties are sending messages, use different keys for each
//! direction, or ensure one bit in the nonce is always set in one direction, and always unset in
//! the other, to make sure a nonce is never reused with the same key.
//!
//! For this construction, individual messages can only be up to approximately `64` GiB long. An
//! error will be returned if a message is too long. Furthermore, no more than ~350 GiB of total
//! input data (across all messages) should ever be encrypted with a single key. The actual figure
//! varies depending on the size of the individual messages encrypted: 350 GiB is for ~16 KiB
//! messages. If frequent rekeying is not an option, use one of the other AEAD algorithms instead.
//!
//! For this construction, it is possible to efficiently compute multiple keys that would cause a
//! (ciphertext, tag) pair to be verified as authentic. This does not compromise the security of the
//! original message, but if an attacker can force the recipient to use a different key to the key
//! used for encryption, issues could arise. [Sodium's
//! documentation](https://doc.libsodium.org/secret-key_cryptography/aead#robustness) explains how
//! to deal with this issue.
//!
//! If many trusted parties have access to the secret key, there is no way to prove which one of
//! them sent a given message without additional information.
//!
//! This construction exposes the length of the plaintext. If this is undesirable, apply padding to
//! the plaintext prior to encryption via [`util::pad`](crate::util::pad), and remove it following
//! decryption via [`util::unpad`](crate::util::unpad).
//!
//! ## Secret Data
//! * The encryption/decryption key ([`Key`]) must only be known to parties who should be able to
//!   both encrypt and decrypt messages
//!
//! ## Non-Secret Data
//! * MACs ([`MAC`]) are not sensitive
//! * Nonces ([`Nonce`]) are not sensitive
//! * Additional data should not be secret

// TODO: Support precalculated key expansion (beforenm/afternm)

use super::AEADError;
use crate::{assert_not_err, mem, require_init, util, AlkaliError};
use libsodium_sys as sodium;
use std::ptr;

/// The length of a symmetric key used for this AEAD construction, in bytes.
pub const KEY_LENGTH: usize = sodium::crypto_aead_aes256gcm_KEYBYTES as usize;

/// The length of a MAC, in bytes.
pub const MAC_LENGTH: usize = sodium::crypto_aead_aes256gcm_ABYTES as usize;

/// The length of a message nonce, in bytes.
pub const NONCE_LENGTH: usize = sodium::crypto_aead_aes256gcm_NPUBBYTES as usize;

lazy_static::lazy_static! {
    /// The maximum message length which can be encrypted with this cipher, in bytes.
    pub static ref MESSAGE_LENGTH_MAX: usize = unsafe {
        // SAFETY: This function just returns a constant value, and should always be safe to call.
        sodium::crypto_aead_aes256gcm_messagebytes_max()
    };
}

mem::hardened_buffer! {
    /// A secret key for this symmetric AEAD algorithm.
    ///
    /// There are no *technical* constraints on the contents of a key, but it should be
    /// indistinguishable from random noise. A random key can be securely generated via
    /// [`Key::generate`].
    ///
    /// A secret key must not be made public.
    ///
    /// This is a [hardened buffer type](https://docs.rs/alkali#hardened-buffer-types), and will be
    /// zeroed on drop. A number of other security measures are also taken to protect its contents.
    /// This type in particular can be thought of as roughly equivalent to a `[u8; KEY_LENGTH]`, and
    /// implements [`std::ops::Deref`] so it can be used like it is an `&[u8]`. This struct uses
    /// heap memory while in scope, allocated using Sodium's [secure memory
    /// utilities](https://doc.libsodium.org/memory_management).
    pub Key(KEY_LENGTH);
}

impl Key {
    /// Generate a new, random key for use with this AEAD construction.
    pub fn generate() -> Result<Self, AlkaliError> {
        require_init()?;

        let mut key = Self::new_empty()?;
        unsafe {
            // SAFETY: This function expects a pointer to a region of memory sufficient to store a
            // key. The `Key` type allocates `crypto_aead_aes256gcm_KEYBYTES` bytes, the length of a
            // key for this algorithm. It is therefore valid for writes of the required length. The
            // `Key::inner_mut` method simply returns a mutable pointer to the struct's backing
            // memory.
            sodium::crypto_aead_aes256gcm_keygen(key.inner_mut() as *mut libc::c_uchar);
        }
        Ok(key)
    }
}

/// A MAC (Message Authentication Code), used to authenticate an encrypted message and any
/// associated data.
///
/// If using [`encrypt`] or [`decrypt`], the MAC is appended to the encrypted message. It is
/// returned separately in the [`encrypt_detached`] variant.
pub type MAC = [u8; MAC_LENGTH];

/// A nonce, used to introduce non-determinism into the keystream calculation.
///
/// Nonces must never be used for multiple messages with the same key. See this algorithm's security
/// considerations for more information on safely managing nonces.
pub type Nonce = [u8; NONCE_LENGTH];

/// Returns `true` if AES-256-GCM is available on this platform, `false` otherwise.
///
/// This algorithm is only available on platforms supporting Intel's SSSE3 extensions, and the
/// `aesni` and `pclmul` instructions.
pub fn aes_available() -> Result<bool, AlkaliError> {
    require_init()?;

    unsafe {
        // SAFETY: This function doesn't have any side effects, and should always be safe to call
        // providing Sodium has been initialised.
        Ok(sodium::crypto_aead_aes256gcm_is_available() == 1)
    }
}

/// Attempt to initialise Sodium & return an error if AES is not available.
///
/// n.b: Crates making use of alkali do not have to call this function, it is only used internally
/// wherever AES is to be used.
fn require_init_aes() -> Result<(), AlkaliError> {
    if !aes_available()? {
        return Err(AEADError::AESUnavailable.into());
    }
    Ok(())
}

/// Treat `nonce` as a little-endian unsigned integer, and increment it by one.
///
/// This is useful for ensuring a different nonce is used for every message: Increment the nonce for
/// every message sent. View the security considerations associated with this algorithm for more
/// information on preventing nonce reuse.
pub fn increment_nonce(nonce: &mut Nonce) -> Result<(), AlkaliError> {
    util::increment_le(nonce)
}

/// Encrypt `message` using the provided `key`, optionally authenticating additional data `ad`,
/// writing the result to `output`.
///
/// `message` should be the message to encrypt.
///
/// If `ad` is set to `Some(ad)`, then this additional data will be included in the calculation of
/// the MAC for this message. The additional data will not be encrypted, nor will it be included in
/// the output, but it will be required to authenticate the message during decryption. Similar to
/// how authentication for the ciphertext works, any changes in the additional data will cause
/// decryption to fail.
///
/// `key` should be a [`Key`] generated randomly using [`Key::generate`].
///
/// `nonce` should be a [nonce](https://en.wikipedia.org/wiki/Cryptographic_nonce) to use in the
/// encryption process. Nonces must *never* be used more than once with the same key. See this
/// algorithm's security considerations for more information on safely managing nonces.
///
/// The encrypted ciphertext will be written to `output`. The ciphertext will be [`MAC_LENGTH`]
/// bytes longer than `message`, so `output` must be of sufficient size to store at least this many
/// bytes. An error will be returned if `output` is not sufficient to store the ciphertext.
///
/// If encryption is successful, returns the number of bytes written to `output` (this will actually
/// always be `message.len()` + [`MAC_LENGTH`] bytes).
///
/// # Security Considerations
/// Nonces must *never* be used more than once with the same key. See this algorithm's security
/// considerations for more information on safely managing nonces.
pub fn encrypt(
    message: &[u8],
    ad: Option<&[u8]>,
    key: &Key,
    nonce: &Nonce,
    output: &mut [u8],
) -> Result<usize, AlkaliError> {
    require_init_aes()?;

    let c_len = message.len() + MAC_LENGTH;

    if output.len() < c_len {
        return Err(AEADError::OutputInsufficient.into());
    } else if message.len() > *MESSAGE_LENGTH_MAX {
        return Err(AEADError::MessageTooLong.into());
    }

    let (ad_ptr, ad_len) = match ad {
        Some(ad) => (ad.as_ptr(), ad.len()),
        None => (ptr::null(), 0),
    };

    let encrypt_result = unsafe {
        // SAFETY: The first argument to this function is the destination to which the combined MAC
        // + ciphertext will be written. The ciphertext will be of the same length as the message,
        // and the MAC will always be `crypto_aead_aes256gcm_ABYTES`, so as long as the output
        // pointer is valid for writes of `message.len() + crypto_aead_aes256gcm_ABYTES`, it is
        // valid to use here. We verify this condition above, and return an error if the output is
        // insufficient. The next argument is a destination to which the length of the combined MAC
        // + ciphertext will be written. It is documented that if this is set to a null pointer,
        // then it will be ignored. The next two arguments specify the message to encrypt and its
        // length. We use `message.len()` to specify the message length, so `message` is definitely
        // valid for reads of this length. The next two arguments specify a pointer to the
        // additional data to authenticate and the length of the additional data. If additional data
        // is provided, we use `ad.as_ptr()` for the pointer to the additional data, and `ad.len()`
        // for the length of the additional data, so `ad` is clearly valid for reads of this length.
        // If additional data is not provided, we pass a null pointer and a length of zero. It is
        // documented that a null pointer is safe to use here, and Sodium will just not include the
        // additional data in the authentication calculation. The next argument is a pointer to a
        // secret nonce, which is not used for this algorithm, and should always be set to a null
        // pointer, which we do here. The next argument should be a pointer to the nonce to use for
        // encryption. We have defined the `Nonce` type to be `crypto_aead_aes256gcm_NPUBBYTES`
        // bytes long, the size of a nonce for this algorithm, so it is valid for reads of the
        // required length. The final argument specifies the key with which the message should be
        // encrypted. We have defined the `Key` type to allocate `crypto_aead_aes256gcm_KEYBYTES`
        // bytes, the length of a key for this algorithm, so it is valid for reads of the required
        // length. The `Key::inner` method simply returns an immutable pointer to its backing
        // memory.
        sodium::crypto_aead_aes256gcm_encrypt(
            output.as_mut_ptr(),
            ptr::null_mut(),
            message.as_ptr(),
            message.len() as libc::c_ulonglong,
            ad_ptr,
            ad_len as libc::c_ulonglong,
            ptr::null(),
            nonce.as_ptr(),
            key.as_ptr(),
        )
    };
    assert_not_err!(encrypt_result, "crypto_aead_aes256gcm_encrypt");

    Ok(c_len)
}

/// Decrypt `ciphertext` using the provided `key`, optionally authenticating additional data `ad`,
/// writing the result to `output`.
///
/// `ciphertext` should be the combined ciphertext + MAC to decrypt (previously encrypted using
/// [`encrypt`]).
///
/// If additional authenticated data was supplied during encryption, it should also be provided as
/// `ad`, otherwise `ad` can be set to `None`. Note that if different additional data is specified
/// to the additional data provided during encryption, decryption will fail.
///
/// `key` should be the [`Key`] to use to decrypt the message. `nonce` should be the [`Nonce`] which
/// was used to encrypt the message.
///
/// The decrypted plaintext will be written to `output`. The plaintext will be [`MAC_LENGTH`] bytes
/// shorter than `ciphertext`, so `output` must be of sufficient size to store at least this many
/// bytes. An error will be returned if `output` is not sufficient to store the ciphertext.
///
/// Decryption will fail if authentication of the encrypted message or the additional data fails. If
/// decryption is successful, the plaintext is written to `output`, and the length of the plaintext
/// will be returned (this will always be `ciphertext.len()` - [`MAC_LENGTH`] bytes).
pub fn decrypt(
    ciphertext: &[u8],
    ad: Option<&[u8]>,
    key: &Key,
    nonce: &Nonce,
    output: &mut [u8],
) -> Result<usize, AlkaliError> {
    require_init_aes()?;

    if ciphertext.len() < MAC_LENGTH {
        return Err(AEADError::DecryptionFailed.into());
    }

    let m_len = ciphertext.len() - MAC_LENGTH;

    if output.len() < m_len {
        return Err(AEADError::OutputInsufficient.into());
    }

    let (ad_ptr, ad_len) = match ad {
        Some(ad) => (ad.as_ptr(), ad.len()),
        None => (ptr::null(), 0),
    };

    let decrypt_result = unsafe {
        // SAFETY: The first argument to this function is the destination to which the decrypted
        // plaintext will be written. The plaintext will be `crypto_aead_aes256gcm_ABYTES` shorter
        // than the ciphertext, so as long as the output pointer is valid for writes of
        // `ciphertext.len() - crypto_aead_aes256gcm_ABYTES`, it is valid to use here. We verify
        // this condition above, and return an error if the output is insufficient. The next
        // argument specifies the destination to which the length of the decrypted plaintext will be
        // written. It is documented that if this is set to a null pointer, then it will be ignored.
        // The next argument is a pointer to a secret nonce, which is not used for this algorithm,
        // and should always be set to a null pointer, which we do here. The next two arguments
        // specify the ciphertext to decrypt and its length. We use `ciphertext.len()` to specify
        // the ciphertext length, so `ciphertext` is definitely valid for reads of this length. The
        // next two arguments specify a pointer to the additional data to authenticate and the
        // length of the additional data. If additional data is provided, we use `ad.as_ptr()` for
        // the pointer to the additional data, and `ad.len()` for the length of the additional data,
        // so `ad` is clearly valid for reads of this length. If additional data is provided, we use
        // `ad.as_ptr()` for the pointer to the additional data, and `ad.len()` for the length of
        // the additional data, so `ad` is clearly valid for reads of this length. If additional
        // data is not provided, we pass a null pointer and a length of zero. It is documented that
        // a null pointer is safe to use here, and Sodium will just not include the additional data
        // in the authentication calculation. The next argument is should be a pointer to the nonce
        // which was used for encryption. We have defined the `Nonce` type to be
        // `crypto_aead_aes256gcm_NPUBBYTES` bytes long, the size of a nonce for this algorithm, so
        // it is valid for reads of the required length. The final argument specifies the key with
        // which the message was encrypted. We have defined the `Key` type to allocate
        // `crypto_aead_aes256gcm_KEYBYTES` bytes, the length of a key for this algorithm, so it is
        // valid for reads of the required length. The `Key::inner` method simply returns an
        // immutable pointer to its backing memory.
        sodium::crypto_aead_aes256gcm_decrypt(
            output.as_mut_ptr(),
            ptr::null_mut(),
            ptr::null_mut(),
            ciphertext.as_ptr(),
            ciphertext.len() as libc::c_ulonglong,
            ad_ptr,
            ad_len as libc::c_ulonglong,
            nonce.as_ptr(),
            key.as_ptr(),
        )
    };

    if decrypt_result == 0 {
        Ok(m_len)
    } else {
        Err(AEADError::DecryptionFailed.into())
    }
}

/// Encrypt `message` using the provided `key`, optionally authenticating additional data `ad`,
/// writing the result to `output`, separately returning the [`MAC`].
///
/// This function is very similar to the [`encrypt`] function. The difference is that the standard
/// [`encrypt`] function appends the Message Authentication Code (MAC, used to verify the
/// authenticity of the ciphertext) to the ciphertext output, while this function only writes the
/// ciphertext to `output`, and separately returns the MAC.
///
/// `message` should be the message to encrypt.
///
/// If `ad` is set to `Some(ad)`, then this additional data will be included in the calculation of
/// the MAC for this message. The additional data will not be encrypted, nor will it be included in
/// the output, but it will be required to authenticate the message during decryption. Similar to
/// how authentication for the ciphertext works, any changes in the additional data will cause
/// decryption to fail.
///
/// `key` should be a [`Key`] generated randomly using [`Key::generate`].
///
/// `nonce` should be a [nonce](https://en.wikipedia.org/wiki/Cryptographic_nonce) to use in the
/// encryption process. Nonces must *never* be used more than once with the same key. See this
/// algorithm's security considerations for more information on safely managing nonces.
///
/// The encrypted ciphertext will be written to `output`. The ciphertext will the same length as
/// `message`, so `output` must be of sufficient size to store at least this many bytes. An error
/// will be returned if `output` is not sufficient to store the ciphertext.
///
/// If encryption is successful, returns the number of bytes written to `output` (this will actually
/// always be `message.len()` bytes), and the authentication tag for the message + additional data
/// (a [`MAC`]).
///
/// # Security Considerations
/// Nonces must *never* be used more than once with the same key. See this algorithm's security
/// considerations for more information on safely managing nonces.
pub fn encrypt_detached(
    message: &[u8],
    ad: Option<&[u8]>,
    key: &Key,
    nonce: &Nonce,
    output: &mut [u8],
) -> Result<(usize, MAC), AlkaliError> {
    require_init_aes()?;

    if output.len() < message.len() {
        return Err(AEADError::OutputInsufficient.into());
    } else if message.len() > *MESSAGE_LENGTH_MAX {
        return Err(AEADError::MessageTooLong.into());
    }

    let (ad_ptr, ad_len) = match ad {
        Some(ad) => (ad.as_ptr(), ad.len()),
        None => (ptr::null(), 0),
    };

    let mut mac = [0u8; MAC_LENGTH];

    let encrypt_result = unsafe {
        // SAFETY: The first argument to this function is the destination to which the ciphertext
        // will be written. The ciphertext will be of the same length as the message, so as long as
        // the output pointer is valid for writes of `message.len()` it is valid to use here. We
        // verify this condition above, and return an error if the output is insufficient. The next
        // argument is the destination to which the MAC will be written. We define the `mac` array
        // to be `crypto_aead_aes256gcm_ABYTES`, the length of a MAC for this algorithm, so it is
        // valid for writes of the required length. The next argument is a destination to which the
        // length of the calculated MAC will be written. It is documented that if this is set to a
        // null pointer, then it will be ignored. The next two arguments specify the message to
        // encrypt and its length. We use `message.len()` to specify the message length, so
        // `message` is definitely valid for reads of this length. The next two arguments specify a
        // pointer to the additional data to authenticate and the length of the additional data. If
        // additional data is provided, we use `ad.as_ptr()` for the pointer to the additional data,
        // and `ad.len()` for the length of the additional data, so `ad` is clearly valid for reads
        // of this length. If additional data is not provided, we pass a null pointer and a length
        // of zero. It is documented that a null pointer is safe to use here, and Sodium will just
        // not include the additional data in the authentication calculation. The next argument is a
        // pointer to a secret nonce, which is not used for this algorithm, and should always be set
        // to a null pointer, which we do here. The next argument should be a pointer to the nonce
        // to use for encryption. We have defined the `Nonce` type to be
        // `crypto_aead_aes256gcm_NPUBBYTES` bytes long, the size of a nonce for this algorithm, so
        // it is valid for reads of the required length. The final argument specifies the key with
        // which the message should be encrypted. We have defined the `Key` type to allocate
        // `crypto_aead_aes256gcm_KEYBYTES` bytes, the length of a key for this algorithm, so it is
        // valid for reads of the required length. The `Key::inner` method simply returns an
        // immutable pointer to its backing memory.
        sodium::crypto_aead_aes256gcm_encrypt_detached(
            output.as_mut_ptr(),
            mac.as_mut_ptr(),
            ptr::null_mut(),
            message.as_ptr(),
            message.len() as libc::c_ulonglong,
            ad_ptr,
            ad_len as libc::c_ulonglong,
            ptr::null(),
            nonce.as_ptr(),
            key.inner() as *const libc::c_uchar,
        )
    };
    assert_not_err!(encrypt_result, "crypto_aead_aes256gcm_encrypt_detached");

    Ok((message.len(), mac))
}

/// Decrypt `ciphertext` using the provided `key`, verifying the detached [`MAC`] (optionally with
/// additional data `ad`), and writing the result to `output`.
///
/// `ciphertext` should be the ciphertext to decrypt (previously encrypted using
/// [`encrypt_detached`]).
///
/// If additional authenticated data was supplied during encryption, it should also be provided as
/// `ad`, otherwise `ad` can be set to `None`. Note that if different additional data is specified
/// to the additional data provided during encryption, decryption will fail.
///
/// `mac` should be the [`MAC`] generated when encrypting the ciphertext. `key` should be the
/// [`Key`] to use to decrypt the message. `nonce` should be the [`Nonce`] which was used to encrypt
/// the message.
///
/// The decrypted plaintext will be written to `output`. The plaintext will be the same length as
/// `ciphertext`, so `output` must be of sufficient size to store at least this many bytes. An error
/// will be returned if `output` is not sufficient to store the ciphertext.
///
/// Decryption will fail if authentication of the encrypted message or the additional data fails. If
/// decryption is successful, the plaintext is written to `output`, and the length of the plaintext
/// will be returned (this will always be `ciphertext.len()` bytes).
pub fn decrypt_detached(
    ciphertext: &[u8],
    ad: Option<&[u8]>,
    mac: &MAC,
    key: &Key,
    nonce: &Nonce,
    output: &mut [u8],
) -> Result<usize, AlkaliError> {
    require_init_aes()?;

    if output.len() < ciphertext.len() {
        return Err(AEADError::OutputInsufficient.into());
    }

    let (ad_ptr, ad_len) = match ad {
        Some(ad) => (ad.as_ptr(), ad.len()),
        None => (ptr::null(), 0),
    };

    let decrypt_result = unsafe {
        // SAFETY: The first argument to this function is the destination to which the decrypted
        // plaintext will be written. The plaintext will be the same length as the ciphertext, so as
        // long as the output pointer is valid for writes of `ciphertext.len()`, it is valid to use
        // here. We verify this condition above, and return an error if the output is insufficient.
        // The next argument is a pointer to a secret nonce, which is not used for this algorithm,
        // and should always be set to a null pointer, which we do here. The next two arguments
        // specify the ciphertext to decrypt and its length. We use `ciphertext.len()` to specify
        // the ciphertext length, so `ciphertext` is definitely valid for reads of this length. The
        // next argument should be a pointer to the MAC to use to verify the message & additional
        // data. The `MAC` type is defined to be `crypto_aead_aes256gcm_BYTES`, the length of a MAC
        // for this algorithm, so `mac` is valid for reads of the required length. The next two
        // arguments specify a pointer to the additional data to authenticate and the length of the
        // additional data. If additional data is provided, we use `ad.as_ptr()` for the pointer to
        // the additional data, and `ad.len()` for the length of the additional data, so `ad` is
        // clearly valid for reads of this length. If additional data is provided, we use
        // `ad.as_ptr()` for the pointer to the additional data, and `ad.len()` for the length of
        // the additional data, so `ad` is clearly valid for reads of this length. If additional
        // data is not provided, we pass a null pointer and a length of zero. It is documented that
        // a null pointer is safe to use here, and Sodium will just not include the additional data
        // in the authentication calculation. The next argument is should be a pointer to the nonce
        // which was used for encryption. We have defined the `Nonce` type to be
        // `crypto_aead_aes256gcm_NPUBBYTES` bytes long, the size of a nonce for this algorithm, so
        // it is valid for reads of the required length. The final argument specifies the key with
        // which the message was encrypted. We have defined the `Key` type to allocate
        // `crypto_aead_aes256gcm_KEYBYTES` bytes, the length of a key for this algorithm, so it is
        // valid for reads of the required length. The `Key::inner` method simply returns an
        // immutable pointer to its backing memory.
        sodium::crypto_aead_aes256gcm_decrypt_detached(
            output.as_mut_ptr(),
            ptr::null_mut(),
            ciphertext.as_ptr(),
            ciphertext.len() as libc::c_ulonglong,
            mac.as_ptr(),
            ad_ptr,
            ad_len as libc::c_ulonglong,
            nonce.as_ptr(),
            key.inner() as *const libc::c_uchar,
        )
    };

    if decrypt_result == 0 {
        Ok(ciphertext.len())
    } else {
        Err(AEADError::DecryptionFailed.into())
    }
}

#[cfg(test)]
mod tests {
    use crate::symmetric::aead::aead_tests;

    #[test]
    fn platform_support_detection() -> Result<(), crate::AlkaliError> {
        use super::{aes_available, require_init_aes};

        assert!(aes_available()?);
        require_init_aes()?;
        Ok(())
    }

    aead_tests! [
        {
            msg:    [] as [u8; 0],
            ad:     [],
            key:    [0xb5, 0x2c, 0x50, 0x5a, 0x37, 0xd7, 0x8e, 0xda, 0x5d, 0xd3, 0x4f, 0x20, 0xc2,
                     0x25, 0x40, 0xea, 0x1b, 0x58, 0x96, 0x3c, 0xf8, 0xe5, 0xbf, 0x8f, 0xfa, 0x85,
                     0xf9, 0xf2, 0x49, 0x25, 0x05, 0xb4],
            nonce:  [0x51, 0x6c, 0x33, 0x92, 0x9d, 0xf5, 0xa3, 0x28, 0x4f, 0xf4, 0x63, 0xd7],
            c:      [],
            mac:    [0xbd, 0xc1, 0xac, 0x88, 0x4d, 0x33, 0x24, 0x57, 0xa1, 0xd2, 0x66, 0x4f, 0x16,
                     0x8c, 0x76, 0xf0],
        },
        {
            msg:    [] as [u8; 0],
            ad:     [0xb9, 0x6b, 0xaa, 0x8c, 0x1c, 0x75, 0xa6, 0x71, 0xbf, 0xb2, 0xd0, 0x8d, 0x06,
                     0xbe, 0x5f, 0x36],
            key:    [0x78, 0xdc, 0x4e, 0x0a, 0xaf, 0x52, 0xd9, 0x35, 0xc3, 0xc0, 0x1e, 0xea, 0x57,
                     0x42, 0x8f, 0x00, 0xca, 0x1f, 0xd4, 0x75, 0xf5, 0xda, 0x86, 0xa4, 0x9c, 0x8d,
                     0xd7, 0x3d, 0x68, 0xc8, 0xe2, 0x23],
            nonce:  [0xd7, 0x9c, 0xf2, 0x2d, 0x50, 0x4c, 0xc7, 0x93, 0xc3, 0xfb, 0x6c, 0x8a],
            c:      [],
            mac:    [0x3e, 0x5d, 0x48, 0x6a, 0xa2, 0xe3, 0x0b, 0x22, 0xe0, 0x40, 0xb8, 0x57, 0x23,
                     0xa0, 0x6e, 0x76],
        },
        {
            msg:    [] as [u8; 0],
            ad:     [0x98, 0xe6, 0x8c, 0x10, 0xbf, 0x4b, 0x5a, 0xe6, 0x2d, 0x43, 0x49, 0x28, 0xfc,
                     0x64, 0x05, 0x14, 0x7c, 0x63, 0x01, 0x41, 0x73, 0x03, 0xef, 0x3a, 0x70, 0x3d,
                     0xcf, 0xd2, 0xc0, 0xc3, 0x39, 0xa4, 0xd0, 0xa8, 0x9b, 0xd2, 0x9f, 0xe6, 0x1f,
                     0xec, 0xf1, 0x06, 0x6a, 0xb0, 0x6d, 0x7a, 0x5c, 0x31, 0xa4, 0x8f, 0xfb, 0xfe,
                     0xd2, 0x2f, 0x74, 0x9b, 0x17, 0xe9, 0xbd, 0x0d, 0xc1, 0xc6, 0xf8, 0xfb, 0xd6,
                     0xfd, 0x45, 0x87, 0x18, 0x4d, 0xb9, 0x64, 0xd5, 0x45, 0x61, 0x32, 0x10, 0x6d,
                     0x78, 0x23, 0x38, 0xc3, 0xf1, 0x17, 0xec, 0x05, 0x22, 0x9b, 0x08, 0x99],
            key:    [0x03, 0xcc, 0xb7, 0xdb, 0xc7, 0xb8, 0x42, 0x54, 0x65, 0xc2, 0xc3, 0xfc, 0x39,
                     0xed, 0x05, 0x93, 0x92, 0x9f, 0xfd, 0x02, 0xa4, 0x5f, 0xf5, 0x83, 0xbd, 0x89,
                     0xb7, 0x9c, 0x6f, 0x64, 0x6f, 0xe9],
            nonce:  [0xfd, 0x11, 0x99, 0x85, 0x53, 0x3b, 0xd5, 0x52, 0x0b, 0x30, 0x1d, 0x12],
            c:      [],
            mac:    [0xcf, 0x54, 0xe7, 0x14, 0x13, 0x49, 0xb6, 0x6f, 0x24, 0x81, 0x54, 0x42, 0x78,
                     0x10, 0xc8, 0x7a],
        },
        {
            msg:    [0x2d, 0xb5, 0x16, 0x8e, 0x93, 0x25, 0x56, 0xf8, 0x08, 0x9a, 0x06, 0x22, 0x98,
                     0x1d, 0x01, 0x7d],
            ad:     [],
            key:    [0x31, 0xbd, 0xad, 0xd9, 0x66, 0x98, 0xc2, 0x04, 0xaa, 0x9c, 0xe1, 0x44, 0x8e,
                     0xa9, 0x4a, 0xe1, 0xfb, 0x4a, 0x9a, 0x0b, 0x3c, 0x9d, 0x77, 0x3b, 0x51, 0xbb,
                     0x18, 0x22, 0x66, 0x6b, 0x8f, 0x22],
            nonce:  [0x0d, 0x18, 0xe0, 0x6c, 0x7c, 0x72, 0x5a, 0xc9, 0xe3, 0x62, 0xe1, 0xce],
            c:      [0xfa, 0x43, 0x62, 0x18, 0x96, 0x61, 0xd1, 0x63, 0xfc, 0xd6, 0xa5, 0x6d, 0x8b,
                     0xf0, 0x40, 0x5a],
            mac:    [0xd6, 0x36, 0xac, 0x1b, 0xbe, 0xdd, 0x5c, 0xc3, 0xee, 0x72, 0x7d, 0xc2, 0xab,
                     0x4a, 0x94, 0x89],
        },
        {
            msg:    [0x2d, 0x71, 0xbc, 0xfa, 0x91, 0x4e, 0x4a, 0xc0, 0x45, 0xb2, 0xaa, 0x60, 0x95,
                     0x5f, 0xad, 0x24],
            ad:     [0x1e, 0x08, 0x89, 0x01, 0x6f, 0x67, 0x60, 0x1c, 0x8e, 0xbe, 0xa4, 0x94, 0x3b,
                     0xc2, 0x3a, 0xd6],
            key:    [0x92, 0xe1, 0x1d, 0xcd, 0xaa, 0x86, 0x6f, 0x5c, 0xe7, 0x90, 0xfd, 0x24, 0x50,
                     0x1f, 0x92, 0x50, 0x9a, 0xac, 0xf4, 0xcb, 0x8b, 0x13, 0x39, 0xd5, 0x0c, 0x9c,
                     0x12, 0x40, 0x93, 0x5d, 0xd0, 0x8b],
            nonce:  [0xac, 0x93, 0xa1, 0xa6, 0x14, 0x52, 0x99, 0xbd, 0xe9, 0x02, 0xf2, 0x1a],
            c:      [0x89, 0x95, 0xae, 0x2e, 0x6d, 0xf3, 0xdb, 0xf9, 0x6f, 0xac, 0x7b, 0x71, 0x37,
                     0xba, 0xe6, 0x7f],
            mac:    [0xec, 0xa5, 0xaa, 0x77, 0xd5, 0x1d, 0x4a, 0x0a, 0x14, 0xd9, 0xc5, 0x1e, 0x1d,
                     0xa4, 0x74, 0xab],
        },
        {
            msg:    [0x5e, 0x7f, 0xd1, 0x29, 0x8c, 0x4f, 0x15, 0xaa, 0x0f, 0x1c, 0x1e, 0x47, 0x21,
                     0x7a, 0xa7, 0xa9],
            ad:     [0x0e, 0x94, 0xf4, 0xc4, 0x8f, 0xd0, 0xc9, 0x69, 0x0c, 0x85, 0x3a, 0xd2, 0xa5,
                     0xe1, 0x97, 0xc5, 0xde, 0x26, 0x21, 0x37, 0xb6, 0x9e, 0xd0, 0xcd, 0xfa, 0x28,
                     0xd8, 0xd1, 0x24, 0x13, 0xe4, 0xff, 0xff, 0x15, 0x37, 0x4e, 0x1c, 0xcc, 0xb0,
                     0x42, 0x3e, 0x8e, 0xd8, 0x29, 0xa9, 0x54, 0xa3, 0x35, 0xed, 0x70, 0x5a, 0x27,
                     0x2a, 0xd7, 0xf9, 0xab, 0xd1, 0x05, 0x7c, 0x84, 0x9b, 0xb0, 0xd5, 0x4b, 0x76,
                     0x8e, 0x9d, 0x79, 0x87, 0x9e, 0xc5, 0x52, 0x46, 0x1c, 0xc0, 0x4a, 0xdb, 0x6c,
                     0xa0, 0x04, 0x0c, 0x5d, 0xd5, 0xbc, 0x73, 0x3d, 0x21, 0xa9, 0x37, 0x02],
            key:    [0x80, 0xd7, 0x55, 0xe2, 0x4d, 0x12, 0x9e, 0x68, 0xa5, 0x25, 0x9e, 0xc2, 0xcf,
                     0x61, 0x8e, 0x39, 0x31, 0x70, 0x74, 0xa8, 0x3c, 0x89, 0x61, 0xd3, 0x76, 0x8c,
                     0xeb, 0x2e, 0xd8, 0xd5, 0xc3, 0xd7],
            nonce:  [0x75, 0x98, 0xc0, 0x7b, 0xa7, 0xb1, 0x6c, 0xd1, 0x2c, 0xf5, 0x08, 0x13],
            c:      [0x57, 0x62, 0xa3, 0x8c, 0xf3, 0xf2, 0xfd, 0xf3, 0x64, 0x5d, 0x2f, 0x66, 0x96,
                     0xa7, 0xee, 0xad],
            mac:    [0x8a, 0x67, 0x08, 0xe6, 0x94, 0x68, 0x91, 0x5c, 0x53, 0x67, 0x57, 0x39, 0x24,
                     0xfe, 0x1a, 0xe3],
        },
        {
            msg:    [0x98, 0x2a, 0x29, 0x6e, 0xe1, 0xcd, 0x70, 0x86, 0xaf, 0xad, 0x97, 0x69, 0x45],
            ad:     [],
            key:    [0x82, 0xc4, 0xf1, 0x2e, 0xee, 0xc3, 0xb2, 0xd3, 0xd1, 0x57, 0xb0, 0xf9, 0x92,
                     0xd2, 0x92, 0xb2, 0x37, 0x47, 0x8d, 0x2c, 0xec, 0xc1, 0xd5, 0xf1, 0x61, 0x38,
                     0x9b, 0x97, 0xf9, 0x99, 0x05, 0x7a],
            nonce:  [0x7b, 0x40, 0xb2, 0x0f, 0x5f, 0x39, 0x71, 0x77, 0x99, 0x0e, 0xf2, 0xd1],
            c:      [0xec, 0x8e, 0x05, 0xa0, 0x47, 0x1d, 0x6b, 0x43, 0xa5, 0x9c, 0xa5, 0x33, 0x5f],
            mac:    [0x11, 0x3d, 0xde, 0xaf, 0xc6, 0x23, 0x73, 0xca, 0xc2, 0xf5, 0x95, 0x1b, 0xb9,
                     0x16, 0x52, 0x49],
        },
        {
            msg:    [0xb5, 0x26, 0xba, 0x10, 0x50, 0x17, 0x7d, 0x05, 0xb0, 0xf7, 0x2f, 0x8d, 0x67],
            ad:     [0x6e, 0x43, 0x78, 0x4a, 0x91, 0x85, 0x1a, 0x77, 0x66, 0x7a, 0x02, 0x19, 0x8e,
                     0x28, 0xdc, 0x32],
            key:    [0xda, 0xd8, 0x9d, 0x9b, 0xe9, 0xbb, 0xa1, 0x38, 0xcd, 0xcf, 0x87, 0x52, 0xc4,
                     0x5b, 0x57, 0x9d, 0x7e, 0x27, 0xc3, 0xdb, 0xb4, 0x0f, 0x53, 0xe7, 0x71, 0xdd,
                     0x8c, 0xfd, 0x50, 0x0a, 0xa2, 0xd5],
            nonce:  [0xcf, 0xb2, 0xae, 0xc8, 0x2c, 0xfa, 0x6c, 0x7d, 0x89, 0xee, 0x72, 0xff],
            c:      [0x8b, 0x29, 0xe6, 0x6e, 0x92, 0x4e, 0xca, 0xe8, 0x4f, 0x6d, 0x8f, 0x7d, 0x68],
            mac:    [0x1e, 0x36, 0x58, 0x05, 0xc8, 0xf2, 0x8b, 0x2e, 0xd8, 0xa5, 0xca, 0xdf, 0xd9,
                     0x07, 0x91, 0x58],
        },
        {
            msg:    [0xfe, 0x29, 0xa4, 0x0d, 0x8e, 0xbf, 0x57, 0x26, 0x2b, 0xdb, 0x87, 0x19, 0x1d,
                     0x01, 0x84, 0x3f, 0x4c, 0xa4, 0xb2, 0xde, 0x97, 0xd8, 0x82, 0x73, 0x15, 0x4a,
                     0x0b, 0x7d, 0x9e, 0x2f, 0xdb, 0x80],
            ad:     [],
            key:    [0x26, 0x8e, 0xd1, 0xb5, 0xd7, 0xc9, 0xc7, 0x30, 0x4f, 0x9c, 0xae, 0x5f, 0xc4,
                     0x37, 0xb4, 0xcd, 0x3a, 0xeb, 0xe2, 0xec, 0x65, 0xf0, 0xd8, 0x5c, 0x39, 0x18,
                     0xd3, 0xd3, 0xb5, 0xbb, 0xa8, 0x9b],
            nonce:  [0x9e, 0xd9, 0xd8, 0x18, 0x05, 0x64, 0xe0, 0xe9, 0x45, 0xf5, 0xe5, 0xd4],
            c:      [0x79, 0x1a, 0x4a, 0x02, 0x6f, 0x16, 0xf3, 0xa5, 0xea, 0x06, 0x27, 0x4b, 0xf0,
                     0x2b, 0xaa, 0xb4, 0x69, 0x86, 0x0a, 0xbd, 0xe5, 0xe6, 0x45, 0xf3, 0xdd, 0x47,
                     0x3a, 0x5a, 0xcd, 0xde, 0xec, 0xfc],
            mac:    [0x05, 0xb2, 0xb7, 0x4d, 0xb0, 0x66, 0x25, 0x50, 0x43, 0x5e, 0xf1, 0x90, 0x0e,
                     0x13, 0x6b, 0x15],
        },
        {
            msg:    [0x93, 0x78, 0xa7, 0x27, 0xa5, 0x11, 0x95, 0x95, 0xad, 0x63, 0x1b, 0x12, 0xa5,
                     0xa6, 0xbc, 0x8a, 0x91, 0x75, 0x6e, 0xf0, 0x9c, 0x8d, 0x6e, 0xaa, 0x2b, 0x71,
                     0x8f, 0xe8, 0x68, 0x76, 0xda, 0x20],
            ad:     [0xfd, 0x09, 0x20, 0xfa, 0xeb, 0x7b, 0x21, 0x29, 0x32, 0x28, 0x0a, 0x00, 0x9b,
                     0xac, 0x96, 0x91, 0x45, 0xe5, 0xc3, 0x16, 0xcf, 0x39, 0x22, 0x62, 0x2c, 0x37,
                     0x05, 0xc3, 0x45, 0x7c, 0x4e, 0x9f, 0x12, 0x4b, 0x20, 0x76, 0x99, 0x43, 0x23,
                     0xfb, 0xcf, 0xb5, 0x23, 0xf8, 0xed, 0x16, 0xd2, 0x41],
            key:    [0xdc, 0x77, 0x6f, 0x01, 0x56, 0xc1, 0x5d, 0x03, 0x26, 0x23, 0x85, 0x4b, 0x62,
                     0x5c, 0x61, 0x86, 0x8e, 0x5d, 0xb8, 0x4b, 0x7b, 0x6f, 0x9f, 0xbd, 0x36, 0x72,
                     0xf1, 0x2f, 0x00, 0x25, 0xe0, 0xf6],
            nonce:  [0x67, 0x13, 0x09, 0x51, 0xc4, 0xa5, 0x7f, 0x6a, 0xe7, 0xf1, 0x32, 0x41],
            c:      [0x6d, 0x95, 0x8c, 0x20, 0x87, 0x0d, 0x40, 0x1a, 0x3c, 0x1f, 0x7a, 0x0a, 0xc0,
                     0x92, 0xc9, 0x77, 0x74, 0xd4, 0x51, 0xc0, 0x9f, 0x7a, 0xae, 0x99, 0x2a, 0x88,
                     0x41, 0xff, 0x0a, 0xb9, 0xd6, 0x0d],
            mac:    [0xb8, 0x76, 0x83, 0x1b, 0x4e, 0xcd, 0x72, 0x42, 0x96, 0x3b, 0x04, 0x0a, 0xa4,
                     0x5c, 0x41, 0x14],
        },
        {
            msg:    [0x06, 0xb2, 0xc7, 0x58, 0x53, 0xdf, 0x9a, 0xeb, 0x17, 0xbe, 0xfd, 0x33, 0xce,
                     0xa8, 0x1c, 0x63, 0x0b, 0x0f, 0xc5, 0x36, 0x67, 0xff, 0x45, 0x19, 0x9c, 0x62,
                     0x9c, 0x8e, 0x15, 0xdc, 0xe4, 0x1e, 0x53, 0x0a, 0xa7, 0x92, 0xf7, 0x96, 0xb8,
                     0x13, 0x8e, 0xea, 0xb2, 0xe8, 0x6c, 0x7b, 0x7b, 0xee, 0x1d, 0x40, 0xb0],
            ad:     [],
            key:    [0x1f, 0xde, 0xd3, 0x2d, 0x59, 0x99, 0xde, 0x4a, 0x76, 0xe0, 0xf8, 0x08, 0x21,
                     0x08, 0x82, 0x3a, 0xef, 0x60, 0x41, 0x7e, 0x18, 0x96, 0xcf, 0x42, 0x18, 0xa2,
                     0xfa, 0x90, 0xf6, 0x32, 0xec, 0x8a],
            nonce:  [0x1f, 0x3a, 0xfa, 0x47, 0x11, 0xe9, 0x47, 0x4f, 0x32, 0xe7, 0x04, 0x62],
            c:      [0x91, 0xfb, 0xd0, 0x61, 0xdd, 0xc5, 0xa7, 0xfc, 0xc9, 0x51, 0x3f, 0xcd, 0xfd,
                     0xc9, 0xc3, 0xa7, 0xc5, 0xd4, 0xd6, 0x4c, 0xed, 0xf6, 0xa9, 0xc2, 0x4a, 0xb8,
                     0xa7, 0x7c, 0x36, 0xee, 0xfb, 0xf1, 0xc5, 0xdc, 0x00, 0xbc, 0x50, 0x12, 0x1b,
                     0x96, 0x45, 0x6c, 0x8c, 0xd8, 0xb6, 0xff, 0x1f, 0x8b, 0x3e, 0x48, 0x0f],
            mac:    [0x30, 0x09, 0x6d, 0x34, 0x0f, 0x3d, 0x5c, 0x42, 0xd8, 0x2a, 0x6f, 0x47, 0x5d,
                     0xef, 0x23, 0xeb],
        },
        {
            msg:    [0x9d, 0x0b, 0x15, 0xfd, 0xf1, 0xbd, 0x59, 0x5f, 0x91, 0xf8, 0xb3, 0xab, 0xc0,
                     0xf7, 0xde, 0xc9, 0x27, 0xdf, 0xd4, 0x79, 0x99, 0x35, 0xa1, 0x79, 0x5d, 0x9c,
                     0xe0, 0x0c, 0x9b, 0x87, 0x94, 0x34, 0x42, 0x0f, 0xe4, 0x2c, 0x27, 0x5a, 0x7c,
                     0xd7, 0xb3, 0x9d, 0x63, 0x8f, 0xb8, 0x1c, 0xa5, 0x2b, 0x49, 0xdc, 0x41],
            ad:     [0xe4, 0xf9, 0x63, 0xf0, 0x15, 0xff, 0xbb, 0x99, 0xee, 0x33, 0x49, 0xbb, 0xaf,
                     0x7e, 0x8e, 0x8e, 0x6c, 0x2a, 0x71, 0xc2, 0x30, 0xa4, 0x8f, 0x9d, 0x59, 0x86,
                     0x0a, 0x29, 0x09, 0x1d, 0x27, 0x47, 0xe0, 0x1a, 0x5c, 0xa5, 0x72, 0x34, 0x7e,
                     0x24, 0x7d, 0x25, 0xf5, 0x6b, 0xa7, 0xae, 0x8e, 0x05, 0xcd, 0xe2, 0xbe, 0x3c,
                     0x97, 0x93, 0x12, 0x92, 0xc0, 0x23, 0x70, 0x20, 0x8e, 0xcd, 0x09, 0x7e, 0xf6,
                     0x92, 0x68, 0x7f, 0xec, 0xf2, 0xf4, 0x19, 0xd3, 0x20, 0x01, 0x62, 0xa6, 0x48,
                     0x0a, 0x57, 0xda, 0xd4, 0x08, 0xa0, 0xdf, 0xeb, 0x49, 0x2e, 0x2c, 0x5d],
            key:    [0x14, 0x85, 0x79, 0xa3, 0xcb, 0xca, 0x86, 0xd5, 0x52, 0x0d, 0x66, 0xc0, 0xec,
                     0x71, 0xca, 0x5f, 0x7e, 0x41, 0xba, 0x78, 0xe5, 0x6d, 0xc6, 0xee, 0xbd, 0x56,
                     0x6f, 0xed, 0x54, 0x7f, 0xe6, 0x91],
            nonce:  [0xb0, 0x8a, 0x5e, 0xa1, 0x92, 0x74, 0x99, 0xc6, 0xec, 0xbf, 0xd4, 0xe0],
            c:      [0x20, 0x97, 0xe3, 0x72, 0x95, 0x0a, 0x5e, 0x93, 0x83, 0xc6, 0x75, 0xe8, 0x9e,
                     0xea, 0x1c, 0x31, 0x4f, 0x99, 0x91, 0x59, 0xf5, 0x61, 0x13, 0x44, 0xb2, 0x98,
                     0xcd, 0xa4, 0x5e, 0x62, 0x84, 0x37, 0x16, 0xf2, 0x15, 0xf8, 0x2e, 0xe6, 0x63,
                     0x91, 0x9c, 0x64, 0x00, 0x2a, 0x5c, 0x19, 0x8d, 0x78, 0x78, 0xfd, 0x3f],
            mac:    [0xad, 0xbe, 0xcd, 0xb0, 0xd5, 0xc2, 0x22, 0x4d, 0x80, 0x4d, 0x28, 0x86, 0xff,
                     0x9a, 0x57, 0x60],
        },
    ];
}
