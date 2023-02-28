//! The [XChaCha20](https://cr.yp.to/chacha.html) cipher with a
//! [Poly1305](https://en.wikipedia.org/wiki/Poly1305) MAC.
//!
//! This module corresponds to the [`crypto_aead_xchacha20poly1305_ietf`
//! API](https://doc.libsodium.org/secret-key_cryptography/aead/chacha20-poly1305/xchacha20-poly1305_construction)
//! from Sodium.
//!
//! # Security Considerations
//! For this algorithm, nonces must *never* be used more than once with the same key. If you supply
//! `None` as the nonce for [`encrypt`] or [`encrypt_detached`], a nonce will be randomly generated
//! for you, and the chance of nonce-reuse is effectively zero. However, if you need to specify your
//! own nonces for each message, please ensure a given nonce is never reused: Random nonce
//! generation with [`generate_nonce`] will probably be your best strategy.
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
//!
//! # Examples
//! Encryption and decryption (uses [`encrypt`] and [`decrypt`]):
//!
//! ```rust
//! use alkali::symmetric::aead::xchacha20poly1305_ietf as aead;
//!
//! const MESSAGE: &'static str = "Here's a message to encrypt. It can be of any length.";
//! const AD: &'static str = "This is additional non-secret data which will also be authenticated.";
//!
//! // Prior to communication:
//!
//! // A random secret key is generated & distributed to all parties.
//! let key = aead::Key::generate().unwrap();
//!
//!
//! // ...
//!
//!
//! // Sender side:
//! // We assume the sender knows `key`.
//!
//! // The encrypted message will be `MAC_LENGTH` bytes longer than the original message.
//! let mut ciphertext = vec![0u8; MESSAGE.as_bytes().len() + aead::MAC_LENGTH];
//! // If this function is successful, the ciphertext + a MAC will be stored in `ciphertext`. A
//! // random nonce will be generated for this message, and returned to be stored in `nonce`. We
//! // will need this to perform the decryption.
//! let (_, nonce) = aead::encrypt(
//!     MESSAGE.as_bytes(), Some(AD.as_bytes()), &key, None, &mut ciphertext
//! ).unwrap();
//!
//!
//! // ...
//!
//!
//! // Receiver side:
//! // We assume the receiver knows `key`.
//!
//! let mut plaintext = vec![0u8; ciphertext.len() - aead::MAC_LENGTH];
//! // The `decrypt` function not only decrypts `ciphertext`, but also verifies the authenticity of
//! // the encrypted message and the additional data using the included MAC. This operation will
//! // fail if a forgery is attempted.
//! aead::decrypt(&ciphertext, Some(AD.as_bytes()), &key, &nonce, &mut plaintext).unwrap();
//! assert_eq!(&plaintext, MESSAGE.as_bytes());
//! ```
//!
//! Detached encryption and decryption (uses [`encrypt_detached`] and [`decrypt_detached`]):
//!
//! ```rust
//! use alkali::symmetric::aead::xchacha20poly1305_ietf as aead;
//!
//! const MESSAGE: &'static str = "Another encryption example!";
//! const AD: &'static str = "Some more additional data to authenticate.";
//!
//! // Prior to communication:
//!
//! // A random secret key is generated & distributed to all parties.
//! let key = aead::Key::generate().unwrap();
//!
//!
//! // ...
//!
//!
//! // Sender side:
//! // We assume the sender knows `key`.
//!
//! // In detached mode, the ciphertext length is identical to the plaintext length.
//! let mut ciphertext = vec![0u8; MESSAGE.as_bytes().len()];
//! // The `encrypt_detached` function will return the MAC of the message separately.
//! let (_, nonce, mac) = aead::encrypt_detached(
//!     MESSAGE.as_bytes(), Some(AD.as_bytes()), &key, None, &mut ciphertext
//! ).unwrap();
//!
//!
//! // ...
//!
//!
//! // Receiver side:
//! // We assume the receiver knows `key`.
//!
//! let mut plaintext = vec![0u8; ciphertext.len()];
//! // We will need to pass the MAC as anothe argument to the detached decryption function.
//! aead::decrypt_detached(&ciphertext, Some(AD.as_bytes()), &mac, &key, &nonce, &mut plaintext)
//!     .unwrap();
//! ```

use super::AEADError;
use crate::{assert_not_err, mem, random, require_init, AlkaliError};
use core::ptr;
use libsodium_sys as sodium;

/// The length of a symmetric key used for this AEAD construction, in bytes.
pub const KEY_LENGTH: usize = sodium::crypto_aead_xchacha20poly1305_ietf_KEYBYTES as usize;

/// The length of a MAC, in bytes.
pub const MAC_LENGTH: usize = sodium::crypto_aead_xchacha20poly1305_ietf_ABYTES as usize;

/// The length of a message nonce, in bytes.
pub const NONCE_LENGTH: usize = sodium::crypto_aead_xchacha20poly1305_ietf_NPUBBYTES as usize;

lazy_static::lazy_static! {
    /// The maximum message length which can be encrypted with this cipher, in bytes.
    pub static ref MESSAGE_LENGTH_MAX: usize = unsafe {
        // SAFETY: This function just returns a constant value, and should always be safe to call.
        sodium::crypto_aead_xchacha20poly1305_ietf_messagebytes_max()
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
    /// implements [`core::ops::Deref`] so it can be used like it is an `&[u8]`. This struct uses
    /// heap memory while in scope, allocated using Sodium's [secure memory
    /// utilities](https://doc.libsodium.org/memory_management).
    pub Key(KEY_LENGTH);
}

impl Key<mem::FullAccess> {
    /// Generate a new, random key for use with this AEAD construction.
    pub fn generate() -> Result<Self, AlkaliError> {
        require_init()?;

        let mut key = Self::new_empty()?;
        unsafe {
            // SAFETY: This function expects a pointer to a region of memory sufficient to store
            // a key. The `Key` type allocates `crypto_aead_xchacha20poly1305_ietf_KEYBYTES`
            // bytes, the length of a key for this algorithm. It is therefore valid for writes
            // of the required length. The `Key::inner_mut` method simply returns a mutable
            // pointer to the struct's backing memory.
            sodium::crypto_aead_xchacha20poly1305_ietf_keygen(key.inner_mut().cast());
        }
        Ok(key)
    }
}

/// A MAC (Message Authentication Code), used to authenticate an encrypted message and any
/// associated data.
///
/// If using [`encrypt`], the MAC is included in the ciphertext. It is returned separately in the
/// [`encrypt_detached`] variant.
pub type MAC = [u8; MAC_LENGTH];

/// A nonce, used to introduce non-determinism into the keystream calculation.
///
/// Nonces must never be used for multiple messages with the same key. Ideally, let alkali generate
/// a random nonce for every message by specifying `None` as the nonce for
/// [`encrypt`]/[`encrypt_detached`].
pub type Nonce = [u8; NONCE_LENGTH];

/// Generate a random nonce for use with this AEAD construction.
///
/// It is vital that a given nonce is never used to encrypt more than one message under the same
/// key. XChaCha20 has a sufficient nonce size that we can simply generate a random nonce for
/// every message we wish to encrypt, and the chances of reusing a nonce are essentially zero.
/// Note that the same does not apply to the other AEAD constructions from Sodium!
///
/// Returns a random nonce, or a [`crate::AlkaliError`] if an error occurred.
pub fn generate_nonce() -> Result<Nonce, AlkaliError> {
    let mut nonce = [0; NONCE_LENGTH];
    random::fill_random(&mut nonce)?;
    Ok(nonce)
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
/// encryption process. It is recommended that this be set to `None`, which will cause alkali to
/// randomly generate a nonce for the message. If you specify a custom nonce, it is vital that the
/// nonce is never used to encrypt more than one message under the same key: Nonce reuse destroys
/// the security of the scheme. Nonces are not secret, but will need to be communicated to the
/// decrypting party for them to be able to decrypt the message. This function will return the nonce
/// used for the encryption of this message.
///
/// The encrypted ciphertext will be written to `output`. The ciphertext will be [`MAC_LENGTH`]
/// bytes longer than `message`, so `output` must be of sufficient size to store at least this many
/// bytes. An error will be returned if `output` is not sufficient to store the ciphertext.
///
/// If encryption is successful, returns the number of bytes written to `output` (this will actually
/// always be `message.len()` + [`MAC_LENGTH`] bytes), and the [`Nonce`] used for the encryption
/// process.
///
/// # Security Considerations
/// Nonces must *never* be used more than once with the same key. You should specify `None` for the
/// nonce to use, which will cause a random nonce to be generated for every message, unless you have
/// good reason to do otherwise.
pub fn encrypt(
    message: &[u8],
    ad: Option<&[u8]>,
    key: &Key<impl mem::MprotectReadable>,
    nonce: Option<&Nonce>,
    output: &mut [u8],
) -> Result<(usize, Nonce), AlkaliError> {
    require_init()?;

    let c_len = message.len() + MAC_LENGTH;

    if output.len() < c_len {
        return Err(AEADError::OutputInsufficient.into());
    } else if message.len() > *MESSAGE_LENGTH_MAX {
        return Err(AEADError::MessageTooLong.into());
    }

    let nonce = match nonce {
        Some(&n) => n,
        None => generate_nonce()?,
    };

    let (ad_ptr, ad_len) = match ad {
        Some(ad) => (ad.as_ptr(), ad.len()),
        None => (ptr::null(), 0),
    };

    let encrypt_result = unsafe {
        // SAFETY: The first argument to this function is the destination to which the combined MAC
        // + ciphertext will be written. The ciphertext will be of the same length as the message,
        // and the MAC will always be `crypto_aead_xchacha20poly1305_ietf_ABYTES`, so as long as the
        // output pointer is valid for writes of `message.len() +
        // crypto_aead_xchacha20poly1305_ietf_ABYTES`, it is valid to use here. We verify this
        // condition above, and return an error if the output is insufficient. The next argument is
        // a destination to which the length of the combined MAC + ciphertext will be written. It is
        // documented that if this is set to a null pointer, then it will be ignored. The next two
        // arguments specify the message to encrypt and its length. We use `message.len()` to
        // specify the message length, so `message` is definitely valid for reads of this length.
        // The next two arguments specify a pointer to the additional data to authenticate and the
        // length of the additional data. If additional data is provided, we use `ad.as_ptr()` for
        // the pointer to the additional data, and `ad.len()` for the length of the additional data,
        // so `ad` is clearly valid for reads of this length. If additional data is not provided,
        // we pass a null pointer and a length of zero. It is documented that a null pointer is safe
        // to use here, and Sodium will just not include the additional data in the authentication
        // calculation. The next argument is a pointer to a secret nonce, which is not used for this
        // algorithm, and should always be set to a null pointer, which we do here. The next
        // argument should be a pointer to the nonce to use for encryption. We have defined the
        // `Nonce` type to be `crypto_aead_xchacha20poly1305_ietf_NPUBBYTES` bytes long, the size of
        // a nonce for this algorithm, so it is valid for reads of the required length. The final
        // argument specifies the key with which the message should be encrypted. We have defined
        // the `Key` type to allocate `crypto_aead_xchacha20poly1305_ietf_KEYBYTES` bytes, the
        // length of a key for this algorithm, so it is valid for reads of the required length. The
        // `Key::inner` method simply returns an immutable pointer to its backing memory.
        sodium::crypto_aead_xchacha20poly1305_ietf_encrypt(
            output.as_mut_ptr(),
            ptr::null_mut(),
            message.as_ptr(),
            message.len() as libc::c_ulonglong,
            ad_ptr,
            ad_len as libc::c_ulonglong,
            ptr::null(),
            nonce.as_ptr(),
            key.inner().cast(),
        )
    };
    assert_not_err!(encrypt_result, "crypto_aead_xchacha20poly1305_ietf_encrypt");

    Ok((c_len, nonce))
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
    key: &Key<impl mem::MprotectReadable>,
    nonce: &Nonce,
    output: &mut [u8],
) -> Result<usize, AlkaliError> {
    require_init()?;

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
        // plaintext will be written. The plaintext will be
        // `crypto_aead_xchacha20poly1305_ietf_ABYTES` shorter than the ciphertext, so as long as
        // the output pointer is valid for writes of `ciphertext.len() -
        // crypto_aead_xchacha20poly1305_ietf_ABYTES`, it is valid to use here. We verify this
        // condition above, and return an error if the output is insufficient. The next argument
        // specifies the destination to which the length of the decrypted plaintext will be written.
        // It is documented that if this is set to a null pointer, then it will be ignored. The next
        // argument is a pointer to a secret nonce, which is not used for this algorithm, and should
        // always be set to a null pointer, which we do here. The next two arguments specify the
        // ciphertext to decrypt and its length. We use `ciphertext.len()` to specify the ciphertext
        // length, so `ciphertext` is definitely valid for reads of this length. The next two
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
        // `crypto_aead_xchacha20poly1305_ietf_NPUBBYTES` bytes long, the size of a nonce for this
        // algorithm, so it is valid for reads of the required length. The final argument specifies
        // the key with which the message was encrypted. We have defined the `Key` type to allocate
        // `crypto_aead_xchacha20poly1305_ietf_KEYBYTES` bytes, the length of a key for this
        // algorithm, so it is valid for reads of the required length. The `Key::inner` method
        // simply returns an immutable pointer to its backing memory.
        sodium::crypto_aead_xchacha20poly1305_ietf_decrypt(
            output.as_mut_ptr(),
            ptr::null_mut(),
            ptr::null_mut(),
            ciphertext.as_ptr(),
            ciphertext.len() as libc::c_ulonglong,
            ad_ptr,
            ad_len as libc::c_ulonglong,
            nonce.as_ptr(),
            key.inner().cast(),
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
/// encryption process. It is recommended that this be set to `None`, which will cause alkali to
/// randomly generate a nonce for the message. If you specify a custom nonce, it is vital that the
/// nonce is never used to encrypt more than one message under the same key: Nonce reuse destroys
/// the security of the scheme. Nonces are not secret, but will need to be communicated to the
/// decrypting party for them to be able to decrypt the message. This function will return the nonce
/// used for the encryption of this message.
///
/// The encrypted ciphertext will be written to `output`. The ciphertext will the same length as
/// `message`, so `output` must be of sufficient size to store at least this many bytes. An error
/// will be returned if `output` is not sufficient to store the ciphertext.
///
/// If encryption is successful, returns the number of bytes written to `output` (this will actually
/// always be `message.len()` bytes), the [`Nonce`] used for the encryption process, and the
/// authentication tag for the message + additional data (a [`MAC`]).
///
/// # Security Considerations
/// Nonces must *never* be used more than once with the same key. You should specify `None` for the
/// nonce to use, which will cause a random nonce to be generated for every message, unless you have
/// good reason to do otherwise.
pub fn encrypt_detached(
    message: &[u8],
    ad: Option<&[u8]>,
    key: &Key<impl mem::MprotectReadable>,
    nonce: Option<&Nonce>,
    output: &mut [u8],
) -> Result<(usize, Nonce, MAC), AlkaliError> {
    require_init()?;

    if output.len() < message.len() {
        return Err(AEADError::OutputInsufficient.into());
    } else if message.len() > *MESSAGE_LENGTH_MAX {
        return Err(AEADError::MessageTooLong.into());
    }

    let nonce = match nonce {
        Some(&n) => n,
        None => generate_nonce()?,
    };

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
        // to be `crypto_aead_xchacha20poly1305_ietf_ABYTES`, the length of a MAC for this
        // algorithm, so it is valid for writes of the required length. The next argument is a
        // destination to which the length of the calculated MAC will be written. It is documented
        // that if this is set to a null pointer, then it will be ignored. The next two arguments
        // specify the message to encrypt and its length. We use `message.len()` to specify the
        // message length, so `message` is definitely valid for reads of this length. The next two
        // arguments specify a pointer to the additional data to authenticate and the length of the
        // additional data. If additional data is provided, we use `ad.as_ptr()` for the pointer to
        // the additional data, and `ad.len()` for the length of the additional data, so `ad` is
        // clearly valid for reads of this length. If additional data is not provided, we pass a
        // null pointer and a length of zero. It is documented that a null pointer is safe to use
        // here, and Sodium will just not include the additional data in the authentication
        // calculation. The next argument is a pointer to a secret nonce, which is not used for this
        // algorithm, and should always be set to a null pointer, which we do here. The next
        // argument should be a pointer to the nonce to use for encryption. We have defined the
        // `Nonce` type to be `crypto_aead_xchacha20poly1305_ietf_NPUBBYTES` bytes long, the size of
        // a nonce for this algorithm, so it is valid for reads of the required length. The final
        // argument specifies the key with which the message should be encrypted. We have defined
        // the `Key` type to allocate `crypto_aead_xchacha20poly1305_ietf_KEYBYTES` bytes, the
        // length of a key for this algorithm, so it is valid for reads of the required length. The
        // `Key::inner` method simply returns an immutable pointer to its backing memory.
        sodium::crypto_aead_xchacha20poly1305_ietf_encrypt_detached(
            output.as_mut_ptr(),
            mac.as_mut_ptr(),
            ptr::null_mut(),
            message.as_ptr(),
            message.len() as libc::c_ulonglong,
            ad_ptr,
            ad_len as libc::c_ulonglong,
            ptr::null(),
            nonce.as_ptr(),
            key.inner().cast(),
        )
    };
    assert_not_err!(encrypt_result, "crypto_aead_xchacha20poly1305_ietf_encrypt");

    Ok((message.len(), nonce, mac))
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
    key: &Key<impl mem::MprotectReadable>,
    nonce: &Nonce,
    output: &mut [u8],
) -> Result<usize, AlkaliError> {
    require_init()?;

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
        // data. The `MAC` type is defined to be `crypto_aead_xchacha20poly1305_ietf_ABYTES`, the
        // length of a MAC for this algorithm, so `mac` is valid for reads of the required length.
        // The next two arguments specify a pointer to the additional data to authenticate and the
        // length of the additional data. If additional data is provided, we use `ad.as_ptr()` for
        // the pointer to the additional data, and `ad.len()` for the length of the additional data,
        // so `ad` is clearly valid for reads of this length. If additional data is provided, we use
        // `ad.as_ptr()` for the pointer to the additional data, and `ad.len()` for the length of
        // the additional data, so `ad` is clearly valid for reads of this length. If additional
        // data is not provided, we pass a null pointer and a length of zero. It is documented that
        // a null pointer is safe to use here, and Sodium will just not include the additional data
        // in the authentication calculation. The next argument is should be a pointer to the nonce
        // which was used for encryption. We have defined the `Nonce` type to be
        // `crypto_aead_xchacha20poly1305_ietf_NPUBBYTES` bytes long, the size of a nonce for this
        // algorithm, so it is valid for reads of the required length. The final argument specifies
        // the key with which the message was encrypted. We have defined the `Key` type to allocate
        // `crypto_aead_xchacha20poly1305_ietf_KEYBYTES` bytes, the length of a key for this
        // algorithm, so it is valid for reads of the required length. The `Key::inner` method
        // simply returns an immutable pointer to its backing memory.
        sodium::crypto_aead_xchacha20poly1305_ietf_decrypt_detached(
            output.as_mut_ptr(),
            ptr::null_mut(),
            ciphertext.as_ptr(),
            ciphertext.len() as libc::c_ulonglong,
            mac.as_ptr(),
            ad_ptr,
            ad_len as libc::c_ulonglong,
            nonce.as_ptr(),
            key.inner().cast(),
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
    use super::{
        decrypt, decrypt_detached, encrypt, encrypt_detached, generate_nonce, Key, MAC_LENGTH,
    };
    use crate::random;
    use crate::AlkaliError;

    #[test]
    fn key_generation() -> Result<(), AlkaliError> {
        let _key = Key::generate()?;
        Ok(())
    }

    #[test]
    fn nonce_generation() -> Result<(), AlkaliError> {
        let _nonce = generate_nonce()?;
        Ok(())
    }

    #[test]
    fn enc_and_dec() -> Result<(), AlkaliError> {
        let key = Key::generate()?;

        let mut msg_a = [];
        let mut msg_b = [0; 16];
        let mut msg_c = [0; 1024];
        let mut msg_d = [0; 1 << 18];
        let mut ad = [0; 1024];

        random::fill_random(&mut msg_b)?;
        random::fill_random(&mut msg_c)?;
        random::fill_random(&mut msg_d)?;
        random::fill_random(&mut ad)?;

        let mut c_a = [0; MAC_LENGTH];
        let mut c_b = [0; 16 + MAC_LENGTH];
        let mut c_c = [0; 1024 + MAC_LENGTH];
        let mut c_d = [0; (1 << 18) + MAC_LENGTH];

        let (l_a, nonce_a) = encrypt(&msg_a, None, &key, None, &mut c_a)?;
        let (l_b, nonce_b) = encrypt(&msg_b, None, &key, None, &mut c_b)?;
        let (l_c, nonce_c) = encrypt(&msg_c, None, &key, None, &mut c_c)?;
        let (l_d, nonce_d) = encrypt(&msg_d, None, &key, None, &mut c_d)?;

        assert_eq!(l_a, MAC_LENGTH);
        assert_eq!(l_b, 16 + MAC_LENGTH);
        assert_eq!(l_c, 1024 + MAC_LENGTH);
        assert_eq!(l_d, (1 << 18) + MAC_LENGTH);

        assert_eq!(decrypt(&c_a, None, &key, &nonce_a, &mut msg_a)?, 0);
        assert_eq!(decrypt(&c_b, None, &key, &nonce_b, &mut msg_b)?, 16);
        assert_eq!(decrypt(&c_c, None, &key, &nonce_c, &mut msg_c)?, 1024);
        assert_eq!(decrypt(&c_d, None, &key, &nonce_d, &mut msg_d)?, 1 << 18);

        let (l_a, nonce_a) = encrypt(&msg_a, Some(&ad), &key, None, &mut c_a)?;
        let (l_b, nonce_b) = encrypt(&msg_b, Some(&ad), &key, None, &mut c_b)?;
        let (l_c, nonce_c) = encrypt(&msg_c, Some(&ad), &key, None, &mut c_c)?;
        let (l_d, nonce_d) = encrypt(&msg_d, Some(&ad), &key, None, &mut c_d)?;

        assert_eq!(l_a, MAC_LENGTH);
        assert_eq!(l_b, 16 + MAC_LENGTH);
        assert_eq!(l_c, 1024 + MAC_LENGTH);
        assert_eq!(l_d, (1 << 18) + MAC_LENGTH);

        assert_eq!(decrypt(&c_a, Some(&ad), &key, &nonce_a, &mut msg_a)?, 0);
        assert_eq!(decrypt(&c_b, Some(&ad), &key, &nonce_b, &mut msg_b)?, 16);
        assert_eq!(decrypt(&c_c, Some(&ad), &key, &nonce_c, &mut msg_c)?, 1024);
        assert_eq!(
            decrypt(&c_d, Some(&ad), &key, &nonce_d, &mut msg_d)?,
            1 << 18
        );

        assert!(decrypt(&c_a, None, &key, &nonce_a, &mut msg_a).is_err());
        assert!(decrypt(&c_b, None, &key, &nonce_b, &mut msg_b).is_err());
        assert!(decrypt(&c_c, Some(&ad[..1023]), &key, &nonce_c, &mut msg_c).is_err());
        random::fill_random(&mut ad)?;
        assert!(decrypt(&c_d, Some(&ad), &key, &nonce_d, &mut msg_d).is_err());

        Ok(())
    }

    #[test]
    fn enc_and_dec_detached() -> Result<(), AlkaliError> {
        let key = Key::generate()?;

        let mut msg_a = [];
        let mut msg_b = [0; 16];
        let mut msg_c = [0; 1024];
        let mut msg_d = [0; 1 << 18];
        let mut ad = [0; 1024];

        random::fill_random(&mut msg_b)?;
        random::fill_random(&mut msg_c)?;
        random::fill_random(&mut msg_d)?;
        random::fill_random(&mut ad)?;

        let mut c_a = [];
        let mut c_b = [0; 16];
        let mut c_c = [0; 1024];
        let mut c_d = [0; 1 << 18];

        let (l_a, nonce_a, mac_a) = encrypt_detached(&msg_a, None, &key, None, &mut c_a)?;
        let (l_b, nonce_b, mac_b) = encrypt_detached(&msg_b, None, &key, None, &mut c_b)?;
        let (l_c, nonce_c, mac_c) = encrypt_detached(&msg_c, None, &key, None, &mut c_c)?;
        let (l_d, nonce_d, mac_d) = encrypt_detached(&msg_d, None, &key, None, &mut c_d)?;

        assert_eq!(l_a, 0);
        assert_eq!(l_b, 16);
        assert_eq!(l_c, 1024);
        assert_eq!(l_d, 1 << 18);

        assert_eq!(
            decrypt_detached(&c_a, None, &mac_a, &key, &nonce_a, &mut msg_a)?,
            0
        );
        assert_eq!(
            decrypt_detached(&c_b, None, &mac_b, &key, &nonce_b, &mut msg_b)?,
            16
        );
        assert_eq!(
            decrypt_detached(&c_c, None, &mac_c, &key, &nonce_c, &mut msg_c)?,
            1024
        );
        assert_eq!(
            decrypt_detached(&c_d, None, &mac_d, &key, &nonce_d, &mut msg_d)?,
            1 << 18
        );

        let (l_a, nonce_a, mac_a) = encrypt_detached(&msg_a, Some(&ad), &key, None, &mut c_a)?;
        let (l_b, nonce_b, mac_b) = encrypt_detached(&msg_b, Some(&ad), &key, None, &mut c_b)?;
        let (l_c, nonce_c, mac_c) = encrypt_detached(&msg_c, Some(&ad), &key, None, &mut c_c)?;
        let (l_d, nonce_d, mac_d) = encrypt_detached(&msg_d, Some(&ad), &key, None, &mut c_d)?;

        assert_eq!(l_a, 0);
        assert_eq!(l_b, 16);
        assert_eq!(l_c, 1024);
        assert_eq!(l_d, 1 << 18);

        assert_eq!(
            decrypt_detached(&c_a, Some(&ad), &mac_a, &key, &nonce_a, &mut msg_a)?,
            0
        );
        assert_eq!(
            decrypt_detached(&c_b, Some(&ad), &mac_b, &key, &nonce_b, &mut msg_b)?,
            16
        );
        assert_eq!(
            decrypt_detached(&c_c, Some(&ad), &mac_c, &key, &nonce_c, &mut msg_c)?,
            1024
        );
        assert_eq!(
            decrypt_detached(&c_d, Some(&ad), &mac_d, &key, &nonce_d, &mut msg_d)?,
            1 << 18
        );

        assert!(decrypt_detached(&c_a, None, &mac_a, &key, &nonce_a, &mut msg_a).is_err());
        assert!(decrypt_detached(&c_b, None, &mac_b, &key, &nonce_b, &mut msg_b).is_err());
        assert!(
            decrypt_detached(&c_c, Some(&ad[..1023]), &mac_c, &key, &nonce_c, &mut msg_c).is_err()
        );
        random::fill_random(&mut ad)?;
        assert!(decrypt_detached(&c_d, Some(&ad), &mac_d, &key, &nonce_d, &mut msg_d).is_err());

        Ok(())
    }

    #[test]
    fn test_vectors() -> Result<(), AlkaliError> {
        let mut key = Key::try_from(&[
            0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d,
            0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b,
            0x9c, 0x9d, 0x9e, 0x9f,
        ])?;
        let mut message = [
            0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x47, 0x65, 0x6e,
            0x74, 0x6c, 0x65, 0x6d, 0x65, 0x6e, 0x20, 0x6f, 0x66, 0x20, 0x74, 0x68, 0x65, 0x20,
            0x63, 0x6c, 0x61, 0x73, 0x73, 0x20, 0x6f, 0x66, 0x20, 0x27, 0x39, 0x39, 0x3a, 0x20,
            0x49, 0x66, 0x20, 0x49, 0x20, 0x63, 0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6f, 0x66, 0x66,
            0x65, 0x72, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x6f, 0x6e, 0x6c, 0x79, 0x20, 0x6f, 0x6e,
            0x65, 0x20, 0x74, 0x69, 0x70, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x74, 0x68, 0x65, 0x20,
            0x66, 0x75, 0x74, 0x75, 0x72, 0x65, 0x2c, 0x20, 0x73, 0x75, 0x6e, 0x73, 0x63, 0x72,
            0x65, 0x65, 0x6e, 0x20, 0x77, 0x6f, 0x75, 0x6c, 0x64, 0x20, 0x62, 0x65, 0x20, 0x69,
            0x74, 0x2e,
        ];
        let mut m2 = message;
        let nonce = [
            0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49,
            0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53,
        ];
        let ad = [
            0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
        ];
        let mut c = [0u8; 114 + MAC_LENGTH];
        let mut c_detached = [0u8; 114];

        // Test encryption with AD
        assert_eq!(
            encrypt(&message, Some(&ad), &key, Some(&nonce), &mut c)?,
            (114 + MAC_LENGTH, nonce)
        );
        assert_eq!(
            c,
            [
                0xf8, 0xeb, 0xea, 0x48, 0x75, 0x04, 0x40, 0x66, 0xfc, 0x16, 0x2a, 0x06, 0x04, 0xe1,
                0x71, 0xfe, 0xec, 0xfb, 0x3d, 0x20, 0x42, 0x52, 0x48, 0x56, 0x3b, 0xcf, 0xd5, 0xa1,
                0x55, 0xdc, 0xc4, 0x7b, 0xbd, 0xa7, 0x0b, 0x86, 0xe5, 0xab, 0x9b, 0x55, 0x00, 0x2b,
                0xd1, 0x27, 0x4c, 0x02, 0xdb, 0x35, 0x32, 0x1a, 0xcd, 0x7a, 0xf8, 0xb2, 0xe2, 0xd2,
                0x50, 0x15, 0xe1, 0x36, 0xb7, 0x67, 0x94, 0x58, 0xe9, 0xf4, 0x32, 0x43, 0xbf, 0x71,
                0x9d, 0x63, 0x9b, 0xad, 0xb5, 0xfe, 0xac, 0x03, 0xf8, 0x0a, 0x19, 0xa9, 0x6e, 0xf1,
                0x0c, 0xb1, 0xd1, 0x53, 0x33, 0xa8, 0x37, 0xb9, 0x09, 0x46, 0xba, 0x38, 0x54, 0xee,
                0x74, 0xda, 0x3f, 0x25, 0x85, 0xef, 0xc7, 0xe1, 0xe1, 0x70, 0xe1, 0x7e, 0x15, 0xe5,
                0x63, 0xe7, 0x76, 0x01, 0xf4, 0xf8, 0x5c, 0xaf, 0xa8, 0xe5, 0x87, 0x76, 0x14, 0xe1,
                0x43, 0xe6, 0x84, 0x20
            ]
        );
        let (l, n, mac) =
            encrypt_detached(&message, Some(&ad), &key, Some(&nonce), &mut c_detached)?;
        assert_eq!(l, 114);
        assert_eq!(n, nonce);
        assert_eq!(
            mac,
            [
                0x76, 0x01, 0xf4, 0xf8, 0x5c, 0xaf, 0xa8, 0xe5, 0x87, 0x76, 0x14, 0xe1, 0x43, 0xe6,
                0x84, 0x20
            ]
        );
        assert_eq!(&c_detached, &c[..114]);

        // Make sure decryption produces the original message
        assert_eq!(decrypt(&c, Some(&ad), &key, &nonce, &mut message)?, 114);
        assert_eq!(message, m2);
        assert_eq!(
            decrypt_detached(&c_detached, Some(&ad), &mac, &key, &nonce, &mut message)?,
            114
        );
        assert_eq!(message, m2);

        // Ensure modifying the ciphertext causes an error
        for i in 0..114 {
            c[i] ^= (i + 1) as u8;
            assert!(decrypt(&c, Some(&ad), &key, &nonce, &mut m2).is_err());
            c[i] ^= (i + 1) as u8;
        }

        // Test encryption without AD
        assert_eq!(
            encrypt(&message, None, &key, Some(&nonce), &mut c)?,
            (114 + MAC_LENGTH, nonce)
        );
        assert_eq!(
            c,
            [
                0xf8, 0xeb, 0xea, 0x48, 0x75, 0x04, 0x40, 0x66, 0xfc, 0x16, 0x2a, 0x06, 0x04, 0xe1,
                0x71, 0xfe, 0xec, 0xfb, 0x3d, 0x20, 0x42, 0x52, 0x48, 0x56, 0x3b, 0xcf, 0xd5, 0xa1,
                0x55, 0xdc, 0xc4, 0x7b, 0xbd, 0xa7, 0x0b, 0x86, 0xe5, 0xab, 0x9b, 0x55, 0x00, 0x2b,
                0xd1, 0x27, 0x4c, 0x02, 0xdb, 0x35, 0x32, 0x1a, 0xcd, 0x7a, 0xf8, 0xb2, 0xe2, 0xd2,
                0x50, 0x15, 0xe1, 0x36, 0xb7, 0x67, 0x94, 0x58, 0xe9, 0xf4, 0x32, 0x43, 0xbf, 0x71,
                0x9d, 0x63, 0x9b, 0xad, 0xb5, 0xfe, 0xac, 0x03, 0xf8, 0x0a, 0x19, 0xa9, 0x6e, 0xf1,
                0x0c, 0xb1, 0xd1, 0x53, 0x33, 0xa8, 0x37, 0xb9, 0x09, 0x46, 0xba, 0x38, 0x54, 0xee,
                0x74, 0xda, 0x3f, 0x25, 0x85, 0xef, 0xc7, 0xe1, 0xe1, 0x70, 0xe1, 0x7e, 0x15, 0xe5,
                0x63, 0xe7, 0xe0, 0x96, 0xe0, 0x33, 0xd9, 0x1b, 0x63, 0xf7, 0xac, 0x92, 0xe9, 0x97,
                0x2e, 0x0d, 0x43, 0xe5
            ]
        );

        // Make sure decryption produces the original message
        assert_eq!(decrypt(&c, None, &key, &nonce, &mut m2)?, 114);
        assert_eq!(message, m2);

        // A couple of other tests which should fail
        let l = random::random_u32_in_range(0, 114)? as usize;
        assert!(decrypt(&c[..l], None, &key, &nonce, &mut m2).is_err());
        assert!(decrypt(&[], None, &key, &nonce, &mut m2).is_err());
        random::fill_random(key.as_mut())?;
        assert!(decrypt(&c, None, &key, &nonce, &mut m2).is_err());

        Ok(())
    }
}
