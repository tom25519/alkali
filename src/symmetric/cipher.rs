//! Authenticated symmetric encryption.
//!
//! This module corresponds to the [`crypto_secretbox`
//! API](https://doc.libsodium.org/secret-key_cryptography/secretbox) from Sodium.
//!
//! Authenticated encryption is used to encrypt messages, providing assurance to the receiver that
//! the ciphertext has not been modified in transit by an attacker or transmission error. In
//! symmetric encryption, all parties who wish to encrypt or decrypt messages must share the same
//! secret key, which is used for both encryption and decryption.
//!
//! # Algorithm Details
//! This authenticated encryption construction uses the [XSalsa20](xsalsa20poly1305) stream cipher
//! (Salsa20 with an eXtended nonce length) for encryption by default, together with the Poly1305
//! MAC for authentication. [XChaCha20](xchacha20poly1305), which uses an eXtended nonce variant of
//! ChaCha20, is also available.

// TODO: Tests

use thiserror::Error;

/// Error type returned if something went wrong in the `symmetric::cipher` module.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum CipherError {
    /// The output buffer is too short to store the ciphertext/plaintext which would result from
    /// encrypting/decrypting this message.
    ///
    /// Each function in this module should provide information in its documentation about the
    /// output length requirements.
    #[error("the output is insufficient to store ciphertext/plaintext, required {0}, found {1}")]
    OutputInsufficient(usize, usize),

    /// Message too long for encryption/decryption with this cipher.
    ///
    /// Beyond a certain point, the keystream of the cipher is exhausted, and it can no longer be
    /// used to safely encrypt message contents. Therefore, this error is returned if the message
    /// provided is too long. Messages can be at most [`struct@MESSAGE_LENGTH_MAX`] bytes.
    #[error("the message is too long for encryption/decryption with this cipher")]
    MessageTooLong,

    /// Indicates decryption of a provided ciphertext failed.
    ///
    /// This could indicate an attempted forgery, or transmission error.
    #[error("decryption failed: ciphertext appears invalid")]
    DecryptionFailed,
}

/// Generates the API for a `symmetric::cipher` module with the given functions from Sodium for a
/// specific implementation.
macro_rules! cipher_module {
    (
        $key_len:expr,      // crypto_secretbox_KEYBYTES
        $mac_len:expr,      // crypto_secretbox_MACBYTES
        $nonce_len:expr,    // crypto_secretbox_NONCEBYTES
        $msg_max:path,      // crypto_secretbox_messagebytes_max
        $keygen:path,       // crypto_secretbox_keygen
        $encrypt:path,      // crypto_secretbox_easy
        $decrypt:path,      // crypto_secretbox_open_easy
        $encrypt_d:path,    // crypto_secretbox_detached
        $decrypt_d:path,    // crypto_secretbox_open_detached
    ) => {
        /// The length of a symmetric key used for encryption/decryption, in bytes.
        pub const KEY_LENGTH: usize = $key_len as usize;

        /// The length of a MAC, in bytes.
        pub const MAC_LENGTH: usize = $mac_len as usize;

        /// The length of a message nonce, in bytes.
        pub const NONCE_LENGTH: usize = $nonce_len as usize;

        lazy_static::lazy_static! {
            /// The maximum message length which can be encrypted with this cipher
            pub static ref MESSAGE_LENGTH_MAX: usize = unsafe {
                // SAFETY: This function just returns a constant value, and should always be safe
                // to call.
                $msg_max()
            };
        }

        $crate::hardened_buffer! {
            /// Secret key for symmetric authenticated encryption.
            ///
            /// There are no technical constraints on the contents of a key, but it should be
            /// generated randomly using [`Key::generate`].
            ///
            /// A secret key must not be made public.
            ///
            /// This is a [hardened buffer type](https://docs.rs/alkali#hardened-buffer-types), and
            /// will be zeroed on drop. A number of other security measures are also taken to
            /// protect its contents.
            Key(KEY_LENGTH);
        }

        impl Key {
            /// Generate a new, random key for use in symmetric authenticated encryption.
            pub fn generate() -> Result<Self, $crate::AlkaliError> {
                $crate::require_init()?;

                let mut key = Self::new_empty()?;
                unsafe {
                    // SAFETY: This function expects a pointer to a region of memory sufficient to
                    // store a key for this algorithm. We have defined this type based on the
                    // `crypto_secretbox_KEYBYTES` constant from Sodium, so it definitely has the
                    // correct amount of space allocated to store the key. The `Key::inner_mut`
                    // method simply returns a mutable pointer to the struct's backing memory.
                    $keygen(key.inner_mut() as *mut libc::c_uchar);
                }
                Ok(key)
            }
        }

        /// A MAC (Message Authentication Code), used to authenticate the message.
        pub type MAC = [u8; MAC_LENGTH];

        /// A nonce, used to introduce non-determinism into the encryption calculation.
        pub type Nonce = [u8; NONCE_LENGTH];

        /// Generate a random nonce for use with the functions throughout this module.
        ///
        /// THe cipher used here has a sufficiently long nonce size that we can simply generate a
        /// random nonce for every message we wish to encrypt, and the chances of reusing a nonce
        /// are essentially zero.
        ///
        /// Returns a nonce generated using a Cryptographically Secure Pseudo-Random Number
        /// Generator, or an error if some error occurred.
        pub fn generate_nonce() -> Result<Nonce, $crate::AlkaliError> {
            let mut nonce = [0; NONCE_LENGTH];
            $crate::random::fill_random(&mut nonce)?;
            Ok(nonce)
        }

        /// Encrypt `message` using the provided `key`, writing the result to `output`.
        ///
        /// `message` should be the message to encrypt, and `key` a [`Key`] generated randomly.
        ///
        /// The encrypted ciphertext will be written to `output`, which must be at least
        /// [`MAC_LENGTH`] bytes longer than `message`. If the `output` slice is not sufficient to
        /// store the ciphertext, an error will be returned.
        ///
        /// This function will generate a random nonce, which is used in the encryption calculation
        /// to ensure that the keystream cannot be revealed. Nonces must *never* be reused for
        /// multiple messages with the same key. The nonce length for this cipher is sufficient
        /// that a random nonce can be generated for every message, and the probability of nonce
        /// reuse is essentially zero. The nonce will be required for decryption, so it should be
        /// stored alongside the ciphertext, or somehow communicated to the decrypting party.
        /// Nonces do not need to be kept secret.
        ///
        /// Returns the nonce used, and the length of the ciphertext written to `output` (which
        /// will actually always be `message.len()` + [`MAC_LENGTH`] bytes.
        pub fn encrypt(
            message: &[u8],
            key: &Key,
            output: &mut [u8],
        ) -> Result<(Nonce, usize), $crate::AlkaliError> {
            $crate::require_init()?;

            let nonce = generate_nonce()?;
            let c_len = encrypt_with_nonce(message, key, &nonce, output)?;

            Ok((nonce, c_len))
        }

        /// Encrypt `message` using the provided `key` and `nonce`, writing the result to `output`.
        ///
        /// `message` should be the message to encrypt, and `key` a [`Key`] generated randomly.
        ///
        /// `nonce` should be the nonce to use. It is *vital* that a given nonce *never* be reused
        /// with the same key. It is best to simply generate a random nonce for every message using
        /// [`generate_nonce`]: The nonce length for this cipher is sufficient that the probability
        /// of repeating a randomly generated nonce is effectively zero. The nonce will be required
        /// for decryption, so it should be stored alongside the ciphertext, or somehow
        /// communicated to the decrypting party. Nonces do not need to be kept secret. The
        /// [`encrypt`] function automatically generates a random nonce for every message.
        ///
        /// The encrypted ciphertext will be written to `output`, which must be at least
        /// [`MAC_LENGTH`] bytes longer than `message`. If the `output` slice is not sufficient to
        /// store the ciphertext, an error will be returned.
        ///
        /// Returns the length of the ciphertext written to `output`, which will always be
        /// `message.len()` + [`MAC_LENGTH`] bytes.
        pub fn encrypt_with_nonce(
            message: &[u8],
            key: &Key,
            nonce: &Nonce,
            output: &mut [u8],
        ) -> Result<usize, $crate::AlkaliError> {
            $crate::require_init()?;

            let c_len = message.len() + MAC_LENGTH;

            if output.len() < c_len {
                return Err($crate::symmetric::cipher::CipherError::OutputInsufficient(
                    c_len,
                    output.len(),
                )
                .into());
            } else if message.len() > *MESSAGE_LENGTH_MAX {
                return Err($crate::symmetric::cipher::CipherError::MessageTooLong.into());
            }

            unsafe {
                // SAFETY: The first argument to this function is the destination pointer to which
                // the ciphertext should be written. We verify above that the `output` slice is of
                // sufficient size to store the message + auth tag, so a buffer overflow will not
                // occur. The next two arguments specify the message to encrypt and its length. We
                // use `message.len()` to specify the message length, so it is correct for this
                // pointer. The final two arguments specify the nonce and key. We have defined the
                // `Nonce` and `Key` types based on the `crypto_secretbox_NONCEBYTES` and
                // `crypto_secretbox_KEYBYTES` constants, so they are of the expected size for use
                // with this function.
                $encrypt(
                    output.as_mut_ptr(),
                    message.as_ptr(),
                    message.len() as libc::c_ulonglong,
                    nonce.as_ptr(),
                    key.inner() as *const libc::c_uchar,
                );
            }

            Ok(c_len)
        }

        /// Encrypt `message` using the provided `key`, writing the result to `output`, but not
        /// prepending the MAC.
        ///
        /// This function is very similar to the [`encrypt`] function. The difference is that the
        /// standard [`encrypt`] function prepends the Message Authentication Code (MAC, used to
        /// verify the authenticity of the ciphertext) to the ciphertext output, while this
        /// function only writes the ciphertext to `output`, and separately returns the MAC.
        ///
        /// `message` should be the message to encrypt, and `key` a [`Key`] generated randomly.
        ///
        /// The encrypted ciphertext will be written to `output`, which must be at least
        /// `message.len()` bytes long. If the `output` slice is not sufficient to store the
        /// ciphertext, an error will be returned.
        ///
        /// This function will generate a random nonce, which is used in the encryption calculation
        /// to ensure that the keystream cannot be revealed. Nonces must *never* be reused for
        /// multiple messages with the same key. The nonce length for this cipher is sufficient
        /// that a random nonce can be generated for every message, and the probability of nonce
        /// reuse is essentially zero. The nonce will be required for decryption, so it should be
        /// stored alongside the ciphertext, or somehow communicated to the decrypting party.
        /// Nonces do not need to be kept secret.
        ///
        /// Returns the nonce used, and the calculated MAC.
        pub fn encrypt_detached(
            message: &[u8],
            key: &Key,
            output: &mut [u8],
        ) -> Result<(Nonce, MAC), $crate::AlkaliError> {
            $crate::require_init()?;

            let nonce = generate_nonce()?;
            let mac = encrypt_detached_with_nonce(message, key, &nonce, output)?;

            Ok((nonce, mac))
        }

        /// Encrypt `message` using the provided `key` and `nonce`, writing the result to `output`,
        /// but not prepending the MAC.
        ///
        /// This function is very similar to the [`encrypt_with_nonce`] function. The difference is
        /// that the standard [`encrypt_with_nonce`] function prepends the Message Authentication
        /// Code (MAC, used to verify the authenticity of the ciphertext) to the ciphertext output,
        /// while this function only writes the ciphertext to `output`, and separately returns the
        /// MAC.
        ///
        /// `message` should be the message to encrypt, and `key` a [`Key`] generated randomly.
        ///
        /// `nonce` should be the nonce to use. It is *vital* that a given nonce *never* be reused
        /// with the same key. It is best to simply generate a random nonce for every message using
        /// [`generate_nonce`]: The nonce length for this cipher is sufficient that the probability
        /// of repeating a randomly generated nonce is effectively zero. The nonce will be required
        /// for decryption, so it should be stored alongside the ciphertext, or somehow
        /// communicated to the decrypting party. Nonces do not need to be kept secret. The
        /// [`encrypt`] function automatically generates a random nonce for every message.
        ///
        /// The encrypted ciphertext will be written to `output`, which must be at least
        /// `message.len()` bytes long. If the `output` slice is not sufficient to
        /// store the ciphertext, an error will be returned.
        ///
        /// Returns the calculated MAC for the ciphertext.
        pub fn encrypt_detached_with_nonce(
            message: &[u8],
            key: &Key,
            nonce: &Nonce,
            output: &mut [u8],
        ) -> Result<MAC, $crate::AlkaliError> {
            $crate::require_init()?;

            if output.len() < message.len() {
                return Err($crate::symmetric::cipher::CipherError::OutputInsufficient(
                    message.len(),
                    output.len(),
                )
                .into());
            } else if message.len() > *MESSAGE_LENGTH_MAX {
                return Err($crate::symmetric::cipher::CipherError::MessageTooLong.into());
            }

            let mut mac = [0u8; MAC_LENGTH];

            unsafe {
                // SAFETY: The first argument to this function is the destination pointer to which
                // the ciphertext should be written. We verify above that the `output` slice is of
                // sufficient size to store the message tag, so a buffer overflow will not occur.
                // The next argument is the destination to which the MAC for this ciphertext will
                // be written. A MAC is always `crypto_secretbox_MACBYTES` bytes, and we have
                // defined the `mac` buffer to be this length, so it is sufficient to store the
                // MAC. The next two arguments specify the message to encrypt and its length. We
                // use `message.len()` to specify the message length, so it is correct for this
                // pointer. The final two arguments specify the nonce and key. We have defined the
                // `Nonce` and `Key` types based on the `crypto_secretbox_NONCEBYTES` and
                // `crypto_secretbox_KEYBYTES` constants, so they are of the expected size for use
                // with this function.
                $encrypt_d(
                    output.as_mut_ptr(),
                    mac.as_mut_ptr(),
                    message.as_ptr(),
                    message.len() as libc::c_ulonglong,
                    nonce.as_ptr(),
                    key.inner() as *const libc::c_uchar,
                );
            }

            Ok(mac)
        }

        /// Try to decrypt `ciphertext` (previously encrypted using [`encrypt`]) using `key` and
        /// `nonce`, writing the result to `output`.
        ///
        /// `ciphertext` should be a message to try to decrypt, `key` the [`Key`] the message is
        /// believed to have been encrypted with, and `nonce` the [`Nonce`] the nonce the message
        /// is believed to have been encrypted with.
        ///
        /// If authentication + decryption succeed, the decrypted message will be written to
        /// `output`. `output` must be at least `ciphertext.len()` - [`MAC_LENGTH`] bytes,
        /// otherwise, an error will be returned.
        ///
        /// Returns the length of the plaintext written to `output`, which will always be
        /// `ciphertext.len()` - [`MAC_LENGTH`] bytes.
        pub fn decrypt(
            ciphertext: &[u8],
            key: &Key,
            nonce: &Nonce,
            output: &mut [u8],
        ) -> Result<usize, $crate::AlkaliError> {
            $crate::require_init()?;

            if ciphertext.len() < MAC_LENGTH {
                return Err(crate::symmetric::cipher::CipherError::DecryptionFailed.into());
            }

            let m_len = ciphertext.len() - MAC_LENGTH;

            if output.len() < m_len {
                return Err($crate::symmetric::cipher::CipherError::OutputInsufficient(
                    m_len,
                    output.len(),
                )
                .into());
            }

            let decrypt_result = unsafe {
                // SAFETY: The first argument to this function is the destination to which the
                // original, decrypted message should be written to if decryption succeeds. This
                // will occupy at most `ciphertext.len() - MAC_LENGTH` bytes, and we have verified
                // above that `output` is of at least this length, so a buffer overflow cannot
                // occur. The next two arguments specify the ciphertext to decrypt, and its length.
                // We use `ciphertext.len()` to specify the length, so it is correct for this
                // pointer. The final two arguments specify the nonce and key: We have defined the
                // `Nonce` and `Key` types based on the `crypto_secretbox_NONCEBYTES` and
                // `crypto_secretbox_KEYBYTES` constants, so they are of the expected size for use
                // with this function.
                $decrypt(
                    output.as_mut_ptr(),
                    ciphertext.as_ptr(),
                    ciphertext.len() as libc::c_ulonglong,
                    nonce.as_ptr(),
                    key.inner() as *const libc::c_uchar,
                )
            };

            if decrypt_result == 0 {
                Ok(m_len)
            } else {
                Err($crate::symmetric::cipher::CipherError::DecryptionFailed.into())
            }
        }

        /// Try to decrypt `ciphertext` (previously encrypted using [`encrypt_detached`]) using
        /// `key` and `nonce`, writing the result to `output`.
        ///
        /// `ciphertext` should be a message to try to decrypt, `mac` the [`MAC`] (Message
        /// Authentication Code) for this message, `key` the [`Key`] the message is believed to
        /// have been encrypted with, and `nonce` the [`Nonce`] the nonce the message is believed
        /// to have been encrypted with.
        ///
        /// If authentication + decryption succeed, the decrypted message will be written to
        /// `output`. `output` must be at least `ciphertext.len()` bytes, otherwise, an error will
        /// be returned.
        ///
        /// Returns the length of the plaintext written to `output`, which will always be
        /// `ciphertext.len()` bytes.
        pub fn decrypt_detached(
            ciphertext: &[u8],
            mac: &MAC,
            key: &Key,
            nonce: &Nonce,
            output: &mut [u8],
        ) -> Result<(), $crate::AlkaliError> {
            $crate::require_init()?;

            if output.len() < ciphertext.len() {
                return Err($crate::symmetric::cipher::CipherError::OutputInsufficient(
                    ciphertext.len(),
                    output.len(),
                )
                .into());
            }

            let decrypt_result = unsafe {
                // SAFETY: The first argument to this function is the destination to which the
                // original, decrypted message should be written to if decryption succeeds. This
                // will occupy at most `ciphertext.len()` bytes, and we have verified above that
                // `output` is of at least this length, so a buffer overflow cannot occur. The next
                // argument and the fourth argument two arguments specify the ciphertext to
                // decrypt, and its length.  We use `ciphertext.len()` to specify the length, so it
                // is correct for this pointer. The third argument, and the final two arguments,
                // specify the MAC, nonce, and key: We have defined the `MAC`, `Nonce`, and `Key`
                // types based on the `crypto_secretbox_MACBYTES`, `crypto_secretbox_NONCEBYTES`,
                // and `crypto_secretbox_KEYBYTES` constants, so they are of the expected size for
                // use with this function.
                $decrypt_d(
                    output.as_mut_ptr(),
                    ciphertext.as_ptr(),
                    mac.as_ptr(),
                    ciphertext.len() as libc::c_ulonglong,
                    nonce.as_ptr(),
                    key.inner() as *const libc::c_uchar,
                )
            };

            if decrypt_result == 0 {
                Ok(())
            } else {
                Err($crate::symmetric::cipher::CipherError::DecryptionFailed.into())
            }
        }
    };
}

/// The [XSalsa20](https://en.wikipedia.org/wiki/Salsa20) cipher with a
/// [Poly1305](https://en.wikipedia.org/wiki/Poly1305) MAC.
pub mod xsalsa20poly1305 {
    use libsodium_sys as sodium;

    cipher_module! {
        sodium::crypto_secretbox_xsalsa20poly1305_KEYBYTES,
        sodium::crypto_secretbox_xsalsa20poly1305_MACBYTES,
        sodium::crypto_secretbox_xsalsa20poly1305_NONCEBYTES,
        sodium::crypto_secretbox_xsalsa20poly1305_messagebytes_max,
        sodium::crypto_secretbox_xsalsa20poly1305_keygen,
        sodium::crypto_secretbox_easy,
        sodium::crypto_secretbox_open_easy,
        sodium::crypto_secretbox_detached,
        sodium::crypto_secretbox_open_detached,
    }
}

/// The [XChaCha20](https://en.wikipedia.org/wiki/Salsa20#ChaCha_variant) cipher with a
/// [Poly1305](https://en.wikipedia.org/wiki/Poly1305) MAC.
pub mod xchacha20poly1305 {
    use libsodium_sys as sodium;

    cipher_module! {
        sodium::crypto_secretbox_xchacha20poly1305_KEYBYTES,
        sodium::crypto_secretbox_xchacha20poly1305_MACBYTES,
        sodium::crypto_secretbox_xchacha20poly1305_NONCEBYTES,
        sodium::crypto_secretbox_xchacha20poly1305_messagebytes_max,
        sodium::crypto_secretbox_keygen,
        sodium::crypto_secretbox_xchacha20poly1305_easy,
        sodium::crypto_secretbox_xchacha20poly1305_open_easy,
        sodium::crypto_secretbox_xchacha20poly1305_detached,
        sodium::crypto_secretbox_xchacha20poly1305_open_detached,
    }
}

pub use xsalsa20poly1305::*;
