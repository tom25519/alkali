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
//!
//! # Security Considerations
//! For the algorithms in this module, nonces must *never* be used more than once with the same
//! key. If you just use the [`encrypt`]/[`encrypt_detached`] functions, this should not be a
//! concern, as a random nonce is generated for every message encrypted with these functions.
//! However, for the functions which allow you to specify the nonce to use, please ensure you never
//! use a given nonce more than once with the same key: Nonces for the algorithms here are
//! sufficiently long that a nonce can be randomly chosen for every message using
//! [`generate_nonce`], and the probability of nonce reuse will be effectively zero.
//!
//! Nonces and MACs are not secret values, and can be transmitted in the clear.

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
        ///
        /// # Security Considerations
        /// For the algorithms in this module, nonces must *never* be used more than once with the
        /// same key. For this function, this should not be a concern, as a random nonce is
        /// generated for every message encrypted.
        ///
        /// Nonces and MACs are not secret values, and can be transmitted in the clear.
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
        ///
        /// # Security Considerations
        /// For the algorithms in this module, nonces must *never* be used more than once with the
        /// same key. Please ensure you never use a given nonce more than once with the same key:
        /// Nonces for the algorithms here are sufficiently long that a nonce can be randomly
        /// chosen for every message using [`generate_nonce`], and the probability of nonce reuse
        /// will be effectively zero.
        ///
        /// Nonces and MACs are not secret values, and can be transmitted in the clear.
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
        ///
        /// # Security Considerations
        /// For the algorithms in this module, nonces must *never* be used more than once with the
        /// same key. For this function, this should not be a concern, as a random nonce is
        /// generated for every message encrypted.
        ///
        /// Nonces and MACs are not secret values, and can be transmitted in the clear.
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
        ///
        /// # Security Considerations
        /// For the algorithms in this module, nonces must *never* be used more than once with the
        /// same key. Please ensure you never use a given nonce more than once with the same key:
        /// Nonces for the algorithms here are sufficiently long that a nonce can be randomly
        /// chosen for every message using [`generate_nonce`], and the probability of nonce reuse
        /// will be effectively zero.
        ///
        /// Nonces and MACs are not secret values, and can be transmitted in the clear.
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

#[allow(unused_macros)]
macro_rules! cipher_tests {
    ( $( {
        msg: $msg:expr,
        key: $key:expr,
        nonce: $nonce:expr,
        c: $c:expr,
        mac: $mac:expr,
    }, )*) => {
        use super::{
            decrypt, decrypt_detached, encrypt, encrypt_with_nonce, encrypt_detached,
            encrypt_detached_with_nonce, Key, MAC_LENGTH
        };
        use $crate::random::fill_random;
        use $crate::AlkaliError;

        #[test]
        fn key_generation() -> Result<(), AlkaliError> {
            let _key = Key::generate()?;
            Ok(())
        }

        #[test]
        fn enc_and_dec() -> Result<(), AlkaliError> {
            let key = Key::generate()?;

            let mut msg_a = [];
            let mut msg_b = [0; 16];
            let mut msg_c = [0; 1024];
            let mut msg_d = [0; 1 << 18];

            fill_random(&mut msg_b)?;
            fill_random(&mut msg_c)?;
            fill_random(&mut msg_d)?;

            let mut c_a = [0; MAC_LENGTH];
            let mut c_b = [0; 16 + MAC_LENGTH];
            let mut c_c = [0; 1024 + MAC_LENGTH];
            let mut c_d = [0; (1 << 18) + MAC_LENGTH];

            let (nonce_a, l_a) = encrypt(&msg_a, &key, &mut c_a)?;
            let (nonce_b, l_b) = encrypt(&msg_b, &key, &mut c_b)?;
            let (nonce_c, l_c) = encrypt(&msg_c, &key, &mut c_c)?;
            let (nonce_d, l_d) = encrypt(&msg_d, &key, &mut c_d)?;

            assert_eq!(l_a, MAC_LENGTH);
            assert_eq!(l_b, 16 + MAC_LENGTH);
            assert_eq!(l_c, 1024 + MAC_LENGTH);
            assert_eq!(l_d, (1 << 18) + MAC_LENGTH);

            decrypt(&c_a, &key, &nonce_a, &mut msg_a)?;
            decrypt(&c_b, &key, &nonce_b, &mut msg_b)?;
            decrypt(&c_c, &key, &nonce_c, &mut msg_c)?;
            decrypt(&c_d, &key, &nonce_d, &mut msg_d)?;

            fill_random(&mut c_a)?;
            fill_random(&mut c_b)?;
            fill_random(&mut c_c)?;
            fill_random(&mut c_d)?;

            assert!(decrypt(&c_a, &key, &nonce_a, &mut msg_a).is_err());
            assert!(decrypt(&c_b, &key, &nonce_b, &mut msg_b).is_err());
            assert!(decrypt(&c_c, &key, &nonce_c, &mut msg_c).is_err());
            assert!(decrypt(&c_d, &key, &nonce_d, &mut msg_d).is_err());

            Ok(())
        }

        #[test]
        fn enc_and_dec_detached() -> Result<(), AlkaliError> {
            let key = Key::generate()?;

            let mut msg_a = [];
            let mut msg_b = [0; 16];
            let mut msg_c = [0; 1024];
            let mut msg_d = [0; 1 << 18];

            fill_random(&mut msg_b)?;
            fill_random(&mut msg_c)?;
            fill_random(&mut msg_d)?;

            let mut c_a = [];
            let mut c_b = [0; 16];
            let mut c_c = [0; 1024];
            let mut c_d = [0; (1 << 18)];

            let (nonce_a, mut mac_a) = encrypt_detached(&msg_a, &key, &mut c_a)?;
            let (nonce_b, mac_b) = encrypt_detached(&msg_b, &key, &mut c_b)?;
            let (nonce_c, mac_c) = encrypt_detached(&msg_c, &key, &mut c_c)?;
            let (nonce_d, mac_d) = encrypt_detached(&msg_d, &key, &mut c_d)?;

            decrypt_detached(&c_a, &mac_a, &key, &nonce_a, &mut msg_a)?;
            decrypt_detached(&c_b, &mac_b, &key, &nonce_b, &mut msg_b)?;
            decrypt_detached(&c_c, &mac_c, &key, &nonce_c, &mut msg_c)?;
            decrypt_detached(&c_d, &mac_d, &key, &nonce_d, &mut msg_d)?;

            fill_random(&mut mac_a)?;
            fill_random(&mut c_b)?;
            fill_random(&mut c_c)?;
            fill_random(&mut c_d)?;

            assert!(decrypt_detached(&c_a, &mac_a, &key, &nonce_a, &mut msg_a).is_err());
            assert!(decrypt_detached(&c_b, &mac_b, &key, &nonce_b, &mut msg_b).is_err());
            assert!(decrypt_detached(&c_c, &mac_c, &key, &nonce_c, &mut msg_c).is_err());
            assert!(decrypt_detached(&c_d, &mac_d, &key, &nonce_d, &mut msg_d).is_err());

            Ok(())
        }

        #[test]
        fn test_vectors() -> Result<(), AlkaliError> {
            let mut key = Key::new_empty()?;

            $(
                key.copy_from_slice(&$key);
                let mut c = vec![0; $msg.len() + MAC_LENGTH];
                assert_eq!(encrypt_with_nonce(&$msg, &key, &$nonce, &mut c)?, $msg.len() + MAC_LENGTH);
                assert_eq!(&c[..MAC_LENGTH], &$mac[..]);
                assert_eq!(&c[MAC_LENGTH..], &$c[..]);
                let mut m = vec![0; $msg.len()];
                assert_eq!(decrypt(&c, &key, &$nonce, &mut m)?, $msg.len());
                assert_eq!(&m, &$msg);
            )*

            Ok(())
        }

        #[test]
        fn test_vectors_detached() -> Result<(), AlkaliError> {
            let mut key = Key::new_empty()?;

            $(
                key.copy_from_slice(&$key);
                let mut c = vec![0; $msg.len()];
                let mac = encrypt_detached_with_nonce(&$msg, &key, &$nonce, &mut c)?;
                assert_eq!(&c, &$c);
                assert_eq!(&mac, &$mac);
                let mut m = vec![0; $msg.len()];
                decrypt_detached(&c, &mac, &key, &$nonce, &mut m)?;
                assert_eq!(&m, &$msg);
            )*

            Ok(())
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

    #[cfg(test)]
    mod tests {
        cipher_tests! [
            {
                msg:   [0xbe, 0x07, 0x5f, 0xc5, 0x3c, 0x81, 0xf2, 0xd5, 0xcf, 0x14, 0x13, 0x16,
                        0xeb, 0xeb, 0x0c, 0x7b, 0x52, 0x28, 0xc5, 0x2a, 0x4c, 0x62, 0xcb, 0xd4,
                        0x4b, 0x66, 0x84, 0x9b, 0x64, 0x24, 0x4f, 0xfc, 0xe5, 0xec, 0xba, 0xaf,
                        0x33, 0xbd, 0x75, 0x1a, 0x1a, 0xc7, 0x28, 0xd4, 0x5e, 0x6c, 0x61, 0x29,
                        0x6c, 0xdc, 0x3c, 0x01, 0x23, 0x35, 0x61, 0xf4, 0x1d, 0xb6, 0x6c, 0xce,
                        0x31, 0x4a, 0xdb, 0x31, 0x0e, 0x3b, 0xe8, 0x25, 0x0c, 0x46, 0xf0, 0x6d,
                        0xce, 0xea, 0x3a, 0x7f, 0xa1, 0x34, 0x80, 0x57, 0xe2, 0xf6, 0x55, 0x6a,
                        0xd6, 0xb1, 0x31, 0x8a, 0x02, 0x4a, 0x83, 0x8f, 0x21, 0xaf, 0x1f, 0xde,
                        0x04, 0x89, 0x77, 0xeb, 0x48, 0xf5, 0x9f, 0xfd, 0x49, 0x24, 0xca, 0x1c,
                        0x60, 0x90, 0x2e, 0x52, 0xf0, 0xa0, 0x89, 0xbc, 0x76, 0x89, 0x70, 0x40,
                        0xe0, 0x82, 0xf9, 0x37, 0x76, 0x38, 0x48, 0x64, 0x5e, 0x07, 0x05],
                key:   [0x1b, 0x27, 0x55, 0x64, 0x73, 0xe9, 0x85, 0xd4, 0x62, 0xcd, 0x51, 0x19,
                        0x7a, 0x9a, 0x46, 0xc7, 0x60, 0x09, 0x54, 0x9e, 0xac, 0x64, 0x74, 0xf2,
                        0x06, 0xc4, 0xee, 0x08, 0x44, 0xf6, 0x83, 0x89],
                nonce: [0x69, 0x69, 0x6e, 0xe9, 0x55, 0xb6, 0x2b, 0x73, 0xcd, 0x62, 0xbd, 0xa8,
                        0x75, 0xfc, 0x73, 0xd6, 0x82, 0x19, 0xe0, 0x03, 0x6b, 0x7a, 0x0b, 0x37],
                c:     [0x8e, 0x99, 0x3b, 0x9f, 0x48, 0x68, 0x12, 0x73, 0xc2, 0x96, 0x50, 0xba,
                        0x32, 0xfc, 0x76, 0xce, 0x48, 0x33, 0x2e, 0xa7, 0x16, 0x4d, 0x96, 0xa4,
                        0x47, 0x6f, 0xb8, 0xc5, 0x31, 0xa1, 0x18, 0x6a, 0xc0, 0xdf, 0xc1, 0x7c,
                        0x98, 0xdc, 0xe8, 0x7b, 0x4d, 0xa7, 0xf0, 0x11, 0xec, 0x48, 0xc9, 0x72,
                        0x71, 0xd2, 0xc2, 0x0f, 0x9b, 0x92, 0x8f, 0xe2, 0x27, 0x0d, 0x6f, 0xb8,
                        0x63, 0xd5, 0x17, 0x38, 0xb4, 0x8e, 0xee, 0xe3, 0x14, 0xa7, 0xcc, 0x8a,
                        0xb9, 0x32, 0x16, 0x45, 0x48, 0xe5, 0x26, 0xae, 0x90, 0x22, 0x43, 0x68,
                        0x51, 0x7a, 0xcf, 0xea, 0xbd, 0x6b, 0xb3, 0x73, 0x2b, 0xc0, 0xe9, 0xda,
                        0x99, 0x83, 0x2b, 0x61, 0xca, 0x01, 0xb6, 0xde, 0x56, 0x24, 0x4a, 0x9e,
                        0x88, 0xd5, 0xf9, 0xb3, 0x79, 0x73, 0xf6, 0x22, 0xa4, 0x3d, 0x14, 0xa6,
                        0x59, 0x9b, 0x1f, 0x65, 0x4c, 0xb4, 0x5a, 0x74, 0xe3, 0x55, 0xa5],
                mac:   [0xf3, 0xff, 0xc7, 0x70, 0x3f, 0x94, 0x00, 0xe5, 0x2a, 0x7d, 0xfb, 0x4b,
                        0x3d, 0x33, 0x05, 0xd9],
            },
            {
                msg:   [] as [u8; 0],
                key:   [0x1b, 0x27, 0x55, 0x64, 0x73, 0xe9, 0x85, 0xd4, 0x62, 0xcd, 0x51, 0x19,
                        0x7a, 0x9a, 0x46, 0xc7, 0x60, 0x09, 0x54, 0x9e, 0xac, 0x64, 0x74, 0xf2,
                        0x06, 0xc4, 0xee, 0x08, 0x44, 0xf6, 0x83, 0x89],
                nonce: [0x69, 0x69, 0x6e, 0xe9, 0x55, 0xb6, 0x2b, 0x73, 0xcd, 0x62, 0xbd, 0xa8,
                        0x75, 0xfc, 0x73, 0xd6, 0x82, 0x19, 0xe0, 0x03, 0x6b, 0x7a, 0x0b, 0x37],
                c:     [],
                mac:   [0x25, 0x39, 0x12, 0x1d, 0x8e, 0x23, 0x4e, 0x65, 0x2d, 0x65, 0x1f, 0xa4,
                        0xc8, 0xcf, 0xf8, 0x80],
            },
        ];
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

    #[cfg(test)]
    mod tests {
        cipher_tests! [
            {
                msg:   [0xbe, 0x07, 0x5f, 0xc5, 0x3c, 0x81, 0xf2, 0xd5, 0xcf, 0x14, 0x13, 0x16,
                        0xeb, 0xeb, 0x0c, 0x7b, 0x52, 0x28, 0xc5, 0x2a, 0x4c, 0x62, 0xcb, 0xd4,
                        0x4b, 0x66, 0x84, 0x9b, 0x64, 0x24, 0x4f, 0xfc, 0xe5, 0xec, 0xba, 0xaf,
                        0x33, 0xbd, 0x75, 0x1a, 0x1a, 0xc7, 0x28, 0xd4, 0x5e, 0x6c, 0x61, 0x29,
                        0x6c, 0xdc, 0x3c, 0x01, 0x23, 0x35, 0x61, 0xf4, 0x1d, 0xb6, 0x6c, 0xce,
                        0x31, 0x4a, 0xdb, 0x31, 0x0e, 0x3b, 0xe8, 0x25, 0x0c, 0x46, 0xf0, 0x6d,
                        0xce, 0xea, 0x3a, 0x7f, 0xa1, 0x34, 0x80, 0x57, 0xe2, 0xf6, 0x55, 0x6a,
                        0xd6, 0xb1, 0x31, 0x8a, 0x02, 0x4a, 0x83, 0x8f, 0x21, 0xaf, 0x1f, 0xde,
                        0x04, 0x89, 0x77, 0xeb, 0x48, 0xf5, 0x9f, 0xfd, 0x49, 0x24, 0xca, 0x1c,
                        0x60, 0x90, 0x2e, 0x52, 0xf0, 0xa0, 0x89, 0xbc, 0x76, 0x89, 0x70, 0x40,
                        0xe0, 0x82, 0xf9, 0x37, 0x76, 0x38, 0x48, 0x64, 0x5e, 0x07, 0x05],
                key:   [0x1b, 0x27, 0x55, 0x64, 0x73, 0xe9, 0x85, 0xd4, 0x62, 0xcd, 0x51, 0x19,
                        0x7a, 0x9a, 0x46, 0xc7, 0x60, 0x09, 0x54, 0x9e, 0xac, 0x64, 0x74, 0xf2,
                        0x06, 0xc4, 0xee, 0x08, 0x44, 0xf6, 0x83, 0x89],
                nonce: [0x69, 0x69, 0x6e, 0xe9, 0x55, 0xb6, 0x2b, 0x73, 0xcd, 0x62, 0xbd, 0xa8,
                        0x75, 0xfc, 0x73, 0xd6, 0x82, 0x19, 0xe0, 0x03, 0x6b, 0x7a, 0x0b, 0x37],
                c:     [0xbf, 0x8a, 0xf3, 0x19, 0x85, 0x85, 0xe5, 0x5d, 0x9c, 0xb0, 0x7e, 0xdc,
                        0xd1, 0xe5, 0xa6, 0x95, 0x26, 0x54, 0x7f, 0xbd, 0x0f, 0x2c, 0x64, 0x2e,
                        0x9e, 0xe9, 0x6e, 0x19, 0x46, 0x20, 0x31, 0xf1, 0x03, 0x2f, 0x1c, 0xd8,
                        0x62, 0xbb, 0x95, 0x29, 0x00, 0x10, 0x3c, 0x06, 0xac, 0x16, 0x34, 0x4d,
                        0x7f, 0x9c, 0x9d, 0xf0, 0xfe, 0xaa, 0xf5, 0xa7, 0x33, 0xde, 0xa7, 0xea,
                        0x2d, 0xf7, 0x0a, 0x61, 0x99, 0x36, 0xfc, 0xc5, 0x50, 0x1d, 0xe7, 0x5c,
                        0x5d, 0x11, 0x2e, 0x8a, 0xbd, 0x75, 0x73, 0xc4, 0x61, 0xad, 0xa2, 0x9e,
                        0xc0, 0x16, 0xd1, 0x31, 0xaa, 0x55, 0x78, 0x04, 0x32, 0x00, 0x11, 0xff,
                        0x6d, 0x94, 0x09, 0x25, 0x81, 0xce, 0xea, 0x1b, 0xad, 0x3c, 0xf0, 0xd6,
                        0x51, 0x93, 0x88, 0x02, 0xca, 0x86, 0x7c, 0xd5, 0x2b, 0xbe, 0x50, 0xc2,
                        0xda, 0x11, 0x61, 0xcb, 0x09, 0x51, 0x44, 0x07, 0x60, 0x99, 0x20],
                mac:   [0x0c, 0x61, 0xfc, 0xff, 0xbc, 0x3f, 0xc8, 0xd3, 0xaa, 0x74, 0x64, 0xb9,
                        0x1a, 0xb3, 0x53, 0x74],
            },
            {
                msg:   [] as [u8; 0],
                key:   [0x1b, 0x27, 0x55, 0x64, 0x73, 0xe9, 0x85, 0xd4, 0x62, 0xcd, 0x51, 0x19,
                        0x7a, 0x9a, 0x46, 0xc7, 0x60, 0x09, 0x54, 0x9e, 0xac, 0x64, 0x74, 0xf2,
                        0x06, 0xc4, 0xee, 0x08, 0x44, 0xf6, 0x83, 0x89],
                nonce: [0x69, 0x69, 0x6e, 0xe9, 0x55, 0xb6, 0x2b, 0x73, 0xcd, 0x62, 0xbd, 0xa8,
                        0x75, 0xfc, 0x73, 0xd6, 0x82, 0x19, 0xe0, 0x03, 0x6b, 0x7a, 0x0b, 0x37],
                c:     [],
                mac:   [0x89, 0x46, 0xd8, 0xf1, 0x8f, 0x31, 0x34, 0x65, 0xc8, 0x62, 0xa0, 0x87,
                        0x82, 0x64, 0x82, 0x48],
            },
        ];
    }
}

pub use xsalsa20poly1305::*;
