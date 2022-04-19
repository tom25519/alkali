//! Symmetric [Authenticated Encryption](https://en.wikipedia.org/wiki/Authenticated_encryption)
//! (AE).
//!
//! This module corresponds to the [`crypto_secretbox`
//! API](https://doc.libsodium.org/secret-key_cryptography/secretbox) from Sodium.
//!
//! Authenticated encryption is used to encrypt messages, providing assurance to the receiver that
//! the ciphertext has not been modified in transit by an attacker or transmission error. In
//! symmetric encryption, all parties who wish to encrypt or decrypt messages must share a single
//! secret key prior to communication, which is used for both encryption and decryption.
//!
//! # Algorithm Details
//! This authenticated encryption construction uses the [XSalsa20](https://cr.yp.to/snuffle.html)
//! stream cipher (Salsa20 with an eXtended nonce length) for encryption by default, together with
//! the [Poly1305](https://en.wikipedia.org/wiki/Poly1305) MAC for authentication. This construction
//! is exposed in the [`xsalsa20poly1305`] module.
//!
//! As an alternative, an implementation which uses [XChaCha20](https://cr.yp.to/chacha.html) as the
//! stream cipher is also available, exposed as [`xchacha20poly1305`].
//!
//! # Security Considerations
//! For the algorithms in this module, nonces must *never* be used more than once with the same key.
//! If you supply `None` as the nonce for [`encrypt`] or [`encrypt_detached`], a nonce will be
//! randomly generated for you, and the chance of nonce-reuse is effectively zero. However, if you
//! need to specify your own nonces for each message, please ensure a given nonce is never reused:
//! Random nonce generation with [`generate_nonce`] will probably be your best strategy.
//!
//! If many trusted parties have access to the secret key, there is no way to prove which one of
//! them sent a given message without additional data.
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
//!
//! # Examples
//! Standard encryption & decryption (uses [`encrypt`] and [`decrypt`]):
//!
//! ```rust
//! use alkali::symmetric::cipher;
//!
//! const MESSAGE: &'static str = "Here's a message to encrypt. It can be of any length.";
//!
//! // Prior to communication:
//!
//! // A random secret key is generated & distributed to all parties:
//! let key = cipher::Key::generate().unwrap();
//!
//!
//! // ...
//!
//!
//! // Sender side:
//! // We assume the sender knows `key`.
//!
//! // The encrypted message will be `MAC_LENGTH` bytes longer than the original message.
//! let mut ciphertext = vec![0u8; MESSAGE.as_bytes().len() + cipher::MAC_LENGTH];
//! // If this function is successful, the ciphertext + a MAC will be stored in `ciphertext`. A
//! // random nonce will be generated for this message, and returned to be stored in `nonce`. We
//! // will need this to perform the decryption.
//! let (_, nonce) = cipher::encrypt(MESSAGE.as_bytes(), &key, None, &mut ciphertext).unwrap();
//!
//!
//! // ...
//!
//!
//! // Receiver side:
//! // We assume the receiver knows `key`.
//!
//! let mut plaintext = vec![0u8; ciphertext.len() - cipher::MAC_LENGTH];
//! // We `decrypt` function not only decrypts `ciphertext`, but also verifies its authenticity
//! // using the included MAC. This operation will fail if a forgery is attempted.
//! cipher::decrypt(&ciphertext, &key, &nonce, &mut plaintext).unwrap();
//! assert_eq!(&plaintext, MESSAGE.as_bytes());
//! ```
//!
//! Detached encryption & decryption, which stores the MAC separately to the ciphertext (uses
//! [`encrypt_detached`] and [`decrypt_detached`]):
//!
//! ```rust
//! use alkali::symmetric::cipher;
//!
//! const MESSAGE: &'static str = "Another encryption example!";
//!
//! // Prior to communication:
//!
//! // A random secret key is generated & distributed to all parties:
//! let key = cipher::Key::generate().unwrap();
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
//! // Here, we'll generate a random nonce ourselves rather than letting alkali randomly generate
//! // one for us. It is vital that a given nonce is never reused with the same key, so it is best
//! // to randomly generate a nonce for every message.
//! let nonce = cipher::generate_nonce().unwrap();
//! // The `encrypt_detached` function will return the MAC of the message separately.
//! let (_, _, mac) =
//!     cipher::encrypt_detached(MESSAGE.as_bytes(), &key, Some(&nonce), &mut ciphertext).unwrap();
//!
//!
//! // ...
//!
//!
//! // Receiver side:
//! // We assume the receiver knows `key`.
//!
//! let mut plaintext = vec![0u8; ciphertext.len()];
//! // We will need to pass the MAC as another argument to the detached decryption function.
//! cipher::decrypt_detached(&ciphertext, &mac, &key, &nonce, &mut plaintext);
//! assert_eq!(&plaintext, MESSAGE.as_bytes());
//! ```

use thiserror::Error;

/// Error type returned if something went wrong in the `symmetric::cipher` module.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum CipherError {
    /// The output buffer is too short to store the ciphertext/plaintext which would result from
    /// encrypting/decrypting this message.
    ///
    /// Each function in this module should provide information in its documentation about the
    /// output length requirements.
    #[error("the output is insufficient to store ciphertext/plaintext")]
    OutputInsufficient,

    /// Message too long for use with this cipher.
    ///
    /// Beyond a certain point, the keystream of the cipher is exhausted, and it can no longer be
    /// used to safely encrypt message contents. Therefore, this error is returned if the message
    /// provided is too long. Messages can be at most [`struct@MESSAGE_LENGTH_MAX`] bytes.
    #[error("the message is too long for encryption/decryption with this cipher")]
    MessageTooLong,

    /// Indicates decryption of a provided ciphertext failed.
    ///
    /// This could indicate an attempted forgery, or transmission error.
    #[error("decryption failed")]
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
        use $crate::symmetric::cipher::CipherError;
        use $crate::{assert_not_err, mem, random, require_init, AlkaliError};

        /// The length of a symmetric key used for encryption/decryption, in bytes.
        pub const KEY_LENGTH: usize = $key_len as usize;

        /// The length of a MAC, in bytes.
        pub const MAC_LENGTH: usize = $mac_len as usize;

        /// The length of a message nonce, in bytes.
        pub const NONCE_LENGTH: usize = $nonce_len as usize;

        lazy_static::lazy_static! {
            /// The maximum message length which can be encrypted with this cipher, in bytes.
            pub static ref MESSAGE_LENGTH_MAX: usize = unsafe {
                // SAFETY: This function just returns a constant value, and should always be safe
                // to call.
                $msg_max()
            };
        }

        mem::hardened_buffer! {
            /// A secret key for symmetric authenticated encryption.
            ///
            /// There are no *technical* constraints on the contents of a key, but it should be
            /// indistinguishable from random noise. A random key can be securely generated via
            /// [`Key::generate`].
            ///
            /// A secret key must not be made public.
            ///
            /// This is a [hardened buffer type](https://docs.rs/alkali#hardened-buffer-types), and
            /// will be zeroed on drop. A number of other security measures are also taken to
            /// protect its contents. This type in particular can be thought of as roughly
            /// equivalent to a `[u8; KEY_LENGTH]`, and implements [`std::ops::Deref`] so it can be
            /// used like it is an `&[u8]`. This struct uses heap memory while in scope, allocated
            /// using Sodium's [secure memory
            /// utilities](https://doc.libsodium.org/memory_management).
            pub Key(KEY_LENGTH);
        }

        impl Key {
            /// Generate a new, random key for use in symmetric AE.
            pub fn generate() -> Result<Self, AlkaliError> {
                require_init()?;

                let mut key = Self::new_empty()?;
                unsafe {
                    // SAFETY: This function expects a pointer to a region of memory sufficient to
                    // store a key. The `Key` type allocates `crypto_secretbox_KEYBYTES`, the length
                    // of a key for this algorithm. It is therefore valid for writes of the required
                    // length. The `Key::inner_mut` method simply returns a mutable pointer to the
                    // struct's backing memory.
                    $keygen(key.inner_mut() as *mut libc::c_uchar);
                }
                Ok(key)
            }
        }

        /// A MAC (Message Authentication Code), used to authenticate a message.
        ///
        /// If using [`encrypt`], the MAC is included in the ciphertext. It is returned separately
        /// in the [`encrypt_detached`] variant.
        pub type MAC = [u8; MAC_LENGTH];

        /// A nonce, used to introduce non-determinism into the keystream calculation.
        ///
        /// Nonces must never be used for multiple messages with the same key. Ideally, let alkali
        /// generate a random nonce for every message by specifying `None` as the nonce for
        /// [`encrypt`]/[`encrypt_detached`].
        pub type Nonce = [u8; NONCE_LENGTH];

        /// Generate a random nonce for use with the functions throughout this module.
        ///
        /// It is vital that a given nonce is never used to encrypt more than one message under the
        /// same key. The cipher used here has a sufficient nonce size that we can simply generate a
        /// random nonce for every message we wish to encrypt, and the chances of reusing a nonce
        /// are essentially zero.
        ///
        /// Returns a nonce generated using a Cryptographically Secure Pseudo-Random Number
        /// Generator, or a [`crate::AlkaliError`] if an error occurred.
        pub fn generate_nonce() -> Result<Nonce, AlkaliError> {
            let mut nonce = [0; NONCE_LENGTH];
            random::fill_random(&mut nonce)?;
            Ok(nonce)
        }

        /// Encrypt `message` using the provided `key`, writing the result to `output`.
        ///
        /// `message` should be the message to encrypt, and `key` a [`Key`] generated randomly using
        /// [`Key::generate`].
        ///
        /// `nonce` should be a [nonce](https://en.wikipedia.org/wiki/Cryptographic_nonce) to use in
        /// the encryption process. It is recommended that this be set to `None`, which will cause
        /// alkali to randomly generate a nonce for the message. If you specify a custom nonce, it
        /// is vital the nonce is never used to encrypt more than one message under the same key:
        /// Nonce reuse could result in an attacker recovering the secret key. Nonces are not
        /// secret, but will need to be communicated to the decrypting party for them to be able to
        /// decrypt the message. This function will return the nonce used for the encryption of this
        /// message.
        ///
        /// The encrypted ciphertext will be written to `output`. The ciphertext will be
        /// [`MAC_LENGTH`] bytes longer than `message`, so `output` must be of sufficient size to
        /// store at least this many bytes. An error will be returned if `output` is not sufficient
        /// to store the ciphertext.
        ///
        /// If encryption is successful, returns the number of bytes written to `output` (this will
        /// actually always be `message.len()` + [`MAC_LENGTH`] bytes), and the [`Nonce`] used for
        /// the encryption process.
        ///
        /// # Security Considerations
        /// Nonces must *never* be used more than once with the same key. You should specify `None`
        /// for the nonce to use, which will cause a random nonce to be generated for every message,
        /// unless you have good reason to do otherwise.
        pub fn encrypt(
            message: &[u8],
            key: &Key,
            nonce: Option<&Nonce>,
            output: &mut [u8],
        ) -> Result<(usize, Nonce), AlkaliError> {
            require_init()?;

            let c_len = message.len() + MAC_LENGTH;

            if output.len() < c_len {
                return Err(CipherError::OutputInsufficient.into());
            } else if message.len() > *MESSAGE_LENGTH_MAX {
                return Err(CipherError::MessageTooLong.into());
            }

            let nonce = if let Some(&n) = nonce {
                n
            } else {
                generate_nonce()?
            };

            let encrypt_result = unsafe {
                // SAFETY: The first argument to this function is the destination to which the
                // combined MAC + ciphertext will be written. The ciphertext will be of the same
                // length as the message, and the MAC will always be `crypto_secretbox_MACBYTES`, so
                // as long as the output pointer is valid for writes of `message.len() +
                // crypto_secretbox_MACBYTES`, it is valid to use here. We verify this condition
                // above, and return an error if the output is insufficient. The next two arguments
                // specify the message to encrypt and its length. We use `message.len()` to specify
                // the message length, so `message` is definitely valid for reads of this length.
                // The next argument should be a pointer to the nonce to use for encryption. We have
                // defined the `Nonce` type to be `crypto_secretbox_NONCEBYTES`, the size of a nonce
                // for this algorithm, so it is valid for reads of the required length. The final
                // argument for this function specifies the key with which the message should be
                // encrypted. We have defined the `Key` type to allocate
                // `crypto_secretbox_KEYBYTES`, the length of a key for this algorithm, so it is
                // valid for reads of the required length. The `Key::inner` method simply returns an
                // immutable pointer to its backing memory.
                $encrypt(
                    output.as_mut_ptr(),
                    message.as_ptr(),
                    message.len() as libc::c_ulonglong,
                    nonce.as_ptr(),
                    key.inner() as *const libc::c_uchar,
                )
            };
            assert_not_err!(encrypt_result, stringify!($encrypt));

            Ok((c_len, nonce))
        }

        /// Decrypt `ciphertext` using the provided `key`, writing the result to `output`.
        ///
        /// `ciphertext` should be the combined ciphertext + MAC to decrypt (previously encrypted
        /// using [`encrypt`]). `key` should be the the [`Key`] to use to decrypt the message.
        /// `nonce` should be the [`Nonce`] which was used to encrypt the message.
        ///
        /// The decrypted plaintext will be written to `output`. The plaintext will be
        /// [`MAC_LENGTH`] bytes shorter than `ciphertext`, so `output` must be of sufficient size
        /// to store at least this many bytes. An error will be returned if `output` is not
        /// sufficient to store the plaintext.
        ///
        /// Decryption will fail if message authentication fails. If decryption is successful, the
        /// plaintext is written to `output`, and the length of the plaintext will be returned (this
        /// will always be `ciphertext.len()` - [`MAC_LENGTH`] bytes.
        pub fn decrypt(
            ciphertext: &[u8],
            key: &Key,
            nonce: &Nonce,
            output: &mut [u8],
        ) -> Result<usize, AlkaliError> {
            require_init()?;

            if ciphertext.len() < MAC_LENGTH {
                return Err(CipherError::DecryptionFailed.into());
            }

            let m_len = ciphertext.len() - MAC_LENGTH;

            if output.len() < m_len {
                return Err(CipherError::OutputInsufficient.into());
            }

            let decrypt_result = unsafe {
                // SAFETY: The first argument to this function is the destination to which the
                // decrypted plaintext will be written. The plaintext will be
                // `crypto_secretbox_MACBYTES` shorter than the ciphertext, so as long as the output
                // pointer is valid for writes of `ciphertext.len() - crypto_secretbox_MACBYTES`, it
                // is valid to use here. We verify this condition above, and return an error if the
                // output is insufficient. The next two arguments specify the ciphertext to decrypt
                // and its length. We use `ciphertext.len()` to specify the ciphertext length, so
                // `ciphertext` is definitely valid for reads of this length. The next argument
                // should be a pointer to the nonce to use for decryption. We have defined the
                // `Nonce` type to be `crypto_secretbox_NONCEBYTES`, the size of a nonce for this
                // algorithm, so it is valid for reads of the required length. The final argument
                // for this function specifies the key with which the message should be decrypted.
                // We have defined the `Key` type to allocate `crypto_secretbox_KEYBYTES`, the
                // length of a key for this algorithm, so it is valid for reads of the required
                // length. The `Key::inner` method simply returns an immutable pointer to its
                // backing memory.
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
                Err(CipherError::DecryptionFailed.into())
            }
        }

        /// Encrypt `message` using the provided `key`, writing the result to `output`, separately
        /// returning the [`MAC`].
        ///
        /// This function is very similar to the [`encrypt`] function. The difference is that the
        /// standard [`encrypt`] function prepends the Message Authentication Code (MAC, used to
        /// verify the authenticity of the ciphertext) to the ciphertext output, while this
        /// function only writes the ciphertext to `output`, and separately returns the MAC.
        ///
        /// `message` should be the message to encrypt. `key` should be the [`Key`] to use for
        /// encryption, generated randomly using [`Key::generate`].
        ///
        /// `nonce` should be a [nonce](https://en.wikipedia.org/wiki/Cryptographic_nonce) to use in
        /// the encryption process. It is recommended that this be set to `None`, which will cause
        /// alkali to randomly generate a nonce for the message. If you specify a custom nonce, it
        /// is vital the nonce is never used to encrypt more than one message under the same key:
        /// Nonce reuse could result in an attacker recovering the secret key. Nonces are not
        /// secret, but will need to be communicated to the decrypting party for them to be able to
        /// decrypt the message. This function will return the nonce used for the encryption of this
        /// message.
        ///
        ///
        /// The encrypted ciphertext will be written to `output`. The ciphertext will be the same
        /// length as `message`, so `output` must be of sufficient size to store at least this many
        /// bytes. An error will be returned if `output` is not sufficient to store the ciphertext.
        ///
        /// If encryption is successful, returns the number of bytes written to `output` (this will
        /// actually always be `message.len()` bytes), the [`Nonce`] used for the encryption
        /// process, and the authentication tag for the message (a [`MAC`]).
        ///
        /// # Security Considerations
        /// Nonces must *never* be used more than once with the same key. You should specify `None`
        /// for the nonce to use, which will cause a random nonce to be generated for every message,
        /// unless you have good reason to do otherwise.
        pub fn encrypt_detached(
            message: &[u8],
            key: &Key,
            nonce: Option<&Nonce>,
            output: &mut [u8],
        ) -> Result<(usize, Nonce, MAC), AlkaliError> {
            require_init()?;

            if output.len() < message.len() {
                return Err(CipherError::OutputInsufficient.into());
            } else if message.len() > *MESSAGE_LENGTH_MAX {
                return Err(CipherError::MessageTooLong.into());
            }

            let nonce = if let Some(&n) = nonce {
                n
            } else {
                generate_nonce()?
            };

            let mut mac = [0u8; MAC_LENGTH];

            let encrypt_result = unsafe {
                // SAFETY: The first argument to this function is the destination to which the
                // ciphertext will be written. The ciphertext will be of the same length as the
                // message, so as long as the output pointer is valid for writes of `message.len()`,
                // it is valid to use here. We verify this condition above, and return an error if
                // the output is insufficient. The next argument is the destination to which the MAC
                // will be written. We define the `mac` array to be `crypto_secretbox_MACBYTES`, the
                // length of a MAC for this algorithm, so it is valid for writes of the required
                // length. The next two arguments specify the message to encrypt and its length. We
                // use `message.len()` to specify the message length, so `message` is definitely
                // valid for reads of this length. The next argument should be a pointer to the
                // nonce to use for encryption. We have defined the `Nonce` type to be
                // `crypto_secretbox_NONCEBYTES`, the size of a nonce for this algorithm, so it is
                // valid for reads of the required length. The final argument for this function
                // specifies the key with which the message should be encrypted. We have defined the
                // `Key` type to allocate `crypto_secretbox_KEYBYTES`, the length of a key for this
                // algorithm, so it is valid for reads of the required length. The `Key::inner`
                // method simply returns an immutable pointer to its backing memory.
                $encrypt_d(
                    output.as_mut_ptr(),
                    mac.as_mut_ptr(),
                    message.as_ptr(),
                    message.len() as libc::c_ulonglong,
                    nonce.as_ptr(),
                    key.inner() as *const libc::c_uchar,
                )
            };
            assert_not_err!(encrypt_result, stringify!($encrypt_d));

            Ok((message.len(), nonce, mac))
        }

        /// Decrypt `ciphertext` using the provided `key`, verifying the detached [`MAC`] and
        /// writing the result to `output`.
        ///
        /// `ciphertext` should be the ciphertext to decrypt, and `mac` the [`MAC`] generated when
        /// encrypting the ciphertext in detached mode with [`encrypt_detached`]. `nonce` should be
        /// the [nonce](https://en.wikipedia.org/wiki/Cryptographic_nonce) which was used to encrypt
        /// the message.
        ///
        /// The decrypted plaintext will be written to `output`. The plaintext will be the same
        /// length as `ciphertext`, so `output` must be of sufficient size to store at least this
        /// many bytes. An error will be returned if `output` is not sufficient to store the
        /// plaintext.
        ///
        /// Decryption will fail if message authentication fails. If decryption is successful, the
        /// plaintext is written to `output`, and the length of the plaintext will be returned (this
        /// will always be `ciphertext.len()` bytes).
        /// be returned.
        pub fn decrypt_detached(
            ciphertext: &[u8],
            mac: &MAC,
            key: &Key,
            nonce: &Nonce,
            output: &mut [u8],
        ) -> Result<usize, AlkaliError> {
            require_init()?;

            if output.len() < ciphertext.len() {
                return Err(CipherError::OutputInsufficient.into());
            }

            let decrypt_result = unsafe {
                // SAFETY: The first argument to this function is the destination to which the
                // decrypted plaintext will be written. The plaintext will be the same length as the
                // ciphertext, so as long as the output pointer is valid for writes of
                // `ciphertext.len()`, it is valid to use here. We verify this condition above, and
                // return an error if the output is insufficient. The next three arguments specify
                // the ciphertext to decrypt, the MAC, and the ciphertext length. We use
                // `ciphertext.len()` to specify the ciphertext length, so `ciphertext` is
                // definitely valid for reads of this length. The `MAC` type is defined to be
                // `crypto_secretbox_MACBYTES`, the length of a MAC for this algorithm, so `mac` is
                // valid for reads of the required length. The next argument should be a pointer to
                // the nonce to use for decryption. We have defined the `Nonce` type to be
                // `crypto_secretbox_NONCEBYTES`, the size of a nonce for this algorithm, so it is
                // valid for reads of the required length. The final argument for this function
                // specifies the key with which the message should be decrypted. We have defined the
                // `Key` type to allocate `crypto_secretbox_KEYBYTES`, the length of a key for this
                // algorithm, so it is valid for reads of the required length. The `Key::inner`
                // method simply returns an immutable pointer to its backing memory.
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
                Ok(ciphertext.len())
            } else {
                Err(CipherError::DecryptionFailed.into())
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
    }, )* ) => {
        use super::{
            decrypt, decrypt_detached, encrypt, encrypt_detached, generate_nonce, Key, MAC_LENGTH,
        };
        use $crate::random::fill_random;
        use $crate::AlkaliError;

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

            fill_random(&mut msg_b)?;
            fill_random(&mut msg_c)?;
            fill_random(&mut msg_d)?;

            let mut c_a = [0; MAC_LENGTH];
            let mut c_b = [0; 16 + MAC_LENGTH];
            let mut c_c = [0; 1024 + MAC_LENGTH];
            let mut c_d = [0; (1 << 18) + MAC_LENGTH];

            let (l_a, nonce_a) = encrypt(&msg_a, &key, None, &mut c_a)?;
            let (l_b, nonce_b) = encrypt(&msg_b, &key, None, &mut c_b)?;
            let (l_c, nonce_c) = encrypt(&msg_c, &key, None, &mut c_c)?;
            let (l_d, nonce_d) = encrypt(&msg_d, &key, None, &mut c_d)?;

            assert_eq!(l_a, MAC_LENGTH);
            assert_eq!(l_b, 16 + MAC_LENGTH);
            assert_eq!(l_c, 1024 + MAC_LENGTH);
            assert_eq!(l_d, (1 << 18) + MAC_LENGTH);

            assert_eq!(decrypt(&c_a, &key, &nonce_a, &mut msg_a)?, 0);
            assert_eq!(decrypt(&c_b, &key, &nonce_b, &mut msg_b)?, 16);
            assert_eq!(decrypt(&c_c, &key, &nonce_c, &mut msg_c)?, 1024);
            assert_eq!(decrypt(&c_d, &key, &nonce_d, &mut msg_d)?, 1 << 18);

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

            let (mut l_a, nonce_a, mut mac_a) = encrypt_detached(&msg_a, &key, None, &mut c_a)?;
            let (mut l_b, nonce_b, mac_b) = encrypt_detached(&msg_b, &key, None, &mut c_b)?;
            let (mut l_c, nonce_c, mac_c) = encrypt_detached(&msg_c, &key, None, &mut c_c)?;
            let (mut l_d, nonce_d, mac_d) = encrypt_detached(&msg_d, &key, None, &mut c_d)?;

            assert_eq!(l_a, 0);
            assert_eq!(l_b, 16);
            assert_eq!(l_c, 1024);
            assert_eq!(l_d, 1 << 18);

            l_a = decrypt_detached(&c_a, &mac_a, &key, &nonce_a, &mut msg_a)?;
            l_b = decrypt_detached(&c_b, &mac_b, &key, &nonce_b, &mut msg_b)?;
            l_c = decrypt_detached(&c_c, &mac_c, &key, &nonce_c, &mut msg_c)?;
            l_d = decrypt_detached(&c_d, &mac_d, &key, &nonce_d, &mut msg_d)?;

            assert_eq!(l_a, 0);
            assert_eq!(l_b, 16);
            assert_eq!(l_c, 1024);
            assert_eq!(l_d, 1 << 18);

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
                let (l, _) = encrypt(&$msg, &key, Some(&$nonce), &mut c)?;
                assert_eq!(l, $msg.len() + MAC_LENGTH);
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
                let (l, _, mac) = encrypt_detached(&$msg, &key, Some(&$nonce), &mut c)?;
                assert_eq!(l, $msg.len());
                assert_eq!(&c, &$c);
                assert_eq!(&mac, &$mac);
                let mut m = vec![0; $msg.len()];
                assert_eq!(decrypt_detached(&c, &mac, &key, &$nonce, &mut m)?, $msg.len());
                assert_eq!(&m, &$msg);
            )*

            Ok(())
        }
    };
}

/// The [XSalsa20](https://cr.yp.to/snuffle.html) cipher with a
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

/// The [XChaCha20](https://cr.yp.to/chacha.html) cipher with a
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
