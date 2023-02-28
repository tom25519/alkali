//! Low-level, unauthenticated [stream cipher](https://en.wikipedia.org/wiki/Stream_cipher)
//! constructions.
//!
//! This module corresponds to the [`crypto_stream`
//! API](https://doc.libsodium.org/advanced/stream_ciphers) from Sodium.
//!
//! Stream ciphers are a low-level building block of many modern cryptosystems. Essentially, a
//! stream cipher just generates an arbitrary amount of pseudorandom data based on a key and a
//! nonce, which is then combined with the plaintext via an XOR operation to produce ciphertext.
//!
//! This API is very low level, and is easy to misuse. The primary concern is that no
//! *authentication* is performed for the ciphertext, so an attacker can modify the ciphertext and
//! it will still decrypt correctly, potentially leading to a wide variety of vulnerabilities.
//! Unless you have a specific need for which only this construction will do, you should use the
//! standard [`symmetric::cipher`](crate::symmetric::cipher) API to encrypt messages.
//!
//! # Algorithm Details
//! The default stream cipher algorithm is [XSalsa20](https://cr.yp.to/snuffle.html) (Salsa20 with
//! an eXtended nonce length), available as [`xsalsa20`].
//!
//! Also available are Salsa20 ([`salsa20`]), [XChaCha20](https://cr.yp.to/chacha.html)
//! ([`xchacha20`]), and ChaCha20 ([`chacha20`]); as well as the IETF-specified variant of ChaCha20
//! ([`chacha20_ietf`]).
//!
//! Furthermore, Salsa20/12 (Salsa20 reduced to 12 rounds, [`salsa2012`]) and Salsa20/8 (Salsa20
//! reduced to 8 rounds, [`salsa208`]) are also available on non-minimal builds.
//!
//! # Security Considerations
//! Each of the stream ciphers in this module has different security properties, which must be
//! carefully considered before use. Each algorithm's documentation will list its individual
//! security considerations:
//! * [XSalsa20](xsalsa20#security-considerations)
//! * [Salsa20](salsa20#security-considerations)
//! * [Salsa20/12](salsa2012#security-considerations)
//! * [Salsa20/8](salsa208#security-considerations)
//! * [XChaCha20](xchacha20#security-considerations)
//! * [ChaCha20](chacha20#security-considerations)
//! * [ChaCha20-IETF](chacha20_ietf#security-considerations)
//!
//! Common to all of the algorithms here is that nonces must *never* be used more than once with the
//! same key. For the extended nonce algorithms (XSalsa20 and XChaCha20), random nonces can be used
//! for every message, but for the other algorithms, the nonce size is too short for the possibility
//! of nonce reuse to be negligible. Again, read the individual algorithms' documentation for more
//! details.
//!
//! This API exposes *unauthenticated* stream ciphers, low-level constructions which are not suited
//! to general use. There is no way to detect if an attacker has modified the ciphertext. You should
//! generally prefer to use the authenticated [`symmetric::cipher`](crate::symmetric::cipher)
//! construction, unless you are using this API as part of a wider authenticated protocol.
//!
//! These algorithms expose the length of the plaintext. If this is undesirable, apply padding to
//! the plaintext prior to encryption via [`util::pad`](crate::util::pad), and remove it following
//! decryption via [`util::unpad`](crate::util::unpad).

use crate::AlkaliError;

crate::error_type! {
    /// Error type returned if something went wrong in the `symmetric::stream` module.
    StreamCipherError {
        /// The output buffer is too short to store the ciphertext/plaintext which would result from
        /// encrypting/decrypting this message.
        OutputInsufficient,

        /// Message too long to encrypt/decrypt with this cipher.
        ///
        /// Beyond a certain point, the keystream of the cipher is exhausted, and it can no longer
        /// be used to safely encrypt messages. Therefore, this error is returned if the message
        /// provided is too long. Messages can be at most [`struct@MESSAGE_LENGTH_MAX`] bytes.
        MessageTooLong,
    }
}

/// Treat `nonce` as a little-endian unsigned integer, and increment it by one.
///
/// This is useful for ensuring a different nonce is used for every message: Increment the nonce for
/// every message sent. View the security considerations associated with this algorithm for more
/// information on preventing nonce reuse.
pub fn increment_nonce(nonce: &mut [u8]) -> Result<(), AlkaliError> {
    crate::util::increment_le(nonce)
}

macro_rules! stream_module {
    (
        $key_len:expr,      // crypto_stream_KEYBYTES
        $nonce_len:expr,    // crypto_stream_NONCEBYTES
        $msg_max:path,      // crypto_stream_messagebytes_max
        $keygen:path,       // crypto_stream_keygen
        $stream:path,       // crypto_stream
        $xor:path,          // crypto_stream_xor
    ) => {
        use super::StreamCipherError;
        use $crate::{assert_not_err, mem, require_init, AlkaliError};

        /// The length of a key used for encryption/decryption with this algorithm, in bytes.
        pub const KEY_LENGTH: usize = $key_len as usize;

        /// The length of a message nonce, in bytes.
        pub const NONCE_LENGTH: usize = $nonce_len as usize;

        lazy_static::lazy_static! {
            /// The maximum message length which can be encrypted with this cipher, in bytes.
            pub static ref MESSAGE_LENGTH_MAX: usize = unsafe {
                // SAFETY: This function just returns a constant value, and should always be safe to
                // call.
                $msg_max()
            };
        }

        mem::hardened_buffer! {
            /// A secret key for this stream cipher.
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
            /// equivalent to a `[u8; KEY_LENGTH]`, and implements [`core::ops::Deref`] so it can be
            /// used like it is an `&[u8]`. This struct uses heap memory while in scope, allocated
            /// using Sodium's [secure memory
            /// utilities](https://doc.libsodium.org/memory_management).
            pub Key(KEY_LENGTH);
        }

        impl Key<mem::FullAccess> {
            /// Generate a new, random key for use with this stream cipher.
            pub fn generate() -> Result<Self, AlkaliError> {
                require_init()?;

                let mut key = Self::new_empty()?;
                unsafe {
                    // SAFETY: This function expects a pointer to a region of memory sufficient to
                    // store a key. The `Key` type allocates `$key_len` bytes, the length of a key
                    // for this algorithm. It is therefore valid for writes of the required length.
                    // The `Key::inner_mut` method simply returns a mutable pointer to the struct's
                    // backing memory.
                    $keygen(key.inner_mut().cast());
                }
                Ok(key)
            }
        }

        /// A nonce, used to introduce non-determinism into the keystream calculation.
        ///
        /// Nonces must never be used for multiple messages with the same key.
        pub type Nonce = [u8; NONCE_LENGTH];

        /// Derive the keystream for the given [`Key`] and [`Nonce`] with this cipher.
        ///
        /// This function will fill `output` with pseudorandom data derived from the provided key &
        /// nonce, using this stream cipher. This pseudorandom data is, in fact, the
        /// [keystream](https://en.wikipedia.org/wiki/Keystream) for the key & nonce. In this stream
        /// cipher, to encrypt a message, this keystream would be XOR'd with the plaintext (so this
        /// function is equivalent to encrypting a message of all zeroes). Therefore, the standard
        /// concerns about nonce reuse with this cipher apply: Do not reuse nonces with the same
        /// key if the keystream is to be used to encrypt messages.
        pub fn keystream(
            key: &Key<impl mem::MprotectReadable>,
            nonce: &Nonce,
            output: &mut [u8],
        ) -> Result<(), AlkaliError> {
            require_init()?;

            if output.len() > *MESSAGE_LENGTH_MAX {
                return Err(StreamCipherError::MessageTooLong.into());
            }

            let stream_result = unsafe {
                // SAFETY: The first two arguments to this function specify the destination to which
                // the keystream should be written, and the length of the pseudorandom data to write
                // to the destination. We use `output.len()` to specify the number of bytes of
                // random data to write, so `output` is clearly valid for writes of this length. The
                // third argument specifies the nonce to use to derive the keystream. We define the
                // `Nonce` type to be `$nonce_len` bytes long, the length of a nonce for this
                // algorithm, so `nonce` is valid for reads of the required length. The final
                // argument specifies the key to use for the keystream calculation. We define the
                // `Key` type to allocate `$key_len` bytes, the length of a key for this algorithm,
                // so `key` is valid for reads of the required length.
                $stream(
                    output.as_mut_ptr(),
                    output.len() as libc::c_ulonglong,
                    nonce.as_ptr(),
                    key.inner().cast(),
                )
            };
            assert_not_err!(stream_result, stringify!($stream));

            Ok(())
        }

        /// Encrypt `message` using the provided [`Key`], writing the result to `output`.
        ///
        /// `message` should be the message to encrypt. `key` should be a [`Key`] generated randomly
        /// using [`Key::generate`].
        ///
        /// `nonce` should be a [nonce](https://en.wikipedia.org/wiki/Cryptographic_nonce) to use in
        /// the encryption process. Nonces must *never* be used more than once with the same key.
        /// See this algorithm's security considerations for more information on safely managing
        /// nonces.
        ///
        /// The encrypted ciphertext will be written to `output`. The ciphertext will be the same
        /// length as `message`, so `output` must be of sufficient size to store at least this many
        /// bytes. An error will be returned if `output` is not sufficient to store the ciphertext.
        ///
        /// If encryption is successful, returns the number of bytes written to `output` (this will
        /// always be `message.len()` bytes).
        ///
        /// # Security Considerations
        /// Nonces must *never* be used more than once with the same key. See this algorithm's
        /// security considerations for more information on safely managing nonces.
        ///
        /// The ciphertext will not be authenticated, so an attacker could modify the ciphertext
        /// without the receiver detecting any change, potentially leading to vulnerabilities.
        pub fn encrypt(
            message: &[u8],
            key: &Key<impl mem::MprotectReadable>,
            nonce: &Nonce,
            output: &mut [u8],
        ) -> Result<usize, AlkaliError> {
            require_init()?;

            if output.len() < message.len() {
                return Err(StreamCipherError::OutputInsufficient.into());
            } else if message.len() > *MESSAGE_LENGTH_MAX {
                return Err(StreamCipherError::MessageTooLong.into());
            }

            let encrypt_result = unsafe {
                // SAFETY: The first argument to this function is the destination to which the
                // ciphertext will be written. The ciphertext will be of the same length as the
                // message, so as long as the output pointer is valid for writes of `message.len()`,
                // it is valid to use here. We verify this condition above, and return an error if
                // the output is insufficient. The next two arguments specify the message to encrypt
                // and its length. We use `message.len()` to specify the number of bytes to read
                // from `message`, so it is clearly valid for reads of this length. The next
                // argument specifies the nonce to use. We define the `Nonce` type to be
                // `$nonce_len` bytes, the length of a nonce for this algorithm, so `nonce` is valid
                // for reads of the required length. The final argument specifies the key to use. We
                // define the `Key` type to be `$key_len` bytes, the length of a key for this
                // algorithm, so `key` is valid for reads of the required length. The `Key::inner`
                // method simply returns a pointer to the struct's backing memory.
                $xor(
                    output.as_mut_ptr(),
                    message.as_ptr(),
                    message.len() as libc::c_ulonglong,
                    nonce.as_ptr(),
                    key.inner().cast(),
                )
            };
            assert_not_err!(encrypt_result, stringify!($xor));

            Ok(message.len())
        }

        /// Decrypt `ciphertext` using the provided [`Key`], writing the decrypted plaintext to
        /// `output`.
        ///
        /// `ciphertext` should be the ciphertext to decrypt. `key` should be the [`Key`] used to
        /// encrypt the ciphertext. `nonce` should be the nonce used to encrypt the ciphertext.
        ///
        /// The decrypted plaintext will be written to `output`. The plaintext will be the same
        /// length as `ciphertext`, so `output` must be of sufficient size to store at least this
        /// many bytes. An error will be returned if `output` is not sufficient to store the
        /// plaintext.
        ///
        /// If decryption is successful, returns the number of bytes written to `output` (this will
        /// always be `ciphertext.len()` bytes).
        pub fn decrypt(
            ciphertext: &[u8],
            key: &Key<impl mem::MprotectReadable>,
            nonce: &Nonce,
            output: &mut [u8],
        ) -> Result<usize, AlkaliError> {
            // Encryption and decryption are the same operation
            encrypt(ciphertext, key, nonce, output)
        }
    };

    (
        $key_len:expr,      // crypto_stream_KEYBYTES
        $nonce_len:expr,    // crypto_stream_NONCEBYTES
        $msg_max:path,      // crypto_stream_messagebytes_max
        $keygen:path,       // crypto_stream_keygen
        $stream:path,       // crypto_stream
        $xor:path,          // crypto_stream_xor
        $xor_ic:path,       // crypto_stream_xor_ic
        $ic_type:ty,        // type for the initial counter
    ) => {
        stream_module! {
            $key_len,
            $nonce_len,
            $msg_max,
            $keygen,
            $stream,
            $xor,
        }

        /// Encrypt `message` using the provided [`Key`], writing the result to `output`,
        /// customising the initial value of the block counter.
        ///
        /// `message` should be the message to encrypt.
        ///
        /// `ic` should be the desired initial value of the block counter, rather than zero. This
        /// allows direct access to any block of the message without first having to compute all
        /// previous blocks.
        ///
        /// `key` should be a [`Key`] generated randomly using [`Key::generate`].
        ///
        /// `nonce` should be a [nonce](https://en.wikipedia.org/wiki/Cryptographic_nonce) to use in
        /// the encryption process. Nonces must *never* be used more than once with the same key.
        /// See this algorithm's security considerations for more information on safely managing
        /// nonces.
        ///
        /// The encrypted ciphertext will be written to `output`. The ciphertext will be the same
        /// length as `message`, so `output` must be of sufficient size to store at least this many
        /// bytes. An error will be returned if `output` is not sufficient to store the ciphertext.
        ///
        /// If encryption is successful, returns the number of bytes written to `output` (this will
        /// always be `message.len()` bytes).
        ///
        /// # Security Considerations
        /// Nonces must *never* be used more than once with the same key. See this algorithm's
        /// security considerations for more information on safely managing nonces.
        ///
        /// The ciphertext will not be authenticated, so an attacker could modify the ciphertext
        /// without the receiver detecting any change, potentially leading to vulnerabilities.
        pub fn encrypt_ic(
            message: &[u8],
            ic: $ic_type,
            key: &Key<impl mem::MprotectReadable>,
            nonce: &Nonce,
            output: &mut [u8],
        ) -> Result<usize, AlkaliError> {
            require_init()?;

            if output.len() < message.len() {
                return Err(StreamCipherError::OutputInsufficient.into());
            } else if message.len() > *MESSAGE_LENGTH_MAX {
                return Err(StreamCipherError::MessageTooLong.into());
            }

            let encrypt_result = unsafe {
                // SAFETY: The first argument to this function is the destination to which the
                // ciphertext will be written. The ciphertext will be of the same length as the
                // message, so as long as the output pointer is valid for writes of `message.len()`,
                // it is valid to use here. We verify this condition above, and return an error if
                // the output is insufficient. The next two arguments specify the message to encrypt
                // and its length. We use `message.len()` to specify the number of bytes to read
                // from `message`, so it is clearly valid for reads of this length. The next
                // argument specifies the nonce to use. We define the `Nonce` type to be
                // `$nonce_len` bytes, the length of a nonce for this algorithm, so `nonce` is valid
                // for reads of the required length. The next argument specifies the initial value
                // for the block counter, which is just an integer. The final argument specifies the
                // key to use. We define the `Key` type to be `$key_len` bytes, the length of a key
                // for this algorithm, so `key` is valid for reads of the required length. The
                // `Key::inner` method simply returns a pointer to the struct's backing memory.
                $xor_ic(
                    output.as_mut_ptr(),
                    message.as_ptr(),
                    message.len() as libc::c_ulonglong,
                    nonce.as_ptr(),
                    ic,
                    key.inner().cast(),
                )
            };
            assert_not_err!(encrypt_result, stringify!($xor));

            Ok(message.len())
        }

        /// Decrypt `ciphertext` using the provided [`Key`], writing the decrypted plaintext to
        /// `output`, customising the initial value of the block counter.
        ///
        /// `ciphertext` should be the ciphertext to decrypt.
        ///
        /// `ic` should be the desired initial value of the block counter, rather than zero. This
        /// allows direct access to any block of the message without first having to compute all
        /// previous blocks.
        ///
        /// `key` should be the [`Key`] used to encrypt the ciphertext. `nonce` should be the nonce
        /// used to encrypt the ciphertext.
        ///
        /// The decrypted plaintext will be written to `output`. The plaintext will be the same
        /// length as `ciphertext`, so `output` must be of sufficient size to store at least this
        /// many bytes. An error will be returned if `output` is not sufficient to store the
        /// plaintext.
        ///
        /// If decryption is successful, returns the number of bytes written to `output` (this will
        /// always be `ciphertext.len()` bytes).
        pub fn decrypt_ic(
            ciphertext: &[u8],
            ic: $ic_type,
            key: &Key<impl mem::MprotectReadable>,
            nonce: &Nonce,
            output: &mut [u8],
        ) -> Result<usize, AlkaliError> {
            // Encryption and decryption are the same operation
            encrypt_ic(ciphertext, ic, key, nonce, output)
        }
    };
}

macro_rules! expansion_function {
    (
        $counter_len:expr,
        $const_len:expr,
        $expand_outlen:expr,
        $(#[$metadata:meta])*
        $expand:path,
    ) => {
        /// The length of the input to [`expand`], normally a combined nonce + counter, in bytes.
        pub const EXPAND_INPUT_LENGTH: usize = $counter_len as usize;

        /// The length of custom constants for [`expand`], in bytes.
        pub const EXPAND_CONSTANTS_LENGTH: usize = $const_len as usize;

        /// The length of the output of [`expand`], in bytes.
        pub const EXPAND_OUTPUT_LENGTH: usize = $expand_outlen as usize;

        /// The input to [`expand`].
        ///
        /// Generally, the first half of this is the nonce being used for encryption, and the second
        /// half is the block counter.
        pub type ExpandInput = [u8; EXPAND_INPUT_LENGTH];

        /// Custom constants to use for [`expand`].
        pub type ExpandConstants = [u8; EXPAND_CONSTANTS_LENGTH];

        $(#[$metadata])*
        pub fn expand(
            key: &Key<impl mem::MprotectReadable>,
            n: &ExpandInput,
            constants: Option<&ExpandConstants>,
            output: &mut [u8],
        ) -> Result<(), AlkaliError> {
            require_init()?;

            if output.len() < EXPAND_OUTPUT_LENGTH {
                return Err(StreamCipherError::OutputInsufficient.into());
            }

            let const_ptr = match constants {
                Some(c) => c.as_ptr(),
                None => core::ptr::null(),
            };

            let expand_result = unsafe {
                // SAFETY: The first argument to this function is the destination to which the
                // expanded output will be written. The output will be `$expand_outlen` bytes long.
                // We verify above that `output` is at least this many bytes in length, so `output`
                // is valid for writes of the required length. The next argument is the input to the
                // expansion function, used to expand the key. We define the `ExpandInput` type to
                // be `$counter_len` bytes long, the length of the input to the expansion function,
                // so `n` is valid for reads of the required length. The next argument is the key to
                // expand. The key type should be defined to be `crypto_stream_KEYBYTES` for this
                // cipher, which is equal to `crypto_core_KEYBYTES`, the length of a key for this
                // algorithm, so `key` is valid for reads of the required length. The next argument
                // is a pointer to custom constants to use in the expansion function. If constants
                // are provided, we pass a pointer to `c`, which is defined to be
                // `crypto_core_CONSTBYTES`, the expected size of custom constants for this
                // algorithm, so `c` is valid for reads of the required length. Otherwise, we pass a
                // null pointer, in which case Sodium is documented to ignore this argument. The
                // `Key::inner` method simply returns an immutable pointer to the struct's backing
                // memory.
                $expand(
                    output.as_mut_ptr(),
                    n.as_ptr(),
                    key.inner().cast(),
                    const_ptr,
                )
            };
            assert_not_err!(expand_result, stringify!($expand));

            Ok(())
        }
    };
}

#[allow(unused_macros)]
macro_rules! stream_tests {
    ( $( {
        msg: $msg:expr,
        key: $key:expr,
        nonce: $nonce:expr,
        c: $c:expr,
        ks: $keystream:expr,
    }, )* ) => {
        use super::{decrypt, encrypt, keystream, Key, NONCE_LENGTH};
        use $crate::{random, AlkaliError};

        #[test]
        fn key_generation() -> Result<(), AlkaliError> {
            let _key = Key::generate()?;
            Ok(())
        }

        #[test]
        fn enc_and_dec() -> Result<(), AlkaliError> {
            let key = Key::generate()?;

            let msg_a = [];
            let mut nonce_a = [0; NONCE_LENGTH];
            let mut msg_b = [0; 16];
            let mut nonce_b = [0; NONCE_LENGTH];
            let mut msg_c = [0; 1024];
            let mut nonce_c = [0; NONCE_LENGTH];
            let mut msg_d = [0; 1 << 18];
            let mut nonce_d = [0; NONCE_LENGTH];

            random::fill_random(&mut nonce_a)?;
            random::fill_random(&mut msg_b)?;
            random::fill_random(&mut nonce_b)?;
            random::fill_random(&mut msg_c)?;
            random::fill_random(&mut nonce_c)?;
            random::fill_random(&mut msg_d)?;
            random::fill_random(&mut nonce_d)?;

            let mut c_a = [];
            let mut c_b = [0; 16];
            let mut c_c = [0; 1024];
            let mut c_d = [0; 1 << 18];

            assert_eq!(encrypt(&msg_a, &key, &nonce_a, &mut c_a)?, 0);
            assert_eq!(encrypt(&msg_b, &key, &nonce_b, &mut c_b)?, 16);
            assert_eq!(encrypt(&msg_c, &key, &nonce_c, &mut c_c)?, 1024);
            assert_eq!(encrypt(&msg_d, &key, &nonce_d, &mut c_d)?, 1 << 18);

            let mut p_a = [];
            let mut p_b = [0; 16];
            let mut p_c = [0; 1024];
            let mut p_d = [0; 1 << 18];

            assert_eq!(decrypt(&c_a, &key, &nonce_a, &mut p_a)?, 0);
            assert_eq!(decrypt(&c_b, &key, &nonce_b, &mut p_b)?, 16);
            assert_eq!(decrypt(&c_c, &key, &nonce_c, &mut p_c)?, 1024);
            assert_eq!(decrypt(&c_d, &key, &nonce_d, &mut p_d)?, 1 << 18);

            assert_eq!(msg_b, p_b);
            assert_eq!(msg_c, p_c);
            assert_eq!(msg_d, p_d);

            Ok(())
        }

        #[test]
        fn test_vectors() -> Result<(), AlkaliError> {
            let mut key = Key::new_empty()?;
            let mut m = [0; 1024];
            let mut c = [0; 1024];
            let mut ks = [0; 1024];

            $(
                key.copy_from_slice(&$key);
                assert_eq!(encrypt(&$msg, &key, &$nonce, &mut c)?, $msg.len());
                assert_eq!(&c[..$msg.len()], &$c[..$msg.len()]);
                assert_eq!(decrypt(&$c[..$msg.len()], &key, &$nonce, &mut m)?, $msg.len());
                assert_eq!(&m[..$msg.len()], &$msg[..$msg.len()]);
                keystream(&key, &$nonce, &mut ks[..$msg.len()])?;
                assert_eq!(&ks[..$msg.len()], &$keystream[..$msg.len()]);
            )*

            Ok(())
        }
    };
}

#[allow(unused_macros)]
macro_rules! expansion_tests {
    ( $( {
        key: $key:expr,
        n: $n:expr,
        c: $c:expr,
        out: $out:expr,
    }, )* ) => {
        use super::{expand, EXPAND_OUTPUT_LENGTH};

        #[test]
        fn expand_vectors() -> Result<(), AlkaliError> {
            let mut key = Key::new_empty()?;
            let mut out = [0; EXPAND_OUTPUT_LENGTH];

            $(
                key.copy_from_slice(&$key);
                expand(&key, &$n, Some(&$c), &mut out)?;
                assert_eq!(out, $out);
            )*

            Ok(())
        }
    };
}

/// The [XSalsa20](https://cr.yp.to/snuffle.html) stream cipher (Salsa20 with an eXtended nonce
/// length).
///
/// This module corresponds to the [`crypto_stream_xsalsa20`
/// API](https://doc.libsodium.org/advanced/stream_ciphers/xsalsa20) from Sodium.
///
/// # Security Considerations
/// For this algorithm, nonces must *never* be used more than once with the same key. For XSalsa20,
/// the nonce size is sufficient that a random nonce can be generated for every message, and the
/// possibility of nonce reuse is negligible. Therefore, it is recommended that you generate a
/// random nonce for every message using the [`crate::random`] API.
///
/// This is an *unauthenticated* stream cipher, a low-level construction which is not suited to
/// general use. There is no way to detect if an attacker has modified the ciphertext. You should
/// generally prefer to use the authenticated [`symmetric::cipher`](crate::symmetric::cipher)
/// construction, unless you are using this cipher as part of a wider authenticated protocol.
///
/// This construction exposes the length of the plaintext. If this is undesirable, apply padding to
/// the plaintext prior to encryption via [`util::pad`](crate::util::pad), and remove it following
/// decryption via [`util::unpad`](crate::util::unpad).
///
/// ## Secret Data
/// * The encryption/decryption key ([`Key`]) must only be known to parties who should be able to
///   both encrypt and decrypt messages
/// * The keystream outputted by [`keystream`] should be treated as sensitive if the same [`Key`] is
///   being used to encrypt/decrypt messages
///
/// ## Non-Secret Data
/// * Nonces ([`Nonce`]) are not sensitive
pub mod xsalsa20 {
    use libsodium_sys as sodium;

    stream_module! {
        sodium::crypto_stream_xsalsa20_KEYBYTES,
        sodium::crypto_stream_xsalsa20_NONCEBYTES,
        sodium::crypto_stream_xsalsa20_messagebytes_max,
        sodium::crypto_stream_xsalsa20_keygen,
        sodium::crypto_stream_xsalsa20,
        sodium::crypto_stream_xsalsa20_xor,
        sodium::crypto_stream_xsalsa20_xor_ic,
        u64,
    }

    /// The length of a nonce for the [`hsalsa20`] function, in bytes.
    pub const HSALSA_NONCE_LENGTH: usize = sodium::crypto_core_hsalsa20_INPUTBYTES as usize;

    /// The length of custom constants for [`hsalsa20`], in bytes.
    pub const HSALSA_CONSTANTS_LENGTH: usize = sodium::crypto_core_hsalsa20_CONSTBYTES as usize;

    /// The length of the output of [`hsalsa20`], in bytes.
    pub const HSALSA_OUTPUT_LENGTH: usize = sodium::crypto_core_hsalsa20_OUTPUTBYTES as usize;

    /// A nonce for [`hsalsa20`].
    pub type HSalsaNonce = [u8; HSALSA_NONCE_LENGTH];

    /// Custom constants to use for [`hsalsa20`].
    pub type HSalsaConstants = [u8; HSALSA_CONSTANTS_LENGTH];

    /// The raw HSalsa20 function.
    ///
    /// This is the HSalsa20 function detailed in section 2 of the paper [*Extending the Salsa20
    /// nonce*](https://cr.yp.to/snuffle/xsalsa-20081128.pdf). HSalsa20 is a key component used in
    /// the definition of XSalsa20: XSalsa20 takes a 32-byte key and 24-byte nonce as input. The key
    /// and first 16 bytes of the nonce are used as input for HSalsa20, which outputs a 32-byte
    /// value. This 32-byte value is then used as the key for the Salsa20 cipher, with the final 8
    /// bytes of the XSalsa20 nonce as the nonce for the Salsa20 cipher.
    ///
    /// `key` should be the [`Key`] for XSalsa20. `nonce` should be the [`HSalsaNonce`], generally
    /// the first 16 bytes of a full XSalsa20 [`Nonce`].
    ///
    /// `constants` can be used to specify custom constants for the HSalsa20 function: These are the
    /// sigma values from the original Salsa20 definition. By default, these are set to `[101, 120,
    /// 112, 97, 110, 100, 32, 51, 50, 45, 98, 121, 116, 101, 32, 107]`, the ASCII representation of
    /// `expand 32-byte k`. There is generally no reason to change these values.
    ///
    /// The output of this function will be written to `output`, which must be at least
    /// [`HSALSA_OUTPUT_LENGTH`] bytes long. The number of bytes written will always be
    /// [`HSALSA_OUTPUT_LENGTH`] bytes.
    ///
    /// # Security Considerations
    /// This is a very low-level function, and generally does not need to be used directly.
    ///
    /// The output of this function is the key which will be used for Salsa20 as part of XSalsa20's
    /// encryption calculation, so it should be treated as sensitive data.
    ///
    /// The [`HSalsaNonce`] input to this function should *never* be used more than once with the
    /// same key.
    pub fn hsalsa20(
        key: &Key<impl mem::MprotectReadable>,
        nonce: &HSalsaNonce,
        constants: Option<&HSalsaConstants>,
        output: &mut [u8],
    ) -> Result<(), AlkaliError> {
        require_init()?;

        if output.len() < HSALSA_OUTPUT_LENGTH {
            return Err(StreamCipherError::OutputInsufficient.into());
        }

        let const_ptr = match constants {
            Some(c) => c.as_ptr(),
            None => core::ptr::null(),
        };

        let hsalsa_result = unsafe {
            // SAFETY: The first argument to this function is the destination to which the output
            // will be written. The output will be `crypto_core_hsalsa20_OUTPUTBYTES` bytes long. We
            // verify above that `output` is at least this many bytes in length, so `output` is
            // valid for writes of the required length. The next argument is the nonce for HSalsa20,
            // which should be `crypto_core_hsalsa20_NONCEBYTES` bytes long. We define `HSalsaNonce`
            // to be this length, so `nonce` is valid for reads of the required size. The next
            // argument is the key to expand. The key type is defined to be
            // `crypto_stream_xsalsa20_KEYBYTES`, which is equal to `crypto_core_hsalsa20_KEYBYTES`,
            // the length of a key for HSalsa20, so `key` is valid for reads of the required length.
            // The final argument is a pointer to custom constants to use with HSalsa20. If
            // constants are provided, we pass a pointer to `c`, which is defined to be
            // `crypto_core_hsalsa20_CONSTBYTES`, the expected size of custom constants for this
            // algorithm, so `c` is valid for reads of the required length. Otherwise, we pass a
            // null pointer, in which case Sodium is documented to ignore this argument. The
            // `Key::inner` method simply returns an immutable pointer to the struct's backing
            // memory.
            sodium::crypto_core_hsalsa20(
                output.as_mut_ptr(),
                nonce.as_ptr(),
                key.inner().cast(),
                const_ptr,
            )
        };
        assert_not_err!(hsalsa_result, "crypto_core_hsalsa20");

        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::{hsalsa20, HSALSA_OUTPUT_LENGTH};

        stream_tests! [
            {
                msg:    [0xbe, 0x07, 0x5f, 0xc5, 0x3c, 0x81, 0xf2, 0xd5, 0xcf, 0x14, 0x13, 0x16,
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
                key:    [0x1b, 0x27, 0x55, 0x64, 0x73, 0xe9, 0x85, 0xd4, 0x62, 0xcd, 0x51, 0x19,
                         0x7a, 0x9a, 0x46, 0xc7, 0x60, 0x09, 0x54, 0x9e, 0xac, 0x64, 0x74, 0xf2,
                         0x06, 0xc4, 0xee, 0x08, 0x44, 0xf6, 0x83, 0x89],
                nonce:  [0x69, 0x69, 0x6e, 0xe9, 0x55, 0xb6, 0x2b, 0x73, 0xcd, 0x62, 0xbd, 0xa8,
                         0x75, 0xfc, 0x73, 0xd6, 0x82, 0x19, 0xe0, 0x03, 0x6b, 0x7a, 0x0b, 0x37],
                c:      [0x50, 0xa1, 0xf8, 0xe0, 0x20, 0x9f, 0x80, 0x44, 0xa2, 0x05, 0xd1, 0xdd,
                         0xca, 0xa6, 0x30, 0x5e, 0x77, 0x11, 0xd7, 0x37, 0xc2, 0x41, 0x85, 0xb1,
                         0x66, 0x03, 0x9b, 0x3f, 0xac, 0xeb, 0xb7, 0x7c, 0xd5, 0x72, 0xde, 0xf5,
                         0x47, 0x54, 0x95, 0xbc, 0x17, 0x45, 0x6b, 0x78, 0x87, 0x7b, 0x1b, 0x9c,
                         0x76, 0xc7, 0xd7, 0x8c, 0x79, 0x1a, 0x3c, 0x84, 0x11, 0xbf, 0x50, 0x90,
                         0x64, 0xcf, 0x8c, 0xa7, 0x2b, 0x08, 0x93, 0xf6, 0xa7, 0x27, 0x6d, 0x0c,
                         0x99, 0x8a, 0xe2, 0xba, 0x13, 0x10, 0x28, 0x0c, 0xff, 0xf8, 0xab, 0x64,
                         0x6e, 0x16, 0xdf, 0x9c, 0x38, 0xf1, 0x80, 0xf9, 0x73, 0x30, 0xd3, 0xd7,
                         0xbe, 0x3c, 0x71, 0x2d, 0x50, 0x14, 0xa3, 0x1a, 0x3e, 0xfc, 0xe6, 0x26,
                         0x89, 0x41, 0x88, 0xab, 0x82, 0x74, 0x9f, 0xbe, 0xf1, 0x42, 0x8e, 0x20,
                         0x5f, 0xa3, 0xc9, 0xcb, 0x7c, 0x57, 0xbe, 0x60, 0xc3, 0x0d, 0x59],
                ks:     [0xee, 0xa6, 0xa7, 0x25, 0x1c, 0x1e, 0x72, 0x91, 0x6d, 0x11, 0xc2, 0xcb,
                         0x21, 0x4d, 0x3c, 0x25, 0x25, 0x39, 0x12, 0x1d, 0x8e, 0x23, 0x4e, 0x65,
                         0x2d, 0x65, 0x1f, 0xa4, 0xc8, 0xcf, 0xf8, 0x80, 0x30, 0x9e, 0x64, 0x5a,
                         0x74, 0xe9, 0xe0, 0xa6, 0x0d, 0x82, 0x43, 0xac, 0xd9, 0x17, 0x7a, 0xb5,
                         0x1a, 0x1b, 0xeb, 0x8d, 0x5a, 0x2f, 0x5d, 0x70, 0x0c, 0x09, 0x3c, 0x5e,
                         0x55, 0x85, 0x57, 0x96, 0x25, 0x33, 0x7b, 0xd3, 0xab, 0x61, 0x9d, 0x61,
                         0x57, 0x60, 0xd8, 0xc5, 0xb2, 0x24, 0xa8, 0x5b, 0x1d, 0x0e, 0xfe, 0x0e,
                         0xb8, 0xa7, 0xee, 0x16, 0x3a, 0xbb, 0x03, 0x76, 0x52, 0x9f, 0xcc, 0x09,
                         0xba, 0xb5, 0x06, 0xc6, 0x18, 0xe1, 0x3c, 0xe7, 0x77, 0xd8, 0x2c, 0x3a,
                         0xe9, 0xd1, 0xa6, 0xf9, 0x72, 0xd4, 0x16, 0x02, 0x87, 0xcb, 0xfe, 0x60,
                         0xbf, 0x21, 0x30, 0xfc, 0x0a, 0x6f, 0xf6, 0x04, 0x9d, 0x0a, 0x5c],
            },
            {
                msg:    [] as [u8; 0],
                key:    [0x1b, 0x27, 0x55, 0x64, 0x73, 0xe9, 0x85, 0xd4, 0x62, 0xcd, 0x51, 0x19,
                         0x7a, 0x9a, 0x46, 0xc7, 0x60, 0x09, 0x54, 0x9e, 0xac, 0x64, 0x74, 0xf2,
                         0x06, 0xc4, 0xee, 0x08, 0x44, 0xf6, 0x83, 0x89],
                nonce:  [0x69, 0x69, 0x6e, 0xe9, 0x55, 0xb6, 0x2b, 0x73, 0xcd, 0x62, 0xbd, 0xa8,
                         0x75, 0xfc, 0x73, 0xd6, 0x82, 0x19, 0xe0, 0x03, 0x6b, 0x7a, 0x0b, 0x37],
                c:      [],
                ks:     [],
            },
        ];

        #[test]
        fn hsalsa_vectors() -> Result<(), AlkaliError> {
            let vectors = [
                (
                    [
                        0x4a, 0x5d, 0x9d, 0x5b, 0xa4, 0xce, 0x2d, 0xe1, 0x72, 0x8e, 0x3b, 0xf4,
                        0x80, 0x35, 0x0f, 0x25, 0xe0, 0x7e, 0x21, 0xc9, 0x47, 0xd1, 0x9e, 0x33,
                        0x76, 0xf0, 0x9b, 0x3c, 0x1e, 0x16, 0x17, 0x42,
                    ],
                    [0; 16],
                    [
                        0x65, 0x78, 0x70, 0x61, 0x6e, 0x64, 0x20, 0x33, 0x32, 0x2d, 0x62, 0x79,
                        0x74, 0x65, 0x20, 0x6b,
                    ],
                    [
                        0x1b, 0x27, 0x55, 0x64, 0x73, 0xe9, 0x85, 0xd4, 0x62, 0xcd, 0x51, 0x19,
                        0x7a, 0x9a, 0x46, 0xc7, 0x60, 0x09, 0x54, 0x9e, 0xac, 0x64, 0x74, 0xf2,
                        0x06, 0xc4, 0xee, 0x08, 0x44, 0xf6, 0x83, 0x89,
                    ],
                ),
                (
                    [
                        0x1b, 0x27, 0x55, 0x64, 0x73, 0xe9, 0x85, 0xd4, 0x62, 0xcd, 0x51, 0x19,
                        0x7a, 0x9a, 0x46, 0xc7, 0x60, 0x09, 0x54, 0x9e, 0xac, 0x64, 0x74, 0xf2,
                        0x06, 0xc4, 0xee, 0x08, 0x44, 0xf6, 0x83, 0x89,
                    ],
                    [
                        0x69, 0x69, 0x6e, 0xe9, 0x55, 0xb6, 0x2b, 0x73, 0xcd, 0x62, 0xbd, 0xa8,
                        0x75, 0xfc, 0x73, 0xd6,
                    ],
                    [
                        0x65, 0x78, 0x70, 0x61, 0x6e, 0x64, 0x20, 0x33, 0x32, 0x2d, 0x62, 0x79,
                        0x74, 0x65, 0x20, 0x6b,
                    ],
                    [
                        0xdc, 0x90, 0x8d, 0xda, 0x0b, 0x93, 0x44, 0xa9, 0x53, 0x62, 0x9b, 0x73,
                        0x38, 0x20, 0x77, 0x88, 0x80, 0xf3, 0xce, 0xb4, 0x21, 0xbb, 0x61, 0xb9,
                        0x1c, 0xbd, 0x4c, 0x3e, 0x66, 0x25, 0x6c, 0xe4,
                    ],
                ),
            ];

            let mut output = [0u8; HSALSA_OUTPUT_LENGTH];
            let mut k = Key::new_empty()?;

            for (key, nonce, constants, expected) in vectors {
                k.copy_from_slice(&key[..]);
                hsalsa20(&k, &nonce, Some(&constants), &mut output)?;
                assert_eq!(output, expected);
            }

            Ok(())
        }
    }
}

/// The [Salsa20](https://cr.yp.to/snuffle.html) stream cipher.
///
/// This module corresponds to the [`crypto_stream_salsa20`
/// API](https://doc.libsodium.org/advanced/stream_ciphers/salsa20) from Sodium.
///
/// # Security Considerations
/// For this algorithm, nonces must *never* be used more than once with the same key. For Salsa20,
/// the nonce size is not sufficient that random nonces can be used without the possibility of
/// collisions, also leading to nonce reuse, so it is unsafe to use random nonces with this
/// construction. Therefore, careful attention is needed to ensure nonces are only used once. If a
/// key is being reused for multiple messages, it is recommended to increment the nonce for the
/// previous message using [`increment_nonce`] for each message sent. The initial nonce can be any
/// value.
///
/// In client-server protocols, where both parties are sending messages, use different keys for each
/// direction, or ensure one bit in the nonce is always set in one direction, and always unset in
/// the other, to make sure a nonce is never reused with the same key.
///
/// This is an *unauthenticated* stream cipher, a low-level construction which is not suited to
/// general use. There is no way to detect if an attacker has modified the ciphertext. You should
/// generally prefer to use the authenticated [`symmetric::cipher`](crate::symmetric::cipher)
/// construction, unless you are using this cipher as part of a wider authenticated protocol.
///
/// This construction exposes the length of the plaintext. If this is undesirable, apply padding to
/// the plaintext prior to encryption via [`util::pad`](crate::util::pad), and remove it following
/// decryption via [`util::unpad`](crate::util::unpad).
///
/// ## Secret Data
/// * The encryption/decryption key ([`Key`]) must only be known to parties who should be able to
///   both encrypt and decrypt messages
/// * The keystream outputted by [`keystream`] should be treated as sensitive if the same [`Key`] is
///   being used to encrypt/decrypt messages
///
/// ## Non-Secret Data
/// * Nonces ([`Nonce`]) are not sensitive
pub mod salsa20 {
    use libsodium_sys as sodium;

    stream_module! {
        sodium::crypto_stream_salsa20_KEYBYTES,
        sodium::crypto_stream_salsa20_NONCEBYTES,
        sodium::crypto_stream_salsa20_messagebytes_max,
        sodium::crypto_stream_salsa20_keygen,
        sodium::crypto_stream_salsa20,
        sodium::crypto_stream_salsa20_xor,
        sodium::crypto_stream_salsa20_xor_ic,
        u64,
    }

    expansion_function! {
        sodium::crypto_core_salsa20_INPUTBYTES,
        sodium::crypto_core_salsa20_CONSTBYTES,
        sodium::crypto_core_salsa20_OUTPUTBYTES,
        /// The raw Salsa20 expansion function.
        ///
        /// This is the expansion function detailed in section 9 of the [Salsa20
        /// specification](https://cr.yp.to/snuffle/spec.pdf). Section 10 of the specification
        /// describes how Salsa20 encryption works: We begin by setting a 8-byte counter to zero,
        /// then expand the key into a 64-byte value using the concatenated nonce + counter as input
        /// to the expansion function. This expanded output is then XORed with the first 64 bytes of
        /// the plaintext. The counter is then incremented, the key is expanded again, and the next
        /// 64 bytes of plaintext are XORed with the output. This process is repeated until the
        /// entire plaintext is encrypted.
        ///
        /// `key` should be the [`Key`] to expand. `n` should be the input to use to expand the key
        /// for this block: In Salsa20 encryption, the first 8 bytes are set to the nonce to use for
        /// encryption, and the second 8 bytes are an 8-byte, little endian counter, incremented for
        /// every block.
        ///
        /// `constants` can be used to specify custom constants for the Salsa20 expansion: These are
        /// the sigma values from the specification. By default, these are set to `[101, 120, 112,
        /// 97, 110, 100, 32, 51, 50, 45, 98, 121, 116, 101, 32, 107]`, the ASCII representation of
        /// `expand 32-byte k`. There is generally no reason to change these values.
        ///
        /// The expanded output will be written to `output`, which must be at least
        /// [`EXPAND_OUTPUT_LENGTH`] bytes. The number of bytes written will always be
        /// [`EXPAND_OUTPUT_LENGTH`] bytes.
        ///
        /// # Security Considerations
        /// This is a very low-level function, and generally does not need to be used directly.
        ///
        /// The expanded output of this function is a portion of the keystream for the provided key,
        /// so it should be treated as sensitive data.
        ///
        /// The [`ExpandInput`] input to this function should *never* be used more than once with
        /// the same key.
        sodium::crypto_core_salsa20,
    }

    #[cfg(test)]
    mod tests {
        stream_tests! [
            {
                msg:    [0xbe, 0x07, 0x5f, 0xc5, 0x3c, 0x81, 0xf2, 0xd5, 0xcf, 0x14, 0x13, 0x16,
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
                key:    [0x1b, 0x27, 0x55, 0x64, 0x73, 0xe9, 0x85, 0xd4, 0x62, 0xcd, 0x51, 0x19,
                         0x7a, 0x9a, 0x46, 0xc7, 0x60, 0x09, 0x54, 0x9e, 0xac, 0x64, 0x74, 0xf2,
                         0x06, 0xc4, 0xee, 0x08, 0x44, 0xf6, 0x83, 0x89],
                nonce:  [0x69, 0x69, 0x6e, 0xe9, 0x55, 0xb6, 0x2b, 0x73],
                c:      [0x47, 0x4b, 0x7c, 0x8e, 0x05, 0x09, 0xaf, 0x47, 0xb1, 0x98, 0xa3, 0xf1,
                         0x33, 0x3b, 0x3b, 0x04, 0x65, 0x3b, 0xb3, 0x80, 0x42, 0x04, 0x47, 0x89,
                         0x86, 0xde, 0x4f, 0xdc, 0x19, 0xac, 0x6b, 0x1f, 0x01, 0x3b, 0xb4, 0x5e,
                         0x8f, 0xd1, 0x14, 0x56, 0x28, 0x25, 0xfa, 0x0e, 0xe2, 0x7e, 0x8c, 0xab,
                         0x7f, 0x81, 0x04, 0x55, 0xaf, 0xaf, 0x99, 0x1b, 0x3a, 0x8d, 0x53, 0xa0,
                         0xe0, 0x57, 0xe3, 0x93, 0x3d, 0x76, 0xf6, 0x85, 0x6f, 0x70, 0xe1, 0x0f,
                         0xbb, 0x8b, 0x68, 0x2a, 0xb1, 0xcc, 0x4b, 0xd4, 0xc9, 0x61, 0xfc, 0x77,
                         0x25, 0xc2, 0xdf, 0x98, 0x0c, 0x53, 0xba, 0xca, 0x0f, 0xc6, 0x02, 0xb1,
                         0x0a, 0x62, 0x5a, 0xf2, 0xd5, 0x40, 0xed, 0x98, 0x62, 0xff, 0xb3, 0x0c,
                         0x8e, 0xf7, 0x72, 0xbd, 0xfd, 0x0e, 0xc5, 0xc4, 0x41, 0x17, 0xdf, 0x8f,
                         0x58, 0xe2, 0x0b, 0xf2, 0x27, 0x4a, 0xc0, 0xdd, 0x9d, 0x47, 0xa2],
                ks:     [0xf9, 0x4c, 0x23, 0x4b, 0x39, 0x88, 0x5d, 0x92, 0x7e, 0x8c, 0xb0, 0xe7,
                         0xd8, 0xd0, 0x37, 0x7f, 0x37, 0x13, 0x76, 0xaa, 0x0e, 0x66, 0x8c, 0x5d,
                         0xcd, 0xb8, 0xcb, 0x47, 0x7d, 0x88, 0x24, 0xe3, 0xe4, 0xd7, 0x0e, 0xf1,
                         0xbc, 0x6c, 0x61, 0x4c, 0x32, 0xe2, 0xd2, 0xda, 0xbc, 0x12, 0xed, 0x82,
                         0x13, 0x5d, 0x38, 0x54, 0x8c, 0x9a, 0xf8, 0xef, 0x27, 0x3b, 0x3f, 0x6e,
                         0xd1, 0x1d, 0x38, 0xa2, 0x33, 0x4d, 0x1e, 0xa0, 0x63, 0x36, 0x11, 0x62,
                         0x75, 0x61, 0x52, 0x55, 0x10, 0xf8, 0xcb, 0x83, 0x2b, 0x97, 0xa9, 0x1d,
                         0xf3, 0x73, 0xee, 0x12, 0x0e, 0x19, 0x39, 0x45, 0x2e, 0x69, 0x1d, 0x6f,
                         0x0e, 0xeb, 0x2d, 0x19, 0x9d, 0xb5, 0x72, 0x65, 0x2b, 0xdb, 0x79, 0x10,
                         0xee, 0x67, 0x5c, 0xef, 0x0d, 0xae, 0x4c, 0x78, 0x37, 0x9e, 0xaf, 0xcf,
                         0xb8, 0x60, 0xf2, 0xc5, 0x51, 0x72, 0x88, 0xb9, 0xc3, 0x40, 0xa7],
            },
            {
                msg:    [] as [u8; 0],
                key:    [0x1b, 0x27, 0x55, 0x64, 0x73, 0xe9, 0x85, 0xd4, 0x62, 0xcd, 0x51, 0x19,
                         0x7a, 0x9a, 0x46, 0xc7, 0x60, 0x09, 0x54, 0x9e, 0xac, 0x64, 0x74, 0xf2,
                         0x06, 0xc4, 0xee, 0x08, 0x44, 0xf6, 0x83, 0x89],
                nonce:  [0x69, 0x69, 0x6e, 0xe9, 0x55, 0xb6, 0x2b, 0x73],
                c:      [],
                ks:     [],
            },
        ];

        expansion_tests! [
            {
                key:    [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                         0x0d, 0x0e, 0x0f, 0x10, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf, 0xd0,
                         0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8],
                n:      [0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70,
                         0x71, 0x72, 0x73, 0x74],
                c:      [0x65, 0x78, 0x70, 0x61, 0x6e, 0x64, 0x20, 0x33, 0x32, 0x2d, 0x62, 0x79,
                         0x74, 0x65, 0x20, 0x6b],
                out:    [0x45, 0x25, 0x44, 0x27, 0x29, 0x0f, 0x6b, 0xc1, 0xff, 0x8b, 0x7a, 0x06,
                         0xaa, 0xe9, 0xd9, 0x62, 0x59, 0x90, 0xb6, 0x6a, 0x15, 0x33, 0xc8, 0x41,
                         0xef, 0x31, 0xde, 0x22, 0xd7, 0x72, 0x28, 0x7e, 0x68, 0xc5, 0x07, 0xe1,
                         0xc5, 0x99, 0x1f, 0x02, 0x66, 0x4e, 0x4c, 0xb0, 0x54, 0xf5, 0xf6, 0xb8,
                         0xb1, 0xa0, 0x85, 0x82, 0x06, 0x48, 0x95, 0x77, 0xc0, 0xc3, 0x84, 0xec,
                         0xea, 0x67, 0xf6, 0x4a],
            },
            {
                key:    [0xee, 0x30, 0x4f, 0xca, 0x27, 0x00, 0x8d, 0x8c, 0x12, 0x6f, 0x90, 0x02,
                         0x79, 0x01, 0xd8, 0x0f, 0x7f, 0x1d, 0x8b, 0x8d, 0xc9, 0x36, 0xcf, 0x3b,
                         0x9f, 0x81, 0x96, 0x92, 0x82, 0x7e, 0x57, 0x77],
                n:      [0x81, 0x91, 0x8e, 0xf2, 0xa5, 0xe0, 0xda, 0x9b, 0x3e, 0x90, 0x60, 0x52,
                         0x1e, 0x4b, 0xb3, 0x52],
                c:      [0x65, 0x78, 0x70, 0x61, 0x6e, 0x64, 0x20, 0x33, 0x32, 0x2d, 0x62, 0x79,
                         0x74, 0x65, 0x20, 0x6b],
                out:    [0x21, 0x94, 0xa0, 0x5d, 0x9a, 0x52, 0x01, 0x48, 0x57, 0xe8, 0x20, 0x61,
                         0xf9, 0x06, 0x5f, 0x61, 0xfd, 0xe9, 0x8a, 0xba, 0x75, 0x90, 0xe1, 0x73,
                         0x6b, 0x2d, 0xa0, 0xdb, 0x4a, 0xfa, 0xf9, 0x2f, 0x1f, 0x1d, 0x1b, 0xe2,
                         0xf6, 0x6c, 0x5a, 0x20, 0xa7, 0x11, 0x1d, 0x21, 0x78, 0x2b, 0x1e, 0xdd,
                         0x2f, 0x54, 0x9a, 0x9a, 0x3d, 0xe6, 0xe7, 0x62, 0xb8, 0x5e, 0x21, 0x24,
                         0xa5, 0x1a, 0xc9, 0xb0],
            },
        ];
    }
}

/// The [Salsa20](https://cr.yp.to/snuffle.html) stream cipher reduced to 12 rounds (rather than the
/// usual 20).
///
/// This construction is generally referred to as Salsa20/12.
///
/// This module corresponds to the [`crypto_stream_salsa2012`
/// API](https://doc.libsodium.org/advanced/stream_ciphers/salsa20) from Sodium.
///
/// # Security Considerations
/// For this algorithm, nonces must *never* be used more than once with the same key. For
/// Salsa20/12, the nonce size is not sufficient that random nonces can be used without the
/// possibility of collisions, also leading to nonce reuse, so it is unsafe to use random nonces
/// with this construction. Therefore, careful attention is needed to ensure nonces are only used
/// once. If a key is being reused for multiple messages, it is recommended to increment the nonce
/// for the previous message using [`increment_nonce`] for each message sent. The initial nonce can
/// be any value.
///
/// In client-server protocols, where both parties are sending messages, use different keys for each
/// direction, or ensure one bit in the nonce is always set in one direction, and always unset in
/// the other, to make sure a nonce is never reused with the same key.
///
/// This is an *unauthenticated* stream cipher, a low-level construction which is not suited to
/// general use. There is no way to detect if an attacker has modified the ciphertext. You should
/// generally prefer to use the authenticated [`symmetric::cipher`](crate::symmetric::cipher)
/// construction, unless you are using this cipher as part of a wider authenticated protocol.
///
/// This construction exposes the length of the plaintext. If this is undesirable, apply padding to
/// the plaintext prior to encryption via [`util::pad`](crate::util::pad), and remove it following
/// decryption via [`util::unpad`](crate::util::unpad).
///
/// ## Secret Data
/// * The encryption/decryption key ([`Key`]) must only be known to parties who should be able to
///   both encrypt and decrypt messages
/// * The keystream outputted by [`keystream`] should be treated as sensitive if the same [`Key`] is
///   being used to encrypt/decrypt messages
///
/// ## Non-Secret Data
/// * Nonces ([`Nonce`]) are not sensitive
#[cfg(not(feature = "minimal"))]
#[cfg_attr(doc_cfg, doc(cfg(not(feature = "minimal"))))]
pub mod salsa2012 {
    use libsodium_sys as sodium;

    stream_module! {
        sodium::crypto_stream_salsa2012_KEYBYTES,
        sodium::crypto_stream_salsa2012_NONCEBYTES,
        sodium::crypto_stream_salsa2012_messagebytes_max,
        sodium::crypto_stream_salsa2012_keygen,
        sodium::crypto_stream_salsa2012,
        sodium::crypto_stream_salsa2012_xor,
    }

    expansion_function! {
        sodium::crypto_core_salsa2012_INPUTBYTES,
        sodium::crypto_core_salsa2012_CONSTBYTES,
        sodium::crypto_core_salsa2012_OUTPUTBYTES,
        /// The raw Salsa20/12 expansion function.
        ///
        /// This is the expansion function detailed in section 9 of the [Salsa20
        /// specification](https://cr.yp.to/snuffle/spec.pdf), but reduced to 12 rounds, rather than
        /// the usual 20. Section 10 of the specification describes how Salsa20/12 encryption works:
        /// We begin by setting a 8-byte counter to zero, then expand the key into a 64-byte value
        /// using the concatenated nonce + counter as input to the expansion function. This expanded
        /// output is then XORed with the first 64 bytes of the plaintext. The counter is then
        /// incremented, the key is expanded again, and the next 64 bytes of plaintext are XORed
        /// with the output. This process is repeated until the entire plaintext is encrypted.
        ///
        /// `key` should be the [`Key`] to expand. `n` should be the input to use to expand the key
        /// for this block: In Salsa20/12 encryption, the first 8 bytes are set to the nonce to use
        /// for encryption, and the second 8 bytes are an 8-byte, little endian counter, incremented
        /// for every block.
        ///
        /// `constants` can be used to specify custom constants for the Salsa20/12 expansion: These
        /// are the sigma values from the specification. By default, these are set to `[101, 120,
        /// 112, 97, 110, 100, 32, 51, 50, 45, 98, 121, 116, 101, 32, 107]`, the ASCII
        /// representation of `expand 32-byte k`. There is generally no reason to change these
        /// values.
        ///
        /// The expanded output will be written to `output`, which must be at least
        /// [`EXPAND_OUTPUT_LENGTH`] bytes. The number of bytes written will always be
        /// [`EXPAND_OUTPUT_LENGTH`] bytes.
        ///
        /// # Security Considerations
        /// This is a very low-level function, and generally does not need to be used directly.
        ///
        /// The expanded output of this function is a portion of the keystream for the provided key,
        /// so it should be treated as sensitive data.
        ///
        /// The [`ExpandInput`] input to this function should *never* be used more than once with
        /// the same key.
        sodium::crypto_core_salsa2012,
    }

    #[cfg(test)]
    mod tests {
        stream_tests![
            {
                msg:    [0xbe, 0x07, 0x5f, 0xc5, 0x3c, 0x81, 0xf2, 0xd5, 0xcf, 0x14, 0x13, 0x16,
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
                key:    [0x1b, 0x27, 0x55, 0x64, 0x73, 0xe9, 0x85, 0xd4, 0x62, 0xcd, 0x51, 0x19,
                         0x7a, 0x9a, 0x46, 0xc7, 0x60, 0x09, 0x54, 0x9e, 0xac, 0x64, 0x74, 0xf2,
                         0x06, 0xc4, 0xee, 0x08, 0x44, 0xf6, 0x83, 0x89],
                nonce:  [0x69, 0x69, 0x6e, 0xe9, 0x55, 0xb6, 0x2b, 0x73],
                c:      [0xea, 0x63, 0xb9, 0xb4, 0x04, 0xdd, 0x20, 0xc1, 0x5a, 0xba, 0x1b, 0xfc,
                         0xd9, 0x1b, 0x0f, 0xd3, 0x0d, 0x1c, 0x58, 0xe2, 0x9f, 0x67, 0x7d, 0xd4,
                         0x50, 0x00, 0x49, 0x5e, 0x0a, 0x88, 0xbe, 0x0d, 0xbb, 0x91, 0x19, 0xf6,
                         0xd5, 0x8c, 0xe2, 0x33, 0x82, 0x99, 0x2f, 0xe7, 0xd0, 0x69, 0x3b, 0x58,
                         0x2b, 0xa7, 0xed, 0xf3, 0x4a, 0xcb, 0xd3, 0x5f, 0x85, 0xe3, 0x75, 0x03,
                         0x2b, 0x76, 0x72, 0xe5, 0x1f, 0x5d, 0xb3, 0x0d, 0x23, 0x79, 0x64, 0x64,
                         0x4c, 0xcb, 0xea, 0xc2, 0x1c, 0xbe, 0x2e, 0x42, 0x6f, 0x7b, 0x19, 0xd6,
                         0x1e, 0xb5, 0x47, 0x79, 0x45, 0xfd, 0x36, 0x8a, 0x97, 0xc4, 0x03, 0xbd,
                         0x98, 0x1a, 0xc1, 0x0c, 0xb9, 0xdc, 0x7e, 0x84, 0xf8, 0xc3, 0xff, 0xe0,
                         0x24, 0xfe, 0xf2, 0x12, 0x4b, 0x51, 0x8e, 0x7f, 0x75, 0xa2, 0xa9, 0xe9,
                         0xf6, 0x2b, 0xe4, 0x7c, 0x83, 0xfa, 0x9f, 0xd3, 0x96, 0xc5, 0xfe],
                ks:     [0x54, 0x64, 0xe6, 0x71, 0x38, 0x5c, 0xd2, 0x14, 0x95, 0xae, 0x08, 0xea,
                         0x32, 0xf0, 0x03, 0xa8, 0x5f, 0x34, 0x9d, 0xc8, 0xd3, 0x05, 0xb6, 0x00,
                         0x1b, 0x66, 0xcd, 0xc5, 0x6e, 0xac, 0xf1, 0xf1, 0x5e, 0x7d, 0xa3, 0x59,
                         0xe6, 0x31, 0x97, 0x29, 0x98, 0x5e, 0x07, 0x33, 0x8e, 0x05, 0x5a, 0x71,
                         0x47, 0x7b, 0xd1, 0xf2, 0x69, 0xfe, 0xb2, 0xab, 0x98, 0x55, 0x19, 0xcd,
                         0x1a, 0x3c, 0xa9, 0xd4, 0x11, 0x66, 0x5b, 0x28, 0x2f, 0x3f, 0x94, 0x09,
                         0x82, 0x21, 0xd0, 0xbd, 0xbd, 0x8a, 0xae, 0x15, 0x8d, 0x8d, 0x4c, 0xbc,
                         0xc8, 0x04, 0x76, 0xf3, 0x47, 0xb7, 0xb5, 0x05, 0xb6, 0x6b, 0x1c, 0x63,
                         0x9c, 0x93, 0xb6, 0xe7, 0xf1, 0x29, 0xe1, 0x79, 0xb1, 0xe7, 0x35, 0xfc,
                         0x44, 0x6e, 0xdc, 0x40, 0xbb, 0xf1, 0x07, 0xc3, 0x03, 0x2b, 0xd9, 0xa9,
                         0x16, 0xa9, 0x1d, 0x4b, 0xf5, 0xc2, 0xd7, 0xb7, 0xc8, 0xc2, 0xfb],
            },
            {
                msg:    [] as [u8; 0],
                key:    [0x1b, 0x27, 0x55, 0x64, 0x73, 0xe9, 0x85, 0xd4, 0x62, 0xcd, 0x51, 0x19,
                         0x7a, 0x9a, 0x46, 0xc7, 0x60, 0x09, 0x54, 0x9e, 0xac, 0x64, 0x74, 0xf2,
                         0x06, 0xc4, 0xee, 0x08, 0x44, 0xf6, 0x83, 0x89],
                nonce:  [0x69, 0x69, 0x6e, 0xe9, 0x55, 0xb6, 0x2b, 0x73],
                c:      [],
                ks:     [],
            },
        ];

        expansion_tests! [
            {
                key:    [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                         0x0d, 0x0e, 0x0f, 0x10, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf, 0xd0,
                         0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8],
                n:      [0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70,
                         0x71, 0x72, 0x73, 0x74],
                c:      [0x65, 0x78, 0x70, 0x61, 0x6e, 0x64, 0x20, 0x33, 0x32, 0x2d, 0x62, 0x79,
                         0x74, 0x65, 0x20, 0x6b],
                out:    [0xc2, 0x84, 0xfe, 0x2e, 0xfa, 0xde, 0x74, 0x85, 0x20, 0xa9, 0xce, 0x85,
                         0x3a, 0x4e, 0xb8, 0x85, 0x89, 0x70, 0x62, 0x10, 0xee, 0x85, 0x26, 0x3b,
                         0x76, 0x13, 0x36, 0x97, 0x8c, 0xb0, 0xdf, 0xf1, 0x54, 0x49, 0xfb, 0x3d,
                         0xcb, 0xdd, 0xea, 0x0f, 0x6c, 0x6f, 0x31, 0x5f, 0x80, 0x77, 0x16, 0x70,
                         0x5c, 0xf7, 0x3d, 0x94, 0xd4, 0x87, 0x14, 0x3b, 0x02, 0xa4, 0x48, 0x81,
                         0xa5, 0xa4, 0x61, 0x79],
            },
            {
                key:    [0xee, 0x30, 0x4f, 0xca, 0x27, 0x00, 0x8d, 0x8c, 0x12, 0x6f, 0x90, 0x02,
                         0x79, 0x01, 0xd8, 0x0f, 0x7f, 0x1d, 0x8b, 0x8d, 0xc9, 0x36, 0xcf, 0x3b,
                         0x9f, 0x81, 0x96, 0x92, 0x82, 0x7e, 0x57, 0x77],
                n:      [0x81, 0x91, 0x8e, 0xf2, 0xa5, 0xe0, 0xda, 0x9b, 0x3e, 0x90, 0x60, 0x52,
                         0x1e, 0x4b, 0xb3, 0x52],
                c:      [0x65, 0x78, 0x70, 0x61, 0x6e, 0x64, 0x20, 0x33, 0x32, 0x2d, 0x62, 0x79,
                         0x74, 0x65, 0x20, 0x6b],
                out:    [0x37, 0x75, 0x1a, 0xb7, 0x13, 0x93, 0xe1, 0xa9, 0xcc, 0xff, 0xf0, 0x45,
                         0x33, 0xda, 0xec, 0xa1, 0x89, 0x7d, 0xe3, 0xa6, 0x91, 0xef, 0x36, 0x36,
                         0x79, 0x77, 0x08, 0x50, 0xb3, 0x4a, 0x22, 0x93, 0xde, 0x3f, 0x06, 0x34,
                         0xd8, 0x92, 0xa2, 0xf3, 0xdf, 0x33, 0x05, 0x61, 0xfa, 0x01, 0x0a, 0xe2,
                         0xc4, 0x71, 0x91, 0x6b, 0x31, 0x8d, 0x2d, 0x56, 0x47, 0x58, 0x43, 0x8b,
                         0x81, 0xbf, 0xed, 0xba],
            },
        ];
    }
}

/// The [Salsa20](https://cr.yp.to/snuffle.html) stream cipher reduced to 8 rounds (rather than the
/// usual 20).
///
/// This construction is generally referred to as Salsa20/8.
///
/// This module corresponds to the [`crypto_stream_salsa208`
/// API](https://doc.libsodium.org/advanced/stream_ciphers/salsa20) from Sodium.
///
/// # Security Considerations
/// For this algorithm, nonces must *never* be used more than once with the same key. For Salsa20/8,
/// the nonce size is not sufficient that random nonces can be used without the possibility of
/// collisions, also leading to nonce reuse, so it is unsafe to use random nonces with this
/// construction. Therefore, careful attention is needed to ensure nonces are only used once. If a
/// key is being reused for multiple messages, it is recommended to increment the nonce for the
/// previous message using [`increment_nonce`] for each message sent. The initial nonce can be any
/// value.
///
/// In client-server protocols, where both parties are sending messages, use different keys for each
/// direction, or ensure one bit in the nonce is always set in one direction, and always unset in
/// the other, to make sure a nonce is never reused with the same key.
///
/// This is an *unauthenticated* stream cipher, a low-level construction which is not suited to
/// general use. There is no way to detect if an attacker has modified the ciphertext. You should
/// generally prefer to use the authenticated [`symmetric::cipher`](crate::symmetric::cipher)
/// construction, unless you are using this cipher as part of a wider authenticated protocol.
///
/// This construction exposes the length of the plaintext. If this is undesirable, apply padding to
/// the plaintext prior to encryption via [`util::pad`](crate::util::pad), and remove it following
/// decryption via [`util::unpad`](crate::util::unpad).
///
/// ## Secret Data
/// * The encryption/decryption key ([`Key`]) must only be known to parties who should be able to
///   both encrypt and decrypt messages
/// * The keystream outputted by [`keystream`] should be treated as sensitive if the same [`Key`] is
///   being used to encrypt/decrypt messages
///
/// ## Non-Secret Data
/// * Nonces ([`Nonce`]) are not sensitive
#[cfg(not(feature = "minimal"))]
#[cfg_attr(doc_cfg, doc(cfg(not(feature = "minimal"))))]
pub mod salsa208 {
    use libsodium_sys as sodium;

    stream_module! {
        sodium::crypto_stream_salsa208_KEYBYTES,
        sodium::crypto_stream_salsa208_NONCEBYTES,
        sodium::crypto_stream_salsa208_messagebytes_max,
        sodium::crypto_stream_salsa208_keygen,
        sodium::crypto_stream_salsa208,
        sodium::crypto_stream_salsa208_xor,
    }

    expansion_function! {
        sodium::crypto_core_salsa208_INPUTBYTES,
        sodium::crypto_core_salsa208_CONSTBYTES,
        sodium::crypto_core_salsa208_OUTPUTBYTES,
        /// The raw Salsa20/8 expansion function.
        ///
        /// This is the expansion function detailed in section 9 of the [Salsa20
        /// specification](https://cr.yp.to/snuffle/spec.pdf), but reduced to 8 rounds, rather than
        /// the usual 20. Section 10 of the specification describes how Salsa20/8 encryption works:
        /// We begin by setting a 8-byte counter to zero, then expand the key into a 64-byte value
        /// using the concatenated nonce + counter as input to the expansion function. This expanded
        /// output is then XORed with the first 64 bytes of the plaintext. The counter is then
        /// incremented, the key is expanded again, and the next 64 bytes of plaintext are XORed
        /// with the output. This process is repeated until the entire plaintext is encrypted.
        ///
        /// `key` should be the [`Key`] to expand. `n` should be the input to use to expand the key
        /// for this block: In Salsa20/8 encryption, the first 8 bytes are set to the nonce to use
        /// for encryption, and the second 8 bytes are an 8-byte, little endian counter, incremented
        /// for every block.
        ///
        /// `constants` can be used to specify custom constants for the Salsa20/8 expansion: These
        /// are the sigma values from the specification. By default, these are set to `[101, 120,
        /// 112, 97, 110, 100, 32, 51, 50, 45, 98, 121, 116, 101, 32, 107]`, the ASCII
        /// representation of `expand 32-byte k`. There is generally no reason to change these
        /// values.
        ///
        /// The expanded output will be written to `output`, which must be at least
        /// [`EXPAND_OUTPUT_LENGTH`] bytes. The number of bytes written will always be
        /// [`EXPAND_OUTPUT_LENGTH`] bytes.
        ///
        /// # Security Considerations
        /// This is a very low-level function, and generally does not need to be used directly.
        ///
        /// The expanded output of this function is a portion of the keystream for the provided key,
        /// so it should be treated as sensitive data.
        ///
        /// The [`ExpandInput`] input to this function should *never* be used more than once with
        /// the same key.
        sodium::crypto_core_salsa208,
    }

    #[cfg(test)]
    mod tests {
        stream_tests![
            {
                msg:    [0xbe, 0x07, 0x5f, 0xc5, 0x3c, 0x81, 0xf2, 0xd5, 0xcf, 0x14, 0x13, 0x16,
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
                key:    [0x1b, 0x27, 0x55, 0x64, 0x73, 0xe9, 0x85, 0xd4, 0x62, 0xcd, 0x51, 0x19,
                         0x7a, 0x9a, 0x46, 0xc7, 0x60, 0x09, 0x54, 0x9e, 0xac, 0x64, 0x74, 0xf2,
                         0x06, 0xc4, 0xee, 0x08, 0x44, 0xf6, 0x83, 0x89],
                nonce:  [0x69, 0x69, 0x6e, 0xe9, 0x55, 0xb6, 0x2b, 0x73],
                c:      [0x8b, 0x6e, 0xbf, 0x50, 0x72, 0x37, 0xc1, 0x66, 0x3b, 0x75, 0x0c, 0xa6,
                         0xbb, 0x74, 0x5b, 0xb6, 0x61, 0x23, 0x0f, 0x57, 0x03, 0x71, 0x36, 0x04,
                         0x63, 0xc3, 0x75, 0x98, 0x9b, 0x0a, 0x9c, 0x78, 0x28, 0x6a, 0x86, 0x8e,
                         0x2f, 0x32, 0x4e, 0x70, 0xa9, 0x44, 0x32, 0xbe, 0x4d, 0xdf, 0x51, 0x0e,
                         0x0c, 0x24, 0xe1, 0xf0, 0xd3, 0x29, 0x00, 0x01, 0x95, 0x64, 0xfc, 0x61,
                         0xb8, 0x45, 0x2d, 0x9c, 0xf9, 0x01, 0xb8, 0x02, 0x53, 0xcb, 0x78, 0x37,
                         0x56, 0x2c, 0xf6, 0x01, 0xa0, 0xbc, 0xc1, 0x45, 0x9e, 0x83, 0x04, 0xb6,
                         0xed, 0x7e, 0x2c, 0xff, 0xcd, 0x15, 0x8a, 0xd2, 0xaa, 0xfb, 0xb1, 0x22,
                         0x93, 0xc6, 0x14, 0xd8, 0x12, 0xa4, 0xa8, 0x71, 0x38, 0x12, 0xd2, 0x13,
                         0x97, 0xaf, 0x27, 0xbd, 0x67, 0x00, 0x7e, 0xc6, 0xa9, 0xa8, 0xa3, 0x4a,
                         0xde, 0x98, 0x74, 0x11, 0x29, 0xe7, 0x22, 0x74, 0xc6, 0xf5, 0x9b],
                ks:     [0x35, 0x69, 0xe0, 0x95, 0x4e, 0xb6, 0x33, 0xb3, 0xf4, 0x61, 0x1f, 0xb0,
                         0x50, 0x9f, 0x57, 0xcd, 0x33, 0x0b, 0xca, 0x7d, 0x4f, 0x13, 0xfd, 0xd0,
                         0x28, 0xa5, 0xf1, 0x03, 0xff, 0x2e, 0xd3, 0x84, 0xcd, 0x86, 0x3c, 0x21,
                         0x1c, 0x8f, 0x3b, 0x6a, 0xb3, 0x83, 0x1a, 0x6a, 0x13, 0xb3, 0x30, 0x27,
                         0x60, 0xf8, 0xdd, 0xf1, 0xf0, 0x1c, 0x61, 0xf5, 0x88, 0xd2, 0x90, 0xaf,
                         0x89, 0x0f, 0xf6, 0xad, 0xf7, 0x3a, 0x50, 0x27, 0x5f, 0x8d, 0x88, 0x5a,
                         0x98, 0xc6, 0xcc, 0x7e, 0x01, 0x88, 0x41, 0x12, 0x7c, 0x75, 0x51, 0xdc,
                         0x3b, 0xcf, 0x1d, 0x75, 0xcf, 0x5f, 0x09, 0x5d, 0x8b, 0x54, 0xae, 0xfc,
                         0x97, 0x4f, 0x63, 0x33, 0x5a, 0x51, 0x37, 0x8c, 0x71, 0x36, 0x18, 0x0f,
                         0xf7, 0x3f, 0x09, 0xef, 0x97, 0xa0, 0xf7, 0x7a, 0xdf, 0x21, 0xd3, 0x0a,
                         0x3e, 0x1a, 0x8d, 0x26, 0x5f, 0xdf, 0x6a, 0x10, 0x98, 0xf2, 0x9e],
            },
            {
                msg:    [] as [u8; 0],
                key:    [0x1b, 0x27, 0x55, 0x64, 0x73, 0xe9, 0x85, 0xd4, 0x62, 0xcd, 0x51, 0x19,
                         0x7a, 0x9a, 0x46, 0xc7, 0x60, 0x09, 0x54, 0x9e, 0xac, 0x64, 0x74, 0xf2,
                         0x06, 0xc4, 0xee, 0x08, 0x44, 0xf6, 0x83, 0x89],
                nonce:  [0x69, 0x69, 0x6e, 0xe9, 0x55, 0xb6, 0x2b, 0x73],
                c:      [],
                ks:     [],
            },
        ];

        expansion_tests! [
            {
                key:    [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                         0x0d, 0x0e, 0x0f, 0x10, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf, 0xd0,
                         0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8],
                n:      [0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70,
                         0x71, 0x72, 0x73, 0x74],
                c:      [0x65, 0x78, 0x70, 0x61, 0x6e, 0x64, 0x20, 0x33, 0x32, 0x2d, 0x62, 0x79,
                         0x74, 0x65, 0x20, 0x6b],
                out:    [0xd9, 0x4c, 0xef, 0xce, 0xbb, 0x50, 0xfc, 0x9d, 0x69, 0xf6, 0x71, 0xa5,
                         0x45, 0x30, 0x5a, 0xf0, 0xd5, 0x5b, 0x1e, 0xc3, 0x0b, 0x78, 0xef, 0xbd,
                         0xff, 0x93, 0xb7, 0x21, 0xd4, 0x91, 0x16, 0xcc, 0xa5, 0x73, 0x30, 0x08,
                         0x70, 0x72, 0xa7, 0x50, 0xaf, 0xad, 0x8e, 0xb5, 0x95, 0xff, 0x56, 0x8b,
                         0x42, 0xce, 0x2e, 0x8f, 0x86, 0x66, 0x6c, 0x45, 0xd7, 0x5b, 0x02, 0xc7,
                         0x69, 0xba, 0xfd, 0x21],
            },
            {
                key:    [0xee, 0x30, 0x4f, 0xca, 0x27, 0x00, 0x8d, 0x8c, 0x12, 0x6f, 0x90, 0x02,
                         0x79, 0x01, 0xd8, 0x0f, 0x7f, 0x1d, 0x8b, 0x8d, 0xc9, 0x36, 0xcf, 0x3b,
                         0x9f, 0x81, 0x96, 0x92, 0x82, 0x7e, 0x57, 0x77],
                n:      [0x81, 0x91, 0x8e, 0xf2, 0xa5, 0xe0, 0xda, 0x9b, 0x3e, 0x90, 0x60, 0x52,
                         0x1e, 0x4b, 0xb3, 0x52],
                c:      [0x65, 0x78, 0x70, 0x61, 0x6e, 0x64, 0x20, 0x33, 0x32, 0x2d, 0x62, 0x79,
                         0x74, 0x65, 0x20, 0x6b],
                out:    [0x6e, 0x51, 0xcf, 0x23, 0xe4, 0xa0, 0x8d, 0xb5, 0x96, 0x33, 0xd2, 0x0d,
                         0xd1, 0x50, 0x55, 0xed, 0x3d, 0xcb, 0x9c, 0x35, 0x18, 0x5c, 0x3d, 0x12,
                         0xc6, 0xd4, 0x29, 0x53, 0x3a, 0xc9, 0x50, 0x99, 0x43, 0xbc, 0x3b, 0x6c,
                         0xf2, 0x45, 0x16, 0x4d, 0xef, 0xcd, 0x81, 0xfe, 0x02, 0xf7, 0x99, 0x0e,
                         0xed, 0x89, 0x78, 0x7d, 0xec, 0x3d, 0xd8, 0x0e, 0xc3, 0x1d, 0xc1, 0xb5,
                         0x5b, 0xfd, 0xe5, 0x27],
            },
        ];
    }
}

/// The [XChaCha20](https://cr.yp.to/chacha.html) stream cipher (ChaCha20 with an eXtended nonce
/// length).
///
/// This module corresponds to the [`crypto_stream_xchacha20`
/// API](https://doc.libsodium.org/advanced/stream_ciphers/xchacha20) from Sodium.
///
/// # Security Considerations
/// For this algorithm, nonces must *never* be used more than once with the same key. For XChaCha20,
/// the nonce size is sufficient that a random nonce can be generated for every message, and the
/// possibility of nonce reuse is negligible. Therefore, it is recommended that you generate a
/// random nonce for every message using the [`crate::random`] API.
///
/// This is an *unauthenticated* stream cipher, a low-level construction which is not suited to
/// general use. There is no way to detect if an attacker has modified the ciphertext. You should
/// generally prefer to use the authenticated [`symmetric::cipher`](crate::symmetric::cipher)
/// construction, unless you are using this cipher as part of a wider authenticated protocol.
///
/// This construction exposes the length of the plaintext. If this is undesirable, apply padding to
/// the plaintext prior to encryption via [`util::pad`](crate::util::pad), and remove it following
/// decryption via [`util::unpad`](crate::util::unpad).
///
/// ## Secret Data
/// * The encryption/decryption key ([`Key`]) must only be known to parties who should be able to
///   both encrypt and decrypt messages
/// * The keystream outputted by [`keystream`] should be treated as sensitive if the same [`Key`] is
///   being used to encrypt/decrypt messages
///
/// ## Non-Secret Data
/// * Nonces ([`Nonce`]) are not sensitive
#[cfg(not(feature = "minimal"))]
#[cfg_attr(doc_cfg, doc(cfg(not(feature = "minimal"))))]
pub mod xchacha20 {
    use libsodium_sys as sodium;

    stream_module! {
        sodium::crypto_stream_xchacha20_KEYBYTES,
        sodium::crypto_stream_xchacha20_NONCEBYTES,
        sodium::crypto_stream_xchacha20_messagebytes_max,
        sodium::crypto_stream_xchacha20_keygen,
        sodium::crypto_stream_xchacha20,
        sodium::crypto_stream_xchacha20_xor,
        sodium::crypto_stream_xchacha20_xor_ic,
        u64,
    }

    /// The length of a nonce for the [`hchacha20`] function, in bytes.
    pub const HCHACHA_NONCE_LENGTH: usize = sodium::crypto_core_hchacha20_INPUTBYTES as usize;

    /// The length of custom constants for [`hchacha20`], in bytes.
    pub const HCHACHA_CONSTANTS_LENGTH: usize = sodium::crypto_core_hchacha20_CONSTBYTES as usize;

    /// The length of the output of [`hchacha20`], in bytes.
    pub const HCHACHA_OUTPUT_LENGTH: usize = sodium::crypto_core_hchacha20_OUTPUTBYTES as usize;

    /// A nonce for [`hchacha20`].
    pub type HChaChaNonce = [u8; HCHACHA_NONCE_LENGTH];

    /// Custom constants to use for [`hchacha20`].
    pub type HChaChaConstants = [u8; HCHACHA_CONSTANTS_LENGTH];

    /// The raw HChaCha20 function.
    ///
    /// This is the HChaCha20 function detailed in section 2.2 of the [XChaCha IETF
    /// Draft](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha-03#section-2.2).
    /// HChaCha20 is a key component used in the definition of XChaCha20: XChaCha20 takes a 32-byte
    /// key and 24-byte nonce as input. The key and first 16 bytes of the nonce are used as input
    /// for HChaCha20, which outputs a 32-byte value. This 32-byte value is then used as the key for
    /// the ChaCha20 cipher, with the final 8 bytes of the XChaCha20 nonce as the nonce for the
    /// ChaCha20 cipher.
    ///
    /// `key` should be the [`Key`] for XChaCha20. `nonce` should be the [`HChaChaNonce`], generally
    /// the first 16 bytes of a full XChaCha20 [`Nonce`].
    ///
    /// `constants` can be used to specify custom constants for the HChaCha20 function: These are
    /// the sigma values from the original Salsa20 definition. By default, these are set to `[101,
    /// 120, 112, 97, 110, 100, 32, 51, 50, 45, 98, 121, 116, 101, 32, 107]`, the ASCII
    /// representation of `expand 32-byte k`. There is generally no reason to change these values.
    ///
    /// The output of this function will be written to `output`, which must be at least
    /// [`HCHACHA_OUTPUT_LENGTH`] bytes long. The number of bytes written will always be
    /// [`HCHACHA_OUTPUT_LENGTH`] bytes.
    ///
    /// # Security Considerations
    /// This is a very low-level function, and generally does not need to be used directly.
    ///
    /// The output of this function is the key which will be used for ChaCha20 as part of
    /// XChaCha20's encryption calculation, so it should be treated as sensitive data.
    ///
    /// The [`HChaChaNonce`] input to this function should *never* be used more than once with the
    /// same key.
    pub fn hchacha20(
        key: &Key<impl mem::MprotectReadable>,
        nonce: &HChaChaNonce,
        constants: Option<&HChaChaConstants>,
        output: &mut [u8],
    ) -> Result<(), AlkaliError> {
        require_init()?;

        if output.len() < HCHACHA_OUTPUT_LENGTH {
            return Err(StreamCipherError::OutputInsufficient.into());
        }

        let const_ptr = match constants {
            Some(c) => c.as_ptr(),
            None => core::ptr::null(),
        };

        let hchacha_result = unsafe {
            // SAFETY: The first argument to this function is the destination to which the output
            // will be written. The output will be `crypto_core_hchacha20_OUTPUTBYTES` bytes long.
            // We verify above that `output` is at least this many bytes in length, so `output` is
            // valid for writes of the required length. The next argument is the nonce for
            // HChaCha20, which should be `crypto_core_hchacha20_NONCEBYTES` bytes long. We define
            // `HChaChaNonce` to be this length, so `nonce` is valid for reads of the required size.
            // The next argument is the key to expand. The key type is defined to be
            // `crypto_stream_xchacha20_KEYBYTES`, which is equal to
            // `crypto_core_hchacha20_KEYBYTES`, the length of a key for HChaCha20, so `key` is
            // valid for reads of the required length. The final argument is a pointer to custom
            // constants to use with HChaCha20. If constants are provided, we pass a pointer to `c`,
            // which is defined to be `crypto_core_hchacha20_CONSTBYTES`, the expected size of
            // custom constants for this algorithm, so `c` is valid for reads of the required
            // length. Otherwise, we pass a null pointer, in which case Sodium is documented to
            // ignore this argument. The `Key::inner` method simply returns an immutable pointer to
            // the struct's backing memory.
            sodium::crypto_core_hchacha20(
                output.as_mut_ptr(),
                nonce.as_ptr(),
                key.inner().cast(),
                const_ptr,
            )
        };
        assert_not_err!(hchacha_result, "crypto_core_hchacha20");

        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::{hchacha20, HCHACHA_OUTPUT_LENGTH};

        stream_tests! [
            {
                msg:    [0xbe, 0x07, 0x5f, 0xc5, 0x3c, 0x81, 0xf2, 0xd5, 0xcf, 0x14, 0x13, 0x16,
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
                key:    [0x1b, 0x27, 0x55, 0x64, 0x73, 0xe9, 0x85, 0xd4, 0x62, 0xcd, 0x51, 0x19,
                         0x7a, 0x9a, 0x46, 0xc7, 0x60, 0x09, 0x54, 0x9e, 0xac, 0x64, 0x74, 0xf2,
                         0x06, 0xc4, 0xee, 0x08, 0x44, 0xf6, 0x83, 0x89],
                nonce:  [0x69, 0x69, 0x6e, 0xe9, 0x55, 0xb6, 0x2b, 0x73, 0xcd, 0x62, 0xbd, 0xa8,
                         0x75, 0xfc, 0x73, 0xd6, 0x82, 0x19, 0xe0, 0x03, 0x6b, 0x7a, 0x0b, 0x37],
                c:      [0xf1, 0xec, 0xad, 0x3b, 0x77, 0xb4, 0x6e, 0x85, 0x42, 0xd1, 0xfb, 0xa3,
                         0x73, 0xe7, 0x84, 0x98, 0xdb, 0x6e, 0x1d, 0xdb, 0xc3, 0x53, 0xff, 0xb1,
                         0x83, 0x04, 0x24, 0x1c, 0xe6, 0x40, 0xcd, 0xb4, 0xe4, 0x61, 0x16, 0x73,
                         0x8a, 0xb9, 0x62, 0x92, 0x49, 0x63, 0x45, 0x1e, 0x64, 0x62, 0xcb, 0xc7,
                         0x18, 0xa0, 0x86, 0x96, 0x60, 0x7b, 0xce, 0x0e, 0xc8, 0x39, 0x86, 0x4c,
                         0x13, 0x4e, 0xa5, 0x3c, 0xe8, 0xf8, 0x4e, 0x52, 0x5d, 0x40, 0x10, 0x5e,
                         0xd4, 0x3d, 0x2e, 0xad, 0x53, 0x4e, 0xd5, 0x33, 0xf1, 0xb6, 0xf4, 0x9b,
                         0x0b, 0x2e, 0xa5, 0xd9, 0x2c, 0x22, 0x48, 0xab, 0x3d, 0x12, 0xce, 0x8e,
                         0x93, 0x84, 0x63, 0x0b, 0x14, 0xae, 0x88, 0xcc, 0xda, 0xdf, 0xde, 0xe9,
                         0x7c, 0xd1, 0xdd, 0xc1, 0x73, 0xfb, 0x7e, 0x48, 0x60, 0x2e, 0x90, 0xfb,
                         0x48, 0x9d, 0x02, 0xbc, 0x65, 0x97, 0x46, 0x45, 0x37, 0x1a, 0x7b],
                ks:     [0x4f, 0xeb, 0xf2, 0xfe, 0x4b, 0x35, 0x9c, 0x50, 0x8d, 0xc5, 0xe8, 0xb5,
                         0x98, 0x0c, 0x88, 0xe3, 0x89, 0x46, 0xd8, 0xf1, 0x8f, 0x31, 0x34, 0x65,
                         0xc8, 0x62, 0xa0, 0x87, 0x82, 0x64, 0x82, 0x48, 0x01, 0x8d, 0xac, 0xdc,
                         0xb9, 0x04, 0x17, 0x88, 0x53, 0xa4, 0x6d, 0xca, 0x3a, 0x0e, 0xaa, 0xee,
                         0x74, 0x7c, 0xba, 0x97, 0x43, 0x4e, 0xaf, 0xfa, 0xd5, 0x8f, 0xea, 0x82,
                         0x22, 0x04, 0x7e, 0x0d, 0xe6, 0xc3, 0xa6, 0x77, 0x51, 0x06, 0xe0, 0x33,
                         0x1a, 0xd7, 0x14, 0xd2, 0xf2, 0x7a, 0x55, 0x64, 0x13, 0x40, 0xa1, 0xf1,
                         0xdd, 0x9f, 0x94, 0x53, 0x2e, 0x68, 0xcb, 0x24, 0x1c, 0xbd, 0xd1, 0x50,
                         0x97, 0x0d, 0x14, 0xe0, 0x5c, 0x5b, 0x17, 0x31, 0x93, 0xfb, 0x14, 0xf5,
                         0x1c, 0x41, 0xf3, 0x93, 0x83, 0x5b, 0xf7, 0xf4, 0x16, 0xa7, 0xe0, 0xbb,
                         0xa8, 0x1f, 0xfb, 0x8b, 0x13, 0xaf, 0x0e, 0x21, 0x69, 0x1d, 0x7e],
            },
            {
                msg:    [] as [u8; 0],
                key:    [0x1b, 0x27, 0x55, 0x64, 0x73, 0xe9, 0x85, 0xd4, 0x62, 0xcd, 0x51, 0x19,
                         0x7a, 0x9a, 0x46, 0xc7, 0x60, 0x09, 0x54, 0x9e, 0xac, 0x64, 0x74, 0xf2,
                         0x06, 0xc4, 0xee, 0x08, 0x44, 0xf6, 0x83, 0x89],
                nonce:  [0x69, 0x69, 0x6e, 0xe9, 0x55, 0xb6, 0x2b, 0x73, 0xcd, 0x62, 0xbd, 0xa8,
                         0x75, 0xfc, 0x73, 0xd6, 0x82, 0x19, 0xe0, 0x03, 0x6b, 0x7a, 0x0b, 0x37],
                c:      [],
                ks:     [],
            },
        ];

        #[test]
        fn hchacha_vectors() -> Result<(), AlkaliError> {
            let vectors = [
                (
                    [
                        0x4a, 0x5d, 0x9d, 0x5b, 0xa4, 0xce, 0x2d, 0xe1, 0x72, 0x8e, 0x3b, 0xf4,
                        0x80, 0x35, 0x0f, 0x25, 0xe0, 0x7e, 0x21, 0xc9, 0x47, 0xd1, 0x9e, 0x33,
                        0x76, 0xf0, 0x9b, 0x3c, 0x1e, 0x16, 0x17, 0x42,
                    ],
                    [0; 16],
                    [
                        0x65, 0x78, 0x70, 0x61, 0x6e, 0x64, 0x20, 0x33, 0x32, 0x2d, 0x62, 0x79,
                        0x74, 0x65, 0x20, 0x6b,
                    ],
                    [
                        0x8e, 0x47, 0xca, 0x37, 0x6b, 0xdc, 0x7e, 0x59, 0xd2, 0xce, 0xd8, 0x10,
                        0x7c, 0xeb, 0x2c, 0x27, 0xf4, 0xa8, 0x0e, 0x85, 0x75, 0xf9, 0x96, 0xba,
                        0xff, 0xb1, 0xa8, 0x69, 0xff, 0xcd, 0x51, 0x79,
                    ],
                ),
                (
                    [
                        0x1b, 0x27, 0x55, 0x64, 0x73, 0xe9, 0x85, 0xd4, 0x62, 0xcd, 0x51, 0x19,
                        0x7a, 0x9a, 0x46, 0xc7, 0x60, 0x09, 0x54, 0x9e, 0xac, 0x64, 0x74, 0xf2,
                        0x06, 0xc4, 0xee, 0x08, 0x44, 0xf6, 0x83, 0x89,
                    ],
                    [
                        0x69, 0x69, 0x6e, 0xe9, 0x55, 0xb6, 0x2b, 0x73, 0xcd, 0x62, 0xbd, 0xa8,
                        0x75, 0xfc, 0x73, 0xd6,
                    ],
                    [
                        0x65, 0x78, 0x70, 0x61, 0x6e, 0x64, 0x20, 0x33, 0x32, 0x2d, 0x62, 0x79,
                        0x74, 0x65, 0x20, 0x6b,
                    ],
                    [
                        0x28, 0x8b, 0xe1, 0xc7, 0x7c, 0x2f, 0xf6, 0x8b, 0x94, 0x45, 0x7d, 0x50,
                        0xa3, 0x13, 0x5f, 0xd9, 0x63, 0x9d, 0x70, 0x9d, 0xd9, 0x7d, 0x1d, 0x1c,
                        0xd7, 0x6c, 0x17, 0x84, 0x4c, 0xba, 0xb0, 0x6d,
                    ],
                ),
            ];

            let mut output = [0u8; HCHACHA_OUTPUT_LENGTH];
            let mut k = Key::new_empty()?;

            for (key, nonce, constants, expected) in vectors {
                k.copy_from_slice(&key[..]);
                hchacha20(&k, &nonce, Some(&constants), &mut output)?;
                assert_eq!(output, expected);
            }

            Ok(())
        }
    }
}

/// The [ChaCha20](https://cr.yp.to/chacha.html) stream cipher.
///
/// This module corresponds to the [`crypto_stream_chacha20`
/// API](https://doc.libsodium.org/advanced/stream_ciphers/chacha20) from Sodium.
///
/// # Security Considerations
/// For this algorithm, nonces must *never* be used more than once with the same key. For ChaCha20,
/// the nonce size is not sufficient that random nonces can be used without the possibility of
/// collisions, also leading to nonce reuse, so it is unsafe to use random nonces with this
/// construction. Therefore, careful attention is needed to ensure nonces are only used once. If a
/// key is being reused for multiple messages, it is recommended to increment the nonce for the
/// previous message using [`increment_nonce`] for each message sent. The initial nonce can be any
/// value.
///
/// In client-server protocols, where both parties are sending messages, use different keys for each
/// direction, or ensure one bit in the nonce is always set in one direction, and always unset in
/// the other, to make sure a nonce is never reused with the same key.
///
/// This is an *unauthenticated* stream cipher, a low-level construction which is not suited to
/// general use. There is no way to detect if an attacker has modified the ciphertext. You should
/// generally prefer to use the authenticated [`symmetric::cipher`](crate::symmetric::cipher)
/// construction, unless you are using this cipher as part of a wider authenticated protocol.
///
/// This construction exposes the length of the plaintext. If this is undesirable, apply padding to
/// the plaintext prior to encryption via [`util::pad`](crate::util::pad), and remove it following
/// decryption via [`util::unpad`](crate::util::unpad).
///
/// ## Secret Data
/// * The encryption/decryption key ([`Key`]) must only be known to parties who should be able to
///   both encrypt and decrypt messages
/// * The keystream outputted by [`keystream`] should be treated as sensitive if the same [`Key`] is
///   being used to encrypt/decrypt messages
///
/// ## Non-Secret Data
/// * Nonces ([`Nonce`]) are not sensitive
pub mod chacha20 {
    use libsodium_sys as sodium;

    stream_module! {
        sodium::crypto_stream_chacha20_KEYBYTES,
        sodium::crypto_stream_chacha20_NONCEBYTES,
        sodium::crypto_stream_chacha20_messagebytes_max,
        sodium::crypto_stream_chacha20_keygen,
        sodium::crypto_stream_chacha20,
        sodium::crypto_stream_chacha20_xor,
        sodium::crypto_stream_chacha20_xor_ic,
        u64,
    }

    #[cfg(test)]
    mod tests {
        stream_tests![
            {
                msg:    [0xbe, 0x07, 0x5f, 0xc5, 0x3c, 0x81, 0xf2, 0xd5, 0xcf, 0x14, 0x13, 0x16,
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
                key:    [0x1b, 0x27, 0x55, 0x64, 0x73, 0xe9, 0x85, 0xd4, 0x62, 0xcd, 0x51, 0x19,
                         0x7a, 0x9a, 0x46, 0xc7, 0x60, 0x09, 0x54, 0x9e, 0xac, 0x64, 0x74, 0xf2,
                         0x06, 0xc4, 0xee, 0x08, 0x44, 0xf6, 0x83, 0x89],
                nonce:  [0x69, 0x69, 0x6e, 0xe9, 0x55, 0xb6, 0x2b, 0x73],
                c:      [0x9e, 0xbf, 0x5f, 0x0f, 0xa6, 0x13, 0xb5, 0x69, 0x0f, 0x8e, 0x7b, 0x00,
                         0x5a, 0xc8, 0xb2, 0x3c, 0xfe, 0x2e, 0x44, 0xc8, 0x7b, 0x2b, 0x18, 0x8b,
                         0xa1, 0x44, 0x44, 0xd5, 0x7f, 0x3f, 0xd4, 0x4d, 0x72, 0x6e, 0x11, 0x86,
                         0x49, 0xd8, 0xbd, 0x10, 0xab, 0x7d, 0xea, 0x2b, 0x72, 0x27, 0x8a, 0x8d,
                         0xa4, 0xdb, 0x83, 0x82, 0x0c, 0xee, 0x36, 0x12, 0x55, 0x05, 0xda, 0xb9,
                         0xe9, 0x35, 0x5c, 0x69, 0x1c, 0x04, 0x58, 0xdc, 0xdf, 0xd8, 0x0a, 0xf8,
                         0x19, 0x37, 0x05, 0x0d, 0x5a, 0x3e, 0x3e, 0xcc, 0x74, 0x10, 0xd0, 0x7e,
                         0x31, 0xe9, 0xd8, 0x54, 0x33, 0xe4, 0x9e, 0xe6, 0x6d, 0xe9, 0x32, 0x3b,
                         0x33, 0x7e, 0x93, 0xba, 0xc0, 0x07, 0x43, 0x44, 0x5b, 0xe2, 0x6a, 0xf1,
                         0x7a, 0x7e, 0x71, 0x39, 0xbd, 0x8b, 0x61, 0x7f, 0xd7, 0x9b, 0x1e, 0xd2,
                         0x6b, 0xed, 0x13, 0xa6, 0xa0, 0x7b, 0xb1, 0xdf, 0xb6, 0x0f, 0xdc],
                ks:     [0x20, 0xb8, 0x00, 0xca, 0x9a, 0x92, 0x47, 0xbc, 0xc0, 0x9a, 0x68, 0x16,
                         0xb1, 0x23, 0xbe, 0x47, 0xac, 0x06, 0x81, 0xe2, 0x37, 0x49, 0xd3, 0x5f,
                         0xea, 0x22, 0xc0, 0x4e, 0x1b, 0x1b, 0x9b, 0xb1, 0x97, 0x82, 0xab, 0x29,
                         0x7a, 0x65, 0xc8, 0x0a, 0xb1, 0xba, 0xc2, 0xff, 0x2c, 0x4b, 0xeb, 0xa4,
                         0xc8, 0x07, 0xbf, 0x83, 0x2f, 0xdb, 0x57, 0xe6, 0x48, 0xb3, 0xb6, 0x77,
                         0xd8, 0x7f, 0x87, 0x58, 0x12, 0x3f, 0xb0, 0xf9, 0xd3, 0x9e, 0xfa, 0x95,
                         0xd7, 0xdd, 0x3f, 0x72, 0xfb, 0x0a, 0xbe, 0x9b, 0x96, 0xe6, 0x85, 0x14,
                         0xe7, 0x58, 0xe9, 0xde, 0x31, 0xae, 0x1d, 0x69, 0x4c, 0x46, 0x2d, 0xe5,
                         0x37, 0xf7, 0xe4, 0x51, 0x88, 0xf2, 0xdc, 0xb9, 0x12, 0xc6, 0xa0, 0xed,
                         0x1a, 0xee, 0x5f, 0x6b, 0x4d, 0x2b, 0xe8, 0xc3, 0xa1, 0x12, 0x6e, 0x92,
                         0x8b, 0x6f, 0xea, 0x91, 0xd6, 0x43, 0xf9, 0xbb, 0xe8, 0x08, 0xd9],
            },
            {
                msg:    [] as [u8; 0],
                key:    [0x1b, 0x27, 0x55, 0x64, 0x73, 0xe9, 0x85, 0xd4, 0x62, 0xcd, 0x51, 0x19,
                         0x7a, 0x9a, 0x46, 0xc7, 0x60, 0x09, 0x54, 0x9e, 0xac, 0x64, 0x74, 0xf2,
                         0x06, 0xc4, 0xee, 0x08, 0x44, 0xf6, 0x83, 0x89],
                nonce:  [0x69, 0x69, 0x6e, 0xe9, 0x55, 0xb6, 0x2b, 0x73],
                c:      [],
                ks:     [],
            },
        ];
    }
}

/// The IETF variant of the [ChaCha20](https://cr.yp.to/chacha.html) stream cipher, specified in
/// [RFC 8439](https://datatracker.ietf.org/doc/html/rfc8439).
///
/// This module corresponds to the [`crypto_stream_chacha20`
/// API](https://doc.libsodium.org/advanced/stream_ciphers/chacha20) from Sodium.
///
/// # Security Considerations
/// For this algorithm, nonces must *never* be used more than once with the same key. For ChaCha20,
/// the nonce size is not sufficient that random nonces can be used without the possibility of
/// collisions, also leading to nonce reuse, so it is unsafe to use random nonces with this
/// construction. Therefore, careful attention is needed to ensure nonces are only used once. If a
/// key is being reused for multiple messages, it is recommended to increment the nonce for the
/// previous message using [`increment_nonce`] for each message sent. The initial nonce can be any
/// value.
///
/// In client-server protocols, where both parties are sending messages, use different keys for each
/// direction, or ensure one bit in the nonce is always set in one direction, and always unset in
/// the other, to make sure a nonce is never reused with the same key.
///
/// This is an *unauthenticated* stream cipher, a low-level construction which is not suited to
/// general use. There is no way to detect if an attacker has modified the ciphertext. You should
/// generally prefer to use the authenticated [`symmetric::cipher`](crate::symmetric::cipher)
/// construction, unless you are using this cipher as part of a wider authenticated protocol.
///
/// This construction exposes the length of the plaintext. If this is undesirable, apply padding to
/// the plaintext prior to encryption via [`util::pad`](crate::util::pad), and remove it following
/// decryption via [`util::unpad`](crate::util::unpad).
///
/// ## Secret Data
/// * The encryption/decryption key ([`Key`]) must only be known to parties who should be able to
///   both encrypt and decrypt messages
/// * The keystream outputted by [`keystream`] should be treated as sensitive if the same [`Key`] is
///   being used to encrypt/decrypt messages
///
/// ## Non-Secret Data
/// * Nonces ([`Nonce`]) are not sensitive
pub mod chacha20_ietf {
    use libsodium_sys as sodium;

    stream_module! {
        sodium::crypto_stream_chacha20_ietf_KEYBYTES,
        sodium::crypto_stream_chacha20_ietf_NONCEBYTES,
        sodium::crypto_stream_chacha20_ietf_messagebytes_max,
        sodium::crypto_stream_chacha20_ietf_keygen,
        sodium::crypto_stream_chacha20_ietf,
        sodium::crypto_stream_chacha20_ietf_xor,
        sodium::crypto_stream_chacha20_ietf_xor_ic,
        u32,
    }

    #[cfg(test)]
    mod tests {
        stream_tests! [
            {
                msg:    [0xbe, 0x07, 0x5f, 0xc5, 0x3c, 0x81, 0xf2, 0xd5, 0xcf, 0x14, 0x13, 0x16,
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
                key:    [0x1b, 0x27, 0x55, 0x64, 0x73, 0xe9, 0x85, 0xd4, 0x62, 0xcd, 0x51, 0x19,
                         0x7a, 0x9a, 0x46, 0xc7, 0x60, 0x09, 0x54, 0x9e, 0xac, 0x64, 0x74, 0xf2,
                         0x06, 0xc4, 0xee, 0x08, 0x44, 0xf6, 0x83, 0x89],
                nonce:  [0x69, 0x69, 0x6e, 0xe9, 0x55, 0xb6, 0x2b, 0x73, 0xcd, 0x62, 0xbd, 0xa8],
                c:      [0xf9, 0x04, 0x73, 0xbb, 0xc6, 0x9f, 0x2a, 0x1f, 0xcb, 0xd4, 0x0f, 0xff,
                         0xce, 0x0d, 0xa5, 0x9b, 0x77, 0x77, 0x59, 0x51, 0x4d, 0x8c, 0x97, 0xed,
                         0x1e, 0x4a, 0xed, 0x32, 0xb9, 0x40, 0xa1, 0xb3, 0x4f, 0x29, 0x06, 0x4a,
                         0x40, 0xfd, 0xc4, 0x12, 0x86, 0x84, 0x16, 0x7f, 0x6f, 0x81, 0xc4, 0x2b,
                         0x19, 0x0b, 0x46, 0x5c, 0x18, 0x95, 0x0a, 0xc0, 0x55, 0xbc, 0xf0, 0x6c,
                         0xa6, 0x20, 0x5e, 0xbb, 0x66, 0x49, 0xc4, 0x1f, 0xc7, 0x49, 0xb5, 0x9e,
                         0xa0, 0xc3, 0x66, 0x13, 0x7a, 0x96, 0xda, 0x99, 0xb2, 0x90, 0x18, 0xdf,
                         0xcd, 0xbc, 0x38, 0xcd, 0x84, 0x95, 0xd5, 0xbc, 0xab, 0xdf, 0x38, 0x8e,
                         0xe7, 0x35, 0x21, 0xb3, 0x6b, 0x5d, 0xba, 0x8e, 0x6d, 0x64, 0x0f, 0xee,
                         0x87, 0x57, 0x88, 0xaa, 0xe9, 0xac, 0xae, 0x0d, 0xe1, 0x00, 0x48, 0xbe,
                         0x3e, 0x29, 0xb2, 0xa0, 0xda, 0x50, 0x78, 0x86, 0xbe, 0x8c, 0x77],
                ks:     [0x47, 0x03, 0x2c, 0x7e, 0xfa, 0x1e, 0xd8, 0xca, 0x04, 0xc0, 0x1c, 0xe9,
                         0x25, 0xe6, 0xa9, 0xe0, 0x25, 0x5f, 0x9c, 0x7b, 0x01, 0xee, 0x5c, 0x39,
                         0x55, 0x2c, 0x69, 0xa9, 0xdd, 0x64, 0xee, 0x4f, 0xaa, 0xc5, 0xbc, 0xe5,
                         0x73, 0x40, 0xb1, 0x08, 0x9c, 0x43, 0x3e, 0xab, 0x31, 0xed, 0xa5, 0x02,
                         0x75, 0xd7, 0x7a, 0x5d, 0x3b, 0xa0, 0x6b, 0x34, 0x48, 0x0a, 0x9c, 0xa2,
                         0x97, 0x6a, 0x85, 0x8a, 0x68, 0x72, 0x2c, 0x3a, 0xcb, 0x0f, 0x45, 0xf3,
                         0x6e, 0x29, 0x5c, 0x6c, 0xdb, 0xa2, 0x5a, 0xce, 0x50, 0x66, 0x4d, 0xb5,
                         0x1b, 0x0d, 0x09, 0x47, 0x86, 0xdf, 0x56, 0x33, 0x8a, 0x70, 0x27, 0x50,
                         0xe3, 0xbc, 0x56, 0x58, 0x23, 0xa8, 0x25, 0x73, 0x24, 0x40, 0xc5, 0xf2,
                         0xe7, 0xc7, 0xa6, 0xf8, 0x19, 0x0c, 0x27, 0xb1, 0x97, 0x89, 0x38, 0xfe,
                         0xde, 0xab, 0x4b, 0x97, 0xac, 0x68, 0x30, 0xe2, 0xe0, 0x8b, 0x72],
            },
            {
                msg:    [] as [u8; 0],
                key:    [0x1b, 0x27, 0x55, 0x64, 0x73, 0xe9, 0x85, 0xd4, 0x62, 0xcd, 0x51, 0x19,
                         0x7a, 0x9a, 0x46, 0xc7, 0x60, 0x09, 0x54, 0x9e, 0xac, 0x64, 0x74, 0xf2,
                         0x06, 0xc4, 0xee, 0x08, 0x44, 0xf6, 0x83, 0x89],
                nonce:  [0x69, 0x69, 0x6e, 0xe9, 0x55, 0xb6, 0x2b, 0x73, 0xcd, 0x62, 0xbd, 0xa8],
                c:      [],
                ks:     [],
            },
        ];
    }
}

pub use xsalsa20::*;
