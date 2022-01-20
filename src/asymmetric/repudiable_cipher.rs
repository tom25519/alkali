//! Anonymised version of [`cipher`](crate::asymmetric::cipher), for asymmetric Authenticated
//! Encryption (AE).
//!
//! This module corresponds to the [`crypto_box_seal`
//! API](https://doc.libsodium.org/public-key_cryptography/sealed_boxes) from Sodium.
//!
//! In the [`cipher`](crate::asymmetric::cipher) module, the receiver must know the sender's public
//! key in order to receive messages. This construction allows messages to be sent anonymously to a
//! recipient, given their public key. They can verify the integrity of the message, but not the
//! identity of the sender.
//!
//! The basic construction is very similar to that of the `cipher` module, but an ephemeral sender
//! keypair is generated for every message. After the encryption process is complete, the secret
//! key is immediately destroyed, while the public key is transmitted to the recipient. This means
//! only the recipient can decrypt the message: The sender can't decrypt their own message later.
//! This also means that the construction is entirely repudiable: There is no cryptographic way to
//! prove a specific person sent the message.
//!
//! # Algorithm Details
//! The same algorithm as in the [`cipher`](crate::asymmetric::cipher) module is used:
//! [X25519](https://en.wikipedia.org/wiki/Curve25519) is used to perform a key exchange,
//! [XSalsa20](https://en.wikipedia.org/wiki/Salsa20) or
//! [XChaCha20](https://en.wikipedia.org/wiki/Salsa20#ChaCha_variant) are used to encrypt/decrypt
//! messages, and [Poly1305](https://en.wikipedia.org/wiki/Poly1305) is used for message
//! authentication.
//!
//! The difference is that an ephemeral sender keypair is generated for every message. The nonce
//! for the message is calculated deterministically by hashing the concatenation of the ephemeral
//! public key and the receiver public key. The ephemeral public key is prepended to the message.
//!
//! The overall format of the ciphertext is as follows, where `||` denotes concatenation:
//!
//! ```text
//! ephemeral_pk || cipher(message, recipient_pk, ephemeral_sk, nonce=blake2b(ephemeral_pk || recipient_pk))
//! ```
//!
//! # Examples
//! ```rust
//! use alkali::asymmetric::repudiable_cipher;
//!
//! let (private_key, public_key) = repudiable_cipher::generate_keypair().unwrap();
//!
//! let msg = b"Encrypt me please!";
//! let mut ciphertext = [0; 18 + repudiable_cipher::ADDED_LENGTH];
//!
//! repudiable_cipher::encrypt(msg, &public_key, &mut ciphertext).unwrap();
//!
//! // ...
//!
//! let mut plaintext = [0; 18];
//! repudiable_cipher::decrypt(&ciphertext, (&private_key, &public_key), &mut plaintext).unwrap();
//!
//! assert_eq!(&plaintext, msg);
//! ```

use thiserror::Error;

/// Error type returned if something went wrong in the `asymmetric::repudiable_cipher` module.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RepudiableCipherError {
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

    /// A public key to be used in encryption is weak (likely of low order), and should not be used
    /// for cryptographic purposes.
    #[error("insecure public key")]
    PublicKeyInsecure,

    /// Indicates decryption of a provided ciphertext failed.
    ///
    /// This could indicate an attempted forgery, or transmission error.
    #[error("decryption failed")]
    DecryptionFailed,
}

/// Generates the API for an `asymmetric::repudiable_cipher` mdoule with the given functions from
/// Sodium for a specific implementation.
macro_rules! repudiable_cipher_module {
    (
        $private_key_len:expr,  // crypto_box_SECRETKEYBYTES
        $public_key_len:expr,   // crypto_box_PUBLICKEYBYTES
        $seed_len:expr,         // crypto_box_SEEDBYTES
        $added_len:expr,        // crypto_box_SEALBYTES
        $msg_max:path,          // crypto_box_messagebytes_max
        $keypair:path,          // crypto_box_keypair
        $seed_keypair:path,     // crypto_box_seed_keypair
        $encrypt:path,          // crypto_box_seal
        $decrypt:path,          // crypto_box_seal_open
    ) => {
        use $crate::asymmetric::repudiable_cipher::RepudiableCipherError;

        /// The length of a private key for asymmetric AE, in bytes.
        pub const PRIVATE_KEY_LENGTH: usize = $private_key_len as usize;

        /// The length of a public key for asymmetric AE, in bytes.
        pub const PUBLIC_KEY_LENGTH: usize = $public_key_len as usize;

        /// The length of a seed to use for the deterministic generation of a (private key, public
        /// key) pair, in bytes.
        pub const KEY_SEED_LENGTH: usize = $seed_len as usize;

        /// The extra length added to a message following encryption, in bytes.
        pub const ADDED_LENGTH: usize = $added_len as usize;

        $crate::hardened_buffer! {
            /// A private key used by a party in asymmetric AE.
            ///
            /// There are no technical constraints on the contents of a private key here, since for
            /// this algorithm, clamping is implemented when keys are used, rather than when they
            /// are generated, but the keypair should be generated randomly using
            /// [`generate_keypair`].
            ///
            /// A private key is secret, and as such, should not ever be made public.
            ///
            /// This is a [hardened buffer type](https://docs.rs/alkali#hardened-buffer-types), and
            /// will be zeroed on drop. A number of other security measures are taken to protect
            /// its contents.
            PrivateKey(PRIVATE_KEY_LENGTH);

            /// A seed used to deterministically derive a (private, public) keypair.
            ///
            /// If a private key derived from a seed is used for real-world operations, the seed
            /// should be treated as securely as the private key itself, since it is trivial to
            /// derive the private key given the seed. Ideally, a seed used in this case should be
            /// discarded immediately after key generation.
            ///
            /// For testing purposes, these concerns obviously do not apply.
            ///
            /// This is a [hardened buffer type](https://docs.rs/alkali#hardened-buffer-types), and
            /// will be zeroed on drop. A number of other security measures are taken to protect
            /// its contents.
            Seed(KEY_SEED_LENGTH);
        }

        impl PrivateKey {
            /// Derive the public key corresponding to this private key.
            pub fn public_key(&self) -> Result<PublicKey, $crate::AlkaliError> {
                $crate::require_init()?;

                let mut public_key = [0; PUBLIC_KEY_LENGTH];
                unsafe {
                    // SAFETY: This function takes a pointer to a buffer to which the result of the
                    // scalar multiplication should be written, and a pointer to the scalar by
                    // which the generator of the elliptic curve should be multiplied. We have
                    // defined the `public_key` array to be `crypto_box_PUBLICKEYBYTES`, which is
                    // equal to `crypto_scalarmult_BYTES`, so this is the expected size for use
                    // with this function. The PrivateKey type has been defined to store
                    // `crypto_box_SECRETKEYBYTES`, which is equal to
                    // `crypto_scalarmult_SCALARBYTES`, so this is also the expected size for use
                    // with this function. The PrivateKey::inner method simply returns an immutable
                    // pointer to the backing memory.
                    libsodium_sys::crypto_scalarmult_base(
                        public_key.as_mut_ptr(),
                        self.inner() as *const libc::c_uchar,
                    );
                }

                Ok(public_key)
            }
        }

        /// A public key used by party to asymmetric AE.
        ///
        /// A public key corresponds to a private key, and represents a point on the Curve25519
        /// curve.
        ///
        /// A public key should be made public.
        pub type PublicKey = [u8; PUBLIC_KEY_LENGTH];

        lazy_static::lazy_static! {
            /// The maximum message length which can be encrypted with this cipher, in bytes.
            pub static ref MESSAGE_LENGTH_MAX: usize = unsafe {
                // SAFETY: This function just returns a constant value, and should always be safe
                // to call.
                $msg_max()
            };
        }

        /// Generates a random private key, and corresponding public key, for use in asymmetric AE.
        ///
        /// Returns a (private key, public key) keypair, or an error if an error occurred
        /// initialising Sodium. The private key should be kept private, the public key can be
        /// publicised.
        ///
        /// # Security Considerations
        /// The generated private key will *not* be clamped, and therefore if used in other X25519
        /// implementations, it must be clamped before use. It is automatically clamped during the
        /// public key calculation, and for other calculations within the Sodium implementation.
        pub fn generate_keypair() -> Result<(PrivateKey, PublicKey), $crate::AlkaliError> {
            $crate::require_init()?;

            let mut private_key = PrivateKey::new_empty()?;
            let mut public_key = [0u8; PUBLIC_KEY_LENGTH];

            unsafe {
                // SAFETY: The first argument to this function is the destination to which the
                // public key will be written. We have defined the `PublicKey` type to store
                // `crypto_box_PUBLICKEYBYTES`, and therefore it is sufficient to store the public
                // key. The second argument is the destination to which the private key will be
                // written. We have defined the `PrivateKey` type to store
                // `crypto_box_SECRETKEYBYTES`, and therefore it is sufficient to store the private
                // key. The `PrivateKey::inner_mut` method simply returns a mutable pointer to the
                // backing memory.
                $keypair(
                    public_key.as_mut_ptr(),
                    private_key.inner_mut() as *mut libc::c_uchar,
                );
            }

            Ok((private_key, public_key))
        }

        /// Deterministically calculate an X25519 private key and corresponding public key for use
        /// in asymmetric AE, based on the provided seed.
        ///
        /// Given the same seed, the same (private, public) keypair will always be generated.
        ///
        /// Returns a (private key, public key) keypair, or an error if an error occurred
        /// initialising Sodium. The private key should be kept private, the public key can be
        /// publicised.
        ///
        /// # Security Considerations
        /// The generated private key will *not* be clamped, and therefore if used in other X25519
        /// implementations, it must be clamped before use. It is automatically clamped during the
        /// public key calculation, and for other calculations within the Sodium implementation.
        pub fn generate_keypair_from_seed(
            seed: &Seed,
        ) -> Result<(PrivateKey, PublicKey), $crate::AlkaliError> {
            $crate::require_init()?;

            let mut private_key = PrivateKey::new_empty()?;
            let mut public_key = [0u8; PUBLIC_KEY_LENGTH];

            unsafe {
                // SAFETY: The first argument to this function is the destination to which the
                // public key will be written. We have defined the `PublicKey` type to store
                // `crypto_box_PUBLICKEYBYTES`, and therefore it is sufficient to store the public
                // key. The second argument is the destination to which the private key will be
                // written. We have defined the `PrivateKey` type to store
                // `crypto_box_SECRETKEYBYTES`, and therefore it is sufficient to store the private
                // key. The `PrivateKey::inner_mut` method simply returns a mutable pointer to the
                // backing memory. The final argument to the function is a pointer to the seed
                // which should be used to generate the keypair. The `Seed` type has been defined
                // to be `crypto_box_SEEDBYTES` long, so it is of the expected size for use with
                // this function. The `Seed::inner` method simply returns an immutable pointer to
                // the backing memory.
                $seed_keypair(
                    public_key.as_mut_ptr(),
                    private_key.inner_mut() as *mut libc::c_uchar,
                    seed.inner() as *const libc::c_uchar,
                );
            }

            Ok((private_key, public_key))
        }

        /// Encrypt `message` for the recipient with public key `public_key_rx`, writing the result
        /// to `output`.
        ///
        /// `message` should be the message to encrypt. `public_key_rx` should be the receiver's
        /// [`PublicKey`], generated from a random private key using [`generate_keypair`].
        ///
        /// The encrypted ciphertext will be written to `output`, which must be at least
        /// [`ADDED_LENGTH`] bytes longer than `message`. If the `output` slice is not sufficient
        /// to store the ciphertext, an error will be returned.
        ///
        /// This function will generate a random ephemeral keypair for the sender, and determine a
        /// nonce from this. The ephemeral public key will be added to the ciphertext, so the
        /// receiver is able to decrypt the message. The receiver can deterministically calculate
        /// the nonce using this public key and their own public key.
        ///
        /// Returns the length of the ciphertext written to `output`, which will always be
        /// `message.len()` + [`ADDED_LENGTH`] bytes.
        pub fn encrypt(
            message: &[u8],
            public_key_rx: &PublicKey,
            output: &mut [u8],
        ) -> Result<usize, $crate::AlkaliError> {
            $crate::require_init()?;

            let c_len = message.len() + ADDED_LENGTH;

            if output.len() < c_len {
                return Err(RepudiableCipherError::OutputInsufficient(c_len, output.len()).into());
            } else if message.len() > *MESSAGE_LENGTH_MAX {
                return Err(RepudiableCipherError::MessageTooLong.into());
            }

            let res = unsafe {
                // SAFETY: The first argument to this function is the destination pointer to which
                // the ciphertext should be written. We verify above that the `output` slice is of
                // sufficient size to store the message + auth tag + ephemeral public key, so a
                // buffer overflow will not occur. The next two arguments specify the message to
                // encrypt and its length. We use `message.len()` to specify the message length, so
                // it is correct for this pointer. The final argument specifies the receiver's
                // public key. We define the `PublicKey` type based on the
                // `crypto_box_PUBLICKEYBYTES` constant, so it is of the expected size for use with
                // this function.
                $encrypt(
                    output.as_mut_ptr(),
                    message.as_ptr(),
                    message.len() as libc::c_ulonglong,
                    public_key_rx.as_ptr(),
                )
            };

            if res == 0 {
                Ok(c_len)
            } else {
                Err(RepudiableCipherError::PublicKeyInsecure.into())
            }
        }

        /// Try to decrypt `ciphertext` (previously encrypted using [`encrypt`]), writing the
        /// result to `output`.
        ///
        /// `ciphertext` shuld be a message to try to decrypt. `keypair_rx` should be the
        /// receiver's (private, public) keypair, with which the message will be decrypted.
        ///
        /// If integrity checking + decryption succeed, the decrypted message will be written to
        /// `output`. `output` must be at least `ciphertext.len()` - [`ADDED_LENGTH`] bytes,
        /// otherwise an error will be returned.
        ///
        /// Returns the length of the plaintext written to `output`, which will always be
        /// `ciphertext.len()` - [`ADDED_LENGTH`] bytes.
        pub fn decrypt(
            ciphertext: &[u8],
            keypair_rx: (&PrivateKey, &PublicKey),
            output: &mut [u8],
        ) -> Result<usize, $crate::AlkaliError> {
            $crate::require_init()?;

            if ciphertext.len() < ADDED_LENGTH {
                return Err(RepudiableCipherError::DecryptionFailed.into());
            }

            let m_len = ciphertext.len() - ADDED_LENGTH;

            if output.len() < m_len {
                return Err(RepudiableCipherError::OutputInsufficient(m_len, output.len()).into());
            }

            let decrypt_result = unsafe {
                // SAFETY: The first argument to this function is the destination pointer to which
                // the decrypted plaintext will be written. We verify above that the output slice
                // is sufficient to store the plaintext for this ciphertext, so a buffer overflow
                // will not occur. The next two arguments specify the ciphertext to decrypt and its
                // length. We use `ciphertext.len()` to specify the ciphertext length, so it is
                // correct for this pointer. The next argument specifies the recipient's public
                // key. We define the `PublicKey` type based on the `crypto_box_PUBLICKEYBYTES`
                // constant, so it is of the expected size for use with this function. The final
                // argument should be the recipient's private key. We define the `PrivateKey` type
                // based on the `crypto_box_SECRETKEYBYTES` constant, so it is of the expected size
                // for use with this function. The `PrivateKey::inner` method simply returns an
                // immutable pointer to the type's backing memory.
                $decrypt(
                    output.as_mut_ptr(),
                    ciphertext.as_ptr(),
                    ciphertext.len() as libc::c_ulonglong,
                    keypair_rx.1.as_ptr(),
                    keypair_rx.0.inner() as *const libc::c_uchar,
                )
            };

            if decrypt_result == 0 {
                Ok(m_len)
            } else {
                Err(RepudiableCipherError::DecryptionFailed.into())
            }
        }
    };
}

#[allow(unused_macros)]
macro_rules! repudiable_cipher_tests {
    () => {
        use super::{
            decrypt, encrypt, generate_keypair, generate_keypair_from_seed, Seed, ADDED_LENGTH,
        };
        use $crate::random;
        use $crate::AlkaliError;

        #[test]
        fn keypair_generation_random() -> Result<(), AlkaliError> {
            let (private_key, public_key) = generate_keypair()?;
            assert_eq!(private_key.public_key()?, public_key);
            Ok(())
        }

        #[test]
        fn keypair_from_seed_vectors() -> Result<(), AlkaliError> {
            let seed = Seed::try_from(&[
                0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2,
                0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5,
                0x1d, 0xb9, 0x2c, 0x2a,
            ])?;
            let (private_key, public_key) = generate_keypair_from_seed(&seed)?;

            assert_eq!(
                &private_key[..],
                &[
                    0xac, 0xcd, 0x44, 0xeb, 0x8e, 0x93, 0x31, 0x9c, 0x05, 0x70, 0xbc, 0x11, 0x00,
                    0x5c, 0x0e, 0x01, 0x89, 0xd3, 0x4f, 0xf0, 0x2f, 0x6c, 0x17, 0x77, 0x34, 0x11,
                    0xad, 0x19, 0x12, 0x93, 0xc9, 0x8f
                ]
            );
            assert_eq!(
                public_key,
                [
                    0xed, 0x77, 0x49, 0xb4, 0xd9, 0x89, 0xf6, 0x95, 0x7f, 0x3b, 0xfd, 0xe6, 0xc5,
                    0x67, 0x67, 0xe9, 0x88, 0xe2, 0x1c, 0x9f, 0x87, 0x84, 0xd9, 0x1d, 0x61, 0x00,
                    0x11, 0xcd, 0x55, 0x3f, 0x9b, 0x06
                ]
            );
            assert_eq!(private_key.public_key()?, public_key);

            Ok(())
        }

        #[test]
        fn enc_and_dec() -> Result<(), AlkaliError> {
            for _ in 0..100 {
                let (private_key, public_key) = generate_keypair()?;

                let mut msg = vec![0; random::random_u32_in_range(0, 1000)? as usize];
                let mut c = vec![0; msg.len() + ADDED_LENGTH];
                random::fill_random(&mut msg)?;

                assert_eq!(encrypt(&msg, &public_key, &mut c)?, c.len());

                let mut p = vec![0; msg.len()];

                assert_eq!(decrypt(&c, (&private_key, &public_key), &mut p)?, msg.len());
                assert_eq!(msg, p);
            }

            Ok(())
        }
    };
}

/// This implementation uses [X25519](https://en.wikipedia.org/wiki/Curve25519) (Elliptic-Curve
/// Diffie-Hellman over Curve25519) to establish a shared secret key for encryption/decryption. The
/// [XSalsa20](https://en.wikipedia.org/wiki/Salsa20) cipher is used to perform
/// encryption/decryption, with the [Poly1305](https://en.wikipedia.org/wiki/Poly1305) MAC for
/// authentication.
pub mod curve25519xsalsa20poly1305 {
    use libsodium_sys as sodium;

    repudiable_cipher_module! {
        sodium::crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES,
        sodium::crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES,
        sodium::crypto_box_curve25519xsalsa20poly1305_SEEDBYTES,
        sodium::crypto_box_SEALBYTES,
        sodium::crypto_box_curve25519xsalsa20poly1305_messagebytes_max,
        sodium::crypto_box_curve25519xsalsa20poly1305_keypair,
        sodium::crypto_box_curve25519xsalsa20poly1305_seed_keypair,
        sodium::crypto_box_seal,
        sodium::crypto_box_seal_open,
    }

    #[cfg(test)]
    mod tests {
        repudiable_cipher_tests! {}
    }
}

/// This implementation uses [X25519](https://en.wikipedia.org/wiki/Curve25519) (Elliptic-Curve
/// Diffie-Hellman over Curve25519) to establish a shared secret key for encryption/decryption. The
/// [XChaCha20](https://en.wikipedia.org/wiki/Salsa20##ChaCha_variant) cipher is used to perform
/// encryption/decryption, with the [Poly1305](https://en.wikipedia.org/wiki/Poly1305) MAC for
/// authentication.
pub mod curve25519xchacha20poly1305 {
    use libsodium_sys as sodium;

    repudiable_cipher_module! {
        sodium::crypto_box_curve25519xchacha20poly1305_SECRETKEYBYTES,
        sodium::crypto_box_curve25519xchacha20poly1305_PUBLICKEYBYTES,
        sodium::crypto_box_curve25519xchacha20poly1305_SEEDBYTES,
        sodium::crypto_box_curve25519xchacha20poly1305_SEALBYTES,
        sodium::crypto_box_curve25519xchacha20poly1305_messagebytes_max,
        sodium::crypto_box_curve25519xchacha20poly1305_keypair,
        sodium::crypto_box_curve25519xchacha20poly1305_seed_keypair,
        sodium::crypto_box_curve25519xchacha20poly1305_seal,
        sodium::crypto_box_curve25519xchacha20poly1305_seal_open,
    }

    #[cfg(test)]
    mod tests {
        repudiable_cipher_tests! {}
    }
}

pub use curve25519xsalsa20poly1305::*;
