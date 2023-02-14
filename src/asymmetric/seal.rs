//! Anonymous asymmetric [Authenticated
//! Encryption](https://en.wikipedia.org/wiki/Authenticated_encryption) (AE).
//!
//! This module corresponds to the [`crypto_box_seal`
//! API](https://doc.libsodium.org/public-key_cryptography/sealed_boxes) from Sodium.
//!
//! In the [`cipher`](crate::asymmetric::cipher) module, the receiver must know the sender's public
//! key in order to receive messages. The `seal` module allows messages to be sent to a recipient
//! who does not know the sender's long-term identity (i.e: messages can be sent anonymously).
//!
//! The basic construction is very similar to that of the `cipher` module, but an ephemeral sender
//! keypair is generated for every message. After the encryption process is complete, the ephemeral
//! private key is immediately destroyed, while the public key is transmitted to the recipient. This
//! means only the recipient can decrypt the message: The sender can't decrypt their own message
//! later. This also means that the construction is entirely repudiable: There is no cryptographic
//! way to prove a specific person sent the message without additional data.
//!
//! # Algorithm Details
//! The same algorithm as in the [`cipher`](crate::asymmetric::cipher) module is used:
//! [X25519](https://cr.yp.to/ecdh.html) is used to perform a key exchange,
//! [XSalsa20](https://cr.yp.to/snuffle.html) or
//! [XChaCha20](https://cr.yp.to/chacha.html) are used to encrypt/decrypt messages, and
//! [Poly1305](https://en.wikipedia.org/wiki/Poly1305) is used for message authentication.
//!
//! The difference to the `cipher` module is that a random ephemeral sender keypair is generated for
//! every message, rather than using a long-term sender identity. The nonce for the message is
//! calculated deterministically by hashing the concatenation of the ephemeral public key and the
//! receiver public key. The ephemeral public key is prepended to the message.
//!
//! The overall format of the ciphertext is as follows, where `||` denotes concatenation:
//!
//! ```text
//! ephemeral_pk || cipher(message, recipient_pk, ephemeral_sk, nonce=blake2b(ephemeral_pk || recipient_pk))
//! ```
//!
//! # Security Considerations
//! The [`PrivateKey`] type stores the private key *unclamped* in memory. While the implementation
//! always clamps it before use, other implementations may not do so, so if you choose to use keys
//! generated here outside of Sodium, it must be clamped: See [this
//! article](https://neilmadden.blog/2020/05/28/whats-the-curve25519-clamping-all-about/) for more
//! information on the procedure.
//!
//! This construction exposes the length of the plaintext. If this is undesirable, apply padding to
//! the plaintext prior to encryption via [`util::pad`](crate::util::pad), and remove it following
//! decryption via [`util::unpad`](crate::util::unpad).
//!
//! # Examples
//! ```rust
//! use alkali::asymmetric::seal;
//!
//! const MESSAGE: &'static str = "Encrypt this message!";
//!
//! // Receiver side:
//!
//! // Generate a random keypair (including a private and public key) for receiving encrypted
//! // messages. The public key should be shared publicly, the private key should be kept secret.
//! let keypair = seal::Keypair::generate().unwrap();
//!
//!
//! // ...
//!
//!
//! // Sender side:
//! // We assume we know the receiver's public key, `receiver_pub`.
//! # let receiver_pub = keypair.public_key.clone();
//!
//! // Encrypting a message with this construction adds `OVERHEAD_LENGTH` bytes of overhead (the
//! // ephemeral public key + MAC).
//! let mut ciphertext = vec![0u8; MESSAGE.as_bytes().len() + seal::OVERHEAD_LENGTH];
//! // In this construction, the sender does not generate a keypair, they just use `encrypt` to
//! // encrypt the message. Once it is sent, they can't decrypt it, as the ephemeral private key is
//! // erased from memory.
//! seal::encrypt(MESSAGE.as_bytes(), &receiver_pub, &mut ciphertext).unwrap();
//!
//!
//! // ...
//!
//!
//! // Receiver side:
//!
//! let mut plaintext = vec![0u8; ciphertext.len() - seal::OVERHEAD_LENGTH];
//! // The receiver does not to receive any other information from the sender besides the ciphertext
//! // in order to decrypt it.
//! seal::decrypt(&ciphertext, &keypair, &mut plaintext).unwrap();
//! assert_eq!(&plaintext, MESSAGE.as_bytes());
//! ```

crate::error_type! {
    /// Error type returned if something went wrong in the `seal` module.
    SealError {
        /// The output buffer is too short to store the ciphertext/plaintext which would result from
        /// encrypting/decrypting this message.
        ///
        /// Each function in this module should provide information in its documentation about the
        /// output length requirements.
        OutputInsufficient,

        /// Message too long for use with this cipher.
        ///
        /// Beyond a certain point, the keystream of the cipher is exhausted, and it can no longer
        /// be used to safely encrypt message contents. Therefore, this error is returned if the
        /// message provided is too long. Messages can be at most [`struct@MESSAGE_LENGTH_MAX`]
        /// bytes.
        MessageTooLong,

        /// The other party's keypair is unacceptable, and should not be used for cryptographic
        /// purposes.
        PublicKeyUnacceptable,

        /// Indicates decryption of a provided ciphertext failed.
        ///
        /// This could indicate an attempted forgery, or transmission error.
        DecryptionFailed,
    }
}

/// Generates the API for an `asymmetric::seal` module with the given functions from Sodium for a
/// specific implementation.
macro_rules! seal_module {
    (
        $private_key_len:expr,  // crypto_box_SECRETKEYBYTES
        $public_key_len:expr,   // crypto_box_PUBLICKEYBYTES
        $seed_len:expr,         // crypto_box_SEEDBYTES
        $overhead:expr,         // crypto_box_SEALBYTES
        $msg_max:path,          // crypto_box_messagebytes_max
        $keypair:path,          // crypto_box_keypair
        $seed_keypair:path,     // crypto_box_seed_keypair
        $scalarmult_base:path,  // crypto_scalarmult_base
        $encrypt:path,          // crypto_box_seal
        $decrypt:path,          // crypto_box_seal_open
    ) => {
        use $crate::asymmetric::seal::SealError;
        use $crate::{assert_not_err, mem, require_init, AlkaliError};

        /// The length of a private key for asymmetric AE, in bytes.
        pub const PRIVATE_KEY_LENGTH: usize = $private_key_len as usize;

        /// The length of a public key for asymmetric AE, in bytes.
        pub const PUBLIC_KEY_LENGTH: usize = $public_key_len as usize;

        /// The length of a seed to use for the deterministic generation of a [`Keypair`], in bytes.
        pub const KEY_SEED_LENGTH: usize = $seed_len as usize;

        /// The extra length added to a message following encryption, in bytes.
        pub const OVERHEAD_LENGTH: usize = $overhead as usize;

        lazy_static::lazy_static! {
            /// The maximum message length which can be encrypted with this cipher, in bytes.
            pub static ref MESSAGE_LENGTH_MAX: usize = unsafe {
                // SAFETY: This function just returns a constant value, and should always be safe
                // to call.
                $msg_max()
            };
        }

        mem::hardened_buffer! {
            /// A private key used in asymmetric AE.
            ///
            /// A private key forms one half of a [`Keypair`], together with a [`PublicKey`].
            ///
            /// There are no technical constraints on the contents of a private key for this API.
            /// Keys are [clamped](https://www.jcraige.com/an-explainer-on-ed25519-clamping) at time
            /// of usage, not when generated, so a private key can just be any random sequence of
            /// bytes. However, private keys should be indistinguishable from random noise, and
            /// should really be generated randomly using [`Keypair::generate`]. If you need to
            /// derive a private key deterministically, use [`Keypair::from_seed`].
            ///
            /// A private key is secret, and as such, should not ever be made public.
            ///
            /// This is a [hardened buffer type](https://docs.rs/alkali#hardened-buffer-types), and
            /// will be zeroed on drop. A number of other security measures are taken to protect
            /// its contents. This type in particular can be thought of as roughly equivalent to a
            /// `[u8; PRIVATE_KEY_LENGTH]`, and implements [`core::ops::Deref`], so it can be used
            /// like it is an `&[u8]`. This struct uses heap memory while in scope, allocated using
            /// Sodium's [secure memory utilities](https://doc.libsodium.org/memory_management).
            ///
            /// # Security Considerations
            /// In this API, private keys are stored *unclamped*. If you intend to use this private
            /// key with a different X25519 implementation, it may need to be clamped before use.
            pub PrivateKey(PRIVATE_KEY_LENGTH);

            /// A seed used to deterministically derive a [`Keypair`].
            ///
            /// A seed can be used with [`Keypair::from_seed`] to deterministically derive a private
            /// key and public key.
            ///
            /// If a keypair derived from a seed is to be used for real-world operations, the seed
            /// should be treated as securely as the private key itself, since it is trivial to
            /// derive the private key given the seed. So, do not make seeds public.
            ///
            /// This is a [hardened buffer type](https://docs.rs/alkali#hardened-buffer-types), and
            /// will be zeroed on drop. A number of other security measures are taken to protect
            /// its contents. This type in particular can be thought of as roughly equivalent to a
            /// `[u8; SESSION_KEY_LENGTH]`, and implements [`core::ops::Deref`], so it can be used
            /// like it is an `&[u8]`. This struct uses heap memory while in scope, allocated using
            /// Sodium's [secure memory utilities](https://doc.libsodium.org/memory_management).
            pub Seed(KEY_SEED_LENGTH);
        }

        impl PrivateKey {
            /// Derive the public key corresponding to this private key.
            pub fn public_key(&self) -> Result<PublicKey, AlkaliError> {
                require_init()?;

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

        /// A ([`PrivateKey`], [`PublicKey`]) keypair, used for receiving messages.
        ///
        /// In the `seal` module, keypairs are only used to receive messages, since messages are
        /// always sent with internal ephemeral keypairs which are not accessible to the user.
        /// However, this type is actually identical to a [`crate::asymmetric::cipher::Keypair`],
        /// and there is no security risk in converting between the two.
        ///
        /// The private key must be kept secret, while the public key can be made public.
        #[cfg_attr(feature = "use-serde", derive(serde::Serialize, serde::Deserialize))]
        pub struct Keypair {
            /// The private key for this keypair.
            pub private_key: PrivateKey,

            /// The public key corresponding to the private key.
            pub public_key: PublicKey,
        }

        impl Keypair {
            /// Generate a new, random X25519 keypair, for use in asymmetric AE.
            ///
            /// A keypair consists of a [`PrivateKey`], which must be kept secret, and a
            /// [`PublicKey`], which should be made public.
            pub fn generate() -> Result<Self, AlkaliError> {
                require_init()?;

                let mut private_key = PrivateKey::new_empty()?;
                let mut public_key = [0u8; PUBLIC_KEY_LENGTH];

                let keypair_result = unsafe {
                    // SAFETY: This function expects a pointer to a region of memory sufficient to
                    // store a public key, and a pointer to a region of memory sufficient to store a
                    // private key for this algorithm. We have defined the `PublicKey` type to be
                    // `crypto_box_PUBLICKEYBYTES`, the length of a public key for this algorithm,
                    // so it is of sufficient size to store the public key. The `PrivateKey` type
                    // allocates `crypto_box_SECRETKEYBYTES`, the length of a private key for this
                    // algorithm, so it is of sufficient size to store the private key. Any region
                    // of memory can be a valid representation of a `u8` array, so both variables
                    // will still be valid after this function call. The `PrivateKey::inner_mut`
                    // method simply returns a mutable pointer to its backing memory.
                    $keypair(
                        public_key.as_mut_ptr(),
                        private_key.inner_mut() as *mut libc::c_uchar,
                    )
                };
                assert_not_err!(keypair_result, stringify!($keypair));

                Ok(Self {
                    private_key,
                    public_key,
                })
            }

            /// Deterministically derive an X25519 keypair for use in asymmetric AE from a seed.
            ///
            /// Given the same seed, the same keypair will always be generated.
            ///
            /// A keypair consists of a [`PrivateKey`], which must be kept secret, and a
            /// [`PublicKey`], which should be made public.
            pub fn from_seed(seed: &Seed) -> Result<Self, AlkaliError> {
                require_init()?;

                let mut private_key = PrivateKey::new_empty()?;
                let mut public_key = [0u8; PUBLIC_KEY_LENGTH];

                let keypair_result = unsafe {
                    // SAFETY: This function expects a pointer to a region of memory sufficient to
                    // store a public key, a pointer to a region of memory sufficient to store a
                    // private key, and a pointer to a seed. We have defined the `PublicKey` type to
                    // be `crypto_box_PUBLICKEYBYTES`, so it is of sufficient size to store the
                    // public key. The `PrivateKey` type allocates `crypto_box_SECRETKEYBYTES`, the
                    // length of a private key for this algorithm, so it is of sufficient size to
                    // store the private key. Any region of memory can be a valid representation of
                    // a `u8` array, so both variables will still be valid after this function call.
                    // The `PrivateKey::inner_mut` method simply returns a mutable pointer to its
                    // backing memory. The `Seed` type is defined to be `crypto_box_SEEDBYTES`, and
                    // is therefore valid for reads of the length required for a seed for this
                    // algorithm. The `Seed::inner` method simply returns an immutable pointer to
                    // its backing memory.
                    $seed_keypair(
                        public_key.as_mut_ptr(),
                        private_key.inner_mut() as *mut libc::c_uchar,
                        seed.inner() as *const libc::c_uchar,
                    )
                };
                assert_not_err!(keypair_result, stringify!($seed_keypair));

                Ok(Self {
                    private_key,
                    public_key,
                })
            }

            /// Construct a keypair given just the [`PrivateKey`].
            ///
            /// A keypair consists of a [`PrivateKey`] and a [`PublicKey`]. This function calculates
            /// the public key associated with the provided private key and stores both in a
            /// [`Keypair`]. This is useful if you know your private key, but don't have the
            /// corresponding public key.
            pub fn from_private_key(private_key: &PrivateKey) -> Result<Self, AlkaliError> {
                require_init()?;

                let mut public_key = [0u8; PUBLIC_KEY_LENGTH];

                let scalarmult_result = unsafe {
                    // SAFETY: This function expects a pointer to a region of memory sufficient to
                    // store a point on Curve25519, and a pointer to a scalar by which the generator
                    // of Curve25519 should be multiplied. We have defined the `PublicKey` type to
                    // be `crypto_box_PUBLICKEYBYTES`, which is equal to `crypto_scalarmult_BYTES`,
                    // the length of the Curve25519 point outputted by this multiplication, so it is
                    // of sufficient size to store the output here. Any region of memory can be a
                    // valid representation of a `u8` array, so the `public_key` variable will still
                    // be valid after this function call. The `PrivateKey` type allocates
                    // `crypto_box_SECRETKEYBYTES` of storage, which is equal to
                    // `crypto_scalarmult_SCALARBYTES`, the length of a scalar for this
                    // multiplication, so it is valid for reads of the expected size. The
                    // `PrivateKey::inner` method simply returns an immutable pointer to its backing
                    // memory.
                    $scalarmult_base(
                        public_key.as_mut_ptr(),
                        private_key.inner() as *const libc::c_uchar,
                    )
                };
                assert_not_err!(scalarmult_result, stringify!($scalarmult_base));

                Ok(Self {
                    private_key: private_key.try_clone()?,
                    public_key,
                })
            }
        }

        /// Encrypt `message` for the recipient with public key `receiver`, writing the result to
        /// `output`.
        ///
        /// `message` should be the message to encrypt. `reciever` should be the recipient's
        /// [`PublicKey`].
        ///
        /// The encrypted ciphertext will be written to `output`, which must be at least
        /// [`OVERHEAD_LENGTH`] bytes longer than `message`. If the `output` slice is not sufficient
        /// to store the ciphertext, an error will be returned.
        ///
        /// This function will generate a random ephemeral keypair for the sender, and determine a
        /// nonce from this. The ephemeral public key will be added to the ciphertext, so the
        /// receiver is able to decrypt the message. The receiver can deterministically calculate
        /// the nonce using this public key and their own public key.
        ///
        /// Returns the length of the ciphertext written to `output`, which will always be
        /// `message.len()` + [`OVERHEAD_LENGTH`] bytes.
        pub fn encrypt(
            message: &[u8],
            receiver: &PublicKey,
            output: &mut [u8],
        ) -> Result<usize, AlkaliError> {
            require_init()?;

            let c_len = message.len() + OVERHEAD_LENGTH;

            if output.len() < c_len {
                return Err(SealError::OutputInsufficient.into());
            } else if message.len() > *MESSAGE_LENGTH_MAX {
                return Err(SealError::MessageTooLong.into());
            }

            let encrypt_result = unsafe {
                // SAFETY: The first argument to this function is the destination to which the
                // ciphertext will be written. The ciphertext will be the length of the plaintext,
                // plus `crypto_box_SEALBYTES` extra bytes, so this pointer must be valid for writes
                // of this length. We verify this condition on `output` above. The next two
                // arguments specify the message to encrypt and its length. We use `message.len()`
                // to specify the length to read from the message pointer, so `message` is
                // definitely valid for reads of this length. The final argument specifies a pointer
                // to the public key for whom the message should be encrypted. We have defined the
                // `PublicKey` type to be `crypto_box_PUBLICKEYBYTES`, the length of a public key
                // for this algorithm, so it is valid for reads of the required length.
                $encrypt(
                    output.as_mut_ptr(),
                    message.as_ptr(),
                    message.len() as libc::c_ulonglong,
                    receiver.as_ptr(),
                )
            };

            if encrypt_result == 0 {
                Ok(c_len)
            } else {
                Err(SealError::PublicKeyUnacceptable.into())
            }
        }

        /// Decrypt `ciphertext` using the provided [`Keypair`], writing the result to `output`.
        ///
        /// `ciphertext` should be the message to attempt to decrypt. `keypair` should be the
        /// [`Keypair`] to use for decryption.
        ///
        /// If integrity checking + decryption succeed, the decrypted message will be written to
        /// `output`. `output` must be at least `ciphertext.len()` - [`OVERHEAD_LENGTH`] bytes,
        /// otherwise an error will be returned.
        ///
        /// Returns the length of the plaintext written to `output`, which will always be
        /// `ciphertext.len()` - [`OVERHEAD_LENGTH`] bytes.
        pub fn decrypt(
            ciphertext: &[u8],
            keypair: &Keypair,
            output: &mut [u8],
        ) -> Result<usize, AlkaliError> {
            require_init()?;

            if ciphertext.len() < OVERHEAD_LENGTH {
                return Err(SealError::DecryptionFailed.into());
            }

            let m_len = ciphertext.len() - OVERHEAD_LENGTH;

            if output.len() < m_len {
                return Err(SealError::OutputInsufficient.into());
            }

            let decrypt_result = unsafe {
                // SAFETY: The first argument to this function is the destination to which the
                // plaintext will be written. The plaintext will be the length of the ciphertext,
                // minus `crypto_box_SEALBYTES` bytes, so this pointer must be valid for writes of
                // this length. We verify this condition on `output` above. The next two arguments
                // specify the ciphertext to decrypt and its length. We use `ciphertext.len()` to
                // specify the length to read from the ciphertext pointer, so `ciphertext` is
                // definitely valid for reads of this length. The next argument specifies a pointer
                // to the recipient's public key. We have defined the `PublicKey` type to be
                // `crypto_box_PUBLICKEYBYTES`, the length of a public key for this algorithm, so it
                // is valid for reads of the required length. The final argument should be a pointer
                // to the recipient's private key. We have defined the `PrivateKey` type to allocate
                // `crypto_box_SECRETKEYBYTES`, the length of a private key for this algorithm, so
                // it is valid for reads of the required length. The `PrivateKey::inner` method
                // simply returns an immutable pointer to its backing memory.
                $decrypt(
                    output.as_mut_ptr(),
                    ciphertext.as_ptr(),
                    ciphertext.len() as libc::c_ulonglong,
                    keypair.public_key.as_ptr(),
                    keypair.private_key.inner() as *const libc::c_uchar,
                )
            };

            if decrypt_result == 0 {
                Ok(m_len)
            } else {
                Err(SealError::DecryptionFailed.into())
            }
        }
    };
}

#[allow(unused_macros)]
macro_rules! seal_tests {
    () => {
        use super::{decrypt, encrypt, Keypair, Seed, OVERHEAD_LENGTH};
        use $crate::random;
        use $crate::AlkaliError;

        #[test]
        fn keypair_generation_random() -> Result<(), AlkaliError> {
            let keypair = Keypair::generate()?;
            let keypair_new = Keypair::from_private_key(&keypair.private_key)?;
            assert_eq!(keypair.public_key, keypair_new.public_key);
            Ok(())
        }

        #[test]
        fn keypair_from_seed_vectors() -> Result<(), AlkaliError> {
            let seed = Seed::try_from(&[
                0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2,
                0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5,
                0x1d, 0xb9, 0x2c, 0x2a,
            ])?;
            let keypair = Keypair::from_seed(&seed)?;

            assert_eq!(
                &keypair.private_key[..],
                &[
                    0xac, 0xcd, 0x44, 0xeb, 0x8e, 0x93, 0x31, 0x9c, 0x05, 0x70, 0xbc, 0x11, 0x00,
                    0x5c, 0x0e, 0x01, 0x89, 0xd3, 0x4f, 0xf0, 0x2f, 0x6c, 0x17, 0x77, 0x34, 0x11,
                    0xad, 0x19, 0x12, 0x93, 0xc9, 0x8f
                ]
            );
            assert_eq!(
                &keypair.public_key,
                &[
                    0xed, 0x77, 0x49, 0xb4, 0xd9, 0x89, 0xf6, 0x95, 0x7f, 0x3b, 0xfd, 0xe6, 0xc5,
                    0x67, 0x67, 0xe9, 0x88, 0xe2, 0x1c, 0x9f, 0x87, 0x84, 0xd9, 0x1d, 0x61, 0x00,
                    0x11, 0xcd, 0x55, 0x3f, 0x9b, 0x06
                ]
            );

            let keypair_new = Keypair::from_private_key(&keypair.private_key)?;
            assert_eq!(keypair.public_key, keypair_new.public_key);

            Ok(())
        }

        #[test]
        fn enc_and_dec() -> Result<(), AlkaliError> {
            for _ in 0..100 {
                let keypair = Keypair::generate()?;

                let mut msg = [0u8; 1000];
                let mut c = [0u8; 1000 + OVERHEAD_LENGTH];
                let l = random::random_u32_in_range(0, 1000)? as usize;
                random::fill_random(&mut msg[..l])?;

                assert_eq!(
                    encrypt(&msg[..l], &keypair.public_key, &mut c)?,
                    l + OVERHEAD_LENGTH
                );

                let mut p = [0u8; 1000];

                assert_eq!(decrypt(&c[..l + OVERHEAD_LENGTH], &keypair, &mut p)?, l);
                assert_eq!(msg, p);
            }

            Ok(())
        }
    };
}

/// This implementation uses [X25519](https://cr.yp.to/ecdh.html) (Elliptic-Curve Diffie-Hellman
/// over Curve25519) to establish a shared secret key for encryption/decryption. The
/// [XSalsa20](https://cr.yp.to/snuffle.html) cipher is used to perform encryption/decryption, with
/// the [Poly1305](https://en.wikipedia.org/wiki/Poly1305) MAC for authentication.
pub mod curve25519xsalsa20poly1305 {
    use libsodium_sys as sodium;

    seal_module! {
        sodium::crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES,
        sodium::crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES,
        sodium::crypto_box_curve25519xsalsa20poly1305_SEEDBYTES,
        sodium::crypto_box_SEALBYTES,
        sodium::crypto_box_curve25519xsalsa20poly1305_messagebytes_max,
        sodium::crypto_box_curve25519xsalsa20poly1305_keypair,
        sodium::crypto_box_curve25519xsalsa20poly1305_seed_keypair,
        sodium::crypto_scalarmult_curve25519_base,
        sodium::crypto_box_seal,
        sodium::crypto_box_seal_open,
    }

    #[cfg(test)]
    mod tests {
        seal_tests! {}
    }
}

/// This implementation uses [X25519](https://cr.yp.to/ecdh.html) (Elliptic-Curve Diffie-Hellman
/// over Curve25519) to establish a shared secret key for encryption/decryption. The
/// [XChaCha20](https://cr.yp.to/chacha.html) cipher is used to perform encryption/decryption, with
/// the [Poly1305](https://en.wikipedia.org/wiki/Poly1305) MAC for authentication.
#[cfg(not(feature = "minimal"))]
#[cfg_attr(doc_cfg, doc(cfg(not(feature = "minimal"))))]
pub mod curve25519xchacha20poly1305 {
    use libsodium_sys as sodium;

    seal_module! {
        sodium::crypto_box_curve25519xchacha20poly1305_SECRETKEYBYTES,
        sodium::crypto_box_curve25519xchacha20poly1305_PUBLICKEYBYTES,
        sodium::crypto_box_curve25519xchacha20poly1305_SEEDBYTES,
        sodium::crypto_box_curve25519xchacha20poly1305_SEALBYTES,
        sodium::crypto_box_curve25519xchacha20poly1305_messagebytes_max,
        sodium::crypto_box_curve25519xchacha20poly1305_keypair,
        sodium::crypto_box_curve25519xchacha20poly1305_seed_keypair,
        sodium::crypto_scalarmult_curve25519_base,
        sodium::crypto_box_curve25519xchacha20poly1305_seal,
        sodium::crypto_box_curve25519xchacha20poly1305_seal_open,
    }

    #[cfg(test)]
    mod tests {
        seal_tests! {}
    }
}

pub use curve25519xsalsa20poly1305::*;
