//! Asymmetric [Authenticated Encryption](https://en.wikipedia.org/wiki/Authenticated_encryption)
//! (AE).
//!
//! This module corresponds to the [`crypto_box`
//! API](https://doc.libsodium.org/public-key_cryptography/authenticated_encryption) from Sodium.
//!
//! Authenticated encryption is used to encrypt messages, providing assurance to the receiver that
//! the ciphertext has not been modified in transit by an attacker or transmission error. In
//! asymmetric encryption, parties do not need to have established a shared secret key prior to
//! communication: they only need to know the other party's public key to communicate.
//!
//! This API employs a [hybrid](https://en.wikipedia.org/wiki/Hybrid_cryptosystem) approach to
//! asymmetric encryption: An asymmetric key exchange is used to establish a shared secret key, and
//! then a symmetric cipher is used to actually encrypt messages. This differs from older asymmetric
//! encryption schemes such as RSA, which directly use an asymmetric cipher for message encryption.
//! The benefit to the hybrid approach is that symmetric ciphers are often much faster than
//! asymmetric ciphers, and are less prone to edge-cases which may lead to vulnerabilities.
//!
//! # Algorithm Details
//! [X25519](https://cr.yp.to/ecdh.html) (Elliptic-Curve Diffie-Hellman over Curve25519) is used to
//! perform the key exchange, establishing a shared secret key. By default,
//! [XSalsa20](https://cr.yp.to/snuffle.html) (Salsa20 with an extended nonce) is used as the
//! symmetric cipher, and [Poly1305](https://en.wikipedia.org/wiki/Poly1305) is used for message
//! authentication. This construction is exposed in the [`curve25519xsalsa20poly1305`] module.
//!
//! A variant which uses [XChaCha20](https://cr.yp.to/chacha.html) (ChaCha20 with an extended nonce)
//! for the symmetric cipher is also available as [`curve25519xchacha20poly1305`].
//!
//! # Security Considerations
//! For the algorithms in this module, nonces must *never* be used more than once with the same key.
//! If you supply `None` as the nonce for [`Keypair::encrypt`] (or any of the other encryption
//! functions), a nonce will be randomly generated for you, and the chance of nonce-reuse is
//! effectively zero. However, if you need to specify your own nonces for each message, please
//! ensure a given nonce is never reused: Random nonce generation with [`generate_nonce`] will
//! probably be your best strategy.
//!
//! The [`PrivateKey`] type stores the private key *unclamped* in memory. While the implementation
//! always clamps it before use, other implementations may not do so, so if you choose to use keys
//! generated here outside of Sodium, it must be clamped: See [this
//! article](https://neilmadden.blog/2020/05/28/whats-the-curve25519-clamping-all-about/) for more
//! information on the procedure.
//!
//! In this construction, either party can both encrypt & decrypt messages, and compute a valid
//! authentication tag for any encrypted message. Furthermore, the recipient must know the identity
//! of the sender to receive and decrypt messages. If any of these factors are a concern, the
//! [`crate::asymmetric::seal`] API should be used.
//!
//! This construction exposes the length of the plaintext. If this is undesirable, apply padding to
//! the plaintext prior to encryption via [`util::pad`](crate::util::pad), and remove it following
//! decryption via [`util::unpad`](crate::util::unpad).
//!
//! ## Secret Data
//! * Private keys ([`PrivateKey`]) must be kept secret
//! * A [`Keypair`] contains a [`PrivateKey`], and as such, should also be kept secret
//! * Seeds ([`Seed`]) must be kept secret
//! * Session keys ([`SessionKey`]) must be kept secret
//!
//! ## Non-Secret Data
//! * Public keys ([`PublicKey`]) can (and should) be made public
//! * MACs ([`MAC`]) are not sensitive
//! * Nonces ([`Nonce`]) are not sensitive
//!
//! # Examples
//! Encrypting and decrypting a message (uses [`Keypair::encrypt`] and [`Keypair::decrypt`]):
//!
//! ```rust
//! use alkali::asymmetric::cipher;
//!
//! const MESSAGE: &'static str = "Encrypt this message!";
//!
//! // Receiver side:
//!
//! // Generate a random keypair (including a private and public key) for sending/receiving
//! // encrypted messages. The public key should be shared publicly, the private key should be kept
//! // secret.
//! let receiver_keypair = cipher::Keypair::generate().unwrap();
//!
//!
//! // ...
//!
//!
//! // Sender side:
//! // We assume we know the receiver's public key, `receiver_pub`.
//! # let receiver_pub = receiver_keypair.public_key.clone();
//!
//! // In this construction, the sender must also have a keypair to send/receive messages.
//! let sender_keypair = cipher::Keypair::generate().unwrap();
//! // An encrypted message will be `MAC_LENGTH` bytes longer than the original message.
//! let mut ciphertext = vec![0u8; MESSAGE.as_bytes().len() + cipher::MAC_LENGTH];
//! // If this function is successful, the ciphertext + a MAC will be stored in `ciphertext`. A
//! // random nonce will be generated for this message, and returned to be stored in `nonce`. We
//! // will need this to perform the decryption.
//! let (_, nonce) = sender_keypair.encrypt(
//!     MESSAGE.as_bytes(), &receiver_pub, None, &mut ciphertext
//! ).unwrap();
//!
//!
//! // ...
//!
//!
//! // Receiver side:
//! // We assume we now know the sender's public key, `sender_pub`.
//! # let sender_pub = sender_keypair.public_key;
//!
//! let mut plaintext = vec![0u8; ciphertext.len() - cipher::MAC_LENGTH];
//! // The `decrypt` method not only decrypts `ciphertext`, but also verifies its authenticity using
//! // the included MAC. This operation will fail if a forgery is attempted.
//! receiver_keypair.decrypt(&ciphertext, &sender_pub, &nonce, &mut plaintext).unwrap();
//! assert_eq!(&plaintext, MESSAGE.as_bytes());
//! ```
//!
//! If many messages are to be sent between the same parties, it can be useful to precalculate the
//! symmetric [`SessionKey`] first, rather than performing a new key exchange for every message
//! (uses [`Keypair::session_key`], [`SessionKey::encrypt`], [`SessionKey::decrypt`]):
//!
//! ```rust
//! use alkali::asymmetric::cipher;
//!
//! const MESSAGE: &'static str = "Encrypt me too :)";
//!
//! // Receiver side:
//!
//! let receiver_keypair = cipher::Keypair::generate().unwrap();
//!
//!
//! // ...
//!
//!
//! // Sender side
//! // We assume we know the receiver's public key, `receiver_pub`.
//! # let receiver_pub = receiver_keypair.public_key.clone();
//!
//! let sender_keypair = cipher::Keypair::generate().unwrap();
//! // Precalculate the symmetric session key for this sender + receiver.
//! let session_key = sender_keypair.session_key(&receiver_pub).unwrap();
//! // Use the session key to encrypt the message, rather than the keypair.
//! let mut ciphertext = vec![0u8; MESSAGE.as_bytes().len() + cipher::MAC_LENGTH];
//! let (_, nonce) = session_key.encrypt(MESSAGE.as_bytes(), None, &mut ciphertext).unwrap();
//!
//!
//! // ...
//!
//!
//! // Receiver side:
//! // We assume we now know the sender's public key, `sender_pub`.
//! # let sender_pub = sender_keypair.public_key;
//!
//! // The session key calculated here will be the same as the session key the sender calculated.
//! let session_key = receiver_keypair.session_key(&sender_pub).unwrap();
//! // Decrypt + verify the message.
//! let mut plaintext = vec![0u8; ciphertext.len() - cipher::MAC_LENGTH];
//! session_key.decrypt(&ciphertext, &nonce, &mut plaintext).unwrap();
//! assert_eq!(&plaintext, MESSAGE.as_bytes());
//! ```
//!
//! Detached encryption & decryption, which stores the MAC separately to the ciphertext (uses
//! [`Keypair::encrypt_detached`], [`Keypair::decrypt_detached`]):
//!
//! ```rust
//! use alkali::asymmetric::cipher;
//!
//! const MESSAGE: &'static str = "One more for luck";
//!
//! // Receiver side:
//!
//! let receiver_keypair = cipher::Keypair::generate().unwrap();
//!
//!
//! // ...
//!
//!
//! // Sender side:
//! // We assume we know the receiver's public key, `receiver_pub`.
//! # let receiver_pub = receiver_keypair.public_key.clone();
//!
//! let sender_keypair = cipher::Keypair::generate().unwrap();
//! // In detached mode, the ciphertext length is identical to the plaintext length.
//! let mut ciphertext = vec![0u8; MESSAGE.as_bytes().len()];
//! // Encrypt the ciphertext, returning a MAC.
//! let (_, nonce, mac) = sender_keypair
//!     .encrypt_detached(MESSAGE.as_bytes(), &receiver_pub, None, &mut ciphertext)
//!     .unwrap();
//!
//!
//! // ...
//!
//!
//! // Receiver side:
//! // We assume we now know the sender's public key, `sender_pub`.
//! # let sender_pub = sender_keypair.public_key;
//!
//! let mut plaintext = vec![0u8; ciphertext.len()];
//! // We now need to pass the MAC as a separate argument to the decryption function.
//! receiver_keypair
//!     .decrypt_detached(&ciphertext, &mac, &sender_pub, &nonce, &mut plaintext)
//!     .unwrap();
//! assert_eq!(&plaintext, MESSAGE.as_bytes());
//! ```

crate::error_type! {
    /// Error type returned if something went wrong in the `asymmetric::cipher` module.
    CipherError {
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

/// Generates the API for an `asymmetric::cipher` module with the given functions from Sodium for a
/// specific implementation.
macro_rules! cipher_module {
    (
        $private_key_len:expr,      // crypto_box_SECRETKEYBYTES
        $public_key_len:expr,       // crypto_box_PUBLICKEYBYTES
        $session_key_len:expr,      // crypto_box_BEFORENMBYTES
        $seed_len:expr,             // crypto_box_SEEDBYTES
        $mac_len:expr,              // crypto_box_MACBYTES
        $nonce_len:expr,            // crypto_box_NONCEBYTES
        $msg_max:path,              // crypto_box_messagebytes_max
        $keypair:path,              // crypto_box_keypair
        $seed_keypair:path,         // crypto_box_seed_keypair
        $scalarmult_base:path,      // crypto_scalarmult_base
        $beforenm:path,             // crypto_box_beforenm
        $encrypt:path,              // crypto_box_easy
        $decrypt:path,              // crypto_box_open_easy
        $encrypt_d:path,            // crypto_box_detached
        $decrypt_d:path,            // crypto_box_open_detached
        $encrypt_afternm:path,      // crypto_box_easy_afternm
        $decrypt_afternm:path,      // crypto_box_open_easy_afternm
        $encrypt_d_afternm:path,    // crypto_box_detached_afternm
        $decrypt_d_afternm:path,    // crypto_box_open_detached_afternm
    ) => {
        use $crate::asymmetric::cipher::CipherError;
        use $crate::{assert_not_err, mem, random, require_init, AlkaliError};

        /// The length of a private key for asymmetric AE, in bytes.
        pub const PRIVATE_KEY_LENGTH: usize = $private_key_len as usize;

        /// The length of a public key for asymmetric AE, in bytes.
        pub const PUBLIC_KEY_LENGTH: usize = $public_key_len as usize;

        /// The length of a session key, derived from a key exchange between two parties, in bytes.
        pub const SESSION_KEY_LENGTH: usize = $session_key_len as usize;

        /// The length of a seed to use for the deterministic generation of a [`Keypair`], in bytes.
        pub const KEY_SEED_LENGTH: usize = $seed_len as usize;

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
            /// A private key used in asymmetric AE.
            ///
            /// A private key forms one half of a [`Keypair`], together with a [`PublicKey`].
            ///
            /// There are no technical constraints on the contents of a private key for this API.
            /// Keys are
            /// [clamped](https://neilmadden.blog/2020/05/28/whats-the-curve25519-clamping-all-about/)
            /// at time of usage, not when generated, so a private key can just be any random
            /// sequence of bytes. However, private keys should be indistinguishable from random
            /// noise, and should really be generated randomly using [`Keypair::generate`]. If you
            /// need to derive a private key deterministically, use [`Keypair::from_seed`].
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

            /// A session key derived during the key exchange used in asymmetric AE.
            ///
            /// The encryption/decryption process in this API involves first deriving a session key
            /// via key exchange, and then using this session key to encrypt/decrypt messages. This
            /// type represents such a session key. If many messages are to be exchanged between the
            /// same two parties, the session key can be precalculated and reused, rather than
            /// calculating it again for every single message. Use [`Keypair::session_key`] to
            /// calculate the session key.
            ///
            /// Session keys must be kept secret.
            ///
            /// This is a [hardened buffer type](https://docs.rs/alkali#hardened-buffer-types), and
            /// will be zeroed on drop. A number of other security measures are taken to protect
            /// its contents. This type in particular can be thought of as roughly equivalent to a
            /// `[u8; SESSION_KEY_LENGTH]`, and implements [`core::ops::Deref`], so it can be used
            /// like it is an `&[u8]`. This struct uses heap memory while in scope, allocated using
            /// Sodium's [secure memory utilities](https://doc.libsodium.org/memory_management).
            pub SessionKey(SESSION_KEY_LENGTH);

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

        /// A public key used in asymmetric AE.
        ///
        /// A public key forms one half of a [`Keypair`], together with a [`PrivateKey`].
        ///
        /// A public key should be made public, unlike a private key, which must be kept secret.
        pub type PublicKey = [u8; PUBLIC_KEY_LENGTH];

        /// A MAC (Message Authentication Code), used to authenticate a message.
        ///
        /// If using [`Keypair::encrypt`]/[`SessionKey::encrypt`], the MAC is included in the
        /// ciphertext. It is returned separately in the `detached` variants,
        /// [`Keypair::encrypt_detached`] and [`SessionKey::encrypt_detached`].
        pub type MAC = [u8; MAC_LENGTH];

        /// A nonce, used to introduce non-determinism into the keystream calculation.
        ///
        /// Nonces must never be used for multiple messages with the same key. Ideally, let alkali
        /// generate a random nonce for every message by specifying `None` as the nonce when
        /// encrypting.
        pub type Nonce = [u8; NONCE_LENGTH];

        /// A ([`PrivateKey`], [`PublicKey`]) keypair, used for asymmetric AE.
        ///
        /// The private key must be kept secret, while the public key can be made public.
        pub struct Keypair {
            /// The private key for this keypair.
            pub private_key: PrivateKey,

            /// The public key corresponding to the private key.
            pub public_key: PublicKey,
        }

        impl Keypair {
            /// Generate a new, random X25519 keypair for use in asymmetric AE.
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

            /// Precalculate the session key for communication with a specific party, to speed up
            /// future encryption/decryption operations.
            ///
            /// The encryption/decryption process in this API involves first deriving a session key
            /// via key exchange, and then using this session key to encrypt/decrypt messages. If
            /// many messages are to be exchanged between the same two parties, the session key can
            /// be precalculated and reused, rather than calculating it again for every single
            /// message. This method precalculates this session key.
            ///
            /// The `public_key` argument should be the public key of the party with whom we are to
            /// exchange messages.
            pub fn session_key(&self, public_key: &PublicKey) -> Result<SessionKey, AlkaliError> {
                require_init()?;

                let mut session_key = SessionKey::new_empty()?;

                let kx_result = unsafe {
                    // SAFETY: The first argument to this function is the destination to which the
                    // session key should be written. `crypto_box_BEFORENMBYTES` will be written to
                    // this pointer. The `SessionKey` type allocates this many bytes, so it is valid
                    // for writes of the required length. The `SessionKey::inner_mut` method simply
                    // returns a mutable pointer to its backing memory. The next argument specifies
                    // the public key of the other party to the key exchange. The `PublicKey` type
                    // is defined to be `crypto_box_PUBLICKEYBYTES`, the expected size here, so it
                    // is valid for reads of the required length. The final argument specifies our
                    // private key, expected to be `crypto_box_SECRETKEYBYTES`. We define the
                    // `PrivateKey` type to allocate this number of bytes, so it is also valid for
                    // reads of the required length. The `PrivateKey::inner` method simply returns
                    // an immutable pointer to its backing memory.
                    $beforenm(
                        session_key.inner_mut() as *mut libc::c_uchar,
                        public_key.as_ptr(),
                        self.private_key.inner() as *const libc::c_uchar,
                    )
                };

                if kx_result == 0 {
                    Ok(session_key)
                } else {
                    Err(CipherError::PublicKeyUnacceptable.into())
                }
            }

            /// Encrypt `message` for `receiver`, writing the result to `output`.
            ///
            /// `message` should be the message to encrypt. `receiver` should be the public key of
            /// the party for whom we are encrypting this message.
            ///
            /// `nonce` should be a [nonce](https://en.wikipedia.org/wiki/Cryptographic_nonce) to
            /// use in the encryption process. It is recommended that this be set to `None`, which
            /// will cause alkali to randomly generate a nonce for the message. If you specify a
            /// custom nonce, it is vital the nonce is never used to encrypt more than one message
            /// under the same key: Nonce reuse destroys the security of the scheme. Nonces are not
            /// secret, but will need to be communicated to the decrypting party for them to be able
            /// to decrypt the message. This function will return the nonce used for the encryption
            /// of this message.
            ///
            /// The encrypted ciphertext will be written to `output`. The ciphertext will be
            /// [`MAC_LENGTH`] bytes longer than `message`, so `output` must be of sufficient size
            /// to store at least this many bytes. An error will be returned if `output` is not
            /// sufficient to store the ciphertext.
            ///
            /// If encryption is successful, returns the number of bytes written to `output` (this
            /// will actually always be `message.len()` + [`MAC_LENGTH`] bytes), and the [`Nonce`]
            /// used for the encryption process.
            ///
            /// # Security Considerations
            /// Nonces must *never* be used more than once with the same key. You should specify
            /// `None` for the nonce to use, which will cause a random nonce to be generated for
            /// every message, unless you have good reason to do otherwise.
            pub fn encrypt(
                &self,
                message: &[u8],
                receiver: &PublicKey,
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

                let nonce = match nonce {
                    Some(&n) => n,
                    None => generate_nonce()?,
                };

                let encrypt_result = unsafe {
                    // SAFETY: The first argument to this function is the destination to which the
                    // ciphertext + MAC will be written. The ciphertext will be of the same length
                    // as the message, and the MAC will always be `crypto_box_MACBYTES`, so as long
                    // as the output pointer is valid for writes of `message.len() +
                    // crypto_box_MACBYTES`, it is valid to use here. We verify this condition
                    // above, and return an error if the output is insufficient. The next two
                    // arguments specify the message to encrypt and its length. We use
                    // `message.len()` to specify the message length, so it is definitely valid for
                    // reads of this length. The next argument should be a pointer to the nonce to
                    // use for encryption. We have defined the `Nonce` type to be
                    // `crypto_box_NONCEBYTES`, the size of a nonce for this algorithm, so it is
                    // valid for reads of the required length. The next argument specifies the
                    // public key for whom the message is to be encrypted. We have defined the
                    // `PublicKey` type to be `crypto_box_PUBLICKEYBYTES`, the size of a public key
                    // for this algorithm, so it is valid for reads of the required length. The
                    // final argument to this function should be a pointer to the private key to use
                    // to send the message. The `PrivateKey` type allocates
                    // `crypto_box_SECRETKEYBYTES`, the size of a private key for this algorithm, so
                    // it is valid for reads of the required length. The `PrivateKey::inner` method
                    // simply returns an immutable pointer to its backing memory.
                    $encrypt(
                        output.as_mut_ptr(),
                        message.as_ptr(),
                        message.len() as libc::c_ulonglong,
                        nonce.as_ptr(),
                        receiver.as_ptr(),
                        self.private_key.inner() as *const libc::c_uchar,
                    )
                };

                if encrypt_result == 0 {
                    Ok((c_len, nonce))
                } else {
                    Err(CipherError::PublicKeyUnacceptable.into())
                }
            }

            /// Decrypt `ciphertext`, sent by `sender`, writing the result to `output`.
            ///
            /// `ciphertext` should be the combined ciphertext + MAC to decrypt. `sender` should be
            /// the public key of the party who encrypted this ciphertext. `nonce` should be the
            /// [nonce](https://en.wikipedia.org/wiki/Cryptographic_nonce) which was used in the
            /// encryption process.
            ///
            /// The decrypted plaintext will be written to `output`. The plaintext will be
            /// [`MAC_LENGTH`] bytes shorter than `ciphertext`, so `output` must be of sufficient
            /// size to store at least this many bytes. An error will be returned if `output` is not
            /// sufficient to store the plaintext.
            ///
            /// Decryption will fail if message authentication fails. If decryption is successful,
            /// the plaintext is written to `output`, and the length of the plaintext will be
            /// returned (this will always be `ciphertext.len()` - [`MAC_LENGTH`] bytes).
            pub fn decrypt(
                &self,
                ciphertext: &[u8],
                sender: &PublicKey,
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
                    // plaintext will be written. The plaintext will be `crypto_box_MACBYTES`
                    // shorter than the ciphertext, so as long as the output pointer is valid for
                    // writes of `message.len() - crypto_box_MACBYTES`, it is valid to use here. We
                    // verify this condition above, and return an error if the output is
                    // insufficient. The next two arguments specify the ciphertext to decrypt and
                    // its length. We use `ciphertext.len()` to specify the ciphertext length, so it
                    // is definitely valid for reads of this length. The next argument should be a
                    // pointer to the nonce to use for decryption. We have defined the `Nonce` type
                    // to be `crypto_box_NONCEBYTES`, the size of a nonce for this algorithm, so it
                    // is valid for reads of the required length. The next argument specifies the
                    // public key of the message sender. We have defined the `PublicKey` type to be
                    // `crypto_box_PUBLICKEYBYTES`, the size of a public key for this algorithm, so
                    // it is valid for reads of the required length. The final argument to this
                    // function should be a pointer to the private key to use to decrypt the
                    // message. The `PrivateKey` type allocates `crypto_box_SECRETKEYBYTES`, the
                    // size of a private key for this algorithm, so it is valid for reads of the
                    // required length. The `PrivateKey::inner` method simply returns an immutable
                    // pointer to its backing memory.
                    $decrypt(
                        output.as_mut_ptr(),
                        ciphertext.as_ptr(),
                        ciphertext.len() as libc::c_ulonglong,
                        nonce.as_ptr(),
                        sender.as_ptr(),
                        self.private_key.inner() as *const libc::c_uchar,
                    )
                };

                if decrypt_result == 0 {
                    Ok(m_len)
                } else {
                    Err(CipherError::DecryptionFailed.into())
                }
            }

            /// Encrypt `message` for `receiver`, writing the result to `output`, separately
            /// returning the [`MAC`].
            ///
            /// `message` should be the message to encrypt. `receiver` should be the public key of
            /// the party for whom we are encrypting this message.
            ///
            /// `nonce` should be a [nonce](https://en.wikipedia.org/wiki/Cryptographic_nonce) to
            /// use in the encryption process. It is recommended that this be set to `None`, which
            /// will cause alkali to randomly generate a nonce for the message. If you specify a
            /// custom nonce, it is vital the nonce is never used to encrypt more than one message
            /// under the same key: Nonce reuse destroys the security of the scheme. Nonces are not
            /// secret, but will need to be communicated to the decrypting party for them to be able
            /// to decrypt the message. This function will return the nonce used for the encryption
            /// of this message.
            ///
            /// The encrypted ciphertext will be written to `output`. The ciphertext will be the
            /// same length as `message`, so `output` must be of sufficient size to store at least
            /// this many bytes. An error will be returned if `output` is not sufficient to store
            /// the ciphertext.
            ///
            /// If encryption is successful, returns the number of bytes written to `output` (this
            /// will actually always be `message.len()` bytes), the [`Nonce`] used for the
            /// encryption process, and the authentication tag for the ciphertext (a [`MAC`]).
            ///
            /// # Security Considerations
            /// Nonces must *never* be used more than once with the same key. You should specify
            /// `None` for the nonce to use, which will cause a random nonce to be generated for
            /// every message, unless you have good reason to do otherwise.
            pub fn encrypt_detached(
                &self,
                message: &[u8],
                receiver: &PublicKey,
                nonce: Option<&Nonce>,
                output: &mut [u8],
            ) -> Result<(usize, Nonce, MAC), AlkaliError> {
                require_init()?;

                if output.len() < message.len() {
                    return Err(CipherError::OutputInsufficient.into());
                } else if message.len() > *MESSAGE_LENGTH_MAX {
                    return Err(CipherError::MessageTooLong.into());
                }

                let nonce = match nonce {
                    Some(&n) => n,
                    None => generate_nonce()?,
                };

                let mut mac = [0u8; MAC_LENGTH];

                let encrypt_result = unsafe {
                    // SAFETY: The first argument to this function is the destination to which the
                    // ciphertext will be written. The ciphertext will be of the same length as the
                    // message, so as long as the output pointer is valid for writes of
                    // `message.len()`, it is valid to use here. We verify this condition above, and
                    // return an error if the output is insufficient. The next argument is the
                    // destination to which the MAC will be written. This must be valid for writes
                    // of `crypto_box_MACBYTES`, and we define the `mac` variable to be this length.
                    // The next two arguments specify the message to encrypt and its length. We use
                    // `message.len()` to specify the message length, so it is definitely valid for
                    // reads of this length. The next argument should be a pointer to the nonce to
                    // use for encryption. We have defined the `Nonce` type to be
                    // `crypto_box_NONCEBYTES`, the size of a nonce for this algorithm, so it is
                    // valid for reads of the required length. The next argument specifies the
                    // public key for whom the message is to be encrypted. We have defined the
                    // `PublicKey` type to be `crypto_box_PUBLICKEYBYTES`, the size of a public key
                    // for this algorithm, so it is valid for reads of the required length. The
                    // final argument to this function should be a pointer to the private key to use
                    // to send the message. The `PrivateKey` type allocates
                    // `crypto_box_SECRETKEYBYTES`, the size of a private key for this algorithm, so
                    // it is valid for reads of the required length. The `PrivateKey::inner` method
                    // simply returns an immutable pointer to its backing memory.
                    $encrypt_d(
                        output.as_mut_ptr(),
                        mac.as_mut_ptr(),
                        message.as_ptr(),
                        message.len() as libc::c_ulonglong,
                        nonce.as_ptr(),
                        receiver.as_ptr(),
                        self.private_key.inner() as *const libc::c_uchar,
                    )
                };

                if encrypt_result == 0 {
                    Ok((message.len(), nonce, mac))
                } else {
                    Err(CipherError::PublicKeyUnacceptable.into())
                }
            }

            /// Decrypt `ciphertext`, sent by `sender`, verifying the detached [`MAC`], writing the
            /// result to `output`.
            ///
            /// `ciphertext` should be the ciphertext to decrypt. `mac` should be the [`MAC`]
            /// generated when encrypting the ciphertext in detached mode. `sender` should be the
            /// public key of the party who encrypted this ciphertext. `nonce` should be the
            /// [nonce](https://en.wikipedia.org/wiki/Cryptographic_nonce) which was used in the
            /// encryption process.
            ///
            /// The decrypted plaintext will be written to `output`. The plaintext will be the same
            /// length as `ciphertext`, so `output` must be of sufficient size to store at least
            /// this many bytes. An error will be returned if `output` is not sufficient to store
            /// the plaintext.
            ///
            /// Decryption will fail if message authentication fails. If decryption is successful,
            /// the plaintext is written to `output`, and the length of the plaintext will be
            /// returned (this will always be `ciphertext.len()` bytes).
            pub fn decrypt_detached(
                &self,
                ciphertext: &[u8],
                mac: &MAC,
                sender: &PublicKey,
                nonce: &Nonce,
                output: &mut [u8],
            ) -> Result<usize, AlkaliError> {
                require_init()?;

                if output.len() < ciphertext.len() {
                    return Err(CipherError::OutputInsufficient.into());
                }

                let decrypt_result = unsafe {
                    // SAFETY: The first argument to this function is the destination to which the
                    // plaintext will be written. The plaintext will be the same length as the
                    // ciphertext, so as long as the output pointer is valid for writes of
                    // `message.len()`, it is valid to use here. We verify this condition above, and
                    // return an error if the output is insufficient. The next three arguments
                    // specify the ciphertext to decrypt, the MAC, and the ciphertext length. We use
                    // `ciphertext.len()` to specify the ciphertext length, so it is definitely
                    // valid for reads of this length. The `MAC` type is defined to be
                    // `crypto_box_MACBYTES`, the length of a MAC for this algorithm, so `mac` is
                    // valid for reads of the required length. The next argument should be a pointer
                    // to the nonce to use for decryption. We have defined the `Nonce` type to be
                    // `crypto_box_NONCEBYTES`, the size of a nonce for this algorithm, so it is
                    // valid for reads of the required length. The next argument specifies the
                    // public key of the message sender. We have defined the `PublicKey` type to be
                    // `crypto_box_PUBLICKEYBYTES`, the size of a public key for this algorithm, so
                    // it is valid for reads of the required length. The final argument to this
                    // function should be a pointer to the private key to use to decrypt the
                    // message. The `PrivateKey` type allocates `crypto_box_SECRETKEYBYTES`, the
                    // size of a private key for this algorithm, so it is valid for reads of the
                    // required length. The `PrivateKey::inner` method simply returns an immutable
                    // pointer to its backing memory.
                    $decrypt_d(
                        output.as_mut_ptr(),
                        ciphertext.as_ptr(),
                        mac.as_ptr(),
                        ciphertext.len() as libc::c_ulonglong,
                        nonce.as_ptr(),
                        sender.as_ptr(),
                        self.private_key.inner() as *const libc::c_uchar,
                    )
                };

                if decrypt_result == 0 {
                    Ok(ciphertext.len())
                } else {
                    Err(CipherError::DecryptionFailed.into())
                }
            }
        }

        impl SessionKey {
            /// Encrypt `message` using this session key, writing the result to `output`.
            ///
            /// `message` should be the message to encrypt.
            ///
            /// `nonce` should be a [nonce](https://en.wikipedia.org/wiki/Cryptographic_nonce) to
            /// use in the encryption process. It is recommended that this be set to `None`, which
            /// will cause alkali to randomly generate a nonce for the message. If you specify a
            /// custom nonce, it is vital the nonce is never used to encrypt more than one message
            /// under the same key: Nonce reuse destroys the security of the scheme. Nonces are not
            /// secret, but will need to be communicated to the decrypting party for them to be able
            /// to decrypt the message. This function will return the nonce used for the encryption
            /// of this message.
            ///
            /// The encrypted ciphertext will be written to `output`. The ciphertext will be
            /// [`MAC_LENGTH`] bytes longer than `message`, so `output` must be of sufficient size
            /// to store at least this many bytes. An error will be returned if `output` is not
            /// sufficient to store the ciphertext.
            ///
            /// If encryption is successful, returns the number of bytes written to `output` (this
            /// will actually always be `message.len()` + [`MAC_LENGTH`] bytes), and the [`Nonce`]
            /// used for the encryption process.
            ///
            /// # Security Considerations
            /// Nonces must *never* be used more than once with the same key. You should specify
            /// `None` for the nonce to use, which will cause a random nonce to be generated for
            /// every message, unless you have good reason to do otherwise.
            pub fn encrypt(
                &self,
                message: &[u8],
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

                let nonce = match nonce {
                    Some(&n) => n,
                    None => generate_nonce()?,
                };

                let encrypt_result = unsafe {
                    // SAFETY: The first argument to this function is the destination to which the
                    // ciphertext + MAC will be written. The ciphertext will be of the same length
                    // as the message, and the MAC will always be `crypto_box_MACBYTES`, so as long
                    // as the output pointer is valid for writes of `message.len() +
                    // crypto_box_MACBYTES`, it is valid to use here. We verify this condition
                    // above, and return an error if the output is insufficient. The next two
                    // arguments specify the message to encrypt and its length. We use
                    // `message.len()` to specify the message length, so it is definitely valid for
                    // reads of this length. The next argument should be a pointer to the nonce to
                    // use for encryption. We have defined the `Nonce` type to be
                    // `crypto_box_NONCEBYTES`, the size of a nonce for this algorithm, so it is
                    // valid for reads of the required length. The final argument to this function
                    // specifies the session key with which the message should be encrypted. We have
                    // defined the `SessionKey` type to allocate `crypto_box_BEFORENMBYTES`, the
                    // expected size of a session key for this algorithm, so it is valid for reads
                    // of the required length. The `SessionKey::inner` method simply returns an
                    // immutable pointer to its backing memory.
                    $encrypt_afternm(
                        output.as_mut_ptr(),
                        message.as_ptr(),
                        message.len() as libc::c_ulonglong,
                        nonce.as_ptr(),
                        self.inner() as *const libc::c_uchar,
                    )
                };

                if encrypt_result == 0 {
                    Ok((c_len, nonce))
                } else {
                    Err(CipherError::PublicKeyUnacceptable.into())
                }
            }

            /// Decrypt `ciphertext` using this session key, writing the result to `output`.
            ///
            /// `ciphertext` should be the combined ciphertext + MAC to decrypt. `nonce` should be
            /// the [nonce](https://en.wikipedia.org/wiki/Cryptographic_nonce) which was used in the
            /// encryption process.
            ///
            /// The decrypted plaintext will be written to `output`. The plaintext will be
            /// [`MAC_LENGTH`] bytes shorter than `ciphertext`, so `output` must be of sufficient
            /// size to store at least this many bytes. An error will be returned if `output` is not
            /// sufficient to store the plaintext.
            ///
            /// Decryption will fail if message authentication fails. If decryption is successful,
            /// the plaintext is written to `output`, and the length of the plaintext will be
            /// returned (this will always be `ciphertext.len()` - [`MAC_LENGTH`] bytes).
            pub fn decrypt(
                &self,
                ciphertext: &[u8],
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
                    // plaintext will be written. The plaintext will be `crypto_box_MACBYTES`
                    // shorter than the ciphertext, so as long as the output pointer is valid for
                    // writes of `message.len() - crypto_box_MACBYTES`, it is valid to use here. We
                    // verify this condition above, and return an error if the output is
                    // insufficient. The next two arguments specify the ciphertext to decrypt and
                    // its length. We use `ciphertext.len()` to specify the ciphertext length, so it
                    // is definitely valid for reads of this length. The next argument should be a
                    // pointer to the nonce to use for decryption. We have defined the `Nonce` type
                    // to be `crypto_box_NONCEBYTES`, the size of a nonce for this algorithm, so it
                    // is valid for reads of the required length. The final argument to this
                    // function specifies the session key with which the message should be
                    // decrypted. We have defined the `SessionKey` type to allocate
                    // `crypto_box_BEFORENMBYTES`, the expected size of a session key for this
                    // algorithm, so it is valid for reads of the required length. The
                    // `SessionKey::inner` method simply returns an immutable pointer to its backing
                    // memory.
                    $decrypt_afternm(
                        output.as_mut_ptr(),
                        ciphertext.as_ptr(),
                        ciphertext.len() as libc::c_ulonglong,
                        nonce.as_ptr(),
                        self.inner() as *const libc::c_uchar,
                    )
                };

                if decrypt_result == 0 {
                    Ok(m_len)
                } else {
                    Err(CipherError::DecryptionFailed.into())
                }
            }

            /// Encrypt `message` using this session key, writing the result to `output`, separately
            /// returning the [`MAC`].
            ///
            /// `message` should be the message to encrypt.
            ///
            /// `nonce` should be a [nonce](https://en.wikipedia.org/wiki/Cryptographic_nonce) to
            /// use in the encryption process. It is recommended that this be set to `None`, which
            /// will cause alkali to randomly generate a nonce for the message. If you specify a
            /// custom nonce, it is vital the nonce is never used to encrypt more than one message
            /// under the same key: Nonce reuse destroys the security of the scheme. Nonces are not
            /// secret, but will need to be communicated to the decrypting party for them to be able
            /// to decrypt the message. This function will return the nonce used for the encryption
            /// of this message.
            ///
            /// The encrypted ciphertext will be written to `output`. The ciphertext will be the
            /// same length as `message`, so `output` must be of sufficient size to store at least
            /// this many bytes. An error will be returned if `output` is not sufficient to store
            /// the ciphertext.
            ///
            /// If encryption is successful, returns the number of bytes written to `output` (this
            /// will actually always be `message.len()` bytes), the [`Nonce`] used for the
            /// encryption process, and the authentication tag for the ciphertext (a [`MAC`]).
            ///
            /// # Security Considerations
            /// Nonces must *never* be used more than once with the same key. You should specify
            /// `None` for the nonce to use, which will cause a random nonce to be generated for
            /// every message, unless you have good reason to do otherwise.
            pub fn encrypt_detached(
                &self,
                message: &[u8],
                nonce: Option<&Nonce>,
                output: &mut [u8],
            ) -> Result<(usize, Nonce, MAC), AlkaliError> {
                require_init()?;

                if output.len() < message.len() {
                    return Err(CipherError::OutputInsufficient.into());
                } else if message.len() > *MESSAGE_LENGTH_MAX {
                    return Err(CipherError::MessageTooLong.into());
                }

                let nonce = match nonce {
                    Some(&n) => n,
                    None => generate_nonce()?,
                };

                let mut mac = [0u8; MAC_LENGTH];

                let encrypt_result = unsafe {
                    // SAFETY: The first argument to this function is the destination to which the
                    // ciphertext will be written. The ciphertext will be of the same length as the
                    // message, so as long as the output pointer is valid for writes of
                    // `message.len()`, it is valid to use here. We verify this condition above, and
                    // return an error if the output is insufficient. The next argument is the
                    // destination to which the MAC will be written. This must be valid for writes
                    // of `crypto_box_MACBYTES`, and we define the `mac` variable to be this length.
                    // The next two arguments specify the message to encrypt and its length. We use
                    // `message.len()` to specify the message length, so it is definitely valid for
                    // reads of this length. The next argument should be a pointer to the nonce to
                    // use for encryption. We have defined the `Nonce` type to be
                    // `crypto_box_NONCEBYTES`, the size of a nonce for this algorithm, so it is
                    // valid for reads of the required length. The final argument to this function
                    // specifies the session key with which the message should be encrypted. We have
                    // defined the `SessionKey` type to allocate `crypto_box_BEFORENMBYTES`, the
                    // expected size of a session key for this algorithm, so it is valid for reads
                    // of the required length. The `SessionKey::inner` method simply returns an
                    // immutable pointer to its backing memory.
                    $encrypt_d_afternm(
                        output.as_mut_ptr(),
                        mac.as_mut_ptr(),
                        message.as_ptr(),
                        message.len() as libc::c_ulonglong,
                        nonce.as_ptr(),
                        self.inner() as *const libc::c_uchar,
                    )
                };

                if encrypt_result == 0 {
                    Ok((message.len(), nonce, mac))
                } else {
                    Err(CipherError::PublicKeyUnacceptable.into())
                }
            }

            /// Decrypt `ciphertext` using this session key, verifying the detached [`MAC`], writing
            /// the result to `output`.
            ///
            /// `ciphertext` should be the ciphertext to decrypt. `mac` should be the [`MAC`]
            /// generated when encrypting the ciphertext in detached mode. `nonce` should be the
            /// [nonce](https://en.wikipedia.org/wiki/Cryptographic_nonce) which was used in the
            /// encryption process.
            ///
            /// The decrypted plaintext will be written to `output`. The plaintext will be the same
            /// length as `ciphertext`, so `output` must be of sufficient size to store at least
            /// this many bytes. An error will be returned if `output` is not sufficient to store
            /// the plaintext.
            ///
            /// Decryption will fail if message authentication fails. If decryption is successful,
            /// the plaintext is written to `output`, and the length of the plaintext will be
            /// returned (this will always be `ciphertext.len()` bytes).
            pub fn decrypt_detached(
                &self,
                ciphertext: &[u8],
                mac: &MAC,
                nonce: &Nonce,
                output: &mut [u8],
            ) -> Result<usize, AlkaliError> {
                require_init()?;

                if output.len() < ciphertext.len() {
                    return Err(CipherError::OutputInsufficient.into());
                }

                let decrypt_result = unsafe {
                    // SAFETY: The first argument to this function is the destination to which the
                    // plaintext will be written. The plaintext will be the same length as the
                    // ciphertext, so as long as the output pointer is valid for writes of
                    // `message.len()`, it is valid to use here. We verify this condition above, and
                    // return an error if the output is insufficient. The next three arguments
                    // specify the ciphertext to decrypt, the MAC, and the ciphertext length. We use
                    // `ciphertext.len()` to specify the ciphertext length, so it is definitely
                    // valid for reads of this length. The `MAC` type is defined to be
                    // `crypto_box_MACBYTES`, the length of a MAC for this algorithm, so `mac` is
                    // valid for reads of the required length. The next argument should be a pointer
                    // to the nonce to use for decryption. We have defined the `Nonce` type to be
                    // `crypto_box_NONCEBYTES`, the size of a nonce for this algorithm, so it is
                    // valid for reads of the required length. The final argument to this function
                    // specifies the session key with which the message should be decrypted. We have
                    // defined the `SessionKey` type to allocate `crypto_box_BEFORENMBYTES`, the
                    // expected size of a session key for this algorithm, so it is valid for reads
                    // of the required length. The `SessionKey::inner` method simply returns an
                    // immutable pointer to its backing memory.
                    $decrypt_d_afternm(
                        output.as_mut_ptr(),
                        ciphertext.as_ptr(),
                        mac.as_ptr(),
                        ciphertext.len() as libc::c_ulonglong,
                        nonce.as_ptr(),
                        self.inner() as *const libc::c_uchar,
                    )
                };

                if decrypt_result == 0 {
                    Ok(ciphertext.len())
                } else {
                    Err(CipherError::DecryptionFailed.into())
                }
            }
        }

        /// Generate a random nonce for use in this module.
        ///
        /// It is vital that a given nonce is never used to encrypt more than one message under the
        /// same key. The cipher used here has a sufficient nonce size that we can simply generate a
        /// random nonce for every message we wish to encrypt, and the chances of reusing a nonce
        /// are essentially zero.
        ///
        /// Returns a random nonce, or a [`crate::AlkaliError`] if an error occurred.
        pub fn generate_nonce() -> Result<Nonce, AlkaliError> {
            let mut nonce = [0; NONCE_LENGTH];
            random::fill_random(&mut nonce)?;
            Ok(nonce)
        }
    };
}

#[allow(unused_macros)]
macro_rules! cipher_tests {
    ( $( {
        msg: $msg:expr,
        priv_a: $priv_a:expr,
        priv_b: $priv_b:expr,
        nonce: $nonce:expr,
        c: $c:expr,
        mac: $mac:expr,
    }, )* ) => {
        use super::{
            generate_nonce, Keypair, PrivateKey, Seed, MAC_LENGTH,
        };
        use $crate::AlkaliError;
        use $crate::random::fill_random;

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
        fn nonce_generation() -> Result<(), AlkaliError> {
            let _nonce = generate_nonce()?;
            Ok(())
        }

        #[test]
        fn enc_and_dec() -> Result<(), AlkaliError> {
            let x = Keypair::generate()?;
            let y = Keypair::generate()?;

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

            let (mut l_a, nonce_a) = x.encrypt(&msg_a, &y.public_key, None, &mut c_a)?;
            let (mut l_b, nonce_b) = x.encrypt(&msg_b, &y.public_key, None, &mut c_b)?;
            let (mut l_c, nonce_c) = x.encrypt(&msg_c, &y.public_key, None, &mut c_c)?;
            let (mut l_d, nonce_d) = x.encrypt(&msg_d, &y.public_key, None, &mut c_d)?;

            assert_eq!(l_a, MAC_LENGTH);
            assert_eq!(l_b, 16 + MAC_LENGTH);
            assert_eq!(l_c, 1024 + MAC_LENGTH);
            assert_eq!(l_d, (1 << 18) + MAC_LENGTH);

            l_a = y.decrypt(&c_a, &x.public_key, &nonce_a, &mut msg_a)?;
            l_b = y.decrypt(&c_b, &x.public_key, &nonce_b, &mut msg_b)?;
            l_c = y.decrypt(&c_c, &x.public_key, &nonce_c, &mut msg_c)?;
            l_d = y.decrypt(&c_d, &x.public_key, &nonce_d, &mut msg_d)?;

            assert_eq!(l_a, 0);
            assert_eq!(l_b, 16);
            assert_eq!(l_c, 1024);
            assert_eq!(l_d, 1 << 18);

            fill_random(&mut c_a)?;
            fill_random(&mut c_b)?;
            fill_random(&mut c_c)?;
            fill_random(&mut c_d)?;

            assert!(y.decrypt(&c_a, &x.public_key, &nonce_a, &mut msg_a).is_err());
            assert!(y.decrypt(&c_b, &x.public_key, &nonce_b, &mut msg_b).is_err());
            assert!(y.decrypt(&c_c, &x.public_key, &nonce_c, &mut msg_c).is_err());
            assert!(y.decrypt(&c_d, &x.public_key, &nonce_d, &mut msg_d).is_err());

            Ok(())
        }

        #[test]
        fn enc_and_dec_detached() -> Result<(), AlkaliError> {
            let x = Keypair::generate()?;
            let y = Keypair::generate()?;

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
            let mut c_d = [0; 1 << 18];

            let (mut l_a, nonce_a, mut mac_a) =
                x.encrypt_detached(&msg_a, &y.public_key, None, &mut c_a)?;
            let (mut l_b, nonce_b, mac_b) =
                x.encrypt_detached(&msg_b, &y.public_key, None, &mut c_b)?;
            let (mut l_c, nonce_c, mac_c) =
                x.encrypt_detached(&msg_c, &y.public_key, None, &mut c_c)?;
            let (mut l_d, nonce_d, mac_d) =
                x.encrypt_detached(&msg_d, &y.public_key, None, &mut c_d)?;

            assert_eq!(l_a, 0);
            assert_eq!(l_b, 16);
            assert_eq!(l_c, 1024);
            assert_eq!(l_d, 1 << 18);

            l_a = y.decrypt_detached(&c_a, &mac_a, &x.public_key, &nonce_a, &mut msg_a)?;
            l_b = y.decrypt_detached(&c_b, &mac_b, &x.public_key, &nonce_b, &mut msg_b)?;
            l_c = y.decrypt_detached(&c_c, &mac_c, &x.public_key, &nonce_c, &mut msg_c)?;
            l_d = y.decrypt_detached(&c_d, &mac_d, &x.public_key, &nonce_d, &mut msg_d)?;

            assert_eq!(l_a, 0);
            assert_eq!(l_b, 16);
            assert_eq!(l_c, 1024);
            assert_eq!(l_d, 1 << 18);

            fill_random(&mut mac_a)?;
            fill_random(&mut c_b)?;
            fill_random(&mut c_c)?;
            fill_random(&mut c_d)?;

            assert!(y.decrypt_detached(&c_a, &mac_a, &x.public_key, &nonce_a, &mut msg_a).is_err());
            assert!(y.decrypt_detached(&c_b, &mac_b, &x.public_key, &nonce_b, &mut msg_b).is_err());
            assert!(y.decrypt_detached(&c_c, &mac_c, &x.public_key, &nonce_c, &mut msg_c).is_err());
            assert!(y.decrypt_detached(&c_d, &mac_d, &x.public_key, &nonce_d, &mut msg_d).is_err());

            Ok(())
        }

        #[test]
        fn enc_and_dec_precalculated() -> Result<(), AlkaliError> {
            let x = Keypair::generate()?;
            let y = Keypair::generate()?;
            let key = x.session_key(&y.public_key)?;
            assert_eq!(&key[..], &y.session_key(&x.public_key)?[..]);

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

            let (mut l_a, nonce_a) = key.encrypt(&msg_a, None, &mut c_a)?;
            let (mut l_b, nonce_b) = key.encrypt(&msg_b, None, &mut c_b)?;
            let (mut l_c, nonce_c) = key.encrypt(&msg_c, None, &mut c_c)?;
            let (mut l_d, nonce_d) = key.encrypt(&msg_d, None, &mut c_d)?;

            assert_eq!(l_a, MAC_LENGTH);
            assert_eq!(l_b, 16 + MAC_LENGTH);
            assert_eq!(l_c, 1024 + MAC_LENGTH);
            assert_eq!(l_d, (1 << 18) + MAC_LENGTH);

            l_a = key.decrypt(&c_a, &nonce_a, &mut msg_a)?;
            l_b = key.decrypt(&c_b, &nonce_b, &mut msg_b)?;
            l_c = key.decrypt(&c_c, &nonce_c, &mut msg_c)?;
            l_d = key.decrypt(&c_d, &nonce_d, &mut msg_d)?;

            assert_eq!(l_a, 0);
            assert_eq!(l_b, 16);
            assert_eq!(l_c, 1024);
            assert_eq!(l_d, 1 << 18);

            fill_random(&mut c_a)?;
            fill_random(&mut c_b)?;
            fill_random(&mut c_c)?;
            fill_random(&mut c_d)?;

            assert!(key.decrypt(&c_a, &nonce_a, &mut msg_a).is_err());
            assert!(key.decrypt(&c_b, &nonce_b, &mut msg_b).is_err());
            assert!(key.decrypt(&c_c, &nonce_c, &mut msg_c).is_err());
            assert!(key.decrypt(&c_d, &nonce_d, &mut msg_d).is_err());

            Ok(())
        }

        #[test]
        fn enc_and_dec_detached_precalculated() -> Result<(), AlkaliError> {
            let x = Keypair::generate()?;
            let y = Keypair::generate()?;
            let key = x.session_key(&y.public_key)?;
            assert_eq!(&key[..], &y.session_key(&x.public_key)?[..]);

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
            let mut c_d = [0; 1 << 18];

            let (mut l_a, nonce_a, mut mac_a) = key.encrypt_detached(&msg_a, None, &mut c_a)?;
            let (mut l_b, nonce_b, mac_b) = key.encrypt_detached(&msg_b, None, &mut c_b)?;
            let (mut l_c, nonce_c, mac_c) = key.encrypt_detached(&msg_c, None, &mut c_c)?;
            let (mut l_d, nonce_d, mac_d) = key.encrypt_detached(&msg_d, None, &mut c_d)?;

            assert_eq!(l_a, 0);
            assert_eq!(l_b, 16);
            assert_eq!(l_c, 1024);
            assert_eq!(l_d, 1 << 18);

            l_a = key.decrypt_detached(&c_a, &mac_a, &nonce_a, &mut msg_a)?;
            l_b = key.decrypt_detached(&c_b, &mac_b, &nonce_b, &mut msg_b)?;
            l_c = key.decrypt_detached(&c_c, &mac_c, &nonce_c, &mut msg_c)?;
            l_d = key.decrypt_detached(&c_d, &mac_d, &nonce_d, &mut msg_d)?;

            assert_eq!(l_a, 0);
            assert_eq!(l_b, 16);
            assert_eq!(l_c, 1024);
            assert_eq!(l_d, 1 << 18);

            fill_random(&mut mac_a)?;
            fill_random(&mut c_b)?;
            fill_random(&mut c_c)?;
            fill_random(&mut c_d)?;

            assert!(key.decrypt_detached(&c_a, &mac_a, &nonce_a, &mut msg_a).is_err());
            assert!(key.decrypt_detached(&c_b, &mac_b, &nonce_b, &mut msg_b).is_err());
            assert!(key.decrypt_detached(&c_c, &mac_c, &nonce_c, &mut msg_c).is_err());
            assert!(key.decrypt_detached(&c_d, &mac_d, &nonce_d, &mut msg_d).is_err());

            Ok(())
        }

        #[test]
        fn test_vectors() -> Result<(), AlkaliError> {
            let mut priv_a = PrivateKey::new_empty()?;
            let mut priv_b = PrivateKey::new_empty()?;
            let mut c = [0; 1024];
            let mut m = [0; 1024];

            $(
                priv_a.copy_from_slice(&$priv_a);
                priv_b.copy_from_slice(&$priv_b);
                let a = Keypair::from_private_key(&priv_a)?;
                let b = Keypair::from_private_key(&priv_b)?;

                let c_len = $msg.len() + MAC_LENGTH;
                let (l, _) = a.encrypt(&$msg, &b.public_key, Some(&$nonce), &mut c)?;
                assert_eq!(l, c_len);
                assert_eq!(&c[..MAC_LENGTH], &$mac[..]);
                assert_eq!(&c[MAC_LENGTH..c_len], &$c[..]);

                assert_eq!(b.decrypt(&c[..c_len], &a.public_key, &$nonce, &mut m)?, $msg.len());
                assert_eq!(&m[..$msg.len()], &$msg);
            )*

            Ok(())
        }

        #[test]
        fn test_vectors_detached() -> Result<(), AlkaliError> {
            let mut priv_a = PrivateKey::new_empty()?;
            let mut priv_b = PrivateKey::new_empty()?;
            let mut c = [0; 1024];
            let mut m = [0; 1024];

            $(
                priv_a.copy_from_slice(&$priv_a);
                priv_b.copy_from_slice(&$priv_b);
                let a = Keypair::from_private_key(&priv_a)?;
                let b = Keypair::from_private_key(&priv_b)?;

                let (l, _, mac) = a.encrypt_detached(&$msg, &b.public_key, Some(&$nonce), &mut c)?;
                assert_eq!(l, $msg.len());
                assert_eq!(&c[..$msg.len()], &$c[..$msg.len()]);
                assert_eq!(&mac, &$mac);

                assert_eq!(
                    b.decrypt_detached(&c[..$msg.len()], &mac, &a.public_key, &$nonce, &mut m)?,
                    $msg.len()
                );
                assert_eq!(&m[..$msg.len()], &$msg);
            )*

            Ok(())
        }

        #[test]
        fn test_vectors_precalculated() -> Result<(), AlkaliError> {
            let mut priv_a = PrivateKey::new_empty()?;
            let mut priv_b = PrivateKey::new_empty()?;
            let mut c = [0; 1024];
            let mut m = [0; 1024];

            $(
                priv_a.copy_from_slice(&$priv_a);
                priv_b.copy_from_slice(&$priv_b);
                let a = Keypair::from_private_key(&priv_a)?;
                let b = Keypair::from_private_key(&priv_b)?;

                let key = a.session_key(&b.public_key)?;
                let c_len = $msg.len() + MAC_LENGTH;
                let (l, _) = key.encrypt(&$msg, Some(&$nonce), &mut c)?;
                assert_eq!(l, c_len);
                assert_eq!(&c[..MAC_LENGTH], &$mac);
                assert_eq!(&c[MAC_LENGTH..c_len], &$c);

                let key = b.session_key(&a.public_key)?;
                assert_eq!(key.decrypt(&c[..c_len], &$nonce, &mut m)?, $msg.len());
                assert_eq!(&m[..$msg.len()], &$msg);
            )*

            Ok(())
        }

        #[test]
        fn test_vectors_detached_precalculated() -> Result<(), AlkaliError> {
            let mut priv_a = PrivateKey::new_empty()?;
            let mut priv_b = PrivateKey::new_empty()?;
            let mut c = [0; 1024];
            let mut m = [0; 1024];

            $(
                priv_a.copy_from_slice(&$priv_a);
                priv_b.copy_from_slice(&$priv_b);
                let a = Keypair::from_private_key(&priv_a)?;
                let b = Keypair::from_private_key(&priv_b)?;

                let key = a.session_key(&b.public_key)?;
                let (l, _, mac) = key.encrypt_detached(&$msg, Some(&$nonce), &mut c)?;
                assert_eq!(l, $msg.len());
                assert_eq!(&c[..$msg.len()], &$c);
                assert_eq!(&mac, &$mac);

                let key = b.session_key(&a.public_key)?;
                assert_eq!(
                    key.decrypt_detached(&c[..$msg.len()], &mac, &$nonce, &mut m)?, $msg.len()
                );
                assert_eq!(&m[..$msg.len()], &$msg[..]);
            )*

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

    cipher_module! {
        sodium::crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES,
        sodium::crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES,
        sodium::crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES,
        sodium::crypto_box_curve25519xsalsa20poly1305_SEEDBYTES,
        sodium::crypto_box_curve25519xsalsa20poly1305_MACBYTES,
        sodium::crypto_box_curve25519xsalsa20poly1305_NONCEBYTES,
        sodium::crypto_box_curve25519xsalsa20poly1305_messagebytes_max,
        sodium::crypto_box_curve25519xsalsa20poly1305_keypair,
        sodium::crypto_box_curve25519xsalsa20poly1305_seed_keypair,
        sodium::crypto_scalarmult_curve25519_base,
        sodium::crypto_box_curve25519xsalsa20poly1305_beforenm,
        sodium::crypto_box_easy,
        sodium::crypto_box_open_easy,
        sodium::crypto_box_detached,
        sodium::crypto_box_open_detached,
        sodium::crypto_box_easy_afternm,
        sodium::crypto_box_open_easy_afternm,
        sodium::crypto_box_detached_afternm,
        sodium::crypto_box_open_detached_afternm,
    }

    #[cfg(test)]
    mod tests {
        cipher_tests![
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
                priv_a: [0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72,
                         0x51, 0xb2, 0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
                         0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a],
                priv_b: [0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b, 0x79, 0xe1, 0x7f, 0x8b,
                         0x83, 0x80, 0x0e, 0xe6, 0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd,
                         0x1c, 0x2f, 0x8b, 0x27, 0xff, 0x88, 0xe0, 0xeb],
                nonce:  [0x69, 0x69, 0x6e, 0xe9, 0x55, 0xb6, 0x2b, 0x73, 0xcd, 0x62, 0xbd, 0xa8,
                         0x75, 0xfc, 0x73, 0xd6, 0x82, 0x19, 0xe0, 0x03, 0x6b, 0x7a, 0x0b, 0x37],
                c:      [0x8e, 0x99, 0x3b, 0x9f, 0x48, 0x68, 0x12, 0x73, 0xc2, 0x96, 0x50, 0xba,
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
                mac:    [0xf3, 0xff, 0xc7, 0x70, 0x3f, 0x94, 0x00, 0xe5, 0x2a, 0x7d, 0xfb, 0x4b,
                         0x3d, 0x33, 0x05, 0xd9],
            },
            {
                msg:    [] as [u8; 0],
                priv_a: [0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72,
                         0x51, 0xb2, 0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
                         0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a],
                priv_b: [0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b, 0x79, 0xe1, 0x7f, 0x8b,
                         0x83, 0x80, 0x0e, 0xe6, 0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd,
                         0x1c, 0x2f, 0x8b, 0x27, 0xff, 0x88, 0xe0, 0xeb],
                nonce:  [0x69, 0x69, 0x6e, 0xe9, 0x55, 0xb6, 0x2b, 0x73, 0xcd, 0x62, 0xbd, 0xa8,
                         0x75, 0xfc, 0x73, 0xd6, 0x82, 0x19, 0xe0, 0x03, 0x6b, 0x7a, 0x0b, 0x37],
                c:      [],
                mac:    [0x25, 0x39, 0x12, 0x1d, 0x8e, 0x23, 0x4e, 0x65, 0x2d, 0x65, 0x1f, 0xa4,
                         0xc8, 0xcf, 0xf8, 0x80],
            },
        ];

        #[test]
        fn precalculation_vectors() -> Result<(), AlkaliError> {
            let seed_a = Seed::try_from(&[
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
                0x1c, 0x1d, 0x1e, 0x1f,
            ])?;
            let seed_b = Seed::try_from(&[
                0x01, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
                0x1c, 0x1d, 0x1e, 0x1f,
            ])?;

            let keypair_a = Keypair::from_seed(&seed_a)?;
            let keypair_b = Keypair::from_seed(&seed_b)?;

            let key_a = keypair_a.session_key(&keypair_b.public_key)?;
            let key_b = keypair_b.session_key(&keypair_a.public_key)?;

            assert_eq!(key_a, key_b);
            assert_eq!(
                &key_a[..],
                &[
                    0xf7, 0xa0, 0x63, 0xc0, 0x5a, 0x44, 0xdf, 0xfc, 0xea, 0xa1, 0x95, 0xc4, 0xea,
                    0xd0, 0xa1, 0xac, 0xdb, 0x15, 0x4d, 0x9e, 0x0a, 0xc9, 0x2a, 0xe0, 0x64, 0xe9,
                    0x7e, 0xed, 0x36, 0x52, 0x30, 0x35
                ]
            );

            Ok(())
        }
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

    cipher_module! {
        sodium::crypto_box_curve25519xchacha20poly1305_SECRETKEYBYTES,
        sodium::crypto_box_curve25519xchacha20poly1305_PUBLICKEYBYTES,
        sodium::crypto_box_curve25519xchacha20poly1305_BEFORENMBYTES,
        sodium::crypto_box_curve25519xchacha20poly1305_SEEDBYTES,
        sodium::crypto_box_curve25519xchacha20poly1305_MACBYTES,
        sodium::crypto_box_curve25519xchacha20poly1305_NONCEBYTES,
        sodium::crypto_box_curve25519xchacha20poly1305_messagebytes_max,
        sodium::crypto_box_curve25519xchacha20poly1305_keypair,
        sodium::crypto_box_curve25519xchacha20poly1305_seed_keypair,
        sodium::crypto_scalarmult_curve25519_base,
        sodium::crypto_box_curve25519xchacha20poly1305_beforenm,
        sodium::crypto_box_curve25519xchacha20poly1305_easy,
        sodium::crypto_box_curve25519xchacha20poly1305_open_easy,
        sodium::crypto_box_curve25519xchacha20poly1305_detached,
        sodium::crypto_box_curve25519xchacha20poly1305_open_detached,
        sodium::crypto_box_curve25519xchacha20poly1305_easy_afternm,
        sodium::crypto_box_curve25519xchacha20poly1305_open_easy_afternm,
        sodium::crypto_box_curve25519xchacha20poly1305_detached_afternm,
        sodium::crypto_box_curve25519xchacha20poly1305_open_detached_afternm,
    }

    #[cfg(test)]
    mod tests {
        cipher_tests! [
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
                priv_a: [0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72,
                         0x51, 0xb2, 0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
                         0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a],
                priv_b: [0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b, 0x79, 0xe1, 0x7f, 0x8b,
                         0x83, 0x80, 0x0e, 0xe6, 0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd,
                         0x1c, 0x2f, 0x8b, 0x27, 0xff, 0x88, 0xe0, 0xeb],
                nonce:  [0x69, 0x69, 0x6e, 0xe9, 0x55, 0xb6, 0x2b, 0x73, 0xcd, 0x62, 0xbd, 0xa8,
                         0x75, 0xfc, 0x73, 0xd6, 0x82, 0x19, 0xe0, 0x03, 0x6b, 0x7a, 0x0b, 0x37],
                c:      [0xef, 0x2c, 0x60, 0x61, 0xb7, 0xbc, 0xec, 0x0c, 0xfd, 0x72, 0x30, 0x55,
                         0xf6, 0x1f, 0x1c, 0xcc, 0xa2, 0x94, 0x6d, 0x5a, 0x04, 0xdb, 0xf8, 0x31,
                         0x51, 0xf4, 0x89, 0x42, 0x23, 0xac, 0x9b, 0xc7, 0x90, 0xc6, 0x60, 0xe1,
                         0x9d, 0xc6, 0x4c, 0xc0, 0xd7, 0xf9, 0xc7, 0x68, 0x9a, 0xd1, 0x90, 0x99,
                         0x55, 0xe7, 0xa9, 0xa7, 0xbd, 0xac, 0x77, 0x7d, 0x6a, 0x79, 0x67, 0xd0,
                         0x00, 0xce, 0x84, 0x1f, 0xc0, 0xf8, 0xf3, 0x1d, 0x6d, 0x87, 0x20, 0xb3,
                         0x74, 0xbc, 0x28, 0x98, 0x27, 0x64, 0xa7, 0xdb, 0xeb, 0x4d, 0xaa, 0x97,
                         0x7a, 0xae, 0x1b, 0x73, 0x50, 0xfa, 0xc7, 0x9a, 0x17, 0x7e, 0xce, 0x75,
                         0x41, 0xfe, 0xd2, 0x64, 0x46, 0x1e, 0xa9, 0x3e, 0x6d, 0x7a, 0xd9, 0xfc,
                         0x08, 0xc9, 0x1e, 0x77, 0x4a, 0xbe, 0x79, 0x03, 0x6e, 0x7f, 0x79, 0xdd,
                         0xcc, 0x6a, 0xab, 0x3a, 0xbf, 0x52, 0x76, 0x31, 0x04, 0x8c, 0xe1],
                mac:    [0x0b, 0x4f, 0xf0, 0x07, 0x42, 0xf3, 0xc1, 0xaa, 0x99, 0xa6, 0x32, 0x1e,
                         0x38, 0x83, 0xb0, 0x3c],
            },
            {
                msg:    [] as [u8; 0],
                priv_a: [0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72,
                         0x51, 0xb2, 0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
                         0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a],
                priv_b: [0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b, 0x79, 0xe1, 0x7f, 0x8b,
                         0x83, 0x80, 0x0e, 0xe6, 0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd,
                         0x1c, 0x2f, 0x8b, 0x27, 0xff, 0x88, 0xe0, 0xeb],
                nonce:  [0x69, 0x69, 0x6e, 0xe9, 0x55, 0xb6, 0x2b, 0x73, 0xcd, 0x62, 0xbd, 0xa8,
                         0x75, 0xfc, 0x73, 0xd6, 0x82, 0x19, 0xe0, 0x03, 0x6b, 0x7a, 0x0b, 0x37],
                c:      [],
                mac:    [0x2b, 0x09, 0xa0, 0xab, 0x9a, 0x31, 0x25, 0xb0, 0x8d, 0x6a, 0x59, 0x42,
                         0x34, 0xd2, 0x15, 0xa7],
            },
        ];

        #[test]
        fn precalculation_vectors() -> Result<(), AlkaliError> {
            let seed_a = Seed::try_from(&[
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
                0x1c, 0x1d, 0x1e, 0x1f,
            ])?;
            let seed_b = Seed::try_from(&[
                0x01, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
                0x1c, 0x1d, 0x1e, 0x1f,
            ])?;

            let keypair_a = Keypair::from_seed(&seed_a)?;
            let keypair_b = Keypair::from_seed(&seed_b)?;

            let key_a = keypair_a.session_key(&keypair_b.public_key)?;
            let key_b = keypair_b.session_key(&keypair_a.public_key)?;

            assert_eq!(key_a, key_b);
            assert_eq!(
                &key_a[..],
                &[
                    0x53, 0xa7, 0x85, 0x2c, 0x7e, 0xe1, 0xe5, 0xaa, 0x34, 0xc2, 0x11, 0x51, 0x21,
                    0x2a, 0xb8, 0x2d, 0xc3, 0xd1, 0xc4, 0xd2, 0xff, 0x5a, 0x04, 0x38, 0xa9, 0x62,
                    0x61, 0xa7, 0xfe, 0xc3, 0x9a, 0x48
                ]
            );

            Ok(())
        }
    }
}

pub use curve25519xsalsa20poly1305::*;
