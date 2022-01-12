//! Asymmetric [Authenticated Encryption](https://en.wikipedia.org/wiki/Authenticated_encryption)
//! (AE).
//!
//! This module corresponds to the [`crypto_box`
//! API](https://doc.libsodium.org/public-key_cryptography/authenticated_encryption) from Sodium.
//!
//! Authenticated encryption is used to encrypt messages, providing assurance to the receiver that
//! the ciphertext has not been modified in transit by an attacker or transmission error. In
//! asymmetric encryption, parties do not need to share a secret key a priori: they only need to
//! know each others' public keys to exchange encrypted messages.
//!
//! Parties to the encryption calculate a shared secret key using a standard asymmetric key
//! exchange, then use a symmetric cipher to encrypt/decrypt messages. This is different to many
//! traditional asymmetric encryption schemes (e.g: RSA), where an asymmetric cipher directly
//! encrypts/decrypts messages. The benefit to the key-exchange then encrypt approach is that
//! symmetric ciphers are often much faster than asymmetric ciphers, and tend to have fewer
//! requirements for secure use.
//!
//! # Algorithm Details
//! [X25519](https://en.wikipedia.org/wiki/Curve25519) (Elliptic-Curve Diffie-Hellman over
//! Curve25519) is used to perform the key exchange. By default,
//! [XSalsa20](https://en.wikipedia.org/wiki/Salsa20) (Salsa20 with an eXtended nonce) is used for
//! the symmetric cipher, and [Poly1305](https://en.wikipedia.org/wiki/Poly1305) is used for
//! message authentication. This construction is exposed in the [`curve25519xsalsa20poly1305`]
//! module.
//!
//! A variant which uses [XChaCha20](https://en.wikipedia.org/wiki/Salsa20#ChaCha_variant)
//! (ChaCha20 with an eXtended nonce) for the symmetric cipher is also available as
//! [`curve25519xchacha20poly1305`].
//!
//! # Security Considerations
//! For the algorithms in this module, nonces must *never* be used more than once with the same
//! keys. If you just use the [`encrypt`]/[`encrypt_detached`] functions, this should not be a
//! concern, as a random nonce is generated for every message encrypted with these functions.
//! However, for the functions which allow you to specify the nonce to use, please ensure you never
//! use a given nonce more than once with the same keys: Nonces for the algorithms here are
//! sufficiently long that a nonce can be randomly chosen for every message using
//! [`generate_nonce`], and the probability of nonce reuse will be effectively zero.
//!
//! Public keys, nonces and MACs are not secret values, and can be transmitted in the clear.
//! However, secret keys must be kept private: Parties do not need to know each others' secret key
//! to communicate.
//!
//! # Examples
//! Generating a random keypair for a sender & receiver, and encrypting/decrypting messages (uses
//! [`generate_keypair`], [`encrypt`], and [`decrypt`]):
//!
//! ```rust
//! use alkali::asymmetric::cipher;
//!
//! let (sender_private, sender_public) = cipher::generate_keypair().unwrap();
//! let (receiver_private, receiver_public) = cipher::generate_keypair().unwrap();
//!
//! let msg = b"Encrypt me please!";
//! let mut ciphertext = [0; 18 + cipher::MAC_LENGTH];
//!
//! let (nonce, _) =
//!     cipher::encrypt(msg, &sender_private, &receiver_public, &mut ciphertext)
//!     .unwrap();
//!
//! // ...
//!
//! let mut plaintext = [0; 18];
//! cipher::decrypt(
//!     &ciphertext, &receiver_private, &sender_public, &nonce, &mut plaintext
//! ).unwrap();
//!
//! assert_eq!(&plaintext, msg);
//! ```
//!
//! Precalculating the shared secret key, which can be useful if many messages are exchanged
//! between the same parties (uses [`precalculate_shared_key`], [`encrypt_precalculated`], and
//! [`decrypt_precalculated`]):
//!
//! ```rust
//! use alkali::asymmetric::cipher;
//!
//! let (sender_private, sender_public) = cipher::generate_keypair().unwrap();
//! let (receiver_private, receiver_public) = cipher::generate_keypair().unwrap();
//!
//! let shared_key = cipher::precalculate_shared_key(&sender_private, &receiver_public).unwrap();
//!
//! let msg = b"I would also like to be encrypted :)";
//! let mut ciphertext = [0; 36 + cipher::MAC_LENGTH];
//!
//! let (nonce, _) = cipher::encrypt_precalculated(msg, &shared_key, &mut ciphertext).unwrap();
//!
//! // ...
//!
//! // This will calculate the same shared key as on the sender's side
//! let shared_key = cipher::precalculate_shared_key(&receiver_private, &sender_public).unwrap();
//!
//! let mut plaintext = [0; 36];
//! cipher::decrypt_precalculated(&ciphertext, &shared_key, &nonce, &mut plaintext).unwrap();
//!
//! assert_eq!(&plaintext, msg);
//! ```
//!
//! Detached encryption & decryption (uses [`encrypt_detached`] and [`decrypt_detached`]):
//!
//! ```rust
//! use alkali::asymmetric::cipher;
//!
//! let (sender_private, sender_public) = cipher::generate_keypair().unwrap();
//! let (receiver_private, receiver_public) = cipher::generate_keypair().unwrap();
//!
//! let msg = b"And one more for luck!";
//! let mut ciphertext = [0; 22];
//!
//! let (nonce, mac) =
//!     cipher::encrypt_detached(msg, &sender_private, &receiver_public, &mut ciphertext)
//!     .unwrap();
//!
//! // ...
//!
//! let mut plaintext = [0; 22];
//! cipher::decrypt_detached(
//!     &ciphertext, &mac, &receiver_private, &sender_public, &nonce, &mut plaintext
//! ).unwrap();
//!
//! assert_eq!(&plaintext, msg);
//! ```

use thiserror::Error;

/// Error type returned if something went wrong in the `asymmetric::cipher` module.
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

/// Generates the API for an `asymmetric::cipher` module with the given functions from Sodium for a
/// specific implementation.
macro_rules! cipher_module {
    (
        $private_key_len:expr,      // crypto_box_SECRETKEYBYTES
        $public_key_len:expr,       // crypto_box_PUBLICKEYBYTES
        $shared_key_len:expr,       // crypto_box_BEFORENMBYTES
        $seed_len:expr,             // crypto_box_SEEDBYTES
        $mac_len:expr,              // crypto_box_MACBYTES
        $nonce_len:expr,            // crypto_box_NONCEBYTES
        $msg_max:path,              // crypto_box_messagebytes_max
        $keypair:path,              // crypto_box_keypair
        $seed_keypair:path,         // crypto_box_seed_keypair
        $beforenm:path,             // crypto_box_beforenm
        $encrypt:path,              // crypto_box_easy
        $decrypt:path,              // crypto_box_open_easy
        $encrypt_d:path,            // crypto_box_detached
        $decrypt_d:path,            // crypto_box_open_detached
        $encrypt_afternm:path,      // crypto_box_easy
        $decrypt_afternm:path,      // crypto_box_open_easy
        $encrypt_d_afternm:path,    // crypto_box_detached
        $decrypt_d_afternm:path,    // crypto_box_open_detached
    ) => {
        /// The length of a private key for asymmetric AE, in bytes.
        pub const PRIVATE_KEY_LENGTH: usize = $private_key_len as usize;

        /// The length of a public key for asymmetric AE, in bytes.
        pub const PUBLIC_KEY_LENGTH: usize = $public_key_len as usize;

        /// The length of a derive shared secret key for asymmetric AE, in bytes.
        pub const SHARED_KEY_LENGTH: usize = $shared_key_len as usize;

        /// The length of a seed to use for the deterministic generation of a (private key, public
        /// key) pair, in bytes.
        pub const KEY_SEED_LENGTH: usize = $seed_len as usize;

        /// The length of a MAC, in bytes.
        pub const MAC_LENGTH: usize = $mac_len as usize;

        /// The length of a message nonce, in bytes.
        pub const NONCE_LENGTH: usize = $nonce_len as usize;

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

            /// The shared secret key derived during the key exchange used in asymmetric AE.
            ///
            /// This should be kept secret, otherwise anyone can read the contents of encrypted
            /// messages.
            ///
            /// This is a [hardened buffer type](https://docs.rs/alkali#hardened-buffer-types), and
            /// will be zeroed on drop. A number of other security measures are taken to protect
            /// its contents.
            SharedKey(SHARED_KEY_LENGTH);

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

        /// A public key used by a party for asymmetric AE.
        ///
        /// A public key corresponds to a private key, and represents a point on the Curve25519
        /// curve.
        ///
        /// A public key should be made public, as any other parties need to know it to communicate
        /// with you.
        pub type PublicKey = [u8; PUBLIC_KEY_LENGTH];

        /// A MAC (Message Authentication Code), used to authenticate a message.
        pub type MAC = [u8; MAC_LENGTH];

        /// A nonce, used to introduce non-determinism into the keystream calculation.
        pub type Nonce = [u8; NONCE_LENGTH];

        lazy_static::lazy_static! {
            /// The maximum message length which can be encrypted with this cipher
            pub static ref MESSAGE_LENGTH_MAX: usize = unsafe {
                // SAFETY: This function just returns a constant value, and should always be safe
                // to call.
                $msg_max()
            };
        }

        /// Generates a random private key, and corresponding public key, for use in asymmetric AE.
        ///
        /// The generate private key will *not* be clamped, and therefore if used in other X25519
        /// implementations, it must be clamped before use. It is automatically clamped during the
        /// public key calculation, and for other calculations within the Sodium implementation.
        ///
        /// Returns a (private key, public key) keypair, or an error if an error occurred
        /// initialising Sodium. The private key should be kept private, the public key can be
        /// publicised.
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
        /// The generated private key will *not* be clamped, and therefore if used in other X25519
        /// implementations, it must be clamped before use. It is automatically clamped during the
        /// public key calculation, and for other calculations within the Sodium implementation.
        ///
        /// Returns a (private key, public key) keypair, or an error if an error occurred
        /// initialising Sodium. The private key should be kept private, the public key can be
        /// publicised.
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

        /// Precalculate the shared secret key to speed up subsequent encryption/decryption
        /// operations.
        ///
        /// As stated in the module description, this API works by first calculating a shared
        /// secret using our private key and the other party's public key, and then using this
        /// shared secret to encrypt messages. If many messages are to be sent to/received from the
        /// same person, it can be inefficient to perfom this calculation for every message, since
        /// the derived secret is the same every time. This function precalculates the shared
        /// secret, so it doesn't need to be calculated every time.
        ///
        /// The first argument to this function should be party A's private key. The second should
        /// be the public key of party B, with whom A is exchanging messages. Returns the derived
        /// shared secret key.
        ///
        /// # Security Concerns
        /// The key derived in this function should be protected as closely as any other secret
        /// key.
        pub fn precalculate_shared_key(
            private_key: &PrivateKey,
            public_key: &PublicKey,
        ) -> Result<SharedKey, $crate::AlkaliError> {
            $crate::require_init()?;

            let mut shared_key = SharedKey::new_empty()?;

            let res = unsafe {
                // SAFETY: The first argument to this function is the destination to which the
                // shared secret key will be written. We have defined the `SharedKey` type to store
                // `crypto_box_BEFORENMBYTES`, and therefore it is sufficient to store the shared
                // secret key. The second argument is a pointer to the other party's public key
                // from which the shared secret will be derived. The `PublicKey` type is defined to
                // be `crypto_box_PUBLICKEYBYTES`, so it is the expected size for use with this
                // function. The third argument is a pointer to our private key, from which the
                // shared secret will be derived. The `PrivateKey` type stores
                // `crypto_box_SECRETKEYBYTES`, so it is of the expected size for use with this
                // function.
                $beforenm(
                    shared_key.inner_mut() as *mut libc::c_uchar,
                    public_key.as_ptr(),
                    private_key.inner() as *const libc::c_uchar,
                )
            };

            if res == 0 {
                Ok(shared_key)
            } else {
                Err($crate::asymmetric::cipher::CipherError::PublicKeyInsecure.into())
            }
        }

        /// Generate a random nonce for use with the functions throughout this module.
        ///
        /// The cipher used here has a sufficiently long nonce size that we can simply generate a
        /// random nonce for every message we wish to encrypt, and the chances of reusing a nonce
        /// are essentially zero.
        ///
        /// Returns a nonce generated using a Cryptographically Secure Pseudo-Random Number
        /// Generator, an an error if some error occurred.
        pub fn generate_nonce() -> Result<Nonce, $crate::AlkaliError> {
            let mut nonce = [0; NONCE_LENGTH];
            $crate::random::fill_random(&mut nonce)?;
            Ok(nonce)
        }

        /// Encrypt `message` for the recipient with the public key `public_key_rx`, from the
        /// sender with private key `private_key_tx`, writing the result to `output`.
        ///
        /// `message` should be the message to encrypt. `private_key_tx` should be the sender's
        /// [`PrivateKey`], generated randomly using [`generate_keypair`]. `public_key_rx` should
        /// be the receiver's [`PublicKey`], generated from a random private key using
        /// [`generate_keypair`].
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
        /// same receiver and sender. For this function, this should not be a concern, as a random
        /// nonce is generated for every message encrypted.
        ///
        /// Nonces and MACs are not secret values, and can be transmitted in the clear.
        pub fn encrypt(
            message: &[u8],
            private_key_tx: &PrivateKey,
            public_key_rx: &PublicKey,
            output: &mut [u8],
        ) -> Result<(Nonce, usize), $crate::AlkaliError> {
            let nonce = generate_nonce()?;
            let c_len = encrypt_with_nonce(message, private_key_tx, public_key_rx, &nonce, output)?;

            Ok((nonce, c_len))
        }

        /// Encrypt `message` for the recipient with the public key `public_key_rx`, from the
        /// sender with private key `private_key_tx`, using the nonce `nonce`, writing the result
        /// to `output`.
        ///
        /// `message` should be the message to encrypt. `private_key_tx` should be the sender's
        /// [`PrivateKey`], generated randomly using [`generate_keypair`]. `public_key_rx` should
        /// be the receiver's [`PublicKey`], generated from a random private key using
        /// [`generate_keypair`].
        ///
        /// `nonce` should be a nonce to use. It is *vital* that a given nonce *never* be reused
        /// with the same key. It is best to simply generate a random nonce for every message using
        /// [`generate_nonce`]: The nonce length for this cipher is sufficient that the probability
        /// of repeating a randomly generated nonce is effecitvely zero. The nonce will be required
        /// for decryption, so it should be stored alongside the ciphertext, or somehow
        /// communicated to the receiver. Nonces do not need to be kept secret. The [`encrypt`]
        /// function automatically generates a random nonce for every message.
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
        /// same receiver and sender. Please ensure you never use a given nonce more than once with
        /// the same key: Nonces for the algorithms here are sufficiently long that a nonce can be
        /// randomly chosen for every message using [`generate_nonce`], and the probability of
        /// nonce reuse will be effectively zero.
        ///
        /// Nonces and MACs are not secret values, and can be transmitted in the clear.
        pub fn encrypt_with_nonce(
            message: &[u8],
            private_key_tx: &PrivateKey,
            public_key_rx: &PublicKey,
            nonce: &Nonce,
            output: &mut [u8],
        ) -> Result<usize, $crate::AlkaliError> {
            $crate::require_init()?;

            let c_len = message.len() + MAC_LENGTH;

            if output.len() < c_len {
                return Err($crate::asymmetric::cipher::CipherError::OutputInsufficient(
                    c_len,
                    output.len(),
                )
                .into());
            } else if message.len() > *MESSAGE_LENGTH_MAX {
                return Err($crate::asymmetric::cipher::CipherError::MessageTooLong.into());
            }

            let res = unsafe {
                // SAFETY: The first argument to this function is the destination pointer to which
                // the ciphertext should be written. We verify above that the `output` slice is of
                // sufficient size to store the message + auth tag, so a buffer overflow will not
                // occur. The next two arguments specify the message to encrypt and its length. We
                // use `message.len()` to specify the message length, so it is correct for this
                // pointer. The next argument specifies the nonce to use. We have defined the
                // `Nonce` type based on the `crypto_box_NONCEBYTES` constant, so it is of the
                // expected size for use with this function. The next argument specifies the
                // receiver's public key. We define the `PublicKey` type based on the
                // `crypto_box_PUBLICKEYBYTES` constant, so it is of the expected size for use with
                // this function. The final argument should be the sender's public key. We define
                // the `PrivateKey` type based on the `crypto_box_SECRETKEYBYTES` constant, so it
                // is of the expected size for use with this function. The `PrivateKey::inner`
                // method simply returns an immutable pointer to the type's backing memory.
                $encrypt(
                    output.as_mut_ptr(),
                    message.as_ptr(),
                    message.len() as libc::c_ulonglong,
                    nonce.as_ptr(),
                    public_key_rx.as_ptr(),
                    private_key_tx.inner() as *const libc::c_uchar,
                )
            };

            if res == 0 {
                Ok(c_len)
            } else {
                Err($crate::asymmetric::cipher::CipherError::PublicKeyInsecure.into())
            }
        }

        /// Encrypt `message` for the recipient with the public key `public_key_rx`, from the
        /// sender with private key `private_key_tx`, writing the result to `output`, but not
        /// prepending the MAC.
        ///
        /// This function is very similar to the [`encrypt`] function. The difference is that the
        /// standard [`encrypt`] function prepends the Message Authentication Code (MAC, used to
        /// verify the authenticity of the ciphertext) to the ciphertext output, while this
        /// function only writes the ciphertext to `output`, and separately returns the MAC.
        ///
        /// `message` should be the message to encrypt. `private_key_tx` should be the sender's
        /// [`PrivateKey`], generated randomly using [`generate_keypair`]. `public_key_rx` should
        /// be the receiver's [`PublicKey`], generated from a random private key using
        /// [`generate_keypair`].
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
        /// same receiver and sender. For this function, this should not be a concern, as a random
        /// nonce is generated for every message encrypted.
        ///
        /// Nonces and MACs are not secret values, and can be transmitted in the clear.
        pub fn encrypt_detached(
            message: &[u8],
            private_key_tx: &PrivateKey,
            public_key_rx: &PublicKey,
            output: &mut [u8],
        ) -> Result<(Nonce, MAC), $crate::AlkaliError> {
            let nonce = generate_nonce()?;
            let mac = encrypt_detached_with_nonce(
                message,
                private_key_tx,
                public_key_rx,
                &nonce,
                output,
            )?;

            Ok((nonce, mac))
        }

        /// Encrypt `message` for the recipient with the public key `public_key_rx`, from the
        /// sender with private key `private_key_tx`, using the nonce `nonce`, writing the result
        /// to `output`, but not prepending the MAC.
        ///
        /// This function is very similar to the [`encrypt_with_nonce`] function. The difference is
        /// that the standard [`encrypt_with_nonce`] function prepends the Message Authentication
        /// Code (MAC, used to verify the authenticity of the ciphertext) to the ciphertext output,
        /// while this function only writes the ciphertext to `output`, and separately returns the
        /// MAC.
        ///
        /// `message` should be the message to encrypt. `private_key_tx` should be the sender's
        /// [`PrivateKey`], generated randomly using [`generate_keypair`]. `public_key_rx` should
        /// be the receiver's [`PublicKey`], generated from a random private key using
        /// [`generate_keypair`].
        ///
        /// `nonce` should be a nonce to use. It is *vital* that a given nonce *never* be reused
        /// with the same key. It is best to simply generate a random nonce for every message using
        /// [`generate_nonce`]: The nonce length for this cipher is sufficient that the probability
        /// of repeating a randomly generated nonce is effecitvely zero. The nonce will be required
        /// for decryption, so it should be stored alongside the ciphertext, or somehow
        /// communicated to the receiver. Nonces do not need to be kept secret. The [`encrypt`]
        /// function automatically generates a random nonce for every message.
        ///
        /// The encrypted ciphertext will be written to `output`, which must be at least
        /// `message.len()` bytes long. If the `output` slice is not sufficient to store the
        /// ciphertext, an error will be returned.
        ///
        /// Returns the calculated MAC for the ciphertext.
        ///
        /// # Security Considerations
        /// For the algorithms in this module, nonces must *never* be used more than once with the
        /// same receiver and sender. Please ensure you never use a given nonce more than once with
        /// the same key: Nonces for the algorithms here are sufficiently long that a nonce can be
        /// randomly chosen for every message using [`generate_nonce`], and the probability of
        /// nonce reuse will be effectively zero.
        ///
        /// Nonces and MACs are not secret values, and can be transmitted in the clear.
        pub fn encrypt_detached_with_nonce(
            message: &[u8],
            private_key_tx: &PrivateKey,
            public_key_rx: &PublicKey,
            nonce: &Nonce,
            output: &mut [u8],
        ) -> Result<MAC, $crate::AlkaliError> {
            $crate::require_init()?;

            if output.len() < message.len() {
                return Err($crate::asymmetric::cipher::CipherError::OutputInsufficient(
                    message.len(),
                    output.len(),
                )
                .into());
            } else if message.len() > *MESSAGE_LENGTH_MAX {
                return Err($crate::asymmetric::cipher::CipherError::MessageTooLong.into());
            }

            let mut mac = [0u8; MAC_LENGTH];

            let res = unsafe {
                // SAFETY: The first argument to this function is the destination pointer to which
                // the ciphertext should be written. We verify above that the `output` slice is of
                // sufficient size to store the message, so a buffer overflow will not occur. The
                // next argument is the destination pointer to which the MAC will be written. We
                // define the `mac` array to be `crypto_box_MACBYTES` bytes long, so it is of the
                // expected size to use here, and a buffer overflow will not occur. The next two
                // arguments specify the message to encrypt and its length. We use `message.len()`
                // to specify the message length, so it is correct for this pointer. The next
                // argument specifies the nonce to use. We have defined the `Nonce` type based on
                // the `crypto_box_NONCEBYTES` constant, so it is of the expected size for use with
                // this function. The next argument specifies the receiver's public key. We define
                // the `PublicKey` type based on the `crypto_box_PUBLICKEYBYTES` constant, so it is
                // of the expected size for use with this function. The final argument should be
                // the sender's public key. We define the `PrivateKey` type based on the
                // `crypto_box_SECRETKEYBYTES` constant, so it is of the expected size for use with
                // this function. The `PrivateKey::inner` method simply returns an immutable
                // pointer to the type's backing memory.
                $encrypt_d(
                    output.as_mut_ptr(),
                    mac.as_mut_ptr(),
                    message.as_ptr(),
                    message.len() as libc::c_ulonglong,
                    nonce.as_ptr(),
                    public_key_rx.as_ptr(),
                    private_key_tx.inner() as *const libc::c_uchar,
                )
            };

            if res == 0 {
                Ok(mac)
            } else {
                Err($crate::asymmetric::cipher::CipherError::PublicKeyInsecure.into())
            }
        }

        /// Encrypt `message` using the shared secret key precalculated with
        /// [`precalculate_shared_key`], writing the result to `output`.
        ///
        /// `message` should be the message to encrypt. `shared_key` should be the [`SharedKey`],
        /// derived from the sender's private key and receiver's public key using
        /// [`precalculate_shared_key`].
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
        /// same receiver and sender. For this function, this should not be a concern, as a random
        /// nonce is generated for every message encrypted.
        ///
        /// Nonces and MACs are not secret values, and can be transmitted in the clear.
        pub fn encrypt_precalculated(
            message: &[u8],
            shared_key: &SharedKey,
            output: &mut [u8],
        ) -> Result<(Nonce, usize), $crate::AlkaliError> {
            let nonce = generate_nonce()?;
            let c_len = encrypt_with_nonce_precalculated(message, shared_key, &nonce, output)?;

            Ok((nonce, c_len))
        }

        /// Encrypt `message` using the shared secret key precalculated with
        /// [`precalculate_shared_key`] and nonce `nonce`, writing the result to `output`.
        ///
        /// `message` should be the message to encrypt. `shared_key` should be the [`SharedKey`],
        /// derived from the sender's private key and receiver's public key using
        /// [`precalculate_shared_key`].
        ///
        /// `nonce` should be a nonce to use. It is *vital* that a given nonce *never* be reused
        /// with the same key. It is best to simply generate a random nonce for every message using
        /// [`generate_nonce`]: The nonce length for this cipher is sufficient that the probability
        /// of repeating a randomly generated nonce is effecitvely zero. The nonce will be required
        /// for decryption, so it should be stored alongside the ciphertext, or somehow
        /// communicated to the receiver. Nonces do not need to be kept secret. The [`encrypt`]
        /// function automatically generates a random nonce for every message.
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
        /// same receiver and sender. Please ensure you never use a given nonce more than once with
        /// the same key: Nonces for the algorithms here are sufficiently long that a nonce can be
        /// randomly chosen for every message using [`generate_nonce`], and the probability of
        /// nonce reuse will be effectively zero.
        ///
        /// Nonces and MACs are not secret values, and can be transmitted in the clear.
        pub fn encrypt_with_nonce_precalculated(
            message: &[u8],
            shared_key: &SharedKey,
            nonce: &Nonce,
            output: &mut [u8],
        ) -> Result<usize, $crate::AlkaliError> {
            $crate::require_init()?;

            let c_len = message.len() + MAC_LENGTH;

            if output.len() < c_len {
                return Err($crate::asymmetric::cipher::CipherError::OutputInsufficient(
                    c_len,
                    output.len(),
                )
                .into());
            } else if message.len() > *MESSAGE_LENGTH_MAX {
                return Err($crate::asymmetric::cipher::CipherError::MessageTooLong.into());
            }

            unsafe {
                // SAFETY: The first argument to this function is the destination pointer to which
                // the ciphertext should be written. We verify above that the `output` slice is of
                // sufficient size to store the message + auth tag, so a buffer overflow will not
                // occur. The next two arguments specify the message to encrypt and its length. We
                // use `message.len()` to specify the message length, so it is correct for this
                // pointer. The next argument specifies the nonce to use. We have defined the
                // `Nonce` type based on the `crypto_box_NONCEBYTES` constant, so it is of the
                // expected size for use with this function. The final argument specifies the
                // derived shared secret key to use to encrypt the message. We define the
                // `SharedKey` type to be `crypto_box_BEFORENMBYTES`, so it is of the correct size
                // to use here.
                $encrypt_afternm(
                    output.as_mut_ptr(),
                    message.as_ptr(),
                    message.len() as libc::c_ulonglong,
                    nonce.as_ptr(),
                    shared_key.inner() as *const libc::c_uchar,
                );
            }

            Ok(c_len)
        }

        /// Encrypt `message` using the shared secret key precalculated with
        /// [`precalculate_shared_key`], writing the result to `output`, but not prepending the
        /// MAC.
        ///
        /// This function is very similar to the [`encrypt_precalculated`] function. The difference
        /// is that the standard [`encrypt_precalculated`] function prepends the Message
        /// Authentication Code (MAC, used to verify the authenticity of the ciphertext) to the
        /// ciphertext output, while this function only writes the ciphertext to `output`, and
        /// separately returns the MAC.
        ///
        /// `message` should be the message to encrypt. `shared_key` should be the [`SharedKey`],
        /// derived from the sender's private key and receiver's public key using
        /// [`precalculate_shared_key`].
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
        /// same receiver and sender. For this function, this should not be a concern, as a random
        /// nonce is generated for every message encrypted.
        ///
        /// Nonces and MACs are not secret values, and can be transmitted in the clear.
        pub fn encrypt_detached_precalculated(
            message: &[u8],
            shared_key: &SharedKey,
            output: &mut [u8],
        ) -> Result<(Nonce, MAC), $crate::AlkaliError> {
            let nonce = generate_nonce()?;
            let mac =
                encrypt_detached_with_nonce_precalculated(message, shared_key, &nonce, output)?;

            Ok((nonce, mac))
        }

        /// Encrypt `message` using the shared secret key precalculated with
        /// [`precalculate_shared_key`] and nonce `nonce`, writing the result to `output`, but not
        /// prepending the MAC.
        ///
        /// This function is very similar to the [`encrypt_with_nonce_precalculated`] function. The
        /// difference is that the standard [`encrypt_with_nonce_precalculated`] function prepends
        /// the Message Authentication Code (MAC, used to verify the authenticity of the
        /// ciphertext) to the ciphertext output, while this function only writes the ciphertext to
        /// `output`, and separately returns the MAC.
        ///
        /// `message` should be the message to encrypt. `shared_key` should be the [`SharedKey`],
        /// derived from the sender's private key and receiver's public key using
        /// [`precalculate_shared_key`].
        ///
        /// `nonce` should be a nonce to use. It is *vital* that a given nonce *never* be reused
        /// with the same key. It is best to simply generate a random nonce for every message using
        /// [`generate_nonce`]: The nonce length for this cipher is sufficient that the probability
        /// of repeating a randomly generated nonce is effecitvely zero. The nonce will be required
        /// for decryption, so it should be stored alongside the ciphertext, or somehow
        /// communicated to the receiver. Nonces do not need to be kept secret. The [`encrypt`]
        /// function automatically generates a random nonce for every message.
        ///
        /// The encrypted ciphertext will be written to `output`, which must be at least
        /// `message.len()` bytes long. If the `output` slice is not sufficient to store the
        /// ciphertext, an error will be returned.
        ///
        /// Returns the calculated MAC for the ciphertext.
        ///
        /// # Security Considerations
        /// For the algorithms in this module, nonces must *never* be used more than once with the
        /// same receiver and sender. Please ensure you never use a given nonce more than once with
        /// the same key: Nonces for the algorithms here are sufficiently long that a nonce can be
        /// randomly chosen for every message using [`generate_nonce`], and the probability of
        /// nonce reuse will be effectively zero.
        ///
        /// Nonces and MACs are not secret values, and can be transmitted in the clear.
        pub fn encrypt_detached_with_nonce_precalculated(
            message: &[u8],
            shared_key: &SharedKey,
            nonce: &Nonce,
            output: &mut [u8],
        ) -> Result<MAC, $crate::AlkaliError> {
            $crate::require_init()?;

            if output.len() < message.len() {
                return Err($crate::asymmetric::cipher::CipherError::OutputInsufficient(
                    message.len(),
                    output.len(),
                )
                .into());
            } else if message.len() > *MESSAGE_LENGTH_MAX {
                return Err($crate::asymmetric::cipher::CipherError::MessageTooLong.into());
            }

            let mut mac = [0u8; MAC_LENGTH];

            unsafe {
                // SAFETY: The first argument to this function is the destination pointer to which
                // the ciphertext should be written. We verify above that the `output` slice is of
                // sufficient size to store the message, so a buffer overflow will not occur. The
                // next argument is the destination pointer to which the MAC will be written. We
                // define the `mac` array to be `crypto_box_MACBYTES` bytes long, so it is of the
                // expected size to use here, and a buffer overflow will not occur. The next two
                // arguments specify the message to encrypt and its length. We use `message.len()`
                // to specify the message length, so it is correct for this pointer. The next
                // argument specifies the nonce to use. We have defined the `Nonce` type based on
                // the `crypto_box_NONCEBYTES` constant, so it is of the expected size for use with
                // this function. The final argument specifies the derived shared secret key to use
                // to encrypt the message. We define the `SharedKey` type to be
                // `crypto_box_BEFORENMBYTES`, so it is of the correct size to use here.
                $encrypt_d_afternm(
                    output.as_mut_ptr(),
                    mac.as_mut_ptr(),
                    message.as_ptr(),
                    message.len() as libc::c_ulonglong,
                    nonce.as_ptr(),
                    shared_key.inner() as *const libc::c_uchar,
                );
            }

            Ok(mac)
        }

        /// Try to decrypt `ciphertext` (previously encrypted by the sender with `public_key_tx`
        /// for the recipient with `private_key_rx` using [`encrypt`]), writing the result to
        /// `output`.
        ///
        /// `ciphertext` should be a message to try to decrypt. `private_key_rx` should be the
        /// receiver's [`PrivateKey`], `public_key_tx` should be the sender's [`PublicKey`].
        /// `nonce` should be the [`Nonce`] the message was encrypted with.
        ///
        /// If authentication + decryption succeed, the decrypted message will be written to
        /// `output`. `output` must be at least `ciphertext.len()` - [`MAC_LENGTH`] bytes,
        /// otherwise an error will be returned.
        ///
        /// Returns the length of the plaintext written to `output`, which will always be
        /// `ciphertext.len()` - [`MAC_LENGTH`] bytes.
        pub fn decrypt(
            ciphertext: &[u8],
            private_key_rx: &PrivateKey,
            public_key_tx: &PublicKey,
            nonce: &Nonce,
            output: &mut [u8],
        ) -> Result<usize, $crate::AlkaliError> {
            $crate::require_init()?;

            if ciphertext.len() < MAC_LENGTH {
                return Err($crate::asymmetric::cipher::CipherError::DecryptionFailed.into());
            }

            let m_len = ciphertext.len() - MAC_LENGTH;

            if output.len() < m_len {
                return Err($crate::asymmetric::cipher::CipherError::OutputInsufficient(
                    m_len,
                    output.len(),
                )
                .into());
            }

            let decrypt_result = unsafe {
                // SAFETY: The first argument to this function is the destination pointer to which
                // the ciphertext will be written. We verified above that the `output` slice's
                // length is sufficient to store the plaintext, so a buffer overrun cannot occur.
                // The next two arguments specify the ciphertext to decrypt and its length. We use
                // `ciphertext.len()` to specify the length, so it is definitely correct for this
                // pointer. The next argument specifies the nonce to use. We define the `Nonce`
                // type to be `crypto_box_NONCEBYTES`, so it is of the expected size for use here.
                // The final two arguments specify the public key and private key to use in the key
                // exchange calculation. We define the `PublicKey` type to be
                // `crypto_box_PUBLICKEYBYTES` and the `PrivateKey` type to be
                // `crypto_box_SECRETKEYBYTES`, so both are of the expected size for use with this
                // function. THe `PrivateKey::inner` method simply returns an immutable pointer to
                // the backing memory for the buffer.
                $decrypt(
                    output.as_mut_ptr(),
                    ciphertext.as_ptr(),
                    ciphertext.len() as libc::c_ulonglong,
                    nonce.as_ptr(),
                    public_key_tx.as_ptr(),
                    private_key_rx.inner() as *const libc::c_uchar,
                )
            };

            if decrypt_result == 0 {
                Ok(m_len)
            } else {
                Err($crate::asymmetric::cipher::CipherError::DecryptionFailed.into())
            }
        }

        /// Try to decrypt `ciphertext` (previously encrypted by the sender with `public_key_tx`
        /// for the recipient with `private_key_rx` using [`encrypt_detached`]), writing the result
        /// to `output`.
        ///
        /// `ciphertext` should be a message to try to decrypt, and `mac` the [`MAC`] (MEssage
        /// Authentication Code) for this message. `private_key_rx` should be the receiver's
        /// [`PrivateKey`], `public_key_tx` should be the sender's [`PublicKey`].  `nonce` should
        /// be the [`Nonce`] the message was encrypted with.
        ///
        /// If authentication + decryption succeed, the decrypted message will be written to
        /// `output`. `output` must be at least `ciphertext.len()`, otherwise an error will be
        /// returned.
        pub fn decrypt_detached(
            ciphertext: &[u8],
            mac: &MAC,
            private_key: &PrivateKey,
            public_key: &PublicKey,
            nonce: &Nonce,
            output: &mut [u8],
        ) -> Result<(), $crate::AlkaliError> {
            $crate::require_init()?;

            if output.len() < ciphertext.len() {
                return Err($crate::asymmetric::cipher::CipherError::OutputInsufficient(
                    ciphertext.len(),
                    output.len(),
                )
                .into());
            }

            let decrypt_result = unsafe {
                // SAFETY: The first argument to this function is the destination pointer to which
                // the ciphertext will be written. We verified above that the `output` slice's
                // length is sufficient to store the plaintext, so a buffer overrun cannot occur.
                // The second and fourth arguments specify the ciphertext to decrypt and its
                // length. We use `ciphertext.len()` to specify the length, so it is definitely
                // correct for this pointer. The third argument and fifth arguments specify the MAC
                // and nonce. We define the `MAC` and `Nonce` types based on the
                // `crypto_box_MACBYTES` and `crypto_box_NONCEBYTES` constants, so they are of the
                // expected size for use with this function. The final two arguments specify the
                // public key and private key to use in the key exchange calculation. We define the
                // `PublicKey` type to be `crypto_box_PUBLICKEYBYTES` and the `PrivateKey` type to
                // be `crypto_box_SECRETKEYBYTES`, so both are of the expected size for use with
                // this function. THe `PrivateKey::inner` method simply returns an immutable
                // pointer to the backing memory for the buffer.
                $decrypt_d(
                    output.as_mut_ptr(),
                    ciphertext.as_ptr(),
                    mac.as_ptr(),
                    ciphertext.len() as libc::c_ulonglong,
                    nonce.as_ptr(),
                    public_key.as_ptr(),
                    private_key.inner() as *const libc::c_uchar,
                )
            };

            if decrypt_result == 0 {
                Ok(())
            } else {
                Err($crate::asymmetric::cipher::CipherError::DecryptionFailed.into())
            }
        }

        /// Try to decrypt `ciphertext` using the shared secret key precalculated with
        /// [`precalculate_shared_key`] (previously encrypted using [`encrypt`]), writing the
        /// result to `output`.
        ///
        /// `ciphertext` should be a message to try to decrypt. `shared_key` should be the
        /// [`SharedKey`], derived from the sender's private key and receiver's public key using
        /// [`precalculate_shared_key`]. `nonce` should be the [`Nonce`] the message was encrypted
        /// with.
        ///
        /// If authentication + decryption succeed, the decrypted message will be written to
        /// `output`. `output` must be at least `ciphertext.len()` - [`MAC_LENGTH`] bytes,
        /// otherwise an error will be returned.
        ///
        /// Returns the length of the plaintext written to `output`, which will always be
        /// `ciphertext.len()` - [`MAC_LENGTH`] bytes.
        pub fn decrypt_precalculated(
            ciphertext: &[u8],
            shared_key: &SharedKey,
            nonce: &Nonce,
            output: &mut [u8],
        ) -> Result<usize, $crate::AlkaliError> {
            $crate::require_init()?;

            if ciphertext.len() < MAC_LENGTH {
                return Err($crate::asymmetric::cipher::CipherError::DecryptionFailed.into());
            }

            let m_len = ciphertext.len() - MAC_LENGTH;

            if output.len() < m_len {
                return Err($crate::asymmetric::cipher::CipherError::OutputInsufficient(
                    m_len,
                    output.len(),
                )
                .into());
            }

            let decrypt_result = unsafe {
                // SAFETY: The first argument to this function is the destination pointer to which
                // the ciphertext will be written. We verified above that the `output` slice's
                // length is sufficient to store the plaintext, so a buffer overrun cannot occur.
                // The next two arguments specify the ciphertext to decrypt and its length. We use
                // `ciphertext.len()` to specify the length, so it is definitely correct for this
                // pointer. The next argument specifies the nonce to use. We define the `Nonce`
                // type to be `crypto_box_NONCEBYTES`, so it is of the expected size for use here.
                // The final argument specifies the derived shared secret key to use to decrypt the
                // message. We define the `SharedKey` type to be `crypto_box_BEFORENMBYTES`, so it
                // is of the correct size to use here.
                $decrypt_afternm(
                    output.as_mut_ptr(),
                    ciphertext.as_ptr(),
                    ciphertext.len() as libc::c_ulonglong,
                    nonce.as_ptr(),
                    shared_key.inner() as *const libc::c_uchar,
                )
            };

            if decrypt_result == 0 {
                Ok(m_len)
            } else {
                Err($crate::asymmetric::cipher::CipherError::DecryptionFailed.into())
            }
        }

        /// Try to decrypt `ciphertext` using the shared secret key precalculated with
        /// [`precalculate_shared_key`] (previously encrypted using [`encrypt_detached`]), writing
        /// the result to `output`.
        ///
        /// `ciphertext` should be a message to try to decrypt, `mac` the [`MAC`] (Message
        /// Authentication Code) for this message. `shared_key` should be the [`SharedKey`],
        /// derived from the sender's private key and receiver's public key using
        /// [`precalculate_shared_key`]. `nonce` should be the [`Nonce`] the message was encrypted
        /// with.
        ///
        /// If authentication + decryption succeed, the decrypted message will be written to
        /// `output`. `output` must be at least `ciphertext.len()` bytes, otherwise an error will
        /// be returned.
        pub fn decrypt_detached_precalculated(
            ciphertext: &[u8],
            mac: &MAC,
            shared_key: &SharedKey,
            nonce: &Nonce,
            output: &mut [u8],
        ) -> Result<(), $crate::AlkaliError> {
            $crate::require_init()?;

            if output.len() < ciphertext.len() {
                return Err($crate::asymmetric::cipher::CipherError::OutputInsufficient(
                    ciphertext.len(),
                    output.len(),
                )
                .into());
            }

            let decrypt_result = unsafe {
                // SAFETY: The first argument to this function is the destination pointer to which
                // the ciphertext will be written. We verified above that the `output` slice's
                // length is sufficient to store the plaintext, so a buffer overrun cannot occur.
                // The second and fourth arguments specify the ciphertext to decrypt and its
                // length. We use `ciphertext.len()` to specify the length, so it is definitely
                // correct for this pointer. The third argument and fifth arguments specify the MAC
                // and nonce. We define the `MAC` and `Nonce` types based on the
                // `crypto_box_MACBYTES` and `crypto_box_NONCEBYTES` constants, so they are of the
                // expected size for use with this function. The final argument specifies the
                // derived shared secret key to use to decrypt the message. We define the
                // `SharedKey` type to be `crypto_box_BEFORENMBYTES`, so it is of the correct size
                // to use here.
                $decrypt_d_afternm(
                    output.as_mut_ptr(),
                    ciphertext.as_ptr(),
                    mac.as_ptr(),
                    ciphertext.len() as libc::c_ulonglong,
                    nonce.as_ptr(),
                    shared_key.inner() as *const libc::c_uchar,
                )
            };

            if decrypt_result == 0 {
                Ok(())
            } else {
                Err($crate::asymmetric::cipher::CipherError::DecryptionFailed.into())
            }
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
            decrypt, decrypt_detached, decrypt_detached_precalculated, decrypt_precalculated,
            encrypt, encrypt_detached, encrypt_detached_precalculated, encrypt_detached_with_nonce,
            encrypt_precalculated, encrypt_detached_with_nonce_precalculated, encrypt_with_nonce,
            encrypt_with_nonce_precalculated, generate_keypair, generate_keypair_from_seed,
            precalculate_shared_key, PrivateKey, Seed, MAC_LENGTH
        };
        use $crate::AlkaliError;
        use $crate::random::fill_random;

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
            let (priv_x, pub_x) = generate_keypair()?;
            let (priv_y, pub_y) = generate_keypair()?;

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

            let (nonce_a, l_a) = encrypt(&msg_a, &priv_x, &pub_y, &mut c_a)?;
            let (nonce_b, l_b) = encrypt(&msg_b, &priv_x, &pub_y, &mut c_b)?;
            let (nonce_c, l_c) = encrypt(&msg_c, &priv_x, &pub_y, &mut c_c)?;
            let (nonce_d, l_d) = encrypt(&msg_d, &priv_x, &pub_y, &mut c_d)?;

            assert_eq!(l_a, MAC_LENGTH);
            assert_eq!(l_b, 16 + MAC_LENGTH);
            assert_eq!(l_c, 1024 + MAC_LENGTH);
            assert_eq!(l_d, (1 << 18) + MAC_LENGTH);

            decrypt(&c_a, &priv_y, &pub_x, &nonce_a, &mut msg_a)?;
            decrypt(&c_b, &priv_y, &pub_x, &nonce_b, &mut msg_b)?;
            decrypt(&c_c, &priv_y, &pub_x, &nonce_c, &mut msg_c)?;
            decrypt(&c_d, &priv_y, &pub_x, &nonce_d, &mut msg_d)?;

            fill_random(&mut c_a)?;
            fill_random(&mut c_b)?;
            fill_random(&mut c_c)?;
            fill_random(&mut c_d)?;

            assert!(decrypt(&c_a, &priv_y, &pub_x, &nonce_a, &mut msg_a).is_err());
            assert!(decrypt(&c_b, &priv_y, &pub_x, &nonce_b, &mut msg_b).is_err());
            assert!(decrypt(&c_c, &priv_y, &pub_x, &nonce_c, &mut msg_c).is_err());
            assert!(decrypt(&c_d, &priv_y, &pub_x, &nonce_d, &mut msg_d).is_err());

            Ok(())
        }

        #[test]
        fn enc_and_dec_detached() -> Result<(), AlkaliError> {
            let (priv_x, pub_x) = generate_keypair()?;
            let (priv_y, pub_y) = generate_keypair()?;

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

            let (nonce_a, mut mac_a) = encrypt_detached(&msg_a, &priv_x, &pub_y, &mut c_a)?;
            let (nonce_b, mac_b) = encrypt_detached(&msg_b, &priv_x, &pub_y, &mut c_b)?;
            let (nonce_c, mac_c) = encrypt_detached(&msg_c, &priv_x, &pub_y, &mut c_c)?;
            let (nonce_d, mac_d) = encrypt_detached(&msg_d, &priv_x, &pub_y, &mut c_d)?;

            decrypt_detached(&c_a, &mac_a, &priv_y, &pub_x, &nonce_a, &mut msg_a)?;
            decrypt_detached(&c_b, &mac_b, &priv_y, &pub_x, &nonce_b, &mut msg_b)?;
            decrypt_detached(&c_c, &mac_c, &priv_y, &pub_x, &nonce_c, &mut msg_c)?;
            decrypt_detached(&c_d, &mac_d, &priv_y, &pub_x, &nonce_d, &mut msg_d)?;

            fill_random(&mut mac_a)?;
            fill_random(&mut c_b)?;
            fill_random(&mut c_c)?;
            fill_random(&mut c_d)?;

            assert!(decrypt_detached(&c_a, &mac_a, &priv_y, &pub_x, &nonce_a, &mut msg_a).is_err());
            assert!(decrypt_detached(&c_b, &mac_b, &priv_y, &pub_x, &nonce_b, &mut msg_b).is_err());
            assert!(decrypt_detached(&c_c, &mac_c, &priv_y, &pub_x, &nonce_c, &mut msg_c).is_err());
            assert!(decrypt_detached(&c_d, &mac_d, &priv_y, &pub_x, &nonce_d, &mut msg_d).is_err());

            Ok(())
        }

        #[test]
        fn enc_and_dec_precalculated() -> Result<(), AlkaliError> {
            let (priv_x, _) = generate_keypair()?;
            let (_, pub_y) = generate_keypair()?;
            let key = precalculate_shared_key(&priv_x, &pub_y)?;

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

            let (nonce_a, l_a) = encrypt_precalculated(&msg_a, &key, &mut c_a)?;
            let (nonce_b, l_b) = encrypt_precalculated(&msg_b, &key, &mut c_b)?;
            let (nonce_c, l_c) = encrypt_precalculated(&msg_c, &key, &mut c_c)?;
            let (nonce_d, l_d) = encrypt_precalculated(&msg_d, &key, &mut c_d)?;

            assert_eq!(l_a, MAC_LENGTH);
            assert_eq!(l_b, 16 + MAC_LENGTH);
            assert_eq!(l_c, 1024 + MAC_LENGTH);
            assert_eq!(l_d, (1 << 18) + MAC_LENGTH);

            decrypt_precalculated(&c_a, &key, &nonce_a, &mut msg_a)?;
            decrypt_precalculated(&c_b, &key, &nonce_b, &mut msg_b)?;
            decrypt_precalculated(&c_c, &key, &nonce_c, &mut msg_c)?;
            decrypt_precalculated(&c_d, &key, &nonce_d, &mut msg_d)?;

            fill_random(&mut c_a)?;
            fill_random(&mut c_b)?;
            fill_random(&mut c_c)?;
            fill_random(&mut c_d)?;

            assert!(decrypt_precalculated(&c_a, &key, &nonce_a, &mut msg_a).is_err());
            assert!(decrypt_precalculated(&c_b, &key, &nonce_b, &mut msg_b).is_err());
            assert!(decrypt_precalculated(&c_c, &key, &nonce_c, &mut msg_c).is_err());
            assert!(decrypt_precalculated(&c_d, &key, &nonce_d, &mut msg_d).is_err());

            Ok(())
        }

        #[test]
        fn enc_and_dec_detached_precalculated() -> Result<(), AlkaliError> {
            let (priv_x, _) = generate_keypair()?;
            let (_, pub_y) = generate_keypair()?;
            let key = precalculate_shared_key(&priv_x, &pub_y)?;

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

            let (nonce_a, mut mac_a) = encrypt_detached_precalculated(&msg_a, &key, &mut c_a)?;
            let (nonce_b, mac_b) = encrypt_detached_precalculated(&msg_b, &key, &mut c_b)?;
            let (nonce_c, mac_c) = encrypt_detached_precalculated(&msg_c, &key, &mut c_c)?;
            let (nonce_d, mac_d) = encrypt_detached_precalculated(&msg_d, &key, &mut c_d)?;

            decrypt_detached_precalculated(&c_a, &mac_a, &key, &nonce_a, &mut msg_a)?;
            decrypt_detached_precalculated(&c_b, &mac_b, &key, &nonce_b, &mut msg_b)?;
            decrypt_detached_precalculated(&c_c, &mac_c, &key, &nonce_c, &mut msg_c)?;
            decrypt_detached_precalculated(&c_d, &mac_d, &key, &nonce_d, &mut msg_d)?;

            fill_random(&mut mac_a)?;
            fill_random(&mut c_b)?;
            fill_random(&mut c_c)?;
            fill_random(&mut c_d)?;

            assert!(
                decrypt_detached_precalculated(&c_a, &mac_a, &key, &nonce_a, &mut msg_a).is_err()
            );
            assert!(
                decrypt_detached_precalculated(&c_b, &mac_b, &key, &nonce_b, &mut msg_b).is_err()
            );
            assert!(
                decrypt_detached_precalculated(&c_c, &mac_c, &key, &nonce_c, &mut msg_c).is_err()
            );
            assert!(
                decrypt_detached_precalculated(&c_d, &mac_d, &key, &nonce_d, &mut msg_d).is_err()
            );

            Ok(())
        }

        #[test]
        fn test_vectors() -> Result<(), AlkaliError> {
            let mut priv_a = PrivateKey::new_empty()?;
            let mut priv_b = PrivateKey::new_empty()?;

            $(
                priv_a.copy_from_slice(&$priv_a);
                priv_b.copy_from_slice(&$priv_b);
                let pub_a = priv_a.public_key()?;
                let pub_b = priv_b.public_key()?;

                let mut c = vec![0; $msg.len() + MAC_LENGTH];
                assert_eq!(
                    encrypt_with_nonce(&$msg, &priv_a, &pub_b, &$nonce, &mut c)?,
                    $msg.len() + MAC_LENGTH
                );
                assert_eq!(&c[..MAC_LENGTH], &$mac[..]);
                assert_eq!(&c[MAC_LENGTH..], &$c[..]);

                let mut m = vec![0; $msg.len()];
                assert_eq!(decrypt(&c, &priv_b, &pub_a, &$nonce, &mut m)?, $msg.len());
                assert_eq!(&m, &$msg);
            )*

            Ok(())
        }

        #[test]
        fn test_vectors_detached() -> Result<(), AlkaliError> {
            let mut priv_a = PrivateKey::new_empty()?;
            let mut priv_b = PrivateKey::new_empty()?;

            $(
                priv_a.copy_from_slice(&$priv_a);
                priv_b.copy_from_slice(&$priv_b);
                let pub_a = priv_a.public_key()?;
                let pub_b = priv_b.public_key()?;

                let mut c = vec![0; $msg.len()];
                let mac = encrypt_detached_with_nonce(&$msg, &priv_a, &pub_b, &$nonce, &mut c)?;
                assert_eq!(&c, &$c);
                assert_eq!(&mac, &$mac);

                let mut m = vec![0; $msg.len()];
                decrypt_detached(&c, &mac, &priv_b, &pub_a, &$nonce, &mut m)?;
                assert_eq!(&m, &$msg);
            )*

            Ok(())
        }

        #[test]
        fn test_vectors_precalculated() -> Result<(), AlkaliError> {
            let mut priv_a = PrivateKey::new_empty()?;
            let mut priv_b = PrivateKey::new_empty()?;

            $(
                priv_a.copy_from_slice(&$priv_a);
                priv_b.copy_from_slice(&$priv_b);
                let pub_a = priv_a.public_key()?;
                let pub_b = priv_b.public_key()?;

                let mut c = vec![0; $msg.len() + MAC_LENGTH];
                let key = precalculate_shared_key(&priv_a, &pub_b)?;
                assert_eq!(
                    encrypt_with_nonce_precalculated(&$msg, &key, &$nonce, &mut c)?,
                    $msg.len() + MAC_LENGTH
                );
                assert_eq!(&c[..MAC_LENGTH], &$mac);
                assert_eq!(&c[MAC_LENGTH..], &$c);

                let mut m = vec![0; $msg.len()];
                let key = precalculate_shared_key(&priv_b, &pub_a)?;
                assert_eq!(decrypt_precalculated(&c, &key, &$nonce, &mut m)?, $msg.len());
                assert_eq!(&m, &$msg);
            )*

            Ok(())
        }

        #[test]
        fn test_vectors_detached_precalculated() -> Result<(), AlkaliError> {
            let mut priv_a = PrivateKey::new_empty()?;
            let mut priv_b = PrivateKey::new_empty()?;

            $(
                priv_a.copy_from_slice(&$priv_a);
                priv_b.copy_from_slice(&$priv_b);
                let pub_a = priv_a.public_key()?;
                let pub_b = priv_b.public_key()?;

                let mut c = vec![0; $msg.len()];
                let key = precalculate_shared_key(&priv_a, &pub_b)?;
                let mac = encrypt_detached_with_nonce_precalculated(&$msg, &key, &$nonce, &mut c)?;
                assert_eq!(&c, &$c);
                assert_eq!(&mac, &$mac);

                let mut m = vec![0; $msg.len()];
                let key = precalculate_shared_key(&priv_b, &pub_a)?;
                decrypt_detached_precalculated(&c, &mac, &key, &$nonce, &mut m)?;
                assert_eq!(&m, &$msg);
            )*

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

            let (private_key_a, public_key_a) = generate_keypair_from_seed(&seed_a)?;
            let (private_key_b, public_key_b) = generate_keypair_from_seed(&seed_b)?;

            let shared_x = precalculate_shared_key(&private_key_a, &public_key_b)?;
            let shared_y = precalculate_shared_key(&private_key_b, &public_key_a)?;

            assert_eq!(shared_x, shared_y);
            assert_eq!(
                &shared_x[..],
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

/// This implementation uses [X25519](https://en.wikipedia.org/wiki/Curve25519) (Elliptic-Curve
/// Diffie-Hellman over Curve25519) to establish a shared secret key for encryption/decryption. The
/// [XChaCha20](https://en.wikipedia.org/wiki/Salsa20##ChaCha_variant) cipher is used to perform
/// encryption/decryption, with the [Poly1305](https://en.wikipedia.org/wiki/Poly1305) MAC for
/// authentication.
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

            let (private_key_a, public_key_a) = generate_keypair_from_seed(&seed_a)?;
            let (private_key_b, public_key_b) = generate_keypair_from_seed(&seed_b)?;

            let shared_x = precalculate_shared_key(&private_key_a, &public_key_b)?;
            let shared_y = precalculate_shared_key(&private_key_b, &public_key_a)?;

            assert_eq!(shared_x, shared_y);
            assert_eq!(
                &shared_x[..],
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
