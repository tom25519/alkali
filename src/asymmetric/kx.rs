//! [Key exchange](https://en.wikipedia.org/wiki/Key_exchange).
//!
//! This module corresponds to the [`crypto_kx` API](https://doc.libsodium.org/key_exchange) from
//! Sodium.
//!
//! Key exchange is used to establish a secret value, usually a key, between two parties
//! communicating exclusively over insecure channels. That is, an attacker can observe all messages
//! between both parties, and still cannot calculate the shared secret, even though the parties
//! communicating have not previously agreed any secret information.
//!
//! Key exchange is most commonly used to establish a key for symmetric encryption as part of a
//! [hybrid cryptosystem](https://en.wikipedia.org/wiki/Hybrid_cryptosystem). This is what the
//! [`asymmetric::cipher`](crate::asymmetric::cipher) module does, so if you just need to exchange
//! encrypted messages with another party using their public key, this is probably your best option.
//! Use cases which actually require using the `kx` module are quite rare.
//!
//! In this particular API, one party takes the role of a client, and the other of a server. The key
//! exchange outputs two keys, one for sending messages from the client to the server, and one for
//! sending message from the server to the client. Both parties know both keys: the server's
//! transmission key is equal to the client's receive key, and vice-versa.
//!
//! # Algorithm Details
//! [X25519](https://cr.yp.to/ecdh.html) (Elliptic-Curve Diffie-Hellman over Curve25519) is used to
//! establish a secret shared point `P` on an elliptic curve. Keys suitable for use in symmetric
//! cryptography are then calculated as follows, using the [BLAKE2b](https://www.blake2.net/) hash
//! function, where `||` denotes concatenation:
//!
//! ```text
//! rx || tx = BLAKE2B-512(P || Client Public Key || Server Public Key)
//! ```
//!
//! # Security Considerations
//! Needing to manually perform a key exchange using this API should be rare when using Sodium, as
//! other APIs exist which are more suited to specific tasks requiring you to establish a shared
//! secret. For example, if you want to encrypt messages for another party using their public key,
//! the [`asymmetric::cipher`](crate::asymmetric::cipher) API is well suited to this: It will
//! perform the process described above of establishing a shared secret via key exchange, and then
//! using a symmetric cipher to actually encrypt messages, and is harder to misuse than implementing
//! this process yourself.
//!
//! The [`PrivateKey`] type stores the private key *unclamped* in memory. While the implementation
//! always clamps it before use, other implementations may not do so, so if you choose to use keys
//! generated here outside of Sodium, it must be clamped: See [this
//! article](https://neilmadden.blog/2020/05/28/whats-the-curve25519-clamping-all-about/) for more
//! information on the procedure.
//!
//! The key exchange process here is deterministic: The same keypairs performing a key exchange will
//! always derive the same session keys. This means that if either party's private key is ever
//! disclosed, an attacker will have access to the session key calculated in every previous
//! exchange. Plus, if a session key is ever disclosed, this is the same key that will be calculated
//! in all future key exchanges. In short, if using a long-term keypair to perform key exchanges,
//! the cryptosystem will lack [perfect forward
//! secrecy](https://en.wikipedia.org/wiki/Forward_secrecy). A solution to this is to generate a new
//! (ephemeral) keypair for every key exchange, and verify it is yours by signing it + a nonce with
//! a long-term key, rather than using the long-term key for the key exchange, but this is outside
//! the scope of this library.
//!
//! ## Secret Data
//! * Private keys ([`PrivateKey`]) must be kept secret
//! * A [`Keypair`] contains a [`PrivateKey`], and as such, should also be kept secret
//! * Seeds ([`Seed`]) must be kept secret
//! * Session keys ([`TransmitKey`] and [`ReceiveKey`]) must be kept secret
//!
//! ## Non-Secret Data
//! * Public keys ([`PublicKey`]) can (and should) be made public
//!
//! # Examples
//! Client-side (using [`Keypair::client_keys`]):
//!
//! ```rust
//! use alkali::asymmetric::kx;
//!
//! let client_keypair = kx::Keypair::generate().unwrap();
//! # let server_keypair = kx::Keypair::generate().unwrap();
//! # let server_pub = server_keypair.public_key;
//!
//! // We assume that the server's public key, `server_pub`, has been distributed to this client.
//!
//! let (tx, rx) = client_keypair.client_keys(&server_pub).unwrap();
//!
//! // We can now send data to the server encrypted with `tx`, and receive data encrypted with `rx`.
//! ```
//!
//! Server-side (using [`Keypair::server_keys`]):
//!
//! ```rust
//! use alkali::asymmetric::kx;
//!
//! let server_keypair = kx::Keypair::generate().unwrap();
//! # let client_keypair = kx::Keypair::generate().unwrap();
//! # let client_pub = client_keypair.public_key;
//!
//! // We assume that the client's public key, `client_pub`, has been sent to this server.
//!
//! let (tx, rx) = server_keypair.server_keys(&client_pub).unwrap();
//!
//! // The `tx` key here should be equal to the `rx` key calculated by the client, and the `rx` key
//! // here should be equal to the `tx` key calculated by the client.
//! ```

crate::error_type! {
    /// Error type returned if something went wrong in the `kx` module.
    KeyExchangeError {
        /// The other party's keypair is unacceptable, and should not be used for cryptographic
        /// purposes.
        PublicKeyUnacceptable,
    }
}

/// The [X25519](https://cr.yp.to/ecdh.html) key exchange, together with the
/// [BLAKE2b](https://www.blake2.net/) hash function.
pub mod x25519blake2b {
    use super::KeyExchangeError;
    use crate::{assert_not_err, mem, require_init, AlkaliError};
    use libsodium_sys as sodium;

    /// The length of a private key for key exchange, in bytes.
    pub const PRIVATE_KEY_LENGTH: usize = sodium::crypto_kx_SECRETKEYBYTES as usize;

    /// The length of a public key for key exchange, in bytes.
    pub const PUBLIC_KEY_LENGTH: usize = sodium::crypto_kx_PUBLICKEYBYTES as usize;

    /// The length of a session key, derived from a key exchange between two parties, in bytes.
    pub const SESSION_KEY_LENGTH: usize = sodium::crypto_kx_SESSIONKEYBYTES as usize;

    /// The length of a seed to use for the deterministic generation of a [`Keypair`].
    pub const KEY_SEED_LENGTH: usize = sodium::crypto_kx_SEEDBYTES as usize;

    mem::hardened_buffer! {
        /// A private key used by a party in a key exchange.
        ///
        /// A private key forms one half of a [`Keypair`], together with a [`PublicKey`].
        ///
        /// There are no technical constraints on the contents of a private key for this API. Keys
        /// are
        /// [clamped](https://neilmadden.blog/2020/05/28/whats-the-curve25519-clamping-all-about/)
        /// at time of usage, not when generated, so a private key can just be any random sequence
        /// of bytes. However, private keys should be indistinguishable from random noise, and
        /// should really be generated randomly using [`Keypair::generate`]. If you need to derive a
        /// private key deterministically, use [`Keypair::from_seed`].
        ///
        /// A private key is secret, and as such, should not ever be made public.
        ///
        /// This is a [hardened buffer type](https://docs.rs/alkali#hardened-buffer-types), and will
        /// be zeroed on drop. A number of other security measures are taken to protect its
        /// contents. This type in particular can be thought of as roughly equivalent to a `[u8;
        /// PRIVATE_KEY_LENGTH]`, and implements [`core::ops::Deref`], so it can be used like it is
        /// an `&[u8]`. This struct uses heap memory while in scope, allocated using Sodium's
        /// [secure memory utilities](https://doc.libsodium.org/memory_management).
        ///
        /// # Security Considerations
        /// In this API, private keys are stored *unclamped*. If you intend to use this private key
        /// with a different X25519 implementation, it may need to be clamped before use.
        pub PrivateKey(PRIVATE_KEY_LENGTH);

        /// A "transmit" session key derived from a key exchange.
        ///
        /// This key should be used to send messages to the other party. It is equal to the other
        /// party's [`ReceiveKey`].
        ///
        /// Session keys must not be made public.
        ///
        /// This is a [hardened buffer type](https://docs.rs/alkali#hardened-buffer-types), and will
        /// be zeroed on drop. A number of other security measures are taken to protect its
        /// contents. This type in particular can be thought of as roughly equivalent to a `[u8;
        /// SESSION_KEY_LENGTH]`, and implements [`core::ops::Deref`], so it can be used like it is
        /// an `&[u8]`. This struct uses heap memory while in scope, allocated using Sodium's
        /// [secure memory utilities](https://doc.libsodium.org/memory_management).
        pub TransmitKey(SESSION_KEY_LENGTH);

        /// A "receive" session key derived from a key exchange.
        ///
        /// This key should be used to receive messages sent by the other party. It is equal to the
        /// other party's [`TransmitKey`].
        ///
        /// Session keys must not be made public.
        ///
        /// This is a [hardened buffer type](https://docs.rs/alkali#hardened-buffer-types), and will
        /// be zeroed on drop. A number of other security measures are taken to protect its
        /// contents. This type in particular can be thought of as roughly equivalent to a `[u8;
        /// SESSION_KEY_LENGTH]`, and implements [`core::ops::Deref`], so it can be used like it is
        /// an `&[u8]`. This struct uses heap memory while in scope, allocated using Sodium's
        /// [secure memory utilities](https://doc.libsodium.org/memory_management).
        pub ReceiveKey(SESSION_KEY_LENGTH);

        /// A seed used to deterministically derive a [`Keypair`].
        ///
        /// A seed can be used with [`Keypair::from_seed`] to deterministically derive a private key
        /// and public key.
        ///
        /// If a keypair derived from a seed is to be used for real-world operations, the seed
        /// should be treated as securely as the private key itself, since it is trivial to derive
        /// the private key given the seed. So, do not make seeds public.
        ///
        /// This is a [hardened buffer type](https://docs.rs/alkali#hardened-buffer-types), and will
        /// be zeroed on drop. A number of other security measures are taken to protect its
        /// contents. This type in particular can be thought of as roughly equivalent to a `[u8;
        /// SESSION_KEY_LENGTH]`, and implements [`core::ops::Deref`], so it can be used like it is
        /// an `&[u8]`. This struct uses heap memory while in scope, allocated using Sodium's
        /// [secure memory utilities](https://doc.libsodium.org/memory_management).
        pub Seed(KEY_SEED_LENGTH);
    }

    /// A public key used as part of key exchange.
    ///
    /// A public key forms one half of a [`Keypair`], together with a [`PrivateKey`].
    ///
    /// A public key should be made public, unlike a private key, which must be kept secret.
    pub type PublicKey = [u8; PUBLIC_KEY_LENGTH];

    /// A ([`PrivateKey`], [`PublicKey`]) keypair, used for key exchange.
    ///
    /// The private key must be kept secret, while the public key can be made public.
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    pub struct Keypair {
        /// The private key for this keypair.
        pub private_key: PrivateKey,

        /// The public key corresponding to the private key.
        pub public_key: PublicKey,
    }

    impl Keypair {
        /// Generate a new, random X25519 keypair for use in key exchange.
        ///
        /// A keypair consists of a [`PrivateKey`], which must be kept secret, and a [`PublicKey`],
        /// which should be made public.
        pub fn generate() -> Result<Self, AlkaliError> {
            require_init()?;

            let mut private_key = PrivateKey::new_empty()?;
            let mut public_key = [0u8; PUBLIC_KEY_LENGTH];

            let keypair_result = unsafe {
                // SAFETY: This function expects a pointer to a region of memory sufficient to store
                // a public key, and a pointer to a region of memory sufficient to store a private
                // key for this algorithm. We have defined the `PublicKey` type to be
                // `crypto_kx_PUBLICKEYBYTES`, the length of a public key for this algorithm, so it
                // is of sufficient size to store the public key. The `PrivateKey` type allocates
                // `crypto_kx_SECRETKEYBYTES`, the length of a private key for this algorithm, so it
                // is of sufficient size to store the private key. Any region of memory can be a
                // valid representation of a `u8` array, so both variables will still be valid after
                // this function call. The `PrivateKey::inner_mut` method simply returns a mutable
                // pointer to its backing memory.
                sodium::crypto_kx_keypair(
                    public_key.as_mut_ptr(),
                    private_key.inner_mut() as *mut libc::c_uchar,
                )
            };
            assert_not_err!(keypair_result, "crypto_kx_keypair");

            Ok(Self {
                private_key,
                public_key,
            })
        }

        /// Deterministically derive an X25519 keypair for use in key exchange from a seed.
        ///
        /// Given the same seed, the same keypair will always be generated.
        ///
        /// A keypair consists of a [`PrivateKey`], which must be kept secret, and a [`PublicKey`],
        /// which should be made public.
        pub fn from_seed(seed: &Seed) -> Result<Self, AlkaliError> {
            require_init()?;

            let mut private_key = PrivateKey::new_empty()?;
            let mut public_key = [0u8; PUBLIC_KEY_LENGTH];

            let keypair_result = unsafe {
                // SAFETY: This function expects a pointer to a region of memory sufficient to store
                // a public key, a pointer to a region of memory sufficient to store a private key,
                // and a pointer to a seed. We have defined the `PublicKey` type to be
                // `crypto_kx_PUBLICKEYBYTES`, so it is of sufficient size to store the public key.
                // The `PrivateKey` type allocates `crypto_kx_SECRETKEYBYTES`, the length of a
                // private key for this algorithm, so it is of sufficient size to store the private
                // key. Any region of memory can be a valid representation of a `u8` array, so both
                // variables will still be valid after this function call. The
                // `PrivateKey::inner_mut` method simply returns a mutable pointer to its backing
                // memory. The `Seed` type is defined to be `crypto_kx_SEEDBYTES`, and is therefore
                // valid for reads of the length required for a seed for this algorithm. The
                // `Seed::inner` method simply returns an immutable pointer to its backing memory.
                sodium::crypto_kx_seed_keypair(
                    public_key.as_mut_ptr(),
                    private_key.inner_mut() as *mut libc::c_uchar,
                    seed.inner() as *const libc::c_uchar,
                )
            };
            assert_not_err!(keypair_result, "crypto_kx_seed_keypair");

            Ok(Self {
                private_key,
                public_key,
            })
        }

        /// Construct a keypair given just the [`PrivateKey`].
        ///
        /// A keypair consists of a [`PrivateKey`] and a [`PublicKey`]. This function calculates the
        /// public key associated with the provided private key and stores both in a [`Keypair`].
        /// This is useful if you know your private key, but don't have the corresponding public
        /// key.
        pub fn from_private_key(private_key: &PrivateKey) -> Result<Self, AlkaliError> {
            require_init()?;

            let mut public_key = [0u8; PUBLIC_KEY_LENGTH];

            let scalarmult_result = unsafe {
                // SAFETY: This function expects a pointer to a region of memory sufficient to store
                // a point on Curve25519, and a pointer to a scalar by which the generator of
                // Curve25519 should be multiplied. We have defined the `PublicKey` type to be
                // `crypto_kx_PUBLICKEYBYTES`, which is equal to `crypto_scalarmult_BYTES`, the
                // length of the Curve25519 point outputted by this multiplication, so it is of
                // sufficient size to store the output here. Any region of memory can be a valid
                // representation of a `u8` array, so the `public_key` variable will still be valid
                // after this function call. The `PrivateKey` type allocates
                // `crypto_kx_SECRETKEYBYTES` of storage, which is equal to
                // `crypto_scalarmult_SCALARBYTES`, the length of a scalar for this multiplication,
                // so it is valid for reads of the expected size. The `PrivateKey::inner` method
                // simply returns an immutable pointer to its backing memory.
                sodium::crypto_scalarmult_curve25519_base(
                    public_key.as_mut_ptr(),
                    private_key.inner() as *const libc::c_uchar,
                )
            };
            assert_not_err!(scalarmult_result, "crypto_scalarmult_curve25519_base");

            Ok(Self {
                private_key: private_key.try_clone()?,
                public_key,
            })
        }

        /// Calculate session keys, treating this keypair as the client and the other party as the
        /// server.
        ///
        /// `server_pub` should be the public key of the other party, who will play the role of the
        /// server in this key exchange.
        ///
        /// Returns `(client_tx, client_rx)`, two session keys. The first is intended to be used to
        /// send messages to the server, the second is intended to receive messages from the server.
        /// If the other party calculates their server session keys using our public key, their
        /// `server_tx` will be equal to our `client_rx`, and their `server_rx` will be equal to our
        /// `client_tx`.
        pub fn client_keys(
            &self,
            server_pub: &PublicKey,
        ) -> Result<(TransmitKey, ReceiveKey), AlkaliError> {
            require_init()?;

            let mut tx = TransmitKey::new_empty()?;
            let mut rx = ReceiveKey::new_empty()?;

            let kx_result = unsafe {
                // SAFETY: The first argument to this function is the destination to which the
                // "receive" key should be written. The second argument is the destination to which
                // the "transmit" key should be written. `crypto_kx_SESSIONKEYBYTES` will be written
                // to each pointer. Both the `TransmitKey` and `ReceiveKey` types are defined to
                // allocate this much storage, and thus are valid for writes of this length. The
                // `TransmitKey::inner_mut` and `ReceiveKey::inner_mut` methods both simply return a
                // mutable pointer to their backing memory. The next argument should be a pointer to
                // the client's public key. We define the `PublicKey` type to be
                // `crypto_kx_PUBLICKEYBYTES`, the expected size of a public key for this algorithm,
                // so it is valid for reads of the required length. The next argument should be a
                // pointer to the client's private key. We define the `PrivateKey` type to allocate
                // `crypto_kx_SECRETKEYBYTES`, the expected size of a private key for this
                // algorithm, so it is also valid for reads of the required length. The
                // `PrivateKey::inner` method simply returns an immutable pointer to its backing
                // memory. The final argument should be a pointer to the server's public key, again
                // of `crypto_kx_PUBLICKEYBYTES` in length. We once again use a `PublicKey` type
                // here.
                sodium::crypto_kx_client_session_keys(
                    rx.inner_mut() as *mut libc::c_uchar,
                    tx.inner_mut() as *mut libc::c_uchar,
                    self.public_key.as_ptr(),
                    self.private_key.inner() as *const libc::c_uchar,
                    server_pub.as_ptr(),
                )
            };

            if kx_result == 0 {
                Ok((tx, rx))
            } else {
                Err(KeyExchangeError::PublicKeyUnacceptable.into())
            }
        }

        /// Calculate session keys, treating this keypair as the server and the other party as the
        /// client.
        ///
        /// `client_pub` should be the public key of the other party, who will play the role of the
        /// client in this key exchange.
        ///
        /// Returns `(server_tx, server_rx)`, two session keys. The first is intended to be used to
        /// send messages to the client, the second is intended to receive messages from the client.
        /// If the other party calculates their client session keys using our public key, their
        /// `client_tx` will be equal to our `server_rx`, and their `client_rx` will be equal to our
        /// `server_tx`.
        pub fn server_keys(
            &self,
            client_pub: &PublicKey,
        ) -> Result<(TransmitKey, ReceiveKey), AlkaliError> {
            require_init()?;

            let mut tx = TransmitKey::new_empty()?;
            let mut rx = ReceiveKey::new_empty()?;

            let kx_result = unsafe {
                // SAFETY: The first argument to this function is the destination to which the
                // "receive" key should be written. The second argument is the destination to which
                // the "transmit" key should be written. `crypto_kx_SESSIONKEYBYTES` will be written
                // to each pointer. Both the `TransmitKey` and `ReceiveKey` types are defined to
                // allocate this much storage, and thus are valid for writes of this length. The
                // `TransmitKey::inner_mut` and `ReceiveKey::inner_mut` methods both simply return a
                // mutable pointer to their backing memory. The next argument should be a pointer to
                // the server's public key. We define the `PublicKey` type to be
                // `crypto_kx_PUBLICKEYBYTES`, the expected size of a public key for this algorithm,
                // so it is valid for reads of the required length. The next argument should be a
                // pointer to the server's private key. We define the `PrivateKey` type to allocate
                // `crypto_kx_SECRETKEYBYTES`, the expected size of a private key for this
                // algorithm, so it is also valid for reads of the required length. The
                // `PrivateKey::inner` method simply returns an immutable pointer to its backing
                // memory. The final argument should be a pointer to the client's public key, again
                // of `crypto_kx_PUBLICKEYBYTES` in length. We once again use a `PublicKey` type
                // here.
                sodium::crypto_kx_server_session_keys(
                    rx.inner_mut() as *mut libc::c_uchar,
                    tx.inner_mut() as *mut libc::c_uchar,
                    self.public_key.as_ptr(),
                    self.private_key.inner() as *const libc::c_uchar,
                    client_pub.as_ptr(),
                )
            };

            if kx_result == 0 {
                Ok((tx, rx))
            } else {
                Err(KeyExchangeError::PublicKeyUnacceptable.into())
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::{Keypair, Seed};
        use crate::AlkaliError;

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
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
                0x1c, 0x1d, 0x1e, 0x1f,
            ])?;
            let keypair = Keypair::from_seed(&seed)?;

            assert_eq!(
                &keypair.private_key[..],
                &[
                    0xcb, 0x2f, 0x51, 0x60, 0xfc, 0x1f, 0x7e, 0x05, 0xa5, 0x5e, 0xf4, 0x9d, 0x34,
                    0x0b, 0x48, 0xda, 0x2e, 0x5a, 0x78, 0x09, 0x9d, 0x53, 0x39, 0x33, 0x51, 0xcd,
                    0x57, 0x9d, 0xd4, 0x25, 0x3, 0xd6
                ]
            );
            assert_eq!(
                &keypair.public_key,
                &[
                    0x0e, 0x02, 0x16, 0x22, 0x3f, 0x14, 0x71, 0x43, 0xd3, 0x26, 0x15, 0xa9, 0x11,
                    0x89, 0xc2, 0x88, 0xc1, 0x72, 0x8c, 0xba, 0x3c, 0xc5, 0xf9, 0xf6, 0x21, 0xb1,
                    0x02, 0x6e, 0x03, 0xd8, 0x31, 0x29
                ]
            );

            let keypair_new = Keypair::from_private_key(&keypair.private_key)?;
            assert_eq!(keypair.public_key, keypair_new.public_key);

            Ok(())
        }

        #[test]
        fn test_vectors() -> Result<(), AlkaliError> {
            let client_seed = Seed::try_from(&[
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
                0x1c, 0x1d, 0x1e, 0x1f,
            ])?;
            let server_seed = Seed::try_from(&[
                0x01, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
                0x1c, 0x1d, 0x1e, 0x1f,
            ])?;
            let client_keypair = Keypair::from_seed(&client_seed)?;
            let server_keypair = Keypair::from_seed(&server_seed)?;

            let (client_tx, client_rx) = client_keypair.client_keys(&server_keypair.public_key)?;

            assert_eq!(
                &client_tx[..],
                &[
                    0x62, 0xc8, 0xf4, 0xfa, 0x81, 0x80, 0x0a, 0xbd, 0x05, 0x77, 0xd9, 0x99, 0x18,
                    0xd1, 0x29, 0xb6, 0x5d, 0xeb, 0x78, 0x9a, 0xf8, 0xc8, 0x35, 0x1f, 0x39, 0x1f,
                    0xeb, 0x0c, 0xbf, 0x23, 0x86, 0x04
                ]
            );
            assert_eq!(
                &client_rx[..],
                &[
                    0x74, 0x95, 0x19, 0xc6, 0x80, 0x59, 0xbc, 0xe6, 0x9f, 0x7c, 0xfc, 0xc7, 0xb3,
                    0x87, 0xa3, 0xde, 0x1a, 0x1e, 0x82, 0x37, 0xd1, 0x10, 0x99, 0x13, 0x23, 0xbf,
                    0x62, 0x87, 0x01, 0x15, 0x73, 0x1a,
                ]
            );

            let (server_tx, server_rx) = server_keypair.server_keys(&client_keypair.public_key)?;
            assert_eq!(&server_tx[..], &client_rx[..]);
            assert_eq!(&server_rx[..], &client_tx[..]);

            Ok(())
        }

        #[test]
        fn reject_weak_key() -> Result<(), AlkaliError> {
            let weak_public_key = [
                0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f,
                0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16,
                0x5f, 0x49, 0xb8, 0x00,
            ];

            let keypair = Keypair::generate()?;

            assert!(keypair.client_keys(&weak_public_key).is_err());
            assert!(keypair.server_keys(&weak_public_key).is_err());

            Ok(())
        }

        #[test]
        fn random_exchanges() -> Result<(), AlkaliError> {
            for _ in 0..100 {
                let client = Keypair::generate()?;
                let server = Keypair::generate()?;

                let (client_tx, client_rx) = client.client_keys(&server.public_key)?;
                let (server_tx, server_rx) = server.server_keys(&client.public_key)?;

                assert_eq!(&client_tx[..], &server_rx[..]);
                assert_eq!(&client_rx[..], &server_tx[..]);
            }

            Ok(())
        }
    }
}

pub use x25519blake2b::*;
