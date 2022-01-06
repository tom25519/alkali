//! Key exchange.
//!
//! This module corresponds to the [`crypto_kx` API](https://doc.libsodium.org/key_exchange) from
//! Sodium.
//!
//! Key exchange is used to establish a secret between two parties communicating exclusively over
//! insecure channels. That is, an attacker can observe all messages between both parties, and
//! still cannot calculate the shared secret, even though the parties communicating have not
//! previously agreed any secret information.
//!
//! Key exchange is often used to establish a key for symmetric encryption, as this is faster than
//! many entirely asymmetric ciphers (e.g: RSA).
//!
//! In this specific API, one party takes the role of the client, and the other of the server.
//! The key exchange produces two keys, one for sending messages from the client to the server, and
//! one for sending message from the server to the client. Both parties know both keys: the
//! server's transmission key is equal to the client's receive key, and vice-versa.
//!
//! # Algorithm Details
//! [X25519](https://cr.yp.to/ecdh.html) (Elliptic-Curve Diffie-Hellman over Curve25519) is used to
//! establish a secret shared point `P` on an elliptic curve. Keys suitable for use in symmetric
//! cryptography are then calculated as follows, using the [BLAKE2b](https://www.blake2.net/) hash
//! algorithm, where `||` denotes concatenation:
//!
//! ```text
//! rx || tx = BLAKE2B-512(P || Client Public Key || Server Public Key)
//! ```
//!
//! # Security Considerations
//! If you just want to send messages between two parties, who have not yet established a shared
//! secret, over an insecure channel, the [`asymmetric::box_`](crate::asymmetric::box_) API is more
//! suitable for this: It does the process described above of establishing a shared secret via key
//! exchange, and then using a symmetric cipher to actually encrypt messages.
//!
//! The [`PrivateKey`] type stores the private key *unclamped* in memory. While the implementation
//! always clamps it before use, other implementations may not do so, so if you choose to use keys
//! generated here outside of Sodium, it must be clamped: See [this
//! article](https://neilmadden.blog/2020/05/28/whats-the-curve25519-clamping-all-about/) for more
//! information on the procedure.
//!
//! # Examples
//! Client-side (using [`derive_client_keys`]):
//!
//! ```rust
//! use alkali::asymmetric::kx;
//!
//! let (client_priv, client_pub) = kx::generate_keypair().unwrap();
//! # let (_, server_pub) = kx::generate_keypair().unwrap();
//!
//! // get the server's public key, `server_pub`, somehow
//!
//! let (rx, tx) = kx::derive_client_keys(&client_priv, &client_pub, &server_pub).unwrap();
//!
//! // we can now send data to the server encrypted with tx, and receive data encrypted with rx
//! ```
//!
//! Server-side (using [`derive_server_keys`]):
//!
//! ```rust
//! use alkali::asymmetric::kx;
//!
//! let (server_priv, server_pub) = kx::generate_keypair().unwrap();
//! # let (_, client_pub) = kx::generate_keypair().unwrap();
//!
//! // get the client's public key, `client_pub`, somehow
//!
//! let (rx, tx) = kx::derive_server_keys(&server_priv, &server_pub, &client_pub).unwrap();
//!
//! // we can now send data to the client encrypted with tx, and receive data encrypted with rx
//! ```

use crate::{hardened_buffer, require_init, AlkaliError};
use libsodium_sys as sodium;
use thiserror::Error;

/// Error type returned if something went wrong in the kx module.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum KeyExchangeError {
    /// A public key used in the key exchange is weak (likely of low order), and should not be used
    /// for cryptographic purposes.
    #[error("insecure public key")]
    PublicKeyInsecure,
}

/// The length of a private key for key exchange, in bytes.
pub const PRIVATE_KEY_LENGTH: usize = sodium::crypto_kx_SECRETKEYBYTES as usize;

/// The length of a public key for key exchange, in bytes.
pub const PUBLIC_KEY_LENGTH: usize = sodium::crypto_kx_PUBLICKEYBYTES as usize;

/// The length of a session key, derived from a key exchange between two parties, in bytes.
pub const SESSION_KEY_LENGTH: usize = sodium::crypto_kx_SESSIONKEYBYTES as usize;

/// The length of a seed to use for the deterministic generation of a (private key, public key)
/// pair.
pub const KEY_SEED_LENGTH: usize = sodium::crypto_kx_SEEDBYTES as usize;

hardened_buffer! {
    /// A private key used by a party in a key exchange.
    ///
    /// There are no technical constraints on the contents of a key, since for this algorithm,
    /// clamping is implemented when keys are used rather than generated, but the keypair should be
    /// generated randomly using [`generate_keypair`].
    ///
    /// A private key is secret, and as such, should not ever be made public.
    ///
    /// This is a [hardened buffer type](https://docs.rs/alkali#hardened-buffer-types), and will be
    /// zeroed on drop. A number of other security measures are taken to protect its contents.
    PrivateKey(PRIVATE_KEY_LENGTH);

    /// The session key derived from a key exchange.
    ///
    /// This session key type is 32 bytes = 256 bits long, and is therefore suitable for use as a
    /// key in many symmetric algorithms.
    ///
    /// This is a [hardened buffer type](https://docs.rs/alkali#hardened-buffer-types), and will be
    /// zeroed on drop. A number of other security measures are taken to protect its contents.
    SessionKey(SESSION_KEY_LENGTH);

    /// A seed used to deterministically derive a (private, public) keypair.
    ///
    /// If a private key derived from a seed is used for real-world operations, the seed should be
    /// treated as securely as the private key itself, since it is trivial to derive the private
    /// key given the seed. Ideally, a seed used in this case would be discarded immediately after
    /// key generation.
    ///
    /// For testing purposes, these concerns obviously do not apply.
    ///
    /// This is a [hardened buffer type](https://docs.rs/alkali#hardened-buffer-types), and will be
    /// zeroed on drop. A number of other security measures are taken to protect its contents.
    Seed(KEY_SEED_LENGTH);
}

impl<'a> PrivateKey<'a> {
    /// Derive the public key corresponding to this private key.
    pub fn public_key(&self) -> Result<PublicKey, AlkaliError> {
        require_init()?;

        let mut public_key = [0; PUBLIC_KEY_LENGTH];
        unsafe {
            // SAFETY: This function takes a pointer to a buffer to which the result of scalar
            // multiplication should be written, and a pointer to the scalar by which the generator
            // of the elliptic curve should be multiplied. We have defined the public_key array to
            // be crypto_kx_PUBLICKEYBYTES, which is equal to crypto_scalarmult_BYTES, so this is
            // the expected size for use with this function. The PrivateKey type has been defined
            // to store crypto_kx_SECRETKEYBYTES, which is equal to crypto_scalarmult_SCALARBYTES,
            // so this is also the expected size for use with this function. The PrivateKey::inner
            // method simply returns a pointer to the backing memory.
            sodium::crypto_scalarmult_base(
                &mut public_key as *mut libc::c_uchar,
                self.inner() as *const libc::c_uchar,
            );
        }

        Ok(public_key)
    }
}

/// A public key used to verify message signatures.
///
/// A public key corresponds to a private key, and represents a point on the Curve25519 curve.
///
/// A public key can be made public (and *should* be, if you want others to be able to perform a
/// key exchange with other parties).
pub type PublicKey = [u8; PUBLIC_KEY_LENGTH];

/// Generates a random X25519 private key and corresponding public key for use in signing messages.
///
/// The generated private key will *not* be clamped, and therefore if used in other X25519
/// implementations, it must be clamped before use. It is clamped for the public key calculation,
/// and for other calculations within the Sodium implementation.
///
/// Returns a (private key, public key) keypair, or an error if an error occurred initialising
/// Sodium. The private key should be kept private, the public key can be publicised.
pub fn generate_keypair<'a>() -> Result<(PrivateKey<'a>, PublicKey), AlkaliError> {
    require_init()?;

    let mut private_key = PrivateKey::new_empty()?;
    let mut public_key = [0u8; PUBLIC_KEY_LENGTH];

    unsafe {
        // SAFETY: This function expects a pointer to a region of memory sufficient to store a
        // public key, and a pointer to a region of memory sufficient to store a private key for
        // this algorithm. We have defined the PublicKey type to be crypto_kx_PUBLICKEYBYTES, and
        // the PrivateKey type to be crypto_kx_SECRETKEYBYTES, so both are of sufficient size to
        // store the respective values. The PrivateKey::inner_mut method simply gives a mutable
        // pointer to the backing memory.
        sodium::crypto_kx_keypair(
            &mut public_key as *mut libc::c_uchar,
            private_key.inner_mut() as *mut libc::c_uchar,
        );
    }

    Ok((private_key, public_key))
}

/// Deterministically calculates an X25519 private key and corresponding public key for use in
/// signing messages, based on the provided seed.
///
/// Given the same seed, the same (private, public) keypair will always be generated.
///
/// The generated private key will *not* be clamped, and therefore if used in other X25519
/// implementations, it must be clamped before use. It is clamped for the public key calculation,
/// and for other calculations within the Sodium implementation.
///
/// Returns a (private key, public key) keypair, or an error if an error occurred initialising
/// Sodium. The private key should be kept private, the public key can be publicised.
pub fn generate_keypair_from_seed<'a>(
    seed: &Seed,
) -> Result<(PrivateKey<'a>, PublicKey), AlkaliError> {
    require_init()?;

    let mut private_key = PrivateKey::new_empty()?;
    let mut public_key = [0u8; PUBLIC_KEY_LENGTH];

    unsafe {
        // SAFETY: This function expects a pointer to a region of memory sufficient to store a
        // public key, a pointer to a region of memory sufficient to store a private key, and a
        // pointer to a seed. We have defined the PublicKey type to be crypto_kx_PUBLICKEYBYTES,
        // and the PrivateKey type to be crypto_kx_SECRETKEYBYTES, so both are of sufficient size
        // to store the respective values. The PrivateKey::inner_mut method simply gives a mutable
        // pointer to the backing memory. We use a Seed type as the final argument, which is
        // defined to be crypto_kx_SEEDBYTES, the expected size for a seed for use in this
        // algorithm. The Seed::inner method simply returns a pointer to the backing memory.
        sodium::crypto_kx_seed_keypair(
            &mut public_key as *mut libc::c_uchar,
            private_key.inner_mut() as *mut libc::c_uchar,
            seed.inner() as *const libc::c_uchar,
        );
    }

    Ok((private_key, public_key))
}

/// Calculate the client's session keys, by performing a key exchange with the server.
///
/// If key exchange is successful, returns (client_rx, client_tx), two session keys. The first is
/// intended to be used to receive messages from the server, the second is used to transmit
/// messages to the server. If only one key is required, you can simply use one of (client_rx,
/// client_tx), rather than using both. Note that client_rx = server_tx, and client_tx = server_rx.
///
/// The key exchange may fail if the server's public key is deemed insecure, in which case an error
/// will be returned.
pub fn derive_client_keys<'a, 'b>(
    client_private_key: &PrivateKey,
    client_public_key: &PublicKey,
    server_public_key: &PublicKey,
) -> Result<(SessionKey<'a>, SessionKey<'b>), AlkaliError> {
    require_init()?;

    let mut rx = SessionKey::new_empty()?;
    let mut tx = SessionKey::new_empty()?;

    let kx_result = unsafe {
        // SAFETY: This function expects a pointer to which the receive key will be written, a
        // pointer to which the transmit key will be written, a pointer to the client's public key,
        // a pointer to the client's private key, and a pointer to the server's public key. The
        // SessionKey type, used as the first two arguments, has been defined to be
        // crypto_kx_SESSIONKEYBYTES, the expected size for each of the keys derived in this
        // exchange. The PublicKey type, used for the client's public key and server's public key,
        // is crypto_kx_PUBLICKEYBYTES, again, the expected size. Finally, the PrivateKey type is
        // crypto_kx_SECRETKEYBYTES, the expected size. The PrivateKey::inner method simply returns
        // a pointer to the backing data.
        sodium::crypto_kx_client_session_keys(
            rx.inner_mut() as *mut libc::c_uchar,
            tx.inner_mut() as *mut libc::c_uchar,
            client_public_key.as_ptr(),
            client_private_key.inner() as *const libc::c_uchar,
            server_public_key.as_ptr(),
        )
    };

    if kx_result == 0 {
        Ok((rx, tx))
    } else {
        Err(KeyExchangeError::PublicKeyInsecure.into())
    }
}

/// Calculate the server's session keys, by performing a key exchange with the client.
///
/// If key exchange is successful, returns (server_rx, server_tx), two session keys. The first is
/// intended to be used to receive messages from the client, the second is used to transmit
/// messages to the client. If only one key is required, you can simply use one of (server_rx,
/// server_tx), rather than using both. Note that server_tx = client_rx, and server_rx = client_tx.
///
/// The key exchange may fail if the client's public key is deemed insecure, in which case an error
/// will be returned.
pub fn derive_server_keys<'a, 'b>(
    server_private_key: &PrivateKey,
    server_public_key: &PublicKey,
    client_public_key: &PublicKey,
) -> Result<(SessionKey<'a>, SessionKey<'b>), AlkaliError> {
    require_init()?;

    let mut rx = SessionKey::new_empty()?;
    let mut tx = SessionKey::new_empty()?;

    let kx_result = unsafe {
        // SAFETY: This function expects a pointer to which the receive key will be written, a
        // pointer to which the transmit key will be written, a pointer to the server's public key,
        // a pointer to the server's private key, and a pointer to the client's public key. The
        // SessionKey type, used as the first two arguments, has been defined to be
        // crypto_kx_SESSIONKEYBYTES, the expected size for each of the keys derived in this
        // exchange. The PublicKey type, used for the server's public key and client's public key,
        // is crypto_kx_PUBLICKEYBYTES, again, the expected size. Finally, the PrivateKey type is
        // crypto_kx_SECRETKEYBYTES, the expected size. The PrivateKey::inner method simply returns
        // a pointer to the backing data.
        sodium::crypto_kx_server_session_keys(
            rx.inner_mut() as *mut libc::c_uchar,
            tx.inner_mut() as *mut libc::c_uchar,
            server_public_key.as_ptr(),
            server_private_key.inner() as *const libc::c_uchar,
            client_public_key.as_ptr(),
        )
    };

    if kx_result == 0 {
        Ok((rx, tx))
    } else {
        Err(KeyExchangeError::PublicKeyInsecure.into())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        derive_client_keys, derive_server_keys, generate_keypair, generate_keypair_from_seed, Seed,
    };
    use crate::AlkaliError;

    #[test]
    fn keypair_generation_works() -> Result<(), AlkaliError> {
        let (private_key, public_key) = generate_keypair()?;
        assert_eq!(private_key.public_key()?, public_key);
        Ok(())
    }

    #[test]
    fn keypair_from_seed_vectors() -> Result<(), AlkaliError> {
        let seed = Seed::try_from(&[
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ])?;
        let (private_key, public_key) = generate_keypair_from_seed(&seed)?;

        assert_eq!(
            &private_key[..],
            &[
                0xcb, 0x2f, 0x51, 0x60, 0xfc, 0x1f, 0x7e, 0x05, 0xa5, 0x5e, 0xf4, 0x9d, 0x34, 0x0b,
                0x48, 0xda, 0x2e, 0x5a, 0x78, 0x09, 0x9d, 0x53, 0x39, 0x33, 0x51, 0xcd, 0x57, 0x9d,
                0xd4, 0x25, 0x3, 0xd6
            ]
        );
        assert_eq!(
            &public_key,
            &[
                0x0e, 0x02, 0x16, 0x22, 0x3f, 0x14, 0x71, 0x43, 0xd3, 0x26, 0x15, 0xa9, 0x11, 0x89,
                0xc2, 0x88, 0xc1, 0x72, 0x8c, 0xba, 0x3c, 0xc5, 0xf9, 0xf6, 0x21, 0xb1, 0x02, 0x6e,
                0x03, 0xd8, 0x31, 0x29
            ]
        );
        assert_eq!(private_key.public_key()?, public_key);

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
        let (client_private_key, client_public_key) = generate_keypair_from_seed(&client_seed)?;
        let (server_private_key, server_public_key) = generate_keypair_from_seed(&server_seed)?;

        let (client_rx, client_tx) =
            derive_client_keys(&client_private_key, &client_public_key, &server_public_key)?;
        assert_eq!(
            &client_rx[..],
            &[
                0x74, 0x95, 0x19, 0xc6, 0x80, 0x59, 0xbc, 0xe6, 0x9f, 0x7c, 0xfc, 0xc7, 0xb3, 0x87,
                0xa3, 0xde, 0x1a, 0x1e, 0x82, 0x37, 0xd1, 0x10, 0x99, 0x13, 0x23, 0xbf, 0x62, 0x87,
                0x01, 0x15, 0x73, 0x1a,
            ]
        );
        assert_eq!(
            &client_tx[..],
            &[
                0x62, 0xc8, 0xf4, 0xfa, 0x81, 0x80, 0x0a, 0xbd, 0x05, 0x77, 0xd9, 0x99, 0x18, 0xd1,
                0x29, 0xb6, 0x5d, 0xeb, 0x78, 0x9a, 0xf8, 0xc8, 0x35, 0x1f, 0x39, 0x1f, 0xeb, 0x0c,
                0xbf, 0x23, 0x86, 0x04
            ]
        );

        let (server_rx, server_tx) =
            derive_server_keys(&server_private_key, &server_public_key, &client_public_key)?;
        assert_eq!(server_rx, client_tx);
        assert_eq!(server_tx, client_rx);

        Ok(())
    }

    #[test]
    fn reject_weak_key() -> Result<(), AlkaliError> {
        let weak_public_key = [
            0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f,
            0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16,
            0x5f, 0x49, 0xb8, 0x00,
        ];

        let (private_key, public_key) = generate_keypair()?;

        assert!(derive_client_keys(&private_key, &public_key, &weak_public_key).is_err());
        assert!(derive_server_keys(&private_key, &public_key, &weak_public_key).is_err());

        Ok(())
    }

    #[test]
    fn random_exchanges() -> Result<(), AlkaliError> {
        for _ in 0..100 {
            let (client_priv, client_pub) = generate_keypair()?;
            let (server_priv, server_pub) = generate_keypair()?;

            let (client_rx, client_tx) =
                derive_client_keys(&client_priv, &client_pub, &server_pub)?;
            let (server_rx, server_tx) =
                derive_server_keys(&server_priv, &server_pub, &client_pub)?;

            assert_eq!(client_rx, server_tx);
            assert_eq!(client_tx, server_rx);
        }

        Ok(())
    }
}
