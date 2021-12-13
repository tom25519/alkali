//! Cryptographic signatures (asymmetric message authentication).
//!
//! This module corresponds to the [`crypto_sign`
//! API](https://doc.libsodium.org/public-key_cryptography/public-key_signatures) from Sodium.
//!
//! Cryptographic signatures are used when a party wishes to compute some form of authentication
//! tag for a message, which others can verify without the need to exchange any secret data. This
//! is opposed to [symmetric authentication](crate::symmetric::auth), in which parties must know a
//! secret key to verify messages. The person signing a message generates a private key, from which
//! they derive a public key which they share with all other parties. They then use their private
//! key to calculate a signature for messages they wish to authenticate. Other parties can use the
//! public key to verify signatures, but cannot themselves construct signatures which will be
//! verifiable using the same public key.
//!
//! # Algorithm Details
//! [Ed25519](https://ed25519.cr.yp.to/) (EdDSA over a twisted Edwards curve birationally
//! equivalent to Curve25519) is used for single-part signatures. For multi-part signatures,
//! Ed25519ph is used, which can be thought of as signing a hash of the message rather than the
//! message itself, although it is a little more complicated in practice.
//!
//! # Examples
//! Generating a signature for a message and verifying the signature is valid (uses [`sign`] and
//! [`verify`]):
//!
//! ```rust
//! use alkali::asymmetric::sign;
//!
//! // Generate a new random keypair to use for signing messages
//! let (private_key, public_key) = sign::generate_keypair().unwrap();
//! let message = "Here's a message we wish to sign. It can be of any length.";
//! // Messages are signed using the private key
//! let signature = sign::sign(message.as_bytes(), &private_key).unwrap();
//!
//! // ...
//!
//! // Messages are verified using the public key
//! match sign::verify(message.as_bytes(), &signature, &public_key) {
//!     Ok(_) => println!("Signature verification succeeded!"),
//!     Err(alkali::AlkaliError::SignError(sign::SignError::InvalidSignature)) => {
//!         panic!("Uh-oh, message altered!")
//!     },
//!     Err(_) => panic!("Some other error ocurred"),
//! }
//! ```
//!
//! If you have an especially long message, or one you're receiving in chunks, it may make more
//! sense to use the streaming API, which allows you to specify the message to sign in multiple
//! multiple parts (uses [`Multipart`]):
//!
//! ```rust
//! use alkali::asymmetric::sign;
//!
//! // Here we use a seed to deterministically specify a keypair, rather than generating a new one
//! // (in this case, just 32 0xdb bytes, which is obviously not secure). You can use
//! // PrivateKey::seed to find a seed which can be used to generate a given private key.
//! let seed = sign::Seed::try_from(&[0xdb; 32]).unwrap();
//! let (private_key, public_key) = sign::generate_keypair_from_seed(&seed).unwrap();
//! let mut state = sign::Multipart::new().unwrap();
//! state.update(b"Here's the first part");
//! state.update(b"... And the second!");
//! let signature = state.sign(&private_key);
//!
//! // ...
//!
//! // Now let's verify the signature we just generated (switching up the chunks we add to the
//! // state):
//! let mut state = sign::Multipart::new().unwrap();
//! state.update(b"Here");
//! state.update(b"'s the first ");
//! state.update(b"part... And the ");
//! state.update(b"second!");
//! assert!(state.verify(&signature, &public_key).is_ok());
//! ```
//!
//! Combined mode can be used to store the signature alongside the message (uses [`sign_combined`]
//! and [`verify_combined`]):
//!
//! ```rust
//! use alkali::asymmetric::sign;
//!
//! let (private_key, public_key) = sign::generate_keypair().unwrap();
//! let message = "Sign me please! :D";
//! // The length of the output should be message.len() + SIGNATURE_LENGTH
//! let mut signed_message = [0u8; 18 + sign::SIGNATURE_LENGTH];
//! sign::sign_combined(&message.as_bytes(), &private_key, &mut signed_message).unwrap();
//!
//! // ...
//!
//! let original_message = sign::verify_combined(&signed_message, &public_key).unwrap();
//! assert_eq!(message.as_bytes(), original_message);
//! ```

use crate::{hardened_buffer, require_init, AlkaliError};
use libsodium_sys as sodium;
use std::mem::MaybeUninit;
use std::ptr;
use thiserror::Error;

/// Error type returned if something went wrong in the sign module.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SignError {
    /// Failed to verify the authenticity of a message.
    ///
    /// This may indicate an attempted forgery, a transmission error, or that you're using a
    /// different public key to the associated with the private key used to sign this message. In
    /// any case, the authenticity of the message can't be verified, and it should not be trusted.
    #[error("the provided signature was invalid for the given message")]
    InvalidSignature,

    /// The output buffer provided was insufficient to store the signed message.
    ///
    /// When signing a message in combined mode, the output must be at least the length of the
    /// original message plus [`SIGNATURE_LENGTH`] bytes, to allow for the signature to be
    /// prepended.
    #[error("the output buffer provided was insufficient: required at least {0} bytes, found {1}")]
    InsufficientBuffer(usize, usize),

    /// The combined signature+message to verify was too short to be valid.
    ///
    /// A signature is [`SIGNATURE_LENGTH`] bytes long, so the combined signature+message must be
    /// at least this long.
    #[error("the signed_message input was too short to be valid")]
    SignedMessageTooShort,
}

/// The length of a private key for signing messages, in bytes.
pub const PRIVATE_KEY_LENGTH: usize = sodium::crypto_sign_ed25519_SECRETKEYBYTES as usize;

/// The length of a public key for verifying message signatures, in bytes.
pub const PUBLIC_KEY_LENGTH: usize = sodium::crypto_sign_ed25519_PUBLICKEYBYTES as usize;

/// The length of a message signature, in bytes.
///
/// While signatures may be shorter than this, they are padded with zeroes such that they are
/// always of this length.
pub const SIGNATURE_LENGTH: usize = sodium::crypto_sign_ed25519_BYTES as usize;

/// The length of a seed to use for the deterministic generation of a (private key, public key)
/// pair.
pub const KEY_SEED_LENGTH: usize = sodium::crypto_sign_ed25519_SEEDBYTES as usize;

hardened_buffer! {
    /// A private key used to sign messages.
    ///
    /// Private keys for Ed25519 require clamping to be secure (just setting a random value is
    /// insufficient, and leads to issues if the associated public key is in a small-order subgroup
    /// of the curve). As such, you should generate a keypair using [`generate_keypair`], and *not*
    /// just use a random value for a private key.
    ///
    /// A private key is secret, and as such, should not ever be made public.
    ///
    /// This is a [hardened buffer type](https://docs.rs/alkali#hardened-buffer-types), and will be
    /// zeroed on drop. A number of other security measures are taken to protect its contents.
    PrivateKey(PRIVATE_KEY_LENGTH);

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

impl PrivateKey {
    /// Derive the public key corresponding to this private key.
    pub fn public_key(&self) -> Result<PublicKey, AlkaliError> {
        require_init()?;

        let mut public_key = [0; PUBLIC_KEY_LENGTH];
        unsafe {
            // SAFETY: This function takes a pointer to a buffer to which the public key should be
            // written, and a pointer to the private key. We have defined the public_key array to
            // be crypto_sign_PUBLICKEYBYTES, so it is the expected size for use with this
            // function, and is sufficient to store a public key. We use a PrivateKey type as the
            // second argument, which is defined to be crypto_sign_SECRETKEYBYTES, the expected
            // length for this argument. The PrivateKey::inner method simply returns a pointer to
            // the backing memory.
            sodium::crypto_sign_ed25519_sk_to_pk(
                &mut public_key as *mut libc::c_uchar,
                self.inner() as *const libc::c_uchar,
            );
        }

        Ok(public_key)
    }

    /// Calculate a seed which can be used to derive this private key.
    pub fn seed(&self) -> Result<Seed, AlkaliError> {
        require_init()?;

        let mut seed = Seed::new_empty()?;
        unsafe {
            // SAFETY: This function takes a pointer to a buffer to which the seed should be
            // written, and a pointer to the private key. We have defined the seed array to be
            // crypto_sign_SEEDBYTES, so it is the expected size for use with this function, and is
            // sufficient to store a seed. We use a PrivateKey type as the second argument, which
            // is defined to be crypto_sign_SECRETKEYBYTES, the expected length for this argument.
            // The PrivateKey::inner method simply returns a pointer to the backing memory.
            sodium::crypto_sign_ed25519_sk_to_seed(
                seed.inner_mut() as *mut libc::c_uchar,
                self.inner() as *const libc::c_uchar,
            );
        }

        Ok(seed)
    }
}

/// A public key used to verify message signatures.
///
/// A public key corresponds to a private key, and represents a point on the Ed25519 curve.
///
/// A public key can be made public (and *should* be, if you want others to be able to verify
/// messages signed with the corresponding public key).
pub type PublicKey = [u8; PUBLIC_KEY_LENGTH];

/// Represents a signature for a message under a specific public key.
pub type Signature = [u8; SIGNATURE_LENGTH];

/// Streaming signature API, for long/multi-part message signatures.
///
/// This can be used to calculate/verify a signature for a message which is too large to fit into
/// memory, or where the message is received in portions.
#[derive(Clone, Copy, Debug)]
pub struct Multipart(sodium::crypto_sign_ed25519ph_state);

impl Multipart {
    /// Create a new instance of the struct.
    pub fn new() -> Result<Self, AlkaliError> {
        require_init()?;

        let mut state_uninit = MaybeUninit::uninit();
        let state = unsafe {
            // SAFETY: This function initialises a crypto_sign_state struct. It expects a pointer
            // to a crypto_sign_state struct. We pass a region of memory sufficient to store the
            // struct as defined in Rust, rather than C. This definition is generated via bindgen,
            // and as such, is equivalent to the struct in C, so it is correct to use it as an
            // argument for this function.
            sodium::crypto_sign_ed25519ph_init(state_uninit.as_mut_ptr());

            // SAFETY: Following the crypto_sign_init call, the struct is correctly initialised, so
            // it is safe to assume its initialised state.
            state_uninit.assume_init()
        };

        Ok(Self(state))
    }

    /// Add message contents to be signed/verified.
    pub fn update(&mut self, chunk: &[u8]) {
        unsafe {
            // SAFETY: This function takes a pointer to a crypto_sign_state struct, a pointer to a
            // chunk of data to add to the signature calculation, and the length of this data. For
            // the first argument, we pass a crypto_sign_state struct, which is defined using
            // bindgen to be equivalent to the definition of the equivalent struct in C. The struct
            // must have been initialised in order to initialise this Multipart wrapper struct, so
            // it is in the right state to call crypto_sign_update. We use chunk.len() as the third
            // argument, so it is definitely the correct length for the chunk.
            sodium::crypto_sign_ed25519ph_update(
                &mut self.0,
                chunk.as_ptr(),
                chunk.len() as libc::c_ulonglong,
            );
        }
    }

    /// Calculate the signature for the specified message under the given private key.
    ///
    /// Equivalent to [`sign`] for single-part messages.
    pub fn sign(mut self, private_key: &PrivateKey) -> Signature {
        let mut signature = [0u8; SIGNATURE_LENGTH];

        unsafe {
            // SAFETY: This function takes a pointer to a crypto_sign_state struct, a pointer to
            // which the signature will be written, a pointer to write the length of the signature,
            // and a pointer to the private key to sign the message. For the first argument, we
            // pass a crypto_sign_state struct, which is defined using bindgen to be equivalent to
            // the definition of the equivalent struct in C. The struct must have been initialised
            // in order to initialise this Multipart wrapper struct, so it is in the right state to
            // call crypto_sign_final_create. The signature array here has been defined to be
            // crypto_sign_BYTES bytes long, so it is of the correct size to store a signature. For
            // the pointer to write the length of the signature to, we pass a NULL pointer. It is
            // documented that Sodium will simply not try to write the length of the signature if
            // this pointer is NULL, so this is safe. The PrivateKey type is defined to store
            // crypto_sign_SECRETKEYBYTES, so it is suitable for use with this function.
            sodium::crypto_sign_ed25519ph_final_create(
                &mut self.0,
                signature.as_mut_ptr(),
                ptr::null::<libc::c_ulonglong>() as *mut libc::c_ulonglong,
                private_key.inner() as *const libc::c_uchar,
            );
        }

        signature
    }

    /// Verify the provided signature is correct for the specified message and public key.
    ///
    /// Returns a [`SignError::InvalidSignature`] if verification of the signature failed.
    ///
    /// Equivalent to [`verify`] for single-part messages.
    pub fn verify(
        mut self,
        signature: &Signature,
        public_key: &PublicKey,
    ) -> Result<(), AlkaliError> {
        let verification_result = unsafe {
            // SAFETY: This function takes a pointer to a crypto_sign_state struct, a pointer to
            // the signature to verify, and a pointer to the public key to verify the signature.
            // For the first argument, we pass a crypto_sign_state struct, which is defined using
            // bindgen to be equivalent to the definition of the equivalent struct in C. The struct
            // must have been initialised in order to initialise this Multipart wrapper struct, so
            // it is in the right state to call crypto_sign_final_verify. The signature array here
            // has been defined to be crypto_sign_BYTES bytes long, so it is of the expected size
            // for a signature. The PublicKey type is defined to store crypto_sign_PUBLICKEYBYTES,
            // so it is suitable for use with this function.
            sodium::crypto_sign_ed25519ph_final_verify(
                &mut self.0,
                signature.as_ptr(),
                public_key.as_ptr(),
            )
        };

        if verification_result == 0 {
            Ok(())
        } else {
            Err(SignError::InvalidSignature.into())
        }
    }
}

/// Generates a random Ed25519 private key and corresponding public key for use in signing
/// messages.
///
/// The generated private key will be clamped, to avoid the associated public key being in a
/// small-order subgroup of the curve, and to try to mitigate side-channel attacks if this key is
/// used in an insecure Ed25519 implementation.
///
/// Returns a (private key, public key) keypair, or an error if an error occurred initialising
/// Sodium. The private key should be kept private, the public key can be publicised.
pub fn generate_keypair() -> Result<(PrivateKey, PublicKey), AlkaliError> {
    require_init()?;

    let mut private_key = PrivateKey::new_empty()?;
    let mut public_key = [0u8; PUBLIC_KEY_LENGTH];

    unsafe {
        // SAFETY: This function expects a pointer to a region of memory sufficient to store a
        // public key, and a pointer to a region of memory sufficient to store a private key for
        // this algorithm. We have defined the PublicKey type to be crypto_sign_PUBLICKEYBYTES, and
        // the PrivateKey type to be crypto_sign_SECRETKEYBYTES, so both are of sufficient size to
        // store the respective values. The PrivateKey::inner_mut method simply gives a mutable
        // pointer to the backing memory.
        sodium::crypto_sign_ed25519_keypair(
            &mut public_key as *mut libc::c_uchar,
            private_key.inner_mut() as *mut libc::c_uchar,
        );
    }

    Ok((private_key, public_key))
}

/// Deterministically calculates a Ed25519 private key and corresponding public key for use in
/// signing messages, based on the provided seed.
///
/// Given the same seed, the same (private, public) keypair will always be generated.
///
/// The generated private key will be clamped, to avoid the associated public key being in a
/// small-order subgroup of the curve, and to try to mitigate side-channel attacks if this key is
/// used in an insecure Ed25519 implementation.
///
/// Returns a (private key, public key) keypair, or an error if an error occurred initialising
/// Sodium. The private key should be kept private, the public key can be publicised.
pub fn generate_keypair_from_seed(seed: &Seed) -> Result<(PrivateKey, PublicKey), AlkaliError> {
    require_init()?;

    let mut private_key = PrivateKey::new_empty()?;
    let mut public_key = [0u8; PUBLIC_KEY_LENGTH];

    unsafe {
        // SAFETY: This function expects a pointer to a region of memory sufficient to store a
        // public key, a pointer to a region of memory sufficient to store a private key, and a
        // pointer to a seed. We have defined the PublicKey type to be crypto_sign_PUBLICKEYBYTES,
        // and the PrivateKey type to be crypto_sign_SECRETKEYBYTES, so both are of sufficient size
        // to store the respective values. The PrivateKey::inner_mut method simply gives a mutable
        // pointer to the backing memory. We use a Seed type as the final argument, which is
        // defined to be crypto_sign_SEEDBYTES, the expected size for a seed for use in this
        // algorithm. The Seed::inner method simply returns a pointer to the backing memory.
        sodium::crypto_sign_ed25519_seed_keypair(
            &mut public_key as *mut libc::c_uchar,
            private_key.inner_mut() as *mut libc::c_uchar,
            seed.inner() as *const libc::c_uchar,
        );
    }

    Ok((private_key, public_key))
}

/// Signs the provided message using the given private key.
///
/// This function produces a signature for a message using the given private key, which can be
/// verified using the corresponding public key. It returns the signature for the message, or an
/// error if Sodium could not be initialised.
pub fn sign(message: &[u8], private_key: &PrivateKey) -> Result<Signature, AlkaliError> {
    require_init()?;

    let mut signature = [0u8; SIGNATURE_LENGTH];

    unsafe {
        // SAFETY: This function takes a pointer to a buffer where the calculated signature will be
        // written, a pointer to where the length of the signature will be written, a pointer to a
        // message to sign, the length of the message, and a pointer to the private key to use. We
        // have defined the signature array to be crypto_sign_BYTES long, the maximum length of a
        // signature as defined in Sodium. For the pointer to write the length of the signature to,
        // we pass a NULL pointer. It is documented that Sodium will simply not try to write the
        // length of the signature if this pointer is NULL, so this is safe. We use message.len()
        // to specify the length of the message to authenticate, so the length provided is correct.
        // Finally, we define the PrivateKey type to be crypto_sign_SECRETKEYBYTES long, so it is
        // of the expected size for use in this function. The PrivateKey::inner method simply
        // provides a pointer to the backing memory.
        sodium::crypto_sign_ed25519_detached(
            &mut signature as *mut libc::c_uchar,
            ptr::null::<libc::c_ulonglong>() as *mut libc::c_ulonglong,
            message.as_ptr() as *const libc::c_uchar,
            message.len() as libc::c_ulonglong,
            private_key.inner() as *const libc::c_uchar,
        );
    }

    Ok(signature)
}

/// Sign the provided message using the given private key, writing a combined signature + message
/// to `output`, which can be verified using [`verify_combined`].
///
/// `output` must be at least `message.len()` plus [`SIGNATURE_LENGTH`] bytes long.
///
/// Returns the number of bytes written to `output` if signing was successful. If signing was
/// unsuccessful, the contents of `output` are unspecified, and an error will be returned.
pub fn sign_combined(
    message: &[u8],
    private_key: &PrivateKey,
    output: &mut [u8],
) -> Result<usize, AlkaliError> {
    require_init()?;

    let output_size = message.len() + SIGNATURE_LENGTH;
    if output.len() < output_size {
        return Err(SignError::InsufficientBuffer(output_size, output.len()).into());
    }

    unsafe {
        // SAFETY: This function takes a pointer to a buffer where the combined signature + message
        // will be written, a pointer to where the length of the combined output will be written, a
        // pointer to a message to sign, the length of the message, and a pointer to the private
        // key to use. Sodium specifies that the number of bytes written to the output will be the
        // length of the original message + crypto_sign_BYTES. We verify above that `output` is at
        // least this long, so it is safe to use here. For the pointer to write the length of the
        // signature to, we pass a NULL pointer. It is documented that Sodium will simply not try
        // to write the length of the signature if this pointer is NULL, so this is safe. We use
        // message.len() to specify the length of the message to authenticate, so the length
        // provided is correct.  Finally, we define the PrivateKey type to be
        // crypto_sign_SECRETKEYBYTES long, so it is of the expected size for use in this function.
        // The PrivateKey::inner method simply provides a pointer to the backing memory.
        sodium::crypto_sign_ed25519(
            output.as_mut_ptr() as *mut libc::c_uchar,
            ptr::null::<libc::c_ulonglong>() as *mut libc::c_ulonglong,
            message.as_ptr() as *const libc::c_uchar,
            message.len() as libc::c_ulonglong,
            private_key.inner() as *const libc::c_uchar,
        );
    };

    Ok(output_size)
}

/// Verifies that the given signature is valid for the provided message, under the private key
/// corresponding to the given public key.
///
/// Returns a [`SignError::InvalidSignature`] error if verification failed.
pub fn verify(
    message: &[u8],
    signature: &Signature,
    public_key: &PublicKey,
) -> Result<(), AlkaliError> {
    require_init()?;

    let verification_result = unsafe {
        // SAFETY: This function takes a pointer to the signature to be verified, a pointer to the
        // message to authenticate, the length of the message, and a pointer to the public key
        // which should be used to verify the signature. We have defined the signature array to be
        // of the Signature type, which is crypto_sign_BYTES long, the maximum length of a
        // signature as defined in Sodium. We use message.len() to specify the length of the
        // message to verify, so the length provided is correct. Finally, we define the PublicKey
        // type to be crypto_sign_PUBLICKEYBYTES long, so it is of the expected size for use in
        // this function.
        sodium::crypto_sign_ed25519_verify_detached(
            signature as *const libc::c_uchar,
            message.as_ptr() as *const libc::c_uchar,
            message.len() as libc::c_ulonglong,
            public_key as *const libc::c_uchar,
        )
    };

    if verification_result == 0 {
        Ok(())
    } else {
        Err(SignError::InvalidSignature.into())
    }
}

/// Verifies that the combined signature + message is valid under the private key corresponding to
/// the given public key, and returns a slice of the input containing just the message.
///
/// `signed_message` must be at least [`SIGNATURE_LENGTH`] bytes long.
///
/// Returns a slice containing the original message if the signature was valid. Otherwise returns a
/// [`SignError::InvalidSignature`] error if verification failed, or another error if there was
/// some other issue.
pub fn verify_combined<'a>(
    signed_message: &'a [u8],
    public_key: &PublicKey,
) -> Result<&'a [u8], AlkaliError> {
    require_init()?;

    if signed_message.len() < SIGNATURE_LENGTH {
        return Err(SignError::SignedMessageTooShort.into());
    }

    let verification_result = unsafe {
        // SAFETY: This function takes a pointer to which the original message will be written
        // (without the signature), a pointer to which the length of the message will be written, a
        // pointer to the signed message, the length of the signed message, and a pointer to the
        // public key to use to verify the signature for the message. We pass a NULL pointer as the
        // first argument, which means Sodium will not try to write the original message anywhere.
        // Similarly, we pass NULL pointer as the location to which the length of the original
        // message will be written. Sodium will therefore not try to write the length of the
        // original message anywhere. We use signed_message.len() for the length of the signed
        // message, so the length is correct for the pointer we provide. The PublicKey type has
        // been defined to be crypto_sign_PUBLICKEYBYTES long, so it is of the expected size for
        // use with this function.
        sodium::crypto_sign_ed25519_open(
            ptr::null::<libc::c_uchar>() as *mut libc::c_uchar,
            ptr::null::<libc::c_ulonglong>() as *mut libc::c_ulonglong,
            signed_message.as_ptr() as *const libc::c_uchar,
            signed_message.len() as libc::c_ulonglong,
            public_key as *const libc::c_uchar,
        )
    };

    if verification_result == 0 {
        Ok(&signed_message[SIGNATURE_LENGTH..])
    } else {
        Err(SignError::InvalidSignature.into())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        generate_keypair, generate_keypair_from_seed, sign, sign_combined, verify, verify_combined,
        Multipart, Seed, SIGNATURE_LENGTH,
    };
    use crate::random::fill_random;
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
            0x42, 0x11, 0x51, 0xa4, 0x59, 0xfa, 0xea, 0xde, 0x3d, 0x24, 0x71, 0x15, 0xf9, 0x4a,
            0xed, 0xae, 0x42, 0x31, 0x81, 0x24, 0x09, 0x5a, 0xfa, 0xbe, 0x4d, 0x14, 0x51, 0xa5,
            0x59, 0xfa, 0xed, 0xee,
        ])?;
        let (private_key, public_key) = generate_keypair_from_seed(&seed)?;

        assert_eq!(
            &private_key[..],
            &[
                0x42, 0x11, 0x51, 0xa4, 0x59, 0xfa, 0xea, 0xde, 0x3d, 0x24, 0x71, 0x15, 0xf9, 0x4a,
                0xed, 0xae, 0x42, 0x31, 0x81, 0x24, 0x09, 0x5a, 0xfa, 0xbe, 0x4d, 0x14, 0x51, 0xa5,
                0x59, 0xfa, 0xed, 0xee, 0xb5, 0x07, 0x6a, 0x84, 0x74, 0xa8, 0x32, 0xda, 0xee, 0x4d,
                0xd5, 0xb4, 0x04, 0x09, 0x83, 0xb6, 0x62, 0x3b, 0x5f, 0x34, 0x4a, 0xca, 0x57, 0xd4,
                0xd6, 0xee, 0x4b, 0xaf, 0x3f, 0x25, 0x9e, 0x6e
            ]
        );
        assert_eq!(
            &public_key,
            &[
                0xb5, 0x07, 0x6a, 0x84, 0x74, 0xa8, 0x32, 0xda, 0xee, 0x4d, 0xd5, 0xb4, 0x04, 0x09,
                0x83, 0xb6, 0x62, 0x3b, 0x5f, 0x34, 0x4a, 0xca, 0x57, 0xd4, 0xd6, 0xee, 0x4b, 0xaf,
                0x3f, 0x25, 0x9e, 0x6e
            ]
        );
        assert_eq!(private_key.public_key()?, public_key);
        assert_eq!(private_key.seed()?, seed);

        Ok(())
    }

    #[test]
    fn sign_and_verify() -> Result<(), AlkaliError> {
        let (private_key, public_key) = generate_keypair()?;

        let buf_a = [];
        let mut buf_b = [0; 16];
        let mut buf_c = [0; 128];
        let mut buf_d = [0; 1024];
        let mut buf_e = [0; 1 << 15];

        fill_random(&mut buf_b)?;
        fill_random(&mut buf_c)?;
        fill_random(&mut buf_d)?;
        fill_random(&mut buf_e)?;

        let sig_a = sign(&buf_a, &private_key)?;
        let sig_b = sign(&buf_b, &private_key)?;
        let sig_c = sign(&buf_c, &private_key)?;
        let sig_d = sign(&buf_d, &private_key)?;
        let sig_e = sign(&buf_e, &private_key)?;

        verify(&buf_a, &sig_a, &public_key)?;
        verify(&buf_b, &sig_b, &public_key)?;
        verify(&buf_c, &sig_c, &public_key)?;
        verify(&buf_d, &sig_d, &public_key)?;
        verify(&buf_e, &sig_e, &public_key)?;

        fill_random(&mut buf_b)?;
        fill_random(&mut buf_c)?;
        fill_random(&mut buf_d)?;
        fill_random(&mut buf_e)?;

        assert!(verify(&buf_b, &sig_b, &public_key).is_err());
        assert!(verify(&buf_c, &sig_c, &public_key).is_err());
        assert!(verify(&buf_d, &sig_d, &public_key).is_err());
        assert!(verify(&buf_e, &sig_e, &public_key).is_err());

        Ok(())
    }

    #[test]
    fn sign_and_verify_combined() -> Result<(), AlkaliError> {
        let (private_key, public_key) = generate_keypair()?;

        let mut input_buf = [0; 1 << 15];
        let mut output_buf = [0; (1 << 15) + SIGNATURE_LENGTH];

        fill_random(&mut input_buf)?;

        let written = sign_combined(&[], &private_key, &mut output_buf)?;
        assert_eq!(written, SIGNATURE_LENGTH);
        verify_combined(&output_buf[..written], &public_key)?;

        let written = sign_combined(&input_buf[..16], &private_key, &mut output_buf)?;
        assert_eq!(written, SIGNATURE_LENGTH + 16);
        verify_combined(&output_buf[..written], &public_key)?;

        let written = sign_combined(&input_buf[..128], &private_key, &mut output_buf)?;
        assert_eq!(written, SIGNATURE_LENGTH + 128);
        verify_combined(&output_buf[..written], &public_key)?;

        let written = sign_combined(&input_buf[..1024], &private_key, &mut output_buf)?;
        assert_eq!(written, SIGNATURE_LENGTH + 1024);
        verify_combined(&output_buf[..written], &public_key)?;

        let written = sign_combined(&input_buf, &private_key, &mut output_buf)?;
        assert_eq!(written, SIGNATURE_LENGTH + (1 << 15));
        verify_combined(&output_buf[..written], &public_key)?;

        fill_random(&mut output_buf)?;
        assert!(verify_combined(&output_buf[..written], &public_key).is_err());

        Ok(())
    }

    #[test]
    fn single_part_test_vectors() -> Result<(), AlkaliError> {
        let seed = Seed::try_from(&[
            0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec,
            0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03,
            0x1c, 0xae, 0x7f, 0x60,
        ])?;
        let (private_key, public_key) = generate_keypair_from_seed(&seed)?;
        let expected = [
            0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72, 0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e,
            0x82, 0x8a, 0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74, 0xd8, 0x73, 0xe0, 0x65,
            0x22, 0x49, 0x01, 0x55, 0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac, 0xc6, 0x1e,
            0x39, 0x70, 0x1c, 0xf9, 0xb4, 0x6b, 0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24,
            0x65, 0x51, 0x41, 0x43, 0x8e, 0x7a, 0x10, 0x0b,
        ];
        let message = [];
        let actual = sign(&message, &private_key)?;
        assert_eq!(actual, expected);
        verify(&message, &actual, &public_key)?;

        let seed = Seed::try_from(&[
            0x0a, 0x47, 0xd1, 0x04, 0x52, 0xae, 0x2f, 0xeb, 0xec, 0x51, 0x8a, 0x1c, 0x7c, 0x36,
            0x28, 0x90, 0xc3, 0xfc, 0x1a, 0x49, 0xd3, 0x4b, 0x03, 0xb6, 0x46, 0x7d, 0x35, 0xc9,
            0x04, 0xa8, 0x36, 0x2d,
        ])?;
        let (private_key, public_key) = generate_keypair_from_seed(&seed)?;
        let expected = [
            0x2a, 0x3d, 0x27, 0xdc, 0x40, 0xd0, 0xa8, 0x12, 0x79, 0x49, 0xa3, 0xb7, 0xf9, 0x08,
            0xb3, 0x68, 0x8f, 0x63, 0xb7, 0xf1, 0x4f, 0x65, 0x1a, 0xac, 0xd7, 0x15, 0x94, 0x0b,
            0xdb, 0xe2, 0x7a, 0x08, 0x09, 0xaa, 0xc1, 0x42, 0xf4, 0x7a, 0xb0, 0xe1, 0xe4, 0x4f,
            0xa4, 0x90, 0xba, 0x87, 0xce, 0x53, 0x92, 0xf3, 0x3a, 0x89, 0x15, 0x39, 0xca, 0xf1,
            0xef, 0x4c, 0x36, 0x7c, 0xae, 0x54, 0x50, 0x0c,
        ];
        let message = [
            0xc9, 0x42, 0xfa, 0x7a, 0xc6, 0xb2, 0x3a, 0xb7, 0xff, 0x61, 0x2f, 0xdc, 0x8e, 0x68,
            0xef, 0x39,
        ];
        let actual = sign(&message, &private_key)?;
        assert_eq!(actual, expected);
        verify(&message, &actual, &public_key)?;

        let seed = Seed::try_from(&[
            0x84, 0x00, 0x96, 0x2b, 0xb7, 0x69, 0xf6, 0x38, 0x68, 0xca, 0xe5, 0xa3, 0xfe, 0xc8,
            0xdb, 0x6a, 0x9c, 0x8d, 0x3f, 0x1c, 0x84, 0x6c, 0x8d, 0xce, 0xeb, 0x64, 0x2b, 0x69,
            0x46, 0xef, 0xa8, 0xe3,
        ])?;
        let (private_key, public_key) = generate_keypair_from_seed(&seed)?;
        let expected = [
            0x0a, 0xd7, 0x1b, 0x00, 0x25, 0xf3, 0xd9, 0xa5, 0x0d, 0xb3, 0x38, 0x41, 0x4d, 0x6d,
            0x67, 0x0e, 0x77, 0x99, 0xb7, 0x27, 0x0a, 0x84, 0x44, 0xf6, 0xae, 0x7f, 0x12, 0xae,
            0x7e, 0xb7, 0x1b, 0xd0, 0x3f, 0xfd, 0x3c, 0x4f, 0x36, 0x63, 0x1f, 0x69, 0xfd, 0xcc,
            0x40, 0x61, 0x46, 0x8f, 0xf5, 0x82, 0xed, 0xe4, 0x95, 0x24, 0x3e, 0xf1, 0x36, 0x1a,
            0x3b, 0x32, 0x95, 0xfa, 0x81, 0x3b, 0xa2, 0x05,
        ];
        let message = [
            0xf7, 0xe6, 0x7d, 0x98, 0x2a, 0x2f, 0xf9, 0x3e, 0xcd, 0xa4, 0x08, 0x71, 0x52, 0xb4,
            0x86, 0x4c, 0x94, 0x3b, 0x1b, 0xa7, 0x02, 0x1f, 0x54, 0x07, 0x04, 0x3c, 0xcb, 0x42,
            0x53, 0xd3, 0x48, 0xc2, 0x7b, 0x92, 0x83, 0xac, 0xb2, 0x6c, 0x19, 0x4f, 0xd1, 0xcb,
            0xb7, 0x9e, 0x6a, 0xfc, 0x32, 0xff, 0x68, 0x6b, 0x55, 0xb0, 0xb3, 0x61, 0x72, 0x18,
            0xdc, 0xf3, 0x93, 0x16, 0xb4, 0xb6, 0x6b, 0x3c, 0x8c, 0x0d, 0x67, 0x26, 0x7a, 0x86,
            0xdb, 0x8a, 0xdf, 0x37, 0x50, 0x80, 0x1b, 0xcf, 0x93, 0x27, 0xd4, 0xc2, 0x54, 0x41,
            0xb9, 0x61, 0x97, 0x83, 0x2b, 0x4c, 0xde, 0x0e, 0xac, 0x3f, 0xf2, 0x28, 0x92, 0xa2,
            0xf0, 0xbc, 0x17, 0xc2, 0xc2, 0x13, 0xc0, 0x23, 0x77, 0xa3, 0x33, 0xe3, 0x08, 0xed,
            0x27, 0x16, 0x58, 0x04, 0x93, 0x83, 0xb7, 0xe2, 0xe5, 0x7b, 0x6b, 0x8b, 0x12, 0x55,
            0x12, 0xe0,
        ];
        let actual = sign(&message, &private_key)?;
        assert_eq!(actual, expected);
        verify(&message, &actual, &public_key)?;

        let seed = Seed::try_from(&[
            0xf5, 0xe5, 0x76, 0x7c, 0xf1, 0x53, 0x31, 0x95, 0x17, 0x63, 0x0f, 0x22, 0x68, 0x76,
            0xb8, 0x6c, 0x81, 0x60, 0xcc, 0x58, 0x3b, 0xc0, 0x13, 0x74, 0x4c, 0x6b, 0xf2, 0x55,
            0xf5, 0xcc, 0x0e, 0xe5,
        ])?;
        let (private_key, public_key) = generate_keypair_from_seed(&seed)?;
        let expected = [
            0x0a, 0xab, 0x4c, 0x90, 0x05, 0x01, 0xb3, 0xe2, 0x4d, 0x7c, 0xdf, 0x46, 0x63, 0x32,
            0x6a, 0x3a, 0x87, 0xdf, 0x5e, 0x48, 0x43, 0xb2, 0xcb, 0xdb, 0x67, 0xcb, 0xf6, 0xe4,
            0x60, 0xfe, 0xc3, 0x50, 0xaa, 0x53, 0x71, 0xb1, 0x50, 0x8f, 0x9f, 0x45, 0x28, 0xec,
            0xea, 0x23, 0xc4, 0x36, 0xd9, 0x4b, 0x5e, 0x8f, 0xcd, 0x4f, 0x68, 0x1e, 0x30, 0xa6,
            0xac, 0x00, 0xa9, 0x70, 0x4a, 0x18, 0x8a, 0x03,
        ];
        let message = [
            0x08, 0xb8, 0xb2, 0xb7, 0x33, 0x42, 0x42, 0x43, 0x76, 0x0f, 0xe4, 0x26, 0xa4, 0xb5,
            0x49, 0x08, 0x63, 0x21, 0x10, 0xa6, 0x6c, 0x2f, 0x65, 0x91, 0xea, 0xbd, 0x33, 0x45,
            0xe3, 0xe4, 0xeb, 0x98, 0xfa, 0x6e, 0x26, 0x4b, 0xf0, 0x9e, 0xfe, 0x12, 0xee, 0x50,
            0xf8, 0xf5, 0x4e, 0x9f, 0x77, 0xb1, 0xe3, 0x55, 0xf6, 0xc5, 0x05, 0x44, 0xe2, 0x3f,
            0xb1, 0x43, 0x3d, 0xdf, 0x73, 0xbe, 0x84, 0xd8, 0x79, 0xde, 0x7c, 0x00, 0x46, 0xdc,
            0x49, 0x96, 0xd9, 0xe7, 0x73, 0xf4, 0xbc, 0x9e, 0xfe, 0x57, 0x38, 0x82, 0x9a, 0xdb,
            0x26, 0xc8, 0x1b, 0x37, 0xc9, 0x3a, 0x1b, 0x27, 0x0b, 0x20, 0x32, 0x9d, 0x65, 0x86,
            0x75, 0xfc, 0x6e, 0xa5, 0x34, 0xe0, 0x81, 0x0a, 0x44, 0x32, 0x82, 0x6b, 0xf5, 0x8c,
            0x94, 0x1e, 0xfb, 0x65, 0xd5, 0x7a, 0x33, 0x8b, 0xbd, 0x2e, 0x26, 0x64, 0x0f, 0x89,
            0xff, 0xbc, 0x1a, 0x85, 0x8e, 0xfc, 0xb8, 0x55, 0x0e, 0xe3, 0xa5, 0xe1, 0x99, 0x8b,
            0xd1, 0x77, 0xe9, 0x3a, 0x73, 0x63, 0xc3, 0x44, 0xfe, 0x6b, 0x19, 0x9e, 0xe5, 0xd0,
            0x2e, 0x82, 0xd5, 0x22, 0xc4, 0xfe, 0xba, 0x15, 0x45, 0x2f, 0x80, 0x28, 0x8a, 0x82,
            0x1a, 0x57, 0x91, 0x16, 0xec, 0x6d, 0xad, 0x2b, 0x3b, 0x31, 0x0d, 0xa9, 0x03, 0x40,
            0x1a, 0xa6, 0x21, 0x00, 0xab, 0x5d, 0x1a, 0x36, 0x55, 0x3e, 0x06, 0x20, 0x3b, 0x33,
            0x89, 0x0c, 0xc9, 0xb8, 0x32, 0xf7, 0x9e, 0xf8, 0x05, 0x60, 0xcc, 0xb9, 0xa3, 0x9c,
            0xe7, 0x67, 0x96, 0x7e, 0xd6, 0x28, 0xc6, 0xad, 0x57, 0x3c, 0xb1, 0x16, 0xdb, 0xef,
            0xef, 0xd7, 0x54, 0x99, 0xda, 0x96, 0xbd, 0x68, 0xa8, 0xa9, 0x7b, 0x92, 0x8a, 0x8b,
            0xbc, 0x10, 0x3b, 0x66, 0x21, 0xfc, 0xde, 0x2b, 0xec, 0xa1, 0x23, 0x1d, 0x20, 0x6b,
            0xe6, 0xcd, 0x9e, 0xc7, 0xaf, 0xf6, 0xf6, 0xc9, 0x4f, 0xcd, 0x72, 0x04, 0xed, 0x34,
            0x55, 0xc6, 0x8c, 0x83, 0xf4, 0xa4, 0x1d, 0xa4, 0xaf, 0x2b, 0x74, 0xef, 0x5c, 0x53,
            0xf1, 0xd8, 0xac, 0x70, 0xbd, 0xcb, 0x7e, 0xd1, 0x85, 0xce, 0x81, 0xbd, 0x84, 0x35,
            0x9d, 0x44, 0x25, 0x4d, 0x95, 0x62, 0x9e, 0x98, 0x55, 0xa9, 0x4a, 0x7c, 0x19, 0x58,
            0xd1, 0xf8, 0xad, 0xa5, 0xd0, 0x53, 0x2e, 0xd8, 0xa5, 0xaa, 0x3f, 0xb2, 0xd1, 0x7b,
            0xa7, 0x0e, 0xb6, 0x24, 0x8e, 0x59, 0x4e, 0x1a, 0x22, 0x97, 0xac, 0xbb, 0xb3, 0x9d,
            0x50, 0x2f, 0x1a, 0x8c, 0x6e, 0xb6, 0xf1, 0xce, 0x22, 0xb3, 0xde, 0x1a, 0x1f, 0x40,
            0xcc, 0x24, 0x55, 0x41, 0x19, 0xa8, 0x31, 0xa9, 0xaa, 0xd6, 0x07, 0x9c, 0xad, 0x88,
            0x42, 0x5d, 0xe6, 0xbd, 0xe1, 0xa9, 0x18, 0x7e, 0xbb, 0x60, 0x92, 0xcf, 0x67, 0xbf,
            0x2b, 0x13, 0xfd, 0x65, 0xf2, 0x70, 0x88, 0xd7, 0x8b, 0x7e, 0x88, 0x3c, 0x87, 0x59,
            0xd2, 0xc4, 0xf5, 0xc6, 0x5a, 0xdb, 0x75, 0x53, 0x87, 0x8a, 0xd5, 0x75, 0xf9, 0xfa,
            0xd8, 0x78, 0xe8, 0x0a, 0x0c, 0x9b, 0xa6, 0x3b, 0xcb, 0xcc, 0x27, 0x32, 0xe6, 0x94,
            0x85, 0xbb, 0xc9, 0xc9, 0x0b, 0xfb, 0xd6, 0x24, 0x81, 0xd9, 0x08, 0x9b, 0xec, 0xcf,
            0x80, 0xcf, 0xe2, 0xdf, 0x16, 0xa2, 0xcf, 0x65, 0xbd, 0x92, 0xdd, 0x59, 0x7b, 0x07,
            0x07, 0xe0, 0x91, 0x7a, 0xf4, 0x8b, 0xbb, 0x75, 0xfe, 0xd4, 0x13, 0xd2, 0x38, 0xf5,
            0x55, 0x5a, 0x7a, 0x56, 0x9d, 0x80, 0xc3, 0x41, 0x4a, 0x8d, 0x08, 0x59, 0xdc, 0x65,
            0xa4, 0x61, 0x28, 0xba, 0xb2, 0x7a, 0xf8, 0x7a, 0x71, 0x31, 0x4f, 0x31, 0x8c, 0x78,
            0x2b, 0x23, 0xeb, 0xfe, 0x80, 0x8b, 0x82, 0xb0, 0xce, 0x26, 0x40, 0x1d, 0x2e, 0x22,
            0xf0, 0x4d, 0x83, 0xd1, 0x25, 0x5d, 0xc5, 0x1a, 0xdd, 0xd3, 0xb7, 0x5a, 0x2b, 0x1a,
            0xe0, 0x78, 0x45, 0x04, 0xdf, 0x54, 0x3a, 0xf8, 0x96, 0x9b, 0xe3, 0xea, 0x70, 0x82,
            0xff, 0x7f, 0xc9, 0x88, 0x8c, 0x14, 0x4d, 0xa2, 0xaf, 0x58, 0x42, 0x9e, 0xc9, 0x60,
            0x31, 0xdb, 0xca, 0xd3, 0xda, 0xd9, 0xaf, 0x0d, 0xcb, 0xaa, 0xaf, 0x26, 0x8c, 0xb8,
            0xfc, 0xff, 0xea, 0xd9, 0x4f, 0x3c, 0x7c, 0xa4, 0x95, 0xe0, 0x56, 0xa9, 0xb4, 0x7a,
            0xcd, 0xb7, 0x51, 0xfb, 0x73, 0xe6, 0x66, 0xc6, 0xc6, 0x55, 0xad, 0xe8, 0x29, 0x72,
            0x97, 0xd0, 0x7a, 0xd1, 0xba, 0x5e, 0x43, 0xf1, 0xbc, 0xa3, 0x23, 0x01, 0x65, 0x13,
            0x39, 0xe2, 0x29, 0x04, 0xcc, 0x8c, 0x42, 0xf5, 0x8c, 0x30, 0xc0, 0x4a, 0xaf, 0xdb,
            0x03, 0x8d, 0xda, 0x08, 0x47, 0xdd, 0x98, 0x8d, 0xcd, 0xa6, 0xf3, 0xbf, 0xd1, 0x5c,
            0x4b, 0x4c, 0x45, 0x25, 0x00, 0x4a, 0xa0, 0x6e, 0xef, 0xf8, 0xca, 0x61, 0x78, 0x3a,
            0xac, 0xec, 0x57, 0xfb, 0x3d, 0x1f, 0x92, 0xb0, 0xfe, 0x2f, 0xd1, 0xa8, 0x5f, 0x67,
            0x24, 0x51, 0x7b, 0x65, 0xe6, 0x14, 0xad, 0x68, 0x08, 0xd6, 0xf6, 0xee, 0x34, 0xdf,
            0xf7, 0x31, 0x0f, 0xdc, 0x82, 0xae, 0xbf, 0xd9, 0x04, 0xb0, 0x1e, 0x1d, 0xc5, 0x4b,
            0x29, 0x27, 0x09, 0x4b, 0x2d, 0xb6, 0x8d, 0x6f, 0x90, 0x3b, 0x68, 0x40, 0x1a, 0xde,
            0xbf, 0x5a, 0x7e, 0x08, 0xd7, 0x8f, 0xf4, 0xef, 0x5d, 0x63, 0x65, 0x3a, 0x65, 0x04,
            0x0c, 0xf9, 0xbf, 0xd4, 0xac, 0xa7, 0x98, 0x4a, 0x74, 0xd3, 0x71, 0x45, 0x98, 0x67,
            0x80, 0xfc, 0x0b, 0x16, 0xac, 0x45, 0x16, 0x49, 0xde, 0x61, 0x88, 0xa7, 0xdb, 0xdf,
            0x19, 0x1f, 0x64, 0xb5, 0xfc, 0x5e, 0x2a, 0xb4, 0x7b, 0x57, 0xf7, 0xf7, 0x27, 0x6c,
            0xd4, 0x19, 0xc1, 0x7a, 0x3c, 0xa8, 0xe1, 0xb9, 0x39, 0xae, 0x49, 0xe4, 0x88, 0xac,
            0xba, 0x6b, 0x96, 0x56, 0x10, 0xb5, 0x48, 0x01, 0x09, 0xc8, 0xb1, 0x7b, 0x80, 0xe1,
            0xb7, 0xb7, 0x50, 0xdf, 0xc7, 0x59, 0x8d, 0x5d, 0x50, 0x11, 0xfd, 0x2d, 0xcc, 0x56,
            0x00, 0xa3, 0x2e, 0xf5, 0xb5, 0x2a, 0x1e, 0xcc, 0x82, 0x0e, 0x30, 0x8a, 0xa3, 0x42,
            0x72, 0x1a, 0xac, 0x09, 0x43, 0xbf, 0x66, 0x86, 0xb6, 0x4b, 0x25, 0x79, 0x37, 0x65,
            0x04, 0xcc, 0xc4, 0x93, 0xd9, 0x7e, 0x6a, 0xed, 0x3f, 0xb0, 0xf9, 0xcd, 0x71, 0xa4,
            0x3d, 0xd4, 0x97, 0xf0, 0x1f, 0x17, 0xc0, 0xe2, 0xcb, 0x37, 0x97, 0xaa, 0x2a, 0x2f,
            0x25, 0x66, 0x56, 0x16, 0x8e, 0x6c, 0x49, 0x6a, 0xfc, 0x5f, 0xb9, 0x32, 0x46, 0xf6,
            0xb1, 0x11, 0x63, 0x98, 0xa3, 0x46, 0xf1, 0xa6, 0x41, 0xf3, 0xb0, 0x41, 0xe9, 0x89,
            0xf7, 0x91, 0x4f, 0x90, 0xcc, 0x2c, 0x7f, 0xff, 0x35, 0x78, 0x76, 0xe5, 0x06, 0xb5,
            0x0d, 0x33, 0x4b, 0xa7, 0x7c, 0x22, 0x5b, 0xc3, 0x07, 0xba, 0x53, 0x71, 0x52, 0xf3,
            0xf1, 0x61, 0x0e, 0x4e, 0xaf, 0xe5, 0x95, 0xf6, 0xd9, 0xd9, 0x0d, 0x11, 0xfa, 0xa9,
            0x33, 0xa1, 0x5e, 0xf1, 0x36, 0x95, 0x46, 0x86, 0x8a, 0x7f, 0x3a, 0x45, 0xa9, 0x67,
            0x68, 0xd4, 0x0f, 0xd9, 0xd0, 0x34, 0x12, 0xc0, 0x91, 0xc6, 0x31, 0x5c, 0xf4, 0xfd,
            0xe7, 0xcb, 0x68, 0x60, 0x69, 0x37, 0x38, 0x0d, 0xb2, 0xea, 0xaa, 0x70, 0x7b, 0x4c,
            0x41, 0x85, 0xc3, 0x2e, 0xdd, 0xcd, 0xd3, 0x06, 0x70, 0x5e, 0x4d, 0xc1, 0xff, 0xc8,
            0x72, 0xee, 0xee, 0x47, 0x5a, 0x64, 0xdf, 0xac, 0x86, 0xab, 0xa4, 0x1c, 0x06, 0x18,
            0x98, 0x3f, 0x87, 0x41, 0xc5, 0xef, 0x68, 0xd3, 0xa1, 0x01, 0xe8, 0xa3, 0xb8, 0xca,
            0xc6, 0x0c, 0x90, 0x5c, 0x15, 0xfc, 0x91, 0x08, 0x40, 0xb9, 0x4c, 0x00, 0xa0, 0xb9,
            0xd0,
        ];
        let actual = sign(&message, &private_key)?;
        assert_eq!(actual, expected);
        verify(&message, &actual, &public_key)?;

        Ok(())
    }

    #[test]
    fn multi_part_test_vectors() -> Result<(), AlkaliError> {
        let seed = Seed::try_from(&[
            0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec,
            0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03,
            0x1c, 0xae, 0x7f, 0x60,
        ])?;
        let (private_key, public_key) = generate_keypair_from_seed(&seed)?;
        let expected = [
            0xc8, 0xc8, 0xad, 0x46, 0xe4, 0xcc, 0x44, 0x17, 0x60, 0xab, 0x19, 0xd7, 0x5c, 0xf2,
            0x2e, 0x75, 0xfa, 0x7d, 0xff, 0x23, 0xb0, 0x74, 0xcc, 0xee, 0x85, 0xcd, 0x60, 0x77,
            0x49, 0xa3, 0xc7, 0xf3, 0xde, 0x34, 0xa3, 0xb3, 0xb5, 0xd5, 0x9b, 0x17, 0x9b, 0x7e,
            0x5e, 0x1c, 0xc8, 0x86, 0x38, 0xac, 0xfb, 0x03, 0xb7, 0x30, 0xb8, 0x4a, 0x68, 0x6a,
            0xec, 0x5c, 0x9d, 0xd6, 0x45, 0x39, 0x6b, 0x0c,
        ];
        let state_sign = Multipart::new()?;
        let actual = state_sign.sign(&private_key);
        assert_eq!(actual, expected);
        let state_verify = Multipart::new()?;
        state_verify.verify(&expected, &public_key)?;

        let seed = Seed::try_from(&[
            0x0a, 0x47, 0xd1, 0x04, 0x52, 0xae, 0x2f, 0xeb, 0xec, 0x51, 0x8a, 0x1c, 0x7c, 0x36,
            0x28, 0x90, 0xc3, 0xfc, 0x1a, 0x49, 0xd3, 0x4b, 0x03, 0xb6, 0x46, 0x7d, 0x35, 0xc9,
            0x04, 0xa8, 0x36, 0x2d,
        ])?;
        let (private_key, public_key) = generate_keypair_from_seed(&seed)?;
        let expected = [
            0x80, 0xf7, 0xed, 0xac, 0x56, 0x20, 0x8c, 0xad, 0xad, 0x4d, 0x9c, 0xfa, 0x5b, 0x7b,
            0xf7, 0x6e, 0x35, 0xd0, 0x03, 0x49, 0x2c, 0x00, 0x21, 0xc9, 0xb6, 0xcd, 0x0f, 0xbb,
            0x32, 0x95, 0xe2, 0xcf, 0x59, 0x71, 0x7b, 0x07, 0x40, 0x05, 0x17, 0xa7, 0x28, 0xd5,
            0x41, 0x00, 0x61, 0xfd, 0x5b, 0x57, 0x92, 0xb1, 0x43, 0x5a, 0xad, 0x3a, 0x78, 0xbe,
            0x04, 0xf3, 0x6f, 0x5d, 0x00, 0xa7, 0xb6, 0x05,
        ];
        let message = [
            0xc9, 0x42, 0xfa, 0x7a, 0xc6, 0xb2, 0x3a, 0xb7, 0xff, 0x61, 0x2f, 0xdc, 0x8e, 0x68,
            0xef, 0x39,
        ];
        let mut state_sign = Multipart::new()?;
        state_sign.update(&message[..4]);
        state_sign.update(&message[4..8]);
        state_sign.update(&message[8..12]);
        state_sign.update(&message[12..16]);
        let actual = state_sign.sign(&private_key);
        assert_eq!(actual, expected);
        let mut state_verify = Multipart::new()?;
        state_verify.update(&message[..8]);
        state_verify.update(&message[8..16]);
        state_verify.verify(&expected, &public_key)?;

        let seed = Seed::try_from(&[
            0x84, 0x00, 0x96, 0x2b, 0xb7, 0x69, 0xf6, 0x38, 0x68, 0xca, 0xe5, 0xa3, 0xfe, 0xc8,
            0xdb, 0x6a, 0x9c, 0x8d, 0x3f, 0x1c, 0x84, 0x6c, 0x8d, 0xce, 0xeb, 0x64, 0x2b, 0x69,
            0x46, 0xef, 0xa8, 0xe3,
        ])?;
        let (private_key, public_key) = generate_keypair_from_seed(&seed)?;
        let expected = [
            0x1e, 0x8a, 0xab, 0x01, 0x68, 0x07, 0xb6, 0xff, 0xda, 0x07, 0x79, 0xd0, 0x09, 0x6f,
            0xd3, 0xaa, 0xfd, 0x03, 0x98, 0x16, 0x03, 0x3a, 0xaa, 0x7e, 0xa8, 0x9f, 0x51, 0xdf,
            0xba, 0x78, 0xb6, 0xc6, 0x35, 0x82, 0x79, 0xdb, 0xfb, 0x04, 0x17, 0xc8, 0x79, 0x82,
            0x2a, 0xd0, 0x88, 0x0b, 0x4f, 0x2c, 0x1b, 0xcb, 0x10, 0xdd, 0x24, 0x84, 0x45, 0x0c,
            0xee, 0x8e, 0x9e, 0x7d, 0x61, 0x30, 0x7c, 0x0a,
        ];
        let message = [
            0x8d, 0xf8, 0xe4, 0x12, 0xfd, 0xf6, 0xc3, 0xc6, 0x4f, 0x26, 0x97, 0x3a, 0x1a, 0xbf,
            0x9e, 0x71, 0xc8, 0x62, 0x97, 0x3c, 0xeb, 0xd9, 0x86, 0x40, 0xef, 0xc5, 0xdd, 0x80,
            0x84, 0x18, 0x6e, 0x5b, 0x31, 0x2d, 0xf1, 0x9d, 0xa2, 0xdc, 0xff, 0x9f, 0x71, 0x21,
            0x74, 0xcf, 0x0c, 0xfd, 0x14, 0xf3, 0xa6, 0x78, 0x6f, 0xa4, 0x8d, 0xab, 0x25, 0x2e,
            0xf9, 0xe6, 0x61, 0x37, 0x1f, 0x5e, 0x99, 0x00,
        ];
        let mut state_sign = Multipart::new()?;
        state_sign.update(&[]);
        state_sign.update(&message[..1]);
        state_sign.update(&message[1..64]);
        let actual = state_sign.sign(&private_key);
        assert_eq!(actual, expected);
        let mut state_verify = Multipart::new()?;
        state_verify.update(&message[..63]);
        state_verify.update(&message[63..64]);
        state_verify.update(&[]);
        state_verify.verify(&expected, &public_key)?;

        let seed = Seed::try_from(&[
            0x84, 0x00, 0x96, 0x2b, 0xb7, 0x69, 0xf6, 0x38, 0x68, 0xca, 0xe5, 0xa3, 0xfe, 0xc8,
            0xdb, 0x6a, 0x9c, 0x8d, 0x3f, 0x1c, 0x84, 0x6c, 0x8d, 0xce, 0xeb, 0x64, 0x2b, 0x69,
            0x46, 0xef, 0xa8, 0xe3,
        ])?;
        let (private_key, public_key) = generate_keypair_from_seed(&seed)?;
        let expected = [
            0x8d, 0xf8, 0xe4, 0x12, 0xfd, 0xf6, 0xc3, 0xc6, 0x4f, 0x26, 0x97, 0x3a, 0x1a, 0xbf,
            0x9e, 0x71, 0xc8, 0x62, 0x97, 0x3c, 0xeb, 0xd9, 0x86, 0x40, 0xef, 0xc5, 0xdd, 0x80,
            0x84, 0x18, 0x6e, 0x5b, 0x31, 0x2d, 0xf1, 0x9d, 0xa2, 0xdc, 0xff, 0x9f, 0x71, 0x21,
            0x74, 0xcf, 0x0c, 0xfd, 0x14, 0xf3, 0xa6, 0x78, 0x6f, 0xa4, 0x8d, 0xab, 0x25, 0x2e,
            0xf9, 0xe6, 0x61, 0x37, 0x1f, 0x5e, 0x99, 0x00,
        ];
        let message = [
            0xf7, 0xe6, 0x7d, 0x98, 0x2a, 0x2f, 0xf9, 0x3e, 0xcd, 0xa4, 0x08, 0x71, 0x52, 0xb4,
            0x86, 0x4c, 0x94, 0x3b, 0x1b, 0xa7, 0x02, 0x1f, 0x54, 0x07, 0x04, 0x3c, 0xcb, 0x42,
            0x53, 0xd3, 0x48, 0xc2, 0x7b, 0x92, 0x83, 0xac, 0xb2, 0x6c, 0x19, 0x4f, 0xd1, 0xcb,
            0xb7, 0x9e, 0x6a, 0xfc, 0x32, 0xff, 0x68, 0x6b, 0x55, 0xb0, 0xb3, 0x61, 0x72, 0x18,
            0xdc, 0xf3, 0x93, 0x16, 0xb4, 0xb6, 0x6b, 0x3c, 0x8c, 0x0d, 0x67, 0x26, 0x7a, 0x86,
            0xdb, 0x8a, 0xdf, 0x37, 0x50, 0x80, 0x1b, 0xcf, 0x93, 0x27, 0xd4, 0xc2, 0x54, 0x41,
            0xb9, 0x61, 0x97, 0x83, 0x2b, 0x4c, 0xde, 0x0e, 0xac, 0x3f, 0xf2, 0x28, 0x92, 0xa2,
            0xf0, 0xbc, 0x17, 0xc2, 0xc2, 0x13, 0xc0, 0x23, 0x77, 0xa3, 0x33, 0xe3, 0x08, 0xed,
            0x27, 0x16, 0x58, 0x04, 0x93, 0x83, 0xb7, 0xe2, 0xe5, 0x7b, 0x6b, 0x8b, 0x12, 0x55,
            0x12, 0xe0,
        ];
        let mut state_sign = Multipart::new()?;
        state_sign.update(&message);
        let actual = state_sign.sign(&private_key);
        assert_eq!(actual, expected);
        let mut state_verify = Multipart::new()?;
        state_verify.update(&message);
        state_verify.verify(&expected, &public_key)?;

        Ok(())
    }
}
