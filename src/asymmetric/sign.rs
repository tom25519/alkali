//! [Cryptographic signatures](https://en.wikipedia.org/wiki/Digital_signature) (asymmetric message
//! authentication).
//!
//! This module corresponds to the [`crypto_sign`
//! API](https://doc.libsodium.org/public-key_cryptography/public-key_signatures) from Sodium.
//!
//! Cryptographic signatures are used when a party wishes to compute some form of authentication
//! tag for a message, which others can verify without the need to exchange any secret data. This
//! is in contrast to [symmetric authentication](crate::symmetric::auth), in which all parties must
//! share a secret key to verify messages.
//!
//! If someone wishes to prove they sent a message, they must first generate a keypair, made up of a
//! private and public key. The private key is kept secret, and not shared with anyone, while the
//! public key is generally shared as widely as possible. A signature for a message can then be
//! calculated using the private key. Other parties can use the public key to verify the signature
//! is valid for the message. However, they cannot construct a new signature for an arbitrary
//! message which will be verifiable with the same public key: It can only be used to verify
//! existing signatures. The private key is necessary to generate a new, valid signature.
//!
//! If you only need to prove the authenticity of a message to known parties with whom a secret key
//! is already shared, then the [`symmetric::auth`](crate::symmetric::auth) module should be less
//! computationally expensive.
//!
//! # Algorithm Details
//! [Ed25519](https://ed25519.cr.yp.to/) (EdDSA over a twisted Edwards curve birationally
//! equivalent to Curve25519) is used for single-part signatures. For multi-part signatures,
//! Ed25519ph is used, which can be thought of as signing a hash of the message rather than the
//! message itself.
//!
//! # Security Considerations
//! Ed25519 private keys require
//! [clamping](https://www.jcraige.com/an-explainer-on-ed25519-clamping) to be secure. The
//! [`Keypair::generate`] function implements clamping automatically, so if you're using this to
//! generate your keys, clamping is not an issue you need to worry about. However, if you want to
//! generate an Ed25519 key deterministically from some other source of entropy, use
//! [`Keypair::from_seed`]; don't just set the private key to a random value and call it a day.
//!
//! Be careful to consider context when signing messages. For example, signing a message which
//! simply states "I agree" could then be used by an attacker to indicate your agreement with
//! anything. Signing the message "I agree with what @someone said in message #1: we should do x" is
//! less likely to lead to your signature being used out of context.
//!
//! ## Secret Data
//! * Private keys ([`PrivateKey`]) must be kept secret
//! * A [`Keypair`] contains a [`PrivateKey`], and as such, should also be kept secret
//! * Seeds ([`Seed`]) must be kept secret
//!
//! ## Non-Secret Data
//! * Public keys ([`PublicKey`]) can (and should) be made public
//! * Signatures ([`Signature`]) are not sensitive, and do not reveal anything about the content of
//!   the signed message to an attacker
//!
//! # Examples
//! Signing and verifying a message (uses [`sign`] and [`verify`]):
//!
//! ```rust
//! use alkali::asymmetric::sign;
//!
//! const MESSAGE: &'static str = "Here's a message to sign. It can be of any length.";
//!
//! // Sender side:
//!
//! // Generate a random keypair (including a private and public key) for signing messages. The
//! // public key should be shared publicly, the private key should be kept secret.
//! let keypair = sign::Keypair::generate().unwrap();
//! // A signed message will be `SIGNATURE_LENGTH` bytes longer than the original message.
//! let mut signed_message = vec![0u8; MESSAGE.as_bytes().len() + sign::SIGNATURE_LENGTH];
//! // If this function is successful, the message + its signature will be stored in
//! // `signed_message`.
//! sign::sign(MESSAGE.as_bytes(), &keypair, &mut signed_message).unwrap();
//!
//!
//! // ...
//!
//!
//! // Receiver side:
//! // We assume the sender's public key, `public_key`, has been distributed to the receiver.
//! # let public_key = keypair.public_key;
//!
//! // The `verify` function checks that `signed_message` is a valid signature + message pair under
//! // the provided public key, and returns a slice of `signed_message` containing the original
//! // message.
//! let original = sign::verify(&signed_message, &public_key).expect("Invalid signature");
//! assert_eq!(original, MESSAGE.as_bytes());
//! ```
//!
//! Detached mode can be used to store the signature and message separately (uses [`sign_detached`]
//! and [`verify_detached`]):
//!
//! ```rust
//! use alkali::asymmetric::sign;
//!
//! const MESSAGE: &'static str = "Sign me please!";
//!
//! // Sender side:
//!
//! let keypair = sign::Keypair::generate().unwrap();
//! // Returns a signature for the message.
//! let signature = sign::sign_detached(&MESSAGE.as_bytes(), &keypair).unwrap();
//!
//!
//! // ...
//!
//!
//! // Receiver side:
//! // We assume the sender's public key, `public_key`, has been distributed to the receiver.
//! # let public_key = keypair.public_key;
//!
//! // An error will be returned if the signature is invalid.
//! sign::verify_detached(MESSAGE.as_bytes(), &signature, &public_key).unwrap();
//! ```
//!
//! If you have an especially long message, or one you're receiving in chunks, it may make more
//! sense to use the streaming API, which allows you to specify the message to sign in multiple
//! multiple parts (uses [`Multipart`]):
//!
//! ```rust
//! use alkali::asymmetric::sign;
//!
//! // Sender side:
//!
//! let keypair = sign::Keypair::generate().unwrap();
//! let mut state = sign::Multipart::new().unwrap();
//! state.update(b"Here's the first part");
//! state.update(b"... And the second!");
//! // This method returns a detached signature, rather than a combined message + signature.
//! let signature = state.sign(&keypair);
//!
//!
//! // ...
//!
//!
//! // Receiver side:
//! // We assume the sender's public key, `public_key`, has been distributed to the receiver.
//! # let public_key = keypair.public_key;
//!
//! // Now let's verify the signature we just generated. The message doesn't have to be added to the
//! // signature stream in the same chunks as it was in the signature calculation: Each piece of the
//! // message added to the state is simply concatenated in the sign & verify calculations.
//! let mut state = sign::Multipart::new().unwrap();
//! state.update(b"Here");
//! state.update(b"'s the first ");
//! state.update(b"part... And the ");
//! state.update(b"second!");
//! assert!(state.verify(&signature, &public_key).is_ok());
//! ```

crate::error_type! {
    /// Error type returned if something went wrong in the `sign` module.
    SignError {
        /// Failed to authenticate a message.
        ///
        /// The provided signature is not correct for this message + public key.
        ///
        /// This may indicate an attempted forgery, a transmission error, or that the private key
        /// used to sign this message doesn't correspond to the public key being used to verify it.
        /// In any case, the authenticity of the message can't be verified, and it should not be
        /// trusted.
        InvalidSignature,

        /// The output buffer provided was insufficient to store the signed message.
        ///
        /// When signing a message in combined mode, the output must be at least the length of the
        /// original message plus [`SIGNATURE_LENGTH`] bytes, to allow for the signature to be
        /// prepended.
        OutputInsufficient,
    }
}

/// The [Ed25519](https://ed25519.cr.yp.to/) signature scheme.
pub mod ed25519 {
    use super::SignError;
    use crate::{assert_not_err, mem, require_init, unexpected_err, AlkaliError};
    use core::marker::PhantomData;
    use core::ptr;
    use libsodium_sys as sodium;

    /// The length of a private key for signing messages, in bytes.
    pub const PRIVATE_KEY_LENGTH: usize = sodium::crypto_sign_ed25519_SECRETKEYBYTES as usize;

    /// The length of a public key for verifying message signatures, in bytes.
    pub const PUBLIC_KEY_LENGTH: usize = sodium::crypto_sign_ed25519_PUBLICKEYBYTES as usize;

    /// The length of a message signature, in bytes.
    ///
    /// No matter the length of the message to sign, the calculated signature is of this fixed
    /// length. Ed25519 may output a shorter signature, but it will be padded with zeroes to reach
    /// this size.
    pub const SIGNATURE_LENGTH: usize = sodium::crypto_sign_ed25519_BYTES as usize;

    /// The length of a seed to use for the deterministic generation of a [`Keypair`].
    pub const KEYPAIR_SEED_LENGTH: usize = sodium::crypto_sign_ed25519_SEEDBYTES as usize;

    mem::hardened_buffer! {
        /// A private key used to sign messages.
        ///
        /// A private key forms one half of a [`Keypair`], together with a [`PublicKey`]. The
        /// private key is used to sign messages, the public key is used to verify that messages
        /// have been signed with the private key.
        ///
        /// Private keys should be generated using [`Keypair::generate`]. It is not sufficient to
        /// simply set a private key to a random value: Ed25519 private keys require
        /// [clamping](https://www.jcraige.com/an-explainer-on-ed25519-clamping) to be secure. The
        /// [`Keypair::generate`] function implements clamping automatically, so if you're using
        /// this to generate your keys, clamping is not an issue you need to worry about. If you
        /// need to derive a private key deterministically, use [`Keypair::from_seed`]; don't just
        /// set the private key to a random value and call it a day.
        ///
        /// A private key is secret, and as such, should not ever be made public.
        ///
        /// This is a [hardened buffer type](https://docs.rs/alkali#hardened-buffer-types), and will
        /// be zeroed on drop. A number of other security measures are taken to protect its
        /// contents. This type in particular can be thought of as roughly equivalent to a `[u8;
        /// PRIVATE_KEY_LENGTH]`, and implements [`core::ops::Deref`], so it can be used like it is
        /// an `&[u8]`. This struct uses heap memory while in scope, allocated using Sodium's
        /// [secure memory utilities](https://doc.libsodium.org/memory_management).
        pub PrivateKey(PRIVATE_KEY_LENGTH);

        /// A seed used to deterministically derive a [`Keypair`].
        ///
        /// A seed can be used with [`Keypair::from_seed`] to deterministically derive a private key
        /// and public key. The [`Keypair::from_seed`] function implements
        /// [clamping](https://www.jcraige.com/an-explainer-on-ed25519-clamping), which is required
        /// for Ed25519 private keys to be secure.
        ///
        /// [`Keypair::get_seed`] can be used to find a seed which will produce the same keypair in
        /// the future.
        ///
        /// If a keypair derived from a seed is to be used for real-world operations, the seed
        /// should be treated as securely as the private key itself, since it is trivial to derive
        /// the private key given the seed. So, do not make seeds public.
        ///
        /// This is a [hardened buffer type](https://docs.rs/alkali#hardened-buffer-types), and will
        /// be zeroed on drop. A number of other security measures are taken to protect its
        /// contents. This type in particular can be thought of as roughly equivalent to a `[u8;
        /// KEYPAIR_SEED_LENGTH]`, and implements [`core::ops::Deref`], so it can be used like it is
        /// an `&[u8]`. This struct uses heap memory while in scope, allocated using Sodium's
        /// [secure memory utilities](https://doc.libsodium.org/memory_management).
        pub Seed(KEYPAIR_SEED_LENGTH);
    }

    /// A public key used to verify message signatures.
    ///
    /// A public key forms one half of a [`Keypair`], together with a [`PrivateKey`]. The
    /// private key is used to sign messages, the public key is used to verify that messages
    /// have been signed with the private key.
    ///
    /// A public key should be made public, unlike a private key, which must be kept secret.
    pub type PublicKey = [u8; PUBLIC_KEY_LENGTH];

    /// A message signature.
    ///
    /// This signature is what proves that a message has been signed by a specific private key, so
    /// it should be transmitted along with the message. Signatures are not sensitive, and may be
    /// transmitted in the clear.
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    #[cfg_attr(feature = "use-serde", derive(serde::Serialize, serde::Deserialize))]
    pub struct Signature(
        #[cfg_attr(feature = "use-serde", serde(with = "serde_big_array::BigArray"))]
        pub  [u8; SIGNATURE_LENGTH],
    );

    /// A ([`PrivateKey`], [`PublicKey`]) keypair, used to sign messages.
    ///
    /// An Ed25519 keypair is generated by choosing a random 32-byte value and then
    /// [clamping](https://www.jcraige.com/an-explainer-on-ed25519-clamping) it to form a private
    /// key. The corresponding public key is then derived by scalar-multiplying the generator of the
    /// underlying curve by the private key. This is the process used in [`Keypair::generate`] to
    /// generate a random keypair.
    ///
    /// The private key is used to sign messages, and must be kept secret, while the public key is
    /// used to verify messages, and should be made public.
    #[cfg_attr(feature = "use-serde", derive(serde::Serialize, serde::Deserialize))]
    pub struct Keypair {
        /// The private key for this keypair.
        pub private_key: PrivateKey,

        /// The public key corresponding to the private key.
        pub public_key: PublicKey,
    }

    impl Keypair {
        /// Generate a new, random Ed25519 keypair for use in message signing.
        ///
        /// A keypair consists of a [`PrivateKey`], which is used to sign messages and must be kept
        /// secret, and a [`PublicKey`], which is used to verify message signatures and should be
        /// made public. The generated private key will be
        /// [clamped](https://www.jcraige.com/an-explainer-on-ed25519-clamping).
        pub fn generate() -> Result<Self, AlkaliError> {
            require_init()?;

            let mut private_key = PrivateKey::new_empty()?;
            let mut public_key = [0u8; PUBLIC_KEY_LENGTH];

            let keypair_result = unsafe {
                // SAFETY: This function expects a pointer to a region of memory sufficient to store
                // a public key, and a pointer to a region of memory sufficient to store a private
                // key for this algorithm. We have defined the `PublicKey` type to be
                // `crypto_sign_PUBLICKEYBYTES`, the length of a public key for this algorithm, so
                // it is of sufficient size to store the public key. The `PrivateKey` type allocates
                // `crypto_sign_SECRETKEYBYTES`, the length of a private key for this algorithm, so
                // it is of sufficient size to store the private key. Any region of memory can be a
                // valid representation of a `u8` array, so both variables will still be valid after
                // this function call. The `PrivateKey::inner_mut` method simply returns a mutable
                // pointer to its backing memory.
                sodium::crypto_sign_ed25519_keypair(
                    &mut public_key as *mut libc::c_uchar,
                    private_key.inner_mut() as *mut libc::c_uchar,
                )
            };
            assert_not_err!(keypair_result, "crypto_sign_ed25519_keypair");

            Ok(Self {
                private_key,
                public_key,
            })
        }

        /// Deterministically derive an Ed25519 keypair for use in message signing from a seed.
        ///
        /// Given the same seed, the same keypair will always be generated. A seed which will
        /// produce an existing keypair can be calculated using [`Keypair::get_seed`].
        ///
        /// A keypair consists of a [`PrivateKey`], which is used to sign messages and must be kept
        /// secret, and a [`PublicKey`], which is used to verify message signatures and should be
        /// made public. The generated private key will be
        /// [clamped](https://www.jcraige.com/an-explainer-on-ed25519-clamping).
        pub fn from_seed(seed: &Seed) -> Result<Self, AlkaliError> {
            require_init()?;

            let mut private_key = PrivateKey::new_empty()?;
            let mut public_key = [0u8; PUBLIC_KEY_LENGTH];

            let keypair_result = unsafe {
                // SAFETY: This function expects a pointer to a region of memory sufficient to store
                // a public key, a pointer to a region of memory sufficient to store a private key,
                // and a pointer to a seed. We have defined the `PublicKey` type to be
                // `crypto_sign_PUBLICKEYBYTES`, the length of a public key for this algorithm, so
                // it is of sufficient size to store the public key. The `PrivateKey` type allocates
                // `crypto_sign_SECRETKEYBYTES`, the length of a private key for this algorithm, so
                // it is of sufficient size to store the private key. Any region of memory can be a
                // valid representation of a `u8` array, so both variables will still be valid after
                // this function call. The `PrivateKey::inner_mut` method simply returns a mutable
                // pointer to its backing memory. The `Seed` type is defined to be
                // `crypto_sign_SEEDBYTES`, and is therefore valid for reads of the length required
                // for a seed for this algorithm. The `Seed::inner` method simply returns an
                // immutable pointer to its backing memory.
                sodium::crypto_sign_ed25519_seed_keypair(
                    &mut public_key as *mut libc::c_uchar,
                    private_key.inner_mut() as *mut libc::c_uchar,
                    seed.inner() as *const libc::c_uchar,
                )
            };
            assert_not_err!(keypair_result, "crypto_sign_ed25519_seed_keypair");

            Ok(Self {
                private_key,
                public_key,
            })
        }

        /// Construct a keypair given just the [`PrivateKey`].
        ///
        /// A keypair consists of a [`PrivateKey`], which is used to sign messages and must be kept
        /// secret, and a [`PublicKey`], which is used to verify message signatures and should be
        /// made public. This function calculates the public key associated with the provided
        /// private key and stores both in a [`Keypair`]. This is useful if you know your private
        /// key, but don't have the corresponding public key.
        ///
        /// No [clamping](https://www.jcraige.com/an-explainer-on-ed25519-clamping) will be applied
        /// to the provided private key, so it is important that it is a valid private key generated
        /// by something like [`Keypair::generate`] or [`Keypair::from_seed`], not just random
        /// bytes! If you want to deterministically construct a keypair from random data, use
        /// [`Keypair::from_seed`] instead, as this will clamp the private key.
        pub fn from_private_key(private_key: &PrivateKey) -> Result<Self, AlkaliError> {
            require_init()?;

            let mut public_key = [0; PUBLIC_KEY_LENGTH];

            let sk_to_pk_result = unsafe {
                // SAFETY: This function expects a pointer to a region of memory sufficient to store
                // a public key, and a pointer to a private key. We have defined the `PublicKey`
                // type to be `crypto_sign_PUBLICKEYBYTES`, the length of a public key for this
                // algorithm, so it is of sufficient size to store the public key. Any region of
                // memory can be a valid representation of a `u8` array, so the `public_key`
                // variable will still be valid after this function call. The `PrivateKey` type
                // stores `crypto_sign_SECRETKEYBYTES`, the length of a private key for this
                // algorithm, so it is valid for reads of the expected size. The `PrivateKey::inner`
                // method simply returns an immutable pointer to its backing memory.
                sodium::crypto_sign_ed25519_sk_to_pk(
                    &mut public_key as *mut libc::c_uchar,
                    private_key.inner() as *const libc::c_uchar,
                )
            };
            assert_not_err!(sk_to_pk_result, "crypto_sign_ed25519_sk_to_pk");

            Ok(Self {
                private_key: private_key.try_clone()?,
                public_key,
            })
        }

        /// Returns a seed which can be used to derive this keypair.
        ///
        /// This function will return a [`Seed`] which will always produce this keypair when used
        /// with [`Keypair::from_seed`]. Since it is trivial to derive the private key given a seed,
        /// the seed returned here should be protected as though it were also a private key.
        pub fn get_seed(&self) -> Result<Seed, AlkaliError> {
            // We do not use `require_init` here, as it must be called to initialise a `Keypair`
            // struct.

            let mut seed = Seed::new_empty()?;

            let sk_to_seed_result = unsafe {
                // SAFETY: This function takes a pointer to a destination to which the seed should
                // be written, and a pointer to the private key from which the seed will be
                // extracted. We have defined the `Seed` type to store `crypto_sign_SEEDBYTES`, the
                // length of a seed for use with this algorithm, so it is valid for writes of the
                // required size. The `Seed::inner_mut` method returns a mutable pointer to its
                // backing memory. The `PrivateKey` type is defined to be
                // `crypto_sign_SECRETKEYBYTES`, the size of a private key for this algorithm.
                // The `PrivateKey::inner` method returns an immutable pointer to its backing
                // memory.
                sodium::crypto_sign_ed25519_sk_to_seed(
                    seed.inner_mut() as *mut libc::c_uchar,
                    self.private_key.inner() as *const libc::c_uchar,
                )
            };
            assert_not_err!(sk_to_seed_result, "crypto_sign_ed25519_sk_to_seed");

            Ok(seed)
        }
    }

    /// Streaming signature API, for long/multi-part message signatures.
    ///
    /// This can be used to sign/verify a message which is too large to fit into memory, or where
    /// the message is transmitted/received in portions.
    ///
    /// This struct uses heap memory while in scope, allocated using Sodium's [secure memory
    /// utilities](https://doc.libsodium.org/memory_management).
    #[derive(Debug)]
    pub struct Multipart {
        state: ptr::NonNull<sodium::crypto_sign_ed25519ph_state>,
        _marker: PhantomData<sodium::crypto_sign_ed25519ph_state>,
    }

    impl Multipart {
        /// Create a new instance of the struct.
        pub fn new() -> Result<Self, AlkaliError> {
            require_init()?;

            let mut state = unsafe {
                // SAFETY: This call to malloc() will allocate the memory required for a
                // `crypto_sign_state` type, outside of Rust's memory management. The associated
                // memory is always freed in the corresponding `drop` call, unless initialisation
                // fails, in which case it is freed before `Multipart::new` returns, and not used
                // again. We never free the memory in any other place in this struct, and drop can
                // only be called once, so a double-free is not possible. We never expose a pointer
                // to the allocated memory directly. See the drop implementation for more reasoning
                // on safety.
                mem::malloc()?
            };

            let init_result = unsafe {
                // SAFETY: This function initialises a `crypto_sign_state` struct. The argument
                // should be a pointer to a region of memory sufficient to store such a struct. We
                // pass a pointer to a region of memory sufficient to store the struct, allocated
                // above. The type of `state` is a `NonNull` pointer, and the unsafe block above
                // will return early if allocation failed, so the pointer is valid for use here.
                // Sodium's documentation specifies that after this function is called, the memory
                // pointed to by `state` is correctly initialised, and is a valid representation of
                // a `crypto_sign_state` struct which can be used with other functions from Sodium.
                sodium::crypto_sign_ed25519ph_init(state.as_mut())
            };

            // This return value is not possible in the current implementation of `crypto_sign_init`
            // in Sodium, but could be in the future.
            if init_result != 0 {
                unsafe {
                    // SAFETY: The memory we free here was allocated previously in this function
                    // using Sodium's allocator, and has not yet been freed, so it is valid to free
                    // it here. The `unexpected_err!` macro below will always panic, so this
                    // function will not return, and an instance of `Self` is never initialised,
                    // preventing a double-free or use-after-free.
                    mem::free(state);
                }
                unexpected_err!("crypto_sign_ed25519ph_init");
            }

            Ok(Self {
                state,
                _marker: PhantomData,
            })
        }

        /// Try to clone this Multipart state.
        ///
        /// This function initialises a new instance of this struct, in the same state as the
        /// current one, so any data written to be signed/verified in the current struct will also
        /// be used in the signature/verification calculation for the new struct.
        pub fn try_clone(&self) -> Result<Self, AlkaliError> {
            // We do not use `require_init` here, as it must be called to initialise a `Multipart`
            // struct.

            let state = unsafe {
                // SAFETY: This call to malloc() will allocate the memory required for a
                // `crypto_sign_state` type, outside of Rust's memory management. The associated
                // memory is always freed in the corresponding `drop` call, unless initialisation
                // fails, in which case it is freed before `Multipart::new` returns, and not used
                // again. We never free the memory in any other place in this struct, and drop can
                // only be called once, so a double-free is not possible. We never expose a pointer
                // to the allocated memory directly. See the drop implementation for more reasoning
                // on safety.
                let mut state = mem::malloc()?;

                // SAFETY: We have called `malloc` to allocate sufficient space for one
                // `crypto_sign_state` struct at each of the two pointers used here: `self.state`
                // was allocated in a call to `Self::new`, and `state` was allocated above, so both
                // are valid for reads/writes of `size_of::<crypto_sign_state>` bytes. We have just
                // allocated a fresh region of memory for `state`, so it definitely doesn't overlap
                // with `self.state`. To initialise an instance of `Self`, `self.state` must be a
                // valid representation of a `crypto_sign_state` struct. No methods within `Self`
                // would cause `self.state` to point to an invalid representation of a
                // `crypto_sign_state` struct. Therefore, after the copy, `state` must also point to
                // a valid representation of a `crypto_sign_state` struct, and can be used with the
                // multipart signature functions from Sodium.
                ptr::copy_nonoverlapping(self.state.as_ptr(), state.as_mut(), 1);

                state
            };

            Ok(Self {
                state,
                _marker: PhantomData,
            })
        }

        /// Add message contents to be signed/verified.
        pub fn update(&mut self, chunk: &[u8]) {
            // We do not use `require_init` here, as it must be called to initialise a `Multipart`
            // struct.

            let update_result = unsafe {
                // SAFETY: The first argument to this function is a pointer to a `crypto_sign_state`
                // struct. `self.state` must be correctly initialised, and point to a valid
                // representation of a `crypto_sign_state` struct to instantiate the `Multipart`
                // struct, so it is in the correct state to use with this function. The next two
                // arguments specify the portion of the message to add to the signature/verification
                // calculation, and its length. We use `chunk.len()` to specify the length of the
                // message to read from `chunk`, so `chunk` is definitely valid for reads of the
                // specified length.
                sodium::crypto_sign_ed25519ph_update(
                    self.state.as_mut(),
                    chunk.as_ptr(),
                    chunk.len() as libc::c_ulonglong,
                )
            };

            assert_not_err!(update_result, "crypto_sign_ed25519ph_update");
        }

        /// Calculate the signature for the specified message under the given keypair.
        ///
        /// Equivalent to [`sign_detached`] for single-part messages.
        pub fn sign(mut self, keypair: &Keypair) -> Signature {
            // We do not use `require_init` here, as it must be called to initialise a `Multipart`
            // struct.

            let mut signature = [0u8; SIGNATURE_LENGTH];

            let sign_result = unsafe {
                // SAFETY: The first argument to this function is a pointer to a `crypto_sign_state`
                // struct. `self.state` must be correctly initialised, and point to a valid
                // representation of a `crypto_sign_state` struct to instantiate the `Multipart`
                // struct, so it is in the correct state to use with this function. The next
                // argument specifies a destination to which the signature will be written. Sodium
                // will write a signature of `crypto_sign_BYTES` to this destination. We have
                // defined the `signature` array to be `crypto_sign_BYTES` bytes long, so it is
                // valid for writes of this length. The next argument specifies the destination to
                // which Sodium should write the calculated signature's length, without padding. It
                // is documented that if a NULL pointer is passed to this function for this
                // argument, Sodium will simply ignore it, and the length will not be written. We
                // pass a NULL pointer here, as Sodium will pad the signature so it is always
                // `crypto_sign_BYTES` bytes long. The final argument should be a pointer to the
                // private key to use to sign the message. We have defined the `PrivateKey` type to
                // be `crypto_sign_SECRETKEYBYTES` bytes long, the expected length for a private key
                // for this algorithm. Therefore, the private key can be read from
                // `keypair.private_key` without an over-read. The `PrivateKey::inner` method simply
                // returns an immutable pointer to its backing memory.
                sodium::crypto_sign_ed25519ph_final_create(
                    self.state.as_mut(),
                    signature.as_mut_ptr(),
                    ptr::null_mut(),
                    keypair.private_key.inner() as *const libc::c_uchar,
                )
            };
            assert_not_err!(sign_result, "crypto_sign_ed25519ph_final_create");

            Signature(signature)
        }

        /// Verify the provided signature is correct for the specified message and public key.
        ///
        /// Returns a [`SignError::InvalidSignature`] if verification of the signature failed.
        ///
        /// Equivalent to [`verify_detached`] for single-part messages.
        pub fn verify(
            mut self,
            signature: &Signature,
            public_key: &PublicKey,
        ) -> Result<(), AlkaliError> {
            // We do not use `require_init` here, as it must be called to initialise a `Multipart`
            // struct.

            let verification_result = unsafe {
                // SAFETY: The first argument to this function is a pointer to a `crypto_sign_state`
                // struct. `self.state` must be correctly initialised, and point to a valid
                // representation of a `crypto_sign_state` struct to instantiate the `Multipart`
                // struct, so it is in the correct state to use with this function. The next
                // argument specifies the signature to verify, which should be of
                // `crypto_sign_BYTES` bytes in length. We define the `Signature` type to be
                // `crypto_sign_BYTES` bytes long, so it is valid for reads of the expected length.
                // The final argument should be a pointer to the public key to use to sign the
                // message. We have defined the `PublicKey` type to be `crypto_sign_PUBLICKEYBYTES`
                // bytes long, the expected length for a public key for this algorithm. Therefore,
                // the public key can be read from `public_key` without an over-read.
                sodium::crypto_sign_ed25519ph_final_verify(
                    self.state.as_mut(),
                    signature.0.as_ptr(),
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

    impl Drop for Multipart {
        fn drop(&mut self) {
            // We do not use `require_init` here, as it must be called to initialise a `Multipart`
            // struct.

            unsafe {
                // SAFETY:
                // * Is a double-free possible in safe code?
                //   * No: We only free in `drop`, which cannot be called manually, and is called
                //     exactly once when the struct is actually dropped. Once the value is dropped,
                //     there's no way to call the method again to cause a double free.
                // * Is a use-after-free possible in safe code?
                //   * No: We only ever free `self.state` on drop, and after drop, none of the
                //     type's methods are accessible.
                // * Is a memory leak possible in safe code?
                //   * Yes: If the user uses something like `Box::leak()`, `ManuallyDrop`, or
                //     `core::mem::forget`, the destructor will not be called even though the struct
                //     is dropped. However, it is documented that in these cases heap memory may be
                //     leaked, so this is expected behaviour. In addition, certain signal interrupts
                //     or using panic=abort behaviour will mean the destructor is not called.
                //     There's little we can do about this, but a failure to free is probably
                //     reasonable in such cases. In any other case, `drop` will be called, and the
                //     memory freed.
                // `self.state` was allocated in the `Multipart` constructor using Sodium's
                // allocator, so it is correct to free it using Sodium's allocator.
                mem::free(self.state);
            }
        }
    }

    /// Sign the provided message using the given keypair, writing a combined signature + message to
    /// `output`.
    ///
    /// The resulting signature + message combination can be verified using [`verify`], with the
    /// public key from `keypair.public_key`.
    ///
    /// `output` must be at least `message.len()` plus [`SIGNATURE_LENGTH`] bytes long.
    ///
    /// Returns the number of bytes written to `output` if signing was successful. If signing was
    /// unsuccessful, the contents of `output` are unspecified, and an error will be returned.
    pub fn sign(
        message: &[u8],
        keypair: &Keypair,
        output: &mut [u8],
    ) -> Result<usize, AlkaliError> {
        require_init()?;

        let output_size = message.len() + SIGNATURE_LENGTH;
        if output.len() < output_size {
            return Err(SignError::OutputInsufficient.into());
        }

        let sign_result = unsafe {
            // SAFETY: The first argument to this function is the destination to which the combined
            // signature + message should be written. It is documented that the size of this output
            // will be the length of the input + `crypto_sign_BYTES`. We verify above that the
            // length of `output` is at least of this length, so it is definitely valid for writes
            // of the required length. The next argument specifies the destination to which Sodium
            // should write the combined signature + message length. It is documented that if a NULL
            // pointer is passed to this function for this argument, Sodium will simply ignore it,
            // and the length will not be written. We pass a NULL pointer here, as we know what the
            // length will be already. The next two arguments specify the message to sign and its
            // length. We use `message.len()` to specify the length of the message, so `message` is
            // clearly valid for reads of this length. The final argument should be a pointer to the
            // private key to use to sign the message. We have defined the `PrivateKey` type to
            // be `crypto_sign_SECRETKEYBYTES` bytes long, the expected length for a private key
            // for this algorithm. Therefore, the private key can be read from
            // `keypair.private_key` without an over-read. The `PrivateKey::inner` method simply
            // returns an immutable pointer to its backing memory.
            sodium::crypto_sign_ed25519(
                output.as_mut_ptr() as *mut libc::c_uchar,
                ptr::null_mut(),
                message.as_ptr() as *const libc::c_uchar,
                message.len() as libc::c_ulonglong,
                keypair.private_key.inner() as *const libc::c_uchar,
            )
        };
        assert_not_err!(sign_result, "crypto_sign_ed25519");

        Ok(output_size)
    }

    /// Sign the provided message using the given keypair, returning the signature separately.
    ///
    /// The resulting signature can be verified using [`verify_detached`], with the public key from
    /// `keypair.public_key`.
    pub fn sign_detached(message: &[u8], keypair: &Keypair) -> Result<Signature, AlkaliError> {
        require_init()?;

        let mut signature = [0u8; SIGNATURE_LENGTH];

        let sign_result = unsafe {
            // SAFETY: The first argument to this function is the destination to which the signature
            // should be written. It is documented that the size of the signature will be
            // `crypto_sign_BYTES`. We have defined the `signature` array to be of this length, so
            // it is valid for writes of the required size. The next argument specifies the
            // destination to which Sodium should write the calculated signature length. It is
            // documented that if a NULL pointer is passed to this function for this argument,
            // Sodium will simply ignore it, and the length will not be written. We pass a NULL
            // pointer here, as the signature is always of a constant length after padding. The next
            // two arguments specify the message to sign and its length. We use `message.len()` to
            // specify the length of the message, so `message` is clearly valid for reads of this
            // length. The final argument should be a pointer to the private key to use to sign the
            // message. We have defined the `PrivateKey` type to be `crypto_sign_SECRETKEYBYTES`
            // bytes long, the expected length for a private key for this algorithm. Therefore, the
            // private key can be read from `keypair.private_key` without an over-read. The
            // `PrivateKey::inner` method simply returns an immutable pointer to its backing memory.
            sodium::crypto_sign_ed25519_detached(
                &mut signature as *mut libc::c_uchar,
                ptr::null_mut(),
                message.as_ptr() as *const libc::c_uchar,
                message.len() as libc::c_ulonglong,
                keypair.private_key.inner() as *const libc::c_uchar,
            )
        };
        assert_not_err!(sign_result, "crypto_sign_ed25519_detached");

        Ok(Signature(signature))
    }

    /// Verifies that the combined signature + message is valid under the given public key.
    ///
    /// `signed_message` must be at least [`SIGNATURE_LENGTH`] bytes long.
    ///
    /// Returns a slice containing the original message if the signature was valid. Otherwise
    /// returns a [`SignError::InvalidSignature`] error if verification failed, or another error if
    /// there was some other issue. The slice returned by this function will be [`SIGNATURE_LENGTH`]
    /// bytes shorter than the input.
    pub fn verify<'a>(
        signed_message: &'a [u8],
        public_key: &PublicKey,
    ) -> Result<&'a [u8], AlkaliError> {
        require_init()?;

        if signed_message.len() < SIGNATURE_LENGTH {
            return Err(SignError::InvalidSignature.into());
        }

        let verification_result = unsafe {
            // SAFETY: The first argument to this function is the destination to which the original
            // message should be written. If a NULL pointer is passed for this argument, Sodium will
            // not write the message. We pass a NULL pointer here, as we do not need another copy of
            // the message. The next argument specifies the destination to which Sodium should write
            // the original message length. It is documented that if a NULL pointer is passed to
            // this function for this argument, Sodium will simply ignore it, and the length will
            // not be written. We pass a NULL pointer here, as we know what the length will be
            // already. The next two arguments specify the signed message to verify and its length.
            // We use `signed_message.len()` to specify the length of the message, so
            // `signed_message` is clearly valid for reads of this length. The final argument should
            // be a pointer to the public key to use to verify the message. We have defined the
            // `PublicKey` type to be `crypto_sign_PUBLICKEYBYTES` bytes long, the expected length
            // for a public key for this algorithm. Therefore, the public key can be read from
            // `keypair.public_key` without an over-read.
            sodium::crypto_sign_ed25519_open(
                ptr::null_mut(),
                ptr::null_mut(),
                signed_message.as_ptr() as *const libc::c_uchar,
                signed_message.len() as libc::c_ulonglong,
                public_key as *const libc::c_uchar,
            )
        };

        if verification_result == 0 {
            // The combined signature + message format places the signature first, so we can
            // retrieve the original message by simply reading after `crypto_sign_BYTES` into the
            // signed message
            Ok(&signed_message[SIGNATURE_LENGTH..])
        } else {
            Err(SignError::InvalidSignature.into())
        }
    }

    /// Verifies that the given signature is valid for the provided message, under the given public
    /// key.
    ///
    /// Returns a [`SignError::InvalidSignature`] error if verification failed.
    pub fn verify_detached(
        message: &[u8],
        signature: &Signature,
        public_key: &PublicKey,
    ) -> Result<(), AlkaliError> {
        require_init()?;

        let verification_result = unsafe {
            // SAFETY: The first argument to this function should bee the signature to verify. We
            // have defined the `Signature` type to be `crypto_sign_BYTES` bytes long, the expected
            // size of a (padded) signature for this algorithm, so it is valid for reads of the
            // required size. The next two arguments specify the message to verify and its length.
            // We use `message.len()` to specify the length of the message, so `message` is clearly
            // valid for reads of this length. The final argument should be a pointer to the public
            // key to use to verify the message. We have defined the `PublicKey` type to be
            // `crypto_sign_PUBLICKEYBYTES` bytes long, the expected length for a public key for
            // this algorithm. Therefore, the public key can be read from `keypair.public_key`
            // without an over-read.
            sodium::crypto_sign_ed25519_verify_detached(
                &signature.0 as *const libc::c_uchar,
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

    #[cfg(test)]
    mod tests {
        use super::{
            sign, sign_detached, verify, verify_detached, Keypair, Multipart, Seed, Signature,
            SIGNATURE_LENGTH,
        };
        use crate::random::fill_random;
        use crate::AlkaliError;

        #[test]
        fn keypair_generation_works() -> Result<(), AlkaliError> {
            let keypair = Keypair::generate()?;
            let keypair_new = Keypair::from_private_key(&keypair.private_key)?;
            assert_eq!(keypair.public_key, keypair_new.public_key);
            Ok(())
        }

        #[test]
        fn keypair_from_seed_vectors() -> Result<(), AlkaliError> {
            let seed = Seed::try_from(&[
                0x42, 0x11, 0x51, 0xa4, 0x59, 0xfa, 0xea, 0xde, 0x3d, 0x24, 0x71, 0x15, 0xf9, 0x4a,
                0xed, 0xae, 0x42, 0x31, 0x81, 0x24, 0x09, 0x5a, 0xfa, 0xbe, 0x4d, 0x14, 0x51, 0xa5,
                0x59, 0xfa, 0xed, 0xee,
            ])?;
            let keypair = Keypair::from_seed(&seed)?;

            assert_eq!(
                &keypair.private_key[..],
                &[
                    0x42, 0x11, 0x51, 0xa4, 0x59, 0xfa, 0xea, 0xde, 0x3d, 0x24, 0x71, 0x15, 0xf9,
                    0x4a, 0xed, 0xae, 0x42, 0x31, 0x81, 0x24, 0x09, 0x5a, 0xfa, 0xbe, 0x4d, 0x14,
                    0x51, 0xa5, 0x59, 0xfa, 0xed, 0xee, 0xb5, 0x07, 0x6a, 0x84, 0x74, 0xa8, 0x32,
                    0xda, 0xee, 0x4d, 0xd5, 0xb4, 0x04, 0x09, 0x83, 0xb6, 0x62, 0x3b, 0x5f, 0x34,
                    0x4a, 0xca, 0x57, 0xd4, 0xd6, 0xee, 0x4b, 0xaf, 0x3f, 0x25, 0x9e, 0x6e
                ]
            );
            assert_eq!(
                &keypair.public_key,
                &[
                    0xb5, 0x07, 0x6a, 0x84, 0x74, 0xa8, 0x32, 0xda, 0xee, 0x4d, 0xd5, 0xb4, 0x04,
                    0x09, 0x83, 0xb6, 0x62, 0x3b, 0x5f, 0x34, 0x4a, 0xca, 0x57, 0xd4, 0xd6, 0xee,
                    0x4b, 0xaf, 0x3f, 0x25, 0x9e, 0x6e
                ]
            );
            assert_eq!(keypair.get_seed()?, seed);

            Ok(())
        }

        #[test]
        fn sign_and_verify() -> Result<(), AlkaliError> {
            let keypair = Keypair::generate()?;

            let mut input_buf = [0; 1 << 15];
            let mut output_buf = [0; (1 << 15) + SIGNATURE_LENGTH];

            fill_random(&mut input_buf)?;

            let written = sign(&[], &keypair, &mut output_buf)?;
            assert_eq!(written, SIGNATURE_LENGTH);
            verify(&output_buf[..written], &keypair.public_key)?;

            let written = sign(&input_buf[..16], &keypair, &mut output_buf)?;
            assert_eq!(written, SIGNATURE_LENGTH + 16);
            verify(&output_buf[..written], &keypair.public_key)?;

            let written = sign(&input_buf[..128], &keypair, &mut output_buf)?;
            assert_eq!(written, SIGNATURE_LENGTH + 128);
            verify(&output_buf[..written], &keypair.public_key)?;

            let written = sign(&input_buf[..1024], &keypair, &mut output_buf)?;
            assert_eq!(written, SIGNATURE_LENGTH + 1024);
            verify(&output_buf[..written], &keypair.public_key)?;

            let written = sign(&input_buf, &keypair, &mut output_buf)?;
            assert_eq!(written, SIGNATURE_LENGTH + (1 << 15));
            verify(&output_buf[..written], &keypair.public_key)?;

            fill_random(&mut output_buf)?;
            assert!(verify(&output_buf[..written], &keypair.public_key).is_err());

            Ok(())
        }

        #[test]
        fn sign_and_verify_detached() -> Result<(), AlkaliError> {
            let keypair = Keypair::generate()?;

            let buf_a = [];
            let mut buf_b = [0; 16];
            let mut buf_c = [0; 128];
            let mut buf_d = [0; 1024];
            let mut buf_e = [0; 1 << 15];

            fill_random(&mut buf_b)?;
            fill_random(&mut buf_c)?;
            fill_random(&mut buf_d)?;
            fill_random(&mut buf_e)?;

            let sig_a = sign_detached(&buf_a, &keypair)?;
            let sig_b = sign_detached(&buf_b, &keypair)?;
            let sig_c = sign_detached(&buf_c, &keypair)?;
            let sig_d = sign_detached(&buf_d, &keypair)?;
            let sig_e = sign_detached(&buf_e, &keypair)?;

            verify_detached(&buf_a, &sig_a, &keypair.public_key)?;
            verify_detached(&buf_b, &sig_b, &keypair.public_key)?;
            verify_detached(&buf_c, &sig_c, &keypair.public_key)?;
            verify_detached(&buf_d, &sig_d, &keypair.public_key)?;
            verify_detached(&buf_e, &sig_e, &keypair.public_key)?;

            fill_random(&mut buf_b)?;
            fill_random(&mut buf_c)?;
            fill_random(&mut buf_d)?;
            fill_random(&mut buf_e)?;

            assert!(verify_detached(&buf_b, &sig_b, &keypair.public_key).is_err());
            assert!(verify_detached(&buf_c, &sig_c, &keypair.public_key).is_err());
            assert!(verify_detached(&buf_d, &sig_d, &keypair.public_key).is_err());
            assert!(verify_detached(&buf_e, &sig_e, &keypair.public_key).is_err());

            Ok(())
        }

        #[test]
        fn single_part_test_vectors() -> Result<(), AlkaliError> {
            let seed = Seed::try_from(&[
                0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec,
                0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03,
                0x1c, 0xae, 0x7f, 0x60,
            ])?;
            let keypair = Keypair::from_seed(&seed)?;
            let expected = Signature([
                0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72, 0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e,
                0x82, 0x8a, 0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74, 0xd8, 0x73, 0xe0, 0x65,
                0x22, 0x49, 0x01, 0x55, 0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac, 0xc6, 0x1e,
                0x39, 0x70, 0x1c, 0xf9, 0xb4, 0x6b, 0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24,
                0x65, 0x51, 0x41, 0x43, 0x8e, 0x7a, 0x10, 0x0b,
            ]);
            let message = [];
            let actual = sign_detached(&message, &keypair)?;
            assert_eq!(actual, expected);
            verify_detached(&message, &actual, &keypair.public_key)?;

            let seed = Seed::try_from(&[
                0x0a, 0x47, 0xd1, 0x04, 0x52, 0xae, 0x2f, 0xeb, 0xec, 0x51, 0x8a, 0x1c, 0x7c, 0x36,
                0x28, 0x90, 0xc3, 0xfc, 0x1a, 0x49, 0xd3, 0x4b, 0x03, 0xb6, 0x46, 0x7d, 0x35, 0xc9,
                0x04, 0xa8, 0x36, 0x2d,
            ])?;
            let keypair = Keypair::from_seed(&seed)?;
            let expected = Signature([
                0x2a, 0x3d, 0x27, 0xdc, 0x40, 0xd0, 0xa8, 0x12, 0x79, 0x49, 0xa3, 0xb7, 0xf9, 0x08,
                0xb3, 0x68, 0x8f, 0x63, 0xb7, 0xf1, 0x4f, 0x65, 0x1a, 0xac, 0xd7, 0x15, 0x94, 0x0b,
                0xdb, 0xe2, 0x7a, 0x08, 0x09, 0xaa, 0xc1, 0x42, 0xf4, 0x7a, 0xb0, 0xe1, 0xe4, 0x4f,
                0xa4, 0x90, 0xba, 0x87, 0xce, 0x53, 0x92, 0xf3, 0x3a, 0x89, 0x15, 0x39, 0xca, 0xf1,
                0xef, 0x4c, 0x36, 0x7c, 0xae, 0x54, 0x50, 0x0c,
            ]);
            let message = [
                0xc9, 0x42, 0xfa, 0x7a, 0xc6, 0xb2, 0x3a, 0xb7, 0xff, 0x61, 0x2f, 0xdc, 0x8e, 0x68,
                0xef, 0x39,
            ];
            let actual = sign_detached(&message, &keypair)?;
            assert_eq!(actual, expected);
            verify_detached(&message, &actual, &keypair.public_key)?;

            let seed = Seed::try_from(&[
                0x84, 0x00, 0x96, 0x2b, 0xb7, 0x69, 0xf6, 0x38, 0x68, 0xca, 0xe5, 0xa3, 0xfe, 0xc8,
                0xdb, 0x6a, 0x9c, 0x8d, 0x3f, 0x1c, 0x84, 0x6c, 0x8d, 0xce, 0xeb, 0x64, 0x2b, 0x69,
                0x46, 0xef, 0xa8, 0xe3,
            ])?;
            let keypair = Keypair::from_seed(&seed)?;
            let expected = Signature([
                0x0a, 0xd7, 0x1b, 0x00, 0x25, 0xf3, 0xd9, 0xa5, 0x0d, 0xb3, 0x38, 0x41, 0x4d, 0x6d,
                0x67, 0x0e, 0x77, 0x99, 0xb7, 0x27, 0x0a, 0x84, 0x44, 0xf6, 0xae, 0x7f, 0x12, 0xae,
                0x7e, 0xb7, 0x1b, 0xd0, 0x3f, 0xfd, 0x3c, 0x4f, 0x36, 0x63, 0x1f, 0x69, 0xfd, 0xcc,
                0x40, 0x61, 0x46, 0x8f, 0xf5, 0x82, 0xed, 0xe4, 0x95, 0x24, 0x3e, 0xf1, 0x36, 0x1a,
                0x3b, 0x32, 0x95, 0xfa, 0x81, 0x3b, 0xa2, 0x05,
            ]);
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
            let actual = sign_detached(&message, &keypair)?;
            assert_eq!(actual, expected);
            verify_detached(&message, &actual, &keypair.public_key)?;

            let seed = Seed::try_from(&[
                0xf5, 0xe5, 0x76, 0x7c, 0xf1, 0x53, 0x31, 0x95, 0x17, 0x63, 0x0f, 0x22, 0x68, 0x76,
                0xb8, 0x6c, 0x81, 0x60, 0xcc, 0x58, 0x3b, 0xc0, 0x13, 0x74, 0x4c, 0x6b, 0xf2, 0x55,
                0xf5, 0xcc, 0x0e, 0xe5,
            ])?;
            let keypair = Keypair::from_seed(&seed)?;
            let expected = Signature([
                0x0a, 0xab, 0x4c, 0x90, 0x05, 0x01, 0xb3, 0xe2, 0x4d, 0x7c, 0xdf, 0x46, 0x63, 0x32,
                0x6a, 0x3a, 0x87, 0xdf, 0x5e, 0x48, 0x43, 0xb2, 0xcb, 0xdb, 0x67, 0xcb, 0xf6, 0xe4,
                0x60, 0xfe, 0xc3, 0x50, 0xaa, 0x53, 0x71, 0xb1, 0x50, 0x8f, 0x9f, 0x45, 0x28, 0xec,
                0xea, 0x23, 0xc4, 0x36, 0xd9, 0x4b, 0x5e, 0x8f, 0xcd, 0x4f, 0x68, 0x1e, 0x30, 0xa6,
                0xac, 0x00, 0xa9, 0x70, 0x4a, 0x18, 0x8a, 0x03,
            ]);
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
            let actual = sign_detached(&message, &keypair)?;
            assert_eq!(actual, expected);
            verify_detached(&message, &actual, &keypair.public_key)?;

            Ok(())
        }

        #[test]
        fn multi_part_test_vectors() -> Result<(), AlkaliError> {
            let seed = Seed::try_from(&[
                0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec,
                0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03,
                0x1c, 0xae, 0x7f, 0x60,
            ])?;
            let keypair = Keypair::from_seed(&seed)?;
            let expected = Signature([
                0xc8, 0xc8, 0xad, 0x46, 0xe4, 0xcc, 0x44, 0x17, 0x60, 0xab, 0x19, 0xd7, 0x5c, 0xf2,
                0x2e, 0x75, 0xfa, 0x7d, 0xff, 0x23, 0xb0, 0x74, 0xcc, 0xee, 0x85, 0xcd, 0x60, 0x77,
                0x49, 0xa3, 0xc7, 0xf3, 0xde, 0x34, 0xa3, 0xb3, 0xb5, 0xd5, 0x9b, 0x17, 0x9b, 0x7e,
                0x5e, 0x1c, 0xc8, 0x86, 0x38, 0xac, 0xfb, 0x03, 0xb7, 0x30, 0xb8, 0x4a, 0x68, 0x6a,
                0xec, 0x5c, 0x9d, 0xd6, 0x45, 0x39, 0x6b, 0x0c,
            ]);
            let state_sign = Multipart::new()?;
            let actual = state_sign.sign(&keypair);
            assert_eq!(actual, expected);
            let state_verify = Multipart::new()?;
            state_verify.verify(&expected, &keypair.public_key)?;

            let seed = Seed::try_from(&[
                0x0a, 0x47, 0xd1, 0x04, 0x52, 0xae, 0x2f, 0xeb, 0xec, 0x51, 0x8a, 0x1c, 0x7c, 0x36,
                0x28, 0x90, 0xc3, 0xfc, 0x1a, 0x49, 0xd3, 0x4b, 0x03, 0xb6, 0x46, 0x7d, 0x35, 0xc9,
                0x04, 0xa8, 0x36, 0x2d,
            ])?;
            let keypair = Keypair::from_seed(&seed)?;
            let expected = Signature([
                0x80, 0xf7, 0xed, 0xac, 0x56, 0x20, 0x8c, 0xad, 0xad, 0x4d, 0x9c, 0xfa, 0x5b, 0x7b,
                0xf7, 0x6e, 0x35, 0xd0, 0x03, 0x49, 0x2c, 0x00, 0x21, 0xc9, 0xb6, 0xcd, 0x0f, 0xbb,
                0x32, 0x95, 0xe2, 0xcf, 0x59, 0x71, 0x7b, 0x07, 0x40, 0x05, 0x17, 0xa7, 0x28, 0xd5,
                0x41, 0x00, 0x61, 0xfd, 0x5b, 0x57, 0x92, 0xb1, 0x43, 0x5a, 0xad, 0x3a, 0x78, 0xbe,
                0x04, 0xf3, 0x6f, 0x5d, 0x00, 0xa7, 0xb6, 0x05,
            ]);
            let message = [
                0xc9, 0x42, 0xfa, 0x7a, 0xc6, 0xb2, 0x3a, 0xb7, 0xff, 0x61, 0x2f, 0xdc, 0x8e, 0x68,
                0xef, 0x39,
            ];
            let mut state_sign = Multipart::new()?;
            state_sign.update(&message[..4]);
            state_sign.update(&message[4..8]);
            state_sign.update(&message[8..12]);
            state_sign.update(&message[12..16]);
            let actual = state_sign.sign(&keypair);
            assert_eq!(actual, expected);
            let mut state_verify = Multipart::new()?;
            state_verify.update(&message[..8]);
            state_verify.update(&message[8..16]);
            state_verify.verify(&expected, &keypair.public_key)?;

            let seed = Seed::try_from(&[
                0x84, 0x00, 0x96, 0x2b, 0xb7, 0x69, 0xf6, 0x38, 0x68, 0xca, 0xe5, 0xa3, 0xfe, 0xc8,
                0xdb, 0x6a, 0x9c, 0x8d, 0x3f, 0x1c, 0x84, 0x6c, 0x8d, 0xce, 0xeb, 0x64, 0x2b, 0x69,
                0x46, 0xef, 0xa8, 0xe3,
            ])?;
            let keypair = Keypair::from_seed(&seed)?;
            let expected = Signature([
                0x1e, 0x8a, 0xab, 0x01, 0x68, 0x07, 0xb6, 0xff, 0xda, 0x07, 0x79, 0xd0, 0x09, 0x6f,
                0xd3, 0xaa, 0xfd, 0x03, 0x98, 0x16, 0x03, 0x3a, 0xaa, 0x7e, 0xa8, 0x9f, 0x51, 0xdf,
                0xba, 0x78, 0xb6, 0xc6, 0x35, 0x82, 0x79, 0xdb, 0xfb, 0x04, 0x17, 0xc8, 0x79, 0x82,
                0x2a, 0xd0, 0x88, 0x0b, 0x4f, 0x2c, 0x1b, 0xcb, 0x10, 0xdd, 0x24, 0x84, 0x45, 0x0c,
                0xee, 0x8e, 0x9e, 0x7d, 0x61, 0x30, 0x7c, 0x0a,
            ]);
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
            let actual = state_sign.sign(&keypair);
            assert_eq!(actual, expected);
            let mut state_verify = Multipart::new()?;
            state_verify.update(&message[..63]);
            state_verify.update(&message[63..64]);
            state_verify.update(&[]);
            state_verify.verify(&expected, &keypair.public_key)?;

            let seed = Seed::try_from(&[
                0x84, 0x00, 0x96, 0x2b, 0xb7, 0x69, 0xf6, 0x38, 0x68, 0xca, 0xe5, 0xa3, 0xfe, 0xc8,
                0xdb, 0x6a, 0x9c, 0x8d, 0x3f, 0x1c, 0x84, 0x6c, 0x8d, 0xce, 0xeb, 0x64, 0x2b, 0x69,
                0x46, 0xef, 0xa8, 0xe3,
            ])?;
            let keypair = Keypair::from_seed(&seed)?;
            let expected = Signature([
                0x8d, 0xf8, 0xe4, 0x12, 0xfd, 0xf6, 0xc3, 0xc6, 0x4f, 0x26, 0x97, 0x3a, 0x1a, 0xbf,
                0x9e, 0x71, 0xc8, 0x62, 0x97, 0x3c, 0xeb, 0xd9, 0x86, 0x40, 0xef, 0xc5, 0xdd, 0x80,
                0x84, 0x18, 0x6e, 0x5b, 0x31, 0x2d, 0xf1, 0x9d, 0xa2, 0xdc, 0xff, 0x9f, 0x71, 0x21,
                0x74, 0xcf, 0x0c, 0xfd, 0x14, 0xf3, 0xa6, 0x78, 0x6f, 0xa4, 0x8d, 0xab, 0x25, 0x2e,
                0xf9, 0xe6, 0x61, 0x37, 0x1f, 0x5e, 0x99, 0x00,
            ]);
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
            let actual = state_sign.sign(&keypair);
            assert_eq!(actual, expected);
            let mut state_verify = Multipart::new()?;
            state_verify.update(&message);
            state_verify.verify(&expected, &keypair.public_key)?;

            Ok(())
        }
    }
}

pub use ed25519::*;
