//! Symmetric Authenticated Encryption for a sequence of messages, or chunks of a single message.
//!
//! This module corresponds to the [`crypto_secretsteam`
//! API](https://doc.libsodium.org/secret-key_cryptography/secretstream) from Sodium.
//!
//! This construction is used to encrypt a sequence of messages, producing a sequence of
//! ciphertexts which cannot be truncated, removed, reordered, duplicated, or modified without
//! detection. This can be used in symmetric protocols, where a sequence of messages must be sent,
//! and in file encryption, where chunks of a single arbitrarily large message are encrypted in
//! order. As this is a symmetric construction, all parties who wish to encrypt or decrypt messages
//! must share the same secret key, which is used for both encryption and decryption.
//!
//! This API satisfies the following properties:
//! * Messages cannot be truncated, removed, reordered, duplicated, or modified without this being
//!   detected by the decryption functions
//! * The same sequence encrypted twice will produce different ciphertexts
//! * An authentication tag is added to each encrypted message: Stream corruption or alteration
//!   will be detected early, without having to read the stream to its end
//! * A message can include additional data (e.g: timestamp, protocol version) in the computation
//!   of the authentication tag: While this data is not encrypted, any attempt to modify it will be
//!   detected
//! * Messages can have different sizes
//! * There are no practical limits to the total length of the stream, or to the total number of
//!   individual messages
//! * Ratcheting: At any point in the stream, it is possible to "forget" the key used to encrypt
//!   the previous messages, and switch to a new key
//!
//! # Algorithm Details
//! The AEAD cipher at the core of this algorithm is the IETF ChaCha20Poly1305 construction,
//! defined in [RFC 8439](https://datatracker.ietf.org/doc/html/rfc8439), which uses a variant of
//! [ChaCha20](https://cr.yp.to/chacha.html) to encrypt messages, with
//! [Poly1305](https://en.wikipedia.org/wiki/Poly1305) for authentication.
//!
//! The [Sodium documentation for this
//! API](https://doc.libsodium.org/secret-key_cryptography/secretstream#algorithm) has more
//! information on how exactly the stream construction operates.
//!
//! # Security Considerations
//! If many trusted parties have access to the secret key, there is no way to prove which one of
//! them sent a given message without additional information.
//!
//! This construction exposes the length of the plaintext. If this is undesirable, apply padding to
//! This construction exposes the length of the plaintext. If this is undesirable, apply padding to
//! the plaintext prior to encryption via [`util::pad`](crate::util::pad), and remove it following
//! decryption via [`util::unpad`](crate::util::unpad).
//!
//! # Examples
//! Stream encryption and decryption:
//!
//! ```rust
//! use alkali::symmetric::cipher_stream;
//!
//! const MESSAGE1: &'static str = "Arbitrary data to encrypt";
//! const MESSAGE2: &'static str = "split into";
//! const MESSAGE3: &'static str = "three messages :)";
//!
//! // Prior to communication:
//!
//! // A random secret key is generated & distribyted to all parties:
//! let key = cipher_stream::Key::generate().unwrap();
//!
//!
//! // ...
//!
//!
//! // Sender side:
//! // We assume the sender knows `key`.
//!
//! // Each encrypted message will be `OVERHEAD_LENGTH` bytes longer than the original message.
//! let mut c1 = vec![0u8; MESSAGE1.as_bytes().len() + cipher_stream::OVERHEAD_LENGTH];
//! let mut c2 = vec![0u8; MESSAGE2.as_bytes().len() + cipher_stream::OVERHEAD_LENGTH];
//! let mut c3 = vec![0u8; MESSAGE3.as_bytes().len() + cipher_stream::OVERHEAD_LENGTH];
//! // An `EncryptionStream` is used to encrypt messages in sequence.
//! let mut enc_stream = cipher_stream::EncryptionStream::new(&key).unwrap();
//! // The `header` marks the start of the stream, and will be needed for decryption.
//! let header = enc_stream.get_header();
//! // Encrypt the messages & indicate the end of the stream when done. The `None` variant here
//! // indicates we will not supply additional authenticated data with each message.
//! enc_stream.encrypt(MESSAGE1.as_bytes(), None, &mut c1).unwrap();
//! enc_stream.encrypt(MESSAGE2.as_bytes(), None, &mut c2).unwrap();
//! enc_stream.finalise(MESSAGE3.as_bytes(), None, &mut c3).unwrap();
//!
//!
//! // ...
//!
//!
//! // Receiver side:
//! // We assume the receiver knows `key`.
//!
//! let mut m1 = vec![0u8; c1.len() - cipher_stream::OVERHEAD_LENGTH];
//! let mut m2 = vec![0u8; c2.len() - cipher_stream::OVERHEAD_LENGTH];
//! let mut m3 = vec![0u8; c3.len() - cipher_stream::OVERHEAD_LENGTH];
//! // A `DecryptionStream` is used to decrypt messages in sequence.
//! let mut dec_stream = cipher_stream::DecryptionStream::new(&key, &header).unwrap();
//! // Decrypt the messages. Again, no additional authenticated data is specified.
//! dec_stream.decrypt(&c1, None, &mut m1).unwrap();
//! dec_stream.decrypt(&c2, None, &mut m2).unwrap();
//! dec_stream.decrypt(&c3, None, &mut m3).unwrap();
//!
//! assert!(dec_stream.is_finalised());
//! assert_eq!(&m1, MESSAGE1.as_bytes());
//! assert_eq!(&m2, MESSAGE2.as_bytes());
//! assert_eq!(&m3, MESSAGE3.as_bytes());
//! ```
//!
//! File encryption: See
//! [`examples/file-encryption.rs`](https://github.com/tom25519/alkali/blob/main/examples/file-encryption.rs)

crate::error_type! {
    /// Error type returned if something went wrong in the `symmetric::cipher_stream` module.
    CipherStreamError {
        /// The output buffer is too short to store the ciphertext/plaintext which would result from
        /// encrypting/decrypting this message.
        ///
        /// Each function in this module should provide information in its documentation about the
        /// output length requirements.
        OutputInsufficient,

        /// Message too long for encryption/decryption with this API.
        ///
        /// An individual message can only be up to
        /// [`MESSAGE_LENGTH_MAX`](struct@MESSAGE_LENGTH_MAX) bytes before the keystream is
        /// exhausted. Longer messages should be split into multiple chunks.
        MessageTooLong,

        /// Tried to write to/read from a stream where a message with the "FINAL" tag has been sent.
        StreamFinalised,

        /// Indicates decryption of the stream failed.
        ///
        /// This could indicate an attempted forgery, or transmission error.
        DecryptionFailed,
    }
}

pub mod xchacha20poly1305 {
    use super::CipherStreamError;
    use crate::{assert_not_err, mem, require_init, unexpected_err, AlkaliError};
    use core::marker::PhantomData;
    use core::ptr;
    use libsodium_sys as sodium;

    /// Types of message which can be sent as part of a stream.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    #[allow(clippy::cast_possible_truncation)]
    #[repr(u8)]
    pub enum MessageType {
        /// Indicates a standard message, doesn't add any information about its nature.
        Message = sodium::crypto_secretstream_xchacha20poly1305_TAG_MESSAGE as libc::c_uchar,

        /// Used to indicate that a message marks the end of a set of messages, but not the end of
        /// the stream.
        ///
        /// For example, a huge JSON string sent as multiple chunks can use this tag to indicate to
        /// the application that the string is complete and that it can be decoded. The stream
        /// itself is not closed, and more data may follow.
        ///
        /// The interpretation of this message type is left up to the application.
        Push = sodium::crypto_secretstream_xchacha20poly1305_TAG_PUSH as libc::c_uchar,

        /// Switch to a new key to encrypt future messages, forgetting the previous key.
        ///
        /// Receipt of a message with the `Rekey` type will automatically cause all parties to
        /// generate a new key.  No other information needs to be transmitted to agree on the key:
        /// it is derived based on the previous subkey, but not in such a way that the previous
        /// subkey can be obtained from the new key (ratcheting).
        Rekey = sodium::crypto_secretstream_xchacha20poly1305_TAG_REKEY as libc::c_uchar,

        /// Indicates the message marks the end of the stream.
        ///
        /// After a message with this type has been received, no more messages can be sent, and the
        /// secret key used for the cipher will be erased.
        Final = sodium::crypto_secretstream_xchacha20poly1305_TAG_FINAL as libc::c_uchar,
    }

    /// The length of a symmetric key used for encryption/decryption of a stream, in bytes.
    pub const KEY_LENGTH: usize = sodium::crypto_secretstream_xchacha20poly1305_KEYBYTES as usize;

    /// The extra length added to a message following encryption, in bytes.
    pub const OVERHEAD_LENGTH: usize =
        sodium::crypto_secretstream_xchacha20poly1305_ABYTES as usize;

    /// The length of a stream header, in bytes.
    pub const HEADER_LENGTH: usize =
        sodium::crypto_secretstream_xchacha20poly1305_HEADERBYTES as usize;

    lazy_static::lazy_static! {
        /// The maximum length of an individual message within the stream which can be encrypted
        /// using this construction, in bytes.
        pub static ref MESSAGE_LENGTH_MAX: usize = unsafe {
            // SAFETY: This function just returns a constant value, and should always be safe to
            // call.
            sodium::crypto_secretstream_xchacha20poly1305_messagebytes_max()
        };
    }

    mem::hardened_buffer! {
        /// Secret key for symmetric authenticated encryption/decryption of a stream of messages.
        ///
        /// There are no *technical* constraints on the contents of a key, but it should be
        /// indistinguishable from random noise. A random key can be securely generated via
        /// [`Key::generate`].
        ///
        /// A secret key must not be made public.
        ///
        /// This is a [hardened buffer type](https://docs.rs/alkali#hardened-buffer-types), and will
        /// be zeroed on drop. A number of other security measures are also taken to protect its
        /// contents. This type in particular can be thought of as roughly equivalent to a
        /// `[u8; KEY_LENGTH]`, and implements [`core::ops::Deref`] so it can be used like it is an
        /// `&[u8]`. This struct uses heap memory while in scope, allocated using Sodium's [secure
        /// memory utilities](https://doc.libsodium.org/memory_management).
        pub Key(KEY_LENGTH);
    }

    impl Key<mem::FullAccess> {
        /// Generate a new, random key for use in stream encryption.
        pub fn generate() -> Result<Self, AlkaliError> {
            require_init()?;

            let mut key = Self::new_empty()?;
            unsafe {
                // SAFETY: The argument to this function should be a location to which a randomly
                // generated key will be written. The key will be of size
                // `crypto_secretstream_xchacha20poly1305_KEYBYTES`, so the argument must be valid
                // for writes of this length. The `Key` type allocates this many bytes, so it is
                // valid for writes of the required size. The `Key::inner_mut` method simply returns
                // a mutable pointer to its backing memory.
                sodium::crypto_secretstream_xchacha20poly1305_keygen(key.inner_mut().cast());
            }
            Ok(key)
        }
    }

    /// A stream header, calculated during encryption initialisation, required for decryption.
    pub type Header = [u8; HEADER_LENGTH];

    /// The encryption side of a cipher stream, used to encrypt messages in sequence.
    ///
    /// This struct stores the state of the cipher stream, used to keep track of where we are in the
    /// message sequence, and rekey when necessary.
    pub struct EncryptionStream {
        state: ptr::NonNull<sodium::crypto_secretstream_xchacha20poly1305_state>,
        header: Header,
        _marker: PhantomData<sodium::crypto_secretstream_xchacha20poly1305_state>,
    }

    impl EncryptionStream {
        /// Create a new encryption stream.
        ///
        /// `Key` should be the symmetric [`Key`] with which the stream is to be secured. The same
        /// key will be required to decrypt the stream.
        ///
        /// Returns a new [`EncryptionStream`] instance, or an error if Sodium could not be
        /// initialised.
        pub fn new(key: &Key<impl mem::MprotectReadable>) -> Result<Self, AlkaliError> {
            require_init()?;

            let mut header = [0u8; HEADER_LENGTH];

            let mut state = unsafe {
                // SAFETY: This call to malloc() will allocate the memory required for a
                // `crypto_secretstream_state` type, outside of Rust's memory management. The
                // associated memory is always freed in the corresponding `drop` call, unless
                // initialisation fails, in which case it is freed before `EncryptionStream::new`
                // returns, and not used again. We never free the memory in any other place in this
                // struct, and drop can only be called once, so a double-free is not possible. We
                // never expose a pointer to the allocated memory directly. See the drop
                // implementation for more reasoning on safety.
                mem::malloc()?
            };

            let init_result = unsafe {
                // SAFETY: This function initialises a `crypto_secretstream_state` struct. The first
                // argument should be a pointer to a region of memory sufficient to store such a
                // struct. We pass a pointer to a region of memory sufficient to store the struct,
                // allocated above. The type of `state` is a `NonNull` pointer, and the unsafe block
                // above will return early if allocation failed, so the pointer is valid for use
                // here. Sodium's documentation states that after this function is called, if its
                // return code indicates success (checked below), then the memory pointed to by
                // `state` is correctly initialised, and is a valid representation of a
                // `crypto_secretstream_state` struct which can be used with other functions from
                // Sodium. The second argument specifies the location to which the stream header
                // should be written. We have defined the `header` array to be
                // `crypto_secretstream_HEADERBYTES` bytes, the length of a header for this
                // construction, so it is valid for writes of the required length. The final
                // argument specifies the key to use to encrypt the stream. We have defined the
                // `Key` type to allocate `crypto_secretstream_KEYBYTES` bytes, the length of a key
                // for this algorithm, so it is valid for reads of the expected length.
                sodium::crypto_secretstream_xchacha20poly1305_init_push(
                    state.as_mut(),
                    header.as_mut_ptr(),
                    key.inner().cast(),
                )
            };

            // This return value is not possible in the current implementation of
            // `crypto_secretstream_init_push` in Sodium, but could be in the future.
            if init_result != 0 {
                unsafe {
                    // SAFETY: The memory we free here was allocated previously in this function
                    // using Sodium's allocator, and has not yet been freed, so it is valid to free
                    // it here. The `unexpected_err!` macro below will always panic, so this
                    // function will not return, and an instance of `Self` is never initialised,
                    // preventing a double-free or use-after-free.
                    mem::free(state);
                }
                unexpected_err!("crypto_secretstream_xchacha20poly1305_init_push");
            }

            Ok(Self {
                state,
                header,
                _marker: PhantomData,
            })
        }

        /// Get the header for this cipher stream.
        ///
        /// The header is required for decryption, and contains the initial nonce from which the
        /// subkey and message nonces are derived. It should be sent before the rest of the stream.
        pub fn get_header(&self) -> Header {
            self.header
        }

        /// Encrypt a message with the given type for inclusion in the stream, writing the result to
        /// `output`.
        fn encrypt_impl(
            &mut self,
            message: &[u8],
            ad: Option<&[u8]>,
            output: &mut [u8],
            mtype: MessageType,
        ) -> Result<usize, AlkaliError> {
            // We do not use `require_init` here, as it must be called to initialise a `Multipart`
            // struct.

            let c_len = message.len() + OVERHEAD_LENGTH;

            if output.len() < c_len {
                return Err(CipherStreamError::OutputInsufficient.into());
            } else if message.len() > *MESSAGE_LENGTH_MAX {
                return Err(CipherStreamError::MessageTooLong.into());
            }

            let (ad_ptr, ad_len) = if let Some(ad_inner) = ad {
                (ad_inner.as_ptr(), ad_inner.len())
            } else {
                (ptr::null::<libc::c_uchar>(), 0)
            };

            let push_result = unsafe {
                // SAFETY: The first argument to this function should be a pointer to a
                // `crypto_secretstream_state` struct. The initialisation of the `EncryptionStream`
                // struct allocates sufficient memory to the `self.state` pointer to store a
                // `crypto_secretstream_state` struct, so the pointer is valid for reads/writes of
                // the required length. Furthermore, the initialisation process for
                // `EncryptionStream` requires a call to `crypto_secretstream_init_push`, so the
                // `self.state` pointer does point to a correctly initialised instance of this
                // struct for use with this function. The next argument specifies the destination
                // pointer to which the encrypted ciphertext will be written. The ciphertext will be
                // of the same length as the message, and the MAC/message tag will always be
                // `crypto_secretstream_ABYTES`, so as long as the output pointer is valid for
                // writes of `message.len + crypto_secretstream_ABYTES`, it is valid to use here. We
                // verify this condition above, and return an error if the output is insufficient.
                // The next argument is a pointer to which the number of bytes written to `output`
                // will be written. It is documented that if this is set to a NULL pointer, it will
                // simply be ignored. The next two arguments specify the message to encrypt and its
                // length. We use `message.len()` to specify the length, so `message` is clearly
                // valid for reads of this size. The next two arguments specify the additional data
                // to authenticate and its length. If additional data has been provided, we simply
                // pass the slice & its length as arguments. If additional data has not been
                // provided, we pass a NULL pointer, which it is documented will cause Sodium to
                // simply ignore the AD. The final argument is the message tag to use. Each variant
                // of the `MessageType` enum is represented using the integers defined by Sodium, so
                // the value when converted to a `u8` will be valid here.
                sodium::crypto_secretstream_xchacha20poly1305_push(
                    self.state.as_mut(),
                    output.as_mut_ptr(),
                    ptr::null_mut(),
                    message.as_ptr(),
                    message.len() as libc::c_ulonglong,
                    ad_ptr,
                    ad_len as libc::c_ulonglong,
                    mtype as u8,
                )
            };
            assert_not_err!(push_result, "crypto_secretstream_xchacha20poly1305_push");

            Ok(c_len)
        }

        /// Encrypt `message` for inclusion in the stream, writing the resulting ciphertext to
        /// `output`.
        ///
        /// When a [`DecryptionStream`] receives this message, the [`MessageType`] will be
        /// [`MessageType::Message`].
        ///
        /// `message` should be the message to encrypt.
        ///
        /// `ad` can contain additional data which will be included in the calculation of the
        /// authentication tag. This will not be encrypted or included in the ciphertext, but will
        /// be authenticated, and will be necessary for the decryption. This is often useful for
        /// including protocol details or other information which does not need to be encrypted, but
        /// should be authenticated.
        ///
        /// The encrypted ciphertext will be written to `output`, which must be at least
        /// [`OVERHEAD_LENGTH`] bytes longer than `message`. If the `output` slice is not sufficient
        /// to store the ciphertext, an error will be returned.
        ///
        /// Returns the number of bytes written to `output`.
        ///
        /// Messages should be sent in the order they were encrypted to the decrypting party. The
        /// order in which messages are encrypted matters, and attempting to decrypt messages out of
        /// order will fail.
        pub fn encrypt(
            &mut self,
            message: &[u8],
            ad: Option<&[u8]>,
            output: &mut [u8],
        ) -> Result<usize, AlkaliError> {
            self.encrypt_impl(message, ad, output, MessageType::Message)
        }

        /// Encrypt a [Push](MessageType::Push) message for inclusion in the stream, writing the
        /// resulting ciphertext to `output`.
        ///
        /// A "Push" message indicates to the receiver that this message marks the end of a set of
        /// messages, but not the end of the cipher stream. For example, a huge JSON string sent as
        /// multiple chunks can use this tag to indicate to the application that the string is
        /// complete and can be decoded. But the stream itself is not closed, and more data may
        /// follow. The interpretation of a "Push" message is left up to the application.
        ///
        /// When a [`DecryptionStream`] receives this message, the [`MessageType`] will be
        /// [`MessageType::Push`].
        ///
        /// `message` should be the message to encrypt.
        ///
        /// `ad` can contain additional data which will be included in the calculation of the
        /// authentication tag. This will not be encrypted or included in the ciphertext, but will
        /// be authenticated, and will be necessary for the decryption. This is often useful for
        /// including protocol details or other information which does not need to be encrypted, but
        /// should be authenticated.
        ///
        /// The encrypted ciphertext will be written to `output`, which must be at least
        /// [`OVERHEAD_LENGTH`] bytes longer than `message`. If the `output` slice is not sufficient
        /// to store the ciphertext, an error will be returned.
        ///
        /// Returns the number of bytes written to `output`.
        ///
        /// Messages should be sent in the order they were encrypted to the decrypting party. The
        /// order in which messages are encrypted matters, and attempting to decrypt messages out of
        /// order will fail.
        pub fn encrypt_push(
            &mut self,
            message: &[u8],
            ad: Option<&[u8]>,
            output: &mut [u8],
        ) -> Result<usize, AlkaliError> {
            self.encrypt_impl(message, ad, output, MessageType::Push)
        }

        /// Encrypt a [Rekey](MessageType::Rekey) message for inclusion in the stream, writing the
        /// resulting ciphertext to `output`.
        ///
        /// A "Rekey" message is like a normal message, but causes both the sender and receiver to
        /// change to a new secret key to encrypt future messages, forgetting the previous key. The
        /// [`EncryptionStream`] and [`DecryptionStream`] structs automatically manage this
        /// rekeying, and no further action is required by API users on sending/receiving a Rekey
        /// message.
        ///
        /// When a [`DecryptionStream`] receives this message, the [`MessageType`] will be
        /// [`MessageType::Rekey`].
        ///
        /// `message` should be the message to encrypt.
        ///
        /// `ad` can contain additional data which will be included in the calculation of the
        /// authentication tag. This will not be encrypted or included in the ciphertext, but will
        /// be authenticated, and will be necessary for the decryption. This is often useful for
        /// including protocol details or other information which does not need to be encrypted, but
        /// should be authenticated.
        ///
        /// The encrypted ciphertext will be written to `output`, which must be at least
        /// [`OVERHEAD_LENGTH`] bytes longer than `message`. If the `output` slice is not sufficient
        /// to store the ciphertext, an error will be returned.
        ///
        /// Returns the number of bytes written to `output`.
        ///
        /// Messages should be sent in the order they were encrypted to the decrypting party. The
        /// order in which messages are encrypted matters, and attempting to decrypt messages out of
        /// order will fail.
        pub fn encrypt_rekey(
            &mut self,
            message: &[u8],
            ad: Option<&[u8]>,
            output: &mut [u8],
        ) -> Result<usize, AlkaliError> {
            self.encrypt_impl(message, ad, output, MessageType::Rekey)
        }

        /// Trigger a rekey without adding any information about the key change to the stream.
        ///
        /// This function updates the internal state, moving to the next key to encrypt future
        /// messages, and forgetting the previous key. However, no information is added to the
        /// cipher stream to communicate to the receiver that a rekey has taken place, so care must
        /// be taken by API users to ensure that [`DecryptionStream::rekey`] is also called at the
        /// same location in the stream.
        ///
        /// Using [`EncryptionStream::encrypt_rekey`] may be preferable, as it communicates to the
        /// receiver a rekey has occurred, and no application-defined sync is required.
        pub fn rekey(&mut self) {
            // We do not use `require_init` here, as it must be called to initialise a `Multipart`
            // struct.

            unsafe {
                // SAFETY: The argument to this function should be a pointer to a
                // `crypto_secretstream_state` struct. The initialisation of the `EncryptionStream`
                // struct allocates sufficient memory to the `self.state` pointer to store a
                // `crypto_secretstream_state` struct, so the pointer is valid for reads/writes of
                // the required length. Furthermore, the initialisation process for
                // `EncryptionStream` requires a call to `crypto_secretstream_init_push`, so the
                // `self.state` pointer does point to a correctly initialised instance of this
                // struct for use with this function.
                sodium::crypto_secretstream_xchacha20poly1305_rekey(self.state.as_mut());
            }
        }

        /// Encrypt a [Final](MessageType::Final) message and close the stream, writing the
        /// ciphertext to `output`.
        ///
        /// A "Final" message can contain any contents, like a normal message, but marks the end of
        /// the cipher stream. After the Final message, no more messages can be sent.
        ///
        /// When a [`DecryptionStream`] receives this message, the [`MessageType`] will be
        /// [`MessageType::Final`].
        ///
        /// `message` should be the message to encrypt.
        ///
        /// `ad` can contain additional data which will be included in the calculation of the
        /// authentication tag. This will not be encrypted or included in the ciphertext, but will
        /// be authenticated, and will be necessary for the decryption. This is often useful for
        /// including protocol details or other information which does not need to be encrypted, but
        /// should be authenticated.
        ///
        /// The encrypted ciphertext will be written to `output`, which must be at least
        /// [`OVERHEAD_LENGTH`] bytes longer than `message`. If the `output` slice is not sufficient
        /// to store the ciphertext, an error will be returned.
        ///
        /// Returns the number of bytes written to `output`.
        ///
        /// Messages should be sent in the order they were encrypted to the decrypting party. The
        /// order in which messages are encrypted matters, and attempting to decrypt messages out of
        /// order will fail.
        pub fn finalise(
            mut self,
            message: &[u8],
            ad: Option<&[u8]>,
            output: &mut [u8],
        ) -> Result<usize, AlkaliError> {
            self.encrypt_impl(message, ad, output, MessageType::Final)
        }
    }

    impl Drop for EncryptionStream {
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
                //   * No: We only ever free a buffer on drop, and after drop, none of the type's
                //     methods are accessible.
                // * Is a memory leak possible in safe code?
                //   * Yes: If the user uses something like `Box::leak()`, `ManuallyDrop`, or
                //     `core::mem::forget`, the destructor will not be called even though the struct
                //     is dropped. However, it is documented that in these cases heap memory may be
                //     leaked, so this is expected behaviour. In addition, certain signal interrupts
                //     or using panic=abort behaviour will mean the destructor is not called.
                //     There's little we can do about this, but a failure to free is probably
                //     reasonable in such cases. In any other case, `drop` will be called, and the
                //     memory freed.
                // `self.state` was allocated in the `EncryptionStream` constructor using Sodium's
                // allocator, so it is correct to free it using Sodium's allocator.
                mem::free(self.state);
            }
        }
    }

    /// The decryption side of a cipher stream, used to decrypt messages in sequence.
    ///
    /// This struct stores the state of the cipher stream, used to keep track of where we are in the
    /// message sequence, and rekey when necessary.
    pub struct DecryptionStream {
        state: ptr::NonNull<sodium::crypto_secretstream_xchacha20poly1305_state>,
        finalised: bool,
        _marker: PhantomData<sodium::crypto_secretstream_xchacha20poly1305_state>,
    }

    impl DecryptionStream {
        /// Create a new decryption stream.
        ///
        /// `Key` should be the symmetric [`Key`] with which the stream is secured. The same key
        /// should have been used to encrypt the stream. `header` should be the [`Header`] generated
        /// for the cipher stream on the sender's side: This can be obtained using
        /// [`EncryptionStream::get_header`].
        ///
        /// Returns a new [`DecryptionStream`] instance, or an error if Sodium could not be
        /// initialised.
        pub fn new(
            key: &Key<impl mem::MprotectReadable>,
            header: &Header,
        ) -> Result<Self, AlkaliError> {
            require_init()?;

            let mut state = unsafe {
                // SAFETY: This call to malloc() will allocate the memory required for a
                // `crypto_secretstream_state` type, outside of Rust's memory management. The
                // associated memory is always freed in the corresponding `drop` call, unless
                // initialisation fails, in which case it is freed before `DecryptionStream::new`
                // returns, and not used again. We never free the memory in any other place in this
                // struct, and drop can only be called once, so a double-free is not possible. We
                // never expose a pointer to the allocated memory directly. See the drop
                // implementation for more reasoning on safety.
                mem::malloc()?
            };

            let init_result = unsafe {
                // SAFETY: This function initialises a `crypto_secretstream_state` struct. The first
                // argument should be a pointer to a region of memory sufficient to store such a
                // struct. We pass a pointer to a region of memory sufficient to store the struct,
                // allocated above. The type of `state` is a `NonNull` pointer, and the unsafe block
                // above will return early if allocation failed, so the pointer is valid for use
                // here. Sodium's documentation states that after this function is called, if its
                // return code indicates success (checked below), then the memory pointed to by
                // `state` is correctly initialised, and is a valid representation of a
                // `crypto_secretstream_state` struct which can be used with other functions from
                // Sodium. The second argument should be a pointer to the stream header. We have
                // defined the `Header` type to be `crypto_secretstream_HEADERBYTES` bytes, the
                // length of a header for this construction, so it is valid for reads of the
                // required length. The final argument specifies the key to use to decrypt the
                // stream. We have defined the `Key` type to allocate `crypto_secretstream_KEYBYTES`
                // bytes, the length of a key for this algorithm, so it is valid for reads of the
                // expected length.
                sodium::crypto_secretstream_xchacha20poly1305_init_pull(
                    state.as_mut(),
                    header.as_ptr(),
                    key.inner().cast(),
                )
            };

            if init_result != 0 {
                return Err(CipherStreamError::DecryptionFailed.into());
            }

            Ok(Self {
                state,
                finalised: false,
                _marker: PhantomData,
            })
        }

        /// Is the stream finalised?
        ///
        /// After the stream has been finalised, no more messages can be received.
        #[must_use]
        pub fn is_finalised(&self) -> bool {
            self.finalised
        }

        /// Decrypt & authenticate `message` (part of the cipher stream), writing the resulting
        /// plaintext to `output`.
        ///
        /// `ciphertext` should be the message to encrypt.
        ///
        /// `ad` can contain additional data which was included in the calculation of the
        /// authentication tag in the encryption stream. This is not be encrypted or included in the
        /// ciphertext, but will be authenticated, and is necessary for the decryption. This is
        /// often useful for including protocol details or other information which does not need to
        /// be encrypted, but should be authenticated.
        ///
        /// If authentication + decryption succeed, the decrypted message will be written to
        /// `output`, which must be at least `message.len()` - [`OVERHEAD_LENGTH`] bytes. If the
        /// `output` slice is not sufficient to store the plaintext, an error will be returned.
        ///
        /// Returns the [`MessageType`] of the message, and the number of bytes written to `output`.
        /// After the [`MessageType::Final`] message has been received, the stream is closed, and
        /// trying to call `decrypt` again will result in an error.
        ///
        /// Messages should be decrypted in the order they were encrypted. The order in which
        /// messages are encrypted matters, and attempting to decrypt messages out of order will
        /// fail.
        #[allow(clippy::cast_lossless)]
        pub fn decrypt(
            &mut self,
            ciphertext: &[u8],
            ad: Option<&[u8]>,
            output: &mut [u8],
        ) -> Result<(MessageType, usize), AlkaliError> {
            // We do not use `require_init` here, as it must be called to initialise a `Multipart`
            // struct.

            if self.finalised {
                return Err(CipherStreamError::StreamFinalised.into());
            }

            if ciphertext.len() < OVERHEAD_LENGTH {
                return Err(CipherStreamError::DecryptionFailed.into());
            }

            let m_len = ciphertext.len() - OVERHEAD_LENGTH;

            if output.len() < m_len {
                return Err(CipherStreamError::OutputInsufficient.into());
            }

            let (ad_ptr, ad_len) = if let Some(ad_inner) = ad {
                (ad_inner.as_ptr(), ad_inner.len())
            } else {
                (ptr::null::<libc::c_uchar>(), 0)
            };

            let mut tag = 0u8;

            let decrypt_result = unsafe {
                // SAFETY: The first argument to this function should be a pointer to a
                // `crypto_secretstream_state` struct. The initialisation of the `DecryptionStream`
                // struct allocates sufficient memory to the `self.state` pointer to store a
                // `crypto_secretstream_state` struct, so the pointer is valid for reads/writes of
                // the required length. Furthermore, the initialisation process for
                // `DecryptionStream` requires a call to `crypto_secretstream_init_pull`, so the
                // `self.state` pointer does point to a correctly initialised instance of this
                // struct for use with this function. The next argument specifies the destination
                // pointer to which the decrypted plaintext will be written. The plaintext will be
                // `crypto_secretstream_ABYTES` shorter than the ciphertext, so as long as the
                // output pointer is valid for writes of `ciphertext.len -
                // crypto_secretstream_ABYTES`, it is valid to use here. We verify this condition
                // above, and return an error if the output is insufficient. The next argument is a
                // pointer to which the number of bytes written to `output` will be written. It is
                // documented that if this is set to a NULL pointer, it will simply be ignored. The
                // next argument is the destination to which the message tag will be written. This
                // should be a pointer to an 8-bit unsigned integer. We pass a pointer to a `u8`,
                // which satisfies this. The next two arguments specify the ciphertext to decrypt
                // and its length. We use `ciphertext.len()` to specify the length, so `ciphertext`
                // is clearly valid for reads of this size. The next two arguments specify the
                // additional data to authenticate and its length. If additional data has been
                // provided, we simply pass the slice & its length as arguments. If additional data
                // has not been provided, we pass a NULL pointer, which it is documented will cause
                // Sodium to simply ignore the AD.
                sodium::crypto_secretstream_xchacha20poly1305_pull(
                    self.state.as_mut(),
                    output.as_mut_ptr(),
                    ptr::null_mut(),
                    &mut tag,
                    ciphertext.as_ptr(),
                    ciphertext.len() as libc::c_ulonglong,
                    ad_ptr,
                    ad_len as libc::c_ulonglong,
                )
            };

            if decrypt_result != 0 {
                return Err(CipherStreamError::DecryptionFailed.into());
            }

            let tag = match tag as u32 {
                sodium::crypto_secretstream_xchacha20poly1305_TAG_MESSAGE => MessageType::Message,
                sodium::crypto_secretstream_xchacha20poly1305_TAG_PUSH => MessageType::Push,
                sodium::crypto_secretstream_xchacha20poly1305_TAG_REKEY => MessageType::Rekey,
                sodium::crypto_secretstream_xchacha20poly1305_TAG_FINAL => {
                    self.finalised = true;
                    MessageType::Final
                }
                // no other tags are defined in Sodium at the time of writing
                _ => unreachable!(),
            };

            Ok((tag, m_len))
        }

        /// Trigger a rekey without adding any information about the key change to the stream.
        ///
        /// This function updates the internal state, moving to the next key to encrypt future
        /// messages, and forgetting the previous key. Care must be taken by API users to ensure
        /// that this function is called at the same time in the stream as
        /// [`EncryptionStream::rekey`].
        pub fn rekey(&mut self) {
            // We do not use `require_init` here, as it must be called to initialise a `Multipart`
            // struct.

            unsafe {
                // SAFETY: The argument to this function should be a pointer to a
                // `crypto_secretstream_state` struct. The initialisation of the `DecryptionStream`
                // struct allocates sufficient memory to the `self.state` pointer to store a
                // `crypto_secretstream_state` struct, so the pointer is valid for reads/writes of
                // the required length. Furthermore, the initialisation process for
                // `DecryptionStream` requires a call to `crypto_secretstream_init_pull`, so the
                // `self.state` pointer does point to a correctly initialised instance of this
                // struct for use with this function.
                sodium::crypto_secretstream_xchacha20poly1305_rekey(self.state.as_mut());
            }
        }
    }

    impl Drop for DecryptionStream {
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
                //   * No: We only ever free a buffer on drop, and after drop, none of the type's
                //     methods are accessible.
                // * Is a memory leak possible in safe code?
                //   * Yes: If the user uses something like `Box::leak()`, `ManuallyDrop`, or
                //     `core::mem::forget`, the destructor will not be called even though the struct
                //     is dropped. However, it is documented that in these cases heap memory may be
                //     leaked, so this is expected behaviour. In addition, certain signal interrupts
                //     or using panic=abort behaviour will mean the destructor is not called.
                //     There's little we can do about this, but a failure to free is probably
                //     reasonable in such cases. In any other case, `drop` will be called, and the
                //     memory freed.
                // `self.state` was allocated in the `DecryptionStream` constructor using Sodium's
                // allocator, so it is correct to free it using Sodium's allocator.
                mem::free(self.state);
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::{DecryptionStream, EncryptionStream, Key, MessageType, OVERHEAD_LENGTH};
        use crate::{random, AlkaliError};

        #[test]
        fn key_generation() -> Result<(), AlkaliError> {
            let _key = Key::generate()?;
            Ok(())
        }

        #[test]
        fn enc_and_dec() -> Result<(), AlkaliError> {
            let key = Key::generate()?;

            for _ in 0..1000 {
                let mut ad = [0u8; 100];
                let mut m1 = [0u8; 1000];
                let mut c1 = [0u8; 1000 + OVERHEAD_LENGTH];
                let mut m2 = [0u8; 1000];
                let mut c2 = [0u8; 1000 + OVERHEAD_LENGTH];
                let mut m3 = [0u8; 1000];
                let mut c3 = [0u8; 1000 + OVERHEAD_LENGTH];
                let mut m4 = [0u8; 1000];
                let mut c4 = [0u8; 1000 + OVERHEAD_LENGTH];

                let al = random::random_u32_in_range(0, 100)? as usize;
                let l1 = random::random_u32_in_range(0, 1000)? as usize;
                let l2 = random::random_u32_in_range(0, 1000)? as usize;
                let l3 = random::random_u32_in_range(0, 1000)? as usize;
                let l4 = random::random_u32_in_range(0, 1000)? as usize;

                random::fill_random(&mut ad[..al])?;
                random::fill_random(&mut m1[..l1])?;
                random::fill_random(&mut m2[..l2])?;
                random::fill_random(&mut m3[..l3])?;
                random::fill_random(&mut m4[..l4])?;

                let mut enc_stream = EncryptionStream::new(&key)?;
                let header = enc_stream.get_header();
                assert_eq!(
                    enc_stream.encrypt(&m1[..l1], None, &mut c1)?,
                    l1 + OVERHEAD_LENGTH
                );
                assert_eq!(
                    enc_stream.encrypt_push(&m2[..l2], Some(&ad[0..0]), &mut c2)?,
                    l2 + OVERHEAD_LENGTH
                );
                assert_eq!(
                    enc_stream.encrypt_rekey(&m3[..l3], None, &mut c3)?,
                    l3 + OVERHEAD_LENGTH
                );
                assert_eq!(
                    enc_stream.finalise(&m4[..l4], Some(&ad[..al]), &mut c4)?,
                    l4 + OVERHEAD_LENGTH
                );

                let mut p1 = [0u8; 1000];
                let mut p2 = [0u8; 1000];
                let mut p3 = [0u8; 1000];
                let mut p4 = [0u8; 1000];

                let mut dec_stream = DecryptionStream::new(&key, &header)?;
                assert_eq!(
                    dec_stream.decrypt(&c1[..l1 + OVERHEAD_LENGTH], None, &mut p1)?,
                    (MessageType::Message, l1)
                );
                assert_eq!(
                    dec_stream.decrypt(&c2[..l2 + OVERHEAD_LENGTH], None, &mut p2)?,
                    (MessageType::Push, l2)
                );
                assert_eq!(
                    dec_stream.decrypt(&c3[..l3 + OVERHEAD_LENGTH], None, &mut p3)?,
                    (MessageType::Rekey, l3)
                );
                assert!(!dec_stream.is_finalised());

                if al > 0 {
                    assert!(dec_stream
                        .decrypt(&c4[..l4 + OVERHEAD_LENGTH], None, &mut p4)
                        .is_err());
                }

                assert_eq!(
                    dec_stream.decrypt(&c4[..l4 + OVERHEAD_LENGTH], Some(&ad[..al]), &mut p4)?,
                    (MessageType::Final, l4)
                );
                assert!(dec_stream.is_finalised());
            }

            Ok(())
        }

        #[test]
        fn explicit_rekey() -> Result<(), AlkaliError> {
            let key = Key::generate()?;

            let mut m1 = [0; 32];
            let mut c1 = [0; 32 + OVERHEAD_LENGTH];
            let mut p1 = [0; 32];
            let mut m2 = [0; 64];
            let mut c2 = [0; 64 + OVERHEAD_LENGTH];
            let mut p2 = [0; 64];

            random::fill_random(&mut m1)?;
            random::fill_random(&mut m2)?;

            let mut enc_stream = EncryptionStream::new(&key)?;
            let header = enc_stream.get_header();
            enc_stream.encrypt(&m1, None, &mut c1)?;
            enc_stream.rekey();
            enc_stream.finalise(&m2, None, &mut c2)?;

            let mut dec_stream = DecryptionStream::new(&key, &header)?;
            dec_stream.decrypt(&c1, None, &mut p1)?;
            assert!(dec_stream.decrypt(&c2, None, &mut p2).is_err());
            dec_stream.rekey();
            dec_stream.decrypt(&c2, None, &mut p2)?;

            assert_eq!(p1, m1);
            assert_eq!(p2, m2);

            Ok(())
        }
    }
}

pub use xchacha20poly1305::*;
