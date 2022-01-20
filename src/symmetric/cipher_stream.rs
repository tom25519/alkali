//! Symmetric Authenticated Encryption for a sequence of messages, or chunks of a single message.
//!
//! This module corresponds to the [`crypto_secretsteam`
//! API](https://doc.libsodium.org/secret-key_cryptography/secretstream) from Sodium.
//!
//! This construction is used to encrypt a sequence of messages, producing a sequence of
//! ciphertexts which cannot be truncated, removed, reordered, duplicated, or modified without
//! detection. This can be used in symmetric protocols, where a sequence of messages must be sent,
//! and in file encryption, where chunks of a single message are encrypted in order. As this is a
//! symmetric construction, all parties who wish to encrypt or decrypt messages must share the same
//! secret key, which is used for both encryption and decryption.
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
//! [ChaCha20](https://en.wikipedia.org/wiki/Salsa20#ChaCha_variant) to encrypt messages, with
//! [Poly1305](https://en.wikipedia.org/wiki/Poly1305) for authentication.
//!
//! The [Sodium documentation for this
//! API](https://doc.libsodium.org/secret-key_cryptography/secretstream#algorithm) has more
//! information on how exactly the stream construction operates.
//!
//! # Security Considerations
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
//! let key = cipher_stream::Key::generate().unwrap();
//!
//! let message1 = b"Arbitrary data to encrypt";
//! let message2 = b"split into";
//! let message3 = b"three messages";
//!
//! let mut ciphertext1 = [0u8; 25 + cipher_stream::ADDED_LENGTH];
//! let mut ciphertext2 = [0u8; 10 + cipher_stream::ADDED_LENGTH];
//! let mut ciphertext3 = [0u8; 14 + cipher_stream::ADDED_LENGTH];
//!
//! // An `EncryptionStream` is used to encrypt messages in sequence
//! let mut enc_stream = cipher_stream::EncryptionStream::new(&key).unwrap();
//! // The `header` marks the start of the stream, and will be needed for decryption
//! let header = enc_stream.get_header();
//! // The `None` here signifies no additional data should be included in the authentication
//! // calculation
//! enc_stream.encrypt(message1, None, &mut ciphertext1).unwrap();
//! enc_stream.encrypt(message2, None, &mut ciphertext2).unwrap();
//! enc_stream.finalise(message3, None, &mut ciphertext3).unwrap();
//!
//! // ...
//!
//! let mut plaintext1 = [0u8; 25];
//! let mut plaintext2 = [0u8; 10];
//! let mut plaintext3 = [0u8; 14];
//!
//! // A `DecryptionStream` is used to decrypt messages in sequence
//! let mut dec_stream = cipher_stream::DecryptionStream::new(&key, &header).unwrap();
//! dec_stream.decrypt(&ciphertext1, None, &mut plaintext1).unwrap();
//! dec_stream.decrypt(&ciphertext2, None, &mut plaintext2).unwrap();
//! dec_stream.decrypt(&ciphertext3, None, &mut plaintext3).unwrap();
//!
//! assert_eq!(&plaintext1, message1);
//! assert_eq!(&plaintext2, message2);
//! assert_eq!(&plaintext3, message3);
//! ```
//!
//! File encryption: See
//! [`examples/file-encryption.rs`](https://github.com/tom25519/alkali/blob/main/examples/file-encryption.rs)

use crate::{hardened_buffer, mem, require_init, AlkaliError};
use libsodium_sys as sodium;
use std::marker::PhantomData;
use std::ptr;
use thiserror::Error;

/// Error type returned if something went wrong in the `symmetric::cipher_stream` module.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum CipherStreamError {
    /// The output buffer is too short to store the ciphertext/plaintext which would result from
    /// encrypting/decrypting this message.
    ///
    /// Each function in this module should provide information in its documentation about the
    /// output length requirements.
    #[error("the output is insufficient to store ciphertext/plaintext, required {0}, found {1}")]
    OutputInsufficient(usize, usize),

    /// Message too long for encryption/decryption with this API.
    ///
    /// An individual message can only be up to [`MESSAGE_LENGTH_MAX`](struct@MESSAGE_LENGTH_MAX)
    /// bytes before the keystream is exhausted. Longer messages should be split into multiple
    /// chunks.
    #[error("the message is too long for encryption/decryption with this API")]
    MessageTooLong,

    /// Tried to write to/read from a stream where a message with the "FINAL" tag has been sent.
    #[error("the final message in this stream has been sent, it can no longer be used")]
    StreamFinalised,

    /// Indicates decryption of the stream failed.
    ///
    /// This could indicate an attempted forgery, or transmission error.
    #[error("decryption failed")]
    DecryptionFailed,
}

/// Types of message which can be sent as part of a stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum MessageType {
    /// Indicates a standard message, doesn't add any information about its nature.
    Message = sodium::crypto_secretstream_xchacha20poly1305_TAG_MESSAGE as libc::c_uchar,

    /// Used to indicate that a message marks the end of a set of messages, but not the end of the
    /// stream.
    ///
    /// For example, a huge JSON string sent as multiple chunks can use this tag to indicate to the
    /// application that the string is complete and that it can be decoded. The stream itself is
    /// not closed, and more data may follow.
    Push = sodium::crypto_secretstream_xchacha20poly1305_TAG_PUSH as libc::c_uchar,

    /// Switch to a new key to encrypt future messages, forgetting the previous key.
    ///
    /// Receipt of a message with the `Rekey` type will automatically cause all parties to generate
    /// a new key.  No other information needs to be transmitted to agree on the key: it is derived
    /// based on the previous subkey, but not in such a way that the previous subkey can be
    /// obtained from the new key (ratcheting).
    Rekey = sodium::crypto_secretstream_xchacha20poly1305_TAG_REKEY as libc::c_uchar,

    /// Indicates the message marks the end of the stream.
    ///
    /// After a message with this type has been received, no more messages can be sent, and the
    /// secret key used for the cipher will be erased.
    Final = sodium::crypto_secretstream_xchacha20poly1305_TAG_FINAL as libc::c_uchar,
}

/// The length of a symmetric key used for encryption/decryption of a stream, in bytes.
pub const KEY_LENGTH: usize = sodium::crypto_secretstream_xchacha20poly1305_KEYBYTES as usize;

/// The extra space required in each encrypted message for the Message Authentication Code (MAC)
/// and message tag.
pub const ADDED_LENGTH: usize = sodium::crypto_secretstream_xchacha20poly1305_ABYTES as usize;

/// The length of a stream header, in bytes.
pub const HEADER_LENGTH: usize = sodium::crypto_secretstream_xchacha20poly1305_HEADERBYTES as usize;

lazy_static::lazy_static! {
    /// The maximum length of an individual message to be encrypted within the stream, in bytes.
    pub static ref MESSAGE_LENGTH_MAX: usize = unsafe {
        // SAFETY: This function just returns a constant value, and should always be safe to call.
        sodium::crypto_secretstream_xchacha20poly1305_messagebytes_max()
    };
}

hardened_buffer! {
    /// Secret key for symmetric authenticated encryption/decryption of a stream of messages.
    ///
    /// There are no technical constraints on the contents of a key, but it should be generated
    /// randomly. [`Key::generate`] will generate a random key suitable for this use.
    ///
    /// A secret key must not be made public.
    ///
    /// This is a [hardened buffer type](https://docs.rs/alkali#hardened-buffer-types), and will be
    /// zeroed on drop. A number of other security measures are also taken to protect its contents.
    Key(KEY_LENGTH);
}

impl Key {
    /// Generate a new, random key for use in stream encryption.
    pub fn generate() -> Result<Self, AlkaliError> {
        require_init()?;

        let mut key = Self::new_empty()?;
        unsafe {
            // SAFETY: This function expects a pointer to a region of memory sufficient to store a
            // key for this algorithm. We have defined this type based on the
            // `crypto_secretstream_KEYBYTES` constant from Sodium, so it definitely has the
            // correct amount of space allocated to store the key. The `Key::inner_mut` method
            // simply returns a mutable pointer to the struct's backing memory.
            sodium::crypto_secretstream_xchacha20poly1305_keygen(
                key.inner_mut() as *mut libc::c_uchar
            );
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
    /// `Key` should be the symmetric [`Key`] with which the stream is secured. The same key will
    /// be required to decrypt the stream.
    ///
    /// Returns a new [`EncryptionStream`] instance, or an error if Sodium could not be
    /// initialised.
    pub fn new(key: &Key) -> Result<Self, AlkaliError> {
        require_init()?;

        let mut header = [0u8; HEADER_LENGTH];

        let state = unsafe {
            // SAFETY: This call to malloc() will allocate the memory required for a
            // `crypto_secretstream_state` type, outside of Rust's memory management. The
            // associated memory is always freed in the corresponding `drop` call. We never free
            // the memory in any other place in this struct, and drop can only be called once, so a
            // double-free is not possible. We never give out a pointer to the allocated memory.
            // See the drop implementation for more reasoning on safety.
            let mut state = mem::malloc()?;

            // SAFETY: This function initialises a `crypto_secretstream_state` struct. The first
            // argument should be a pointer to a region of memory sufficient to store a
            // crypto_secretstream_state struct. We pass a pointer to a region of memory sufficient
            // to store the struct as defined in Rust, rather than C. This definition is generated
            // via bindgen, and as such, is equivalent to the struct in C, so it is correct to use
            // it as an argument for this function. The second argument specifies the location to
            // which the stream header should be written. We have defined the `header` array to be
            // `crypto_secretstream_HEADERBYTES` bytes, so it is of the expected size for use here,
            // and a buffer overflow will not occur. The final argument specifies the key to use
            // for the stream. We have defined the `Key` type to be crypto_secretstream_KEYBYTES
            // bytes, so it is of the expected size for use here.
            sodium::crypto_secretstream_xchacha20poly1305_init_push(
                state.as_mut(),
                header.as_mut_ptr(),
                key.inner() as *const libc::c_uchar,
            );

            state
        };

        Ok(Self {
            state,
            header,
            _marker: PhantomData,
        })
    }

    /// Get the header for this cipher stream.
    ///
    /// The header is required for decryption, and contains the initial nonce from which the subkey
    /// and message nonces are derived. It should be sent before the rest of the stream.
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
        let c_len = message.len() + ADDED_LENGTH;

        if output.len() < c_len {
            return Err(CipherStreamError::OutputInsufficient(c_len, output.len()).into());
        } else if message.len() > *MESSAGE_LENGTH_MAX {
            return Err(CipherStreamError::MessageTooLong.into());
        }

        let (ad_ptr, ad_len) = if let Some(ad_inner) = ad {
            (ad_inner.as_ptr(), ad_inner.len())
        } else {
            (ptr::null::<libc::c_uchar>(), 0)
        };

        unsafe {
            // SAFETY: The first argument to this function should be a pointer to a
            // crypto_secretstream_state struct. The initialisation of the `EncryptionStream`
            // struct allocates sufficient memory to the `self.state` pointer to store a
            // crypto_secretstream_state struct. Furthermore, the initialisation process for
            // `EncryptionStream` requires a call to `crypto_secretstream_init_push`, so the
            // `self.state` pointer does point to a correctly initialised instance of this struct
            // for use with this function. The next argument specifies the destination pointer to
            // which the encrypted ciphertext will be written. We verify above that the output
            // slice is sufficient to store the ciphertext, so a buffer overflow cannot occur. The
            // next argument is a pointer to which the number of bytes written to `output` will be
            // written. It is documented that if this is set to a NULL pointer, it will simply be
            // ignored. The next two arguments specify the message to encrypt and its length. We
            // use `message.len()` to specify the length, so it is correct for this pointer. The
            // next two arguments specify the additional data to authenticate and its length. If
            // additional data has been provided, we simply pass the slice & its length as
            // arguments. If additional data has not been provided, we pass a NULL pointer, which
            // it is documented will cause Sodium to simply ignore the AD. The final argument is
            // the message tag to use. We have defined the `MessageType` enum using the different
            // message tags defined in Sodium, so it is one of the expected values.
            sodium::crypto_secretstream_xchacha20poly1305_push(
                self.state.as_mut(),
                output.as_mut_ptr(),
                ptr::null::<libc::c_ulonglong>() as *mut _,
                message.as_ptr(),
                message.len() as libc::c_ulonglong,
                ad_ptr,
                ad_len as libc::c_ulonglong,
                mtype as u8,
            );
        }

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
    /// authentication tag. This will not be encrypted or included in the ciphertext, but will be
    /// authenticated, and will be necessary for the decryption. This is often useful for including
    /// protocol details or other information which does not need to be encrypted, but should be
    /// authenticated.
    ///
    /// The encrypted ciphertext will be written to `output`, which must be at least
    /// [`ADDED_LENGTH`] bytes longer than `message`. If the `output` slice is not sufficient to
    /// store the ciphertext, an error will be returned.
    ///
    /// Returns the number of bytes written to `output`.
    ///
    /// Messages should be sent in the order they were encrypted to the decrypting party. The order
    /// in which messages are encrypted matters, and attempting to decrypt messages out of order
    /// will fail.
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
    /// multiple chunks can use this tag to indicate to the application that the string is complete
    /// and can be decoded. But the stream itself is not closed, and more data may follow.
    ///
    /// When a [`DecryptionStream`] receives this message, the [`MessageType`] will be
    /// [`MessageType::Push`].
    ///
    /// `message` should be the message to encrypt.
    ///
    /// `ad` can contain additional data which will be included in the calculation of the
    /// authentication tag. This will not be encrypted or included in the ciphertext, but will be
    /// authenticated, and will be necessary for the decryption. This is often useful for including
    /// protocol details or other information which does not need to be encrypted, but should be
    /// authenticated.
    ///
    /// The encrypted ciphertext will be written to `output`, which must be at least
    /// [`ADDED_LENGTH`] bytes longer than `message`. If the `output` slice is not sufficient to
    /// store the ciphertext, an error will be returned.
    ///
    /// Returns the number of bytes written to `output`.
    ///
    /// Messages should be sent in the order they were encrypted to the decrypting party. The order
    /// in which messages are encrypted matters, and attempting to decrypt messages out of order
    /// will fail.
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
    /// [`EncryptionStream`] and [`DecryptionStream`] structs automatically manage this rekeying,
    /// and no further action is required by API users on sending/receiving a Rekey message.
    ///
    /// When a [`DecryptionStream`] receives this message, the [`MessageType`] will be
    /// [`MessageType::Rekey`].
    ///
    /// `message` should be the message to encrypt.
    ///
    /// `ad` can contain additional data which will be included in the calculation of the
    /// authentication tag. This will not be encrypted or included in the ciphertext, but will be
    /// authenticated, and will be necessary for the decryption. This is often useful for including
    /// protocol details or other information which does not need to be encrypted, but should be
    /// authenticated.
    ///
    /// The encrypted ciphertext will be written to `output`, which must be at least
    /// [`ADDED_LENGTH`] bytes longer than `message`. If the `output` slice is not sufficient to
    /// store the ciphertext, an error will be returned.
    ///
    /// Returns the number of bytes written to `output`.
    ///
    /// Messages should be sent in the order they were encrypted to the decrypting party. The order
    /// in which messages are encrypted matters, and attempting to decrypt messages out of order
    /// will fail.
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
    /// messages, and forgetting the previous key. However, no information is added to the cipher
    /// stream to communicate to the receiver that a rekey has taken place, so care must be taken
    /// by API users to ensure that [`DecryptionStream::rekey`] is also called at the same time in
    /// the stream.
    ///
    /// Using [`EncryptionStream::encrypt_rekey`] may be preferable, as it communicates to the
    /// receiver a rekey has occurred, and no sync is required beyond the stream itself.
    pub fn rekey(&mut self) {
        unsafe {
            // SAFETY: This function takes a pointer to a crypto_secretstream_state struct. The
            // initialisation of the `EncryptionStream` struct allocates sufficient memory to the
            // `self.state` pointer to store a crypto_secretstream_state struct. Furthermore, the
            // initialisation process for `EncryptionStream` requires a call to
            // `crypto_secretstream_init_push`, so the `self.state` pointer does point to a
            // correctly initialised instance of this struct for use with this function.
            sodium::crypto_secretstream_xchacha20poly1305_rekey(self.state.as_mut());
        }
    }

    /// Encrypt a [Final](MessageType::Final) message and close the stream, writing the ciphertext
    /// to `output`.
    ///
    /// A "Final" message can contain any contents, like a normal message, but marks the end of the
    /// cipher stream. After the Final message, no more messages can be sent.
    ///
    /// When a [`DecryptionStream`] receives this message, the [`MessageType`] will be
    /// [`MessageType::Final`].
    ///
    /// `message` should be the message to encrypt.
    ///
    /// `ad` can contain additional data which will be included in the calculation of the
    /// authentication tag. This will not be encrypted or included in the ciphertext, but will be
    /// authenticated, and will be necessary for the decryption. This is often useful for including
    /// protocol details or other information which does not need to be encrypted, but should be
    /// authenticated.
    ///
    /// The encrypted ciphertext will be written to `output`, which must be at least
    /// [`ADDED_LENGTH`] bytes longer than `message`. If the `output` slice is not sufficient to
    /// store the ciphertext, an error will be returned.
    ///
    /// Returns the number of bytes written to `output`.
    ///
    /// Messages should be sent in the order they were encrypted to the decrypting party. The order
    /// in which messages are encrypted matters, and attempting to decrypt messages out of order
    /// will fail.
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
            //     `std::mem::forget`, the destructor will not be called even though the struct is
            //     dropped. However, it is documented that in these cases heap memory may be
            //     leaked, so this is expected behaviour. In addition, certain signal interrupts or
            //     using panic=abort behaviour will mean the destructor is not called. There's
            //     little we can do about this, but a failure to free is probably reasonable in
            //     such cases. In any other case, `drop` will be called, and the memory freed.
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
    /// `Key` should be the symmetric [`Key`] with which the stream is secured. The same key should
    /// have been used to encrypt the stream. `header` should be the [`Header`] generated for the
    /// cipher stream on the sender's side: This can be obtained using
    /// [`EncryptionStream::get_header`].
    ///
    /// Returns a new [`DecryptionStream`] instance, or an error if Sodium could not be
    /// initialised.
    pub fn new(key: &Key, header: &Header) -> Result<Self, AlkaliError> {
        require_init()?;

        let (state, init_result) = unsafe {
            // SAFETY: This call to malloc() will allocate the memory required for a
            // `crypto_secretstream_state` type, outside of Rust's memory management. The
            // associated memory is always freed in the corresponding `drop` call. We never free
            // the memory in any other place in this struct, and drop can only be called once, so a
            // double-free is not possible. We never give out a pointer to the allocated memory.
            // See the drop implementation for more reasoning on safety.
            let mut state = mem::malloc()?;

            // SAFETY: This function initialises a `crypto_secretstream_state` struct. The first
            // argument should be a pointer to a region of memory sufficient to store a
            // crypto_secretstream_state struct. We pass a pointer to a region of memory sufficient
            // to store the struct as defined in Rust, rather than C. This definition is generated
            // via bindgen, and as such, is equivalent to the struct in C, so it is correct to use
            // it as an argument for this function. The second argument specifies the stream
            // header. We have defined the `header` array to be `crypto_secretstream_HEADERBYTES`
            // bytes, so it is of the expected size for use here. The final argument specifies the
            // key to use for the stream. We have defined the `Key` type to be
            // crypto_secretstream_KEYBYTES bytes, so it is of the expected size for use here.
            let res = sodium::crypto_secretstream_xchacha20poly1305_init_pull(
                state.as_mut(),
                header.as_ptr(),
                key.inner() as *const libc::c_uchar,
            );

            (state, res)
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
    /// ciphertext, but will be authenticated, and is necessary for the decryption. This is often
    /// useful for including protocol details or other information which does not need to be
    /// encrypted, but should be authenticated.
    ///
    /// If authentication + decryption succeed, the decrypted message will be written to `output`,
    /// which must be at least `message.len()` - [`ADDED_LENGTH`] bytes. If the `output` slice is
    /// not sufficient to store the plaintext, an error will be returned.
    ///
    /// Returns the [`MessageType`] of the message, and the number of bytes written to `output`.
    /// After the [`MessageType::Final`] message has been received, the stream is closed, and
    /// trying to call `decrypt` again will result in an error.
    ///
    /// Messages should be decrypted in the order they were encrypted. The order in which messages
    /// are encrypted matters, and attempting to decrypt messages out of order will fail.
    pub fn decrypt(
        &mut self,
        ciphertext: &[u8],
        ad: Option<&[u8]>,
        output: &mut [u8],
    ) -> Result<(MessageType, usize), AlkaliError> {
        if self.finalised {
            return Err(CipherStreamError::StreamFinalised.into());
        }

        if ciphertext.len() < ADDED_LENGTH {
            return Err(CipherStreamError::DecryptionFailed.into());
        }

        let m_len = ciphertext.len() - ADDED_LENGTH;

        if output.len() < m_len {
            return Err(CipherStreamError::OutputInsufficient(m_len, output.len()).into());
        }

        let (ad_ptr, ad_len) = if let Some(ad_inner) = ad {
            (ad_inner.as_ptr(), ad_inner.len())
        } else {
            (ptr::null::<libc::c_uchar>(), 0)
        };

        let mut tag = 0u8;

        let decrypt_result = unsafe {
            // SAFETY: The first argument to this function should be a pointer to a
            // crypto_secretstream_state struct. The initialisation of the `DecryptionStream`
            // struct allocates sufficient memory to the `self.state` pointer to store a
            // crypto_secretstream_state struct. Furthermore, the initialisation process for
            // `DecryptionStream` requires a call to `crypto_secretstream_init_pull`, so the
            // `self.state` pointer does point to a correctly initialised instance of this struct
            // for use with this function. The next argument specifies the destination pointer to
            // which the decrypted plaintext will be written. We verify above that the output slice
            // is sufficient to store the plaintext, so a buffer overflow cannot occur. The next
            // argument is a pointer to which the number of bytes written to `output` will be
            // written. It is documented that if this is set to a NULL pointer, it will simply be
            // ignored. The next argument is a pointer to which the tag for this message will be
            // written. This is simply an unsigned char in C, so we pass a mutable reference to a
            // u8. The next two arguments specify the ciphertext to decrypt and its length. We
            // use `ciphertext.len()` to specify the length, so it is correct for this pointer. The
            // final two arguments specify the additional data to authenticate and its length. If
            // additional data has been provided, we simply pass the slice & its length as
            // arguments. If additional data has not been provided, we pass a NULL pointer, which
            // it is documented will cause Sodium to simply ignore the AD.
            sodium::crypto_secretstream_xchacha20poly1305_pull(
                self.state.as_mut(),
                output.as_mut_ptr(),
                ptr::null::<libc::c_ulonglong>() as *mut _,
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
            _ => unreachable!(),
        };

        Ok((tag, m_len))
    }

    /// Trigger a rekey without adding any information about the key change to the stream.
    ///
    /// This function updates the internal state, moving to the next key to encrypt future
    /// messages, and forgetting the previous key. Care must be taken by API users to ensure that
    /// this function is called at the same time in the stream as [`EncryptionStream::rekey`].
    pub fn rekey(&mut self) {
        unsafe {
            // SAFETY: This function takes a pointer to a crypto_secretstream_state struct. The
            // initialisation of the `DecryptionStream` struct allocates sufficient memory to the
            // `self.state` pointer to store a crypto_secretstream_state struct. Furthermore, the
            // initialisation process for `DecryptionStream` requires a call to
            // `crypto_secretstream_init_pull`, so the `self.state` pointer does point to a
            // correctly initialised instance of this struct for use with this function.
            sodium::crypto_secretstream_xchacha20poly1305_rekey(self.state.as_mut());
        }
    }
}

impl Drop for DecryptionStream {
    fn drop(&mut self) {
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
            //     `std::mem::forget`, the destructor will not be called even though the struct is
            //     dropped. However, it is documented that in these cases heap memory may be
            //     leaked, so this is expected behaviour. In addition, certain signal interrupts or
            //     using panic=abort behaviour will mean the destructor is not called. There's
            //     little we can do about this, but a failure to free is probably reasonable in
            //     such cases. In any other case, `drop` will be called, and the memory freed.
            mem::free(self.state);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{DecryptionStream, EncryptionStream, Key, MessageType, ADDED_LENGTH};
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
            let mut ad = vec![0; random::random_u32_in_range(0, 100)? as usize];
            let mut m1 = vec![0; random::random_u32_in_range(0, 1000)? as usize];
            let mut c1 = vec![0; m1.len() + ADDED_LENGTH];
            let mut m2 = vec![0; random::random_u32_in_range(0, 1000)? as usize];
            let mut c2 = vec![0; m2.len() + ADDED_LENGTH];
            let mut m3 = vec![0; random::random_u32_in_range(0, 1000)? as usize];
            let mut c3 = vec![0; m3.len() + ADDED_LENGTH];
            let mut m4 = vec![0; random::random_u32_in_range(0, 1000)? as usize];
            let mut c4 = vec![0; m4.len() + ADDED_LENGTH];

            random::fill_random(&mut ad)?;
            random::fill_random(&mut m1)?;
            random::fill_random(&mut m2)?;
            random::fill_random(&mut m3)?;
            random::fill_random(&mut m4)?;

            let mut enc_stream = EncryptionStream::new(&key)?;
            let header = enc_stream.get_header();
            assert_eq!(enc_stream.encrypt(&m1, None, &mut c1)?, c1.len());
            assert_eq!(
                enc_stream.encrypt_push(&m2, Some(&ad[0..0]), &mut c2)?,
                c2.len()
            );
            assert_eq!(enc_stream.encrypt_rekey(&m3, None, &mut c3)?, c3.len());
            assert_eq!(enc_stream.finalise(&m4, Some(&ad), &mut c4)?, c4.len());

            let mut p1 = vec![0; m1.len()];
            let mut p2 = vec![0; m2.len()];
            let mut p3 = vec![0; m3.len()];
            let mut p4 = vec![0; m4.len()];

            let mut dec_stream = DecryptionStream::new(&key, &header)?;
            assert_eq!(
                dec_stream.decrypt(&c1, None, &mut p1)?,
                (MessageType::Message, m1.len())
            );
            assert_eq!(
                dec_stream.decrypt(&c2, None, &mut p2)?,
                (MessageType::Push, m2.len())
            );
            assert_eq!(
                dec_stream.decrypt(&c3, None, &mut p3)?,
                (MessageType::Rekey, m3.len())
            );
            assert!(!dec_stream.is_finalised());

            if ad.len() > 0 {
                assert!(dec_stream.decrypt(&c4, None, &mut p4).is_err());
            }

            assert_eq!(
                dec_stream.decrypt(&c4, Some(&ad), &mut p4)?,
                (MessageType::Final, m4.len())
            );
            assert!(dec_stream.is_finalised());
        }

        Ok(())
    }

    #[test]
    fn explicit_rekey() -> Result<(), AlkaliError> {
        let key = Key::generate()?;

        let mut m1 = [0; 32];
        let mut c1 = [0; 32 + ADDED_LENGTH];
        let mut p1 = [0; 32];
        let mut m2 = [0; 64];
        let mut c2 = [0; 64 + ADDED_LENGTH];
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
