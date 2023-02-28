//! Symmetric [Authenticated Encryption with Associated
//! Data](https://en.wikipedia.org/wiki/Authenticated_encryption#Authenticated_encryption_with_associated_data_(AEAD))
//! (AEAD).
//!
//! This module corresponds to the [`crypto_aead`
//! API](https://doc.libsodium.org/secret-key_cryptography/aead) from Sodium.
//!
//! AEAD is a variant of [authenticated encryption](crate::symmetric::cipher) which allows
//! additional unencrypted data to be included in the calculation of the authentication tag. This
//! provides assurance to the receiver that neither the ciphertext, nor the additional data, has
//! been modified in transit. In symmetric encryption, all parties who wish to encrypt or decrypt
//! messages must share a single secret key prior to communication, which is used for both
//! encryption and decryption.
//!
//! Use of additional data may be helpful to authenticate protocol information, or other
//! non-sensitive data associated with the encrypted message.
//!
//! Often, you won't actually need to authenticate additional data, in which you should just stick
//! to the [`symmetric::cipher`](crate::symmetric::cipher) module. This corresponds to the original
//! `crypto_secretbox` API from Sodium, and is more widely used.
//!
//! # Algorithm Details
//! Four AEAD algorithms are available in this module.
//!
//! The recommended AEAD algorithm is [`xchacha20poly1305_ietf`], which uses the
//! [XChaCha20](https://cr.yp.to/chacha.html) stream cipher (ChaCha20 with an eXtended nonce length)
//! for encryption, together with the [Poly1305](https://en.wikipedia.org/wiki/Poly1305) MAC for
//! authentication.
//!
//! Two algorithms which use ChaCha20 (i.e: ChaCha20 with the original nonce length) are also
//! available: [`chacha20poly1305`] is the original Sodium ChaCha20-Poly1305 construction, and
//! [`chacha20poly1305_ietf`] is the construction [specified by the
//! IETF](https://datatracker.ietf.org/doc/html/rfc8439). Extra consideration is needed when using
//! these algorithms to prevent nonce reuse, and for this reason they are gated behind the [`hazmat`
//! feature](https://docs.rs/alkali#the-hazmat-feature). Do not use these algorithms unless you
//! absolutely have to, and be sure to understand the associated security considerations.
//!
//! On modern x86 systems, [AES-256](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) in
//! [Galois/Counter Mode (GCM)](https://en.wikipedia.org/wiki/Galois/Counter_Mode) is available, as
//! [`aes256gcm`]. In particular, the SSSE3 extensions, `aesni`, and `pclmul` instructions are
//! required for this construction, and trying to use it on platforms lacking these features will
//! fail. AES-GCM is difficult to use securely when compared with XChaCha20-Poly1305, and is
//! therefore gated behind the `aes` feature. Do not use this algorithm unless you absolutely have
//! to, and be sure to understand the associated security considerations.
//!
//! # Security Considerations
//! Each of the AEAD algorithms in this module has different security properties, which must be
//! carefully considered before use. Each algorithm's documentation will list its individual
//! security considerations:
//! * [XChaCha20-Poly1305][xchacha20poly1305_ietf#security-considerations]
//! * [ChaCha20-Poly1305][chacha20poly1305#security-considerations]
//! * [ChaCha20-Poly1305 IETF Variant][chacha20poly1305_ietf#security-considerations]
//! * [AES-256-GCM][aes256gcm#security-considerations]
//!
//! Common to all of the algorithms here is that nonces must *never* be used more than once with the
//! same key. For XChaCha20, random nonces can be used for every message, but for the other
//! algorithms, the nonce size is too short for the possibility of nonce reuse to be negligible.
//! Again, read the individual algorithms' documentation for more details.
//!
//! If many trusted parties have access to the secret key, there is no way to prove which of them
//! sent a given message without additional information.
//!
//! All of these constructions may expose the length of the plaintext. If this is undesirable, apply
//! padding to the plaintext prior to encryption via [`util::pad`](crate::util::pad), and remove it
//! following decryption via [`util::unpad`](crate::util::unpad).

#[cfg(feature = "aes")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "aes")))]
pub mod aes256gcm;
#[cfg(feature = "aead-chacha20")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "hazmat")))]
pub mod chacha20poly1305;
#[cfg(feature = "aead-chacha20")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "hazmat")))]
pub mod chacha20poly1305_ietf;
pub mod xchacha20poly1305_ietf;

crate::error_type! {
    /// Error type returned if something went wrong in the `symmetric::aead` module.
    AEADError {
        /// The output buffer is too short to store the ciphertext/plaintext which would result from
        /// encrypting/decrypting this message.
        ///
        /// Each function in this module should provide information in its documentation about the
        /// output length requirements.
        OutputInsufficient,

        /// Message too long for use with this cipher.
        MessageTooLong,

        /// Indicates decryption of a provided ciphertext failed.
        ///
        /// This could indicate an attempted forgery, or transmission error.
        DecryptionFailed,

        /// This system does not support the necessary CPU features for AES support.
        ///
        /// AES is only available on x86 systems with SSSE3 extensions, and the `aesni` and `pclmul`
        /// instructions.
        AESUnavailable,
    }
}

#[allow(unused_macros)]
macro_rules! chacha_aead_module {
    (
        $key_len:expr,      // crypto_aead_KEYBYTES
        $mac_len:expr,      // crypto_aead_ABYTES
        $nonce_len:expr,    // crypto_aead_NPUBBYTES
        $msg_max:path,      // crypto_aead_messagebytes_max
        $keygen:path,       // crypto_aead_keygen
        $encrypt:path,      // crypto_aead_encrypt
        $decrypt:path,      // crypto_aead_decrypt
        $encrypt_d:path,    // crypto_aead_encrypt_detached
        $decrypt_d:path,    // crypto_aead_decrypt_detached
    ) => {
        use core::ptr;
        use $crate::symmetric::aead::AEADError;
        use $crate::{assert_not_err, mem, require_init, AlkaliError};

        /// The length of a symmetric key used for this AEAD construction, in bytes.
        pub const KEY_LENGTH: usize = $key_len as usize;

        /// The length of a MAC, in bytes.
        pub const MAC_LENGTH: usize = $mac_len as usize;

        /// The length of a message nonce, in bytes.
        pub const NONCE_LENGTH: usize = $nonce_len as usize;

        lazy_static::lazy_static! {
            /// The maximum length of a message that can be encrypted with this cipher, in bytes.
            pub static ref MESSAGE_LENGTH_MAX: usize = unsafe {
                // SAFETY: This function just returns a constant value, and should always be safe to
                // call.
                $msg_max()
            };
        }

        mem::hardened_buffer! {
            /// A secret key for this symmetric AEAD construction.
            ///
            /// There are no *technical* constraints on the contents of a key, but it should be
            /// indistinguishable from random noise. A random key can be securely generated via
            /// [`Key::generate`].
            ///
            /// A secret key must not be made public.
            ///
            /// This is a [hardened buffer type](https://docs.rs/alkali#hardened-buffer-types), and
            /// will be zeroed on drop. A number of other security measures are also taken to
            /// protect its contents. This type in particular can be thought of as roughly
            /// equivalent to a `[u8; KEY_LENGTH]`, and implements [`core::ops::Deref`] so it can be
            /// used like it is an `&[u8]`. This struct uses heap memory while in scope, allocated
            /// using Sodium's [secure memory
            /// utilities](https://doc.libsodium.org/memory_management).
            pub Key(KEY_LENGTH);
        }

        impl Key<mem::FullAccess> {
            /// Generate a new, random key for use with this symmetric AEAD construction.
            pub fn generate() -> Result<Self, AlkaliError> {
                require_init()?;

                let mut key = Self::new_empty()?;
                unsafe {
                    // SAFETY: This function expects a pointer to a region of memory sufficient to
                    // store a key. The `Key` type allocates `crypto_aead_KEYBYTES`, the length of a
                    // key for this algorithm. It is therefore valid for writes of the required
                    // length. The `Key::inner_mut` method simply returns a mutable pointer to the
                    // struct's backing memory.
                    $keygen(key.inner_mut().cast());
                }
                Ok(key)
            }
        }

        /// A MAC (Message Authentication Code), used to authenticate an encrypted message and any
        /// associated data.
        ///
        /// If using [`encrypt`], the MAC is included in the ciphertext. it is returned separately
        /// in the [`encrypt_detached`] variant.
        pub type MAC = [u8; MAC_LENGTH];

        /// A nonce, used to introduce non-determinism into the keystream calculation.
        ///
        /// Nonces must never be used for multiple messages with the same key. See this algorithm's
        /// security considerations for more information on safely managing nonces.
        pub type Nonce = [u8; NONCE_LENGTH];

        /// Treat `nonce` as a little-endian unsigned integer, and increment it by one.
        ///
        /// This is useful for ensuring a different nonce is used for every message: Increment the
        /// nonce for every message sent. View the security considerations associated with this
        /// algorithm for more information on preventing nonce reuse.
        pub fn increment_nonce(nonce: &mut Nonce) -> Result<(), AlkaliError> {
            $crate::util::increment_le(nonce)
        }

        /// Encrypt `message` using the provided `key`, optionally authenticating additional data
        /// `ad`, writing the result to `output`.
        ///
        /// `message` should be the message to encrypt.
        ///
        /// If `ad` is set to `Some(ad)`, then this additional data will be included in the
        /// calculation of the MAC for this message. The additional data will not be encrypted, nor
        /// will it be included in the output, but it will be required to authenticate the message
        /// during decryption. Similar to how authentication for the ciphertext works, any changes
        /// in the additional data will cause decryption to fail.
        ///
        /// `key` should be a [`Key`] generated randomly using [`Key::generate`].
        ///
        /// `nonce` should be a [nonce](https://en.wikipedia.org/wiki/Cryptographic_nonce) to use in
        /// the encryption process. Nonces must *never* be used more than once with the same key.
        /// See this algorithm's security considerations for more information on safely managing
        /// nonces.
        ///
        /// The encrypted ciphertext will be written to `output`. The ciphertext will be
        /// [`MAC_LENGTH`] bytes longer than `message`, so `output` must be of sufficient size to
        /// store at least this many bytes. An error will be returned if `output` is not sufficient
        /// to store the ciphertext.
        ///
        /// If encryption is successful, returns the number of bytes written to `output` (this will
        /// actually always be `message.len()` + [`MAC_LENGTH`] bytes).
        ///
        /// # Security Considerations
        /// Nonces must *never* be used more than once with the same key. See this algorithm's
        /// security considerations for more information on safely managing nonces.
        pub fn encrypt(
            message: &[u8],
            ad: Option<&[u8]>,
            key: &Key<impl mem::MprotectReadable>,
            nonce: &Nonce,
            output: &mut [u8],
        ) -> Result<usize, AlkaliError> {
            require_init()?;

            let c_len = message.len() + MAC_LENGTH;

            if output.len() < c_len {
                return Err(AEADError::OutputInsufficient.into());
            } else if message.len() > *MESSAGE_LENGTH_MAX {
                return Err(AEADError::MessageTooLong.into());
            }

            let (ad_ptr, ad_len) = match ad {
                Some(ad) => (ad.as_ptr(), ad.len()),
                None => (ptr::null(), 0),
            };

            let encrypt_result = unsafe {
                // SAFETY: The first argument to this function is the destination to which the
                // combined MAC + ciphertext will be written. The ciphertext will be of the same
                // length as the message, and the MAC will always be `$mac_len`, so as long as the
                // output pointer is valid for writes of `message.len() + $mac_len`, it is valid to
                // use here. We verify this condition above, and return an error if the output is
                // insufficient. The next argument is a destination to which the length of the
                // combined MAC + ciphertext will be written. It is documented that if this is set
                // to a null pointer, then it will be ignored. The next two arguments specify the
                // message to encrypt and its length. We use `message.len()` to specify the message
                // length, so `message` is definitely valid for reads of this length. The next two
                // arguments specify a pointer to the additional data to authenticate and the length
                // of the additional data. If additional data is provided, we use `ad.as_ptr()` for
                // the pointer to the additional data, and `ad.len()` for the length of the
                // additional data, so `ad` is clearly valid for reads of this length. If additional
                // data is not provided, we pass a null pointer and a length of zero. It is
                // documented that a null pointer is safe to use here, and Sodium will just not
                // include the additional data in the authentication calculation. The next argument
                // is a pointer to a secret nonce, which is not used for this algorithm, and should
                // always be set to a null pointer, which we do here. The next argument should be a
                // pointer to the nonce to use for encryption. We have defined the `Nonce` type to
                // be `$nonce_len` bytes long, the size of a nonce for this algorithm, so it is
                // valid for reads of the required length. The final argument specifies the key with
                // which the message should be encrypted. We have defined the `Key` type to allocate
                // `$key_len` bytes, the length of a key for this algorithm, so it is valid for
                // reads of the required length. The `Key::inner` method simply returns an immutable
                // pointer to its backing memory.
                $encrypt(
                    output.as_mut_ptr(),
                    ptr::null_mut(),
                    message.as_ptr(),
                    message.len() as libc::c_ulonglong,
                    ad_ptr,
                    ad_len as libc::c_ulonglong,
                    ptr::null(),
                    nonce.as_ptr(),
                    key.inner().cast(),
                )
            };
            assert_not_err!(encrypt_result, stringify!($encrypt));

            Ok(c_len)
        }

        /// Decrypt `ciphertext` using the provided `key`, optionally authenticating additional data
        /// `ad`, writing the result to `output`.
        ///
        /// `ciphertext` should be the combined ciphertext + MAC to decrypt (previously encrypted
        /// using [`encrypt`]).
        ///
        /// If additional authenticated data was supplied during encryption, it should also be
        /// provided as `ad`, otherwise `ad` can be set to `None`. Note that if different additional
        /// data is specified to the additional data provided during encryption, decryption will
        /// fail.
        ///
        /// `key` should be the [`Key`] to use to decrypt the message. `nonce` should be the
        /// [`Nonce`] which was used to encrypt the message.
        ///
        /// The decrypted plaintext will be written to `output`. The plaintext will be
        /// [`MAC_LENGTH`] bytes shorter than `ciphertext`, so `output` must be of sufficient size
        /// to store at least this many bytes. An error will be returned if `output` is not
        /// sufficient to store the ciphertext.
        ///
        /// Decryption will fail if authentication of the encrypted message or the additional data
        /// fails. If decryption is successful, the plaintext is written to `output`, and the length
        /// of the plaintext will be returned (this will always be `ciphertext.len()` -
        /// [`MAC_LENGTH`] bytes).
        pub fn decrypt(
            ciphertext: &[u8],
            ad: Option<&[u8]>,
            key: &Key<impl mem::MprotectReadable>,
            nonce: &Nonce,
            output: &mut [u8],
        ) -> Result<usize, AlkaliError> {
            require_init()?;

            if ciphertext.len() < MAC_LENGTH {
                return Err(AEADError::DecryptionFailed.into());
            }

            let m_len = ciphertext.len() - MAC_LENGTH;

            if output.len() < m_len {
                return Err(AEADError::OutputInsufficient.into());
            }

            let (ad_ptr, ad_len) = match ad {
                Some(ad) => (ad.as_ptr(), ad.len()),
                None => (ptr::null(), 0),
            };

            let decrypt_result = unsafe {
                // SAFETY: The first argument to this function is the destination to which the
                // decrypted plaintext will be written. The plaintext will be `$mac_len` bytes
                // shorter than the ciphertext, so as long as the output pointer is valid for writes
                // of `ciphertext.len() - $mac_len`, it is valid to use here. We verify this
                // condition above, and return an error if the output is insufficient. The next
                // argument specifies the destination to which the length of the decrypted plaintext
                // will be written. It is documented that if this is set to a null pointer, then it
                // will be ignored. The next argument is a pointer to a secret nonce, which is not
                // used for this algorithm, and should always be set to a null pointer, which we do
                // here. The next two arguments specify the ciphertext to decrypt and its length. We
                // use `ciphertext.len()` to specify the ciphertext length, so `ciphertext` is
                // definitely valid for reads of this length. The next two arguments specify a
                // pointer to the additional data to authenticate and the length of the additional
                // data. If additional data is provided, we use `ad.as_ptr()` for the pointer to the
                // additional data, and `ad.len()` for the length of the additional data, so `ad` is
                // clearly valid for reads of this length. If additional data is provided, we use
                // `ad.as_ptr()` for the pointer to the additional data, and `ad.len()` for the
                // length of the additional data, so `ad` is clearly valid for reads of this length.
                // If additional data is not provided, we pass a null pointer and a length of zero.
                // It is documented that a null pointer is safe to use here, and Sodium will just
                // not include the additional data in the authentication calculation. The next
                // argument is should be a pointer to the nonce which was used for encryption. We
                // have defined the `Nonce` type to be `$nonce_len` bytes long, the size of a nonce
                // for this algorithm, so it is valid for reads of the required length. The final
                // argument specifies the key with which the message was encrypted. We have defined
                // the `Key` type to allocate `$key_len` bytes, the length of a key for this
                // algorithm, so it is valid for reads of the required length. The `Key::inner`
                // method simply returns an immutable pointer to its backing memory.
                $decrypt(
                    output.as_mut_ptr(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ciphertext.as_ptr(),
                    ciphertext.len() as libc::c_ulonglong,
                    ad_ptr,
                    ad_len as libc::c_ulonglong,
                    nonce.as_ptr(),
                    key.inner().cast(),
                )
            };

            if decrypt_result == 0 {
                Ok(m_len)
            } else {
                Err(AEADError::DecryptionFailed.into())
            }
        }

        /// Encrypt `message` using the provided `key`, optionally authenticating additional data
        /// `ad`, writing the result to `output`, separately returning the [`MAC`].
        ///
        /// This function is very similar to the [`encrypt`] function. The difference is that the
        /// standard [`encrypt`] function appends the Message Authentication Code (MAC, used to
        /// verify the authenticity of the ciphertext) to the ciphertext output, while this function
        /// only writes the ciphertext to `output`, and separately returns the MAC.
        ///
        /// `message` should be the message to encrypt.
        ///
        /// If `ad` is set to `Some(ad)`, then this additional data will be included in the
        /// calculation of the MAC for this message. The additional data will not be encrypted, nor
        /// will it be included in the output, but it will be required to authenticate the message
        /// during decryption. Similar to how authentication for the ciphertext works, any changes
        /// in the additional data will cause decryption to fail.
        ///
        /// `key` should be a [`Key`] generated randomly using [`Key::generate`].
        ///
        /// `nonce` should be a [nonce](https://en.wikipedia.org/wiki/Cryptographic_nonce) to use in
        /// the encryption process. Nonces must *never* be used more than once with the same key.
        /// See this algorithm's security considerations for more information on safely managing
        /// nonces.
        ///
        /// The encrypted ciphertext will be written to `output`. The ciphertext will the same
        /// length as `message`, so `output` must be of sufficient size to store at least this many
        /// bytes. An error will be returned if `output` is not sufficient to store the ciphertext.
        ///
        /// If encryption is successful, returns the number of bytes written to `output` (this will
        /// actually always be `message.len()` bytes), the [`Nonce`] used for the encryption
        /// process, and the authentication tag for the message + additional data (a [`MAC`]).
        ///
        /// # Security Considerations
        /// Nonces must *never* be used more than once with the same key. See this algorithm's
        /// security considerations for more information on safely managing nonces.
        pub fn encrypt_detached(
            message: &[u8],
            ad: Option<&[u8]>,
            key: &Key<impl mem::MprotectReadable>,
            nonce: &Nonce,
            output: &mut [u8],
        ) -> Result<(usize, MAC), AlkaliError> {
            require_init()?;

            if output.len() < message.len() {
                return Err(AEADError::OutputInsufficient.into());
            } else if message.len() > *MESSAGE_LENGTH_MAX {
                return Err(AEADError::MessageTooLong.into());
            }

            let (ad_ptr, ad_len) = match ad {
                Some(ad) => (ad.as_ptr(), ad.len()),
                None => (ptr::null(), 0),
            };

            let mut mac = [0u8; MAC_LENGTH];

            let encrypt_result = unsafe {
                // SAFETY: The first argument to this function is the destination to which the
                // ciphertext will be written. The ciphertext will be of the same length as the
                // message, so as long as the output pointer is valid for writes of `message.len()`
                // it is valid to use here. We verify this condition above, and return an error if
                // the output is insufficient. The next argument is the destination to which the MAC
                // will be written. We define the `mac` array to be `$mac_len` bytes, the length of
                // a MAC for this algorithm, so it is valid for writes of the required length. The
                // next argument is a destination to which the length of the calculated MAC will be
                // written. It is documented that if this is set to a null pointer, then it will be
                // ignored. The next two arguments specify the message to encrypt and its length. We
                // use `message.len()` to specify the message length, so `message` is definitely
                // valid for reads of this length. The next two arguments specify a pointer to the
                // additional data to authenticate and the length of the additional data. If
                // additional data is provided, we use `ad.as_ptr()` for the pointer to the
                // additional data, and `ad.len()` for the length of the additional data, so `ad` is
                // clearly valid for reads of this length. If additional data is not provided, we
                // pass a null pointer and a length of zero. It is documented that a null pointer is
                // safe to use here, and Sodium will just not include the additional data in the
                // authentication calculation. The next argument is a pointer to a secret nonce,
                // which is not used for this algorithm, and should always be set to a null pointer,
                // which we do here. The next argument should be a pointer to the nonce to use for
                // encryption. We have defined the `Nonce` type to be `$nonce_len` bytes long, the
                // size of a nonce for this algorithm, so it is valid for reads of the required
                // length. The final argument specifies the key with which the message should be
                // encrypted. We have defined the `Key` type to allocate `$key_len` bytes, the
                // length of a key for this algorithm, so it is valid for reads of the required
                // length. The `Key::inner` method simply returns an immutable pointer to its
                // backing memory.
                $encrypt_d(
                    output.as_mut_ptr(),
                    mac.as_mut_ptr(),
                    ptr::null_mut(),
                    message.as_ptr(),
                    message.len() as libc::c_ulonglong,
                    ad_ptr,
                    ad_len as libc::c_ulonglong,
                    ptr::null(),
                    nonce.as_ptr(),
                    key.inner().cast(),
                )
            };
            assert_not_err!(encrypt_result, stringify!($encrypt_d));

            Ok((message.len(), mac))
        }

        /// Decrypt `ciphertext` using the provided `key`, verifying the detached [`MAC`]
        /// (optionally with additional data `ad`), and writing the result to `output`.
        ///
        /// `ciphertext` should be the ciphertext to decrypt (previously encrypted using
        /// [`encrypt_detached`]).
        ///
        /// If additional authenticated data was supplied during encryption, it should also be
        /// provided as `ad`, otherwise `ad` can be set to `None`. Note that if different additional
        /// data is specified to the additional data provided during encryption, decryption will
        /// fail.
        ///
        /// `mac` should be the [`MAC`] generated when encrypting the ciphertext. `key` should be
        /// the [`Key`] to use to decrypt the message. `nonce` should be the [`Nonce`] which was
        /// used to encrypt the message.
        ///
        /// The decrypted plaintext will be written to `output`. The plaintext will be the same
        /// length as `ciphertext`, so `output` must be of sufficient size to store at least this
        /// many bytes. An error will be returned if `output` is not sufficient to store the
        /// ciphertext.
        ///
        /// Decryption will fail if authentication of the encrypted message or the additional data
        /// fails. If decryption is successful, the plaintext is written to `output`, and the length
        /// of the plaintext will be returned (this will always be `ciphertext.len()` bytes).
        pub fn decrypt_detached(
            ciphertext: &[u8],
            ad: Option<&[u8]>,
            mac: &MAC,
            key: &Key<impl mem::MprotectReadable>,
            nonce: &Nonce,
            output: &mut [u8],
        ) -> Result<usize, AlkaliError> {
            require_init()?;

            if output.len() < ciphertext.len() {
                return Err(AEADError::OutputInsufficient.into());
            }

            let (ad_ptr, ad_len) = match ad {
                Some(ad) => (ad.as_ptr(), ad.len()),
                None => (ptr::null(), 0),
            };

            let decrypt_result = unsafe {
                // SAFETY: The first argument to this function is the destination to which the
                // decrypted plaintext will be written. The plaintext will be the same length as the
                // ciphertext, so as long as the output pointer is valid for writes of
                // `ciphertext.len()`, it is valid to use here. We verify this condition above, and
                // return an error if the output is insufficient. The next argument is a pointer to
                // a secret nonce, which is not used for this algorithm, and should always be set to
                // a null pointer, which we do here. The next two arguments specify the ciphertext
                // to decrypt and its length. We use `ciphertext.len()` to specify the ciphertext
                // length, so `ciphertext` is definitely valid for reads of this length. The next
                // argument should be a pointer to the MAC to use to verify the message & additional
                // data. The `MAC` type is defined to be `$mac_len`, the length of a MAC for this
                // algorithm, so `mac` is valid for reads of the required length. The next two
                // arguments specify a pointer to the additional data to authenticate and the length
                // of the additional data. If additional data is provided, we use `ad.as_ptr()` for
                // the pointer to the additional data, and `ad.len()` for the length of the
                // additional data, so `ad` is clearly valid for reads of this length. If additional
                // data is provided, we use `ad.as_ptr()` for the pointer to the additional data,
                // and `ad.len()` for the length of the additional data, so `ad` is clearly valid
                // for reads of this length. If additional data is not provided, we pass a null
                // pointer and a length of zero. It is documented that a null pointer is safe to use
                // here, and Sodium will just not include the additional data in the authentication
                // calculation. The next argument is should be a pointer to the nonce which was used
                // for encryption. We have defined the `Nonce` type to be `$nonce_len` bytes long,
                // the size of a nonce for this algorithm, so it is valid for reads of the required
                // length. The final argument specifies the key with which the message was
                // encrypted. We have defined the `Key` type to allocate `$key_len` bytes, the
                // length of a key for this algorithm, so it is valid for reads of the required
                // length. The `Key::inner` method simply returns an immutable pointer to its
                // backing memory.
                $decrypt_d(
                    output.as_mut_ptr(),
                    ptr::null_mut(),
                    ciphertext.as_ptr(),
                    ciphertext.len() as libc::c_ulonglong,
                    mac.as_ptr(),
                    ad_ptr,
                    ad_len as libc::c_ulonglong,
                    nonce.as_ptr(),
                    key.inner().cast(),
                )
            };

            if decrypt_result == 0 {
                Ok(ciphertext.len())
            } else {
                Err(AEADError::DecryptionFailed.into())
            }
        }
    };
}

#[allow(unused_imports)]
pub(crate) use chacha_aead_module;

#[allow(unused_macros)]
macro_rules! aead_tests {
    ( $( {
        msg: $msg:expr,
        ad: $ad:expr,
        key: $key:expr,
        nonce: $nonce:expr,
        c: $c:expr,
        mac: $mac:expr,
    }, )* ) => {
        use super::{
            decrypt, decrypt_detached, encrypt, encrypt_detached, Key, MAC_LENGTH, NONCE_LENGTH,
        };
        use crate::{random, AlkaliError};

        #[test]
        fn key_generation() -> Result<(), AlkaliError> {
            let _key = Key::generate()?;
            Ok(())
        }

        #[test]
        fn enc_and_dec() -> Result<(), AlkaliError> {
            let key = Key::generate()?;

            let mut msg_a = [];
            let mut nonce_a = [0; NONCE_LENGTH];
            let mut msg_b = [0; 16];
            let mut nonce_b = [0; NONCE_LENGTH];
            let mut msg_c = [0; 1024];
            let mut nonce_c = [0; NONCE_LENGTH];
            let mut msg_d = [0; 1 << 18];
            let mut nonce_d = [0; NONCE_LENGTH];
            let mut ad = [0; 1024];

            random::fill_random(&mut nonce_a)?;
            random::fill_random(&mut msg_b)?;
            random::fill_random(&mut nonce_b)?;
            random::fill_random(&mut msg_c)?;
            random::fill_random(&mut nonce_c)?;
            random::fill_random(&mut msg_d)?;
            random::fill_random(&mut nonce_d)?;
            random::fill_random(&mut ad)?;

            let mut c_a = [0; MAC_LENGTH];
            let mut c_b = [0; 16 + MAC_LENGTH];
            let mut c_c = [0; 1024 + MAC_LENGTH];
            let mut c_d = [0; (1 << 18) + MAC_LENGTH];

            assert_eq!(encrypt(&msg_a, None, &key, &nonce_a, &mut c_a)?, MAC_LENGTH);
            assert_eq!(
                encrypt(&msg_b, None, &key, &nonce_b, &mut c_b)?,
                16 + MAC_LENGTH
            );
            assert_eq!(
                encrypt(&msg_c, None, &key, &nonce_c, &mut c_c)?,
                1024 + MAC_LENGTH
            );
            assert_eq!(
                encrypt(&msg_d, None, &key, &nonce_d, &mut c_d)?,
                (1 << 18) + MAC_LENGTH
            );

            assert_eq!(decrypt(&c_a, None, &key, &nonce_a, &mut msg_a)?, 0);
            assert_eq!(decrypt(&c_b, None, &key, &nonce_b, &mut msg_b)?, 16);
            assert_eq!(decrypt(&c_c, None, &key, &nonce_c, &mut msg_c)?, 1024);
            assert_eq!(decrypt(&c_d, None, &key, &nonce_d, &mut msg_d)?, 1 << 18);

            assert_eq!(
                encrypt(&msg_a, Some(&ad), &key, &nonce_a, &mut c_a)?,
                MAC_LENGTH
            );
            assert_eq!(
                encrypt(&msg_b, Some(&ad), &key, &nonce_b, &mut c_b)?,
                16 + MAC_LENGTH
            );
            assert_eq!(
                encrypt(&msg_c, Some(&ad), &key, &nonce_c, &mut c_c)?,
                1024 + MAC_LENGTH
            );
            assert_eq!(
                encrypt(&msg_d, Some(&ad), &key, &nonce_d, &mut c_d)?,
                (1 << 18) + MAC_LENGTH
            );

            assert_eq!(decrypt(&c_a, Some(&ad), &key, &nonce_a, &mut msg_a)?, 0);
            assert_eq!(decrypt(&c_b, Some(&ad), &key, &nonce_b, &mut msg_b)?, 16);
            assert_eq!(decrypt(&c_c, Some(&ad), &key, &nonce_c, &mut msg_c)?, 1024);
            assert_eq!(
                decrypt(&c_d, Some(&ad), &key, &nonce_d, &mut msg_d)?,
                1 << 18
            );

            assert!(decrypt(&c_a, None, &key, &nonce_a, &mut msg_a).is_err());
            assert!(decrypt(&c_b, None, &key, &nonce_b, &mut msg_b).is_err());
            assert!(decrypt(&c_c, Some(&ad[..1023]), &key, &nonce_c, &mut msg_c).is_err());
            random::fill_random(&mut ad)?;
            assert!(decrypt(&c_d, Some(&ad), &key, &nonce_d, &mut msg_d).is_err());

            Ok(())
        }

        #[test]
        fn enc_and_dec_detached() -> Result<(), AlkaliError> {
            let key = Key::generate()?;

            let mut msg_a = [];
            let mut nonce_a = [0; NONCE_LENGTH];
            let mut msg_b = [0; 16];
            let mut nonce_b = [0; NONCE_LENGTH];
            let mut msg_c = [0; 1024];
            let mut nonce_c = [0; NONCE_LENGTH];
            let mut msg_d = [0; 1 << 18];
            let mut nonce_d = [0; NONCE_LENGTH];
            let mut ad = [0; 1024];

            random::fill_random(&mut nonce_a)?;
            random::fill_random(&mut msg_b)?;
            random::fill_random(&mut nonce_b)?;
            random::fill_random(&mut msg_c)?;
            random::fill_random(&mut nonce_c)?;
            random::fill_random(&mut msg_d)?;
            random::fill_random(&mut nonce_d)?;
            random::fill_random(&mut ad)?;

            let mut c_a = [];
            let mut c_b = [0; 16];
            let mut c_c = [0; 1024];
            let mut c_d = [0; 1 << 18];

            let (l_a, mac_a) = encrypt_detached(&msg_a, None, &key, &nonce_a, &mut c_a)?;
            let (l_b, mac_b) = encrypt_detached(&msg_b, None, &key, &nonce_b, &mut c_b)?;
            let (l_c, mac_c) = encrypt_detached(&msg_c, None, &key, &nonce_c, &mut c_c)?;
            let (l_d, mac_d) = encrypt_detached(&msg_d, None, &key, &nonce_d, &mut c_d)?;

            assert_eq!(l_a, 0);
            assert_eq!(l_b, 16);
            assert_eq!(l_c, 1024);
            assert_eq!(l_d, 1 << 18);

            assert_eq!(
                decrypt_detached(&c_a, None, &mac_a, &key, &nonce_a, &mut msg_a)?,
                0
            );
            assert_eq!(
                decrypt_detached(&c_b, None, &mac_b, &key, &nonce_b, &mut msg_b)?,
                16
            );
            assert_eq!(
                decrypt_detached(&c_c, None, &mac_c, &key, &nonce_c, &mut msg_c)?,
                1024
            );
            assert_eq!(
                decrypt_detached(&c_d, None, &mac_d, &key, &nonce_d, &mut msg_d)?,
                1 << 18
            );

            let (l_a, mac_a) = encrypt_detached(&msg_a, Some(&ad), &key, &nonce_a, &mut c_a)?;
            let (l_b, mac_b) = encrypt_detached(&msg_b, Some(&ad), &key, &nonce_b, &mut c_b)?;
            let (l_c, mac_c) = encrypt_detached(&msg_c, Some(&ad), &key, &nonce_c, &mut c_c)?;
            let (l_d, mac_d) = encrypt_detached(&msg_d, Some(&ad), &key, &nonce_d, &mut c_d)?;

            assert_eq!(l_a, 0);
            assert_eq!(l_b, 16);
            assert_eq!(l_c, 1024);
            assert_eq!(l_d, 1 << 18);

            assert_eq!(
                decrypt_detached(&c_a, Some(&ad), &mac_a, &key, &nonce_a, &mut msg_a)?,
                0
            );
            assert_eq!(
                decrypt_detached(&c_b, Some(&ad), &mac_b, &key, &nonce_b, &mut msg_b)?,
                16
            );
            assert_eq!(
                decrypt_detached(&c_c, Some(&ad), &mac_c, &key, &nonce_c, &mut msg_c)?,
                1024
            );
            assert_eq!(
                decrypt_detached(&c_d, Some(&ad), &mac_d, &key, &nonce_d, &mut msg_d)?,
                1 << 18
            );

            assert!(decrypt_detached(&c_a, None, &mac_a, &key, &nonce_a, &mut msg_a).is_err());
            assert!(decrypt_detached(&c_b, None, &mac_b, &key, &nonce_b, &mut msg_b).is_err());
            assert!(
                decrypt_detached(&c_c, Some(&ad[..1023]), &mac_c, &key, &nonce_c, &mut msg_c)
                    .is_err()
            );
            random::fill_random(&mut ad)?;
            assert!(decrypt_detached(&c_d, Some(&ad), &mac_d, &key, &nonce_d, &mut msg_d).is_err());

            Ok(())
        }

        #[test]
        fn test_vectors() -> Result<(), AlkaliError> {
            let mut key = Key::new_empty()?;
            let mut c = [0; 1024];
            let mut m = [0; 1024];

            $(
                key.copy_from_slice(&$key);
                assert_eq!(
                    encrypt(&$msg, Some(&$ad), &key, &$nonce, &mut c)?,
                    $msg.len() + MAC_LENGTH
                );
                assert_eq!(&c[..$msg.len()], &$c[..]);
                assert_eq!(&c[$msg.len()..$msg.len() + MAC_LENGTH], &$mac[..]);
                assert_eq!(
                    decrypt(&c[..$msg.len() + MAC_LENGTH], Some(&$ad), &key, &$nonce, &mut m)?,
                    $msg.len()
                );
                assert_eq!(&m[..$msg.len()], &$msg[..$msg.len()]);
            )*

            Ok(())
        }

        #[test]
        fn test_vectors_detached() -> Result<(), AlkaliError> {
            let mut key = Key::new_empty()?;
            let mut c = [0; 1024];
            let mut m = [0; 1024];

            $(
                key.copy_from_slice(&$key);
                let (l, mac) = encrypt_detached(&$msg, Some(&$ad), &key, &$nonce, &mut c)?;
                assert_eq!(l, $msg.len());
                assert_eq!(&c[..l], &$c[..l]);
                assert_eq!(&mac, &$mac);
                assert_eq!(
                    decrypt_detached(&c[..l], Some(&$ad), &mac, &key, &$nonce, &mut m)?,
                    $msg.len()
                );
                assert_eq!(&m[..l], &$msg[..l]);
            )*

            Ok(())
        }
    };
}

#[allow(unused_imports)]
pub(crate) use aead_tests;
