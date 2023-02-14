//! Symmetric [message authentication](https://en.wikipedia.org/wiki/Message_authentication)
//! (HMAC).
//!
//! This module corresponds to the [`crypto_auth`
//! API](https://doc.libsodium.org/secret-key_cryptography/secret-key_authentication) from Sodium.
//!
//! In symmetric authentication, a secret key is used to compute an authentication tag for a
//! message. This authentication tag is deterministic, based on the key and message: the same (key,
//! message) pair will always produce the same tag. An authentication tag can't be calculated
//! without knowing the key. These properties allow parties with knowledge of the key to verify
//! that an authentication tag for a given message was created by someone else with access to the
//! same key. This is often used to verify a message has not been altered by an attacker or
//! transmission error.
//!
//! If *anyone* should be able to verify the authenticity of messages, rather than just parties with
//! whom a shared secret key is already established, the
//! [`asymmetric::sign`](crate::asymmetric::sign) module is best suited for this purpose.
//!
//! # Algorithm Details
//! A [Hash-Based Message Authentication Code](https://en.wikipedia.org/wiki/HMAC) (HMAC) is used
//! to calculate authentication tags. The default algorithm is [HMAC-SHA512-256](hmacsha512256)
//! (HMAC-SHA512 truncated to 256 bits), but [HMAC-SHA512](hmacsha512) and
//! [HMAC-SHA256](hmacsha256) are also available.
//!
//! # Security Considerations
//! A common, but dangerous, mistake is to try to verify the authenticity of a message by generating
//! an authentication tag for the message yourself via [`authenticate`], and naively comparing the
//! tag you calculate with the tag you received from the message's sender. This opens the door to
//! [timing attacks](https://en.wikipedia.org/wiki/Timing_attack). The [`verify`] and
//! [`Multipart::verify`] functions use a constant-time comparison between the tags, and should be
//! used whenever you want to verify a tag, rather than comparing tags yourself.
//!
//! ## Secret Data
//! * The authentication key ([`Key`]) must only be known to parties who should be able to both
//!   create and verify tags
//! * The internal state of the [`Multipart`] struct should be kept secret
//!
//! ## Non-Secret Data
//! * Authentication tags ([`Tag`]) are not sensitive, and do not reveal anything about the content
//!   of the authenticated message to an attacker
//!
//! # Examples
//! Generating an authentication tag for a message and verifying the authentication tag is valid
//! (uses [`authenticate`] and [`verify`]):
//!
//! ```rust
//! use alkali::symmetric::auth;
//!
//! const MESSAGE: &'static str = "Here's a message to authenticate. It can be of any length.";
//!
//! // Sender side:
//!
//! // Generate a new, random key to use for message authentication. This will need to be shared
//! // with the message receiver somehow.
//! let key = auth::Key::generate().unwrap();
//! // The tag returned by `authenticate` is what proves the message's authenticity, and should be
//! // transmitted alongside the message.
//! let tag = auth::authenticate(MESSAGE.as_bytes(), &key).unwrap();
//!
//!
//! // ...
//!
//!
//! // Receiver side:
//! // We assume `key` is somehow known to the receiver.
//!
//! // The `verify` function checks that `tag` is a valid authentication tag for the message and
//! // key, thereby proving the message's authenticity. An error is returned if the tag is not valid
//! // (i.e: the message is inauthentic).
//! auth::verify(MESSAGE.as_bytes(), &tag, &key).expect("Authentication failed!");
//! ```
//!
//! If you have an especially long message, or a message you are transmitting/receiving in chunks,
//! it may make more sense to use the streaming API, which allows you to specify the message to
//! authenticate in multiple parts (uses [`Multipart`]):
//!
//! ```rust
//! use alkali::symmetric::auth;
//!
//! // Sender side:
//!
//! let key = auth::Key::generate().unwrap();
//! let mut state = auth::Multipart::new(&key).unwrap();
//! state.update(b"Here's the first part");
//! state.update(b"... And the second!");
//! let tag = state.authenticate();
//!
//!
//! // ...
//!
//!
//! // Receiver side:
//! // We assume `key` is somehow known to the receiver.
//!
//! // When we verify the message, the contents don't have to be added to the Multipart state in the
//! // same chunks as we did when the authentication tag was created: Each piece of the message
//! // added to the state is concatenated in the tag calculation
//! let mut state = auth::Multipart::new(&key).unwrap();
//! state.update(b"Here");
//! state.update(b"'s the first ");
//! state.update(b"part... And the ");
//! state.update(b"second!");
//! state.verify(&tag).expect("Authentication failed!");
//! ```

// TODO: The multipart API in Sodium supports variable-length keys. We should consider support for
// this.

crate::error_type! {
    /// Error type returned if something went wrong in the `auth` module.
    AuthError {
        /// Failed to authenticate a message.
        ///
        /// The provided tag is not correct for this message + key.
        ///
        /// This may indicate an attempted forgery, a transmission error, or that you're using a
        /// different key to the one used by the message sender. In any case, the authenticity of
        /// the message can't be verified, and it should not be trusted.
        AuthenticationFailed,
    }
}

/// Generates the API for an `auth` module with the given functions from Sodium for a specific
/// implementation.
macro_rules! auth_module {
    (
        $key_len:expr,      // crypto_auth_KEYBYTES
        $tag_len:expr,      // crypto_auth_BYTES
        $keygen:path,       // crypto_auth_keygen
        $authenticate:path, // crypto_auth
        $verify:path,       // crypto_auth_verify
        $mp_state:ty,       // crypto_auth_state
        $mp_init:path,      // crypto_auth_init
        $mp_update:path,    // crypto_auth_update
        $mp_final:path,     // crypto_auth_final
    ) => {
        use $crate::symmetric::auth::AuthError;
        use $crate::{assert_not_err, mem, require_init, unexpected_err, AlkaliError};

        /// The length of a symmetric key for message authentication, in bytes.
        pub const KEY_LENGTH: usize = $key_len as usize;

        /// The length of a message authentication tag, in bytes.
        ///
        /// No matter the length of the message to authenticate, the calculated tag is of this fixed
        /// length.
        pub const TAG_LENGTH: usize = $tag_len as usize;

        mem::hardened_buffer! {
            /// A secret key for symmetric message authentication.
            ///
            /// There are no *technical* constraints on the contents of a key, but it should be
            /// indistinguishable from random noise. A random key can be securely generated via
            /// [`Key::generate`].
            ///
            /// A secret key must not be made public.
            ///
            /// This is a [hardened buffer type](https://docs.rs/alkali#hardened-buffer-types), and
            /// will be zeroed on drop. A number of other security measures are taken to protect
            /// its contents. This type in particular can be thought of as roughly equivalent to a
            /// `[u8; KEY_LENGTH]`, and implements [`core::ops::Deref`] so it can be used like it is
            /// an `&[u8]`. This struct uses heap memory while in scope, allocated using Sodium's
            /// [secure memory utilities](https://doc.libsodium.org/memory_management).
            pub Key(KEY_LENGTH);
        }

        impl Key {
            /// Generate a new, random key for use in symmetric message authentication.
            pub fn generate() -> Result<Self, AlkaliError> {
                require_init()?;

                let mut key = Self::new_empty()?;
                unsafe {
                    // SAFETY: This function expects a pointer to a region of memory sufficient to
                    // store a key for this algorithm. We have defined the `Key` type using the
                    // `crypto_auth_KEYBYTES` constant from Sodium, so it definitely has the correct
                    // amount of space allocated to store a key. The `Key::inner_mut` method simply
                    // returns a mutable pointer to its backing memory. The Sodium documentation
                    // specifies that `crypto_auth_KEYBYTES` random bytes will be written starting
                    // at the provided pointer. This is a valid representation of
                    // `[u8; KEY_LENGTH]`, so `key` is in a valid state following this function
                    // call.
                    $keygen(key.inner_mut() as *mut libc::c_uchar);
                }
                Ok(key)
            }
        }

        /// An authentication tag for a message.
        ///
        /// This authentication tag is what proves the authenticity of a message, so it should be
        /// transmitted along with the message to be authenticated. Authentication tags are not
        /// sensitive, and may be transmitted in the clear.
        #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
        #[cfg_attr(feature = "use-serde", derive(serde::Serialize, serde::Deserialize))]
        pub struct Tag(
            #[cfg_attr(feature = "use-serde", serde(with = "serde_big_array::BigArray"))]
            pub  [u8; TAG_LENGTH],
        );

        /// Streaming authentication API, for long/multi-part message authentication.
        ///
        /// This can be used to calculate an authentication tag for a message which is too large to
        /// fit into memory, or where the message is transmitted/received in portions.
        ///
        /// This struct uses heap memory while in scope, allocated using Sodium's [secure memory
        /// utilities](https://doc.libsodium.org/memory_management).
        ///
        /// # Security Considerations
        /// The inner state of this struct should not be made public: It can be used to calculate
        /// authentication tags for the associated key. None of the methods exposed here will reveal
        /// any of its inner state, so this shouldn't be something that you need to worry about.
        #[derive(Debug)]
        pub struct Multipart {
            state: core::ptr::NonNull<$mp_state>,
            _marker: core::marker::PhantomData<$mp_state>,
        }

        impl Multipart {
            /// Create a new instance of the struct.
            ///
            /// The provided [`Key`] should be the shared symmetric key to use for
            /// authentication/verification.
            pub fn new(key: &Key) -> Result<Self, AlkaliError> {
                require_init()?;

                let mut state = unsafe {
                    // SAFETY: This call to malloc() will allocate the memory required for a
                    // `crypto_auth_state` type, outside of Rust's memory management. The
                    // associated memory is always freed in the corresponding `drop` call for the
                    // Multipart struct, unless initialisation fails, in which case it is freed
                    // before `Multipart::new` returns, and not used again. We never free the memory
                    // in any other place in this struct, and drop can only be called once, so a
                    // double-free is not possible. We never expose a pointer to the allocated
                    // memory directly. See the drop implementation for more reasoning on safety.
                    mem::malloc()?
                };

                let init_result = unsafe {
                    // SAFETY: This function initialises a `crypto_auth_state` struct. It expects a
                    // pointer to a region of memory sufficient to store such a struct, a key, and
                    // the length of the provided key. For the first argument, we pass a region of
                    // memory sufficient to store the struct, allocated above. The type of `state`
                    // is a `NonNull` pointer, and the unsafe block above will return early if
                    // allocation failed, so this pointer is valid for use here. The `Key` type is
                    // defined to have length equal to `crypto_auth_KEYBYTES`, so
                    // `crypto_auth_KEYBYTES` bytes can be read from the `key` pointer without an
                    // over-read. The `Key::inner` method simply returns an immutable pointer to the
                    // type's backing memory. Sodium's documentation specifies that after this
                    // function is called, the memory pointed to by `state` is correctly
                    // initialised, and is a valid representation of a `crypto_auth_state` struct
                    // which can be used with other functions from Sodium.
                    $mp_init(
                        state.as_mut(),
                        key.inner() as *const libc::c_uchar,
                        KEY_LENGTH,
                    )
                };

                // This return value is not possible in the current implementation of
                // `crypto_auth_init` in Sodium, but could be in the future.
                if init_result != 0 {
                    unsafe {
                        // SAFETY: The memory we free here was allocated previously in this function
                        // using Sodium's allocator, and has not yet been freed, so it is valid to
                        // free it here. The `unexpected_err!` macro below will always panic, so
                        // this function will not return, and an instance of `Self` is never
                        // initialised, preventing a double-free or use-after-free.
                        mem::free(state);
                    }
                    unexpected_err!(stringify!($mp_init));
                }

                Ok(Self {
                    state,
                    _marker: core::marker::PhantomData,
                })
            }

            /// Try to clone this Multipart state.
            ///
            /// This function initialises a new instance of this struct, in the same state as the
            /// current one, so any data written to be authenticated in the current struct will also
            /// be used in the authentication tag calculation for the new struct.
            ///
            /// The same [`Key`] used to initialise the original [`Multipart`] instance will be used
            /// to authenticate any data added to the new instance.
            pub fn try_clone(&self) -> Result<Self, AlkaliError> {
                // We do not use `require_init` here, as it must be called to initialise a
                // `Multipart` struct.

                let state = unsafe {
                    // SAFETY: This call to malloc() will allocate the memory required for a
                    // `crypto_auth_state` type, outside of Rust's memory management. The
                    // associated memory is always freed in the corresponding `drop` call for the
                    // Multipart struct. We never free the memory in any other place in this struct,
                    // and drop can only be called once, so a double-free is not possible. We never
                    // expose a pointer to the allocated memory directly. See the drop
                    // implementation for more reasoning on safety.
                    let mut state = mem::malloc()?;

                    // SAFETY: We have called `malloc` to allocate sufficient space for one
                    // `crypto_auth_state` struct at each of the two pointers used here:
                    // `self.state` was allocated in a call to `Self::new`, and `state` was
                    // allocated above, so both are valid for reads/writes of
                    // `size_of::<crypto_auth_state>` bytes. We have just allocated a fresh region
                    // of memory for `state`, so it definitely doesn't overlap with `self.state`. To
                    // initialise an instance of `Self`, `self.state` must be a valid representation
                    // of a `crypto_auth_state` struct. No methods within `Self` would cause
                    // `self.state` to point to an invalid representation of a `crypto_auth_state`
                    // struct. Therefore, after the copy, `state` must also point to a valid
                    // representation of a `crypto_auth_state` struct, and can be used with the
                    // multipart auth functions from Sodium.
                    core::ptr::copy_nonoverlapping(self.state.as_ptr(), state.as_mut(), 1);

                    state
                };

                Ok(Self {
                    state,
                    _marker: core::marker::PhantomData,
                })
            }

            /// Add message contents to be authenticated.
            pub fn update(&mut self, chunk: &[u8]) {
                // We do not use `require_init` here, as it must be called to initialise a
                // `Multipart` struct.

                let update_result = unsafe {
                    // SAFETY: This function takes a pointer to a `crypto_auth_state` struct, a
                    // pointer to a chunk of data to add to the auth tag calculation, and the
                    // length of this data. For the first argument, we pass a mutable pointer to a
                    // `crypto_auth_state` struct. The `Multipart::new` method ensures that the
                    // `self.state` pointer is correctly initialised and points to a valid
                    // representation of a `crypto_auth_state` struct. Therefore, it is correct to
                    // use it with this function. We use chunk.len() as the third argument, so this
                    // many bytes can definitely be read from `chunk` to be used in the
                    // authentication tag calculation.
                    $mp_update(
                        self.state.as_mut(),
                        chunk.as_ptr(),
                        chunk.len() as libc::c_ulonglong,
                    )
                };

                assert_not_err!(update_result, stringify!($mp_update));
            }

            /// Calculate the authentication tag for the specified message.
            ///
            /// Equivalent to [`authenticate`] for single-part messages.
            ///
            /// # Security Considerations
            /// Do not use this method to *verify* an existing authentication tag for a message, as
            /// naïve comparison of authentication tags gives rise to a timing attack. Instead, use
            /// the [`Multipart::verify`] method, which verifies an authentication tag in constant
            /// time.
            pub fn authenticate(mut self) -> Tag {
                // We do not use `require_init` here, as it must be called to initialise a
                // `Multipart` struct.

                let mut tag = [0u8; TAG_LENGTH];

                let finalise_result = unsafe {
                    // SAFETY: This function takes a pointer to a `crypto_auth_state` struct and a
                    // pointer to which the authentication tag will be written. For the first
                    // argument, we pass a mutable pointer to a `crypto_auth_state` struct. The
                    // `Multipart::new` method ensures that the `self.state` pointer is correctly
                    // initialised and points to a valid representation of a `crypto_auth_state`
                    // struct. Therefore, it is correct to use it with this function. The tag array
                    // here has been defined to be `crypto_auth_BYTES` bytes long, so it is valid
                    // for writes of the expected size for this function.
                    $mp_final(self.state.as_mut(), tag.as_mut_ptr())
                };
                assert_not_err!(finalise_result, stringify!($mp_final));

                Tag(tag)
            }

            /// Verify the provided tag is correct for the specified message.
            ///
            /// Returns an [`AuthError::AuthenticationFailed`](
            /// crate::symmetric::auth::AuthError::AuthenticationFailed) if verification of the
            /// authentication tag failed.
            ///
            /// Equivalent to [`verify`] for single-part messages.
            pub fn verify(mut self, tag: &Tag) -> Result<(), AlkaliError> {
                // We do not use `require_init` here, as it must be called to initialise a
                // `Multipart` struct.

                let mut actual_tag = [0u8; TAG_LENGTH];

                let finalise_result = unsafe {
                    // SAFETY: This function takes a pointer to a `crypto_auth_state` struct and a
                    // pointer to which the authentication tag will be written. For the first
                    // argument, we pass a mutable pointer to a `crypto_auth_state` struct. The
                    // `Multipart::new` method ensures that the `self.state` pointer is correctly
                    // initialised and points to a valid representation of a `crypto_auth_state`
                    // struct. Therefore, it is correct to use it with this function. The
                    // `actual_tag` array here has been defined to be `crypto_auth_BYTES` bytes
                    // long, so it is valid for writes of the expected size for this function.
                    $mp_final(self.state.as_mut(), actual_tag.as_mut_ptr())
                };
                assert_not_err!(finalise_result, stringify!($mp_final));

                if mem::eq(&tag.0, &actual_tag)? {
                    Ok(())
                } else {
                    Err(AuthError::AuthenticationFailed.into())
                }
            }
        }

        impl Drop for Multipart {
            fn drop(&mut self) {
                // We do not use `require_init` here, as it must be called to initialise a
                // `Multipart` struct.

                unsafe {
                    // SAFETY:
                    // * Is a double-free possible in safe code?
                    //   * No: We only free in `drop`, which cannot be called manually, and is
                    //     called exactly once when the struct is actually dropped. Once the value
                    //     is dropped, there's no way to call the method again to cause a double
                    //     free.
                    // * Is a use-after-free possible in safe code?
                    //   * No: We only ever free `self.state` on drop, and after drop, none of the
                    //     type's methods are accessible.
                    // * Is a memory leak possible in safe code?
                    //   * Yes: If the user uses something like `Box::leak()`, `ManuallyDrop`, or
                    //     `core::mem::forget`, the destructor will not be called even though the
                    //     struct is dropped. However, it is documented that in these cases heap
                    //     memory may be leaked, so this is expected behaviour. In addition, certain
                    //     signal interrupts or using panic=abort behaviour will mean the destructor
                    //     is not called. There's little we can do about this, but a failure to free
                    //     is probably reasonable in such cases. In any other case, `drop` will be
                    //     called, and the memory freed.
                    // `self.state` was allocated in the `Multipart` constructor using Sodium's
                    // allocator, so it is correct to free it using Sodium's allocator.
                    mem::free(self.state);
                }
            }
        }

        /// Compute the authentication tag for a given message and key.
        ///
        /// # Security Considerations
        /// Do not use this function to *verify* an existing authentication tag for a message, as
        /// naïve comparison of authentication tags gives rise to a timing attack. Instead, use
        /// the [`verify`] function, which verifies an authentication tag in constant time.
        pub fn authenticate(message: &[u8], key: &Key) -> Result<Tag, AlkaliError> {
            require_init()?;

            let mut tag = [0u8; TAG_LENGTH];

            let auth_result = unsafe {
                // SAFETY: This function takes a pointer to a location where the calculated
                // authentication tag will be written, a pointer to a message to authenticate, the
                // length of the message, and a pointer to the key to use for authentication. We
                // have defined the `tag` buffer to be `crypto_auth_BYTES` long, the length of an
                // authentication tag as defined in Sodium, so it is of sufficient size to store the
                // tag. We use `message.len()` to specify the length of the message to authenticate,
                // so clearly the `message` pointer is valid for reads of this length, and an
                // over-read will not occur. Finally, we define the `Key` type to be
                // `crypto_auth_KEYBYTES` long, so it is of the expected size for use in this
                // function, and a full key can be read from the pointer without an over-read. The
                // `Key::inner` method simply returns a pointer to the backing memory.
                $authenticate(
                    tag.as_mut_ptr(),
                    message.as_ptr(),
                    message.len() as libc::c_ulonglong,
                    key.inner() as *const libc::c_uchar,
                )
            };
            assert_not_err!(auth_result, stringify!($authenticate));

            Ok(Tag(tag))
        }

        /// Verifies that an authentication tag is valid for a given message, using the provided
        /// key.
        ///
        /// Returns an [`AuthError::AuthenticationFailed`](
        /// crate::symmetric::auth::AuthError::AuthenticationFailed) if verification of the
        /// authentication tag failed.
        pub fn verify(message: &[u8], tag: &Tag, key: &Key) -> Result<(), AlkaliError> {
            require_init()?;

            let verification_result = unsafe {
                // SAFETY: This function takes a pointer to the tag to be verified, a pointer to the
                // message to authenticate, the length of the message, and a pointer to the key to
                // use for authentication. We have defined the `Tag` type to be `crypto_auth_BYTES`
                // long, the length of an authentication tag as defined in Sodium, so it is valid
                // for reads of this length. We use `message.len()` to specify the length of the
                // message to authenticate, so clearly the `message` pointer is valid for reads of
                // this length, and an over-read will not occur. Finally, we define the `Key` type
                // to be `crypto_auth_KEYBYTES` long, so it is of the expected size for use in this
                // function, and a full key can be read from the pointer without an over-read. The
                // `Key::inner` method simply returns a pointer to the backing memory.
                $verify(
                    tag.0.as_ptr(),
                    message.as_ptr(),
                    message.len() as libc::c_ulonglong,
                    key.inner() as *const libc::c_uchar,
                )
            };

            if verification_result == 0 {
                Ok(())
            } else {
                Err(AuthError::AuthenticationFailed.into())
            }
        }
    };
}

/// Generates tests for an `auth` implementation.
#[allow(unused_macros)]
macro_rules! auth_tests {
    ( $( {
        msg: $msg:expr,
        key: $key:expr,
        tag: $tag:expr,
    }, )* ) => {
        use super::{authenticate, verify, Key, Multipart, Tag};
        use $crate::random::{fill_random, random_u32_in_range};
        use $crate::AlkaliError;

        #[test]
        fn key_generation() -> Result<(), AlkaliError> {
            let _key = Key::generate()?;
            Ok(())
        }

        #[test]
        fn auth_and_verify() -> Result<(), AlkaliError> {
            let key = Key::generate()?;

            let buf_a = [];
            let mut buf_b = [0; 16];
            let mut buf_c = [0; 1024];
            let mut buf_d = [0; 1 << 20];

            fill_random(&mut buf_b)?;
            fill_random(&mut buf_c)?;
            fill_random(&mut buf_d)?;

            let tag_a = authenticate(&buf_a, &key)?;
            let tag_b = authenticate(&buf_b, &key)?;
            let tag_c = authenticate(&buf_c, &key)?;
            let tag_d = authenticate(&buf_d, &key)?;

            verify(&buf_a, &tag_a, &key)?;
            verify(&buf_b, &tag_b, &key)?;
            verify(&buf_c, &tag_c, &key)?;
            verify(&buf_d, &tag_d, &key)?;

            fill_random(&mut buf_b)?;
            fill_random(&mut buf_c)?;
            fill_random(&mut buf_d)?;

            assert!(verify(&buf_b, &tag_b, &key).is_err());
            assert!(verify(&buf_c, &tag_c, &key).is_err());
            assert!(verify(&buf_d, &tag_d, &key).is_err());

            Ok(())
        }

        #[test]
        fn single_part_vectors() -> Result<(), AlkaliError> {
            let mut key = Key::new_empty()?;

            $(
                key.copy_from_slice(&$key);

                let actual_tag = authenticate(&$msg, &key)?;
                assert_eq!(actual_tag.0, $tag);

                verify(&$msg, &Tag($tag), &key)?;
            )*

            Ok(())
        }

        #[test]
        fn random_tests_multipart() -> Result<(), AlkaliError> {
            let mut msg = [0; 2000];
            for i in 1..2000 {
                let key = Key::generate()?;
                fill_random(&mut msg[..i])?;

                let tag_single = authenticate(&msg[..i], &key)?;
                let mut state = Multipart::new(&key)?;
                let mut written = 0;
                while written < i {
                    let write_to = random_u32_in_range(written as u32, i as u32 + 1)?;
                    state.update(&msg[written..write_to as usize]);
                    written = write_to as usize;
                }
                let mut tag_multi = state.authenticate();
                assert_eq!(tag_single, tag_multi);
                verify(&msg[..i], &tag_multi, &key)?;

                let mut state = Multipart::new(&key)?;
                let mut written = 0;
                while written < i {
                    let write_to = random_u32_in_range(written as u32, i as u32 + 1)?;
                    state.update(&msg[written..write_to as usize]);
                    written = write_to as usize;
                }
                state.verify(&tag_multi)?;

                fill_random(&mut tag_multi.0)?;
                let mut state = Multipart::new(&key)?;
                let mut written = 0;
                while written < i {
                    let write_to = random_u32_in_range(written as u32, i as u32 + 1)?;
                    state.update(&msg[written..write_to as usize]);
                    written = write_to as usize;
                }
                assert!(state.verify(&tag_multi).is_err());
            }

            Ok(())
        }
    };
}

/// HMAC construction using SHA-512 truncated to 256 bits.
pub mod hmacsha512256 {
    use libsodium_sys as sodium;

    auth_module!(
        sodium::crypto_auth_hmacsha512256_KEYBYTES,
        sodium::crypto_auth_hmacsha512256_BYTES,
        sodium::crypto_auth_hmacsha512256_keygen,
        sodium::crypto_auth_hmacsha512256,
        sodium::crypto_auth_hmacsha512256_verify,
        sodium::crypto_auth_hmacsha512256_state,
        sodium::crypto_auth_hmacsha512256_init,
        sodium::crypto_auth_hmacsha512256_update,
        sodium::crypto_auth_hmacsha512256_final,
    );

    #[cfg(test)]
    mod tests {
        auth_tests! [
            {
                msg: [],
                key: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                      0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a,
                      0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20],
                tag: [0x2e, 0xe8, 0x66, 0x81, 0x5c, 0x14, 0x65, 0xe4, 0x00, 0xf1, 0x9f, 0x5d, 0xb9,
                      0x06, 0x44, 0x35, 0x53, 0x73, 0xa3, 0x94, 0x13, 0x2e, 0x3e, 0xca, 0x6d, 0xa1,
                      0x63, 0x11, 0x8f, 0x8e, 0x63, 0x57],
            },
            {
                msg: [0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
                      0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
                      0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
                      0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd],
                key: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                      0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a,
                      0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20],
                tag: [0x79, 0x18, 0x7c, 0xac, 0xd8, 0x64, 0xc1, 0x32, 0x51, 0x3e, 0xa8, 0x9d, 0xc3,
                      0x69, 0xd3, 0x02, 0x0e, 0x8e, 0x74, 0x52, 0x05, 0xdf, 0xfb, 0xd3, 0x66, 0xf2,
                      0xf9, 0xbc, 0xdd, 0x50, 0xd3, 0xe7],
            },
            {
                msg: [0x41, 0x6e, 0x6f, 0x74, 0x68, 0x65, 0x72, 0x20, 0x6f, 0x6e, 0x65, 0x20, 0x67,
                      0x6f, 0x74, 0x20, 0x63, 0x61, 0x75, 0x67, 0x68, 0x74, 0x20, 0x74, 0x6f, 0x64,
                      0x61, 0x79, 0x2c, 0x20, 0x69, 0x74, 0x27, 0x73, 0x20, 0x61, 0x6c, 0x6c, 0x20,
                      0x6f, 0x76, 0x65, 0x72, 0x20, 0x74, 0x68, 0x65, 0x20, 0x70, 0x61, 0x70, 0x65,
                      0x72, 0x73, 0x2e, 0x20, 0x22, 0x54, 0x65, 0x65, 0x6e, 0x61, 0x67, 0x65, 0x72,
                      0x20, 0x41, 0x72, 0x72, 0x65, 0x73, 0x74, 0x65, 0x64, 0x20, 0x69, 0x6e, 0x20,
                      0x43, 0x6f, 0x6d, 0x70, 0x75, 0x74, 0x65, 0x72, 0x20, 0x43, 0x72, 0x69, 0x6d,
                      0x65, 0x20, 0x53, 0x63, 0x61, 0x6e, 0x64, 0x61, 0x6c, 0x22, 0x2c, 0x20, 0x22,
                      0x48, 0x61, 0x63, 0x6b, 0x65, 0x72, 0x20, 0x41, 0x72, 0x72, 0x65, 0x73, 0x74,
                      0x65, 0x64, 0x20, 0x61, 0x66, 0x74, 0x65, 0x72, 0x20, 0x42, 0x61, 0x6e, 0x6b,
                      0x20, 0x54, 0x61, 0x6d, 0x70, 0x65, 0x72, 0x69, 0x6e, 0x67, 0x22, 0x2e, 0x2e,
                      0x2e, 0x20, 0x44, 0x61, 0x6d, 0x6e, 0x20, 0x6b, 0x69, 0x64, 0x73, 0x2e, 0x20,
                      0x54, 0x68, 0x65, 0x79, 0x27, 0x72, 0x65, 0x20, 0x61, 0x6c, 0x6c, 0x20, 0x61,
                      0x6c, 0x69, 0x6b, 0x65, 0x2e],
                key: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                      0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a,
                      0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20],
                tag: [0x45, 0x4b, 0x4f, 0xfa, 0xbc, 0x4d, 0x83, 0x97, 0xc7, 0x82, 0xcd, 0x60, 0x28,
                      0x36, 0xe1, 0x41, 0xde, 0x07, 0x9c, 0x61, 0x24, 0x04, 0xb6, 0x96, 0xca, 0x20,
                      0x17, 0x05, 0xe9, 0x46, 0x57, 0x9f],
            },
        ];
    }
}

/// HMAC construction using SHA-256.
pub mod hmacsha256 {
    use libsodium_sys as sodium;

    auth_module!(
        sodium::crypto_auth_hmacsha256_KEYBYTES,
        sodium::crypto_auth_hmacsha256_BYTES,
        sodium::crypto_auth_hmacsha256_keygen,
        sodium::crypto_auth_hmacsha256,
        sodium::crypto_auth_hmacsha256_verify,
        sodium::crypto_auth_hmacsha256_state,
        sodium::crypto_auth_hmacsha256_init,
        sodium::crypto_auth_hmacsha256_update,
        sodium::crypto_auth_hmacsha256_final,
    );

    #[cfg(test)]
    mod tests {
        auth_tests! {
            {
                msg: [],
                key: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                      0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a,
                      0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20],
                tag: [0x46, 0x24, 0x76, 0xa8, 0x97, 0xdd, 0xfd, 0xbd, 0x40, 0xd1, 0x42, 0x0e, 0x08,
                      0xa5, 0xbc, 0xfe, 0xeb, 0x25, 0xc3, 0xe2, 0xad, 0xe6, 0xa0, 0xa9, 0x08, 0x3b,
                      0x32, 0x7b, 0x9e, 0xf9, 0xfc, 0xa1],
            },
            {
                msg: [0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
                      0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
                      0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
                      0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd],
                key: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                      0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a,
                      0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20],
                tag: [0x37, 0x2e, 0xfc, 0xf9, 0xb4, 0x0b, 0x35, 0xc2, 0x11, 0x5b, 0x13, 0x46, 0x90,
                      0x3d, 0x2e, 0xf4, 0x2f, 0xce, 0xd4, 0x6f, 0x08, 0x46, 0xe7, 0x25, 0x7b, 0xb1,
                      0x56, 0xd3, 0xd7, 0xb3, 0x0d, 0x3f],
            },
            {
                msg: [0x41, 0x6e, 0x6f, 0x74, 0x68, 0x65, 0x72, 0x20, 0x6f, 0x6e, 0x65, 0x20, 0x67,
                      0x6f, 0x74, 0x20, 0x63, 0x61, 0x75, 0x67, 0x68, 0x74, 0x20, 0x74, 0x6f, 0x64,
                      0x61, 0x79, 0x2c, 0x20, 0x69, 0x74, 0x27, 0x73, 0x20, 0x61, 0x6c, 0x6c, 0x20,
                      0x6f, 0x76, 0x65, 0x72, 0x20, 0x74, 0x68, 0x65, 0x20, 0x70, 0x61, 0x70, 0x65,
                      0x72, 0x73, 0x2e, 0x20, 0x22, 0x54, 0x65, 0x65, 0x6e, 0x61, 0x67, 0x65, 0x72,
                      0x20, 0x41, 0x72, 0x72, 0x65, 0x73, 0x74, 0x65, 0x64, 0x20, 0x69, 0x6e, 0x20,
                      0x43, 0x6f, 0x6d, 0x70, 0x75, 0x74, 0x65, 0x72, 0x20, 0x43, 0x72, 0x69, 0x6d,
                      0x65, 0x20, 0x53, 0x63, 0x61, 0x6e, 0x64, 0x61, 0x6c, 0x22, 0x2c, 0x20, 0x22,
                      0x48, 0x61, 0x63, 0x6b, 0x65, 0x72, 0x20, 0x41, 0x72, 0x72, 0x65, 0x73, 0x74,
                      0x65, 0x64, 0x20, 0x61, 0x66, 0x74, 0x65, 0x72, 0x20, 0x42, 0x61, 0x6e, 0x6b,
                      0x20, 0x54, 0x61, 0x6d, 0x70, 0x65, 0x72, 0x69, 0x6e, 0x67, 0x22, 0x2e, 0x2e,
                      0x2e, 0x20, 0x44, 0x61, 0x6d, 0x6e, 0x20, 0x6b, 0x69, 0x64, 0x73, 0x2e, 0x20,
                      0x54, 0x68, 0x65, 0x79, 0x27, 0x72, 0x65, 0x20, 0x61, 0x6c, 0x6c, 0x20, 0x61,
                      0x6c, 0x69, 0x6b, 0x65, 0x2e],
                key: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                      0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a,
                      0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20],
                tag: [0xf5, 0x59, 0xbd, 0x27, 0xe1, 0x7f, 0x8f, 0x8f, 0xa2, 0x58, 0x8b, 0x7a, 0x1a,
                      0xe0, 0x70, 0x8a, 0x8b, 0xdf, 0x68, 0xb3, 0xb0, 0x90, 0x8c, 0xea, 0x87, 0xec,
                      0x93, 0xb9, 0x77, 0x38, 0x69, 0xb4],
            },
        }
    }
}

/// HMAC construction using SHA-512.
pub mod hmacsha512 {
    use libsodium_sys as sodium;

    auth_module!(
        sodium::crypto_auth_hmacsha512_KEYBYTES,
        sodium::crypto_auth_hmacsha512_BYTES,
        sodium::crypto_auth_hmacsha512_keygen,
        sodium::crypto_auth_hmacsha512,
        sodium::crypto_auth_hmacsha512_verify,
        sodium::crypto_auth_hmacsha512_state,
        sodium::crypto_auth_hmacsha512_init,
        sodium::crypto_auth_hmacsha512_update,
        sodium::crypto_auth_hmacsha512_final,
    );

    #[cfg(test)]
    mod tests {
        auth_tests! {
            {
                msg: [],
                key: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                      0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a,
                      0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20],
                tag: [0x2e, 0xe8, 0x66, 0x81, 0x5c, 0x14, 0x65, 0xe4, 0x00, 0xf1, 0x9f, 0x5d, 0xb9,
                      0x06, 0x44, 0x35, 0x53, 0x73, 0xa3, 0x94, 0x13, 0x2e, 0x3e, 0xca, 0x6d, 0xa1,
                      0x63, 0x11, 0x8f, 0x8e, 0x63, 0x57, 0xd4, 0x8c, 0x62, 0x31, 0xe5, 0xd0, 0xee,
                      0xd1, 0x1e, 0x2b, 0xed, 0x7d, 0x60, 0x3a, 0xc1, 0x1b, 0x80, 0x24, 0x14, 0x96,
                      0x90, 0xe9, 0x0b, 0x30, 0x3b, 0xda, 0xf0, 0x05, 0x51, 0x72, 0xd6, 0x00],
            },
            {
                msg: [0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
                      0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
                      0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
                      0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd],
                key: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                      0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a,
                      0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20],
                tag: [0x79, 0x18, 0x7c, 0xac, 0xd8, 0x64, 0xc1, 0x32, 0x51, 0x3e, 0xa8, 0x9d, 0xc3,
                      0x69, 0xd3, 0x02, 0x0e, 0x8e, 0x74, 0x52, 0x05, 0xdf, 0xfb, 0xd3, 0x66, 0xf2,
                      0xf9, 0xbc, 0xdd, 0x50, 0xd3, 0xe7, 0x02, 0xa7, 0x43, 0x3a, 0xe0, 0x2e, 0x2f,
                      0xfd, 0xe7, 0x37, 0x56, 0xcb, 0xbc, 0xca, 0x2b, 0x0a, 0x18, 0xa0, 0x9b, 0x0a,
                      0x6e, 0xb5, 0x30, 0x05, 0x13, 0x19, 0x27, 0xba, 0xf7, 0xc4, 0x83, 0x54],
            },
            {
                msg: [0x41, 0x6e, 0x6f, 0x74, 0x68, 0x65, 0x72, 0x20, 0x6f, 0x6e, 0x65, 0x20, 0x67,
                      0x6f, 0x74, 0x20, 0x63, 0x61, 0x75, 0x67, 0x68, 0x74, 0x20, 0x74, 0x6f, 0x64,
                      0x61, 0x79, 0x2c, 0x20, 0x69, 0x74, 0x27, 0x73, 0x20, 0x61, 0x6c, 0x6c, 0x20,
                      0x6f, 0x76, 0x65, 0x72, 0x20, 0x74, 0x68, 0x65, 0x20, 0x70, 0x61, 0x70, 0x65,
                      0x72, 0x73, 0x2e, 0x20, 0x22, 0x54, 0x65, 0x65, 0x6e, 0x61, 0x67, 0x65, 0x72,
                      0x20, 0x41, 0x72, 0x72, 0x65, 0x73, 0x74, 0x65, 0x64, 0x20, 0x69, 0x6e, 0x20,
                      0x43, 0x6f, 0x6d, 0x70, 0x75, 0x74, 0x65, 0x72, 0x20, 0x43, 0x72, 0x69, 0x6d,
                      0x65, 0x20, 0x53, 0x63, 0x61, 0x6e, 0x64, 0x61, 0x6c, 0x22, 0x2c, 0x20, 0x22,
                      0x48, 0x61, 0x63, 0x6b, 0x65, 0x72, 0x20, 0x41, 0x72, 0x72, 0x65, 0x73, 0x74,
                      0x65, 0x64, 0x20, 0x61, 0x66, 0x74, 0x65, 0x72, 0x20, 0x42, 0x61, 0x6e, 0x6b,
                      0x20, 0x54, 0x61, 0x6d, 0x70, 0x65, 0x72, 0x69, 0x6e, 0x67, 0x22, 0x2e, 0x2e,
                      0x2e, 0x20, 0x44, 0x61, 0x6d, 0x6e, 0x20, 0x6b, 0x69, 0x64, 0x73, 0x2e, 0x20,
                      0x54, 0x68, 0x65, 0x79, 0x27, 0x72, 0x65, 0x20, 0x61, 0x6c, 0x6c, 0x20, 0x61,
                      0x6c, 0x69, 0x6b, 0x65, 0x2e],
                key: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                      0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a,
                      0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20],
                tag: [0x45, 0x4b, 0x4f, 0xfa, 0xbc, 0x4d, 0x83, 0x97, 0xc7, 0x82, 0xcd, 0x60, 0x28,
                      0x36, 0xe1, 0x41, 0xde, 0x07, 0x9c, 0x61, 0x24, 0x04, 0xb6, 0x96, 0xca, 0x20,
                      0x17, 0x05, 0xe9, 0x46, 0x57, 0x9f, 0x59, 0xdf, 0x10, 0xa1, 0x15, 0xd8, 0xdb,
                      0x09, 0x07, 0x9f, 0x7e, 0x25, 0xba, 0x2b, 0x22, 0x66, 0x49, 0xac, 0xd8, 0x66,
                      0x78, 0x0f, 0xcb, 0x80, 0x33, 0xa3, 0xce, 0xa1, 0xe6, 0x9d, 0xf5, 0x8d],
            },
        }
    }
}

pub use hmacsha512256::*;
