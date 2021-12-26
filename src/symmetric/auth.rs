//! Symmetric message authentication (HMAC).
//!
//! This module corresponds to the [`crypto_auth`
//! API](https://doc.libsodium.org/secret-key_cryptography/secret-key_authentication) from Sodium.
//!
//! In symmetric authentication, a secret key is used to compute an authentication tag for a
//! message. This authentication tag is deterministic, based on the key and message: the same (key,
//! message) pair will always produce the same tag. An authentication tag can't be calculated
//! without knowing the key. These properties allow parties with knowledge of the key to verify
//! that an authentication tag for a given message was created by someone else with access to the
//! same key. This is often used to verify a message has not been altered.
//!
//! # Algorithm Details
//! A [Hash-Based Message Authentication Code](https://en.wikipedia.org/wiki/HMAC) (HMAC) is used
//! to calculate authentication tags. The default algorithm is [HMAC-SHA512-256](hmacsha512256)
//! (HMAC-SHA512 truncated to 256 bits), but [HMAC-SHA512](hmacsha512) and
//! [HMAC-SHA256](hmacsha256) are also available.
//!
//! # Security Considerations
//! A common, but dangerous, mistake is to try to verify a tag by generating the tag again yourself
//! via [`authenticate`], and naively comparing the tag you calculate with the other tag. This
//! opens the door to [timing attacks](https://en.wikipedia.org/wiki/Timing_attack). The [`verify`]
//! and [`Multipart::verify`] functions use a constant-time comparison between the tags, and should
//! be used whenever you want to verify a tag, rather than comparing tags yourself.
//!
//! # Examples
//! Generating an authentication tag for a message and verifying the authentication tag is valid
//! (uses [`authenticate`] and [`verify`]):
//!
//! ```rust
//! use alkali::symmetric::auth;
//!
//! // Generate a new random key to use for authentication
//! let key = auth::Key::generate().unwrap();
//! let message = "Here's a message we wish to authenticate. It can be of any length.";
//! let tag = auth::authenticate(message.as_bytes(), &key).unwrap();
//!
//! // ...
//!
//! match auth::verify(message.as_bytes(), &tag, &key) {
//!     Ok(_) => println!("Authentication succeeded!"),
//!     Err(alkali::AlkaliError::AuthError(auth::AuthError::AuthenticationFailed)) => {
//!         panic!("Uh-oh, message altered!")
//!     },
//!     Err(_) => panic!("Some other error ocurred"),
//! }
//! ```
//!
//! If you have an especially long message, or one you're receiving in chunks, it may make more
//! sense to use the streaming API, which allows you to specify the message to authenticate in
//! multiple parts (uses [`Multipart`]):
//!
//! ```rust
//! use alkali::symmetric::auth;
//!
//! // Here we specify a pre-existing key, rather than generating a new one (in this case, just 32
//! // 0xdb bytes, which is obviously not secure).
//! let key = auth::Key::try_from(&[0xdb; 32]).unwrap();
//! let mut state = auth::Multipart::new(&key).unwrap();
//! state.update(b"Here's the first part");
//! state.update(b"... And the second!");
//! let tag = state.authenticate();
//!
//! // ...
//!
//! // Now let's verify the tag we just generated (switching up the chunks we add to the state):
//! let mut state = auth::Multipart::new(&key).unwrap();
//! state.update(b"Here");
//! state.update(b"'s the first ");
//! state.update(b"part... And the ");
//! state.update(b"second!");
//! assert!(state.verify(&tag).is_ok());
//! ```

// TODO: The multipart API in Sodium supports variable-length keys. We should consider support for
// this.

use thiserror::Error;

/// Error type returned if something went wrong in the auth module.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum AuthError {
    /// Failed to authenticate a message.
    ///
    /// This may indicate an attempted forgery, a transmission error, or that you're using the
    /// wrong key. In any case, the authenticity of the message can't be verified, and it should
    /// not be trusted.
    #[error("authentication failed")]
    AuthenticationFailed,
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
        /// The length of a symmetric key used for message authentication, in bytes.
        pub const KEY_LENGTH: usize = $key_len as usize;

        /// The length of a message authentication tag, in bytes.
        ///
        /// No matter the length of the input to the auth API, the output tag is of fixed length.
        pub const TAG_LENGTH: usize = $tag_len as usize;

        $crate::hardened_buffer! {
            /// Secret key for symmetric message authentication.
            ///
            /// There are no technical constraints on the contents of a key, but it should be
            /// generated randomly using [`Key::generate`].
            ///
            /// A secret key must not be made public.
            ///
            /// This is a [hardened buffer type](https://docs.rs/alkali#hardened-buffer-types), and
            /// will be zeroed on drop. A number of other security measures are taken to protect
            /// its contents.
            Key($key_len as usize)
        }

        impl Key {
            /// Generate a new, random key for use in symmetric message authentication.
            pub fn generate() -> Result<Self, $crate::AlkaliError> {
                $crate::require_init()?;

                let mut key = Self::new_empty()?;
                unsafe {
                    // SAFETY: This function expects a pointer to a region of memory sufficient to
                    // store a key for this algorithm. We have defined this type based on the
                    // crypto_auth_KEYBYTES constant from Sodium, so it definitely has the correct
                    // amount of space allocated to store the key. The Key::inner_mut method simply
                    // gives a mutable pointer to the backing memory.
                    $keygen(key.inner_mut() as *mut libc::c_uchar);
                }
                Ok(key)
            }
        }

        /// An authentication tag for a message.
        pub type Tag = [u8; TAG_LENGTH as usize];

        /// Streaming authentication API, for long/multi-part message authentication.
        ///
        /// This can be used to calculate an authentication tag for a message which is too large to
        /// fit into memory, or where the message is received in portions.
        #[derive(Clone, Copy, Debug)]
        pub struct Multipart($mp_state);

        impl Multipart {
            /// Create a new instance of the struct.
            pub fn new(key: &Key) -> Result<Self, $crate::AlkaliError> {
                $crate::require_init()?;

                let mut state_uninit = std::mem::MaybeUninit::uninit();
                let state = unsafe {
                    // SAFETY: This function initialises a crypto_auth_state struct. It expects a
                    // pointer to a crypto_auth_state struct, a key, and the length of the provided
                    // key. For the first argument, we pass a region of memory sufficient to store
                    // the struct as defined in Rust, rather than C. This definition is generated
                    // via bindgen, and as such, is equivalent to the struct in C, so it is correct
                    // to use it as an argument for this function. The Key type is defined to have
                    // length equal to KEY_LENGTH.
                    $mp_init(state_uninit.as_mut_ptr(), key.as_ptr(), KEY_LENGTH);

                    // SAFETY: Following the crypto_auth_init call, the struct is correctly
                    // initialised, so it is safe to assume its initialised state.
                    state_uninit.assume_init()
                };

                Ok(Self(state))
            }

            /// Add message contents to be authenticated.
            pub fn update(&mut self, chunk: &[u8]) {
                unsafe {
                    // SAFETY: This function takes a pointer to a crypto_auth_state struct, a
                    // pointer to a chunk of data to add to the auth tag calculation, and the
                    // length of this data. For the first argument, we pass a crypto_auth_state
                    // struct, which is defined using bindgen to be equivalent to the definition of
                    // the equivalent struct in C. The struct must have been initialised in order
                    // to initialise this Multipart wrapper struct, so it is in the right state to
                    // call crypto_auth_update. We use chunk.len() as the third argument, so it is
                    // definitely the correct length for the chunk.
                    $mp_update(
                        &mut self.0,
                        chunk.as_ptr(),
                        chunk.len() as libc::c_ulonglong,
                    );
                }
            }

            /// Calculate an authentication tag for the specified message and key.
            ///
            /// Equivalent to [`authenticate`] for single-part messages.
            pub fn authenticate(mut self) -> Tag {
                let mut tag = [0u8; TAG_LENGTH as usize];
                unsafe {
                    // SAFETY: This function takes a pointer to a crypto_auth_state struct and a
                    // pointer to which the authentication tag will be written. For the first
                    // argument, we pass a crypto_auth_state struct, which is defined using bindgen
                    // to be equivalent to the definition of the equivalent struct in C. The struct
                    // must have been initialised in order to initialise this Multipart wrapper
                    // struct, so it is in the right state to call crypto_auth_final. The tag array
                    // here has been defined to be crypto_auth_BYTES bytes long, so it is of the
                    // correct size to write an auth tag to.
                    $mp_final(&mut self.0, tag.as_mut_ptr());
                }
                tag
            }

            /// Verify the provided tag is correct for the specified message and key.
            ///
            /// Returns an [`AuthError::AuthenticationFailed`](
            /// crate::symmetric::auth::AuthError::AuthenticationFailed) if verification of the
            /// authentication tag failed.
            ///
            /// Equivalent to [`verify`] for single-part messages.
            pub fn verify(mut self, tag: &Tag) -> Result<(), $crate::AlkaliError> {
                let mut actual_tag = [0u8; TAG_LENGTH as usize];
                let verification_result = unsafe {
                    // SAFETY: This function takes a pointer to a crypto_auth_state struct and a
                    // pointer to which the authentication tag will be written. For the first
                    // argument, we pass a crypto_auth_state struct, which is defined using bindgen
                    // to be equivalent to the definition of the equivalent struct in C. The struct
                    // must have been initialised in order to initialise this Multipart wrapper
                    // struct, so it is in the right state to call crypto_auth_final. The
                    // actual_tag array here has been defined to be crypto_auth_BYTES bytes long,
                    // so it is of the correct size to write an auth tag to.
                    $mp_final(&mut self.0, actual_tag.as_mut_ptr());

                    // SAFETY: This function takes two pointers, and a length. The two pointers
                    // will be compared over length bytes for equality. The Tag type here is
                    // defined to be TAG_LENGTH bytes, so both pointers passed to the function
                    // point to TAG_LENGTH bytes of data.
                    libsodium_sys::sodium_memcmp(
                        tag.as_ptr() as *const libc::c_void,
                        actual_tag.as_ptr() as *const libc::c_void,
                        TAG_LENGTH,
                    )
                };

                if verification_result == 0 {
                    Ok(())
                } else {
                    Err($crate::symmetric::auth::AuthError::AuthenticationFailed.into())
                }
            }
        }

        /// Compute the authentication tag for a given message and key.
        ///
        /// Returns an authentication tag, which is non-secret.
        ///
        /// # Security Considerations
        /// **Do not** use this function to *verify* an existing authentication tag for a message
        /// as naïve comparison of authentication tags gives rise to a trivial timing attack.
        /// Instead, use the [`verify`] function.
        pub fn authenticate(message: &[u8], key: &Key) -> Result<Tag, $crate::AlkaliError> {
            $crate::require_init()?;

            let mut tag = [0; TAG_LENGTH as usize];
            unsafe {
                // SAFETY: This function takes a pointer to a buffer where the calculated
                // authentication tag will be written, a pointer to a message to authenticate, the
                // length of the message, and a pointer to the key to use for authentication. We
                // have defined the tag buffer to be crypto_auth_BYTES long, the maximum length of
                // an authentication tag as defined in Sodium. We use message.len() to specify the
                // length of the message to authenticate, so the length provided is correct.
                // Finally, we define the Key type to be crypto_auth_KEYBYTES long, so it is of the
                // expected size for use in this function. The Key::inner method simply provides a
                // pointer to the backing memory.
                $authenticate(
                    tag.as_mut_ptr(),
                    message.as_ptr(),
                    message.len() as libc::c_ulonglong,
                    key.inner() as *const libc::c_uchar,
                );
            }

            Ok(tag)
        }

        /// Verifies that an authentication tag is valid for a given message, using the provided
        /// key.
        ///
        /// Returns an [`AuthError::AuthenticationFailed`](
        /// crate::symmetric::auth::AuthError::AuthenticationFailed) if verification of the
        /// authentication tag failed.
        pub fn verify(message: &[u8], tag: &Tag, key: &Key) -> Result<(), $crate::AlkaliError> {
            $crate::require_init()?;

            let verification_result = unsafe {
                // SAFETY: This function takes a pointer to the tag to be verified, a pointer to
                // the message to authenticate, the length of the message, and a pointer to the key
                // to use for authentication. We have defined the tag buffer to be of the Tag type,
                // which is crypto_auth_BYTES long, the maximum length of an authentication tag as
                // defined in Sodium. We use message.len() to specify the length of the message to
                // authenticate, so the length provided is correct. Finally, we define the Key type
                // to be crypto_auth_KEYBYTES long, so it is of the expected size for use in this
                // function. The Key::inner method simply provides a pointer to the backing memory.
                $verify(
                    tag.as_ptr(),
                    message.as_ptr(),
                    message.len() as libc::c_ulonglong,
                    key.inner() as *const libc::c_uchar,
                )
            };

            if verification_result == 0 {
                Ok(())
            } else {
                Err($crate::symmetric::auth::AuthError::AuthenticationFailed.into())
            }
        }
    };
}

/// Generates tests for an `auth` implementation. Takes `message => key => tag;` as arguments,
/// which are test vectors to be run (tag should be the expected auth tag for message under key).
#[allow(unused_macros)]
macro_rules! auth_tests {
    ( $( $msg:expr => $key:expr => $tag:expr; )* ) => {
        use super::{authenticate, verify, Key};
        use $crate::random::fill_random;
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
                assert_eq!(&actual_tag, &$tag);

                verify(&$msg, &$tag, &key)?;
            )*

            Ok(())
        }

        // TODO: Testing for multi-part authentication
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
        auth_tests! {
            []
                => [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                    0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a,
                    0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20]
                => [0x2e, 0xe8, 0x66, 0x81, 0x5c, 0x14, 0x65, 0xe4, 0x00, 0xf1, 0x9f, 0x5d, 0xb9,
                    0x06, 0x44, 0x35, 0x53, 0x73, 0xa3, 0x94, 0x13, 0x2e, 0x3e, 0xca, 0x6d, 0xa1,
                    0x63, 0x11, 0x8f, 0x8e, 0x63, 0x57];

            [0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
             0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
             0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
             0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd]
                => [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                    0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a,
                    0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20]
                => [0x79, 0x18, 0x7c, 0xac, 0xd8, 0x64, 0xc1, 0x32, 0x51, 0x3e, 0xa8, 0x9d, 0xc3,
                    0x69, 0xd3, 0x02, 0x0e, 0x8e, 0x74, 0x52, 0x05, 0xdf, 0xfb, 0xd3, 0x66, 0xf2,
                    0xf9, 0xbc, 0xdd, 0x50, 0xd3, 0xe7];

            [0x41, 0x6e, 0x6f, 0x74, 0x68, 0x65, 0x72, 0x20, 0x6f, 0x6e, 0x65, 0x20, 0x67, 0x6f,
             0x74, 0x20, 0x63, 0x61, 0x75, 0x67, 0x68, 0x74, 0x20, 0x74, 0x6f, 0x64, 0x61, 0x79,
             0x2c, 0x20, 0x69, 0x74, 0x27, 0x73, 0x20, 0x61, 0x6c, 0x6c, 0x20, 0x6f, 0x76, 0x65,
             0x72, 0x20, 0x74, 0x68, 0x65, 0x20, 0x70, 0x61, 0x70, 0x65, 0x72, 0x73, 0x2e, 0x20,
             0x22, 0x54, 0x65, 0x65, 0x6e, 0x61, 0x67, 0x65, 0x72, 0x20, 0x41, 0x72, 0x72, 0x65,
             0x73, 0x74, 0x65, 0x64, 0x20, 0x69, 0x6e, 0x20, 0x43, 0x6f, 0x6d, 0x70, 0x75, 0x74,
             0x65, 0x72, 0x20, 0x43, 0x72, 0x69, 0x6d, 0x65, 0x20, 0x53, 0x63, 0x61, 0x6e, 0x64,
             0x61, 0x6c, 0x22, 0x2c, 0x20, 0x22, 0x48, 0x61, 0x63, 0x6b, 0x65, 0x72, 0x20, 0x41,
             0x72, 0x72, 0x65, 0x73, 0x74, 0x65, 0x64, 0x20, 0x61, 0x66, 0x74, 0x65, 0x72, 0x20,
             0x42, 0x61, 0x6e, 0x6b, 0x20, 0x54, 0x61, 0x6d, 0x70, 0x65, 0x72, 0x69, 0x6e, 0x67,
             0x22, 0x2e, 0x2e, 0x2e, 0x20, 0x44, 0x61, 0x6d, 0x6e, 0x20, 0x6b, 0x69, 0x64, 0x73,
             0x2e, 0x20, 0x54, 0x68, 0x65, 0x79, 0x27, 0x72, 0x65, 0x20, 0x61, 0x6c, 0x6c, 0x20,
             0x61, 0x6c, 0x69, 0x6b, 0x65, 0x2e]
                => [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                    0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a,
                    0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20]
                => [0x45, 0x4b, 0x4f, 0xfa, 0xbc, 0x4d, 0x83, 0x97, 0xc7, 0x82, 0xcd, 0x60, 0x28,
                    0x36, 0xe1, 0x41, 0xde, 0x07, 0x9c, 0x61, 0x24, 0x04, 0xb6, 0x96, 0xca, 0x20,
                    0x17, 0x05, 0xe9, 0x46, 0x57, 0x9f];
        }
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
            []
                => [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                    0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a,
                    0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20]
                => [0x46, 0x24, 0x76, 0xa8, 0x97, 0xdd, 0xfd, 0xbd, 0x40, 0xd1, 0x42, 0x0e, 0x08,
                    0xa5, 0xbc, 0xfe, 0xeb, 0x25, 0xc3, 0xe2, 0xad, 0xe6, 0xa0, 0xa9, 0x08, 0x3b,
                    0x32, 0x7b, 0x9e, 0xf9, 0xfc, 0xa1];

            [0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
             0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
             0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
             0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd]
                => [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                    0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a,
                    0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20]
                => [0x37, 0x2e, 0xfc, 0xf9, 0xb4, 0x0b, 0x35, 0xc2, 0x11, 0x5b, 0x13, 0x46, 0x90,
                    0x3d, 0x2e, 0xf4, 0x2f, 0xce, 0xd4, 0x6f, 0x08, 0x46, 0xe7, 0x25, 0x7b, 0xb1,
                    0x56, 0xd3, 0xd7, 0xb3, 0x0d, 0x3f];

            [0x41, 0x6e, 0x6f, 0x74, 0x68, 0x65, 0x72, 0x20, 0x6f, 0x6e, 0x65, 0x20, 0x67, 0x6f,
             0x74, 0x20, 0x63, 0x61, 0x75, 0x67, 0x68, 0x74, 0x20, 0x74, 0x6f, 0x64, 0x61, 0x79,
             0x2c, 0x20, 0x69, 0x74, 0x27, 0x73, 0x20, 0x61, 0x6c, 0x6c, 0x20, 0x6f, 0x76, 0x65,
             0x72, 0x20, 0x74, 0x68, 0x65, 0x20, 0x70, 0x61, 0x70, 0x65, 0x72, 0x73, 0x2e, 0x20,
             0x22, 0x54, 0x65, 0x65, 0x6e, 0x61, 0x67, 0x65, 0x72, 0x20, 0x41, 0x72, 0x72, 0x65,
             0x73, 0x74, 0x65, 0x64, 0x20, 0x69, 0x6e, 0x20, 0x43, 0x6f, 0x6d, 0x70, 0x75, 0x74,
             0x65, 0x72, 0x20, 0x43, 0x72, 0x69, 0x6d, 0x65, 0x20, 0x53, 0x63, 0x61, 0x6e, 0x64,
             0x61, 0x6c, 0x22, 0x2c, 0x20, 0x22, 0x48, 0x61, 0x63, 0x6b, 0x65, 0x72, 0x20, 0x41,
             0x72, 0x72, 0x65, 0x73, 0x74, 0x65, 0x64, 0x20, 0x61, 0x66, 0x74, 0x65, 0x72, 0x20,
             0x42, 0x61, 0x6e, 0x6b, 0x20, 0x54, 0x61, 0x6d, 0x70, 0x65, 0x72, 0x69, 0x6e, 0x67,
             0x22, 0x2e, 0x2e, 0x2e, 0x20, 0x44, 0x61, 0x6d, 0x6e, 0x20, 0x6b, 0x69, 0x64, 0x73,
             0x2e, 0x20, 0x54, 0x68, 0x65, 0x79, 0x27, 0x72, 0x65, 0x20, 0x61, 0x6c, 0x6c, 0x20,
             0x61, 0x6c, 0x69, 0x6b, 0x65, 0x2e]
                => [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                    0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a,
                    0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20]
                => [0xf5, 0x59, 0xbd, 0x27, 0xe1, 0x7f, 0x8f, 0x8f, 0xa2, 0x58, 0x8b, 0x7a, 0x1a,
                    0xe0, 0x70, 0x8a, 0x8b, 0xdf, 0x68, 0xb3, 0xb0, 0x90, 0x8c, 0xea, 0x87, 0xec,
                    0x93, 0xb9, 0x77, 0x38, 0x69, 0xb4];
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
            []
                => [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                    0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a,
                    0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20]
                => [0x2e, 0xe8, 0x66, 0x81, 0x5c, 0x14, 0x65, 0xe4, 0x00, 0xf1, 0x9f, 0x5d, 0xb9,
                    0x06, 0x44, 0x35, 0x53, 0x73, 0xa3, 0x94, 0x13, 0x2e, 0x3e, 0xca, 0x6d, 0xa1,
                    0x63, 0x11, 0x8f, 0x8e, 0x63, 0x57, 0xd4, 0x8c, 0x62, 0x31, 0xe5, 0xd0, 0xee,
                    0xd1, 0x1e, 0x2b, 0xed, 0x7d, 0x60, 0x3a, 0xc1, 0x1b, 0x80, 0x24, 0x14, 0x96,
                    0x90, 0xe9, 0x0b, 0x30, 0x3b, 0xda, 0xf0, 0x05, 0x51, 0x72, 0xd6, 0x00];

            [0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
             0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
             0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
             0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd]
                => [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                    0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a,
                    0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20]
                => [0x79, 0x18, 0x7c, 0xac, 0xd8, 0x64, 0xc1, 0x32, 0x51, 0x3e, 0xa8, 0x9d, 0xc3,
                    0x69, 0xd3, 0x02, 0x0e, 0x8e, 0x74, 0x52, 0x05, 0xdf, 0xfb, 0xd3, 0x66, 0xf2,
                    0xf9, 0xbc, 0xdd, 0x50, 0xd3, 0xe7, 0x02, 0xa7, 0x43, 0x3a, 0xe0, 0x2e, 0x2f,
                    0xfd, 0xe7, 0x37, 0x56, 0xcb, 0xbc, 0xca, 0x2b, 0x0a, 0x18, 0xa0, 0x9b, 0x0a,
                    0x6e, 0xb5, 0x30, 0x05, 0x13, 0x19, 0x27, 0xba, 0xf7, 0xc4, 0x83, 0x54];

            [0x41, 0x6e, 0x6f, 0x74, 0x68, 0x65, 0x72, 0x20, 0x6f, 0x6e, 0x65, 0x20, 0x67, 0x6f,
             0x74, 0x20, 0x63, 0x61, 0x75, 0x67, 0x68, 0x74, 0x20, 0x74, 0x6f, 0x64, 0x61, 0x79,
             0x2c, 0x20, 0x69, 0x74, 0x27, 0x73, 0x20, 0x61, 0x6c, 0x6c, 0x20, 0x6f, 0x76, 0x65,
             0x72, 0x20, 0x74, 0x68, 0x65, 0x20, 0x70, 0x61, 0x70, 0x65, 0x72, 0x73, 0x2e, 0x20,
             0x22, 0x54, 0x65, 0x65, 0x6e, 0x61, 0x67, 0x65, 0x72, 0x20, 0x41, 0x72, 0x72, 0x65,
             0x73, 0x74, 0x65, 0x64, 0x20, 0x69, 0x6e, 0x20, 0x43, 0x6f, 0x6d, 0x70, 0x75, 0x74,
             0x65, 0x72, 0x20, 0x43, 0x72, 0x69, 0x6d, 0x65, 0x20, 0x53, 0x63, 0x61, 0x6e, 0x64,
             0x61, 0x6c, 0x22, 0x2c, 0x20, 0x22, 0x48, 0x61, 0x63, 0x6b, 0x65, 0x72, 0x20, 0x41,
             0x72, 0x72, 0x65, 0x73, 0x74, 0x65, 0x64, 0x20, 0x61, 0x66, 0x74, 0x65, 0x72, 0x20,
             0x42, 0x61, 0x6e, 0x6b, 0x20, 0x54, 0x61, 0x6d, 0x70, 0x65, 0x72, 0x69, 0x6e, 0x67,
             0x22, 0x2e, 0x2e, 0x2e, 0x20, 0x44, 0x61, 0x6d, 0x6e, 0x20, 0x6b, 0x69, 0x64, 0x73,
             0x2e, 0x20, 0x54, 0x68, 0x65, 0x79, 0x27, 0x72, 0x65, 0x20, 0x61, 0x6c, 0x6c, 0x20,
             0x61, 0x6c, 0x69, 0x6b, 0x65, 0x2e]
                => [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                    0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a,
                    0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20]
                => [0x45, 0x4b, 0x4f, 0xfa, 0xbc, 0x4d, 0x83, 0x97, 0xc7, 0x82, 0xcd, 0x60, 0x28,
                    0x36, 0xe1, 0x41, 0xde, 0x07, 0x9c, 0x61, 0x24, 0x04, 0xb6, 0x96, 0xca, 0x20,
                    0x17, 0x05, 0xe9, 0x46, 0x57, 0x9f, 0x59, 0xdf, 0x10, 0xa1, 0x15, 0xd8, 0xdb,
                    0x09, 0x07, 0x9f, 0x7e, 0x25, 0xba, 0x2b, 0x22, 0x66, 0x49, 0xac, 0xd8, 0x66,
                    0x78, 0x0f, 0xcb, 0x80, 0x33, 0xa3, 0xce, 0xa1, 0xe6, 0x9d, 0xf5, 0x8d];
        }
    }
}

pub use hmacsha512256::*;
