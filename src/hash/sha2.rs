//! The [SHA-2](https://en.wikipedia.org/wiki/SHA-2) family of hash functions.
//!
//! This module corresponds to the [`crypto_hash`
//! API](https://doc.libsodium.org/advanced/sha-2_hash_function) from Sodium.
//!
//! This API is provided for interoperability with older versions of Sodium. For newer
//! applications, if you need a generic hash function like SHA, the
//! [`hash::generic`](crate::hash::generic) API should be preferred over using SHA-2. It is faster
//! and not vulnerable to length extension attacks.
//!
//! This generic hash function can be used in cases such as file integrity checking or generating
//! unique identifiers to index arbitrarily-long data. Please note that the [`hash`](super) module
//! has a number of alternative members which are better suited to certain tasks: For example, the
//! [`hash::pbkdf`](crate::hash::pbkdf) module should be used for password hashing, and the
//! [`hash::short`](crate::hash::short) module is better suited to the construction of hash
//! tables/bloom filters.
//!
//! # Algorithm Details
//! [SHA-512](sha512) is the default algorithm exposed in this API. [SHA-256](sha256) is also
//! available.
//!
//! # Security Considerations
//! Generic hash functions such as SHA-2 *must not* be used for password hashing, they are not
//! sufficiently computationally intensive. Instead, use a [Password-Based Key Derivation
//! Function](https://en.wikipedia.org/wiki/Key_derivation_function#Password_hashing) (PBKDF) such
//! as those available in the [`hash::pbkdf`](crate::hash::pbkdf) module.
//!
//! SHA-2 is vulnerable to [length extension
//! attacks](https://en.wikipedia.org/wiki/Length_extension_attack) if a truncated version is not
//! used. For this reason (as well as speed improvements), the
//! [`hash::generic`](crate::hash::generic) API should be preferred if possible.
//!
//! # Examples
//! Single-part hashing (using [`hash`]):
//!
//! ```rust
//! use alkali::hash::sha2;
//!
//! let message = b"Here's some message we wish to hash :)";
//! let hash = sha2::hash(message).unwrap();
//! assert_eq!(
//!     hash,
//!     [
//!         0xb7, 0xee, 0x33, 0x80, 0x83, 0xf0, 0x41, 0x65, 0xc1, 0xff, 0xfb, 0xb2, 0x14, 0x6f,
//!         0x18, 0x8b, 0x9c, 0x01, 0x31, 0xd3, 0x0e, 0x7c, 0x45, 0x36, 0xbe, 0xb3, 0x4a, 0x1d,
//!         0xb0, 0x2d, 0x86, 0x9d, 0x87, 0x1a, 0x1c, 0x84, 0xd7, 0x9b, 0x9d, 0xe3, 0x15, 0xc3,
//!         0xb4, 0x2d, 0x9a, 0xb9, 0x54, 0x25, 0x7a, 0xf9, 0x06, 0x28, 0x66, 0x8d, 0x9a, 0xa5,
//!         0x31, 0x45, 0x19, 0xbc, 0x4c, 0x2f, 0xcb, 0xa4
//!     ]
//! );
//! ```
//!
//! Multi-part hashing (using [`Multipart`]):
//!
//! ```rust
//! use alkali::hash::sha2;
//!
//! let mut state_a = sha2::Multipart::new().unwrap();
//! state_a.update(b"Here's the first part");
//! state_a.update(b"... And the second!");
//! let hash_a = state_a.calculate();
//!
//! let mut state_b = sha2::Multipart::new().unwrap();
//! state_b.update(b"Here");
//! state_b.update(b"'s the first ");
//! state_b.update(b"part... And the ");
//! state_b.update(b"second!");
//! let hash_b = state_b.calculate();
//!
//! assert_eq!(hash_a, hash_b);
//! ```

/// Generates the API for a `sha2` module with the given functions from Sodium for a specific
/// implementation.
macro_rules! sha2_module {
    (
        $digest_len:expr,   // crypto_hash_BYTES
        $hash:path,         // crypto_hash
        $mp_state:ty,       // crypto_hash_state
        $mp_init:path,      // crypto_hash_init
        $mp_update:path,    // crypto_hash_update
        $mp_final:path,     // crypto_hash_final
    ) => {
        use $crate::{assert_not_err, mem, require_init, unexpected_err, AlkaliError};

        /// The length of the output of this hash function, in bytes.
        pub const DIGEST_LENGTH: usize = $digest_len as usize;

        /// Stores the digest ("fingerprint") of a message calculated using this hash function.
        pub type Digest = [u8; DIGEST_LENGTH];

        /// Streaming hash API, for long/multi-part message hashing.
        ///
        /// This can be used to calculate the hash of a message which is too large to fit into
        /// memory, or where the message is received in portions.
        ///
        /// This struct uses heap memory while in scope, allocated using Sodium's [secure memory
        /// utilities](https://doc.libsodium.org/memory_management).
        pub struct Multipart {
            state: core::ptr::NonNull<$mp_state>,
            _marker: core::marker::PhantomData<$mp_state>,
        }

        impl Multipart {
            /// Create a new instance of the struct.
            pub fn new() -> Result<Self, AlkaliError> {
                require_init()?;

                let mut state = unsafe {
                    // SAFETY: This call to malloc() will allocate the memory required for a
                    // `crypto_hash_state` type, outside of Rust's memory management. The
                    // associated memory is always freed in the corresponding `drop` call for the
                    // Multipart struct, unless initialisation fails, in which case it is freed
                    // before `Multipart::new` returns, and not used again. We never free the memory
                    // in any other place in this struct, and drop can only be called once, so a
                    // double-free is not possible. We never expose a pointer to the allocated
                    // memory directly. See the drop implementation for more reasoning on safety.
                    mem::malloc()?
                };

                let init_result = unsafe {
                    // SAFETY: This function initialises a `crypto_hash_state` struct. It expects a
                    // pointer to a region of memory sufficient to store such a struct. We pass a
                    // region of memory sufficient to store the struct, allocated above. The type of
                    // `state` is a `NonNull` pointer, and the unsafe block above will return early
                    // if allocation failed, so this pointer is valid to use here. Sodium's
                    // documentation specifies that after this function is called, if the return
                    // value indicates success, then the memory pointed to by `state` is correctly
                    // initialised, and is a valid representation of a `crypto_hash_state` struct
                    // which can be used with other functions from Sodium.
                    $mp_init(state.as_mut())
                };

                // This return value is not possible in the current implementation of
                // `crypto_hash_init` in Sodium, but could be in the future.
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
            /// current one, so any data written to be hashed in the current struct will also be
            /// used in the digest calculation for the new struct.
            pub fn try_clone(&self) -> Result<Self, AlkaliError> {
                // We do not use `require_init` here, as it must be called to initialise a
                // `Multipart` struct.

                let state = unsafe {
                    // SAFETY: This call to malloc() will allocate the memory required for a
                    // `crypto_hash_state` type, outside of Rust's memory management. The
                    // associated memory is always freed in the corresponding `drop` call for the
                    // Multipart struct and not used again. We never free the memory in any other
                    // place in this struct, and drop can only be called once, so a double-free is
                    // not possible. We never expose a pointer to the allocated memory directly. See
                    // the drop implementation for more reasoning on safety.
                    let mut state = mem::malloc()?;

                    // SAFETY: We have called `malloc` to allocate sufficient space for one
                    // `crypto_hash_state` struct at each of the two pointers used here:
                    // `self.state` was allocated in a call to `Self::new`, and `state` was
                    // allocated above, so both are valid for reads/writes of
                    // `size_of::<crypto_hash_state>` bytes. We have just allocated a fresh region
                    // of memory for `state`, so it definitely doesn't overlap with `self.state`. To
                    // initialise an instance of `Self`, `self.state` must be a valid representation
                    // of a `crypto_hash_state` struct. No methods within `Self` would cause
                    // `self.state` to point to an invalid representation of a `crypto_hash_state`
                    // struct. Therefore, after the copy, `state` must also point to a valid
                    // representation of a `crypto_hash_state` struct, and can be used with the SHA2
                    // functions from Sodium.
                    core::ptr::copy_nonoverlapping(self.state.as_ptr(), state.as_mut(), 1);

                    state
                };

                Ok(Self {
                    state,
                    _marker: core::marker::PhantomData,
                })
            }

            /// Add message contents to hash.
            pub fn update(&mut self, chunk: &[u8]) {
                // We do not use `require_init` here, as it must be called to initialise a
                // `Multipart` struct.

                let update_result = unsafe {
                    // SAFETY: The first argument to this function is a pointer to a
                    // `crypto_hash_state` struct. The `Multipart::new` method ensures that the
                    // `self.state` pointer is correctly initialised and points to a valid
                    // representation of a `crypto_hash_state` struct. Therefore, it is correct to
                    // use it with this function. The next two arguments specify the chunk of data
                    // to add to the hash calculation and its length. We use `chunk.len()` to
                    // specify the number of bytes to read from `chunk`, so the pointer is
                    // definitely valid for reads of this length.
                    $mp_update(
                        self.state.as_mut(),
                        chunk.as_ptr(),
                        chunk.len() as libc::c_ulonglong,
                    )
                };

                assert_not_err!(update_result, stringify!($mp_update));
            }

            /// Finalise the hash state, returning the digest.
            ///
            /// This method is not marked public since we want to use the type system to ensure the
            /// `Multipart` struct cannot be used again after being finalised.
            fn finalise(&mut self) -> Digest {
                // We do not use `require_init` here, as it must be called to initialise a
                // `Multipart` struct.

                let mut digest = [0u8; DIGEST_LENGTH];

                let finalise_result = unsafe {
                    // SAFETY: The first argument to this function is a pointer to a
                    // `crypto_hash_state` struct. The `Multipart::new` method ensures that the
                    // `self.state` pointer is correctly initialised and points to a valid
                    // representation of a `crypto_hash_state` struct. Therefore, it is correct to
                    // use it with this function. The other argument specifies the destination to
                    // which the digest will be written. The `digest` array is defined to be
                    // `crypto_hash_BYTES`, the length of a digest for this algorithm, so it is
                    // valid for writes of the required length.
                    $mp_final(self.state.as_mut(), digest.as_mut_ptr())
                };
                assert_not_err!(finalise_result, stringify!($mp_final));

                digest
            }

            /// Calculate the hash of the concatenated message contents.
            pub fn calculate(mut self) -> Digest {
                self.finalise()
            }

            /// Compare the hash of the specified message to another hash, returning `true` if the
            /// message hashes to the given value, and `false` otherwise.
            ///
            /// `digest` is the hash against which the message will be compared.
            ///
            /// This comparison runs in constant time.
            pub fn compare(mut self, digest: &Digest) -> bool {
                let actual_digest = self.finalise();
                mem::eq(digest, &actual_digest).unwrap()
            }
        }

        impl Drop for Multipart {
            fn drop(&mut self) {
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

        /// Calculate the hash of the provided message.
        ///
        /// This function returns the hash of the given message. The same message will always
        /// produce the same hash.
        pub fn hash(message: &[u8]) -> Result<Digest, AlkaliError> {
            require_init()?;

            let mut digest = [0u8; DIGEST_LENGTH];

            let hash_result = unsafe {
                // SAFETY: The first argument to this function specifies the location to which the
                // output of the hash function should be written. We have defined the `digest`
                // array to be `crypto_hash_BYTES` bytes long, the length of a digest for this
                // algorithm, so it is valid for writes of the required length. The next two
                // parameters specify the message to hash and its length. We use `message.len()` to
                // specify the length, so the `message` slice is definitely valid for reads of this
                // length.
                $hash(
                    digest.as_mut_ptr(),
                    message.as_ptr(),
                    message.len() as libc::c_ulonglong,
                )
            };
            assert_not_err!(hash_result, stringify!($hash));

            Ok(digest)
        }
    };
}

/// Generates tests for a `sha2` implementation.
#[allow(unused_macros)]
macro_rules! sha2_tests {
    ( $( {
        msg: $msg:expr,
        out: $out:expr,
    }, )* ) => {
        use $crate::{AlkaliError, random};
        use super::{hash, Multipart};

        #[test]
        fn single_part_test_vectors() -> Result<(), AlkaliError> {
            $(
                let digest = hash($msg)?;
                assert_eq!(digest, $out);
            )*

            Ok(())
        }

        #[test]
        fn multi_part_test_vectors() -> Result<(), AlkaliError> {
                $(
                    let mut state = Multipart::new()?;
                    state.update($msg);
                    let state_b = state.try_clone()?;
                    assert!(state_b.compare(&$out));
                    let digest = state.calculate();
                    assert_eq!(digest, $out);
                )*

            for _ in 0..1000 {
                $(
                    let mut state = Multipart::new()?;
                    let boundary = random::random_u32_in_range(0, $msg.len() as u32)? as usize;
                    state.update(&$msg[..boundary]);
                    state.update(&$msg[boundary..]);
                    let state_b = state.try_clone()?;
                    assert!(state_b.compare(&$out));
                    let digest = state.calculate();
                    assert_eq!(digest, $out);
                )*

                $(
                    let mut state = Multipart::new()?;
                    let boundary_a = random::random_u32_in_range(0, $msg.len() as u32)? as usize;
                    let boundary_b =
                        random::random_u32_in_range(boundary_a as u32, $msg.len() as u32)? as usize;
                    state.update(&$msg[..boundary_a]);
                    state.update(&$msg[boundary_a..boundary_b]);
                    state.update(&$msg[boundary_b..]);
                    let state_b = state.try_clone()?;
                    assert!(state_b.compare(&$out));
                    let digest = state.calculate();
                    assert_eq!(digest, $out);
                )*
            }

            Ok(())
        }
    };
}

/// The SHA-256 hash function.
pub mod sha256 {
    use libsodium_sys as sodium;

    sha2_module!(
        sodium::crypto_hash_sha256_BYTES,
        sodium::crypto_hash_sha256,
        sodium::crypto_hash_sha256_state,
        sodium::crypto_hash_sha256_init,
        sodium::crypto_hash_sha256_update,
        sodium::crypto_hash_sha256_final,
    );

    #[cfg(test)]
    mod tests {
        sha2_tests! [
            {
                msg: b"testing\n",
                out: [0x12, 0xa6, 0x1f, 0x4e, 0x17, 0x3f, 0xb3, 0xa1, 0x1c, 0x05, 0xd6, 0x47, 0x1f,
                      0x74, 0x72, 0x8f, 0x76, 0x23, 0x1b, 0x4a, 0x5f, 0xcd, 0x96, 0x67, 0xce, 0xf3,
                      0xaf, 0x87, 0xa3, 0xae, 0x4d, 0xc2],
            },
            {
                msg: b"The Conscience of a Hacker is a small essay written January 8, 1986 by a \
                       computer security hacker who went by the handle of The Mentor, who \
                       belonged to the 2nd generation of Legion of Doom.",
                out: [0x71, 0xcc, 0x81, 0x23, 0xfe, 0xf8, 0xc2, 0x36, 0xe4, 0x51, 0xd3, 0xc3, 0xdd,
                      0xf1, 0xad, 0xae, 0x9a, 0xa6, 0xcd, 0x95, 0x21, 0xe7, 0x04, 0x17, 0x69, 0xd7,
                      0x37, 0x02, 0x49, 0x00, 0xa0, 0x3a],
            },
        ];
    }
}

/// The SHA-512 hash function.
pub mod sha512 {
    use libsodium_sys as sodium;

    sha2_module!(
        sodium::crypto_hash_sha512_BYTES,
        sodium::crypto_hash_sha512,
        sodium::crypto_hash_sha512_state,
        sodium::crypto_hash_sha512_init,
        sodium::crypto_hash_sha512_update,
        sodium::crypto_hash_sha512_final,
    );

    #[cfg(test)]
    mod tests {
        sha2_tests! [
            {
                msg: b"testing\n",
                out: [0x24, 0xf9, 0x50, 0xaa, 0xc7, 0xb9, 0xea, 0x9b, 0x3c, 0xb7, 0x28, 0x22, 0x8a,
                      0x0c, 0x82, 0xb6, 0x7c, 0x39, 0xe9, 0x6b, 0x4b, 0x34, 0x47, 0x98, 0x87, 0x0d,
                      0x5d, 0xae, 0xe9, 0x3e, 0x3a, 0xe5, 0x93, 0x1b, 0xaa, 0xe8, 0xc7, 0xca, 0xcf,
                      0xea, 0x4b, 0x62, 0x94, 0x52, 0xc3, 0x80, 0x26, 0xa8, 0x1d, 0x13, 0x8b, 0xc7,
                      0xaa, 0xd1, 0xaf, 0x3e, 0xf7, 0xbf, 0xd5, 0xec, 0x64, 0x6d, 0x6c, 0x28],
            },
            {
                msg: b"The Conscience of a Hacker is a small essay written January 8, 1986 by a \
                       computer security hacker who went by the handle of The Mentor, who \
                       belonged to the 2nd generation of Legion of Doom.",
                out: [0xa7, 0x7a, 0xbe, 0x1c, 0xcf, 0x8f, 0x54, 0x97, 0xe2, 0x28, 0xfb, 0xc0, 0xac,
                      0xd7, 0x3a, 0x52, 0x1e, 0xde, 0xdb, 0x21, 0xb8, 0x97, 0x26, 0x68, 0x4a, 0x6e,
                      0xbb, 0xc3, 0xba, 0xa3, 0x23, 0x61, 0xac, 0xa5, 0xa2, 0x44, 0xda, 0xa8, 0x4f,
                      0x24, 0xbf, 0x19, 0xc6, 0x8b, 0xaf, 0x78, 0xe6, 0x90, 0x76, 0x25, 0xa6, 0x59,
                      0xb1, 0x54, 0x79, 0xeb, 0x7b, 0xd4, 0x26, 0xfc, 0x62, 0xaa, 0xfa, 0x73],
            },
        ];
    }
}

pub use sha512::*;
