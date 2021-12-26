//! **Please note**: This is currently a work-in-progress, and isn't yet complete, nor is it
//! suitable for production usage.
//!
//! Safe, idiomatic Rust bindings to the [Sodium](https://libsodium.org) cryptographic library.
//!
//! Sodium is a fast, modern cryptographic library written in C. This crate intends to provide a
//! higher-level API for making use of the constructs Sodium provides. These constructs include
//! simple-to-use symmetric and asymmetric AEAD, signatures, hashing, password derivation, and key
//! exchange: In short, the majority of operations required for most modern cryptographic
//! protocols.
//!
//! The intention for this library is to be a spiritual successor to
//! [sodiumoxide](https://github.com/sodiumoxide/sodiumoxide), which is now deprecated. Lots of
//! design decisions here were inspired by this library, so thanks to all of its contributors!
//!
//! # Which API Should I Use?
//! The cryptographic operations in this crate are mostly split into two main modules:
//! [`symmetric`] and [`asymmetric`]. Symmetric (sometimes called secret-key) operations use a
//! single secret key, shared between every party to a communication. In asymmetric (public-key)
//! operations, every party has its own secret key, which is used to derive a public-key, which is
//! shared with all other parties. Parties need to know each others' public keys to communicate.
//!
//! There are also hashing algorithms available in the [`hash`] module, and tools for
//! cryptographically-secure pseudo-random number generation in the [`random`] module.
//!
//! I want to...
//! * Produce a signature for a message, so that anyone can verify I sent it
//!     * Use [`asymmetric::sign`]
//! * Produce an authentication tag for a message, so that specific trusted parties, with whom I
//!   already share a secret key, can verify I sent it
//!     * Use [`symmetric::auth`]
//! * Store a user's password so I can verify their identity on next login
//!     * Use [`hash::pwhash`]
//! * Derive a key from a low-entropy input (i.e: a password)
//!     * Use [`hash::pwhash`]
//! * Establish a secret key with another party over an insecure channel
//!     * Use [`asymmetric::kx`]
//! * Generate cryptographically secure pseudo-random data
//!     * Use [`random`]
//!
//! # Hardened Buffer Types
//! Throughout this crate, a number of types used to store secret data (keys, seeds, etc.) use a
//! custom allocator from Sodium to manage their memory. These types have a number of protections
//! intended to prevent leakage of their contents. They are stored in memory locked regions, which
//! won't be swapped to disk, and will be securely zeroed on drop. Measures are also taken (guard
//! pages, canaries) to detect buffer overflows.
//!
//! In the future, we should be able to use the [Allocator
//! API](https://doc.rust-lang.org/std/alloc/trait.Allocator.html) to simplify these types, but for
//! the time being, we have to do a fair amount of manual memory management under the hood to
//! enable them to work. Regardless, these implementation details do not require you to do anything
//! differently yourself.

use libsodium_sys as sodium;
use thiserror::Error;

pub mod asymmetric;
pub mod hash;
mod mem;
pub mod random;
pub mod symmetric;
pub mod util;

/// General error type used in alkali.
///
/// This type is returned by functions which can possibly fail throughout alkali.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum AlkaliError {
    /// Failed to initialise Sodium.
    ///
    /// This corresponds to a call to `sodium_init` returning -1, indicating initialisation
    /// failure. In such a case, Sodium is unsafe to use.
    #[error("failed to initialise libsodium")]
    SodiumInitFailed,

    /// Memory management error.
    ///
    /// This could indicate a number of possible issues. In the worst case, it indicates a buffer
    /// overflow or similar error occurred and was detected by Sodium, but it could also indicate
    /// any other reason secure memory allocation may fail.
    #[error("memory management error")]
    MemoryManagement,

    /// Tried to create a hardened buffer from an incorrectly sized slice.
    ///
    /// The 0th item is the expected length, the 1st item is the actual length of the slice.
    #[error("incorrect slice length: expected {0}, found {1}")]
    IncorrectSliceLength(usize, usize),

    /// An error occurred in the [`asymmetric::kx`] module.
    #[error("key exchange error")]
    KeyExchangeError(#[from] asymmetric::kx::KeyExchangeError),

    /// An error occurred in the [`asymmetric::sign`] module.
    #[error("signing error")]
    SignError(#[from] asymmetric::sign::SignError),

    #[error("PBKDF error")]
    PasswordHashError(#[from] hash::pwhash::PasswordHashError),

    /// An error occurred in the [`random`] module.
    #[error("PRNG error")]
    RandomError(#[from] random::RandomError),

    /// An error occurred in the [`symmetric::auth`] module.
    #[error("authentication error")]
    AuthError(#[from] symmetric::auth::AuthError),
}

/// Creates a hardened buffer type, for storing sensitive data (keys, passwords, etc).
macro_rules! hardened_buffer {
    ( $( $(#[$metadata:meta])* $name:ident($size:expr)$(;)? )* ) => {
        $(
            $(#[$metadata])*
            pub struct $name(std::ptr::NonNull<[u8; $size]>);

            impl $name {
                pub const LENGTH: usize = $size as usize;

                /// Create a new instance of this type, filled with all zeroes.
                pub fn new_empty() -> Result<Self, $crate::AlkaliError> {
                    $crate::require_init()?;

                    unsafe {
                        // SAFETY: This call to malloc() will allocate the memory required for a
                        // [u8; $size] type, outside of Rust's memory management. The associated
                        // memory is always freed in the corresponding `drop` call. We never free
                        // the memory in any other place in this struct, and drop can only be
                        // called once, so a double-free is not possible. We never give out a
                        // pointer to the allocated memory directly, only references. The region of
                        // memory allocated will always be a valid representation of a [u8; $size].
                        // The alignment for a u8 is just 1 byte, so we don't need to worry about
                        // alignment issues. See the drop implementation for more reasoning on
                        // safety.
                        let ptr = $crate::mem::malloc()?;
                        $crate::mem::memzero(ptr)?;
                        Ok(Self(ptr))
                    }
                }

                /// Safely zero the contents of the buffer, in such a way that the compiler will
                /// not optimise away the operation.
                pub fn zero(&mut self) -> Result<(), $crate::AlkaliError> {
                    $crate::require_init()?;

                    unsafe {
                        // SAFETY: While this struct is in scope, the memory backing it is
                        // allocated and writeable, so we can safely write zeros to it. All zeroes
                        // is a valid representation of a u8 array.
                        $crate::mem::memzero(self.0)
                    }
                }

                /// Create a new instance of the same type, copying the contents of this buffer.
                ///
                /// This operation may fail, as Sodium's allocator is more likely to encounter
                /// issues than the standard system allocator.
                pub fn try_clone(&self) -> Result<Self, $crate::AlkaliError> {
                    let mut new_buf = Self::new_empty()?;
                    new_buf.copy_from_slice(self.as_ref());
                    Ok(new_buf)
                }

                /// Returns a raw constant pointer to the memory backing this type.
                ///
                /// # Safety
                /// This function is only used internally. This struct assumes that the memory will
                /// remain valid until it is dropped, so anywhere this method is used, the memory
                /// must not be freed. Furthermore, the memory is only valid for the lifetime of
                /// this struct, so after it is dropped, this pointer must not be used again.
                #[allow(dead_code)]
                unsafe fn inner(&self) -> *const [u8; $size] {
                    self.0.as_ptr()
                }

                /// Returns a raw mutable pointer to the memory backing this type.
                ///
                /// # Safety
                /// This function is only used internally. This struct assumes that the memory will
                /// remain valid until it is dropped, so anywhere this method is used, the memory
                /// must not be freed. Furthermore, the memory is only valid for the lifetime of
                /// this struct, so after it is dropped, this pointer must not be used again.
                #[allow(dead_code)]
                unsafe fn inner_mut(&mut self) -> *mut [u8; $size] {
                    self.0.as_mut()
                }
            }

            impl Drop for $name {
                fn drop(&mut self) {
                    unsafe {
                        // SAFETY:
                        // * Is a double-free possible in safe code?
                        //   * No: We only free in `drop`, which cannot be called manually, and
                        //     is called exactly once when the struct is actually dropped. Once
                        //     the value is dropped, there's no way to call the method again to
                        //     cause a double free. In the `try_clone` method, new memory is
                        //     allocated.
                        // * Is a use-after-free possible in safe code?
                        //   * No: We only ever free a buffer on drop, and after drop, none of the
                        //     type's methods are accessible.
                        // * Is a memory leak possible in safe code?
                        //   * Yes: If the user uses something like `Box::leak()`, `ManuallyDrop`,
                        //     or `std::mem::forget`, the destructor will not be called even though
                        //     the buffer is dropped. However, it is documented that in these cases
                        //     heap memory may be leaked, so this is expected behaviour. In
                        //     addition, certain signal interrupts or using panic=abort behaviour
                        //     will mean the destructor is not called. There's little we can do
                        //     about this, but a failure to free is probably reasonable in such
                        //     cases. In any other case, `drop` will be called, and the memory
                        //     freed.
                        $crate::mem::free(self.0);
                    }
                }
            }

            impl std::convert::TryFrom<&[u8]> for $name {
                type Error = $crate::AlkaliError;

                fn try_from(buf: &[u8]) -> Result<Self, Self::Error> {
                    if buf.len() != $size {
                        return Err(Self::Error::IncorrectSliceLength($size as usize, buf.len()));
                    }

                    let mut new = Self::new_empty()?;
                    new.copy_from_slice(buf);
                    Ok(new)
                }
            }

            impl TryFrom<&[u8; $size]> for $name {
                type Error = $crate::AlkaliError;

                fn try_from(buf: &[u8; $size]) -> Result<Self, Self::Error> {
                    let mut new = Self::new_empty()?;
                    new.copy_from_slice(buf);
                    Ok(new)
                }
            }

            impl std::convert::AsMut<[u8; $size]> for $name {
                fn as_mut(&mut self) -> &mut [u8; $size] {
                    unsafe {
                        // SAFETY: The memory backing this buffer is valid for the lifetime of the
                        // struct. Implicitly, since we don't specify a lifetime for the reference
                        // we return here, this reference is also only valid for the lifetime of
                        // the struct, so it will always point to valid memory. Any region of
                        // memory of length $size is a valid representation of a [u8; $size], so
                        // initialisation & alignment issues are not a concern.
                        self.0.as_mut()
                    }
                }
            }

            impl std::convert::AsRef<[u8; $size]> for $name {
                fn as_ref(&self) -> &[u8; $size] {
                    unsafe {
                        // SAFETY: The memory backing this buffer is valid for the lifetime of the
                        // struct. Implicitly, since we don't specify a lifetime for the reference
                        // we return here, this reference is also only valid for the lifetime of
                        // the struct, so it will always point to valid memory. Any region of
                        // memory of length $size is a valid representation of a [u8; $size], so
                        // initialisation & alignment issues are not a concern.
                        self.0.as_ref()
                    }
                }
            }

            impl std::borrow::Borrow<[u8; $size]> for $name {
                fn borrow(&self) -> &[u8; $size] {
                    unsafe {
                        // SAFETY: The memory backing this buffer is valid for the lifetime of the
                        // struct. Implicitly, since we don't specify a lifetime for the reference
                        // we return here, this reference is also only valid for the lifetime of
                        // the struct, so it will always point to valid memory. Any region of
                        // memory of length $size is a valid representation of a [u8; $size], so
                        // initialisation & alignment issues are not a concern.
                        self.0.as_ref()
                    }
                }
            }

            impl std::borrow::BorrowMut<[u8; $size]> for $name {
                fn borrow_mut(&mut self) -> &mut [u8; $size] {
                    unsafe {
                        // SAFETY: The memory backing this buffer is valid for the lifetime of the
                        // struct. Implicitly, since we don't specify a lifetime for the reference
                        // we return here, this reference is also only valid for the lifetime of
                        // the struct, so it will always point to valid memory. Any region of
                        // memory of length $size is a valid representation of a [u8; $size], so
                        // initialisation & alignment issues are not a concern.
                        self.0.as_mut()
                    }
                }
            }

            impl std::fmt::Debug for $name {
                fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    f.write_str(&format!("{}([u8; {}])", stringify!($name), $size))
                }
            }

            impl std::ops::Deref for $name {
                type Target = [u8; $size];

                fn deref(&self) -> &Self::Target {
                    unsafe {
                        // SAFETY: The memory backing this buffer is valid for the lifetime of the
                        // struct. Implicitly, since we don't specify a lifetime for the reference
                        // we return here, this reference is also only valid for the lifetime of
                        // the struct, so it will always point to valid memory. Any region of
                        // memory of length $size is a valid representation of a [u8; $size], so
                        // initialisation & alignment issues are not a concern.
                        self.0.as_ref()
                    }
                }
            }

            impl std::ops::DerefMut for $name {
                fn deref_mut(&mut self) -> &mut Self::Target {
                    unsafe {
                        // SAFETY: The memory backing this buffer is valid for the lifetime of the
                        // struct. Implicitly, since we don't specify a lifetime for the reference
                        // we return here, this reference is also only valid for the lifetime of
                        // the struct, so it will always point to valid memory. Any region of
                        // memory of length $size is a valid representation of a [u8; $size], so
                        // initialisation & alignment issues are not a concern.
                        self.0.as_mut()
                    }
                }
            }

            impl std::cmp::PartialEq<Self> for $name {
                fn eq(&self, other: &Self) -> bool {
                    unsafe {
                        // SAFETY: To initialise a struct of this type, we must successfully
                        // allocate the backing data, otherwise initialisation will fail.
                        // Therefore, we know the backing data for other is not NULL, so it is safe
                        // to initialise the NonNull without checking for NULL.
                        let other = std::ptr::NonNull::new_unchecked(other.inner() as *mut _);

                        // SAFETY: Both self.0 and other are pointers to regions of memory of the
                        // same length, and are of sufficient size to store a [u8; $size].
                        $crate::mem::memcmp(self.0, other).unwrap()
                    }
                }
            }

            impl std::fmt::Pointer for $name {
                fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
                    <std::ptr::NonNull<[u8; $size]> as std::fmt::Pointer>::fmt(&self.0, f)
                }
            }
        )*
    };
}

pub(crate) use hardened_buffer;

/// Attempt to initialise Sodium.
///
/// n.b: Crates making use of alkali do not have to call this function, it is only used internally
/// wherever initialisation may be necessary.
///
/// This function should be called in any scenario where a function from Sodium will be used
/// internally. Returns `Ok(0)` if Sodium was initialised successfully, `Ok(1)` if Sodium has
/// already been initialised, or [`AlkaliError::SodiumInitFailed`] if the initialisation was
/// unsuccessful.
fn require_init() -> Result<libc::c_int, crate::AlkaliError> {
    let init_status = unsafe {
        // SAFETY: This function can safely be called multiple times from multiple threads. Once it
        // has been called, all other Sodium functions are also thread-safe.
        sodium::sodium_init()
    };

    // sodium_init() returns -1 on init failure, 0 on success, or 1 if Sodium is already
    // initialised
    if init_status < 0 {
        return Err(AlkaliError::SodiumInitFailed);
    }

    Ok(init_status)
}

#[cfg(test)]
mod tests {
    use super::{require_init, AlkaliError};

    #[test]
    fn can_initialise() -> Result<(), AlkaliError> {
        require_init().map(|_| ())
    }

    // TODO: Test hardened_buffer!
}
