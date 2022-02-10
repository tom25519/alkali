//! **Please note**: This is currently a work-in-progress, and isn't yet complete, nor is it
//! suitable for production usage.
//!
//! Safe, idiomatic Rust bindings to the [Sodium](https://libsodium.org) cryptographic library.
//!
//! Sodium is a fast, modern cryptographic library written in C. This crate intends to provide a
//! higher-level API for making use of the cryptographic constructions Sodium provides. These
//! constructions include simple-to-use symmetric and asymmetric authenticated encryption,
//! signatures, hashing, password derivation, and key exchange: In short, the majority of
//! operations required for many modern cryptographic protocols.
//!
//! The intention for this library is to be a spiritual successor to
//! [sodiumoxide](https://github.com/sodiumoxide/sodiumoxide), which is now deprecated. Lots of
//! design decisions here were inspired by this library, so thanks to all of its contributors!
//!
//! # Which API Should I Use?
//! The cryptographic operations in this crate are mostly split into two main modules:
//! [`symmetric`] and [`asymmetric`]. Symmetric (sometimes called secret-key) operations use a
//! single secret key, shared between every party to a communication. In asymmetric (public-key)
//! operations, every party has their own secret key, used to derive a public-key which is shared
//! with all other parties. Parties need to know each others' public keys to communicate.
//!
//! There are also hashing algorithms available in the [`hash`] module, and tools for
//! cryptographically-secure pseudo-random number generation in the [`random`] module.
//!
//! I want to...
//! * Encrypt a message for a specific party using their public key, so that they can verify I sent
//!   it
//!     * Use [`asymmetric::cipher`]
//! * Anonymously encrypt a message for a specific party using their public key
//!     * Use [`asymmetric::repudiable_cipher`]
//! * Encrypt a message, so that specific trusted parties, with whom I already share a secret key,
//!   can decrypt it
//!     * Use [`symmetric::cipher`]
//! * Encrypt a sequence of messages in order, so that the decrypting party can verify no messages
//!   have been removed, reordered, etc.
//!     * Use [`symmetric::cipher_stream`]
//! * Encrypt an arbitrarily-long data stream, such as a file
//!     * Use [`symmetric::cipher_stream`]
//! * Produce a signature for a message, so that anyone can verify I sent it
//!     * Use [`asymmetric::sign`]
//! * Produce an authentication tag for a message, so that specific trusted parties, with whom I
//!   already share a secret key, can verify I sent it
//!     * Use [`symmetric::auth`]
//! * Store a user's password so I can verify their identity on next login
//!     * Use [`hash::pbkdf`]
//! * Derive a key from a low-entropy input (i.e: a password)
//!     * Use [`hash::pbkdf`]
//! * Calculate the  "fingerprint" of a file or message
//!     * Use [`hash::generic`]
//! * Establish a secret key with another party over an insecure channel
//!     * Use [`asymmetric::kx`]
//! * Calculate a hash for use in a hash table/bloom filter/etc.
//!     * Use [`hash::short`]
//! * Derive multiple subkeys from a single high-entropy key
//!     * Use [`hash::kdf`]
//! * Generate cryptographically secure pseudo-random data
//!     * Use [`random`]
//!
//! # Hardened Buffer Types
//! Throughout this crate, a number of types used to store secret data (keys, seeds, etc.) use a
//! custom allocator from Sodium to manage their memory. They can be used like standard array/slice
//! types, as they implement `std::ops::Deref`, [`AsRef`], etc., so anywhere where you might be
//! able to use a `&[u8]`, a hardened buffer can also be used. The benefit to using these structs
//! over just using normal arrays/vectors is that they have a number of protections implemented
//! intended to prevent leakage of their contents via side channels.
//!
//! When these hardened buffer types are dropped, their memory is securely zeroed, so that secrets
//! cannot later be recovered from uninitialised memory. This operation is done in such a way that
//! the compiler will not remove it during optimisation. Memory for these types is allocated at the
//! end of a page, immediately followed by a guard page, so any buffer overflow should be
//! immediately detected and prevented. A canary is also placed before the allocated memory region
//! to detect potential overflows, and another guard page is placed before the canary. The entire
//! region is "locked", which advises the operating system not to swap it to disk if it would
//! normally do so, and not to include the memory contents in crash reports/core dumps.
//!
//! In the future, we should be able to use the [Allocator
//! API](https://doc.rust-lang.org/std/alloc/trait.Allocator.html) to simplify these types, but for
//! the time being, we have to do a fair amount of manual memory management under the hood to
//! enable them to work. Regardless, these implementation details do not require you to do anything
//! differently yourself.

use libsodium_sys as sodium;
use thiserror::Error;

pub mod asymmetric;
pub mod encode;
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
    /// any other reason secure memory allocation may fail. Sodium's allocator is less likely to
    /// succeed in general than the standard operating system allocator, since there are limits
    /// placed on how much memory can be locked, etc.
    #[error("memory management error")]
    MemoryManagement,

    /// Tried to create a hardened buffer from an incorrectly sized slice.
    ///
    /// The 0th item is the expected length of a slice from which this buffer can be initialised,
    /// the 1st item is the actual length of the slice that was provided.
    #[error("incorrect slice length: expected {0}, found {1}")]
    IncorrectSliceLength(usize, usize),

    /// The slices supplied to [`util::add_le`], [`util::sub_le`], or [`util::compare_le`] differ
    /// in length.
    #[error("numbers differ in length")]
    NumberLengthsDiffer,

    /// Could not add padding to the provided buffer.
    ///
    /// This should only occur if `blocksize` was set to zero.
    #[error("failed to pad the provided buffer")]
    PaddingError,

    /// Could not calculate the unpadded buffer size.
    ///
    /// This can occur if `blocksize` was set to zero, or if `buf` does not appear to be correctly
    /// padded.
    #[error("failed to unpad the provided buffer")]
    UnpaddingError,

    /// Failed to decode the provided hex/base64 string.
    ///
    /// This could occur if the string contains invalid characters which were not marked to be
    /// ignored, or if the output was insufficient to store the decoded bytes.
    #[error("could not decode provided hex/base64")]
    DecodeError,

    /// An error occurred in the [`asymmetric::cipher`] module.
    #[error("asymmetric cipher error")]
    AsymmetricCipherError(#[from] asymmetric::cipher::CipherError),

    /// An error occurred in the [`asymmetric::kx`] module.
    #[error("key exchange error")]
    KeyExchangeError(#[from] asymmetric::kx::KeyExchangeError),

    /// An error occurred in the [`asymmetric::repudiable_cipher`] module.
    #[error("repudiable cipher error")]
    RepudiableCipherError(#[from] asymmetric::repudiable_cipher::RepudiableCipherError),

    /// An error occurred in the [`asymmetric::sign`] module.
    #[error("signing error")]
    SignError(#[from] asymmetric::sign::SignError),

    /// An error occurred in the [`hash::generic`] module.
    #[error("hash error")]
    GenericHashError(#[from] hash::generic::GenericHashError),

    /// An error occurred in the [`hash::kdf`] module.
    #[error("KDF error")]
    KDFError(#[from] hash::kdf::KDFError),

    /// An error occurred in the [`hash::pbkdf`] module.
    #[error("PBKDF error")]
    PasswordHashError(#[from] hash::pbkdf::PasswordHashError),

    /// An error occurred in the [`random`] module.
    #[error("PRNG error")]
    RandomError(#[from] random::RandomError),

    /// An error occurred in the [`symmetric::auth`] module.
    #[error("authentication error")]
    AuthError(#[from] symmetric::auth::AuthError),

    /// An error occurred in the [`symmetric::cipher`] module.
    #[error("symmetric cipher error")]
    SymmetricCipherError(#[from] symmetric::cipher::CipherError),

    /// An error occurred in the [`symmetric::cipher_stream`] module.
    #[error("symmetric cipher stream error")]
    CipherStreamError(#[from] symmetric::cipher_stream::CipherStreamError),

    /// An error occurred in the [`symmetric::one_time_auth`] module.
    #[error("one-time authentication error")]
    OneTimeAuthError(#[from] symmetric::one_time_auth::OneTimeAuthError),
}

/// Creates a hardened buffer type, for storing sensitive data (keys, passwords, etc).
macro_rules! hardened_buffer {
    ( $( $(#[$metadata:meta])* $name:ident($size:expr)$(;)? )* ) => {
        $(
            $(#[$metadata])*
            pub struct $name {
                ptr: std::ptr::NonNull<[u8; $size]>,
                _marker: std::marker::PhantomData<[u8; $size]>,
            }

            impl $name {
                pub const LENGTH: usize = $size as usize;

                /// Create a new instance of this type, filled with all zeroes.
                pub fn new_empty() -> Result<Self, $crate::AlkaliError> {
                    $crate::require_init()?;

                    let ptr = unsafe {
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

                        // SAFETY: This call to memzero will clear the memory pointed to by `ptr`.
                        // The `memzero::<T>` function clears an amount of memory equal to the size
                        // of the `T`. Since the `malloc` call above succeeded, `ptr` points to
                        // sufficient memory to store a `[u8; $size]`, so `memzero::<[u8; $size]>`
                        // is valid here. Any memory value can be a valid representation of this
                        // type, so zeroing the memory is valid.
                        $crate::mem::memzero(ptr)?;

                        ptr
                    };

                    Ok(Self {
                        ptr,
                        _marker: std::marker::PhantomData,
                    })
                }

                /// Safely zero the contents of the buffer, in such a way that the compiler will
                /// not optimise away the operation.
                ///
                /// This is automatically done when the buffer is dropped, but you may wish to do
                /// this as soon as the buffer is no longer required.
                pub fn zero(&mut self) -> Result<(), $crate::AlkaliError> {
                    $crate::require_init()?;

                    unsafe {
                        // SAFETY: While this struct is in scope, the memory backing it is
                        // allocated and writeable, so we can safely write zeros to it. All zeroes
                        // is a valid representation of a u8 array.
                        $crate::mem::memzero(self.ptr)
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
                    self.ptr.as_ptr()
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
                    self.ptr.as_mut()
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
                        $crate::mem::free(self.ptr);
                    }
                }
            }

            impl TryFrom<&[u8]> for $name {
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
                        self.ptr.as_mut()
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
                        self.ptr.as_ref()
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
                        self.ptr.as_ref()
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
                        self.ptr.as_mut()
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
                        self.ptr.as_ref()
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
                        self.ptr.as_mut()
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
                        $crate::mem::memcmp(self.ptr, other).unwrap()
                    }
                }
            }

            impl std::fmt::Pointer for $name {
                fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
                    <std::ptr::NonNull<[u8; $size]> as std::fmt::Pointer>::fmt(&self.ptr, f)
                }
            }
        )*
    };
}

pub(crate) use hardened_buffer;

/// Used where Sodium returns an error which we didn't expect.
///
/// This indicates the implementation has changed, and is now fallible where it previously always
/// succeeded, so we need to handle the error individually.
macro_rules! unexpected_err {
    ($source:expr) => {
        panic!(
            "An unexpected error occurred in `{}`. Please report this bug to \
            https://github.com/tom25519/alkali/issues.",
            $source
        );
    };
}

pub(crate) use unexpected_err;

/// Assert than `$result` is not a C-style indicator of error (i.e: ensure it is equal to zero).
///
/// Calls `unexpected_err!($source)` if an error did occur.
macro_rules! assert_not_err {
    ($result:expr, $source:expr) => {
        if $result != 0 {
            $crate::unexpected_err!($source);
        }
    };
}

pub(crate) use assert_not_err;

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
