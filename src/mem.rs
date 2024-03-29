//! Hardened memory management utilities.
//!
//! This module contains various wrappers around Sodium's [secure memory management
//! functions](https://doc.libsodium.org/memory_management), intended to simplify the process of
//! keeping secret values safe while they are located in memory.
//!
//! Due to the nature of modern computing, it is often difficult to ensure that once a key/password
//! is no longer required, it is truly unrecoverable. For example, if we store a key on the heap
//! while we perform some cryptographic operation, then free the associated memory when done, the
//! memory it occupied will not be erased, only marked as free. So if another application later
//! allocates memory, the uninitialised memory it is allocated could contain key data which we
//! intended to keep secret. There are many other possible pitfalls when storing sensitive data, but
//! hopefully this gives some insight into the problems this module intends to address.
//!
//! Sodium's allocator takes a number of measures to ensure that the memory it allocates is
//! protected against many possible vulnerabilities. First, memory is always securely cleared when
//! freed, so that secrets cannot later be recovered from uninitialised memory. This kind of
//! operation is often removed in optimisation passes, but Sodium's implementation is intended to
//! ensure the memory is always securely cleared. The allocated memory is placed at the end of a
//! page boundary, directly before a guard page, so that if an attempt is made to access memory
//! beyond the end of the allocated region, the guard page will be hit, and the program will
//! terminate. Furthermore, a canary will be placed before the allocated region to detect
//! modifications on free, and a further guard page is placed before this. Memory regions are marked
//! to the operating system as "locked", so they will not be swapped to disk or included in core
//! dumps/crash reports. All of these measures aim to minimise the risk of storing sensitive data in
//! memory, but do mean that Sodium's allocator has much more overhead than the standard system
//! allocator, so it should only be used to protect sensitive data, not as a general-purpose
//! allocator.
//!
//! The intent of this module is to provide a safe interface to this allocator, so that types which
//! store sensitive data can easily be created. All of the key types throughout alkali use tools
//! from module to store their contents securely.
//!
//! # The `alloc` Feature
//! Work is currently ongoing on standardising the Rust standard library's [`Allocator`
//! API](https://doc.rust-lang.org/core/alloc/trait.Allocator.html), which allows for user-defined
//! allocators for many common Rust types (`Vec`, `Box`, etc.). The [`SodiumAllocator`] struct
//! implements the `Allocator` trait, and can therefore be used for this purpose, providing an
//! allocator based on Sodium's secure memory management tools. Similarly, the [`HardenedVec`] and
//! [`HardenedBox`] types use this allocator to secure their contents.
//!
//! However, the allocator API is still not stable, and is only available in nightly Rust.
//! Therefore, access to these types is feature-gated behind the `alloc` feature. You can enable
//! this if you wish to make use of the API, but it will cause builds to fail on stable Rust.

// TODO: Testing for SodiumAllocator, HardenedBox, HardenedVec, hardened_buffer, anon_buffer

#[cfg(feature = "alloc")]
extern crate alloc;

use crate::{require_init, AlkaliError};
#[cfg(feature = "alloc")]
use alloc::{boxed::Box, vec::Vec};
use core::alloc::Layout;
#[cfg(feature = "alloc")]
use core::alloc::{AllocError, Allocator};
use core::ptr::NonNull;
use libsodium_sys as sodium;

/// An [`Allocator`] which allocates memory using Sodium's secure memory utilities.
///
/// Allocation of memory using this struct is expensive - it shouldn't be used as a global
/// allocator, but rather confined to manage memory for data structures storing sensitive data
/// (keys, passwords, etc).
#[cfg(feature = "alloc")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "alloc")))]
#[derive(Clone, Copy, Debug)]
pub struct SodiumAllocator;

#[cfg(feature = "alloc")]
unsafe impl Allocator for SodiumAllocator {
    fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
        let ptr = unsafe {
            // SAFETY: It is the caller's responsibility to take care of memory management here and
            // ensure that `SodiumAllocator::deallocate` is called exactly once for this pointer and
            // that the pointer is not used again after free. The `malloc_layout` function will
            // expand the layout size to be a multiple of the alignment and allocate this much
            // memory, satisfying the size & alignment requirements of the layout.
            malloc_layout(layout).map_err(|_| AllocError)?
        };
        // As `ptr` is a `u8` pointer, the number of "elements" is equal to the layout size in
        // bytes.
        Ok(NonNull::slice_from_raw_parts(ptr, layout.size()))
    }

    unsafe fn deallocate(&self, ptr: NonNull<u8>, _layout: Layout) {
        free(ptr);
    }
}

/// A [`Vec`] backed by Sodium's secure memory allocator.
///
/// The contents of this vector will be stored securely in memory, and will be cleared on drop.
#[cfg(feature = "alloc")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "alloc")))]
pub type HardenedVec<T> = Vec<T, SodiumAllocator>;

/// A [`Box`] backed by Sodium's secure memory allocator.
///
/// The contents of this box will be stored securely in memory, and will be cleared on drop.
#[cfg(feature = "alloc")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "alloc")))]
pub type HardenedBox<T> = Box<T, SodiumAllocator>;

/// Marker trait for types used to signify the status of a [hardened
/// buffer](https://docs.rs/alkali#hardened-buffer-types).
///
/// The [`sodium_mprotect`](https://doc.libsodium.org/memory_management#guarded-heap-allocations)
/// API can be used to set a region of memory to be read-only, or totally inaccessible, to minimise
/// the risk of sensitive data being leaked. In order to provide a type-safe system for interacting
/// with this API, we attach a zero-sized `MprotectStatus` marker type to hardened buffers,
/// signifying the current memory-protection status of the buffer.
pub trait MprotectStatus {}

/// Marker trait for types used to signify that a [hardened
/// buffer](https://docs.rs/alkali#hardened-buffer-types) is in a readable state.
///
/// The [`sodium_mprotect`](https://doc.libsodium.org/memory_management#guarded-heap-allocations)
/// API can be used to set a region of memory to be read-only, or totally inaccessible, to minimise
/// the risk of sensitive data being leaked. In order to provide a type-safe system for interacting
/// with this API, we attach a zero-sized `MprotectStatus` marker type to hardened buffers,
/// signifying the current memory-protection status of the buffer.
///
/// This trait is implemented for `MprotectStatus` types which signify that the buffer is in a
/// readable state.
pub trait MprotectReadable: MprotectStatus {}

/// Marker type used to signify that a [hardened
/// buffer](https://docs.rs/alkali#hardened-buffer-types) can be written to/read from.
///
/// The [`sodium_mprotect`](https://doc.libsodium.org/memory_management#guarded-heap-allocations)
/// API can be used to set a region of memory to be read-only, or totally inaccessible, to minimise
/// the risk of sensitive data being leaked. In order to provide a type-safe system for interacting
/// with this API, we attach a zero-sized `MprotectStatus` marker type to hardened buffers,
/// signifying the current memory-protection status of the buffer.
///
/// This type indicates a buffer is in the "normal" state for any allocated memory region - it can
/// be written to and read from.
#[derive(Clone, Copy, Eq, Debug, Hash, PartialEq)]
pub struct FullAccess;

impl MprotectStatus for FullAccess {}
impl MprotectReadable for FullAccess {}

/// Marker type used to signify that a [hardened
/// buffer](https://docs.rs/alkali#hardened-buffer-types) is read-only.
///
/// The [`sodium_mprotect`](https://doc.libsodium.org/memory_management#guarded-heap-allocations)
/// API can be used to set a region of memory to be read-only, or totally inaccessible, to minimise
/// the risk of sensitive data being leaked. In order to provide a type-safe system for interacting
/// with this API, we attach a zero-sized `MprotectStatus` marker type to hardened buffers,
/// signifying the current memory-protection status of the buffer.
///
/// This type indicates a buffer may only be read from, and not written to. Attempts to write to a
/// buffer in this state will result in the process being terminated.
pub struct ReadOnly;

impl MprotectStatus for ReadOnly {}
impl MprotectReadable for ReadOnly {}

/// Marker type used to signify that a [hardened
/// buffer](https://docs.rs/alkali#hardened-buffer-types) may not be accessed.
///
/// The [`sodium_mprotect`](https://doc.libsodium.org/memory_management#guarded-heap-allocations)
/// API can be used to set a region of memory to be read-only, or totally inaccessible, to minimise
/// the risk of sensitive data being leaked. In order to provide a type-safe system for interacting
/// with this API, we attach a zero-sized `MprotectStatus` marker type to hardened buffers,
/// signifying the current memory-protection status of the buffer.
///
/// This type indicates a buffer may not be accessed at all. Attempts to read from or write to a
/// buffer in this state will result in the process being terminated.
pub struct NoAccess;

impl MprotectStatus for NoAccess {}

/// Trait for types which are protected with mprotect, and can be unprotected.
///
/// Used to convert a [`ReadOnly`] or [`NoAccess`] buffer into a [`FullAccess`] buffer.
pub trait Unprotect {
    type Output;

    /// Remove the read-only or no-access protection from this buffer.
    fn unprotect(self) -> Result<Self::Output, AlkaliError>;
}

/// Trait for types which can be made read-only via mprotect.
///
/// Used to convert a [`FullAccess`] or [`NoAccess`] buffer into a [`ReadOnly`] buffer.
pub trait ProtectReadOnly {
    type Output;

    /// Make this buffer read-only.
    fn protect_read_only(self) -> Result<Self::Output, AlkaliError>;
}

/// Trait for types which can be made inaccessible via mprotect.
///
/// Used to convert a [`FullAccess`] or [`ReadOnly`] buffer into a [`NoAccess`] buffer.
pub trait ProtectNoAccess {
    type Output;

    /// Make this buffer inaccessible.
    fn protect_no_access(self) -> Result<Self::Output, AlkaliError>;
}

/// Creates a hardened buffer type, for storing sensitive data (keys, passwords, etc).
///
/// As per the rationale presented in the [`mem`](crate::mem) module, it is often necessary to take
/// extra measures to ensure that sensitive data stored in memory is not at risk of being revealed.
/// This macro creates a fixed size array-like type with memory allocated using Sodium's [secure
/// memory utilities](https://doc.libsodium.org/memory_management), which is therefore suitable for
/// storing secret values. All the key types throughout alkali are created using this macro, so
/// examples of its usage are abundant throughout the source code.
///
/// `hardened_buffer!(Name(Size))` will create a new type `Name` that provides access to `Size`
/// bytes of contiguous hardened memory. The new type will implement the following traits:
/// * [`AsRef<[u8; $size]>`](core::convert::AsRef) and [`AsMut<[u8; $size]>`](core::convert::AsMut)
/// * [`Borrow<[u8; $size]>`](core::borrow::Borrow) and
///   [`BorrowMut<[u8; $size]>`](core::borrow::BorrowMut)
/// * [`Debug`](core::fmt::Debug)
/// * [`Deref`](core::ops::Deref) and [`DerefMut`](core::ops::DerefMut)
/// * [`PartialEq<Self>`](core::cmp::PartialEq) and [`Eq<Self>`](core::cmp::Eq)
///     * This operation uses a constant-time comparison, so it can be used to compare buffers
///       without the risk of side-channel attacks
/// * [`Pointer`](core::fmt::Pointer)
/// * [`TryFrom<&[u8]>`](core::convert::TryFrom)
/// * [`TryFrom<&[u8; $size]>`](core::convert::TryFrom)
///
/// The new type will also implement the methods `new_empty` (which creates a new, zeroed instance
/// of the type), `zero` (which sets all the bytes in the buffer to zero in such a way that the
/// compiler will not optimize away the operation), and `try_clone` (which attempts to clone the
/// struct). The struct constant `LENGTH` will be set to `$size`. For an example of a hardened
/// buffer type, see [`crate::asymmetric::cipher::Seed`].
///
/// The memory backing types created by this macro will be heap-allocated. See the
/// [`mem`](crate::mem) module for documentation on the measures taken to protect the contents of
/// these types.
///
/// # Examples
/// Creating a public 32-byte key type:
/// ```rust
/// use alkali::mem::hardened_buffer;
///
/// hardened_buffer! {
///     /// Any documentation provided here will be used as the generated type's documentation
///     ///
///     /// e.g: "A 32-byte buffer suitable for storing a key"
///     pub Key(32);
/// }
///
/// let mut my_key = Key::new_empty().unwrap();
/// my_key.copy_from_slice(b"don't steal my super secret key!");
/// println!("{:?}", my_key);       // just printing the type will not reveal its contents
/// println!("{:?}", &my_key[..]);  // taking a slice lets us see what's inside
///
/// // `Key` implements lots of the standard smart pointer traits, so you can often just treat it
/// // like a `&[u8]`
/// ```
///
/// Creating multiple types with one macro invocation:
/// ```rust
/// use alkali::mem::hardened_buffer;
///
/// hardened_buffer! {
///     pub TypeA(1024);        // no documentation needs to be provided
///
///     TypeB(2048);            // types can be public or private
/// }
/// ```
#[macro_export]
macro_rules! hardened_buffer {
    ( $( $(#[$metadata:meta])* $vis:vis $name:ident($size:expr)$(;)? )* ) => {
        $(
            $(#[$metadata])*
            $vis struct $name<Mprotect: $crate::mem::MprotectStatus> {
                ptr: core::ptr::NonNull<[u8; $size]>,
                _marker: core::marker::PhantomData<[u8; $size]>,
                _mprotect: core::marker::PhantomData<Mprotect>,
            }

            #[allow(dead_code)]
            impl<Mprotect: $crate::mem::MprotectStatus> $name<Mprotect> {
                /// The number of bytes this type stores.
                pub const LENGTH: usize = $size as usize;
            }

            #[allow(dead_code)]
            impl $name<$crate::mem::FullAccess> {
                /// Create a new instance of this type, filled with all zeroes.
                pub fn new_empty() -> Result<Self, $crate::AlkaliError> {
                    $crate::require_init()?;

                    let ptr = unsafe {
                        // SAFETY: This call to `malloc` will allocate the memory required for a
                        // `[u8; $size]` type, outside of Rust's memory management. The associated
                        // memory is always freed in the corresponding `drop` call. We never free
                        // the memory in any other place in this struct, and drop can only be called
                        // once, so a double-free is not possible. We never expose a pointer to the
                        // allocated memory directly. The region of memory allocated will always be
                        // a valid representation of a `[u8; $size]`. See the drop implementation
                        // for more reasoning on safety.
                        let ptr: core::ptr::NonNull<[u8; $size]> = $crate::mem::malloc()?;

                        // SAFETY: This function expects a pointer to a region of memory, and a
                        // number of bytes to clear starting at that pointer. We allocate `$size`
                        // bytes of memory at `ptr` in the line above, and specify `$size` bytes
                        // should be cleared, so the amount of memory to clear here is correct. All
                        // zeroes is a valid representation of a `u8` slice.
                        $crate::libsodium_sys::sodium_memzero(
                            ptr.as_ptr().cast::<$crate::libc::c_void>(),
                            $size
                        );

                        ptr
                    };

                    Ok(Self {
                        ptr,
                        _marker: core::marker::PhantomData,
                        _mprotect: core::marker::PhantomData,
                    })
                }

                /// Safely zero the contents of the buffer, in such a way that the compiler will
                /// not optimise away the operation.
                ///
                /// This is automatically done when the buffer is dropped, but you may wish to do
                /// this as soon as the buffer is no longer required.
                pub fn zero(&mut self) -> Result<(), $crate::AlkaliError> {
                    $crate::mem::clear(self.as_mut())
                }

                /// Returns a raw mutable pointer to the memory backing this type.
                ///
                /// # Safety
                /// This function is only used internally. This struct assumes that the memory will
                /// remain valid until it is dropped, so anywhere this method is used, the memory
                /// must not be freed. Furthermore, the memory is only valid for the lifetime of
                /// this struct, so after it is dropped, this pointer must not be used again.
                unsafe fn inner_mut(&mut self) -> *mut [u8; $size] {
                    self.ptr.as_mut()
                }
            }

            impl<Mprotect: $crate::mem::MprotectStatus> $crate::mem::Unprotect for $name<Mprotect> {
                type Output = $name<$crate::mem::FullAccess>;

                fn unprotect(
                    mut self
                ) -> Result<$name<$crate::mem::FullAccess>, $crate::AlkaliError> {
                    let mprotect_result = unsafe {
                        // SAFETY: This function expects a pointer to a region of memory previously
                        // allocated using `sodium_malloc`. The only way to construct an instance of
                        // this type is to allocate such a region of memory (via `new_empty`), so
                        // this pointer is guaranteed to be valid to use here.
                        $crate::libsodium_sys::sodium_mprotect_readwrite(
                            (self.ptr.as_mut() as *mut u8).cast::<$crate::libc::c_void>()
                        )
                    };
                    if mprotect_result < 0 {
                        return Err($crate::AlkaliError::MprotectFailed);
                    }

                    // The `Drop` trait for hardened buffers frees the memory pointed to by
                    // `self.ptr`. We want to reuse the memory with our new buffer, so avoid calling
                    // the destructor on `self` by forgetting it. The memory will be freed when the
                    // new buffer is dropped.
                    let ptr = self.ptr;
                    core::mem::forget(self);

                    Ok($name {
                        ptr,
                        _marker: core::marker::PhantomData,
                        _mprotect: core::marker::PhantomData,
                    })
                }
            }

            impl<Mprotect: $crate::mem::MprotectStatus> $crate::mem::ProtectReadOnly for $name<Mprotect> {
                type Output = $name<$crate::mem::ReadOnly>;

                fn protect_read_only(
                    mut self
                ) -> Result<$name<$crate::mem::ReadOnly>, $crate::AlkaliError> {
                    let mprotect_result = unsafe {
                        // SAFETY: This function expects a pointer to a region of memory previously
                        // allocated using `sodium_malloc`. The only way to construct an instance of
                        // this type is to allocate such a region of memory (via `new_empty`), so
                        // this pointer is guaranteed to be valid to use here.
                        $crate::libsodium_sys::sodium_mprotect_readonly(
                            (self.ptr.as_mut() as *mut u8).cast::<$crate::libc::c_void>()
                        )
                    };
                    if mprotect_result < 0 {
                        return Err($crate::AlkaliError::MprotectFailed);
                    }

                    // The `Drop` trait for hardened buffers frees the memory pointed to by
                    // `self.ptr`. We want to reuse the memory with our new buffer, so avoid calling
                    // the destructor on `self` by forgetting it. The memory will be freed when the
                    // new buffer is dropped.
                    let ptr = self.ptr;
                    core::mem::forget(self);

                    Ok($name {
                        ptr,
                        _marker: core::marker::PhantomData,
                        _mprotect: core::marker::PhantomData,
                    })
                }
            }

            impl<Mprotect: $crate::mem::MprotectStatus> $crate::mem::ProtectNoAccess for $name<Mprotect> {
                type Output = $name<$crate::mem::NoAccess>;

                fn protect_no_access(
                    mut self
                ) -> Result<$name<$crate::mem::NoAccess>, $crate::AlkaliError> {
                    let mprotect_result = unsafe {
                        // SAFETY: This function expects a pointer to a region of memory previously
                        // allocated using `sodium_malloc`. The only way to construct an instance of
                        // this type is to allocate such a region of memory (via `new_empty`), so
                        // this pointer is guaranteed to be valid to use here.
                        $crate::libsodium_sys::sodium_mprotect_noaccess(
                            (self.ptr.as_mut() as *mut u8).cast::<$crate::libc::c_void>()
                        )
                    };
                    if mprotect_result < 0 {
                        return Err($crate::AlkaliError::MprotectFailed);
                    }

                    // The `Drop` trait for hardened buffers frees the memory pointed to by
                    // `self.ptr`. We want to reuse the memory with our new buffer, so avoid calling
                    // the destructor on `self` by forgetting it. The memory will be freed when the
                    // new buffer is dropped.
                    let ptr = self.ptr;
                    core::mem::forget(self);

                    Ok($name {
                        ptr,
                        _marker: core::marker::PhantomData,
                        _mprotect: core::marker::PhantomData,
                    })
                }
            }

            #[allow(dead_code)]
            impl<Mprotect: $crate::mem::MprotectReadable> $name<Mprotect> {
                /// Create a new instance of the same type, copying the contents of this buffer.
                ///
                /// This operation may fail, as Sodium's allocator is more likely to encounter
                /// issues than the standard system allocator.
                pub fn try_clone(&self) -> Result<$name<$crate::mem::FullAccess>, $crate::AlkaliError> {
                    let mut new_buf = $name::new_empty()?;
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
                unsafe fn inner(&self) -> *const [u8; $size] {
                    self.ptr.as_ptr()
                }
            }

            // # Safety
            // It is safe to transfer ownership between threads because we have exclusive access to
            // the inner pointer.
            // As long as we respect rust borrowing rules, there is no way the internal pointer can
            // be freed more than once.
            unsafe impl<Mprotect: $crate::mem::MprotectStatus> core::marker::Send for $name<Mprotect> {}

            // # Safety
            // A read-only reference is safe to send across multiple threads because we have
            // exclusive access to the inner pointer.
            // As long as we respect rust borrowing rules, there is no way the internal pointer can
            // be freed more than once.
            unsafe impl<Mprotect: $crate::mem::MprotectStatus> core::marker::Sync for $name<Mprotect> {}

            impl<Mprotect: $crate::mem::MprotectStatus> Drop for $name<Mprotect> {
                fn drop(&mut self) {
                    // We do not use `require_init` here, as it must be called to initialise this
                    // struct.

                    unsafe {
                        // SAFETY:
                        // * Is a double-free possible in safe code?
                        //   * No: We only free in `drop`, which cannot be called manually, and
                        //     is called exactly once when the struct is actually dropped. Once
                        //     the value is dropped, there's no way to call the method again to
                        //     cause a double free.
                        // * Is a use-after-free possible in safe code?
                        //   * No: We only ever free a buffer on drop, and after drop, none of the
                        //     type's methods are accessible.
                        // * Is a memory leak possible in safe code?
                        //   * Yes: If the user uses something like `Box::leak()`, `ManuallyDrop`,
                        //     or `core::mem::forget`, the destructor will not be called even though
                        //     the buffer is dropped. However, it is documented that in these cases
                        //     heap memory may be leaked, so this is expected behaviour. In
                        //     addition, certain signal interrupts or using panic=abort behaviour
                        //     will mean the destructor is not called. There's little we can do
                        //     about this, but a failure to free is probably reasonable in such
                        //     cases. In any other case, `drop` will be called, and the memory
                        //     freed.
                        // `self.ptr` was allocated in the constructor using Sodium's allocator, so
                        // it is correct to free it using Sodium's allocator.
                        $crate::mem::free(self.ptr);
                    }
                }
            }

            impl TryFrom<&[u8]> for $name<$crate::mem::FullAccess> {
                type Error = $crate::AlkaliError;

                fn try_from(buf: &[u8]) -> Result<Self, Self::Error> {
                    if buf.len() != $size {
                        return Err(Self::Error::IncorrectSliceLength);
                    }

                    let mut new = Self::new_empty()?;
                    new.copy_from_slice(buf);
                    Ok(new)
                }
            }

            impl TryFrom<&[u8; $size]> for $name<$crate::mem::FullAccess> {
                type Error = $crate::AlkaliError;

                fn try_from(buf: &[u8; $size]) -> Result<Self, Self::Error> {
                    let mut new = Self::new_empty()?;
                    new.copy_from_slice(buf);
                    Ok(new)
                }
            }

            impl core::convert::AsMut<[u8; $size]> for $name<$crate::mem::FullAccess> {
                fn as_mut(&mut self) -> &mut [u8; $size] {
                    unsafe {
                        // SAFETY: The memory backing this buffer is valid for the lifetime of the
                        // struct. Implicitly, since we don't specify a lifetime for the reference
                        // we return here, this reference is also only valid for the lifetime of
                        // the struct, so it will always point to valid memory. Since we have an
                        // exclusive reference to self, `&mut self`, we can only give out one
                        // exclusive reference to the backing memory at a time. Any region of
                        // memory of length $size is a valid representation of a [u8; $size], so
                        // initialisation & alignment issues are not a concern.
                        self.ptr.as_mut()
                    }
                }
            }

            impl<Mprotect: $crate::mem::MprotectReadable> core::convert::AsRef<[u8; $size]> for $name<Mprotect> {
                fn as_ref(&self) -> &[u8; $size] {
                    unsafe {
                        // SAFETY: The memory backing this buffer is valid for the lifetime of the
                        // struct. Implicitly, since we don't specify a lifetime for the reference
                        // we return here, this reference is also only valid for the lifetime of
                        // the struct, so it will always point to valid memory. Since we have a
                        // shared reference to self, `&self`, there is no mutable reference to
                        // `self` in scope, and therefore no mutable reference to the backing
                        // memory. So it's safe to give out a shared reference. Any region of
                        // memory of length $size is a valid representation of a [u8; $size], so
                        // initialisation & alignment issues are not a concern.
                        self.ptr.as_ref()
                    }
                }
            }

            impl<Mprotect: $crate::mem::MprotectReadable> core::borrow::Borrow<[u8; $size]> for $name<Mprotect> {
                fn borrow(&self) -> &[u8; $size] {
                    unsafe {
                        // SAFETY: The memory backing this buffer is valid for the lifetime of the
                        // struct. Implicitly, since we don't specify a lifetime for the reference
                        // we return here, this reference is also only valid for the lifetime of
                        // the struct, so it will always point to valid memory. Since we have a
                        // shared reference to self, `&self`, there is no mutable reference to
                        // `self` in scope, and therefore no mutable reference to the backing
                        // memory. So it's safe to give out a shared reference. Any region of
                        // memory of length $size is a valid representation of a [u8; $size], so
                        // initialisation & alignment issues are not a concern.
                        self.ptr.as_ref()
                    }
                }
            }

            impl core::borrow::BorrowMut<[u8; $size]> for $name<$crate::mem::FullAccess> {
                fn borrow_mut(&mut self) -> &mut [u8; $size] {
                    unsafe {
                        // SAFETY: The memory backing this buffer is valid for the lifetime of the
                        // struct. Implicitly, since we don't specify a lifetime for the reference
                        // we return here, this reference is also only valid for the lifetime of
                        // the struct, so it will always point to valid memory. Since we have an
                        // exclusive reference to self, `&mut self`, we can only give out one
                        // exclusive reference to the backing memory at a time. Any region of
                        // memory of length $size is a valid representation of a [u8; $size], so
                        // initialisation & alignment issues are not a concern.
                        self.ptr.as_mut()
                    }
                }
            }

            impl<Mprotect: $crate::mem::MprotectStatus> core::fmt::Debug for $name<Mprotect> {
                fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                    f.write_str(stringify!($name))?;
                    f.write_str("([u8; ")?;
                    f.write_str(stringify!($size))?;
                    f.write_str("])")
                }
            }

            impl<Mprotect: $crate::mem::MprotectReadable> core::ops::Deref for $name<Mprotect> {
                type Target = [u8; $size];

                fn deref(&self) -> &Self::Target {
                    unsafe {
                        // SAFETY: The memory backing this buffer is valid for the lifetime of the
                        // struct. Implicitly, since we don't specify a lifetime for the reference
                        // we return here, this reference is also only valid for the lifetime of
                        // the struct, so it will always point to valid memory. Since we have a
                        // shared reference to self, `&self`, there is no mutable reference to
                        // `self` in scope, and therefore no mutable reference to the backing
                        // memory. So it's safe to give out a shared reference. Any region of
                        // memory of length $size is a valid representation of a [u8; $size], so
                        // initialisation & alignment issues are not a concern.
                        self.ptr.as_ref()
                    }
                }
            }

            /// This implementation of `Eq` is constant-time.
            impl<Mprotect: $crate::mem::MprotectReadable> core::cmp::Eq for $name<Mprotect> {}

            impl core::ops::DerefMut for $name<$crate::mem::FullAccess> {
                fn deref_mut(&mut self) -> &mut Self::Target {
                    unsafe {
                        // SAFETY: The memory backing this buffer is valid for the lifetime of the
                        // struct. Implicitly, since we don't specify a lifetime for the reference
                        // we return here, this reference is also only valid for the lifetime of
                        // the struct, so it will always point to valid memory. Since we have an
                        // exclusive reference to self, `&mut self`, we can only give out one
                        // exclusive reference to the backing memory at a time. Any region of
                        // memory of length $size is a valid representation of a [u8; $size], so
                        // initialisation & alignment issues are not a concern.
                        self.ptr.as_mut()
                    }
                }
            }

            /// This implementation of `PartialEq` is constant-time.
            impl<Mprotect: $crate::mem::MprotectReadable> core::cmp::PartialEq<Self> for $name<Mprotect> {
                fn eq(&self, other: &Self) -> bool {
                    $crate::mem::eq(self.as_ref(), other.as_ref()).unwrap()
                }
            }

            impl<Mprotect: $crate::mem::MprotectStatus> core::fmt::Pointer for $name<Mprotect> {
                fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
                    <core::ptr::NonNull<[u8; $size]> as core::fmt::Pointer>::fmt(&self.ptr, f)
                }
            }

            #[cfg(feature = "use-serde")]
            #[cfg_attr(doc_cfg, doc(cfg(feature = "use-serde")))]
            impl<Mprotect: $crate::mem::MprotectReadable> $crate::serde::Serialize for $name<Mprotect> {
                fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
                where
                    S: $crate::serde::Serializer,
                {
                    serializer.serialize_bytes(self.as_ref())
                }
            }

            #[cfg(feature = "use-serde")]
            #[cfg_attr(doc_cfg, doc(cfg(feature = "use-serde")))]
            impl<'de> $crate::serde::Deserialize<'de> for $name<$crate::mem::FullAccess> {
                fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
                where
                    D: $crate::serde::Deserializer<'de>,
                {
                    struct BufVisitor;

                    impl<'de> $crate::serde::de::Visitor<'de> for BufVisitor {
                        type Value = $name<$crate::mem::FullAccess>;

                        fn expecting(
                            &self,
                            formatter: &mut core::fmt::Formatter
                        ) -> core::fmt::Result {
                            formatter.write_str("a byte array of length ")?;
                            formatter.write_str(stringify!($size))
                        }

                        fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
                        where
                            E: $crate::serde::de::Error,
                        {
                            if v.len() != $size {
                                return Err(E::invalid_length(v.len(), &self));
                            }
                            $name::try_from(v).map_err(E::custom)
                        }

                        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
                        where
                            A: $crate::serde::de::SeqAccess<'de>,
                        {
                            use $crate::serde::de::Error;

                            if let Some(s) = seq.size_hint() {
                                if s != $size {
                                    return Err(A::Error::invalid_length(s, &self));
                                }
                            }

                            let mut buf = Self::Value::new_empty().map_err(A::Error::custom)?;

                            for i in 0..$size {
                                let b = seq.next_element()?;
                                if b.is_none() {
                                    return Err(A::Error::invalid_length(i, &self));
                                }
                                buf[i] = b.unwrap();
                            }

                            if seq.next_element::<u8>()?.is_some() {
                                return Err(A::Error::invalid_length($size + 1, &self));
                            }

                            Ok(buf)
                        }
                    }

                    deserializer.deserialize_bytes(BufVisitor)
                }
            }
        )*
    };
}

pub use hardened_buffer;

/// Create a fixed-size hardened anonymous buffer.
///
/// As per the rationale presented in the [`mem`](crate::mem) module, it is often necessary to take
/// extra measures to ensure that sensitive data stored in memory is not at risk of being revealed.
/// This macro is like the "little sibling" of the [`hardened_buffer`] macro: It creates an
/// anonymous fixed size array-like buffer with memory allocated using Sodium's [secure  memory
/// utilities](https://doc.libsodium.org/memory_management), which is therefore suitable for
/// storing secret values. This macro is most useful for storing sensitive intermediary values,
/// where creating a whole new type with [`hardened_buffer`] seems redundant.
///
/// `anon_buffer!(Size)` will return an array-like type of length `Size` backed by hardened memory.
/// The new type will implement the following traits:
/// * [`AsRef<[u8; $size]>`](core::convert::AsRef) and [`AsMut<[u8; $size]>`](core::convert::AsMut)
/// * [`Borrow<[u8; $size]>`](core::borrow::Borrow) and
///   [`BorrowMut<[u8; $size]>`](core::borrow::BorrowMut)
/// * [`Debug`](core::fmt::Debug)
/// * [`Deref`](core::ops::Deref) and [`DerefMut`](core::ops::DerefMut)
/// * [`Pointer`](core::fmt::Pointer)
///
/// The new type will also implement the methods `zero` (which sets all the bytes in the buffer to
/// zero in such a way that the compiler will not optimize away the operation), and `try_clone`
/// (which attempts to clone the struct). The struct constant `LENGTH` will be set to `$size`.
///
/// # Examples
/// ```rust
/// use alkali::mem::{anon_buffer, eq};
///
/// let mut buffer_a = anon_buffer!(32).unwrap();
/// buffer_a.copy_from_slice(b"Copy this data into that buffer.");
/// println!("{:x?}", &buffer_a[..]);
///
/// let mut buffer_b = anon_buffer!(16).unwrap();
/// buffer_b.copy_from_slice(b"Copy this data i");
///
/// assert!(eq(&buffer_a[..16], &buffer_b[..]).unwrap());
/// ```
#[macro_export]
macro_rules! anon_buffer {
    ($size:expr$(;)?) => {{
        use $crate::mem::hardened_buffer;
        hardened_buffer!(_AlkaliAnonBuffer($size));
        _AlkaliAnonBuffer::new_empty()
    }};
}

pub use anon_buffer;

/// Allocate sufficient hardened memory to store a value of type `T`, returning a pointer to the
/// start of the allocated memory.
///
/// # Safety
/// This function returns a pointer to uninitialised memory, allocated outside of Rust's memory
/// management. As such, all the issues associated with manual memory management in languages like C
/// apply: Memory must be initialised before use, it must be freed exactly once, and not used after
/// having been freed. Memory allocated with this function must be freed using the [`free`] function
/// from this module.
pub unsafe fn malloc<T>() -> Result<NonNull<T>, AlkaliError> {
    // `Layout::new` creates a `Layout` with both the size & alignment requirements of `T`.
    let layout = Layout::new::<T>();
    Ok(malloc_layout(layout)?.cast())
}

/// Allocate a region of hardened memory which meets the size and alignment requirements of
/// `layout`.
///
/// The region of memory allocated may be larger that `layout.size()` if the layout size is not a
/// multiple of the layout alignment.
///
/// # Safety
/// This function returns a pointer to uninitialised memory, allocated outside of Rust's memory
/// management. As such, all the issues associated with manual memory management in languages like C
/// apply: Memory must be initialised before use, it must be freed exactly once, and not used after
/// having been freed. Memory allocated with this function must be freed using the [`free`] function
/// from this module.
pub unsafe fn malloc_layout(layout: Layout) -> Result<NonNull<u8>, AlkaliError> {
    require_init()?;

    // A `Layout` in Rust must have an associated alignment which is a power-of-two. As the region
    // Sodium allocates will be placed at the end of a page boundary, if we pad the layout until its
    // size is a multiple of the alignment, we can guarantee that the allocated region will be
    // aligned correctly.
    let layout = layout.pad_to_align();
    let ptr = sodium::sodium_malloc(layout.size()).cast();

    NonNull::new(ptr).ok_or(AlkaliError::MemoryManagement)
}

/// Free the memory pointed to by `ptr`, previously allocated using [`malloc`]/[`malloc_layout`].
///
/// # Safety
/// This function should only be called with a pointer to memory previously allocated using
/// [`malloc`] or [`malloc_layout`] from this module. This function will cause the program to exit
/// if a buffer overflow is detected (i.e: the canary placed next to the allocated region has been
/// overwritten). This function must be called exactly once for each memory region allocated, and
/// after the region has been freed, it must not be used again.
pub unsafe fn free<T>(ptr: NonNull<T>) {
    // This function should only ever be called after calling `malloc`, which invokes
    // `require_init`, so we don't need to initialise Sodium again here.

    sodium::sodium_free(ptr.as_ptr().cast());
}

/// Constant time test for equality of two slices.
///
/// This function tests whether two byte slices contain the same contents. For the same input size,
/// the time taken to compare the slices is always identical. Returns true if the slices contain
/// the same contents, false otherwise. Always returns false if the slices are not of the same
/// length.
pub fn eq(a: &[u8], b: &[u8]) -> Result<bool, AlkaliError> {
    require_init()?;

    if a.len() != b.len() {
        return Ok(false);
    }

    let comparison_result = unsafe {
        // SAFETY: This function expects two pointers to regions of memory of the same length,
        // specified by the third parameter. We check above to ensure that a and b are of the same
        // length. We use a.len() to specify the length, so it is correct for these slices. This
        // function will not modify the contents of either slice.
        sodium::sodium_memcmp(a.as_ptr().cast(), b.as_ptr().cast(), a.len())
    };

    Ok(comparison_result == 0)
}

/// Zero the contents of `buf`.
///
/// After sensitive data is no longer required, it should be cleared from memory. However, since
/// memory is often not accessed after being cleared, compilers may remove the operation to erase
/// the memory as part of the optimisation process. This function zeroes the memory in such a way
/// that the compiler will not remove the operation.
pub fn clear(buf: &mut [u8]) -> Result<(), AlkaliError> {
    require_init()?;

    unsafe {
        // SAFETY: This function expects a pointer to a region of memory, and a number of bytes to
        // clear starting at that pointer. We pass a pointer to `buf`, and specify `buf.len()`
        // bytes should be cleared. Since `buf` is a slice of `u8`s, it points to `buf.len()`
        // bytes, so the amount of memory to clear here is correct. All zeroes is a valid
        // representation of a u8 slice.
        sodium::sodium_memzero(buf.as_mut_ptr().cast(), buf.len());
    };

    Ok(())
}

/// Test whether `buf` is filled entirely with zeroes, in constant-time for a specific length.
///
/// Returns true if `buf` is filled with all-zeroes, false otherwise. This function will always
/// take the same number of operations to perform the check for a specific length of `buf`.
pub fn is_zero(buf: &[u8]) -> Result<bool, AlkaliError> {
    require_init()?;

    let comparison_result = unsafe {
        // SAFETY: This function expects a pointer to a region of memory, and a number of bytes to
        // test for being zero. We use `buf.len()` as the number of bytes to check, which is the
        // size of `buf` in bytes, so this is correct for this pointer.
        sodium::sodium_is_zero(buf.as_ptr(), buf.len())
    };

    Ok(comparison_result != 0)
}

#[cfg(test)]
mod tests {
    // This set of tests relies on having at least 1 MiB of memory available to allocate.
    // Therefore, these tests may fail on platforms with very limited resources.
    use super::{clear, eq, free, is_zero, malloc};
    use crate::mem::{ProtectNoAccess, ProtectReadOnly, Unprotect};
    use crate::{random, AlkaliError};
    use core::ptr::NonNull;

    #[test]
    fn malloc_allocates_and_free_deallocates() -> Result<(), AlkaliError> {
        unsafe {
            // Test allocations of various sizes
            let mut ptr_a: NonNull<u8> = malloc()?; // 1 byte
            let a = ptr_a.as_mut();
            let mut ptr_b: NonNull<[u8; 1 << 3]> = malloc()?; // 8 bytes
            let b = ptr_b.as_mut();
            let mut ptr_c: NonNull<[u8; 1 << 10]> = malloc()?; // 1 KiB
            let c = ptr_c.as_mut();
            let mut ptr_d: NonNull<[u8; 1 << 20]> = malloc()?; // 1 MiB
            let d = ptr_d.as_mut();

            // Ensure we can write data to the allocated memory
            *a = 0xff;
            random::fill_random(b)?;
            random::fill_random(c)?;
            random::fill_random(d)?;

            // Free everything we've allocated
            free(ptr_a);
            free(ptr_b);
            free(ptr_c);
            free(ptr_d);

            Ok(())
        }
    }

    #[test]
    fn eq_tests() -> Result<(), AlkaliError> {
        let mut buf_a = [0; 1000];
        let mut buf_b = [0; 1000];

        random::fill_random(&mut buf_a)?;
        buf_b.copy_from_slice(&buf_a);

        assert!(eq(&buf_a, &buf_b)?);

        for i in 0..1000 {
            assert!(eq(&buf_a[..i], &buf_b[..i])?);
        }

        assert!(!eq(&buf_a[..500], &buf_b[..501])?);

        buf_b[..500].copy_from_slice(&[0; 500]);

        assert!(!eq(&buf_a, &buf_b)?);
        assert!(!eq(&buf_a[..500], &buf_b[..500])?);
        assert!(eq(&buf_a[500..], &buf_b[500..])?);

        buf_a[..500].copy_from_slice(&[0; 500]);

        assert!(eq(&buf_a, &buf_b)?);

        Ok(())
    }

    #[test]
    fn clear_tests() -> Result<(), AlkaliError> {
        for _ in 0..1000 {
            let mut buf = [0u8; 1000];
            let l = random::random_u32_in_range(0, 1000)? as usize;
            random::fill_random(&mut buf[..l])?;
            clear(&mut buf[..l])?;
            assert_eq!(&buf, &[0; 1000]);
        }

        Ok(())
    }

    #[test]
    fn is_zero_tests() -> Result<(), AlkaliError> {
        for _ in 0..1000 {
            let mut buf = [0u8; 1000];
            let l = random::random_u32_in_range(100, 1000)? as usize;
            assert!(is_zero(&buf[..l])?);
            random::fill_random(&mut buf[..l])?;
            assert!(!is_zero(&buf[..l])?);
            clear(&mut buf[..l])?;
            assert!(is_zero(&buf[..l])?);
        }

        Ok(())
    }

    #[test]
    fn mprotect() -> Result<(), AlkaliError> {
        let buf = anon_buffer!(32)?;
        // should be permissible to mprotect a buffer to the same protection status
        let mut buf = buf.unprotect()?;
        buf.copy_from_slice(b"00001111222233334444555566667777");

        let buf = buf.protect_read_only()?;
        assert_eq!(&buf[..], b"00001111222233334444555566667777");
        let mut buf = buf.unprotect()?;
        buf.copy_from_slice(b"11112222333344445555666677778888");
        assert_eq!(&buf[..], b"11112222333344445555666677778888");

        let buf = buf.protect_no_access()?;
        let buf = buf.unprotect()?;
        assert_eq!(&buf[..], b"11112222333344445555666677778888");
        let buf = buf.protect_read_only()?;
        let buf = buf.protect_no_access()?;
        let buf = buf.protect_read_only()?;
        assert_eq!(&buf[..], b"11112222333344445555666677778888");

        Ok(())
    }
}
