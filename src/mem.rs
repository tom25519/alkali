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
//! API](https://doc.rust-lang.org/std/alloc/trait.Allocator.html), which allows for user-defined
//! allocators for many common Rust types (`Vec`, `Box`, etc.). The [`SodiumAllocator`] struct
//! implements the `Allocator` trait, and can therefore be used for this purpose, providing an
//! allocator based on Sodium's secure memory management tools. Similarly, the [`HardenedVec`] and
//! [`HardenedBox`] types use this allocator to secure their contents.
//!
//! However, the allocator API is still not stable, and is only available in nightly Rust.
//! Therefore, access to these types is feature-gated behind the `alloc` feature. You can enable
//! this if you wish to make use of the API, but it will cause builds to fail on stable Rust.

use crate::{require_init, AlkaliError};
use libsodium_sys as sodium;
use std::alloc::Layout;
#[cfg(feature = "alloc")]
use std::alloc::{AllocError, Allocator};
use std::ptr::NonNull;

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
/// * [`AsRef<[u8; $size]>`](std::convert::AsRef) and [`AsMut<[u8; $size]>`](std::convert::AsMut)
/// * [`Borrow<[u8; $size]>`](std::borrow::Borrow) and
///   [`BorrowMut<[u8; $size]>`](std::borrow::BorrowMut)
/// * [`Debug`](std::fmt::Debug)
/// * [`Deref`](std::ops::Deref) and [`DerefMut`](std::ops::DerefMut)
/// * [`PartialEq<Self>`](std::cmp::PartialEq) and [`Eq<Self>`](std::cmp::Eq)
///     * This operation uses a constant-time comparison, so it can be used to compare buffers
///       without the risk of side-channel attacks
/// * [`Pointer`](std::fmt::Pointer)
/// * [`TryFrom<&[u8]>`](std::convert::TryFrom)
/// * [`TryFrom<&[u8; $size]>`](std::convert::TryFrom)
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
            $vis struct $name {
                ptr: std::ptr::NonNull<[u8; $size]>,
                _marker: std::marker::PhantomData<[u8; $size]>,
            }

            impl $name {
                pub const LENGTH: usize = $size as usize;

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
                        let ptr = $crate::mem::malloc()?;

                        // SAFETY: This function expects a pointer to a region of memory, and a
                        // number of bytes to clear starting at that pointer. We allocate `$size`
                        // bytes of memory at `ptr` in the line above, and specify `$size` bytes
                        // should be cleared, so the amount of memory to clear here is correct. All
                        // zeroes is a valid representation of a `u8` slice.
                        libsodium_sys::sodium_memzero(ptr.as_ptr() as *mut libc::c_void, $size);

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
                    $crate::mem::clear(self.as_mut())
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
                        //     or `std::mem::forget`, the destructor will not be called even though
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

            impl TryFrom<&[u8]> for $name {
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

            impl std::cmp::Eq for $name {}

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
                    $crate::mem::eq(self.as_ref(), other.as_ref()).unwrap()
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
/// * [`AsRef<[u8; $size]>`](std::convert::AsRef) and [`AsMut<[u8; $size]>`](std::convert::AsMut)
/// * [`Borrow<[u8; $size]>`](std::borrow::Borrow) and
///   [`BorrowMut<[u8; $size]>`](std::borrow::BorrowMut)
/// * [`Debug`](std::fmt::Debug)
/// * [`Deref`](std::ops::Deref) and [`DerefMut`](std::ops::DerefMut)
/// * [`Pointer`](std::fmt::Pointer)
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
    let ptr = sodium::sodium_malloc(layout.size()) as *mut u8;

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

    sodium::sodium_free(ptr.as_ptr() as *mut libc::c_void)
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
        sodium::sodium_memcmp(
            a.as_ptr() as *const libc::c_void,
            b.as_ptr() as *const libc::c_void,
            a.len(),
        )
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
        sodium::sodium_memzero(buf.as_mut_ptr() as *mut libc::c_void, buf.len());
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
    use crate::{random, AlkaliError};
    use std::ptr::NonNull;

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
            let mut buf = vec![0; random::random_u32_in_range(0, 1000)? as usize];
            random::fill_random(&mut buf)?;
            clear(&mut buf)?;
            assert_eq!(&buf, &vec![0; buf.len()]);
        }

        Ok(())
    }

    #[test]
    fn is_zero_tests() -> Result<(), AlkaliError> {
        for _ in 0..1000 {
            let mut buf = vec![0; random::random_u32_in_range(100, 1000)? as usize];
            assert!(is_zero(&buf)?);
            random::fill_random(&mut buf)?;
            assert!(!is_zero(&buf)?);
            clear(&mut buf)?;
            assert!(is_zero(&buf)?);
        }

        Ok(())
    }
}
