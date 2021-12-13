//! Low-level memory management utilities.

use crate::{require_init, AlkaliError};
use libsodium_sys as sodium;
use std::ptr::NonNull;

/// Allocate sufficient hardened memory to store a value of type `T`, returning a pointer to the
/// start of the allocated memory.
///
/// Uses the Sodium function `sodium_malloc` to securely allocate a region of memory, which will be
/// `mlock`ed, and surrounded with guard pages.
///
/// Returns `Ok(ptr)`, where `ptr` is a pointer to the newly-allocated memory, if allocation was
/// successful, otherwise returns an [`AlkaliError`].
///
/// # Safety
/// This function returns a pointer to uninitialised memory, allocated outside of Rust's memory
/// management. As such, all the issues associated with manual memory management in languages like
/// C apply: Memory must be initialised before use, it must be freed exactly once, and not used
/// after having been freed. Memory allocated with this function should be freed using [`free`]
/// from this module, rather than any other memory management tool, to preserve Sodium's security
/// invariants.
pub unsafe fn malloc<T>() -> Result<NonNull<T>, AlkaliError> {
    require_init()?;

    // Returns a `*mut c_void`, cast to `*mut ()`. If allocation is successful, this will be a
    // pointer to sufficient allocated memory to store a `T` value. Otherwise, it will be NULL.
    let ptr = sodium::sodium_malloc(std::mem::size_of::<T>()) as *mut ();
    // We use the `NonNull::new` method, which returns `None` in the case that we pass it a NULL
    // pointer, to detect the case where allocation fails.
    NonNull::new(ptr)
        .map(|p| p.cast())
        .ok_or(AlkaliError::MemoryManagement)
}

/// Free the memory pointed to by `ptr`, previously allocated using [`malloc`] from this module.
///
/// Uses the Sodium function `sodium_free` to securely zero and deallocate memory previously
/// allocated using `sodium_malloc`.
///
/// # Safety
/// This function should only be called with a pointer to memory previously allocated using
/// [`malloc`] from this module. This function will cause the program to exit if a buffer overrun
/// is detected (i.e: the canary placed next to the allocated region has been overwritten).
pub unsafe fn free<T>(ptr: NonNull<T>) {
    // We don't use `require_init` here, since it should only be called after `malloc`, which does
    // initialise Sodium.
    // `sodium_free` has no return type in libsodium: It will simply exit if there is an error, as
    // there can only be an error if something dangerous has occurred.
    sodium::sodium_free(ptr.as_ptr() as *mut libc::c_void)
}

/// Zero the memory region pointed to by `ptr`.
///
/// Uses `sodium_memzero` to zero memory in such a way that the compiler will not optimise away the
/// operation.
///
/// # Safety
/// This function should only be called with a pointer to at least `size` bytes of allocated,
/// writeable memory, where `size` is the size of a value of type `T`. If `size` is larger than the
/// allocated region, undefined behaviour will occur.
pub unsafe fn memzero<T>(ptr: NonNull<T>) -> Result<(), AlkaliError> {
    require_init()?;

    sodium::sodium_memzero(ptr.as_ptr() as *mut libc::c_void, std::mem::size_of::<T>());
    Ok(())
}

/// Compare two regions of memory for equality in constant-time.
///
/// Uses `sodium_memcmp` for constant-time comparison of two memory regions, to prevent timing
/// attacks. The length of the region compared is determined by the size of the type `T`. Returns
/// true if the contents of the memory regions are equal, false if they are non-equal, or an
/// [`AlkaliError`] if an error occurred.
///
/// # Safety
/// Both `a` and `b` must be pointers to regions of allocated memory of length at least `size`
/// bytes, where `size` is the size of a value of type `T`. If `size` is larger than either
/// allocated region, undefined behaviour will occur.
pub unsafe fn memcmp<T>(a: NonNull<T>, b: NonNull<T>) -> Result<bool, AlkaliError> {
    require_init()?;

    Ok(sodium::sodium_memcmp(
        a.as_ptr() as *const libc::c_void,
        b.as_ptr() as *const libc::c_void,
        std::mem::size_of::<T>(),
    ) == 0)
}

#[cfg(test)]
mod tests {
    // This set of tests relies on having at least 1 MiB of memory available to allocate.
    // Therefore, these tests may fail on platforms with very limited resources.
    use super::{free, malloc, memcmp, memzero};
    use crate::random::fill_random;
    use crate::AlkaliError;
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
            fill_random(b)?;
            fill_random(c)?;
            fill_random(d)?;

            // Free everything we've allocated
            free(ptr_a);
            free(ptr_b);
            free(ptr_c);
            free(ptr_d);

            Ok(())
        }
    }

    #[test]
    fn memzero_does_zero() -> Result<(), AlkaliError> {
        unsafe {
            let mut ptr_a: NonNull<u8> = malloc()?;
            let a = ptr_a.as_mut();
            let mut ptr_b: NonNull<[u8; 1 << 3]> = malloc()?;
            let b = ptr_b.as_mut();
            let mut ptr_c: NonNull<[u8; 1 << 10]> = malloc()?;
            let c = ptr_c.as_mut();
            let mut ptr_d: NonNull<[u8; 1 << 20]> = malloc()?;
            let d = ptr_d.as_mut();

            // Write some data to the memory which we will then clear
            *a = 0xff;
            fill_random(b)?;
            fill_random(c)?;
            fill_random(d)?;

            // Clear the memory
            memzero(ptr_a)?;
            memzero(ptr_b)?;
            memzero(ptr_c)?;
            memzero(ptr_d)?;

            // Ensure the memory was cleared successfully
            assert_eq!(*a, 0);
            assert_eq!(b, &[0; 1 << 3]);
            assert_eq!(c, &[0; 1 << 10]);
            assert_eq!(d, &[0; 1 << 20]);

            free(ptr_a);
            free(ptr_b);
            free(ptr_c);
            free(ptr_d);

            Ok(())
        }
    }

    #[test]
    fn memcmp_comparison_correct() -> Result<(), AlkaliError> {
        unsafe {
            let mut ptr_a: NonNull<[u8; 8]> = malloc()?;
            let a = ptr_a.as_mut();
            let mut ptr_b: NonNull<[u8; 8]> = malloc()?;
            let b = ptr_b.as_mut();

            // Compare two equal slices
            a.copy_from_slice(&[0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe]);
            b.copy_from_slice(&[0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe]);
            assert!(memcmp(ptr_a, ptr_b)?);

            // Change the first byte of the second memory region & ensure the regions are no longer
            // considered equal
            b.copy_from_slice(&[0xff, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe]);
            assert!(!memcmp(ptr_a, ptr_b)?);

            // Now change the final byte
            b.copy_from_slice(&[0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xff]);
            assert!(!memcmp(ptr_a, ptr_b)?);

            // And a couple of bytes in the middle for good measure
            b.copy_from_slice(&[0xde, 0xad, 0xbe, 0x00, 0x00, 0xfe, 0xba, 0xbe]);
            assert!(!memcmp(ptr_a, ptr_b)?);

            free(ptr_a);
            free(ptr_b);

            Ok(())
        }
    }
}
