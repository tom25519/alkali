//! General utilities from Sodium.

use crate::{require_init, AlkaliError};
use libsodium_sys as sodium;

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

/// Treat `number` as a little-endian, unsigned integer, and increment its value by 1.
///
/// Increments `number` in-place.
///
/// This function runs in constant-time for a specific length of `number` (in bytes). This is
/// especially useful for incrementing nonces for messages in sequence.
pub fn increment_le(number: &mut [u8]) -> Result<(), AlkaliError> {
    require_init()?;

    unsafe {
        // SAFETY: This function expects a pointer to a region of memory and a number of bytes to
        // interpret as a little endian number. We use `number.len()` as the number of bytes, which
        // is the size of `number` in bytes, so this is correct for this pointer.
        sodium::sodium_increment(number.as_mut_ptr(), number.len());
    }

    Ok(())
}

/// Add `summand` to `number`, treating both as little-endian, unsigned integers, and writing the
/// result to `number`.
///
/// The computation is calculated `mod 2^(8 * len)`: In short, the standard wrapping behaviour for
/// unsigned integers is to be expected. The computation runs in constant time for a given length
/// of `number` & `summand` (in bytes).
///
/// Returns an error if `number` and `summand` are not the same length.
pub fn add_le(number: &mut [u8], summand: &[u8]) -> Result<(), AlkaliError> {
    require_init()?;

    if number.len() != summand.len() {
        return Err(AlkaliError::NumberLengthsDiffer);
    }

    unsafe {
        // SAFETY: This function expects two pointers to numbers to add, and the length of the
        // numbers. We verify above that the `number` and `summand` slices are of the same length,
        // and use `number.len()` to specify the length of the two numbers. This is therefore the
        // correct length for these pointers.
        sodium::sodium_add(number.as_mut_ptr(), summand.as_ptr(), number.len());
    }

    Ok(())
}

/// Subtract `subtrahend` from `minuend`, treating both as little-endian, unsigned integers, and
/// writing the difference to `minuend`.
///
/// The computation is calculated `mod 2^(8 * len)`: In short, the standard wrapping behaviour for
/// unsigned integers is to be expected. The computation runs in constant time for a given length
/// of `minuend` & `subtrahend` (in bytes).
///
/// Returns an error if `minuend` and `subtrahend` are not the same length.
pub fn sub_le(minuend: &mut [u8], subtrahend: &[u8]) -> Result<(), AlkaliError> {
    require_init()?;

    if minuend.len() != subtrahend.len() {
        return Err(AlkaliError::NumberLengthsDiffer);
    }

    unsafe {
        // SAFETY: This function expects two pointers to numbers to subtract, and the length of the
        // numbers. We verify above that the `minuend` and `subtrahend` slices are of the same
        // length, and use `minuend.len()` to specify the length of the two numbers. This is
        // therefore the correct length for these pointers.
        sodium::sodium_sub(minuend.as_mut_ptr(), subtrahend.as_ptr(), minuend.len());
    }

    Ok(())
}

/// Treat `a` and `b` as little-endian, unsigned integers, and compare them.
///
/// Returns:
/// * [`std::cmp::Ordering::Less`] if `a` is less than `b`
/// * [`std::cmp::Ordering::Equal`] if `a` equals `b`
/// * [`std::cmp::Ordering::Greater`] if `a` is greater than `b`
/// * An error if `a` and `b` are not the same length (in bytes)
///
/// This comparison runs in constant time for a given length of `a` & `b`.
pub fn compare_le(a: &[u8], b: &[u8]) -> Result<std::cmp::Ordering, AlkaliError> {
    require_init()?;

    if a.len() != b.len() {
        return Err(AlkaliError::NumberLengthsDiffer);
    }

    let comparison = unsafe {
        // SAFETY: This function expects two pointers to numbers to compare, and the length of the
        // numbers. We verify above that the `a` and `b` slices are of the same length, and use
        // `a.len()` to specify the length of the two numbers. This is therefore the correct length
        // for these pointers.
        sodium::sodium_compare(a.as_ptr(), b.as_ptr(), a.len())
    };

    match comparison {
        -1 => Ok(std::cmp::Ordering::Less),
        0 => Ok(std::cmp::Ordering::Equal),
        1 => Ok(std::cmp::Ordering::Greater),
        _ => unreachable!(),
    }
}

#[cfg(test)]
mod tests {
    use super::{add_le, clear, compare_le, eq, increment_le, is_zero, sub_le};
    use crate::{random, AlkaliError};

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

    #[test]
    fn increment_le_vectors() -> Result<(), AlkaliError> {
        let mut nonce = [0; 24];

        increment_le(&mut nonce)?;
        assert_eq!(
            &nonce,
            &[
                0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            ]
        );

        nonce.fill(0xff);
        increment_le(&mut nonce)?;
        assert_eq!(
            &nonce,
            &[
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            ]
        );

        nonce[1] = 0x01;
        increment_le(&mut nonce)?;
        assert_eq!(
            &nonce,
            &[
                0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            ]
        );

        nonce[1] = 0x00;
        increment_le(&mut nonce)?;
        assert_eq!(
            &nonce,
            &[
                0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            ]
        );

        nonce[0] = 0xff;
        nonce[2] = 0xff;
        increment_le(&mut nonce)?;
        assert_eq!(
            &nonce,
            &[
                0x00, 0x01, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            ]
        );

        nonce[..6].fill(0xff);
        nonce[6..].fill(0xfe);
        increment_le(&mut nonce[..8])?;
        assert_eq!(
            &nonce,
            &[
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe,
                0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe
            ]
        );

        nonce[..10].fill(0xff);
        increment_le(&mut nonce[..12])?;
        assert_eq!(
            &nonce,
            &[
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xfe, 0xfe, 0xfe,
                0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe
            ]
        );

        nonce[..22].fill(0xff);
        increment_le(&mut nonce)?;
        assert_eq!(
            &nonce,
            &[
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xfe
            ]
        );

        Ok(())
    }

    #[test]
    fn add_equivalent_to_repeated_increment() -> Result<(), AlkaliError> {
        let mut buf1 = vec![0; random::random_u32_in_range(0, 1000)? as usize];
        let mut buf_add = buf1.clone();
        random::fill_random(&mut buf1)?;
        let mut buf2 = buf1.clone();

        for _ in 0..random::random_u32_in_range(0, 10000)? {
            increment_le(&mut buf1)?;
            increment_le(&mut buf_add)?;
        }

        add_le(&mut buf2, &buf_add)?;

        assert_eq!(compare_le(&buf1, &buf2)?, std::cmp::Ordering::Equal);

        Ok(())
    }

    #[test]
    fn add_wrapping_behaviour() -> Result<(), AlkaliError> {
        let mut buf1 = vec![0; random::random_u32_in_range(0, 1000)? as usize];
        random::fill_random(&mut buf1)?;
        let mut buf2 = buf1.clone();
        let buf_add = vec![0xff; buf1.len()];

        increment_le(&mut buf2)?;
        add_le(&mut buf2, &buf_add)?;

        assert_eq!(compare_le(&buf1, &buf2)?, std::cmp::Ordering::Equal);

        Ok(())
    }

    #[test]
    fn add_and_subtract_le() -> Result<(), AlkaliError> {
        let mut buf1 = [0; 1000];
        let mut buf2 = [0; 1000];

        for _ in 0..1000 {
            random::fill_random(&mut buf1)?;
            random::fill_random(&mut buf2)?;

            add_le(&mut buf1, &buf2)?;
            sub_le(&mut buf1, &buf2)?;

            assert!(!is_zero(&buf1)?);

            buf2.copy_from_slice(&buf1);
            sub_le(&mut buf1, &buf2)?;

            assert!(is_zero(&buf1)?);
        }

        let mut buf_add = [0; 1000];
        random::fill_random(&mut buf1)?;
        random::fill_random(&mut buf2)?;

        add_le(&mut buf_add, &buf1)?;
        add_le(&mut buf_add, &buf2)?;
        sub_le(&mut buf_add, &buf1)?;
        sub_le(&mut buf_add, &buf2)?;

        assert!(is_zero(&buf_add)?);

        Ok(())
    }

    #[test]
    fn add_vectors() -> Result<(), AlkaliError> {
        let mut nonce = [0xfe; 24];
        let mut nonce2 = [0; 24];
        nonce[..6].fill(0xff);
        nonce2.copy_from_slice(&nonce);
        add_le(&mut nonce[..7], &nonce2[..7])?;
        nonce2.copy_from_slice(&nonce);
        add_le(&mut nonce[..8], &nonce2[..8])?;
        assert_eq!(
            &nonce,
            &[
                0xfc, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfb, 0xfd, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe,
                0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe
            ]
        );

        nonce[..10].fill(0xff);
        nonce2.copy_from_slice(&nonce);
        add_le(&mut nonce[..11], &nonce2[..11])?;
        nonce2.copy_from_slice(&nonce);
        add_le(&mut nonce[..12], &nonce2[..12])?;
        assert_eq!(
            &nonce,
            &[
                0xfc, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfb, 0xfd, 0xfe, 0xfe,
                0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe,
            ]
        );

        nonce[..22].fill(0xff);
        nonce2.copy_from_slice(&nonce);
        add_le(&mut nonce[..23], &nonce2[..23])?;
        nonce2.copy_from_slice(&nonce);
        add_le(&mut nonce, &nonce2)?;
        assert_eq!(
            &nonce,
            &[
                0xfc, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfb, 0xfd,
            ]
        );

        Ok(())
    }

    #[test]
    fn compare_random() -> Result<(), AlkaliError> {
        let mut buf1 = [0; 1000];
        let mut buf2 = [0; 1000];

        for _ in 0..1000 {
            random::fill_random(&mut buf1)?;
            random::fill_random(&mut buf2)?;

            let compare_result = compare_le(&buf1, &buf2)? as i8 as i32;
            buf1.reverse();
            buf2.reverse();
            let memcmp_result = unsafe {
                // SAFETY: The memcmp function takes three arguments, `ptr1`, `ptr2`, and `len`,
                // and compares the `len` bytes starting at `ptr1` with `len` bytes starting at
                // `ptr2`. We have defined `buf1` and `buf2` to be 1000 bytes each, so we can read
                // 1000 bytes from the pointer starting at `buf1` and the pointer starting at
                // `buf2`.
                libc::memcmp(
                    buf1.as_ptr() as *const libc::c_void,
                    buf2.as_ptr() as *const libc::c_void,
                    1000,
                )
            };

            assert!(compare_result * memcmp_result > 0);
        }

        Ok(())
    }
}
