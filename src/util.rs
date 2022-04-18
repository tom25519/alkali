//! General utilities from Sodium.

use crate::{require_init, AlkaliError};
use libsodium_sys as sodium;

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

/// Add padding to `buf` to extend its length to a multiple of `blocksize`.
///
/// `blocksize` must be at least `1`, otherwise an error will be returned.
///
/// # Security Considerations
/// If hiding the length of a plaintext is desired, padding should be applied prior to encryption,
/// and removed after decryption.
pub fn pad(buf: &mut Vec<u8>, blocksize: usize) -> Result<(), AlkaliError> {
    require_init()?;

    if blocksize == 0 {
        return Err(AlkaliError::PaddingError);
    }

    let original_len = buf.len();

    // Add `blocksize` zeroes to `buf`: This is the most that could possibly be added via padding
    buf.resize(original_len + blocksize, 0x00);

    let mut padded_len = 0usize;

    let pad_result = unsafe {
        // SAFETY: The first argument to this function is the destination to which the padded
        // length will be written. We just pass a mutable reference to a `usize`, which is the
        // expected type for this destination. The next argument specifies a pointer to the buffer
        // to extend. The next argument specifies the unpadded length of `buf`: We obtained
        // `original_len` above using `buf.len()`, and then increased the size of the buffer, so
        // `buf` is definitely at least as large as this. The next argument specifies the block
        // size to pad to. This can be any size. The final argument is the maximum length that the
        // padded buffer can be, i.e: The amount of storage allocated for `buf`. We use `buf.len()`
        // to specify this, so this many bytes can definitely be written to `buf`.
        sodium::sodium_pad(
            &mut padded_len,
            buf.as_mut_ptr(),
            original_len,
            blocksize,
            buf.len(),
        )
    };

    if pad_result != 0 {
        return Err(AlkaliError::PaddingError);
    }

    // Remove any excess zeroes we added when resizing `buf` above
    buf.truncate(padded_len);

    Ok(())
}

/// Compute the original, unpadded length of `buf`, and return the slice of `buf` without padding.
///
/// `buf` should have been previously padded using [`pad`].
///
/// `blocksize` must be at least `1`, otherwise an error will be returned. Returns an error if
/// `buf` does not appear to be correctly padded.
///
/// # Security Considerations
/// If hiding the length of a plaintext is desired, padding should be applied prior to encryption,
/// and removed after decryption.
pub fn unpad(buf: &[u8], blocksize: usize) -> Result<&[u8], AlkaliError> {
    require_init()?;

    if blocksize == 0 {
        return Err(AlkaliError::UnpaddingError);
    }

    let mut unpadded_len = 0;

    let unpad_result = unsafe {
        // SAFETY: The first argument to this function is the destination to which the unpadded
        // length will be written. We just pass a mutable reference to a `usize`, which is the
        // expected type for this destination. The next two arguments specify a pointer to the
        // buffer for which we should calculate the original length, and its size. We use
        // `buf.len()` to specify the length, so it is definitely correct for this pointer. The
        // final argument specifies the block size which `buf` has been padded to, which can be any
        // value.
        sodium::sodium_unpad(&mut unpadded_len, buf.as_ptr(), buf.len(), blocksize)
    };

    if unpad_result != 0 {
        return Err(AlkaliError::UnpaddingError);
    }

    Ok(&buf[..unpadded_len])
}

#[cfg(test)]
mod tests {
    use super::{add_le, compare_le, increment_le, pad, sub_le, unpad};
    use crate::{mem, random, AlkaliError};

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

            assert!(!mem::is_zero(&buf1)?);

            buf2.copy_from_slice(&buf1);
            sub_le(&mut buf1, &buf2)?;

            assert!(mem::is_zero(&buf1)?);
        }

        let mut buf_add = [0; 1000];
        random::fill_random(&mut buf1)?;
        random::fill_random(&mut buf2)?;

        add_le(&mut buf_add, &buf1)?;
        add_le(&mut buf_add, &buf2)?;
        sub_le(&mut buf_add, &buf1)?;
        sub_le(&mut buf_add, &buf2)?;

        assert!(mem::is_zero(&buf_add)?);

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

    #[test]
    fn pad_and_unpad() -> Result<(), AlkaliError> {
        for _ in 0..2000 {
            let mut buf = vec![0; random::random_u32_in_range(0, 200)? as usize];
            let buf_clone = buf.clone();
            let blocksize = random::random_u32_in_range(1, 501)? as usize;

            pad(&mut buf, blocksize)?;
            assert_eq!(buf.len() % blocksize, 0);
            assert_eq!(&buf[..buf_clone.len()], &buf_clone);

            assert_eq!(unpad(&buf, blocksize)?, &buf_clone);
        }

        Ok(())
    }
}
