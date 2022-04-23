//! General utilities from Sodium.

use crate::{assert_not_err, require_init, AlkaliError};
use libsodium_sys as sodium;

/// Treat `number` as a little-endian, unsigned integer, and increment its value by 1.
///
/// Increments `number` in-place. This function is especially useful for incrementing nonces for
/// messages in sequence.
///
/// This function runs in constant-time for a given length of `number` (in bytes).
pub fn increment_le(number: &mut [u8]) -> Result<(), AlkaliError> {
    require_init()?;

    unsafe {
        // SAFETY: This function expects a pointer and a number of bytes to interpret as a little
        // endian number, starting at that pointer. We use `number.len()` as the number of bytes,
        // which is the size of `number` in bytes, so `number` is valid for reads and writes of this
        // length.
        sodium::sodium_increment(number.as_mut_ptr(), number.len());
    }

    Ok(())
}

/// Add `summand` to `number`, treating both as little-endian, unsigned integers, and writing the
/// result to `number`.
///
/// `number` and `summand` must be of the same length, otherwise an error will be returned. Since
/// the calculation is little-endian, if one value is shorter than the other, you can pad the
/// shorter value with zeros at the end so the slices are of equal length to obtain a
/// representation of the same value which can be used with this function.
///
/// The computation is calculated modulo `2^(8 * number.len())`: In short, the standard wrapping
/// behaviour for unsigned integers is to be expected. So if `number` was 4 bytes long, the sum
/// would be calculated modulo `2^32`, like if you were adding normal [`u32`] values.
///
/// The computation runs in constant time for a given length of `number` (in bytes).
pub fn add_le(number: &mut [u8], summand: &[u8]) -> Result<(), AlkaliError> {
    require_init()?;

    if number.len() != summand.len() {
        return Err(AlkaliError::NumberLengthsDiffer);
    }

    unsafe {
        // SAFETY: This function expects two pointers to numbers to add, and the length of the
        // values to read from each pointer, in bytes. We verify above that the `number` and
        // `summand` slices are of the same length, and use `number.len()` to specify the length of
        // the two numbers. Therefore `number` is valid for reads and writes of this length, and
        // `summand` is valid for reads of this length.
        sodium::sodium_add(number.as_mut_ptr(), summand.as_ptr(), number.len());
    }

    Ok(())
}

/// Subtract `subtrahend` from `number`, treating both as little-endian, unsigned integers, and
/// writing the difference to `number`.
///
/// `number` and `subtrahend` must be of the same length, otherwise an error will be returned. Since
/// the calculation is little-endian, if one value is shorter than the other, you can pad the
/// shorter value with zeros at the end so the slices are of equal length to obtain a
/// representation of the same value which can be used with this function.
///
/// The computation is calculated modulo `2^(8 * number.len())`: In short, the standard wrapping
/// behaviour for unsigned integers is to be expected. So if `number` was 4 bytes long, the
/// difference would be calculated modulo `2^32`, like if you were adding normal [`u32`] values.
///
/// The computation runs in constant time for a given length of `number` (in bytes).
pub fn sub_le(number: &mut [u8], subtrahend: &[u8]) -> Result<(), AlkaliError> {
    require_init()?;

    if number.len() != subtrahend.len() {
        return Err(AlkaliError::NumberLengthsDiffer);
    }

    unsafe {
        // SAFETY: This function expects two pointers to numbers to find the difference of, and the
        // length of the values to read from each pointer, in bytes. We verify above that the
        // `number` and `subtrahend` slices are of the same length, and use `number.len()` to
        // specify the length of the two numbers. Therefore `number` is valid for reads and writes
        // of this length, and `subtrahend` is valid for reads of this length.
        sodium::sodium_sub(number.as_mut_ptr(), subtrahend.as_ptr(), number.len());
    }

    Ok(())
}

/// Treat `a` and `b` as little-endian, unsigned integers, and compare their values.
///
/// `a` and `b` must be of the same length, otherwise an error will be returned. Since the
/// calculation is little-endian, if one value is shorter than the other, you can pad the shorter
/// value with zeros at the end so the slices are of equal length to obtain a representation of the
/// same value which can be used with this function.
///
/// This function may be used with nonces to prevent replay attacks.
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
        // values to read from each pointer, in bytes. We verify above that the `a` and `b` slices
        // are of the same length, and use `a.len()` to specify the length of the two numbers.
        // Therefore `a` and `b` are valid for reads of this length.
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
/// This function is useful if you wish to obscure the length of an encrypted message.
///
/// `blocksize` must be at least `1`, otherwise an error will be returned.
///
/// # Algorithm Details
/// This function uses [ISO/IEC
/// 7816-4](https://en.wikipedia.org/wiki/Padding_(cryptography)#ISO/IEC_7816-4) padding.
///
/// # Security Considerations
/// If hiding the length of a plaintext is desired, padding should be applied prior to encryption,
/// and removed after decryption.
///
/// Some thought is required to ensure that sufficient padding is applied in some circumstances.
/// Consider a scenario in which "A" can only send one of two messages to "B", one of which is 1
/// byte long, and the other is 100 bytes long. If "A" pads to a blocksize of 16, then the length of
/// the encrypted message will *still* reveal which of the two messages was sent (the first message
/// will be padded to 16 bytes, the second to 112). This example is obviously contrived, but you
/// should ensure that your padding scheme is appropriate for your use case.
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
        // SAFETY: The first argument to this function is a pointer to which the final padded length
        // will be written. We pass a mutable reference to a `usize`, which is the expected type for
        // this argument. The next argument specifies a pointer to the buffer to extend. The next
        // argument specifies the unpadded length of `buf`: We obtained `original_len` above using
        // `buf.len()`, and then increased the size of the buffer, so `buf` is definitely at least
        // as large as this. The next argument specifies the block size to pad to. This can be any
        // size greater than zero, which we verify above. The final argument is the maximum length
        // to which the buffer can be padded, i.e: The amount of storage allocated for `buf`. We use
        // `buf.len()` to specify this, so `buf` is definitely valid for writes of this size.
        sodium::sodium_pad(
            &mut padded_len,
            buf.as_mut_ptr(),
            original_len,
            blocksize,
            buf.len(),
        )
    };

    assert_not_err!(pad_result, "sodium_pad");

    // Remove excess zeroes we added when resizing `buf` above
    buf.truncate(padded_len);

    Ok(())
}

/// Compute the original, unpadded length of `buf`, and return the slice of `buf` without padding.
///
/// `buf` should have been previously padded using [`pad`].
///
/// `blocksize` must be at least `1`, otherwise an error will be returned.
///
/// Returns an error if `buf` does not appear to be correctly padded.
///
/// # Algorithm Details
/// This function uses [ISO/IEC
/// 7816-4](https://en.wikipedia.org/wiki/Padding_(cryptography)#ISO/IEC_7816-4) padding.
pub fn unpad(buf: &[u8], blocksize: usize) -> Result<&[u8], AlkaliError> {
    require_init()?;

    if blocksize == 0 || buf.len() < blocksize {
        return Err(AlkaliError::UnpaddingError);
    }

    let mut unpadded_len = 0;

    let unpad_result = unsafe {
        // SAFETY: The first argument to this function is a pointer to which the unpadded length
        // will be written. We pass a mutable reference to a `usize`, which is the expected type for
        // this argument. The next two arguments specify a pointer to the padded buffer for which we
        // should calculate the original length, and its length. We use `buf.len()` to specify the
        // length, so `buf` is definitely valid for reads of this length. The final argument
        // specifies the block size which `buf` has been padded to, which can be any non-zero value.
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
