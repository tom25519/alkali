//! General utilities from Sodium.

use crate::{require_init, AlkaliError};
use libsodium_sys as sodium;
use std::ffi::CString;
use std::ptr;

/// Different variants of Base64 encoding supported by Sodium.
///
/// Different Base64 alphabets & padding settings are used for different applications.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Base64Variant {
    /// The standard Base64 alphabet, `[A-Za-z0-9+/=]`
    Original = sodium::sodium_base64_VARIANT_ORIGINAL,

    /// The standard Base64 alphabet, `[A-Za-z0-9+/]`, with no padding appended
    NoPadding = sodium::sodium_base64_VARIANT_ORIGINAL_NO_PADDING,

    /// The URL-safe Base64 alphabet, `[A-Za-z0-9-_=]`
    URLSafe = sodium::sodium_base64_VARIANT_URLSAFE,

    /// The URL-safe Base64 alphabet, `[A-Za-z0-9-_]`, with no padding appended
    URLSafeNoPadding = sodium::sodium_base64_VARIANT_URLSAFE_NO_PADDING,
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

/// Encode the contents of `buf` (raw bytes) as a hex string (suitable for printing).
///
/// Returns the hex-encoded contents of `buf`. This can later be decoded back to raw bytes using
/// [`decode_hex`].
///
/// This encoding runs in constant-time for a given length of `buf`.
pub fn encode_hex(buf: &[u8]) -> Result<String, AlkaliError> {
    require_init()?;

    let mut out = vec![0u8; (buf.len() * 2) + 1];

    let hex_len = unsafe {
        // SAFETY: The first argument to this function is the destination pointer to which the
        // C-formatted string will be written. The second argument specifies the maximum number of
        // bytes which can be written to this pointer. We use `out.len()` to specify the number of
        // bytes which can be written, so this number of bytes can definitely be written to `out`.
        // The next two arguments specify the buffer to encode, and its length. We use `buf.len()`
        // to specify the number of bytes to encode, so it is correct for this pointer.
        sodium::sodium_bin2hex(
            out.as_mut_ptr() as *mut libc::c_char,
            out.len(),
            buf.as_ptr(),
            buf.len(),
        );

        // SAFETY: This is a binding to the strlen function from the C standard library. This
        // function takes a pointer to a C-formatted string (with null byte) as an argument, and
        // returns the (inclusive) length to the nul byte. The `bin2hex` function above was used to
        // fill the contents of `out`, which Sodium guarantees will produce a valid C string,
        // including null byte. Therefore, it is safe to use strlen to determine the length of the
        // string, including the null byte.
        libc::strlen(out.as_ptr() as *const libc::c_char)
    };

    let output_string = CString::new(&out[..hex_len])
        .unwrap()
        .into_string()
        .unwrap();

    Ok(output_string)
}

/// Attempt to decode the hex string `hex`, writing the result to `output`, ignoring characters in
/// the C-style string pointed to by `ignore`.
///
/// # Safety
/// `ignore` must be a valid C-style string, i.e: it must be null-terminated. This is best done by
/// taking a standard Rust string, and using `CString` to convert it to the C format.
/// Alternatively, `ignore` *can* be a NULL pointer, in which case it will simply be ignored.
///
/// The caller is responsible for freeing `ignore` after use.
unsafe fn decode_hex_impl(
    hex: &str,
    ignore: *const libc::c_char,
    output: &mut [u8],
) -> Result<usize, AlkaliError> {
    require_init()?;

    let mut written = 0;

    // SAFETY: The first argument to this function is the destination to which the decoded bytes
    // will be written. The second argument specifies the maximum number of bytes which can be
    // written to this pointer. We use `output.len()` to specify the number of bytes which can be
    // written, so this number of bytes can definitely be written to `output`. The next two
    // arguments specify the hex string to decode, and its length. As the second argument specifies
    // the length of the string, it does not need to be null-terminated, so we just pass the Rust
    // byte representation of the string directly, and specify is length using `.len()`. The next
    // argument is a pointer to a C-formatted string of characters to ignore. It is the
    // responsibility of the caller to provide a valid pointer here. The next argument specifies
    // the location to which the length of the decoded output will be written. We simply pass a
    // mutable reference to a `usize` value, which is reasonable here. The final argument should be
    // a pointer to which a pointer to the final valid byte of the hex string will be written. It
    // is documented that if this is simply set to NULL, Sodium will ignore it.
    let decode_result = sodium::sodium_hex2bin(
        output.as_mut_ptr(),
        output.len(),
        hex.as_bytes().as_ptr() as *const libc::c_char,
        hex.as_bytes().len(),
        ignore,
        &mut written,
        ptr::null_mut::<*const libc::c_char>(),
    );

    if decode_result == 0 {
        Ok(written)
    } else {
        Err(AlkaliError::DecodeFailed)
    }
}

/// Attempt to decode the hex-encoded string `hex`, writing the resulting raw bytes to `output`.
///
/// `hex` should be a hex-encoded string to decode. `output` should be the destination to which the
/// decoded bytes will be written.
///
/// This function will return an error if `output` is insufficient to store the decoded bytes, or
/// if `hex` contains characters which are not valid hex characters, `[0-9a-fA-F]`. If you want to
/// decode a string containing characters which can be ignored (e.g: `"CA FE:BA BE"`), you can use
/// [`decode_hex_ignore`].
///
/// If decoding was successful, returns the number of bytes written to `output`.
///
/// This decoding runs in constant-time for a given length of hex string.
pub fn decode_hex(hex: &str, output: &mut [u8]) -> Result<usize, AlkaliError> {
    unsafe {
        // SAFETY: The `decode_hex_impl` function requires that the `ignore` argument (second
        // argument here) be either a valid pointer to a C-formatted string, or a NULL pointer. We
        // pass a NULL pointer here, which means Sodium will just ignore the argument.
        decode_hex_impl(hex, ptr::null(), output)
    }
}

/// Attempt to decode the hex-encoded string `hex`, writing the resulting raw bytes to `output`,
/// ignoring any characters listed in `ignore`.
///
/// `hex` should be a hex-encoded string to decode. `ignore` should be a string containing any
/// characters which should be ignored in `hex`. `output` should be the destination to which the
/// decoded bytes will be written.
///
/// This function will return an error if `output` is insufficient to store the decoded bytes, or
/// if `hex` contains characters which are not valid hex characters, `[0-9a-fA-F]`, and which have
/// not been specified to be ignored.
///
/// If decoding was successful, returns the number of bytes written to `output`.
///
/// This decoding runs in constant-time for a given length of hex string.
pub fn decode_hex_ignore(hex: &str, ignore: &str, output: &mut [u8]) -> Result<usize, AlkaliError> {
    let ignore = CString::new(ignore).unwrap();
    let ignore_ptr = ignore.into_raw();

    let written = unsafe {
        // SAFETY: The `decode_hex_impl` function requires that the `ignore` argument (second
        // argument here) be either a valid pointer to a C-formatted string, or a NULL pointer. We
        // construct the `ignore_ptr` argument by building a CString from a valid Rust string, then
        // calling `into_raw`. The definition of CString in the Rust standard library says that
        // this produces a valid pointer to a C-formatted string.
        decode_hex_impl(hex, ignore_ptr, output)
    };

    // Make sure we free the ignore string's memory.
    let _ignore = unsafe {
        // SAFETY: The `ignore_ptr` pointer was created using CString::into_raw, so it is safe to
        // create a CString from it.
        CString::from_raw(ignore_ptr)
    };

    written
}

/// Encode the contents of `buf` (raw bytes) as a Base64 string (suitable for printing).
///
/// `variant` should be the [`Base64Variant`] to use for encoding.
///
/// Returns the Base64-encoded contents of `buf`. This can later be decoded back to raw bytes using
/// [`decode_base64`].
pub fn encode_base64(buf: &[u8], variant: Base64Variant) -> Result<String, AlkaliError> {
    require_init()?;

    let out_len = unsafe {
        // SAFETY: This function just calls the `sodium_base64_ENCODED_LEN` macro, checking first
        // that `variant` is a valid Base64 variant. We have defined the `Base64Variant` enum
        // based on the `sodium_base64_VARIANT_NAME` constants, so every item is a valid variant.
        // The macro itself just performs basic mathematical operations on the length & variant,
        // which should always be safe.
        sodium::sodium_base64_encoded_len(buf.len(), variant as libc::c_int)
    };
    let mut out = vec![0u8; out_len];

    let base64_len = unsafe {
        // SAFETY: The first argument to this function is the destination pointer to which the
        // C-formatted string will be written. The second argument specifies the maximum number of
        // bytes which can be written to this pointer. We use `out.len()` to specify the number of
        // bytes which can be written, so this number of bytes can definitely be written to `out`.
        // The next two arguments specify the buffer to encode, and its length. We use `buf.len()`
        // to specify the number of bytes to encode, so it is correct for this pointer. The final
        // argument specifies the Base64 variant to use. We define the `Base64Variant` enum based
        // on the `sodium_base64_VARIANT_NAME` constants, so every item is a valid variant.
        sodium::sodium_bin2base64(
            out.as_mut_ptr() as *mut libc::c_char,
            out.len(),
            buf.as_ptr(),
            buf.len(),
            variant as libc::c_int,
        );

        // SAFETY: This is a binding to the strlen function from the C standard library. This
        // function takes a pointer to a C-formatted string (with null byte) as an argument, and
        // returns the (inclusive) length to the nul byte. The `bin2base64` function above was used
        // to fill the contents of `out`, which Sodium guarantees will produce a valid C string,
        // including null byte. Therefore, it is safe to use strlen to determine the length of the
        // string, including the null byte.
        libc::strlen(out.as_ptr() as *const libc::c_char)
    };

    let output_string = CString::new(&out[..base64_len])
        .unwrap()
        .into_string()
        .unwrap();

    Ok(output_string)
}

/// Attempt to decode the base64 string `base64`, writing the result to `output`, ignoring
/// characters in the C-style string pointed to by `ignore`.
///
/// # Safety
/// `ignore` must be a valid C-style string, i.e: it must be null-terminated. This is best done by
/// taking a standard Rust string, and using `CString` to convert it to the C format.
/// Alternatively, `ignore` *can* be a NULL pointer, in which case it will simply be ignored.
///
/// The caller is responsible for freeing `ignore` after use.
unsafe fn decode_base64_impl(
    base64: &str,
    ignore: *const libc::c_char,
    variant: Base64Variant,
    output: &mut [u8],
) -> Result<usize, AlkaliError> {
    require_init()?;

    let mut written = 0;

    // SAFETY: The first argument to this function is the destination to which the decoded bytes
    // will be written. The second argument specifies the maximum number of bytes which can be
    // written to this pointer. We use `output.len()` to specify the number of bytes which can be
    // written, so this number of bytes can definitely be written to `output`. The next two
    // arguments specify the Base64 string to decode, and its length. As the second argument
    // specifies the length of the string, it does not need to be null-terminated, so we just pass
    // the Rust byte representation of the string directly, and specify is length using `.len()`.
    // The next argument is a pointer to a C-formatted string of characters to ignore. It is the
    // responsibility of the caller to provide a valid pointer here. The next argument specifies
    // the location to which the length of the decoded output will be written. We simply pass a
    // mutable reference to a `usize` value, which is reasonable here. The next argument should be
    // a pointer to which a pointer to the final valid byte of the Base64 string will be written.
    // It is documented that if this is simply set to NULL, Sodium will ignore it. The final
    // argument specifies the Base64 variant to use. We define the `Base64Variant` enum based
    // on the `sodium_base64_VARIANT_NAME` constants, so every item is a valid variant.
    let decode_result = sodium::sodium_base642bin(
        output.as_mut_ptr(),
        output.len(),
        base64.as_bytes().as_ptr() as *const libc::c_char,
        base64.as_bytes().len(),
        ignore,
        &mut written,
        ptr::null_mut::<*const libc::c_char>(),
        variant as libc::c_int,
    );

    if decode_result == 0 {
        Ok(written)
    } else {
        Err(AlkaliError::DecodeFailed)
    }
}

/// Attempt to decode the Base64-encoded string `base64`, writing the resulting raw bytes to
/// `output`, ignoring any characters listed in `ignore`.
///
/// `base64` should be a Base64-encoded string to decode. `variant` should be the [`Base64Variant`]
/// which `base64` is encoded as. `output` should be the destination to which the decoded bytes
/// will be written.
///
/// This function will return an error if `output` is insufficient to store the decoded bytes, or
/// if `base64` contains characters which are not valid for this variant. If you want to decode a
/// string containing characters which can be ignored, you can use [`decode_base64_ignore`].
///
/// If decoding was successful, returns the number of bytes written to `output`.
pub fn decode_base64(
    base64: &str,
    variant: Base64Variant,
    output: &mut [u8],
) -> Result<usize, AlkaliError> {
    unsafe {
        // SAFETY: The `decode_base64_impl` function requires that the `ignore` argument (second
        // argument here) be either a valid pointer to a C-formatted string, or a NULL pointer. We
        // pass a NULL pointer here, which means Sodium will just ignore the argument.
        decode_base64_impl(base64, ptr::null(), variant, output)
    }
}

/// Attempt to decode the Base64-encoded string `base64`, writing the resulting raw bytes to
/// `output`.
///
/// `base64` should be a Base64-encoded string to decode. `ignore` should be a string containing
/// any characters which should be ignored in `hex`. `variant` should be the [`Base64Variant`]
/// which `base64` is encoded as. `output` should be the destination to which the decoded bytes
/// will be written.
///
/// This function will return an error if `output` is insufficient to store the decoded bytes, or
/// if `base64` contains characters which are not valid for this variant, and have not been listed
/// to be ignored.
///
/// If decoding was successful, returns the number of bytes written to `output`.
pub fn decode_base64_ignore(
    base64: &str,
    ignore: &str,
    variant: Base64Variant,
    output: &mut [u8],
) -> Result<usize, AlkaliError> {
    let ignore = CString::new(ignore).unwrap();
    let ignore_ptr = ignore.into_raw();

    let written = unsafe {
        // SAFETY: The `decode_base64_impl` function requires that the `ignore` argument (second
        // argument here) be either a valid pointer to a C-formatted string, or a NULL pointer. We
        // construct the `ignore_ptr` argument by building a CString from a valid Rust string, then
        // calling `into_raw`. The definition of CString in the Rust standard library says that
        // this produces a valid pointer to a C-formatted string.
        decode_base64_impl(base64, ignore_ptr, variant, output)
    };

    // Make sure we free the ignore string's memory.
    let _ignore = unsafe {
        // SAFETY: The `ignore_ptr` pointer was created using CString::into_raw, so it is safe to
        // create a CString from it.
        CString::from_raw(ignore_ptr)
    };

    written
}

#[cfg(test)]
mod tests {
    use super::{
        add_le, clear, compare_le, decode_base64, decode_hex, decode_hex_ignore, encode_base64,
        encode_hex, eq, increment_le, is_zero, sub_le, Base64Variant,
    };
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

    #[test]
    fn hex_encoding() -> Result<(), AlkaliError> {
        assert_eq!(&encode_hex(b"")?, "");
        assert_eq!(&encode_hex(b"f")?, "66");
        assert_eq!(&encode_hex(b"fo")?, "666f");
        assert_eq!(&encode_hex(b"foo")?, "666f6f");
        assert_eq!(&encode_hex(b"foob")?, "666f6f62");
        assert_eq!(&encode_hex(b"fooba")?, "666f6f6261");
        assert_eq!(&encode_hex(b"foobar")?, "666f6f626172");

        let mut output = [0u8; 6];

        assert_eq!(decode_hex("", &mut output)?, 0);
        assert_eq!(output, [0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(decode_hex("66", &mut output)?, 1);
        assert_eq!(output, [0x66, 0x00, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(decode_hex("666f", &mut output)?, 2);
        assert_eq!(output, [0x66, 0x6f, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(decode_hex("666f6f", &mut output)?, 3);
        assert_eq!(output, [0x66, 0x6f, 0x6f, 0x00, 0x00, 0x00]);
        assert_eq!(decode_hex("666f6f62", &mut output)?, 4);
        assert_eq!(output, [0x66, 0x6f, 0x6f, 0x62, 0x00, 0x00]);
        assert_eq!(decode_hex("666f6f6261", &mut output)?, 5);
        assert_eq!(output, [0x66, 0x6f, 0x6f, 0x62, 0x61, 0x00]);
        assert_eq!(decode_hex("666f6f626172", &mut output)?, 6);
        assert_eq!(output, [0x66, 0x6f, 0x6f, 0x62, 0x61, 0x72]);

        assert!(decode_hex("66:6f:6f:62:61:72", &mut output).is_err());
        assert!(decode_hex("66 : 6f : 6f : 62 : 61 : 72", &mut output).is_err());
        assert!(decode_hex("66, 6f, 6f, 62, 61, 72, ", &mut output).is_err());

        assert_eq!(decode_hex_ignore("626172666f6f", "", &mut output)?, 6);
        assert_eq!(output, [0x62, 0x61, 0x72, 0x66, 0x6f, 0x6f]);
        assert_eq!(decode_hex_ignore("666f6f626172", ": ", &mut output)?, 6);
        assert_eq!(output, [0x66, 0x6f, 0x6f, 0x62, 0x61, 0x72]);
        assert_eq!(
            decode_hex_ignore("62:61:72:66:6f:6f", ": ", &mut output)?,
            6
        );
        assert_eq!(output, [0x62, 0x61, 0x72, 0x66, 0x6f, 0x6f]);
        assert_eq!(
            decode_hex_ignore("66 : 6f : 6f : 62 : 61 : 72", ": ", &mut output)?,
            6
        );
        assert_eq!(output, [0x66, 0x6f, 0x6f, 0x62, 0x61, 0x72]);

        assert!(decode_hex_ignore("62, 61, 72, 66, 6f, 6f, ", ": ", &mut output).is_err());

        assert_eq!(
            decode_hex_ignore("62, 61, 72, 66, 6f, 6f, ", " ,", &mut output)?,
            6
        );
        assert_eq!(output, [0x62, 0x61, 0x72, 0x66, 0x6f, 0x6f]);

        Ok(())
    }

    #[test]
    fn base64_encoding() -> Result<(), AlkaliError> {
        assert_eq!(&encode_base64(b"", Base64Variant::Original)?, "");
        assert_eq!(&encode_base64(b"f", Base64Variant::Original)?, "Zg==");
        assert_eq!(&encode_base64(b"fo", Base64Variant::Original)?, "Zm8=");
        assert_eq!(&encode_base64(b"foo", Base64Variant::Original)?, "Zm9v");
        assert_eq!(
            &encode_base64(b"foob", Base64Variant::Original)?,
            "Zm9vYg=="
        );
        assert_eq!(
            &encode_base64(b"fooba", Base64Variant::Original)?,
            "Zm9vYmE="
        );
        assert_eq!(
            &encode_base64(b"foobar", Base64Variant::Original)?,
            "Zm9vYmFy"
        );
        assert_eq!(
            &encode_base64(&[0xff, 0xee], Base64Variant::Original)?,
            "/+4="
        );

        assert_eq!(&encode_base64(b"", Base64Variant::NoPadding)?, "");
        assert_eq!(&encode_base64(b"f", Base64Variant::NoPadding)?, "Zg");
        assert_eq!(&encode_base64(b"fo", Base64Variant::NoPadding)?, "Zm8");
        assert_eq!(&encode_base64(b"foo", Base64Variant::NoPadding)?, "Zm9v");
        assert_eq!(&encode_base64(b"foob", Base64Variant::NoPadding)?, "Zm9vYg");
        assert_eq!(
            &encode_base64(b"fooba", Base64Variant::NoPadding)?,
            "Zm9vYmE"
        );
        assert_eq!(
            &encode_base64(b"foobar", Base64Variant::NoPadding)?,
            "Zm9vYmFy"
        );
        assert_eq!(
            &encode_base64(&[0xff, 0xee], Base64Variant::NoPadding)?,
            "/+4"
        );

        assert_eq!(&encode_base64(b"", Base64Variant::URLSafe)?, "");
        assert_eq!(&encode_base64(b"f", Base64Variant::URLSafe)?, "Zg==");
        assert_eq!(&encode_base64(b"fo", Base64Variant::URLSafe)?, "Zm8=");
        assert_eq!(&encode_base64(b"foo", Base64Variant::URLSafe)?, "Zm9v");
        assert_eq!(&encode_base64(b"foob", Base64Variant::URLSafe)?, "Zm9vYg==");
        assert_eq!(
            &encode_base64(b"fooba", Base64Variant::URLSafe)?,
            "Zm9vYmE="
        );
        assert_eq!(
            &encode_base64(b"foobar", Base64Variant::URLSafe)?,
            "Zm9vYmFy"
        );
        assert_eq!(
            &encode_base64(&[0xff, 0xee], Base64Variant::URLSafe)?,
            "_-4="
        );

        assert_eq!(&encode_base64(b"", Base64Variant::URLSafeNoPadding)?, "");
        assert_eq!(&encode_base64(b"f", Base64Variant::URLSafeNoPadding)?, "Zg");
        assert_eq!(
            &encode_base64(b"fo", Base64Variant::URLSafeNoPadding)?,
            "Zm8"
        );
        assert_eq!(
            &encode_base64(b"foo", Base64Variant::URLSafeNoPadding)?,
            "Zm9v"
        );
        assert_eq!(
            &encode_base64(b"foob", Base64Variant::URLSafeNoPadding)?,
            "Zm9vYg"
        );
        assert_eq!(
            &encode_base64(b"fooba", Base64Variant::URLSafeNoPadding)?,
            "Zm9vYmE"
        );
        assert_eq!(
            &encode_base64(b"foobar", Base64Variant::URLSafeNoPadding)?,
            "Zm9vYmFy"
        );
        assert_eq!(
            &encode_base64(&[0xff, 0xee], Base64Variant::URLSafeNoPadding)?,
            "_-4"
        );

        let mut output = [0u8; 6];

        assert_eq!(decode_base64("", Base64Variant::Original, &mut output)?, 0);
        assert_eq!(output, [0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(
            decode_base64("Zg==", Base64Variant::Original, &mut output)?,
            1
        );
        assert_eq!(output, [0x66, 0x00, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(
            decode_base64("Zm8=", Base64Variant::Original, &mut output)?,
            2
        );
        assert_eq!(output, [0x66, 0x6f, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(
            decode_base64("Zm9v", Base64Variant::Original, &mut output)?,
            3
        );
        assert_eq!(output, [0x66, 0x6f, 0x6f, 0x00, 0x00, 0x00]);
        assert_eq!(
            decode_base64("Zm9vYg==", Base64Variant::Original, &mut output)?,
            4
        );
        assert_eq!(output, [0x66, 0x6f, 0x6f, 0x62, 0x00, 0x00]);
        assert_eq!(
            decode_base64("Zm9vYmE=", Base64Variant::Original, &mut output)?,
            5
        );
        assert_eq!(output, [0x66, 0x6f, 0x6f, 0x62, 0x61, 0x00]);
        assert_eq!(
            decode_base64("Zm9vYmFy", Base64Variant::Original, &mut output)?,
            6
        );
        assert_eq!(output, [0x66, 0x6f, 0x6f, 0x62, 0x61, 0x72]);
        assert_eq!(
            decode_base64("/+4=", Base64Variant::Original, &mut output)?,
            2
        );
        assert_eq!(&output[..2], &[0xff, 0xee]);

        output.fill(0x00);
        assert_eq!(decode_base64("", Base64Variant::NoPadding, &mut output)?, 0);
        assert_eq!(output, [0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(
            decode_base64("Zg", Base64Variant::NoPadding, &mut output)?,
            1
        );
        assert_eq!(output, [0x66, 0x00, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(
            decode_base64("Zm8", Base64Variant::NoPadding, &mut output)?,
            2
        );
        assert_eq!(output, [0x66, 0x6f, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(
            decode_base64("Zm9v", Base64Variant::NoPadding, &mut output)?,
            3
        );
        assert_eq!(output, [0x66, 0x6f, 0x6f, 0x00, 0x00, 0x00]);
        assert_eq!(
            decode_base64("Zm9vYg", Base64Variant::NoPadding, &mut output)?,
            4
        );
        assert_eq!(output, [0x66, 0x6f, 0x6f, 0x62, 0x00, 0x00]);
        assert_eq!(
            decode_base64("Zm9vYmE", Base64Variant::NoPadding, &mut output)?,
            5
        );
        assert_eq!(output, [0x66, 0x6f, 0x6f, 0x62, 0x61, 0x00]);
        assert_eq!(
            decode_base64("Zm9vYmFy", Base64Variant::NoPadding, &mut output)?,
            6
        );
        assert_eq!(output, [0x66, 0x6f, 0x6f, 0x62, 0x61, 0x72]);
        assert_eq!(
            decode_base64("/+4", Base64Variant::NoPadding, &mut output)?,
            2
        );
        assert_eq!(&output[..2], &[0xff, 0xee]);

        output.fill(0x00);
        assert_eq!(decode_base64("", Base64Variant::URLSafe, &mut output)?, 0);
        assert_eq!(output, [0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(
            decode_base64("Zg==", Base64Variant::URLSafe, &mut output)?,
            1
        );
        assert_eq!(output, [0x66, 0x00, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(
            decode_base64("Zm8=", Base64Variant::URLSafe, &mut output)?,
            2
        );
        assert_eq!(output, [0x66, 0x6f, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(
            decode_base64("Zm9v", Base64Variant::URLSafe, &mut output)?,
            3
        );
        assert_eq!(output, [0x66, 0x6f, 0x6f, 0x00, 0x00, 0x00]);
        assert_eq!(
            decode_base64("Zm9vYg==", Base64Variant::URLSafe, &mut output)?,
            4
        );
        assert_eq!(output, [0x66, 0x6f, 0x6f, 0x62, 0x00, 0x00]);
        assert_eq!(
            decode_base64("Zm9vYmE=", Base64Variant::URLSafe, &mut output)?,
            5
        );
        assert_eq!(output, [0x66, 0x6f, 0x6f, 0x62, 0x61, 0x00]);
        assert_eq!(
            decode_base64("Zm9vYmFy", Base64Variant::URLSafe, &mut output)?,
            6
        );
        assert_eq!(output, [0x66, 0x6f, 0x6f, 0x62, 0x61, 0x72]);
        assert_eq!(
            decode_base64("_-4=", Base64Variant::URLSafe, &mut output)?,
            2
        );
        assert_eq!(&output[..2], &[0xff, 0xee]);

        output.fill(0x00);
        assert_eq!(
            decode_base64("", Base64Variant::URLSafeNoPadding, &mut output)?,
            0
        );
        assert_eq!(output, [0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(
            decode_base64("Zg", Base64Variant::URLSafeNoPadding, &mut output)?,
            1
        );
        assert_eq!(output, [0x66, 0x00, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(
            decode_base64("Zm8", Base64Variant::URLSafeNoPadding, &mut output)?,
            2
        );
        assert_eq!(output, [0x66, 0x6f, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(
            decode_base64("Zm9v", Base64Variant::URLSafeNoPadding, &mut output)?,
            3
        );
        assert_eq!(output, [0x66, 0x6f, 0x6f, 0x00, 0x00, 0x00]);
        assert_eq!(
            decode_base64("Zm9vYg", Base64Variant::URLSafeNoPadding, &mut output)?,
            4
        );
        assert_eq!(output, [0x66, 0x6f, 0x6f, 0x62, 0x00, 0x00]);
        assert_eq!(
            decode_base64("Zm9vYmE", Base64Variant::URLSafeNoPadding, &mut output)?,
            5
        );
        assert_eq!(output, [0x66, 0x6f, 0x6f, 0x62, 0x61, 0x00]);
        assert_eq!(
            decode_base64("Zm9vYmFy", Base64Variant::URLSafeNoPadding, &mut output)?,
            6
        );
        assert_eq!(output, [0x66, 0x6f, 0x6f, 0x62, 0x61, 0x72]);
        assert_eq!(
            decode_base64("_-4", Base64Variant::URLSafeNoPadding, &mut output)?,
            2
        );
        assert_eq!(&output[..2], &[0xff, 0xee]);

        // TODO: Testing for decode_base64_ignore

        Ok(())
    }
}
