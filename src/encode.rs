//! Binary-to-text encoding/decoding functions.
//!
//! Cryptographic functions generally operate on raw bytes. This can be inconvenient if the
//! input/output to a function needs to be communicated to another human via a text-based system
//! (e.g: email). Binary-to-text encoding uses ASCII characters to unambiguously represent binary
//! data, so that it can be easily converted back to the raw data when need be.
//!
//! This module provides utilities for [hexadecimal](https://en.wikipedia.org/wiki/Hexadecimal) and
//! [Base64](https://en.wikipedia.org/wiki/Base64) encoding.
//!
//! # Security Considerations
//! Encoding is *not* the same as encryption: Anyone can decode an encoded message. If you need to
//! encrypt messages, use [`symmetric::cipher`](crate::symmetric::cipher),
//! [`asymmetric::cipher`](crate::asymmetric::cipher), etc.

/// Hexadecimal encoding.
pub mod hex {
    use crate::{require_init, AlkaliError};
    use libsodium_sys as sodium;
    use std::ffi::CString;
    use std::ptr;

    /// Encode the contents of `buf` (raw bytes) as a hex string (suitable for printing).
    ///
    /// Returns the hex-encoded contents of `buf`. This can later be decoded back to raw bytes
    /// using [`decode`].
    ///
    /// This encoding runs in constant-time for a given length of `buf`.
    pub fn encode(buf: &[u8]) -> Result<String, AlkaliError> {
        require_init()?;

        let mut out = vec![0u8; (buf.len() * 2) + 1];

        let hex_len = unsafe {
            // SAFETY: The first argument to this function is the destination pointer to which the
            // C-formatted string will be written. Each byte of input corresponds to two hex
            // characters. We allocate twice the length of the input buffer to store the hex
            // characters, plus an extra byte to store the null byte at the end of the string, so
            // `out` is sufficient to store the hex string. The second argument specifies the
            // maximum number of bytes which can be written to this pointer. We use `out.len()` to
            // specify the number of bytes which can be written, so `out` is definitely valid for
            // writes of this length. The next two arguments specify the buffer to encode, and its
            // length. We use `buf.len()` to specify the number of bytes to encode, so `buf` is
            // definitely valid for reads of this length.
            sodium::sodium_bin2hex(
                out.as_mut_ptr() as *mut libc::c_char,
                out.len(),
                buf.as_ptr(),
                buf.len(),
            );

            // SAFETY: This is a binding to the strnlen function from the C standard library. This
            // function takes a pointer to a C-formatted string (with null byte) as an argument,
            // and returns the (inclusive) length to the null byte, up to a provided maximum number
            // of bytes. The `bin2hex` function above was used to fill the contents of `out`, which
            // Sodium guarantees will produce a valid C string, including null byte. Therefore, it
            // is safe to use strnlen to determine the length of the string, including the null
            // byte. We set the maximum number of bytes to read from `out` to be `out.len()`, so
            // `out` is clearly valid for reads of this length.
            libc::strnlen(out.as_ptr() as *const libc::c_char, out.len())
        };

        let output_string = CString::new(&out[..hex_len])
            .unwrap()
            .into_string()
            .unwrap();

        Ok(output_string)
    }

    /// Attempt to decode the hex string `hex`, writing the result to `output`, ignoring characters
    /// in the C-style string pointed to by `ignore`.
    ///
    /// # Safety
    /// `ignore` must be a pointer to a valid C-style string, i.e: it must be null-terminated. This
    /// is best done by taking a standard Rust string, and using `CString` to convert it to the C
    /// format. Alternatively, `ignore` *can* be a NULL pointer, in which case it will simply be
    /// ignored.
    ///
    /// The caller is responsible for freeing `ignore` after use.
    unsafe fn decode_impl(
        hex: &str,
        ignore: *const libc::c_char,
        output: &mut [u8],
    ) -> Result<usize, AlkaliError> {
        require_init()?;

        let mut written = 0;

        let hex = CString::new(hex).unwrap();

        // SAFETY: The first argument to this function is the destination to which the decoded
        // bytes will be written. The second argument specifies the maximum number of bytes which
        // can be written to this pointer. We use `output.len()` to specify the number of bytes
        // which can be written, so `output` is definitely valid for writes of this length. The next
        // two arguments specify the hex string to decode, and its length. As the second
        // argument specifies the length of the string, it does not need to be null-terminated, so
        // we just pass the CString byte representation of the string directly, and specify its
        // length using `.len()`. The next argument is a pointer to a C-formatted string of
        // characters to ignore. It is the responsibility of the caller to provide a valid pointer
        // here. The next argument specifies the location to which the length of the decoded output
        // will be written. We simply pass a mutable reference to a `usize` value, which is
        // reasonable here. The final argument should be a pointer to which a pointer to the final
        // valid byte of the hex string will be written. It is documented that if this is simply set
        // to NULL, Sodium will ignore it.
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
            Err(AlkaliError::DecodeError)
        }
    }

    /// Attempt to decode the hex-encoded string `hex`, writing the resulting raw bytes to
    /// `output`.
    ///
    /// `hex` should be a hex-encoded string to decode. `output` should be the destination to which
    /// the decoded bytes will be written. The length of the output should be half the length of the
    /// input, in bytes.
    ///
    /// This function will return an [`AlkaliError::DecodeError`] if `output` is insufficient to
    /// store the decoded bytes, or if `hex` contains characters which are not valid hex characters,
    /// `[0-9a-fA-F]`. If you want to decode a string containing characters which can be ignored
    /// (e.g: `"CA FE:BA BE"`), you can use [`decode_ignore`].
    ///
    /// If decoding was successful, returns the number of bytes written to `output`.
    ///
    /// This decoding runs in constant-time for a given length of hex string.
    pub fn decode(hex: &str, output: &mut [u8]) -> Result<usize, AlkaliError> {
        unsafe {
            // SAFETY: The `decode_impl` function requires that the `ignore` argument (second
            // argument here) be either a valid pointer to a C-formatted string, or a NULL pointer.
            // We pass a NULL pointer here, which means Sodium will just ignore the argument.
            decode_impl(hex, ptr::null(), output)
        }
    }

    /// Attempt to decode the hex-encoded string `hex`, writing the resulting raw bytes to `output`,
    /// ignoring any characters listed in `ignore`.
    ///
    /// `hex` should be a hex-encoded string to decode. `ignore` should be a string containing any
    /// characters which should be ignored in `hex`. `output` should be the destination to which
    /// the decoded bytes will be written. The length of the output should be at most half the
    /// length of the input, in bytes.
    ///
    /// This function will return an [`AlkaliError::DecodeError`] if `output` is insufficient to
    /// store the decoded bytes, or if `hex` contains characters which are not valid hex characters,
    /// `[0-9a-fA-F]`, and which have not been specified to be ignored.
    ///
    /// If decoding was successful, returns the number of bytes written to `output`.
    ///
    /// This decoding runs in constant-time for a given length of hex string.
    pub fn decode_ignore(hex: &str, ignore: &str, output: &mut [u8]) -> Result<usize, AlkaliError> {
        let ignore = CString::new(ignore).unwrap();

        let written = unsafe {
            // SAFETY: The `decode_impl` function requires that the `ignore` argument (second
            // argument here) be either a valid pointer to a C-formatted string, or a NULL pointer.
            // We construct the `ignore_ptr` argument by building a CString from a valid Rust
            // string, then calling `as_bytes_with_nul`. The definition of CString in the Rust
            // standard library says that this will produce a byte slice ending in a null byte,
            // equivalent to the C-style representation of the string.
            decode_impl(
                hex,
                ignore.as_bytes_with_nul().as_ptr() as *const libc::c_char,
                output,
            )
        };

        written
    }

    #[cfg(test)]
    mod tests {
        use super::{decode, decode_ignore, encode};
        use crate::AlkaliError;

        #[test]
        fn encoding() -> Result<(), AlkaliError> {
            assert_eq!(&encode(b"")?, "");
            assert_eq!(&encode(b"f")?, "66");
            assert_eq!(&encode(b"fo")?, "666f");
            assert_eq!(&encode(b"foo")?, "666f6f");
            assert_eq!(&encode(b"foob")?, "666f6f62");
            assert_eq!(&encode(b"fooba")?, "666f6f6261");
            assert_eq!(&encode(b"foobar")?, "666f6f626172");

            Ok(())
        }

        #[test]
        fn decoding() -> Result<(), AlkaliError> {
            let mut output = [0u8; 6];

            assert_eq!(decode("", &mut output)?, 0);
            assert_eq!(output, [0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
            assert_eq!(decode("66", &mut output)?, 1);
            assert_eq!(output, [0x66, 0x00, 0x00, 0x00, 0x00, 0x00]);
            assert_eq!(decode("666f", &mut output)?, 2);
            assert_eq!(output, [0x66, 0x6f, 0x00, 0x00, 0x00, 0x00]);
            assert_eq!(decode("666f6f", &mut output)?, 3);
            assert_eq!(output, [0x66, 0x6f, 0x6f, 0x00, 0x00, 0x00]);
            assert_eq!(decode("666f6f62", &mut output)?, 4);
            assert_eq!(output, [0x66, 0x6f, 0x6f, 0x62, 0x00, 0x00]);
            assert_eq!(decode("666f6f6261", &mut output)?, 5);
            assert_eq!(output, [0x66, 0x6f, 0x6f, 0x62, 0x61, 0x00]);
            assert_eq!(decode("666f6f626172", &mut output)?, 6);
            assert_eq!(output, [0x66, 0x6f, 0x6f, 0x62, 0x61, 0x72]);

            assert!(decode("66:6f:6f:62:61:72", &mut output).is_err());
            assert!(decode("66 : 6f : 6f : 62 : 61 : 72", &mut output).is_err());
            assert!(decode("66, 6f, 6f, 62, 61, 72, ", &mut output).is_err());

            assert_eq!(decode_ignore("626172666f6f", "", &mut output)?, 6);
            assert_eq!(output, [0x62, 0x61, 0x72, 0x66, 0x6f, 0x6f]);
            assert_eq!(decode_ignore("666f6f626172", ": ", &mut output)?, 6);
            assert_eq!(output, [0x66, 0x6f, 0x6f, 0x62, 0x61, 0x72]);
            assert_eq!(decode_ignore("62:61:72:66:6f:6f", ": ", &mut output)?, 6);
            assert_eq!(output, [0x62, 0x61, 0x72, 0x66, 0x6f, 0x6f]);
            assert_eq!(
                decode_ignore("66 : 6f : 6f : 62 : 61 : 72", ": ", &mut output)?,
                6
            );
            assert_eq!(output, [0x66, 0x6f, 0x6f, 0x62, 0x61, 0x72]);

            assert!(decode_ignore("62, 61, 72, 66, 6f, 6f, ", ": ", &mut output).is_err());

            assert_eq!(
                decode_ignore("62, 61, 72, 66, 6f, 6f, ", " ,", &mut output)?,
                6
            );
            assert_eq!(output, [0x62, 0x61, 0x72, 0x66, 0x6f, 0x6f]);

            Ok(())
        }
    }
}

/// Base64 encoding.
pub mod base64 {
    use crate::{require_init, AlkaliError};
    use libsodium_sys as sodium;
    use std::ffi::CString;
    use std::ptr;

    /// Different variants of Base64 encoding supported by Sodium.
    ///
    /// Different Base64 alphabets & padding settings are used for different applications.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    #[repr(u32)]
    pub enum Variant {
        /// The standard Base64 alphabet, `[A-Za-z0-9+/=]`
        Original = sodium::sodium_base64_VARIANT_ORIGINAL,

        /// The standard Base64 alphabet, `[A-Za-z0-9+/]`, with no padding appended
        NoPadding = sodium::sodium_base64_VARIANT_ORIGINAL_NO_PADDING,

        /// The URL-safe Base64 alphabet, `[A-Za-z0-9-_=]`
        URLSafe = sodium::sodium_base64_VARIANT_URLSAFE,

        /// The URL-safe Base64 alphabet, `[A-Za-z0-9-_]`, with no padding appended
        URLSafeNoPadding = sodium::sodium_base64_VARIANT_URLSAFE_NO_PADDING,
    }

    /// Encode the contents of `buf` (raw bytes) as a Base64 string (suitable for printing).
    ///
    /// `variant` should be the [`Variant`] to use for encoding.
    ///
    /// Returns the Base64-encoded contents of `buf`. This can later be decoded back to raw bytes
    /// using [`decode`].
    pub fn encode(buf: &[u8], variant: Variant) -> Result<String, AlkaliError> {
        require_init()?;

        let out_len = unsafe {
            // SAFETY: This function just calls the `sodium_base64_ENCODED_LEN` macro, checking
            // first that `variant` is a valid Base64 variant. We have defined the `Base64Variant`
            // enum based on the `sodium_base64_VARIANT_NAME` constants, so every item is a valid
            // variant. The macro itself just performs basic mathematical operations on the length &
            // variant, which should always be safe.
            sodium::sodium_base64_encoded_len(buf.len(), variant as libc::c_int)
        };
        let mut out = vec![0u8; out_len];

        let base64_len = unsafe {
            // SAFETY: The first argument to this function is the destination pointer to which the
            // C-formatted string will be written. We define `out` to be
            // `sodium_base64_encoded_len(buf.len(), variant)` bytes, which returns the number of
            // bytes required to store the output (inc. null byte), so `out` is sufficient to store
            // the hex string. The second argument specifies the maximum number of bytes which can
            // be written to this pointer. We use `out.len()` to specify the number of bytes which
            // can be written, so `out` is definitely valid for writes of this length. The next two
            // arguments specify the buffer to encode, and its length. We use `buf.len()` to specify
            // the number of bytes to encode, so `buf` is definitely valid for reads of this length.
            // The final argument specifies which Base64 variant to use, which must be one of four
            // integers corresponding to the different variants defined in Sodium. We define the
            // `Variant` enum so that each item is represented by Sodium's integer value for each
            // variant, so `variant`'s integer representation is valid here.
            sodium::sodium_bin2base64(
                out.as_mut_ptr() as *mut libc::c_char,
                out.len(),
                buf.as_ptr(),
                buf.len(),
                variant as libc::c_int,
            );

            // SAFETY: This is a binding to the strnlen function from the C standard library. This
            // function takes a pointer to a C-formatted string (with null byte) as an argument,
            // and returns the (inclusive) length to the nul byte, up to a provided maximum number
            // of bytes. The `bin2base64` function above was used to fill the contents of `out`,
            // which Sodium guarantees will produce a valid C string, including null byte.
            // Therefore, it is safe to use strnlen to determine the length of the string,
            // including the null byte. We set the maximum number of bytes to read from `out` to be
            // `out.len()`, so `out` is clearly valid for reads of this length.
            libc::strnlen(out.as_ptr() as *const libc::c_char, out.len())
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
    /// `ignore` must be a pointer to a valid C-style string, i.e: it must be null-terminated. This
    /// is best done by taking a standard Rust string, and using `CString` to convert it to the C
    /// format. Alternatively, `ignore` *can* be a NULL pointer, in which case it will simply be
    /// ignored.
    ///
    /// The caller is responsible for freeing `ignore` after use.
    unsafe fn decode_impl(
        base64: &str,
        ignore: *const libc::c_char,
        variant: Variant,
        output: &mut [u8],
    ) -> Result<usize, AlkaliError> {
        require_init()?;

        let mut written = 0;

        let base64 = CString::new(base64).unwrap();

        // SAFETY: The first argument to this function is the destination to which the decoded
        // bytes will be written. The second argument specifies the maximum number of bytes which
        // can be written to this pointer. We use `output.len()` to specify the number of bytes
        // which can be written, so `output` is definitely valid for writes of this length. The next
        // two arguments specify the Base64 string to decode, and its length. As the second
        // argument specifies the length of the string, it does not need to be null-terminated, so
        // we just pass the CString byte representation of the string directly, and specify its
        // length using `.len()`. The next argument is a pointer to a C-formatted string of
        // characters to ignore. It is the responsibility of the caller to provide a valid pointer
        // here. The next argument specifies the location to which the length of the decoded output
        // will be written. We simply pass a mutable reference to a `usize` value, which is
        // reasonable here. The next argument should be a pointer to which a pointer to the final
        // valid byte of the hex string will be written. It is documented that if this is simply set
        // to NULL, Sodium will ignore it. The final argument specifies which Base64 variant to use,
        // which must be one of four integers corresponding to the different variants defined in
        // Sodium. We define the `Variant` enum so that each item is represented by Sodium's integer
        // value for each variant, so `variant`'s integer representation is valid here.
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
            Err(AlkaliError::DecodeError)
        }
    }

    /// Attempt to decode the Base64-encoded string `base64`, writing the resulting raw bytes to
    /// `output`, ignoring any characters listed in `ignore`.
    ///
    /// `base64` should be a Base64-encoded string to decode. `variant` should be the [`Variant`]
    /// which `base64` is encoded as. `output` should be the destination to which the decoded bytes
    /// will be written.
    ///
    /// This function will return an [`AlkaliError::DecodeError`] if `output` is insufficient to
    /// store the decoded bytes, or if `base64` contains characters which are not valid for this
    /// variant. If you want to decode a string containing characters which can be ignored, you can
    /// use [`decode_ignore`].
    ///
    /// If decoding was successful, returns the number of bytes written to `output`.
    pub fn decode(base64: &str, variant: Variant, output: &mut [u8]) -> Result<usize, AlkaliError> {
        unsafe {
            // SAFETY: The `decode_impl` function requires that the `ignore` argument (second
            // argument here) be either a valid pointer to a C-formatted string, or a NULL pointer.
            // We pass a NULL pointer here, which means Sodium will just ignore the argument.
            decode_impl(base64, ptr::null(), variant, output)
        }
    }

    /// Attempt to decode the Base64-encoded string `base64`, writing the resulting raw bytes to
    /// `output`.
    ///
    /// `base64` should be a Base64-encoded string to decode. `ignore` should be a string containing
    /// any characters which should be ignored in `hex`. `variant` should be the [`Variant`] which
    /// `base64` is encoded as. `output` should be the destination to which the decoded bytes will
    /// be written.
    ///
    /// This function will return an [`AlkaliError::DecodeError`] if `output` is insufficient to
    /// store the decoded bytes, or if `base64` contains characters which are not valid for this
    /// variant, and have not been listed to be ignored.
    ///
    /// If decoding was successful, returns the number of bytes written to `output`.
    pub fn decode_ignore(
        base64: &str,
        ignore: &str,
        variant: Variant,
        output: &mut [u8],
    ) -> Result<usize, AlkaliError> {
        let ignore = CString::new(ignore).unwrap();

        let written = unsafe {
            // SAFETY: The `decode_impl` function requires that the `ignore` argument (second
            // argument here) be either a valid pointer to a C-formatted string, or a NULL pointer.
            // We construct the `ignore_ptr` argument by building a CString from a valid Rust
            // string, then calling `as_bytes_with_nul`. The definition of CString in the Rust
            // standard library says that this will produce a byte slice ending in a null byte,
            // equivalent to the C-style representation of the string.
            decode_impl(
                base64,
                ignore.as_bytes_with_nul().as_ptr() as *const libc::c_char,
                variant,
                output,
            )
        };

        written
    }

    #[cfg(test)]
    mod tests {
        use super::{decode, decode_ignore, encode, Variant};
        use crate::AlkaliError;

        macro_rules! encode_tests {
            ( $variant:expr, $( [
                $bin:expr,
                $b64:expr
            ], )* ) => {
                $(
                    assert_eq!(&encode($bin, $variant)?, $b64);
                )*
            };
        }

        macro_rules! decode_tests {
            ( $variant:expr, $( [
                $b64:expr,
                $bin:expr
            ], )* ) => {
                $(
                    let mut output = vec![0u8; $bin.len()];
                    assert_eq!(decode($b64, $variant, &mut output)?, $bin.len());
                    assert_eq!(&$bin[..], &output[..]);
                )*
            };
        }

        macro_rules! decode_ignore_tests {
            ( $variant:expr, $( [
                $b64:expr,
                $bin:expr,
                $ignore:expr,
                $should_pass:expr
            ], )* ) => {
                $(
                    let mut output = vec![0u8; $bin.len()];
                    if $should_pass {
                        assert_eq!(
                            decode_ignore($b64, $ignore, $variant, &mut output)?,
                            $bin.len()
                        );
                        assert_eq!(&$bin[..], &output[..]);
                    } else {
                        assert!(decode_ignore($b64, $ignore, $variant, &mut output).is_err());
                    }
                )*
            };
        }

        #[test]
        fn encoding_original() -> Result<(), AlkaliError> {
            encode_tests![
                Variant::Original,
                [b"", ""],
                [b"f", "Zg=="],
                [b"fo", "Zm8="],
                [b"foo", "Zm9v"],
                [b"foob", "Zm9vYg=="],
                [b"fooba", "Zm9vYmE="],
                [b"foobar", "Zm9vYmFy"],
                [&[0xff, 0xee], "/+4="],
            ];

            Ok(())
        }

        #[test]
        fn decoding_original() -> Result<(), AlkaliError> {
            decode_tests![
                Variant::Original,
                ["", [] as [u8; 0]],
                ["Zg==", [0x66]],
                ["Zm8=", [0x66, 0x6f]],
                ["Zm9v", [0x66, 0x6f, 0x6f]],
                ["Zm9vYg==", [0x66, 0x6f, 0x6f, 0x62]],
                ["Zm9vYmE=", [0x66, 0x6f, 0x6f, 0x62, 0x61]],
                ["Zm9vYmFy", [0x66, 0x6f, 0x6f, 0x62, 0x61, 0x72]],
                ["/+4=", [0xff, 0xee]],
            ];

            decode_ignore_tests![
                Variant::Original,
                ["Zm9vYmFy", [0x66, 0x6f, 0x6f, 0x62, 0x61, 0x72], "", true],
                ["Zm9vYmFy", [0x66, 0x6f, 0x6f, 0x62, 0x61, 0x72], ": ", true],
                [
                    "Zm9v:YmFy",
                    [0x66, 0x6f, 0x6f, 0x62, 0x61, 0x72],
                    ": ",
                    true
                ],
                [
                    "Z m 9v : YmF y",
                    [0x66, 0x6f, 0x6f, 0x62, 0x61, 0x72],
                    ": ",
                    true
                ],
                [
                    "Z, m, 9v, YmF, y, ",
                    [0x66, 0x6f, 0x6f, 0x62, 0x61, 0x72],
                    ": ",
                    false
                ],
                [
                    "Z, m, 9v, YmF, y, ",
                    [0x66, 0x6f, 0x6f, 0x62, 0x61, 0x72],
                    " ,",
                    true
                ],
                ["/+\n4", [0xff, 0xee], "\n", false],
                ["/+\n4=", [0xff, 0xee], "\n", true],
            ];

            Ok(())
        }

        #[test]
        fn encoding_nopadding() -> Result<(), AlkaliError> {
            encode_tests![
                Variant::NoPadding,
                [b"", ""],
                [b"f", "Zg"],
                [b"fo", "Zm8"],
                [b"foo", "Zm9v"],
                [b"foob", "Zm9vYg"],
                [b"fooba", "Zm9vYmE"],
                [b"foobar", "Zm9vYmFy"],
                [&[0xff, 0xee], "/+4"],
            ];

            Ok(())
        }

        #[test]
        fn decoding_nopadding() -> Result<(), AlkaliError> {
            decode_tests![
                Variant::NoPadding,
                ["", [] as [u8; 0]],
                ["Zg", [0x66]],
                ["Zm8", [0x66, 0x6f]],
                ["Zm9v", [0x66, 0x6f, 0x6f]],
                ["Zm9vYg", [0x66, 0x6f, 0x6f, 0x62]],
                ["Zm9vYmE", [0x66, 0x6f, 0x6f, 0x62, 0x61]],
                ["Zm9vYmFy", [0x66, 0x6f, 0x6f, 0x62, 0x61, 0x72]],
                ["/+4", [0xff, 0xee]],
            ];

            decode_ignore_tests![
                Variant::NoPadding,
                ["Zm9vYmFy", [0x66, 0x6f, 0x6f, 0x62, 0x61, 0x72], "", true],
                ["Zm9vYmFy", [0x66, 0x6f, 0x6f, 0x62, 0x61, 0x72], ": ", true],
                [
                    "Zm9v:YmFy",
                    [0x66, 0x6f, 0x6f, 0x62, 0x61, 0x72],
                    ": ",
                    true
                ],
                [
                    "Z m 9v : YmF y",
                    [0x66, 0x6f, 0x6f, 0x62, 0x61, 0x72],
                    ": ",
                    true
                ],
                [
                    "Z, m, 9v, YmF, y, ",
                    [0x66, 0x6f, 0x6f, 0x62, 0x61, 0x72],
                    ": ",
                    false
                ],
                [
                    "Z, m, 9v, YmF, y, ",
                    [0x66, 0x6f, 0x6f, 0x62, 0x61, 0x72],
                    " ,",
                    true
                ],
                ["/+\n4", [0xff, 0xee], "\n", true],
                ["/+\n4=", [0xff, 0xee], "\n", false],
            ];

            Ok(())
        }

        #[test]
        fn encoding_urlsafe() -> Result<(), AlkaliError> {
            encode_tests![
                Variant::URLSafe,
                [b"", ""],
                [b"f", "Zg=="],
                [b"fo", "Zm8="],
                [b"foo", "Zm9v"],
                [b"foob", "Zm9vYg=="],
                [b"fooba", "Zm9vYmE="],
                [b"foobar", "Zm9vYmFy"],
                [&[0xff, 0xee], "_-4="],
            ];

            Ok(())
        }

        #[test]
        fn decoding_urlsafe() -> Result<(), AlkaliError> {
            decode_tests![
                Variant::URLSafe,
                ["", [] as [u8; 0]],
                ["Zg==", [0x66]],
                ["Zm8=", [0x66, 0x6f]],
                ["Zm9v", [0x66, 0x6f, 0x6f]],
                ["Zm9vYg==", [0x66, 0x6f, 0x6f, 0x62]],
                ["Zm9vYmE=", [0x66, 0x6f, 0x6f, 0x62, 0x61]],
                ["Zm9vYmFy", [0x66, 0x6f, 0x6f, 0x62, 0x61, 0x72]],
                ["_-4=", [0xff, 0xee]],
            ];

            decode_ignore_tests![
                Variant::URLSafe,
                ["Zm9vYmFy", [0x66, 0x6f, 0x6f, 0x62, 0x61, 0x72], "", true],
                ["Zm9vYmFy", [0x66, 0x6f, 0x6f, 0x62, 0x61, 0x72], ": ", true],
                [
                    "Zm9v:YmFy",
                    [0x66, 0x6f, 0x6f, 0x62, 0x61, 0x72],
                    ": ",
                    true
                ],
                [
                    "Z m 9v : YmF y",
                    [0x66, 0x6f, 0x6f, 0x62, 0x61, 0x72],
                    ": ",
                    true
                ],
                [
                    "Z, m, 9v, YmF, y, ",
                    [0x66, 0x6f, 0x6f, 0x62, 0x61, 0x72],
                    ": ",
                    false
                ],
                [
                    "Z, m, 9v, YmF, y, ",
                    [0x66, 0x6f, 0x6f, 0x62, 0x61, 0x72],
                    " ,",
                    true
                ],
                ["/+4=", [0xff, 0xee], "\n", false],
                ["_-\n4", [0xff, 0xee], "\n", false],
                ["_-\n4=", [0xff, 0xee], "\n", true],
            ];

            Ok(())
        }

        #[test]
        fn encoding_urlsafe_nopadding() -> Result<(), AlkaliError> {
            encode_tests![
                Variant::URLSafeNoPadding,
                [b"", ""],
                [b"f", "Zg"],
                [b"fo", "Zm8"],
                [b"foo", "Zm9v"],
                [b"foob", "Zm9vYg"],
                [b"fooba", "Zm9vYmE"],
                [b"foobar", "Zm9vYmFy"],
                [&[0xff, 0xee], "_-4"],
            ];

            Ok(())
        }

        #[test]
        fn decoding_urlsafe_nopadding() -> Result<(), AlkaliError> {
            decode_tests![
                Variant::URLSafeNoPadding,
                ["", [] as [u8; 0]],
                ["Zg", [0x66]],
                ["Zm8", [0x66, 0x6f]],
                ["Zm9v", [0x66, 0x6f, 0x6f]],
                ["Zm9vYg", [0x66, 0x6f, 0x6f, 0x62]],
                ["Zm9vYmE", [0x66, 0x6f, 0x6f, 0x62, 0x61]],
                ["Zm9vYmFy", [0x66, 0x6f, 0x6f, 0x62, 0x61, 0x72]],
                ["_-4", [0xff, 0xee]],
            ];

            decode_ignore_tests![
                Variant::URLSafeNoPadding,
                ["Zm9vYmFy", [0x66, 0x6f, 0x6f, 0x62, 0x61, 0x72], "", true],
                ["Zm9vYmFy", [0x66, 0x6f, 0x6f, 0x62, 0x61, 0x72], ": ", true],
                [
                    "Zm9v:YmFy",
                    [0x66, 0x6f, 0x6f, 0x62, 0x61, 0x72],
                    ": ",
                    true
                ],
                [
                    "Z m 9v : YmF y",
                    [0x66, 0x6f, 0x6f, 0x62, 0x61, 0x72],
                    ": ",
                    true
                ],
                [
                    "Z, m, 9v, YmF, y, ",
                    [0x66, 0x6f, 0x6f, 0x62, 0x61, 0x72],
                    ": ",
                    false
                ],
                [
                    "Z, m, 9v, YmF, y, ",
                    [0x66, 0x6f, 0x6f, 0x62, 0x61, 0x72],
                    " ,",
                    true
                ],
                ["/+4=", [0xff, 0xee], "\n", false],
                ["_-\n4", [0xff, 0xee], "\n", true],
                ["_-\n4=", [0xff, 0xee], "\n", false],
            ];

            Ok(())
        }
    }
}
