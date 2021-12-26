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

#[cfg(test)]
mod tests {
    use super::eq;
    use crate::AlkaliError;

    #[test]
    fn eq_tests() -> Result<(), AlkaliError> {
        use crate::random::fill_random;

        let mut buf_a = [0; 1000];
        let mut buf_b = [0; 1000];

        fill_random(&mut buf_a)?;
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
}
