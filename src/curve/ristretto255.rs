//! The [Ristretto](https://ristretto.group/) group defined over Curve25519 (ristretto255).
//!
//! This module corresponds to the [`crypto_core_ristretto255`
//! API](https://doc.libsodium.org/advanced/point-arithmetic/ristretto) from Sodium.
//!
//! Ristretto is a construction which defines a prime-order group using a non-prime-order Edwards
//! curve. The benefits of this are explained in the [Ristretto
//! documentation](https://ristretto.group/why_ristretto.html), but the point is that many
//! cryptographic algorithms are defined over prime-order groups, and using curves with non-prime
//! orders (such as Curve25519) can lead to vulnerabilities. Ristretto255 in particular defines a
//! prime-order group using Curve25519, of order `2^252 + 27742317777372353535851937790883648493`.

use super::CurveError;
use crate::{assert_not_err, mem, require_init, AlkaliError};
use libsodium_sys as sodium;

/// The length of the byte representation of a point on Ristretto255, in bytes.
pub const POINT_LENGTH: usize = sodium::crypto_core_ristretto255_BYTES as usize;

/// The length of a secret scalar by which a point on Ristretto255 can be multiplied, in bytes.
pub const SCALAR_LENGTH: usize = sodium::crypto_core_ristretto255_SCALARBYTES as usize;

/// THe length of a value which can be reduced to produce a [`Scalar`], in bytes.
pub const UNREDUCED_SCALAR_LENGTH: usize =
    sodium::crypto_core_ristretto255_NONREDUCEDSCALARBYTES as usize;

/// The length of a value from which a point on Ristretto255 can be derived using
/// [`Point::from_hash`], in bytes.
pub const HASH_LENGTH: usize = sodium::crypto_core_ristretto255_HASHBYTES as usize;

mem::hardened_buffer! {
    /// A secret scalar value by which a point on the curve can be scalar-multiplied.
    ///
    /// A scalar such as this generally takes the role of a secret key in elliptic-curve
    /// cryptography. Given `Q = nP`, where `Q, P` are public points on the curve, and `n` is an
    /// unknown scalar, it is computationally infeasible to find `n` (ECDLP).
    ///
    /// A scalar should be between 0 (inclusive) and `L = 2^252 +
    /// 27742317777372353535851937790883648493` (exclusive). If a scalar is intended to be secret,
    /// it should be generated randomly using [`Scalar::generate`].
    ///
    /// This is a [hardened buffer type](https://docs.rs/alkali#hardened-buffer-types), and will be
    /// zeroed on drop. A number of other security measures are taken to protect its contents. This
    /// type in particular can be thought of as roughly equivalent to a `[u8; SCALAR_LENGTH]`, and
    /// implements [`core::ops::Deref`], so it can be used like it is an `&[u8]`. This struct uses
    /// heap memory while in scope, allocated using Sodium's [secure memory
    /// utilities](https://doc.libsodium.org/memory_management).
    pub Scalar(SCALAR_LENGTH);

    /// A value which can be reduced modulo `L` to produce a [`Scalar`] using
    /// [`Scalar::reduce_from`].
    ///
    /// This is a [hardened buffer type](https://docs.rs/alkali#hardened-buffer-types), and will be
    /// zeroed on drop. A number of other security measures are taken to protect its contents. This
    /// type in particular can be thought of as roughly equivalent to a `[u8;
    /// UNREDUCED_SCALAR_LENGTH]`, and implements [`core::ops::Deref`], so it can be used like it is
    /// an `&[u8]`. This struct uses heap memory while in scope, allocated using Sodium's [secure
    /// memory utilities](https://doc.libsodium.org/memory_management).
    pub UnreducedScalar(UNREDUCED_SCALAR_LENGTH);
}

impl Scalar<mem::FullAccess> {
    /// Generate a random scalar value for use with Ristretto255.
    ///
    /// The generated scalar will be between 0 and `L = 2^252 +
    /// 27742317777372353535851937790883648493` (exclusive).
    pub fn generate() -> Result<Self, AlkaliError> {
        require_init()?;

        let mut scalar = Self::new_empty()?;
        unsafe {
            // SAFETY: The argument to this function should be a destination to which the
            // randomly-generated scalar should be written. We define the `Scalar` type to allocate
            // `crypto_core_ristretto255_SCALARBYTES` bytes, the length of a reduced scalar for this
            // algorithm, so `scalar` is valid for writes of the required length. The
            // `Scalar::inner_mut` method simply returns a mutable pointer to the struct's backing
            // memory.
            sodium::crypto_core_ristretto255_scalar_random(scalar.inner_mut() as *mut libc::c_uchar);
        }

        Ok(scalar)
    }

    /// Reduce a value to a [`Scalar`] modulo `L = 2^252 + 27742317777372353535851937790883648493`.
    ///
    /// The [`UnreducedScalar`] type is much larger than the [`Scalar`] type (64 bytes vs 32 bytes).
    /// Bits of `unreduced` can be set to zero, but the interval `unreduced` is sampled from should
    /// be at least 317 bits to ensure uniformity of the output over `L`.
    pub fn reduce_from(
        unreduced: &UnreducedScalar<impl mem::MprotectReadable>,
    ) -> Result<Self, AlkaliError> {
        require_init()?;

        let mut scalar = Self::new_empty()?;
        unsafe {
            // SAFETY: The first argument to this function is the destination to which the reduced
            // scalar value should be written. We define the `Scalar` type to allocate
            // `crypto_core_ristretto255_SCALARBYTES`, the length of a reduced scalar value for this
            // algorithm, so `scalar` is valid for writes of the required length. The second
            // argument should be the larger value which will be reduced to produce the scalar, of
            // length `crypto_core_ristretto255_NONREDUCEDSCALARBYTES`. We define the
            // `UnreducedScalar` type to allocate this many bytes, so `unreduced` is valid for reads
            // of the required length.
            sodium::crypto_core_ristretto255_scalar_reduce(
                scalar.inner_mut() as *mut libc::c_uchar,
                unreduced.inner() as *const libc::c_uchar,
            );
        }

        Ok(scalar)
    }

    /// Compute the multiplicative inverse of this scalar modulo `L = 2^252 +
    /// 27742317777372353535851937790883648493`.
    ///
    /// Computes `q` such that `p * q = 1 (mod L)`, where `p` is this scalar, and sets `self` to
    /// `q`. If `self` is zero, this will result in an error: You can check for this using
    /// [`mem::is_zero`].
    pub fn multiplicative_inverse(&mut self) -> Result<(), AlkaliError> {
        require_init()?;

        // can't invert the zero element
        if mem::is_zero(self.as_ref())? {
            return Err(CurveError::InversionFailed.into());
        }

        let mut buf = [0u8; SCALAR_LENGTH];
        buf.copy_from_slice(self.as_ref());

        let invert_result = unsafe {
            // SAFETY: The first argument is the destination to which the inverse scalar should be
            // written. We define the `Scalar` type to allocate
            // `crypto_core_ristretto255_SCALARBYTES`, the length of a reduced scalar value for this
            // algorithm, so `self` is valid for writes of the required length. The second argument
            // is the scalar to invert. We define the `buf` array to be of length
            // `crypto_core_ristretto255_SCALARBYTES`, so it is valid for reads of the required
            // length.
            sodium::crypto_core_ristretto255_scalar_invert(
                self.inner_mut() as *mut libc::c_uchar,
                buf.as_ptr(),
            )
        };
        mem::clear(&mut buf)?;
        assert_not_err!(invert_result, "crypto_core_ristretto255_scalar_invert");

        Ok(())
    }

    /// Compute that additive inverse of this scalar modulo `L = 2^252 +
    /// 27742317777372353535851937790883648493`.
    ///
    /// Computes `q` such that `p + q = 0 (mod L)`, where `p` is this scalar, and sets `self` to
    /// `q`.
    pub fn additive_inverse(&mut self) -> Result<(), AlkaliError> {
        require_init()?;

        let mut buf = [0u8; SCALAR_LENGTH];
        buf.copy_from_slice(self.as_ref());

        unsafe {
            // SAFETY: The first argument is the destination to which the negated scalar should be
            // written. We define the `Scalar` type to allocate
            // `crypto_core_ristretto255_SCALARBYTES`, the length of a reduced scalar value for this
            // algorithm, so `self` is valid for writes of the required length. The second argument
            // is the scalar to negate. We define the `buf` array to be of length
            // `crypto_core_ristretto255_SCALARBYTES`, so it is valid for reads of the required
            // length.
            sodium::crypto_core_ristretto255_scalar_negate(
                self.inner_mut() as *mut libc::c_uchar,
                buf.as_ptr(),
            );
        }
        mem::clear(&mut buf)?;

        Ok(())
    }

    /// Computes `q` such that `p + q = 1 (mod L)`, where `p` is this scalar, `L = 2^252 +
    /// 27742317777372353535851937790883648493`.
    ///
    /// Sets `self` to `q`.
    pub fn complement(&mut self) -> Result<(), AlkaliError> {
        require_init()?;

        let mut buf = [0u8; SCALAR_LENGTH];
        buf.copy_from_slice(self.as_ref());

        unsafe {
            // SAFETY: The first argument is the destination to which the complement of the scalar
            // should be written. We define the `Scalar` type to allocate
            // `crypto_core_ristretto255_SCALARBYTES`, the length of a reduced scalar value for this
            // algorithm, so `self` is valid for writes of the required length. The second argument
            // is the scalar to complement. We define the `buf` array to be of length
            // `crypto_core_ristretto255_SCALARBYTES`, so it is valid for reads of the required
            // length.
            sodium::crypto_core_ristretto255_scalar_complement(
                self.inner_mut() as *mut libc::c_uchar,
                buf.as_ptr(),
            );
        }
        mem::clear(&mut buf)?;

        Ok(())
    }

    /// Add `s` to this value, modulo `L = 2^252 + 27742317777372353535851937790883648493`.
    ///
    /// Computes `q = p + s (mod L)`, where `p` is this scalar, and sets `self` to `q`.
    pub fn add(&mut self, s: &Scalar<impl mem::MprotectReadable>) -> Result<(), AlkaliError> {
        require_init()?;

        let mut buf = [0u8; SCALAR_LENGTH];
        buf.copy_from_slice(self.as_ref());

        unsafe {
            // SAFETY: The first argument is the destination to which the scalar sum should be
            // written. We define the `Scalar` type to allocate
            // `crypto_core_ristretto255_SCALARBYTES`, the length of a reduced scalar value for this
            // algorithm, so `self` is valid for writes of the required length. The second and third
            // arguments are the scalar summands. We define the `buf` array and `Scalar` type to
            // store `crypto_core_ristretto255_SCALARBYTES`, so `s` and `buf` are valid for reads of
            // the required length.
            sodium::crypto_core_ristretto255_scalar_add(
                self.inner_mut() as *mut libc::c_uchar,
                buf.as_ptr(),
                s.inner() as *const libc::c_uchar,
            );
        }
        mem::clear(&mut buf)?;

        Ok(())
    }

    /// Subtract `s` from this value, modulo `L = 2^252 + 27742317777372353535851937790883648493`.
    ///
    /// Computes `q = p - s (mod L)`, where `p` is this scalar, and sets `self` to `q`.
    pub fn sub(&mut self, s: &Scalar<impl mem::MprotectReadable>) -> Result<(), AlkaliError> {
        require_init()?;

        let mut buf = [0u8; SCALAR_LENGTH];
        buf.copy_from_slice(self.as_ref());

        unsafe {
            // SAFETY: The first argument is the destination to which the scalar difference should
            // be written. We define the `Scalar` type to allocate
            // `crypto_core_ristretto255_SCALARBYTES`, the length of a reduced scalar value for this
            // algorithm, so `self` is valid for writes of the required length. The second and third
            // arguments are the arguments to the minus operation. We define the `buf` array and
            // `Scalar` type to store `crypto_core_ristretto255_SCALARBYTES`, so `s` and `buf` are
            // valid for reads of the required length.
            sodium::crypto_core_ristretto255_scalar_sub(
                self.inner_mut() as *mut libc::c_uchar,
                buf.as_ptr(),
                s.inner() as *const libc::c_uchar,
            );
        }
        mem::clear(&mut buf)?;

        Ok(())
    }

    /// Multiply this value by `s`, modulo `L = 2^252 + 27742317777372353535851937790883648493`.
    ///
    /// Computes `q = p * s (mod L)`, where `p` is this scalar, and sets `self` to `q`.
    pub fn mul(&mut self, s: &Scalar<impl mem::MprotectReadable>) -> Result<(), AlkaliError> {
        require_init()?;

        let mut buf = [0u8; SCALAR_LENGTH];
        buf.copy_from_slice(self.as_ref());

        unsafe {
            // SAFETY: The first argument is the destination to which the scalar product should be
            // written. We define the `Scalar` type to allocate
            // `crypto_core_ristretto255_SCALARBYTES`, the length of a reduced scalar value for this
            // algorithm, so `self` is valid for writes of the required length. The second and third
            // arguments are the scalar multiplicands. We define the `buf` array and `Scalar` type
            // to store `crypto_core_ristretto255_SCALARBYTES`, so `s` and `buf` are valid for reads
            // of the required length.
            sodium::crypto_core_ristretto255_scalar_mul(
                self.inner_mut() as *mut libc::c_uchar,
                buf.as_ptr(),
                s.inner() as *const libc::c_uchar,
            );
        }
        mem::clear(&mut buf)?;

        Ok(())
    }
}

/// A 64-byte value from which a point on the curve can be derived via [`Point::from_hash`].
///
/// This is usually the output of a hash function.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[cfg_attr(feature = "use-serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Hash(
    #[cfg_attr(feature = "use-serde", serde(with = "serde_big_array::BigArray"))]
    pub  [u8; HASH_LENGTH],
);

/// A point on Ristretto255.
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "use-serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Point(pub [u8; POINT_LENGTH]);

impl Point {
    /// Generate a random point on Ristretto255.
    pub fn generate() -> Result<Self, AlkaliError> {
        require_init()?;

        let mut p = [0; POINT_LENGTH];
        unsafe {
            // SAFETY: The argument to this function should be a destination to which the
            // randomly-generated point should be written. We define the `p` array to store
            // `crypto_core_ristretto255_BYTES` bytes, the length of the encoded point format for
            // Ristretto255, so `p` is valid for writes of the required length.
            sodium::crypto_core_ristretto255_random(p.as_mut_ptr());
        }
        Ok(Point(p))
    }

    /// Deterministically derive a point on Ristretto255 from a 64-byte value.
    ///
    /// The value `h` is generally the output of a hash function, hence the name. This is analogous
    /// to the [`ed25519::Point::from_uniform`](crate::curve::ed25519::Point::from_uniform)
    /// function.
    ///
    /// This applies the Elligator 2 mapping twice and adds the resulting points.
    pub fn from_hash(h: &Hash) -> Result<Self, AlkaliError> {
        require_init()?;

        let mut p = [0; POINT_LENGTH];
        let from_hash_result = unsafe {
            // SAFETY: The first argument to this function is the destination to which the derived
            // point on the group will be written. We define the `p` array to store
            // `crypto_core_ristretto255_BYTES`, the length of the encoded point format for
            // Ristretto255, so `p` is valid for writes of the required length. The next argument is
            // the 64-byte value from which the point should be derived. We define the `Hash` type
            // to be `crypto_core_ristretto255_HASHBYTES`, the length of a value from which a point
            // can be derived. Therefore `h` is valid for reads of the required length.
            sodium::crypto_core_ristretto255_from_hash(p.as_mut_ptr(), h.0.as_ptr())
        };
        assert_not_err!(from_hash_result, "crypto_core_ristretto255_from_hash");

        Ok(Point(p))
    }

    /// Is this [`Point`] a valid representation of a point on Ristretto255?
    ///
    /// The set of values which can be represented in a `[u8; POINT_LENGTH]` is considerably larger
    /// than the set of values which are valid representations of elements of Ristretto255. This
    /// function returns `true` if `self` is a valid representation of a Ristretto255 point, or
    /// `false` otherwise.
    ///
    /// This must be `true` to use any of the group operation or scalar multiplication functions
    /// from this struct.
    pub fn is_valid(&self) -> Result<bool, AlkaliError> {
        require_init()?;

        let valid = unsafe {
            // SAFETY: This function expects a pointer to an encoded representation of a point on
            // Ristretto255. We define the `Point` type to store `crypto_core_ristretto255_BYTES`,
            // so `self.0` is valid for reads of the required length.
            sodium::crypto_core_ristretto255_is_valid_point(self.0.as_ptr())
        };

        Ok(valid == 1)
    }

    /// Scalar-multiply this point by the scalar `n`.
    ///
    /// Calculates `Q = nP`, where `P` is this point, `n` is the [`Scalar`] by which `P` should be
    /// multiplied, and `Q` is the return value. This is, `P` is added to itself `n` times.
    ///
    /// Finding `n` given `Q` and `P` is the elliptic curve discrete logarithm problem, so it is
    /// computationally infeasible to find `n`. This can be used to compute a shared secret `Q` if
    /// `P` is a user's public key and `n` is another user's secret key.
    ///
    /// Returns the result of the scalar multiplication (a new point on the curve), or an error if
    /// this point is not a valid representation of a point on Ristretto255.
    pub fn scalar_mult(&self, n: &Scalar<impl mem::MprotectReadable>) -> Result<Self, AlkaliError> {
        require_init()?;

        let mut q = [0; POINT_LENGTH];

        let scalarmult_result = unsafe {
            // SAFETY: The first argument to this function is the destination to which the scalar
            // product should be written, a point on Ristretto255. We define the `q` array to be
            // `crypto_scalarmult_ristretto255_BYTES`, the length of the encoded point format for
            // Ristretto255, so `q` is valid for writes of the required length. The next argument is
            // the scalar to multiply by. We define the `Scalar` type to allocate
            // `crypto_scalarmult_ristretto255_SCALARBYTES`, the length of a scalar for
            // Ristretto255, so `n` is valid for reads of the required length. The final argument is
            // the encoded representation of the point on Ristretto255 which should be multiplied by
            // the scalar. The `Point` type stores `crypto_scalarmult_ristretto255_BYTES`, the
            // length of the encoded Ristretto255 point representation, so `self.0` is valid for
            // reads of the required length. The `Scalar::inner` method simply returns a pointer to
            // the backing memory of the struct.
            sodium::crypto_scalarmult_ristretto255(
                q.as_mut_ptr(),
                n.inner() as *const libc::c_uchar,
                self.0.as_ptr(),
            )
        };

        if scalarmult_result == 0 {
            Ok(Point(q))
        } else {
            Err(CurveError::ScalarMultUnacceptable.into())
        }
    }

    /// Scalar multiply this point by the scalar `n` in place.
    ///
    /// This function is equivalent to [`Self::scalar_mult`], but modifies `self` in place, rather
    /// than returning the new point.
    pub fn scalar_mult_in_place(
        &mut self,
        n: &Scalar<impl mem::MprotectReadable>,
    ) -> Result<(), AlkaliError> {
        let q = self.scalar_mult(n)?;
        self.0 = q.0;
        Ok(())
    }

    /// Add the point `q` to this point (the elliptic curve group operation).
    ///
    /// Calculates `R = P + Q`, where `P` is this point, `Q` is the other point, and `+` is the
    /// elliptic curve group operation. Returns `R`.
    ///
    /// `self` and `q` must be valid encoded representations of points on Ristretto255.
    pub fn add(&self, q: &Point) -> Result<Self, AlkaliError> {
        require_init()?;

        let mut r = [0u8; POINT_LENGTH];
        let add_result = unsafe {
            // SAFETY: Each argument to this function should be the encoded representation of a
            // point on Ristretto255, of length `crypto_core_ristretto255_BYTES`. We define the
            // `Point` type and `r` array to store this many bytes, so `r` is valid for writes of
            // the required length, and `p`, `q` are valid for reads of the required length.
            sodium::crypto_core_ristretto255_add(r.as_mut_ptr(), self.0.as_ptr(), q.0.as_ptr())
        };

        if add_result == 0 {
            Ok(Point(r))
        } else {
            Err(CurveError::InvalidPoint.into())
        }
    }

    /// Add the point `q` to this point (the elliptic curve group operation) in place.
    ///
    /// This function is equivalent to [`Self::add`], but modifies `self` in place, rather than
    /// returning the new point.
    pub fn add_in_place(&mut self, q: &Point) -> Result<(), AlkaliError> {
        let r = self.add(q)?;
        self.0 = r.0;
        Ok(())
    }

    /// Subtract the point `q` from this point.
    ///
    /// Calculates `R = P - Q`, where `P` is this point, `Q` is the other point, and `-` is the
    /// inverse of the elliptic curve group operation. Returns `R`.
    ///
    /// `self` and `q` must be valid encoded representations of points on Ristretto255.
    pub fn sub(&self, q: &Point) -> Result<Self, AlkaliError> {
        require_init()?;

        let mut r = [0u8; POINT_LENGTH];
        let sub_result = unsafe {
            // SAFETY: Each argument to this function should be the encoded representation of a
            // point on Ristretto255, of length `crypto_core_ristretto255_BYTES`. We define the
            // `Point` type and `r` array to store this many bytes, so `r` is valid for writes of
            // the required length, and `p`, `q` are valid for reads of the required length.
            sodium::crypto_core_ristretto255_sub(r.as_mut_ptr(), self.0.as_ptr(), q.0.as_ptr())
        };

        if sub_result == 0 {
            Ok(Point(r))
        } else {
            Err(CurveError::InvalidPoint.into())
        }
    }

    /// Subtract the point `q` from this point.
    ///
    /// This function is equivalent to [`Self::sub`], but modifies `self` in place, rather than
    /// returning the new point.
    pub fn sub_in_place(&mut self, q: &Point) -> Result<(), AlkaliError> {
        let q = self.sub(q)?;
        self.0 = q.0;
        Ok(())
    }
}

/// Multiply the Ristretto255 generator by the scalar `n`.
///
/// Calculates `Q = nG`, where `G` is the generator for the curve, `n` is the scalar by which `G`
/// should be multiplied, and `Q` is the return value. That is, `G` is added to itself `n` times.
///
/// Finding `n` given `Q` and `G` is the elliptic curve discrete logarithm problem, so it is
/// computationally infeasible to find `n`. This can be used to compute the public key corresponding
/// to the secret key `n`.
pub fn scalar_mult_base(n: &Scalar<impl mem::MprotectReadable>) -> Result<Point, AlkaliError> {
    require_init()?;

    let mut q = [0u8; POINT_LENGTH];

    let scalarmult_result = unsafe {
        // SAFETY: The first argument to this function is the destination to which the scalar
        // product should be written, the encoded representation of a point on Ristretto255. We
        // define `q` to be `crypto_scalarmult_ristretto255_BYTES` bytes, the length of the
        // Ristretto255 encoded point format, so `q` is valid for writes of the required length. The
        // next argument is the scalar by which the generator should be multiplied. The `Scalar`
        // type is defined to allocate `crypto_scalarmult_ristretto255_SCALARBYTES` bytes, the
        // length of a scalar for this algorithm, so `n` is valid for reads of the required length.
        // The `Scalar::inner` method simply returns a pointer to the backing memory of the struct.
        sodium::crypto_scalarmult_ristretto255_base(
            q.as_mut_ptr(),
            n.inner() as *const libc::c_uchar,
        )
    };

    if scalarmult_result == 0 {
        Ok(Point(q))
    } else {
        Err(CurveError::ScalarMultUnacceptable.into())
    }
}

#[cfg(test)]
mod tests {
    use super::{scalar_mult_base, Hash, Point, Scalar, HASH_LENGTH};
    use crate::{random, AlkaliError};

    const GENERATOR: Point = Point([
        0xe2, 0xf2, 0xae, 0x0a, 0x6a, 0xbc, 0x4e, 0x71, 0xa8, 0x84, 0xa9, 0x61, 0xc5, 0x00, 0x51,
        0x5f, 0x58, 0xe3, 0x0b, 0x6a, 0xa5, 0x82, 0xdd, 0x8d, 0xb6, 0xa6, 0x59, 0x45, 0xe0, 0x8d,
        0x2d, 0x76,
    ]);

    #[test]
    fn scalar_generation() -> Result<(), AlkaliError> {
        let _ = Scalar::generate()?;
        Ok(())
    }

    #[test]
    fn point_generation() -> Result<(), AlkaliError> {
        let point = Point::generate()?;
        assert!(point.is_valid()?);
        Ok(())
    }

    #[test]
    fn scalarmult_base_vectors() -> Result<(), AlkaliError> {
        let scalars = [
            [
                1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ],
            [
                2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ],
            [
                3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ],
            [
                4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ],
            [
                5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ],
            [
                6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ],
            [
                7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ],
            [
                8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ],
            [
                9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ],
            [
                10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0,
            ],
            [
                11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0,
            ],
            [
                12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0,
            ],
            [
                13, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0,
            ],
            [
                14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0,
            ],
            [
                15, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0,
            ],
        ];
        let points = [
            [
                0xe2, 0xf2, 0xae, 0x0a, 0x6a, 0xbc, 0x4e, 0x71, 0xa8, 0x84, 0xa9, 0x61, 0xc5, 0x00,
                0x51, 0x5f, 0x58, 0xe3, 0x0b, 0x6a, 0xa5, 0x82, 0xdd, 0x8d, 0xb6, 0xa6, 0x59, 0x45,
                0xe0, 0x8d, 0x2d, 0x76,
            ],
            [
                0x6a, 0x49, 0x32, 0x10, 0xf7, 0x49, 0x9c, 0xd1, 0x7f, 0xec, 0xb5, 0x10, 0xae, 0x0c,
                0xea, 0x23, 0xa1, 0x10, 0xe8, 0xd5, 0xb9, 0x01, 0xf8, 0xac, 0xad, 0xd3, 0x09, 0x5c,
                0x73, 0xa3, 0xb9, 0x19,
            ],
            [
                0x94, 0x74, 0x1f, 0x5d, 0x5d, 0x52, 0x75, 0x5e, 0xce, 0x4f, 0x23, 0xf0, 0x44, 0xee,
                0x27, 0xd5, 0xd1, 0xea, 0x1e, 0x2b, 0xd1, 0x96, 0xb4, 0x62, 0x16, 0x6b, 0x16, 0x15,
                0x2a, 0x9d, 0x02, 0x59,
            ],
            [
                0xda, 0x80, 0x86, 0x27, 0x73, 0x35, 0x8b, 0x46, 0x6f, 0xfa, 0xdf, 0xe0, 0xb3, 0x29,
                0x3a, 0xb3, 0xd9, 0xfd, 0x53, 0xc5, 0xea, 0x6c, 0x95, 0x53, 0x58, 0xf5, 0x68, 0x32,
                0x2d, 0xaf, 0x6a, 0x57,
            ],
            [
                0xe8, 0x82, 0xb1, 0x31, 0x01, 0x6b, 0x52, 0xc1, 0xd3, 0x33, 0x70, 0x80, 0x18, 0x7c,
                0xf7, 0x68, 0x42, 0x3e, 0xfc, 0xcb, 0xb5, 0x17, 0xbb, 0x49, 0x5a, 0xb8, 0x12, 0xc4,
                0x16, 0x0f, 0xf4, 0x4e,
            ],
            [
                0xf6, 0x47, 0x46, 0xd3, 0xc9, 0x2b, 0x13, 0x05, 0x0e, 0xd8, 0xd8, 0x02, 0x36, 0xa7,
                0xf0, 0x00, 0x7c, 0x3b, 0x3f, 0x96, 0x2f, 0x5b, 0xa7, 0x93, 0xd1, 0x9a, 0x60, 0x1e,
                0xbb, 0x1d, 0xf4, 0x03,
            ],
            [
                0x44, 0xf5, 0x35, 0x20, 0x92, 0x6e, 0xc8, 0x1f, 0xbd, 0x5a, 0x38, 0x78, 0x45, 0xbe,
                0xb7, 0xdf, 0x85, 0xa9, 0x6a, 0x24, 0xec, 0xe1, 0x87, 0x38, 0xbd, 0xcf, 0xa6, 0xa7,
                0x82, 0x2a, 0x17, 0x6d,
            ],
            [
                0x90, 0x32, 0x93, 0xd8, 0xf2, 0x28, 0x7e, 0xbe, 0x10, 0xe2, 0x37, 0x4d, 0xc1, 0xa5,
                0x3e, 0x0b, 0xc8, 0x87, 0xe5, 0x92, 0x69, 0x9f, 0x02, 0xd0, 0x77, 0xd5, 0x26, 0x3c,
                0xdd, 0x55, 0x60, 0x1c,
            ],
            [
                0x02, 0x62, 0x2a, 0xce, 0x8f, 0x73, 0x03, 0xa3, 0x1c, 0xaf, 0xc6, 0x3f, 0x8f, 0xc4,
                0x8f, 0xdc, 0x16, 0xe1, 0xc8, 0xc8, 0xd2, 0x34, 0xb2, 0xf0, 0xd6, 0x68, 0x52, 0x82,
                0xa9, 0x07, 0x60, 0x31,
            ],
            [
                0x20, 0x70, 0x6f, 0xd7, 0x88, 0xb2, 0x72, 0x0a, 0x1e, 0xd2, 0xa5, 0xda, 0xd4, 0x95,
                0x2b, 0x01, 0xf4, 0x13, 0xbc, 0xf0, 0xe7, 0x56, 0x4d, 0xe8, 0xcd, 0xc8, 0x16, 0x68,
                0x9e, 0x2d, 0xb9, 0x5f,
            ],
            [
                0xbc, 0xe8, 0x3f, 0x8b, 0xa5, 0xdd, 0x2f, 0xa5, 0x72, 0x86, 0x4c, 0x24, 0xba, 0x18,
                0x10, 0xf9, 0x52, 0x2b, 0xc6, 0x00, 0x4a, 0xfe, 0x95, 0x87, 0x7a, 0xc7, 0x32, 0x41,
                0xca, 0xfd, 0xab, 0x42,
            ],
            [
                0xe4, 0x54, 0x9e, 0xe1, 0x6b, 0x9a, 0xa0, 0x30, 0x99, 0xca, 0x20, 0x8c, 0x67, 0xad,
                0xaf, 0xca, 0xfa, 0x4c, 0x3f, 0x3e, 0x4e, 0x53, 0x03, 0xde, 0x60, 0x26, 0xe3, 0xca,
                0x8f, 0xf8, 0x44, 0x60,
            ],
            [
                0xaa, 0x52, 0xe0, 0x00, 0xdf, 0x2e, 0x16, 0xf5, 0x5f, 0xb1, 0x03, 0x2f, 0xc3, 0x3b,
                0xc4, 0x27, 0x42, 0xda, 0xd6, 0xbd, 0x5a, 0x8f, 0xc0, 0xbe, 0x01, 0x67, 0x43, 0x6c,
                0x59, 0x48, 0x50, 0x1f,
            ],
            [
                0x46, 0x37, 0x6b, 0x80, 0xf4, 0x09, 0xb2, 0x9d, 0xc2, 0xb5, 0xf6, 0xf0, 0xc5, 0x25,
                0x91, 0x99, 0x08, 0x96, 0xe5, 0x71, 0x6f, 0x41, 0x47, 0x7c, 0xd3, 0x00, 0x85, 0xab,
                0x7f, 0x10, 0x30, 0x1e,
            ],
            [
                0xe0, 0xc4, 0x18, 0xf7, 0xc8, 0xd9, 0xc4, 0xcd, 0xd7, 0x39, 0x5b, 0x93, 0xea, 0x12,
                0x4f, 0x3a, 0xd9, 0x90, 0x21, 0xbb, 0x68, 0x1d, 0xfc, 0x33, 0x02, 0xa9, 0xd9, 0x9a,
                0x2e, 0x53, 0xe6, 0x4e,
            ],
        ];

        let mut s = Scalar::new_empty()?;

        for (scalar, &point) in scalars.iter().zip(points.iter()) {
            s.copy_from_slice(scalar);
            let actual = scalar_mult_base(&s)?;
            assert_eq!(actual.0, point);
            assert_eq!(GENERATOR.scalar_mult(&s)?.0, point);
        }

        let p = Point([0xfe; 32]);
        let s = Scalar::try_from(&[
            16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ])?;
        assert!(p.scalar_mult(&s).is_err());

        Ok(())
    }

    #[test]
    fn reject_invalid_encodings() -> Result<(), AlkaliError> {
        let bad_encodings = [
            // non-canonical field encodings
            [
                0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff,
            ],
            [
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0x7f,
            ],
            [
                0xf3, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0x7f,
            ],
            [
                0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0x7f,
            ],
            [
                0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x80,
            ],
            // negative field elements
            [
                0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
            ],
            [
                0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0x7f,
            ],
            [
                0xed, 0x57, 0xff, 0xd8, 0xc9, 0x14, 0xfb, 0x20, 0x14, 0x71, 0xd1, 0xc3, 0xd2, 0x45,
                0xce, 0x3c, 0x74, 0x6f, 0xcb, 0xe6, 0x3a, 0x36, 0x79, 0xd5, 0x1b, 0x6a, 0x51, 0x6e,
                0xbe, 0xbe, 0x0e, 0x20,
            ],
            [
                0xc3, 0x4c, 0x4e, 0x18, 0x26, 0xe5, 0xd4, 0x03, 0xb7, 0x8e, 0x24, 0x6e, 0x88, 0xaa,
                0x05, 0x1c, 0x36, 0xcc, 0xf0, 0xaa, 0xfe, 0xbf, 0xfe, 0x13, 0x7d, 0x14, 0x8a, 0x2b,
                0xf9, 0x10, 0x45, 0x62,
            ],
            [
                0xc9, 0x40, 0xe5, 0xa4, 0x40, 0x41, 0x57, 0xcf, 0xb1, 0x62, 0x8b, 0x10, 0x8d, 0xb0,
                0x51, 0xa8, 0xd4, 0x39, 0xe1, 0xa4, 0x21, 0x39, 0x4e, 0xc4, 0xeb, 0xcc, 0xb9, 0xec,
                0x92, 0xa8, 0xac, 0x78,
            ],
            [
                0x47, 0xcf, 0xc5, 0x49, 0x7c, 0x53, 0xdc, 0x8e, 0x61, 0xc9, 0x1d, 0x17, 0xfd, 0x62,
                0x6f, 0xfb, 0x1c, 0x49, 0xe2, 0xbc, 0xa9, 0x4e, 0xed, 0x05, 0x22, 0x81, 0xb5, 0x10,
                0xb1, 0x11, 0x7a, 0x24,
            ],
            [
                0xf1, 0xc6, 0x16, 0x5d, 0x33, 0x36, 0x73, 0x51, 0xb0, 0xda, 0x8f, 0x6e, 0x45, 0x11,
                0x01, 0x0c, 0x68, 0x17, 0x4a, 0x03, 0xb6, 0x58, 0x12, 0x12, 0xc7, 0x1c, 0x0e, 0x1d,
                0x02, 0x6c, 0x3c, 0x72,
            ],
            [
                0x87, 0x26, 0x0f, 0x7a, 0x2f, 0x12, 0x49, 0x51, 0x18, 0x36, 0x0f, 0x02, 0xc2, 0x6a,
                0x47, 0x0f, 0x45, 0x0d, 0xad, 0xf3, 0x4a, 0x41, 0x3d, 0x21, 0x04, 0x2b, 0x43, 0xb9,
                0xd9, 0x3e, 0x13, 0x09,
            ],
            // non-square x^2
            [
                0x26, 0x94, 0x8d, 0x35, 0xca, 0x62, 0xe6, 0x43, 0xe2, 0x6a, 0x83, 0x17, 0x73, 0x32,
                0xe6, 0xb6, 0xaf, 0xeb, 0x9d, 0x08, 0xe4, 0x26, 0x8b, 0x65, 0x0f, 0x1f, 0x5b, 0xbd,
                0x8d, 0x81, 0xd3, 0x71,
            ],
            [
                0x4e, 0xac, 0x07, 0x7a, 0x71, 0x3c, 0x57, 0xb4, 0xf4, 0x39, 0x76, 0x29, 0xa4, 0x14,
                0x59, 0x82, 0xc6, 0x61, 0xf4, 0x80, 0x44, 0xdd, 0x3f, 0x96, 0x42, 0x7d, 0x40, 0xb1,
                0x47, 0xd9, 0x74, 0x2f,
            ],
            [
                0xde, 0x6a, 0x7b, 0x00, 0xde, 0xad, 0xc7, 0x88, 0xeb, 0x6b, 0x6c, 0x8d, 0x20, 0xc0,
                0xae, 0x96, 0xc2, 0xf2, 0x01, 0x90, 0x78, 0xfa, 0x60, 0x4f, 0xee, 0x5b, 0x87, 0xd6,
                0xe9, 0x89, 0xad, 0x7b,
            ],
            [
                0xbc, 0xab, 0x47, 0x7b, 0xe2, 0x08, 0x61, 0xe0, 0x1e, 0x4a, 0x0e, 0x29, 0x52, 0x84,
                0x14, 0x6a, 0x51, 0x01, 0x50, 0xd9, 0x81, 0x77, 0x63, 0xca, 0xf1, 0xa6, 0xf4, 0xb4,
                0x22, 0xd6, 0x70, 0x42,
            ],
            [
                0x2a, 0x29, 0x2d, 0xf7, 0xe3, 0x2c, 0xab, 0xab, 0xbd, 0x9d, 0xe0, 0x88, 0xd1, 0xd1,
                0xab, 0xec, 0x9f, 0xc0, 0x44, 0x0f, 0x63, 0x7e, 0xd2, 0xfb, 0xa1, 0x45, 0x09, 0x4d,
                0xc1, 0x4b, 0xea, 0x08,
            ],
            [
                0xf4, 0xa9, 0xe5, 0x34, 0xfc, 0x0d, 0x21, 0x6c, 0x44, 0xb2, 0x18, 0xfa, 0x0c, 0x42,
                0xd9, 0x96, 0x35, 0xa0, 0x12, 0x7e, 0xe2, 0xe5, 0x3c, 0x71, 0x2f, 0x70, 0x60, 0x96,
                0x49, 0xfd, 0xff, 0x22,
            ],
            [
                0x82, 0x68, 0x43, 0x6f, 0x8c, 0x41, 0x26, 0x19, 0x6c, 0xf6, 0x4b, 0x3c, 0x7d, 0xdb,
                0xda, 0x90, 0x74, 0x6a, 0x37, 0x86, 0x25, 0xf9, 0x81, 0x3d, 0xd9, 0xb8, 0x45, 0x70,
                0x77, 0x25, 0x67, 0x31,
            ],
            [
                0x28, 0x10, 0xe5, 0xcb, 0xc2, 0xcc, 0x4d, 0x4e, 0xec, 0xe5, 0x4f, 0x61, 0xc6, 0xf6,
                0x97, 0x58, 0xe2, 0x89, 0xaa, 0x7a, 0xb4, 0x40, 0xb3, 0xcb, 0xea, 0xa2, 0x19, 0x95,
                0xc2, 0xf4, 0x23, 0x2b,
            ],
            // negative xy value
            [
                0x3e, 0xb8, 0x58, 0xe7, 0x8f, 0x5a, 0x72, 0x54, 0xd8, 0xc9, 0x73, 0x11, 0x74, 0xa9,
                0x4f, 0x76, 0x75, 0x5f, 0xd3, 0x94, 0x1c, 0x0a, 0xc9, 0x37, 0x35, 0xc0, 0x7b, 0xa1,
                0x45, 0x79, 0x63, 0x0e,
            ],
            [
                0xa4, 0x5f, 0xdc, 0x55, 0xc7, 0x64, 0x48, 0xc0, 0x49, 0xa1, 0xab, 0x33, 0xf1, 0x70,
                0x23, 0xed, 0xfb, 0x2b, 0xe3, 0x58, 0x1e, 0x9c, 0x7a, 0xad, 0xe8, 0xa6, 0x12, 0x52,
                0x15, 0xe0, 0x42, 0x20,
            ],
            [
                0xd4, 0x83, 0xfe, 0x81, 0x3c, 0x6b, 0xa6, 0x47, 0xeb, 0xbf, 0xd3, 0xec, 0x41, 0xad,
                0xca, 0x1c, 0x61, 0x30, 0xc2, 0xbe, 0xee, 0xe9, 0xd9, 0xbf, 0x06, 0x5c, 0x8d, 0x15,
                0x1c, 0x5f, 0x39, 0x6e,
            ],
            [
                0x8a, 0x2e, 0x1d, 0x30, 0x05, 0x01, 0x98, 0xc6, 0x5a, 0x54, 0x48, 0x31, 0x23, 0x96,
                0x0c, 0xcc, 0x38, 0xae, 0xf6, 0x84, 0x8e, 0x1e, 0xc8, 0xf5, 0xf7, 0x80, 0xe8, 0x52,
                0x37, 0x69, 0xba, 0x32,
            ],
            [
                0x32, 0x88, 0x84, 0x62, 0xf8, 0xb4, 0x86, 0xc6, 0x8a, 0xd7, 0xdd, 0x96, 0x10, 0xbe,
                0x51, 0x92, 0xbb, 0xea, 0xf3, 0xb4, 0x43, 0x95, 0x1a, 0xc1, 0xa8, 0x11, 0x84, 0x19,
                0xd9, 0xfa, 0x09, 0x7b,
            ],
            [
                0x22, 0x71, 0x42, 0x50, 0x1b, 0x9d, 0x43, 0x55, 0xcc, 0xba, 0x29, 0x04, 0x04, 0xbd,
                0xe4, 0x15, 0x75, 0xb0, 0x37, 0x69, 0x3c, 0xef, 0x1f, 0x43, 0x8c, 0x47, 0xf8, 0xfb,
                0xf3, 0x5d, 0x11, 0x65,
            ],
            [
                0x5c, 0x37, 0xcc, 0x49, 0x1d, 0xa8, 0x47, 0xcf, 0xeb, 0x92, 0x81, 0xd4, 0x07, 0xef,
                0xc4, 0x1e, 0x15, 0x14, 0x4c, 0x87, 0x6e, 0x01, 0x70, 0xb4, 0x99, 0xa9, 0x6a, 0x22,
                0xed, 0x31, 0xe0, 0x1e,
            ],
            [
                0x44, 0x54, 0x25, 0x11, 0x7c, 0xb8, 0xc9, 0x0e, 0xdc, 0xbc, 0x7c, 0x1c, 0xc0, 0xe7,
                0x4f, 0x74, 0x7f, 0x2c, 0x1e, 0xfa, 0x56, 0x30, 0xa9, 0x67, 0xc6, 0x4f, 0x28, 0x77,
                0x92, 0xa4, 0x8a, 0x4b,
            ],
            // s = -1 (causes y = 0)
            [
                0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0x7f,
            ],
        ];

        let mut p = Point([0; 32]);

        for point in bad_encodings {
            p.0.copy_from_slice(&point);
            assert!(!p.is_valid()?);
        }

        Ok(())
    }

    #[test]
    fn point_from_hash() -> Result<(), AlkaliError> {
        let hashes = [
            [
                0x5d, 0x1b, 0xe0, 0x9e, 0x3d, 0x0c, 0x82, 0xfc, 0x53, 0x81, 0x12, 0x49, 0x0e, 0x35,
                0x70, 0x19, 0x79, 0xd9, 0x9e, 0x06, 0xca, 0x3e, 0x2b, 0x5b, 0x54, 0xbf, 0xfe, 0x8b,
                0x4d, 0xc7, 0x72, 0xc1, 0x4d, 0x98, 0xb6, 0x96, 0xa1, 0xbb, 0xfb, 0x5c, 0xa3, 0x2c,
                0x43, 0x6c, 0xc6, 0x1c, 0x16, 0x56, 0x37, 0x90, 0x30, 0x6c, 0x79, 0xea, 0xca, 0x77,
                0x05, 0x66, 0x8b, 0x47, 0xdf, 0xfe, 0x5b, 0xb6,
            ],
            [
                0xf1, 0x16, 0xb3, 0x4b, 0x8f, 0x17, 0xce, 0xb5, 0x6e, 0x87, 0x32, 0xa6, 0x0d, 0x91,
                0x3d, 0xd1, 0x0c, 0xce, 0x47, 0xa6, 0xd5, 0x3b, 0xee, 0x92, 0x04, 0xbe, 0x8b, 0x44,
                0xf6, 0x67, 0x8b, 0x27, 0x01, 0x02, 0xa5, 0x69, 0x02, 0xe2, 0x48, 0x8c, 0x46, 0x12,
                0x0e, 0x92, 0x76, 0xcf, 0xe5, 0x46, 0x38, 0x28, 0x6b, 0x9e, 0x4b, 0x3c, 0xdb, 0x47,
                0x0b, 0x54, 0x2d, 0x46, 0xc2, 0x06, 0x8d, 0x38,
            ],
            [
                0x84, 0x22, 0xe1, 0xbb, 0xda, 0xab, 0x52, 0x93, 0x8b, 0x81, 0xfd, 0x60, 0x2e, 0xff,
                0xb6, 0xf8, 0x91, 0x10, 0xe1, 0xe5, 0x72, 0x08, 0xad, 0x12, 0xd9, 0xad, 0x76, 0x7e,
                0x2e, 0x25, 0x51, 0x0c, 0x27, 0x14, 0x07, 0x75, 0xf9, 0x33, 0x70, 0x88, 0xb9, 0x82,
                0xd8, 0x3d, 0x7f, 0xcf, 0x0b, 0x2f, 0xa1, 0xed, 0xff, 0xe5, 0x19, 0x52, 0xcb, 0xe7,
                0x36, 0x5e, 0x95, 0xc8, 0x6e, 0xaf, 0x32, 0x5c,
            ],
            [
                0xac, 0x22, 0x41, 0x51, 0x29, 0xb6, 0x14, 0x27, 0xbf, 0x46, 0x4e, 0x17, 0xba, 0xee,
                0x8d, 0xb6, 0x59, 0x40, 0xc2, 0x33, 0xb9, 0x8a, 0xfc, 0xe8, 0xd1, 0x7c, 0x57, 0xbe,
                0xeb, 0x78, 0x76, 0xc2, 0x15, 0x0d, 0x15, 0xaf, 0x1c, 0xb1, 0xfb, 0x82, 0x4b, 0xbd,
                0x14, 0x95, 0x5f, 0x2b, 0x57, 0xd0, 0x8d, 0x38, 0x8a, 0xab, 0x43, 0x1a, 0x39, 0x1c,
                0xfc, 0x33, 0xd5, 0xba, 0xfb, 0x5d, 0xbb, 0xaf,
            ],
            [
                0x16, 0x5d, 0x69, 0x7a, 0x1e, 0xf3, 0xd5, 0xcf, 0x3c, 0x38, 0x56, 0x5b, 0xee, 0xfc,
                0xf8, 0x8c, 0x0f, 0x28, 0x2b, 0x8e, 0x7d, 0xbd, 0x28, 0x54, 0x4c, 0x48, 0x34, 0x32,
                0xf1, 0xce, 0xc7, 0x67, 0x5d, 0xeb, 0xea, 0x8e, 0xbb, 0x4e, 0x5f, 0xe7, 0xd6, 0xf6,
                0xe5, 0xdb, 0x15, 0xf1, 0x55, 0x87, 0xac, 0x4d, 0x4d, 0x4a, 0x1d, 0xe7, 0x19, 0x1e,
                0x0c, 0x1c, 0xa6, 0x66, 0x4a, 0xbc, 0xc4, 0x13,
            ],
            [
                0xa8, 0x36, 0xe6, 0xc9, 0xa9, 0xca, 0x9f, 0x1e, 0x8d, 0x48, 0x62, 0x73, 0xad, 0x56,
                0xa7, 0x8c, 0x70, 0xcf, 0x18, 0xf0, 0xce, 0x10, 0xab, 0xb1, 0xc7, 0x17, 0x2d, 0xdd,
                0x60, 0x5d, 0x7f, 0xd2, 0x97, 0x98, 0x54, 0xf4, 0x7a, 0xe1, 0xcc, 0xf2, 0x04, 0xa3,
                0x31, 0x02, 0x09, 0x5b, 0x42, 0x00, 0xe5, 0xbe, 0xfc, 0x04, 0x65, 0xac, 0xcc, 0x26,
                0x31, 0x75, 0x48, 0x5f, 0x0e, 0x17, 0xea, 0x5c,
            ],
            [
                0x2c, 0xdc, 0x11, 0xea, 0xeb, 0x95, 0xda, 0xf0, 0x11, 0x89, 0x41, 0x7c, 0xdd, 0xdb,
                0xf9, 0x59, 0x52, 0x99, 0x3a, 0xa9, 0xcb, 0x9c, 0x64, 0x0e, 0xb5, 0x05, 0x8d, 0x09,
                0x70, 0x2c, 0x74, 0x62, 0x2c, 0x99, 0x65, 0xa6, 0x97, 0xa3, 0xb3, 0x45, 0xec, 0x24,
                0xee, 0x56, 0x33, 0x5b, 0x55, 0x6e, 0x67, 0x7b, 0x30, 0xe6, 0xf9, 0x0a, 0xc7, 0x7d,
                0x78, 0x10, 0x64, 0xf8, 0x66, 0xa3, 0xc9, 0x82,
            ],
        ];
        let points = [
            [
                0x30, 0x66, 0xf8, 0x2a, 0x1a, 0x74, 0x7d, 0x45, 0x12, 0x0d, 0x17, 0x40, 0xf1, 0x43,
                0x58, 0x53, 0x1a, 0x8f, 0x04, 0xbb, 0xff, 0xe6, 0xa8, 0x19, 0xf8, 0x6d, 0xfe, 0x50,
                0xf4, 0x4a, 0x0a, 0x46,
            ],
            [
                0xf2, 0x6e, 0x5b, 0x6f, 0x7d, 0x36, 0x2d, 0x2d, 0x2a, 0x94, 0xc5, 0xd0, 0xe7, 0x60,
                0x2c, 0xb4, 0x77, 0x3c, 0x95, 0xa2, 0xe5, 0xc3, 0x1a, 0x64, 0xf1, 0x33, 0x18, 0x9f,
                0xa7, 0x6e, 0xd6, 0x1b,
            ],
            [
                0x00, 0x6c, 0xcd, 0x2a, 0x9e, 0x68, 0x67, 0xe6, 0xa2, 0xc5, 0xce, 0xa8, 0x3d, 0x33,
                0x02, 0xcc, 0x9d, 0xe1, 0x28, 0xdd, 0x2a, 0x9a, 0x57, 0xdd, 0x8e, 0xe7, 0xb9, 0xd7,
                0xff, 0xe0, 0x28, 0x26,
            ],
            [
                0xf8, 0xf0, 0xc8, 0x7c, 0xf2, 0x37, 0x95, 0x3c, 0x58, 0x90, 0xae, 0xc3, 0x99, 0x81,
                0x69, 0x00, 0x5d, 0xae, 0x3e, 0xca, 0x1f, 0xbb, 0x04, 0x54, 0x8c, 0x63, 0x59, 0x53,
                0xc8, 0x17, 0xf9, 0x2a,
            ],
            [
                0xae, 0x81, 0xe7, 0xde, 0xdf, 0x20, 0xa4, 0x97, 0xe1, 0x0c, 0x30, 0x4a, 0x76, 0x5c,
                0x17, 0x67, 0xa4, 0x2d, 0x6e, 0x06, 0x02, 0x97, 0x58, 0xd2, 0xd7, 0xe8, 0xef, 0x7c,
                0xc4, 0xc4, 0x11, 0x79,
            ],
            [
                0xe2, 0x70, 0x56, 0x52, 0xff, 0x9f, 0x5e, 0x44, 0xd3, 0xe8, 0x41, 0xbf, 0x1c, 0x25,
                0x1c, 0xf7, 0xdd, 0xdb, 0x77, 0xd1, 0x40, 0x87, 0x0d, 0x1a, 0xb2, 0xed, 0x64, 0xf1,
                0xa9, 0xce, 0x86, 0x28,
            ],
            [
                0x80, 0xbd, 0x07, 0x26, 0x25, 0x11, 0xcd, 0xde, 0x48, 0x63, 0xf8, 0xa7, 0x43, 0x4c,
                0xef, 0x69, 0x67, 0x50, 0x68, 0x1c, 0xb9, 0x51, 0x0e, 0xea, 0x55, 0x70, 0x88, 0xf7,
                0x6d, 0x9e, 0x50, 0x65,
            ],
        ];

        for (&hash, expected) in hashes.iter().zip(&points) {
            let p = Point::from_hash(&Hash(hash))?;
            assert_eq!(&p.0[..], &expected[..]);
            assert!(p.is_valid()?);
        }

        Ok(())
    }

    #[test]
    fn point_addition_subtraction() -> Result<(), AlkaliError> {
        let mut p = Point::generate()?;
        let p2 = p;
        let q = Point::generate()?;

        let repetitions = random::random_u32_in_range(1, 100)? as usize;

        for _ in 0..repetitions {
            p.add_in_place(&q)?;
            assert!(p.is_valid()?);
        }
        assert_ne!(p.0, p2.0);

        for _ in 0..repetitions {
            p.sub_in_place(&q)?;
            assert!(p.is_valid()?);
        }
        assert_eq!(p.0, p2.0);

        Ok(())
    }

    #[test]
    fn scalar_complement_over_mul() -> Result<(), AlkaliError> {
        let mut h = [0u8; HASH_LENGTH];
        random::fill_random(&mut h)?;
        let mut p = Point::from_hash(&Hash(h))?;
        let mut q = p;
        let mut s = Scalar::generate()?;

        p.scalar_mult_in_place(&s)?;
        s.complement()?;
        q.scalar_mult_in_place(&s)?;

        let r = p.add(&q)?;
        let mut p_orig = Point::from_hash(&Hash(h))?;
        p_orig.sub_in_place(&r)?;

        assert_eq!(
            p_orig.0,
            [
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00
            ]
        );

        Ok(())
    }

    #[test]
    fn scalar_negate_over_mul() -> Result<(), AlkaliError> {
        let mut p = Point::generate()?;
        let mut q = p;
        let mut s = Scalar::generate()?;

        p.scalar_mult_in_place(&s)?;
        s.additive_inverse()?;
        q.scalar_mult_in_place(&s)?;

        p.add_in_place(&q)?;

        assert_eq!(
            p.0,
            [
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00
            ]
        );

        Ok(())
    }
}
