//! [Ed25519](https://en.wikipedia.org/wiki/EdDSA#Ed25519) group operations.
//!
//! This module corresponds to the [`crypto_core_ed25519`
//! API](https://doc.libsodium.org/advanced/point-arithmetic) from Sodium.
//!
//! Ed25519 is the twisted Edwards curve `-x^2 + y^1 = 1 - (121665/121666) * x^2 * y^2` defined over
//! the prime field of order `2^255 - 19`, with generator given by the point on the curve with
//! `y = 4/5` and positive `x` coordinate.
//!
//! Ed25519 is not of prime-order: The number of points on the curve is `8 * p`, where `p` is a
//! large prime. Many cryptographic operations require that operations are performed over a
//! prime-order group, so normally all the points on the curve are scalar-multiplied by 8, to obtain
//! a prime-order subgroup. [This blog
//! post](https://www.jcraige.com/an-explainer-on-ed25519-clamping) explains the
//! clamping procedure, which is applied as part of the default scalar multiplication operation
//! here.

use super::{curve25519, CurveError};
use crate::{assert_not_err, mem, require_init, AlkaliError};
use libsodium_sys as sodium;

/// The length of the byte representation of a point on the curve, in bytes.
pub const POINT_LENGTH: usize = sodium::crypto_core_ed25519_BYTES as usize;

/// The length of a secret scalar by which a point on the curve can be multiplied, in bytes.
pub const SCALAR_LENGTH: usize = sodium::crypto_core_ed25519_SCALARBYTES as usize;

/// The length of a value which can be reduced to produce a [`Scalar`], in bytes.
pub const UNREDUCED_SCALAR_LENGTH: usize =
    sodium::crypto_core_ed25519_NONREDUCEDSCALARBYTES as usize;

/// The length of a value from which a point on the curve can be derived using
/// [`Point::from_uniform`], in bytes.
pub const UNIFORM_LENGTH: usize = sodium::crypto_core_ed25519_UNIFORMBYTES as usize;

mem::hardened_buffer! {
    /// A secret scalar value by which a point on the curve can be scalar-multiplied.
    ///
    /// A scalar such as this generally takes the role of a secret key in elliptic-curve
    /// cryptography. Given `Q = nP`, where `Q, P` are public points on the curve, and `n` is an
    /// unknown scalar, it is computationally infeasible to calculate `n` (ECDLP).
    ///
    /// A scalar should be between 0 (inclusive) and `L = 2^252 +
    /// 27742317777372353535851937790883648493` (exclusive). If a scalar is intended to be secret,
    /// it should be generated randomly using [`Scalar::generate`].
    ///
    /// This is a [hardened buffer type](https://docs.rs/alkali#hardened-buffer-types), and will be
    /// zeroed on drop. A number of other security measures are taken to protect its contents. This
    /// type in particular can be thought of as roughly equivalent to a `[u8;
    /// UNREDUCED_SCALAR_LENGTH]`, and implements [`core::ops::Deref`], so it can be used like it is
    /// an `&[u8]`. This struct uses heap memory while in scope, allocated using Sodium's [secure
    /// memory utilities](https://doc.libsodium.org/memory_management).
    pub Scalar(SCALAR_LENGTH);

    /// A value which can be reduced modulo `L` to produce a [`Scalar`] using
    /// [`Scalar::reduce_from`].
    ///
    /// This is a [hardened buffer type](https://docs.rs/alkali#hardened-buffer-types), and will be
    /// zeroed on drop. A number of other security measures are taken to protect its contents. This
    /// type in particular can be thought of as roughly equivalent to a `[u8; SCALAR_LENGTH]`, and
    /// implements [`core::ops::Deref`], so it can be used like it is an `&[u8]`. This struct uses
    /// heap memory while in scope, allocated using Sodium's [secure memory
    /// utilities](https://doc.libsodium.org/memory_management).
    pub UnreducedScalar(UNREDUCED_SCALAR_LENGTH);
}

impl Scalar<mem::FullAccess> {
    /// Generate a random scalar value for use with Ed25519.
    ///
    /// The generated scalar will be between 0 and `L = 2^252 +
    /// 27742317777372353535851937790883648493` (exclusive).
    pub fn generate() -> Result<Self, AlkaliError> {
        require_init()?;

        let mut scalar = Self::new_empty()?;
        unsafe {
            // SAFETY: The argument to this function should be a destination to which the
            // randomly-generated scalar should be written. We define the `Scalar` type to allocate
            // `crypto_core_ed25519_SCALARBYTES` bytes, the length of a reduced scalar for this
            // algorithm, so `scalar` is valid for writes of the required length. The
            // `Scalar::inner_mut` method simply returns a mutable pointer to the struct's backing
            // memory.
            sodium::crypto_core_ed25519_scalar_random(scalar.inner_mut().cast());
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
            // `crypto_core_ed25519_SCALARBYTES`, the length of a reduced scalar value for this
            // algorithm, so `scalar` is valid for writes of the required length. The second
            // argument should be the larger value which will be reduced to produce the scalar, of
            // length `crypto_core_ed25519_NONREDUCEDSCALARBYTES`. We define the `UnreducedScalar`
            // type to allocate this many bytes, so `unreduced` is valid for reads of the required
            // length.
            sodium::crypto_core_ed25519_scalar_reduce(
                scalar.inner_mut().cast(),
                unreduced.inner().cast(),
            );
        }

        Ok(scalar)
    }

    /// Convert this Ed25519 secret key to a Curve25519 secret key.
    pub fn to_curve25519(&self) -> Result<curve25519::Scalar<mem::FullAccess>, AlkaliError> {
        require_init()?;

        let mut s = curve25519::Scalar::new_empty()?;
        let conversion_result = unsafe {
            // SAFETY: The first argument to this function is the destination to which the
            // calculated Curve25519 secret scalar should be written. We define the
            // `curve25519::Scalar` type to allocate `crypto_scalarmult_curve25519_SCALARBYTES`, the
            // length of a scalar for Curve25519, so `s` is valid for writes of the required length.
            // The second argument is the Ed25519 scalar to convert to Curve25519. We define the
            // `Scalar` type to allocate `crypto_core_ed25519_SCALARBYTES`, the length of a scalar
            // for Ed25519. This is half the length of `crypto_sign_ed25519_SCALARBYTES`, as
            // generally for the sign API, the public key is appended to the private key. However,
            // it is documented that this function specifically will only read the first
            // `crypto_core_ed25519_SCALARBYTES` of this value, so `self` is valid for reads of the
            // required length. The `Scalar::inner()` method returns a pointer to the scalar's
            // backing memory.
            sodium::crypto_sign_ed25519_sk_to_curve25519(s.as_mut_ptr(), self.inner().cast())
        };
        assert_not_err!(conversion_result, "crypto_sign_ed25519_sk_to_curve25519");

        Ok(s)
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
            // written. We define the `Scalar` type to allocate `crypto_core_ed25519_SCALARBYTES`,
            // the length of a reduced scalar value for this algorithm, so `self` is valid for
            // writes of the required length. The second argument is the scalar to invert. We define
            // the `buf` array to be of length `crypto_core_ed25519_SCALARBYTES`, so it is valid for
            // reads of the required length.
            sodium::crypto_core_ed25519_scalar_invert(self.inner_mut().cast(), buf.as_ptr())
        };
        mem::clear(&mut buf)?;
        assert_not_err!(invert_result, "crypto_core_ed25519_scalar_invert");

        Ok(())
    }

    /// Compute the additive inverse of this scalar modulo `L = 2^252 +
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
            // written. We define the `Scalar` type to allocate `crypto_core_ed25519_SCALARBYTES`,
            // the length of a reduced scalar value for this algorithm, so `self` is valid for
            // writes of the required length. The second argument is the scalar to negate. We define
            // the `buf` array to be of length `crypto_core_ed25519_SCALARBYTES`, so it is valid for
            // reads of the required length.
            sodium::crypto_core_ed25519_scalar_negate(self.inner_mut().cast(), buf.as_ptr());
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
            // `crypto_core_ed25519_SCALARBYTES`, the length of a reduced scalar value for this
            // algorithm, so `self` is valid for writes of the required length. The second argument
            // is the scalar to complement. We define the `buf` array to be of length
            // `crypto_core_ed25519_SCALARBYTES`, so it is valid for reads of the required length.
            sodium::crypto_core_ed25519_scalar_complement(self.inner_mut().cast(), buf.as_ptr());
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
            // written. We define the `Scalar` type to allocate `crypto_core_ed25519_SCALARBYTES`,
            // the length of a reduced scalar value for this algorithm, so `self` is valid for
            // writes of the required length. The second and third arguments are the scalar
            // summands. We define the `buf` array and `Scalar` type to store
            // `crypto_core_ed25519_SCALARBYTES`, so `s` and `buf` are valid for reads of the
            // required length.
            sodium::crypto_core_ed25519_scalar_add(
                self.inner_mut().cast(),
                buf.as_ptr(),
                s.inner().cast(),
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
            // `crypto_core_ed25519_SCALARBYTES`, the length of a reduced scalar value for this
            // algorithm, so `self` is valid for writes of the required length. The second and third
            // arguments are the arguments to the minus operation. We define the `buf` array and
            // `Scalar` type to store `crypto_core_ed25519_SCALARBYTES`, so `s` and `buf` are valid
            // for reads of the required length.
            sodium::crypto_core_ed25519_scalar_sub(
                self.inner_mut().cast(),
                buf.as_ptr(),
                s.inner().cast(),
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
            // written. We define the `Scalar` type to allocate `crypto_core_ed25519_SCALARBYTES`,
            // the length of a reduced scalar value for this algorithm, so `self` is valid for
            // writes of the required length. The second and third arguments are the scalar
            // multiplicands. We define the `buf` array and `Scalar` type to store
            // `crypto_core_ed25519_SCALARBYTES`, so `s` and `buf` are valid for reads of the
            // required length.
            sodium::crypto_core_ed25519_scalar_mul(
                self.inner_mut().cast(),
                buf.as_ptr(),
                s.inner().cast(),
            );
        }
        mem::clear(&mut buf)?;

        Ok(())
    }
}

/// A 32-byte value from which a point on the curve can be derived via the Elligator 2 map via
/// [`Point::from_uniform`].
pub type Uniform = [u8; UNIFORM_LENGTH];

/// A point on Ed25519.
///
/// For Ed25519, only the `y` coordinate is stored.
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "use-serde", derive(serde::Serialize, serde::Deserialize))]
#[allow(clippy::unsafe_derive_deserialize)]
pub struct Point(pub [u8; POINT_LENGTH]);

impl Point {
    /// Generate a random point on Ed25519.
    ///
    /// The generated point will be on the curve, and on the prime-order subgroup.
    pub fn generate() -> Result<Self, AlkaliError> {
        require_init()?;

        let mut p = [0; POINT_LENGTH];
        unsafe {
            // SAFETY: The argument to this function should be a destination to which the
            // randomly-generated point should be written. We define the `p` array to store
            // `crypto_core_ed25519_BYTES` bytes, the length of the compressed point format for this
            // algorithm, so `p` is valid for writes of the required length.
            sodium::crypto_core_ed25519_random(p.as_mut_ptr());
        }
        Ok(Point(p))
    }

    /// Deterministically derive a point on Ed25519 from a 32-byte value.
    ///
    /// The generated point will be on the curve, and on the prime-order subgroup.
    ///
    /// This applies the Elligator 2 decoding map, and uses the high bit to set the sign of the X
    /// coordinate. The derived curve point is multiplied by the cofactor to ensure the final point
    /// is on the prime-order subgroup.
    pub fn from_uniform(u: &Uniform) -> Result<Self, AlkaliError> {
        require_init()?;

        let mut p = [0; POINT_LENGTH];
        let from_uniform_result = unsafe {
            // SAFETY: The first argument to this function is the destination to which the derived
            // point on the curve will be written. We define the `p` array to store
            // `crypto_core_ed25519_BYTES` bytes, the length of the compressed point format for this
            // algorithm, so `p` is valid for writes of the required length. The next argument is
            // the 32-byte value from which the point should be derived. We define the `Uniform`
            // type to be `crypto_core_ed25519_UNIFORMBYTES` bytes, the length of a value from which
            // a point can be derived. Therefore `u` is valid for reads of the required length.
            sodium::crypto_core_ed25519_from_uniform(p.as_mut_ptr(), u.as_ptr())
        };
        assert_not_err!(from_uniform_result, "crypto_core_ed25519_from_uniform");

        Ok(Point(p))
    }

    /// Is this [`Point`] on the prime-order subgroup of the curve, and in canonical form?
    ///
    /// The set of values which can be represented in a `[u8; POINT_LENGTH]` is considerably larger
    /// than the set of values which are valid points on the curve, of prime order, in canonical
    /// form. This function returns `true` if `self` is a point on the curve, is of prime order, and
    /// is in canonical form, or `false` otherwise.
    ///
    /// This must be `true` to use the [`Point::scalar_mult`], [`Point::scalar_mult_in_place`],
    /// [`Point::scalar_mult_no_clamp`], or [`Point::scalar_mult_in_place_no_clamp`] functions.
    pub fn is_valid(&self) -> Result<bool, AlkaliError> {
        require_init()?;

        let valid = unsafe {
            // SAFETY: This function expects a pointer to a compressed representation of an Ed25519
            // point, of length `crypto_core_ed25519_BYTES` bytes. We define the `Point` type to
            // store this many bytes, so `self.0` is valid for reads of the required length.
            sodium::crypto_core_ed25519_is_valid_point(self.0.as_ptr())
        };

        Ok(valid == 1)
    }
    /// Convert this Ed25519 public key to a Curve25519 public key.
    pub fn to_curve25519(&self) -> Result<curve25519::Point, AlkaliError> {
        require_init()?;

        let mut p = [0u8; curve25519::POINT_LENGTH];
        let conversion_result = unsafe {
            // SAFETY: The first argument to this function is the destination to which the
            // calculated Curve25519 point should be written. We define the `curve25519::Point` type
            // to allocate `crypto_scalarmult_curve25519_BYTES`, the length of the point
            // representation for Curve25519, so `p` is valid for writes of the required length. The
            // second argument is the Ed25519 point to convert to Curve25519. We define the `Point`
            // type to store `crypto_core_ed25519_BYTES`, the length of the point representation for
            // Ed25519, so `self.0` is valid for reads of the required length.
            sodium::crypto_sign_ed25519_pk_to_curve25519(p.as_mut_ptr(), self.0.as_ptr())
        };

        if conversion_result == 0 {
            Ok(curve25519::Point(p))
        } else {
            Err(CurveError::ConversionFailed.into())
        }
    }

    /// Scalar-multiply this point by the scalar `n`.
    ///
    /// Calculates `Q = nP`, where `P` is this point, `n` is the [`Scalar`] by which `P` should be
    /// multiplied, and `Q` is the return value. That is, `P` is added to itself `n` times.
    ///
    /// Finding `n` given `Q` and `P` is the elliptic curve discrete logarithm problem, since we
    /// check that `P` is in the prime-order subgroup of the curve, so it is computationally
    /// infeasible to find `n`. This can be used to compute a shared secret `Q`, if `P` is a user's
    /// public key and `n` is another user's secret key.
    ///
    /// `n` will be [clamped](https://www.jcraige.com/an-explainer-on-ed25519-clamping) before
    /// multiplying. Use [`Point::scalar_mult_no_clamp`] if clamping is not required for your
    /// application.
    ///
    /// Returns the result of the scalar multiplication (a new point on the curve), or an error if
    /// this point is not on the curve, is of low order, or is not in canonical form.
    pub fn scalar_mult(&self, n: &Scalar<impl mem::MprotectReadable>) -> Result<Self, AlkaliError> {
        require_init()?;

        let mut q = [0u8; POINT_LENGTH];

        let scalarmult_result = unsafe {
            // SAFETY: The first argument to this function is the destination to which the scalar
            // product should be written, a point on Ed25519 in compressed format. We define `q` to
            // be `crypto_scalarmult_ed25519_BYTES`, the length of the compressed Ed25519 point
            // representation, so `q` is valid for writes of the required length. The next argument
            // is the scalar to multiply by. The `Scalar` type is defined to allocate
            // `crypto_scalarmult_ed25519_SCALARBYTES` bytes, the length of a scalar for this
            // algorithm, so `n` is valid for reads of the required length. The final argument is
            // the compressed representation of the point on Ed25519 which should be multiplied by
            // the scalar. The `Point` type stores `crypto_scalarmult_ed25519_BYTES` bytes, the
            // length of the compressed Ed25519 point representation, so `self.0` is valid for reads
            // of the required length. The `Scalar::inner` method simply returns a pointer to the
            // backing memory of the struct.
            sodium::crypto_scalarmult_ed25519(q.as_mut_ptr(), n.inner().cast(), self.0.as_ptr())
        };

        if scalarmult_result == 0 {
            Ok(Point(q))
        } else {
            Err(CurveError::ScalarMultUnacceptable.into())
        }
    }

    /// Scalar multiply this point by the scalar `n`, in place.
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

    /// Scalar-multiply this point by the scalar `n`, without first clamping `n`.
    ///
    /// This function is equivalent to [`Self::scalar_mult`], but `n` will not be
    /// [clamped](https://www.jcraige.com/an-explainer-on-ed25519-clamping) before multiplying. Use
    /// [`Point::scalar_mult`] if clamping is required.
    pub fn scalar_mult_no_clamp(
        &self,
        n: &Scalar<impl mem::MprotectReadable>,
    ) -> Result<Self, AlkaliError> {
        require_init()?;

        let mut q = [0u8; POINT_LENGTH];

        let scalarmult_result = unsafe {
            // SAFETY: The first argument to this function is the destination to which the scalar
            // product should be written, a point on Ed25519 in compressed format. We define `q` to
            // be `crypto_scalarmult_ed25520_BYTES`, the length of the compressed Ed25519 point
            // representation, so `q` is valid for writes of the required length. The next argument
            // is the scalar to multiply by. The `Scalar` type is defined to allocate
            // `crypto_scalarmult_ed25519_SCALARBYTES` bytes, the length of a scalar for this
            // algorithm, so `n` is valid for reads of the required length. The final argument is
            // the compressed representation of the point on Ed25519 which should be multiplied by
            // the scalar. The `Point` type stores `crypto_scalarmult_ed25519_BYTES` bytes, the
            // length of the compressed Ed25519 point representation, so `self.0` is valid for reads
            // of the required length. The `Scalar::inner` method simply returns a pointer to the
            // backing memory of the struct.
            sodium::crypto_scalarmult_ed25519_noclamp(
                q.as_mut_ptr(),
                n.inner().cast(),
                self.0.as_ptr(),
            )
        };

        if scalarmult_result == 0 {
            Ok(Point(q))
        } else {
            Err(CurveError::ScalarMultUnacceptable.into())
        }
    }

    /// Scalar-multiply this point by the scalar `n` in place, without first clamping `n`.
    ///
    /// This function is equivalent to [`Self::scalar_mult_no_clamp`], but modifies `self` in place,
    /// rather than returning the new point.
    pub fn scalar_mult_in_place_no_clamp(
        &mut self,
        n: &Scalar<impl mem::MprotectReadable>,
    ) -> Result<(), AlkaliError> {
        let q = self.scalar_mult_no_clamp(n)?;
        self.0 = q.0;
        Ok(())
    }

    /// Add the point `q` to this point (the elliptic curve group operation).
    ///
    /// Calculates `R = P + Q`, where `P` is this point, `Q` is the other point, and `+` is the
    /// elliptic curve group operation. Returns `R`.
    ///
    /// `self` and `q` must be valid points on the curve in canonical representation, but do not
    /// need to be in the prime-order subgroup.
    pub fn add(&self, q: &Point) -> Result<Self, AlkaliError> {
        require_init()?;

        let mut r = [0u8; POINT_LENGTH];
        let add_result = unsafe {
            // SAFETY: Each argument to this function should be the compressed representation of a
            // point on Ed25519, of length `crypto_core_ed25519_BYTES`. We define the `Point` type
            // and `r` array to store this many bytes, so `r` is valid for writes of the required
            // length, and `p`, `q` are valid for reads of the required length.
            sodium::crypto_core_ed25519_add(r.as_mut_ptr(), self.0.as_ptr(), q.0.as_ptr())
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
    /// returning the result.
    pub fn add_in_place(&mut self, q: &Point) -> Result<(), AlkaliError> {
        let q = self.add(q)?;
        self.0 = q.0;
        Ok(())
    }

    /// Subtract the point `q` from this point.
    ///
    /// Calculates `R = P - Q`, where `P` is this point, `Q` is the other point, and `-` is the
    /// inverse of the elliptic curve group operation. Returns `R`.
    ///
    /// `self` and `q` must be valid points on the curve in canonical representation, but do not
    /// need to be in the prime-order subgroup.
    pub fn sub(&self, q: &Point) -> Result<Self, AlkaliError> {
        require_init()?;

        let mut r = [0u8; POINT_LENGTH];
        let sub_result = unsafe {
            // SAFETY: Each argument to this function should be the compressed representation of a
            // point on Ed25519, of length `crypto_core_ed25519_BYTES`. We define the `Point` type
            // and `r` array to store this many bytes, so `r` is valid for writes of the required
            // length, and `p`, `q` are valid for reads of the required length.
            sodium::crypto_core_ed25519_sub(r.as_mut_ptr(), self.0.as_ptr(), q.0.as_ptr())
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
    /// returning the result.
    pub fn sub_in_place(&mut self, q: &Point) -> Result<(), AlkaliError> {
        let q = self.sub(q)?;
        self.0 = q.0;
        Ok(())
    }
}

/// Multiply the Ed25519 generator by the scalar `n`.
///
/// Calculates `Q = nG`, where `G` is the generator for the curve (the point with `y = 4/5` and
/// positive `x` coordinate), `n` is the scalar by which `G` should be multiplied, and `Q` is the
/// return value. That is, `G` is added to itself `n` times.
///
/// Finding `n` given `Q` and `G` is the elliptic curve discrete logarithm problem, so it is
/// computationally infeasible to find `n`. This can be used to compute the public key corresponding
/// to the secret key `n`.
///
/// `n` will be [clamped](https://www.jcraige.com/an-explainer-on-ed25519-clamping) before
/// multiplying. Use [`scalar_mult_base_no_clamp`] if clamping is not required for your application.
pub fn scalar_mult_base(n: &Scalar<impl mem::MprotectReadable>) -> Result<Point, AlkaliError> {
    require_init()?;

    let mut q = [0u8; POINT_LENGTH];

    let scalarmult_result = unsafe {
        // SAFETY: The first argument to this function is the destination to which the scalar
        // product should be written, a point on Ed25519 in compressed format. We define `q` to be
        // `crypto_scalarmult_ed25519_BYTES`, the length of the compressed Ed25519 point
        // representation, so `q` is valid for writes of the required length. The next argument is
        // the scalar by which the generator should be multiplied. The `Scalar` type is defined to
        // allocate `crypto_scalarmult_ed25519_SCALARBYTES` bytes, the length of a scalar for this
        // algorithm, so `n` is valid for reads of the required length. The `Scalar::inner` method
        // simply returns a pointer to the backing memory of the struct.
        sodium::crypto_scalarmult_ed25519_base(q.as_mut_ptr(), n.inner().cast())
    };

    if scalarmult_result == 0 {
        Ok(Point(q))
    } else {
        Err(CurveError::ScalarMultUnacceptable.into())
    }
}

/// Multiply the Ed25519 generator by the scalar `n`, without first clamping `n`.
///
/// This function is equivalent to [`scalar_mult_base`], but `n` will not be
/// [clamped](https://www.jcraige.com/an-explainer-on-ed25519-clamping) before multiplying. Use
/// [`scalar_mult_base`] if clamping is required.
pub fn scalar_mult_base_no_clamp(
    n: &Scalar<impl mem::MprotectReadable>,
) -> Result<Point, AlkaliError> {
    require_init()?;

    let mut q = [0u8; POINT_LENGTH];

    let scalarmult_result = unsafe {
        // SAFETY: The first argument to this function is the destination to which the scalar
        // product should be written, a point on Ed25519 in compressed format. We define `q` to be
        // `crypto_scalarmult_ed25519_BYTES`, the length of the compressed Ed25519 point
        // representation, so `q` is valid for writes of the required length. The next argument is
        // the scalar by which the generator should be multiplied. The `Scalar` type is defined to
        // allocate `crypto_scalarmult_ed25519_SCALARBYTES` bytes, the length of a scalar for this
        // algorithm, so `n` is valid for reads of the required length. The `Scalar::inner` method
        // simply returns a pointer to the backing memory of the struct.
        sodium::crypto_scalarmult_ed25519_base_noclamp(q.as_mut_ptr(), n.inner().cast())
    };

    if scalarmult_result == 0 {
        Ok(Point(q))
    } else {
        Err(CurveError::ScalarMultUnacceptable.into())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        scalar_mult_base, scalar_mult_base_no_clamp, Point, Scalar, UnreducedScalar, UNIFORM_LENGTH,
    };
    use crate::{mem, random, util, AlkaliError};

    const NON_CANONICAL: Point = Point([
        0xf6, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ]);
    const NON_CANONICAL_INVALID: Point = Point([
        0xf5, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ]);
    const MAX_CANONICAL: Point = Point([
        0xe4, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
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
    fn scalarmult_random() -> Result<(), AlkaliError> {
        let mut n = Scalar::generate()?;
        let q = scalar_mult_base(&n)?;
        let mut p = Point([
            0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
            0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
            0x66, 0x66, 0x66, 0x66,
        ]);
        let q2 = p.scalar_mult(&n)?;
        assert_eq!(q.0, q2.0);

        mem::clear(n.as_mut())?;
        assert!(scalar_mult_base(&n).is_err());
        assert!(p.scalar_mult(&n).is_err());
        assert!(p.scalar_mult_no_clamp(&n).is_err());

        n[0] = 1;
        scalar_mult_base(&n)?;
        p.scalar_mult(&n)?;
        p.scalar_mult_no_clamp(&n)?;

        assert!(NON_CANONICAL.scalar_mult(&n).is_err());
        assert!(NON_CANONICAL_INVALID.scalar_mult(&n).is_err());
        MAX_CANONICAL.scalar_mult(&n)?;

        n[0] = 9;
        let q = p.scalar_mult(&n)?;
        let q2 = p.scalar_mult_no_clamp(&n)?;
        assert_ne!(q.0, q2.0);
        let q = scalar_mult_base(&n)?;
        let q2 = scalar_mult_base_no_clamp(&n)?;
        assert_ne!(q.0, q2.0);
        n[0] = 8;
        n[31] = 64;
        let q2 = scalar_mult_base_no_clamp(&n)?;
        assert_eq!(q.0, q2.0);

        mem::clear(&mut p.0)?;
        assert!(p.scalar_mult(&n).is_err());
        assert!(p.scalar_mult_no_clamp(&n).is_err());

        n[0] = 8;
        assert!(p.scalar_mult(&n).is_err());
        assert!(p.scalar_mult_no_clamp(&n).is_err());

        Ok(())
    }

    #[test]
    fn to_curve25519() -> Result<(), AlkaliError> {
        let point_ed = Point([
            0xb5, 0x07, 0x6a, 0x84, 0x74, 0xa8, 0x32, 0xda, 0xee, 0x4d, 0xd5, 0xb4, 0x04, 0x09,
            0x83, 0xb6, 0x62, 0x3b, 0x5f, 0x34, 0x4a, 0xca, 0x57, 0xd4, 0xd6, 0xee, 0x4b, 0xaf,
            0x3f, 0x25, 0x9e, 0x6e,
        ]);
        let scalar_ed = Scalar::try_from(&[
            0x42, 0x11, 0x51, 0xa4, 0x59, 0xfa, 0xea, 0xde, 0x3d, 0x24, 0x71, 0x15, 0xf9, 0x4a,
            0xed, 0xae, 0x42, 0x31, 0x81, 0x24, 0x09, 0x5a, 0xfa, 0xbe, 0x4d, 0x14, 0x51, 0xa5,
            0x59, 0xfa, 0xed, 0xee,
        ])?;

        let point_mont = point_ed.to_curve25519()?;
        let scalar_mont = scalar_ed.to_curve25519()?;

        assert_eq!(
            point_mont.0,
            [
                0xf1, 0x81, 0x4f, 0x0e, 0x8f, 0xf1, 0x04, 0x3d, 0x8a, 0x44, 0xd2, 0x5b, 0xab, 0xff,
                0x3c, 0xed, 0xca, 0xe6, 0xc2, 0x2c, 0x3e, 0xda, 0xa4, 0x8f, 0x85, 0x7a, 0xe7, 0x0d,
                0xe2, 0xba, 0xae, 0x50
            ]
        );
        assert_eq!(
            &scalar_mont[..],
            &[
                0x80, 0x52, 0x03, 0x03, 0x76, 0xd4, 0x71, 0x12, 0xbe, 0x7f, 0x73, 0xed, 0x7a, 0x01,
                0x92, 0x93, 0xdd, 0x12, 0xad, 0x91, 0x0b, 0x65, 0x44, 0x55, 0x79, 0x8b, 0x46, 0x67,
                0xd7, 0x3d, 0xe1, 0x66
            ]
        );

        Ok(())
    }

    #[test]
    fn point_from_uniform() -> Result<(), AlkaliError> {
        let mut uniform = [0u8; UNIFORM_LENGTH];
        for _ in 0..500 {
            random::fill_random(&mut uniform)?;
            let point = Point::from_uniform(&uniform)?;
            assert!(point.is_valid()?);
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
            p = p.add(&q)?;
            assert!(p.is_valid()?);
        }
        assert_ne!(p.0, p2.0);

        for _ in 0..repetitions {
            p = p.sub(&q)?;
            assert!(p.is_valid()?);
        }
        assert_eq!(p.0, p2.0);

        Ok(())
    }

    #[test]
    fn repeated_addition_is_scalar_mult() -> Result<(), AlkaliError> {
        let mut p = Point::generate()?;
        let p2 = p;

        for _ in 0..254 {
            p = p.add(&p)?;
        }
        for _ in 0..8 {
            p.add_in_place(&p2)?;
        }

        let mut s = Scalar::new_empty()?;
        s[0] = 8;
        let q = p2.scalar_mult(&s)?;

        assert_eq!(p.0, q.0);

        Ok(())
    }

    #[test]
    fn is_valid() -> Result<(), AlkaliError> {
        let mut p = Point::generate()?;
        assert!(p.is_valid()?);

        mem::clear(&mut p.0)?;
        assert!(!p.is_valid()?);
        p.0[0] = 1;
        assert!(!p.is_valid()?);
        p.0[0] = 2;
        assert!(!p.is_valid()?);
        p.0[0] = 9;
        assert!(p.is_valid()?);

        assert!(MAX_CANONICAL.is_valid()?);
        assert!(!NON_CANONICAL.is_valid()?);
        assert!(!NON_CANONICAL_INVALID.is_valid()?);

        Ok(())
    }

    #[test]
    fn scalar_reduce_from() -> Result<(), AlkaliError> {
        let s = Scalar::generate()?;
        let mut u = UnreducedScalar::new_empty()?;
        u[..32].copy_from_slice(&s[..]);
        let repetitions = random::random_u32_in_range(1, 100)? as u64;
        for _ in 0..repetitions {
            util::add_le(
                &mut u[..],
                &[
                    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde,
                    0xf9, 0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                ],
            )?;
        }
        let t = Scalar::reduce_from(&u)?;
        assert_eq!(&s[..], &t[..]);

        Ok(())
    }

    #[test]
    fn scalar_complement_over_mul() -> Result<(), AlkaliError> {
        let mut uniform = [0u8; UNIFORM_LENGTH];
        random::fill_random(&mut uniform)?;
        let mut p = Point::from_uniform(&uniform)?;
        let mut q = p;
        let mut s = Scalar::generate()?;

        p.scalar_mult_in_place_no_clamp(&s)?;
        s.complement()?;
        q.scalar_mult_in_place_no_clamp(&s)?;

        let r = p.add(&q)?;
        let mut p_orig = Point::from_uniform(&uniform)?;
        p_orig.sub_in_place(&r)?;

        assert_eq!(
            p_orig.0,
            [
                0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
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

        p.scalar_mult_in_place_no_clamp(&s)?;
        s.additive_inverse()?;
        q.scalar_mult_in_place_no_clamp(&s)?;

        p.add_in_place(&q)?;

        assert_eq!(
            p.0,
            [
                0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00
            ]
        );

        Ok(())
    }

    #[test]
    fn scalar_mul_invert_vectors() -> Result<(), AlkaliError> {
        let scalars = [
            [
                0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2,
                0xf1, 0xf0, 0xef, 0xee, 0xed, 0xec, 0xeb, 0xea, 0xe9, 0xe8, 0xe7, 0xe6, 0xe5, 0xe4,
                0xe3, 0xe2, 0xe1, 0xe0,
            ],
            [
                0x58, 0x58, 0xcd, 0xec, 0x40, 0xa0, 0x44, 0xb1, 0x54, 0x8b, 0x3b, 0xb0, 0x8f, 0x8c,
                0xe0, 0xd7, 0x11, 0x03, 0xd1, 0xf8, 0x87, 0xdf, 0x84, 0xeb, 0xc5, 0x02, 0x64, 0x3d,
                0xac, 0x4d, 0xf4, 0x0b,
            ],
            [
                0x20, 0x1f, 0x1e, 0x1d, 0x1c, 0x1b, 0x1a, 0x19, 0x18, 0x17, 0x16, 0x15, 0x14, 0x13,
                0x12, 0x11, 0x10, 0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, 0x07, 0x06, 0x05,
                0x04, 0x03, 0x02, 0x01,
            ],
            [
                0xf7, 0x0b, 0x4f, 0x27, 0x2b, 0x47, 0xbd, 0x6a, 0x10, 0x15, 0xa5, 0x11, 0xfb, 0x3c,
                0x9f, 0xc1, 0xb9, 0xc2, 0x1c, 0xa4, 0xca, 0x2e, 0x17, 0xd5, 0xa2, 0x25, 0xb4, 0xc4,
                0x10, 0xb9, 0xb6, 0x0d,
            ],
        ];

        let inverses = [
            [
                0x58, 0x58, 0xcd, 0xec, 0x40, 0xa0, 0x44, 0xb1, 0x54, 0x8b, 0x3b, 0xb0, 0x8f, 0x8c,
                0xe0, 0xd7, 0x11, 0x03, 0xd1, 0xf8, 0x87, 0xdf, 0x84, 0xeb, 0xc5, 0x02, 0x64, 0x3d,
                0xac, 0x4d, 0xf4, 0x0b,
            ],
            [
                0x09, 0x68, 0x8c, 0xe7, 0x8a, 0x8f, 0xf8, 0x27, 0x3f, 0x63, 0x6b, 0x0b, 0xc7, 0x48,
                0xc0, 0xcc, 0xee, 0xee, 0xed, 0xec, 0xeb, 0xea, 0xe9, 0xe8, 0xe7, 0xe6, 0xe5, 0xe4,
                0xe3, 0xe2, 0xe1, 0x00,
            ],
            [
                0xf7, 0x0b, 0x4f, 0x27, 0x2b, 0x47, 0xbd, 0x6a, 0x10, 0x15, 0xa5, 0x11, 0xfb, 0x3c,
                0x9f, 0xc1, 0xb9, 0xc2, 0x1c, 0xa4, 0xca, 0x2e, 0x17, 0xd5, 0xa2, 0x25, 0xb4, 0xc4,
                0x10, 0xb9, 0xb6, 0x0d,
            ],
            [
                0x20, 0x1f, 0x1e, 0x1d, 0x1c, 0x1b, 0x1a, 0x19, 0x18, 0x17, 0x16, 0x15, 0x14, 0x13,
                0x12, 0x11, 0x10, 0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, 0x07, 0x06, 0x05,
                0x04, 0x03, 0x02, 0x01,
            ],
        ];

        let mut scalar = Scalar::new_empty()?;

        for (s, i) in scalars.iter().zip(&inverses) {
            scalar.copy_from_slice(s);
            scalar.multiplicative_inverse()?;
            assert_eq!(&scalar[..], i);
        }

        Ok(())
    }

    #[test]
    fn scalar_add_invert_vectors() -> Result<(), AlkaliError> {
        let scalars = [
            [
                0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2,
                0xf1, 0xf0, 0xef, 0xee, 0xed, 0xec, 0xeb, 0xea, 0xe9, 0xe8, 0xe7, 0xe6, 0xe5, 0xe4,
                0xe3, 0xe2, 0xe1, 0xe0,
            ],
            [
                0xe4, 0x6b, 0x69, 0x75, 0x8f, 0xd3, 0x19, 0x30, 0x97, 0x39, 0x8c, 0x97, 0x17, 0xb1,
                0x1e, 0x48, 0x11, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
                0x1c, 0x1d, 0x1e, 0x0f,
            ],
            [
                0x20, 0x1f, 0x1e, 0x1d, 0x1c, 0x1b, 0x1a, 0x19, 0x18, 0x17, 0x16, 0x15, 0x14, 0x13,
                0x12, 0x11, 0x10, 0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, 0x07, 0x06, 0x05,
                0x04, 0x03, 0x02, 0x01,
            ],
            [
                0xcd, 0xb4, 0xd7, 0x3f, 0xfe, 0x47, 0xf8, 0x3e, 0xbe, 0x85, 0xe1, 0x8d, 0xca, 0xe6,
                0xcc, 0x03, 0xf0, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa,
                0xfb, 0xfc, 0xfd, 0x0e,
            ],
        ];

        let inverses = [
            [
                0xe4, 0x6b, 0x69, 0x75, 0x8f, 0xd3, 0x19, 0x30, 0x97, 0x39, 0x8c, 0x97, 0x17, 0xb1,
                0x1e, 0x48, 0x11, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
                0x1c, 0x1d, 0x1e, 0x0f,
            ],
            [
                0x09, 0x68, 0x8c, 0xe7, 0x8a, 0x8f, 0xf8, 0x27, 0x3f, 0x63, 0x6b, 0x0b, 0xc7, 0x48,
                0xc0, 0xcc, 0xee, 0xee, 0xed, 0xec, 0xeb, 0xea, 0xe9, 0xe8, 0xe7, 0xe6, 0xe5, 0xe4,
                0xe3, 0xe2, 0xe1, 0x00,
            ],
            [
                0xcd, 0xb4, 0xd7, 0x3f, 0xfe, 0x47, 0xf8, 0x3e, 0xbe, 0x85, 0xe1, 0x8d, 0xca, 0xe6,
                0xcc, 0x03, 0xf0, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa,
                0xfb, 0xfc, 0xfd, 0x0e,
            ],
            [
                0x20, 0x1f, 0x1e, 0x1d, 0x1c, 0x1b, 0x1a, 0x19, 0x18, 0x17, 0x16, 0x15, 0x14, 0x13,
                0x12, 0x11, 0x10, 0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, 0x07, 0x06, 0x05,
                0x04, 0x03, 0x02, 0x01,
            ],
        ];

        let mut scalar = Scalar::new_empty()?;

        for (s, i) in scalars.iter().zip(&inverses) {
            scalar.copy_from_slice(s);
            scalar.additive_inverse()?;
            assert_eq!(&scalar[..], i);
        }

        Ok(())
    }

    #[test]
    fn scalar_complement_vectors() -> Result<(), AlkaliError> {
        let scalars = [
            [
                0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2,
                0xf1, 0xf0, 0xef, 0xee, 0xed, 0xec, 0xeb, 0xea, 0xe9, 0xe8, 0xe7, 0xe6, 0xe5, 0xe4,
                0xe3, 0xe2, 0xe1, 0xe0,
            ],
            [
                0xe5, 0x6b, 0x69, 0x75, 0x8f, 0xd3, 0x19, 0x30, 0x97, 0x39, 0x8c, 0x97, 0x17, 0xb1,
                0x1e, 0x48, 0x11, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
                0x1c, 0x1d, 0x1e, 0x0f,
            ],
            [
                0x20, 0x1f, 0x1e, 0x1d, 0x1c, 0x1b, 0x1a, 0x19, 0x18, 0x17, 0x16, 0x15, 0x14, 0x13,
                0x12, 0x11, 0x10, 0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, 0x07, 0x06, 0x05,
                0x04, 0x03, 0x02, 0x01,
            ],
            [
                0xce, 0xb4, 0xd7, 0x3f, 0xfe, 0x47, 0xf8, 0x3e, 0xbe, 0x85, 0xe1, 0x8d, 0xca, 0xe6,
                0xcc, 0x03, 0xf0, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa,
                0xfb, 0xfc, 0xfd, 0x0e,
            ],
        ];

        let complements = [
            [
                0xe5, 0x6b, 0x69, 0x75, 0x8f, 0xd3, 0x19, 0x30, 0x97, 0x39, 0x8c, 0x97, 0x17, 0xb1,
                0x1e, 0x48, 0x11, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
                0x1c, 0x1d, 0x1e, 0x0f,
            ],
            [
                0x09, 0x68, 0x8c, 0xe7, 0x8a, 0x8f, 0xf8, 0x27, 0x3f, 0x63, 0x6b, 0x0b, 0xc7, 0x48,
                0xc0, 0xcc, 0xee, 0xee, 0xed, 0xec, 0xeb, 0xea, 0xe9, 0xe8, 0xe7, 0xe6, 0xe5, 0xe4,
                0xe3, 0xe2, 0xe1, 0x00,
            ],
            [
                0xce, 0xb4, 0xd7, 0x3f, 0xfe, 0x47, 0xf8, 0x3e, 0xbe, 0x85, 0xe1, 0x8d, 0xca, 0xe6,
                0xcc, 0x03, 0xf0, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa,
                0xfb, 0xfc, 0xfd, 0x0e,
            ],
            [
                0x20, 0x1f, 0x1e, 0x1d, 0x1c, 0x1b, 0x1a, 0x19, 0x18, 0x17, 0x16, 0x15, 0x14, 0x13,
                0x12, 0x11, 0x10, 0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, 0x07, 0x06, 0x05,
                0x04, 0x03, 0x02, 0x01,
            ],
        ];

        let mut scalar = Scalar::new_empty()?;

        for (s, c) in scalars.iter().zip(&complements) {
            scalar.copy_from_slice(s);
            scalar.complement()?;
            assert_eq!(&scalar[..], c);
        }

        Ok(())
    }

    #[test]
    fn scalar_add_sub_vectors() -> Result<(), AlkaliError> {
        let summands = [([0x69; 32], [0x42; 32]), ([0xcd; 32], [0x42; 32])];
        let sums_diffs = [
            (
                [
                    0xf7, 0x56, 0x7c, 0xd8, 0x7c, 0x82, 0xec, 0x1c, 0x35, 0x5a, 0x63, 0x04, 0xc1,
                    0x43, 0xbc, 0xc9, 0xec, 0xed, 0xed, 0xed, 0xed, 0xed, 0xed, 0xed, 0xed, 0xed,
                    0xed, 0xed, 0xed, 0xed, 0xed, 0x0d,
                ],
                [
                    0xf6, 0x7c, 0x79, 0x84, 0x9d, 0xe0, 0x25, 0x3b, 0xa1, 0x42, 0x94, 0x9e, 0x1d,
                    0xb6, 0x22, 0x4b, 0x13, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12,
                    0x12, 0x12, 0x12, 0x12, 0x12, 0x02,
                ],
            ),
            (
                [
                    0xb0, 0x2e, 0x85, 0x81, 0xce, 0x62, 0xf6, 0x99, 0x22, 0x42, 0x7c, 0x23, 0xf9,
                    0x70, 0xf7, 0xe9, 0x51, 0x52, 0x52, 0x52, 0x52, 0x52, 0x52, 0x52, 0x52, 0x52,
                    0x52, 0x52, 0x52, 0x52, 0x52, 0x02,
                ],
                [
                    0x3d, 0xa5, 0x70, 0xdb, 0x4b, 0x00, 0x1c, 0xbe, 0xb3, 0x5a, 0x7b, 0x7f, 0xe5,
                    0x88, 0xe7, 0x2a, 0xae, 0xad, 0xad, 0xad, 0xad, 0xad, 0xad, 0xad, 0xad, 0xad,
                    0xad, 0xad, 0xad, 0xad, 0xad, 0x0d,
                ],
            ),
        ];

        let mut scalar1 = Scalar::new_empty()?;
        let mut scalar2 = Scalar::new_empty()?;
        let mut scalar3 = Scalar::new_empty()?;

        for ((s1, s2), (s, d)) in summands.iter().zip(&sums_diffs) {
            scalar1.copy_from_slice(s1);
            scalar2.copy_from_slice(s2);
            scalar1.add(&scalar2)?;
            scalar1.add(&scalar2)?;
            assert_eq!(&scalar1[..], s);

            scalar3.copy_from_slice(&scalar2[..]);
            scalar3.sub(&scalar1)?;
            scalar3.sub(&scalar2)?;
            assert_eq!(&scalar3[..], d);
        }

        Ok(())
    }

    #[test]
    fn scalar_mul_vectors() -> Result<(), AlkaliError> {
        let mut p = Scalar::try_from(&[0x69; 32])?;
        let mut q = Scalar::try_from(&[0x42; 32])?;

        for _ in 0..100 {
            p.mul(&q)?;
            q.mul(&p)?;
        }

        assert_eq!(
            &q[..],
            &[
                0x44, 0x53, 0xef, 0x38, 0x40, 0x8c, 0x06, 0x67, 0x7c, 0x1b, 0x81, 0x0e, 0x4b, 0xf8,
                0xb1, 0x99, 0x1f, 0x01, 0xc8, 0x87, 0x16, 0xfb, 0xfa, 0x2f, 0x07, 0x5a, 0x51, 0x8b,
                0x77, 0xda, 0x40, 0x0b,
            ]
        );

        Ok(())
    }
}
