//! Low-level Elliptic Curve operations.
//!
//! The asymmetric cryptography in Sodium makes use of [Elliptic Curve
//! Cryptography](https://en.wikipedia.org/wiki/Elliptic-curve_cryptography). In particular,
//! [Curve25519](https://en.wikipedia.org/wiki/Curve25519) is always used for key exchange, and
//! [Ed25519](https://en.wikipedia.org/wiki/EdDSA#Ed25519) is always used for message signatures
//! (these two curves are actually birationally equivalent).
//!
//! In general, Sodium is designed such that you never have to interact with the underlying elliptic
//! curve group operations directly. For example, the
//! [`asymmetric::cipher`](crate::asymmetric::cipher) module takes care of performing a key exchange
//! over Curve25519, then deriving a symmetric key from that exchange which is used with a symmetric
//! cipher to perform encryption. However, if you need to directly perform group operations on the
//! underlying elliptic curves, this module exposes an API for doing so.
//!
//! # Security Considerations
//! The security considerations associated with this module will vary widely depending on your
//! use-case. It is expected that you understand the security implications of the use of low-level
//! curve operations and the different algorithms provided here before using this module.

pub mod curve25519;
#[cfg(not(feature = "minimal"))]
#[cfg_attr(doc_cfg, doc(cfg(not(feature = "minimal"))))]
pub mod ed25519;
#[cfg(not(feature = "minimal"))]
#[cfg_attr(doc_cfg, doc(cfg(not(feature = "minimal"))))]
pub mod ristretto255;

crate::error_type! {
    /// Error type returned if something went wrong in the `curve` module.
    CurveError {
        /// The given point/scalar cannot be scalar multiplied with this API.
        ///
        /// For Curve25519, this indicates the point is of low order: Performing a key exchange with
        /// this point could leak the secret key.
        ///
        /// For Ed25519, this could indicate a number of issues: The scalar could be zero, the point
        /// could be of low order, the point could not be on the curve at all, or the point may not
        /// be provided in canonical form.
        ///
        /// For Ristretto255, this indicates the calculated product is the identity element or that
        /// the scalar is zero.
        ScalarMultUnacceptable,

        /// One of the given points is not a valid representation of a point on the curve.
        InvalidPoint,

        /// Could not invert the provided scalar.
        ///
        /// You cannot invert a scalar if it is zero, as there does not exist a value `n` such that
        /// `0n` is congruent to `1`.
        InversionFailed,

        /// Could not convert the provided Ed25519 point to a Curve25519 point.
        ///
        /// Only points on the main (prime-order) subgroup of the Ed25519 curve can be converted to
        /// points on Curve25519.
        ConversionFailed,
    }
}
