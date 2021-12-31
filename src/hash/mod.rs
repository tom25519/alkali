//! Hash algorithms.
//!
//! Hash algorithms are used to produce a fixed-size output (called the digest) from an
//! arbitrary-length input. [Cryptographic hash
//! functions](https://en.wikipedia.org/wiki/Cryptographic_hash_function) aim for three key
//! properties: Pre-image resistance (given `h`, it should be difficult to find `m` such that `h =
//! hash(m)`), second pre-image resistance (given `m`, it should be difficult to find `n` such that
//! `hash(m) = hash(n)`), and collision resistance (it should be difficult to find `m` and `n` such
//! that `hash(m) = hash(n)`). These three properties, in combination, give rise to a number of use
//! cases for hash algorithms.

pub mod pbkdf;
