//! Random data suitable for cryptographic use.
//!
//! This module is a wrapper around the [`randombytes`
//! API](https://doc.libsodium.org/generating_random_data) from Sodium.
//!
//! Being able to generate unpredictable data is vital to cryptography. This module provides
//! utilities to generate such random data. By default, random data is sourced from the platform's
//! secure RNG API (e.g: /dev/urandom), but [`fill_random_from_seed`] can be used for deterministic
//! pseudo-random number generation if this is required for testing purposes.
//!
//! # Examples
//! Using the [rand](https://rust-random.github.io/book)-compatible API:
//!
//! ```rust
//! use rand::prelude::*;
//! use rand::distributions::{Alphanumeric, DistString};
//! use alkali::random::SodiumRng;
//!
//! let mut rng = SodiumRng;
//!
//! // Demonstrating some APIs from rand
//! let random_number = rng.gen_range(1..101);
//! println!("My random number is... {}", random_number);
//! let random_bool_50 = rng.gen_bool(0.5);
//! println!("True or false? {}", random_bool_50);
//! let random_str = Alphanumeric.sample_string(&mut rng, 20);
//! println!("Here's a random alphanumeric string: '{}'", random_str);
//! ```
//!
//! Using the more basic API:
//!
//! ```rust
//! use alkali::random;
//!
//! let mut my_random_data = [0u8; 32];
//! random::fill_random(&mut my_random_data).unwrap();
//! println!("Here's some random bytes: {:x?}", my_random_data);
//! ```

// TODO: Consider whether we should support specifying a custom RNG, as detailed in
// https://doc.libsodium.org/advanced/custom_rng. Would be helpful for our testing, but I'm unsure
// whether this is beneficial to other crates using this one. We expose a RngCore API anyway, other
// implementations are very easy to swap in.

use crate::{mem, require_init, AlkaliError};
use libsodium_sys as sodium;
use rand_core::{impls, CryptoRng, Error as RandError, RngCore};

/// The length of a seed for use with [`fill_random_from_seed`].
pub const SEED_LENGTH: usize = sodium::randombytes_SEEDBYTES as usize;

mem::hardened_buffer! {
    /// Represents a seed for deterministic pseudo-random number generation, see
    /// [`fill_random_from_seed`].
    ///
    /// If a seed is used to generate pseudo-random data for real-world cryptographic use, the seed
    /// should be treated as securely as a secret/private key, and ideally, should be discarded
    /// immediately after use.
    ///
    /// This is a [hardened buffer type](https://docs.rs/alkali#hardened-buffer-types), and will be
    /// zeroed on drop. A number of other security measures are taken to protect its contents. This
    /// type in particular can be thought of as roughly equivalent to a `[u8; SEED_LENGTH]`, and
    /// implements [`core::ops::Deref`], so it can be used like it is an `&[u8]`. This struct uses
    /// heap memory while in scope, allocated using Sodium's [secure memory
    /// utilities](https://doc.libsodium.org/memory_management).
    pub Seed(SEED_LENGTH)
}

crate::error_type! {
    /// Error type returned if something went wrong in the random module.
    RandomError {
        /// Tried to generate too much random data for a given seed.
        ///
        /// For a specific seed, it is only safe to generate up to 2^38 bytes (=256 GiB) of
        /// pseudo-random data before the output of the RNG may become predictable. This should only
        /// be possible if you are specifying a seed to use for deterministic random number
        /// generation.
        SeedExhausted,

        /// Tried to call [`random_u32_in_range`] with `low` > `high`.
        BoundsInvalid,
    }
}

/// [rand](https://rust-random.github.io/book)-compatible CSPRNG API.
///
/// The `rand` crate exposes a number of utilities for random number generation, and is especially
/// useful for sampling values which conform to a specific distribution. This struct implements the
/// `RngCore` trait, allowing it to be used as a source of randomness for `rand`. It will
/// automatically implement the wider `Rng` trait if this is imported.
#[derive(Clone, Copy, Debug)]
pub struct SodiumRng;

impl RngCore for SodiumRng {
    fn next_u32(&mut self) -> u32 {
        random_u32().unwrap()
    }

    fn next_u64(&mut self) -> u64 {
        impls::next_u64_via_u32(self)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.try_fill_bytes(dest).unwrap();
    }

    #[cfg(feature = "std")]
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), RandError> {
        fill_random(dest).map_err(RandError::new)
    }

    #[cfg(not(feature = "std"))]
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), RandError> {
        fill_random(dest).map_err(|_| {
            core::num::NonZeroU32::new(RandError::CUSTOM_START)
                .unwrap()
                .into()
        })
    }
}

impl CryptoRng for SodiumRng {}

/// Returns a random 32-bit integer.
pub fn random_u32() -> Result<u32, AlkaliError> {
    require_init()?;

    unsafe {
        // SAFETY: This function is safe as long as Sodium has been initialised, which we ensure
        // with the call to `require_init` above.
        Ok(sodium::randombytes_random())
    }
}

/// Returns a random number in the range low (included) to high (excluded).
///
/// This should be preferred to simply taking [`random_u32`] modulo some value, which does not
/// guarantee a uniform distribution of output values.
pub fn random_u32_in_range(low: u32, high: u32) -> Result<u32, AlkaliError> {
    require_init()?;

    if low > high {
        return Err(RandomError::BoundsInvalid.into());
    }

    let upper_bound = high - low;
    let unshifted = unsafe {
        // SAFETY: This function is safe as long as Sodium has been initialised, which we ensure
        // with the call to `require_init` above.
        sodium::randombytes_uniform(upper_bound)
    };

    Ok(low + unshifted)
}

/// Fill `buf` with random data suitable for cryptographic use.
///
/// Returns an error if Sodium could not be correctly initialised.
pub fn fill_random(buf: &mut [u8]) -> Result<(), AlkaliError> {
    require_init()?;

    unsafe {
        // SAFETY: The first argument to this function should be a pointer to which random data will
        // be written, and the second argument should be the number of bytes to write, starting at
        // the pointer. We use `buf.len()` to specify the number of bytes to write, so `buf` is
        // clearly valid for writes of the required length.
        sodium::randombytes_buf(buf.as_mut_ptr() as *mut libc::c_void, buf.len());
    }

    Ok(())
}

/// Fills `buf` with pseudo-random data generated from the seed `seed`.
///
/// With the same seed, the same pseudo-random data will be generated, making this function useful
/// for testing purposes. The generated data will be indistinguishable from random data to a party
/// who does not know the seed.
///
/// Only up to 2^38 bytes (=256 GiB) of data can be generated using this function with a specific
/// seed, otherwise an error will be encountered.
///
/// Returns an [`AlkaliError`] if Sodium could not be correctly initialised, or if too many bytes
/// were requested from this seed.
pub fn fill_random_from_seed(
    buf: &mut [u8],
    seed: &Seed<impl mem::MprotectReadable>,
) -> Result<usize, AlkaliError> {
    require_init()?;

    // We can only safely generate up to 2^38 bytes of pseudo-random data from a given seed. This
    // constraint doesn't apply if we use `randombytes_buf` (unseeded PRNG) since Sodium
    // automatically reseeds the PRNG when required.
    #[cfg(target_pointer_width = "64")]
    if buf.len() > 0x4000000000 {
        return Err(RandomError::SeedExhausted.into());
    }

    unsafe {
        // SAFETY: The first argument to this function should be a pointer to which pseudo-random
        // data will be written, and the second argument should be the number of bytes to write,
        // starting at the pointer. We use `buf.len()` to specify the number of bytes to write, so
        // `buf` is clearly valid for writes of the required length. The third argument should be a
        // pointer to the seed to use for the pseudorandom number generation. We define the `Seed`
        // type to store `randombytes_SEEDBYTES` bytes of data, the length of a seed for this PRNG,
        // so `seed` is valid for reads of the required length. The `Seed::inner` method simply
        // returns an immutable pointer to its backing memory.
        sodium::randombytes_buf_deterministic(
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len(),
            seed.inner() as *const libc::c_uchar,
        );
    }

    Ok(buf.len())
}

#[cfg(test)]
mod tests {
    // It's non-obvious what exactly the tests of this module should contain. For the time being,
    // I'm just doing a basic heuristic of checking that, for sufficiently many random samples, we
    // cover the space of possible outputs. However these tests are mostly here to prevent API
    // regressions, rather than actually "verify" the randomness of the implementation.
    use super::{
        fill_random, fill_random_from_seed, random_u32, random_u32_in_range, Seed, SodiumRng,
    };
    use crate::AlkaliError;
    use rand_core::{Error as RandError, RngCore};

    #[test]
    fn random_u32_appears_random() -> Result<(), AlkaliError> {
        let mut x: u32;

        for shift in [0, 8, 16, 24] {
            let mut seen = [false; 256];

            for _ in 0..65535 {
                x = random_u32()?;
                seen[((x >> shift) & 0xff) as usize] = true;
            }

            assert!(seen.iter().position(|b| !b).is_none());
        }

        Ok(())
    }

    #[test]
    fn random_u32_in_range_appears_random() -> Result<(), AlkaliError> {
        let mut seen = [false; 256];
        let mut x: u32;

        for _ in 0..65535 {
            x = random_u32_in_range(256, 512)?;
            assert!(x >= 256);
            assert!(x < 512);
            seen[(x - 256) as usize] = true;
        }

        assert!(seen.iter().position(|b| !b).is_none());

        Ok(())
    }

    #[test]
    fn fill_random_appears_random() -> Result<(), AlkaliError> {
        let mut buf = [0u8; 65536];
        fill_random(&mut buf)?;

        let mut seen = [0; 256];
        for b in buf {
            seen[b as usize] += 1;
        }

        for c in seen {
            assert!(c > 0);
        }

        Ok(())
    }

    #[test]
    fn fill_random_from_seed_vector() -> Result<(), AlkaliError> {
        let seed = Seed::try_from(&[
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ])?;
        let expected = [
            0x0d, 0x8e, 0x6c, 0xc6, 0x87, 0x15, 0x64, 0x89, 0x26, 0x73, 0x2e, 0x7e, 0xa7, 0x32,
            0x50, 0xcf, 0xaf, 0x2d, 0x58, 0x42, 0x20, 0x83, 0x90, 0x4c, 0x84, 0x1a, 0x8b, 0xa3,
            0x3b, 0x98, 0x61, 0x11, 0xf3, 0x46, 0xba, 0x50, 0x72, 0x3a, 0x68, 0xae, 0x28, 0x35,
            0x24, 0xa6, 0xbd, 0xed, 0x09, 0xf8, 0x3b, 0xe6, 0xb8, 0x05, 0x95, 0x85, 0x6f, 0x72,
            0xe2, 0x5b, 0x86, 0x91, 0x8e, 0x8b, 0x11, 0x4b, 0xaf, 0xb9, 0x4b, 0xc8, 0xab, 0xed,
            0xd7, 0x3d, 0xaa, 0xb4, 0x54, 0x57, 0x6b, 0x7c, 0x58, 0x33, 0xeb, 0x0b, 0xf9, 0x82,
            0xa1, 0xbb, 0x45, 0x87, 0xa5, 0xc9, 0x70, 0xff, 0x08, 0x10, 0xca, 0x3b, 0x79, 0x1d,
            0x7e, 0x12,
        ];
        let mut actual = [0u8; 100];

        fill_random_from_seed(&mut actual, &seed)?;
        assert_eq!(&actual, &expected);

        Ok(())
    }

    #[test]
    fn sodiumrng_is_rngcore() -> Result<(), RandError> {
        let mut x: u64;

        for shift in [0, 8, 16, 24, 32, 40, 48, 56] {
            let mut seen = [false; 256];

            for _ in 0..65535 {
                x = SodiumRng.next_u64();
                seen[((x >> shift) & 0xff) as usize] = true;
            }

            assert!(seen.iter().position(|b| !b).is_none());
        }

        let mut buf = [0u8; 65536];
        SodiumRng.try_fill_bytes(&mut buf)?;

        let mut seen = [0; 256];
        for b in buf {
            seen[b as usize] += 1;
        }

        for c in seen {
            assert!(c > 0);
        }

        Ok(())
    }
}
