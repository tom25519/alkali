//! Password hashing (Password-based Key Derivation Function)
//!
//! This module corresponds to the [`crypto_pwhash`
//! API](https://doc.libsodium.org/password_hashing) from Sodium.
//!
//! Many hash algorithms are designed to be fast to compute, while still preserving pre-image and
//! collision resistance. Password hashing is different: A normal user's password is actually not
//! hashed very often (typically only on login), so a very slow hash algorithm doesn't have a major
//! impact on them. However, for an attacker trying to brute force a password given its hash, the
//! slowdown caused by a slow algorithm has a major impact. Therefore, password-based key derivation
//! algorithms, such as those in this module, are intentionally computationally-intensive.
//!
//! Password-based key derivation is used for password storage, in which we store a hash of a
//! password rather than the password itself. When a user wishes to login, we compare the hash of
//! the password they provide with the hash we have stored. The [Wikipedia article on hash
//! functions](https://en.wikipedia.org/wiki/Cryptographic_hash_function#Password_verification)
//! elaborates on this procedure. The [`hash_str`]/[`verify_str`] API is intended for this use. It
//! is also used for key derivation, in which a key is deterministically derived from a low-entropy
//! source (i.e: a password). This key can then be used for other cryptographic applications. The
//! [`derive_key`] API is intended for this use.
//!
//! # Algorithm Details
//! The term for this cryptographic primitive is a [password-based key derivation
//! function](https://en.wikipedia.org/wiki/Key_derivation_function). The default algorithm is
//! [Argon2id](argon2id). Argon2id strikes a balance between resisting GPU-based attacks, and
//! resisting side-channel attacks. [Argon2i](argon2i), which is just intended to be highly
//! resistant to side-channel attacks, and may be less resistant to GPU-based attacks, is also
//! available. [Scrypt](scrypt), an older (and perhaps more widely analysed) algorithm, is also
//! available. Unless you have a specific use-case which requires the use of Argon2i or Scrypt, the
//! default algorithm is probably the best choice.
//!
//! # Choosing Memory and Operations Limits
//! Unlike the other operations exposed by Sodium, the algorithms provided in module are
//! configurable, using the operations and memory limit parameters. Suitable values for these
//! parameters will vary based on application and hardware, but getting them right is important, as
//! they determine the cost of the hash, which corresponds to its brute-force resistance.
//!
//! The [Sodium
//! docs](https://doc.libsodium.org/password_hashing/default_phf#guidelines-for-choosing-the-parameters)
//! provide guidelines for choosing the parameters, copied here:
//!
//! ## Argon2
//! The memory limit directly specifies how much memory the password hash operation will use. Set
//! this to the amount of memory you wish to use for password hashing, in bytes.
//!
//! The operations limit corresponds to the maximum number of operations to perform, and a higher
//! value increases the number of CPU cycles required to compute a hash. Begin by setting this to
//! `3`.
//!
//! If the hash takes too long for your application, reduce the memory limit, keeping the
//! operations limit set to `3`.
//!
//! If the hash is very fast, and you can therefore afford to be more computationally intensive,
//! increase the operations limit until the computation time is no longer acceptable.
//!
//! For online use (website logins), a 1 second computation is likely the acceptable maximum. For
//! interactive desktop applications, a 5 second computation is acceptable if the password is only
//! entered once. For more infrequent use (e.g: restoring encrypted backups), even slower
//! computations can be reasonable.
//!
//! Some baseline values for these parameters are provided for each of the algorithms in this
//! module:
//! * [`OPS_LIMIT_INTERACTIVE`] and [`MEM_LIMIT_INTERACTIVE`]: For interactive, online operations
//! (requires 64 MiB memory)
//! * [`OPS_LIMIT_MODERATE`] and [`MEM_LIMIT_MODERATE`]: More conservative values for online
//! operations (requires 256 MiB memory)
//! * [`OPS_LIMIT_SENSITIVE`] and [`MEM_LIMIT_SENSITIVE`]: For offline operations (requires 1 GiB
//! memory)
//!
//! ## scrypt
//! The memory limit directly specifies how much memory the password hash operation will use. Set
//! this to the amount of memory you wish to use for password hashing, in bytes. This *should be a
//! power of 2*.
//!
//! The operations limit corresponds to the maximum number of operations to perform, and a higher
//! value increases the number of CPU cycles required to compute a hash. Begin by setting this to
//! `memlimit / 32`.
//!
//! If the hash takes too long for your application, reduce the memory limit, adjusting the
//! operationgs limit to the new value of `memlimit / 32` in kind.
//!
//! If the hash is very fast, and you can therefore afford to be more computationally intensive,
//! increase the operations limit until the computation time is no longer acceptable.
//!
//! For online use (website logins), a 1 second computation is likely the acceptable maximum. For
//! interactive desktop applications, a 5 second computation is acceptable if the password is only
//! entered once. For more infrequent use (e.g: restoring encrypted backups), even slower
//! computations can be reasonable.
//!
//! Some baseline values for these parameters are provided for each of the algorithms in this
//! module:
//! * [`scrypt::OPS_LIMIT_INTERACTIVE`] and [`scrypt::MEM_LIMIT_INTERACTIVE`]: For interactive,
//! online operations
//! * [`scrypt::OPS_LIMIT_SENSITIVE`] and [`scrypt::MEM_LIMIT_SENSITIVE`]: For offline operations
//!
//! # Security Considerations
//! It is important to set the operations limit and memory limit to suitable values for your
//! application. See [the section on this subject](#choosing-memory-and-operations-limits).
//!
//! Passwords should ideally be immediately erased from memory when they are no longer required for
//! hash calculation/key derivation. You can use the [zeroize](https://crates.io/crates/zeroize)
//! crate to do this very simply, or use the [hard](https://crates.io/crates/hard) crate if you
//! want to make use of the other memory hardening utilties from Sodium.
//!
//! A common, but dangerous, mistake is to verify the correctness of a password by generating the
//! hash again yourself, and naively comparing the newly calculated hash with the stored hash. This
//! opens the door to [timing attacks](https://en.wikipedia.org/wiki/Timing_attack). The
//! [`hash_str`]/[`verify_str`] API is designed to prevent this: [`verify_str`] uses a
//! constant-time comparison, and is safe to use to verify passwords against a password hash
//! generated with [`hash_str`].
//!
//! # Examples
//! This example demonstrates an example user authentication flow using [`hash_str`] and
//! [`verify_str`]: When a user account is created, we hash the provided password with [`hash_str`],
//! and store this in the database alongside the username. When the user wishes to log in, we
//! retrieve the hash from the database, and verify the password is correct using [`verify_str`].
//! Some example `store_details_in_db` and `retrieve_passwd_hash_from_db` functions are used here,
//! obviously in a real-world application, there would be considerably more boilerplate.
//!
//! ```rust
//! use alkali::hash::pbkdf::{
//!     hash_str, verify_str, PasswordHashError, OPS_LIMIT_INTERACTIVE, MEM_LIMIT_INTERACTIVE,
//! };
//! use alkali::AlkaliError;
//! # fn store_details_in_db(_username: &str, _passwd_hash: &str) {}
//!
//! /// Creates a new user account with the specified username and password
//! fn create_user_account(username: &str, passwd: &str) {
//!     let hash = hash_str(passwd, OPS_LIMIT_INTERACTIVE, MEM_LIMIT_INTERACTIVE).unwrap();
//!
//!     store_details_in_db(username, &hash);
//! }
//!
//! # fn retrieve_passwd_hash_from_db(_username: &str) -> &'static str {
//! #     "$argon2id$v=19$m=65536,t=2,p=1$oH2BFYR6JuV1k2IXDvh67w$Xy0iVWdHMbfq2eLN/dRMRcjNcMnkjckbJN\
//! #     v+xSOZ0qc"
//! # }
//! /// Tries to log in a user with the given username and password
//! fn log_in(username: &str, passwd: &str) -> bool {
//!     let hash = retrieve_passwd_hash_from_db(username);
//!
//!     match verify_str(passwd, hash) {
//!         Ok(_) => true,
//!         Err(AlkaliError::PasswordHashError(PasswordHashError::PasswordIncorrect)) => false,
//!         Err(_) => panic!("some other error occurred"),
//!     }
//! }
//! # create_user_account("some_dude", "hunter2");
//! # assert!(log_in("some_dude", "hunter2"));
//! ```
//!
//! Key derivation (using [`derive_key`]):
//!
//! ```rust
//! use alkali::hash::pbkdf::{
//!     derive_key, generate_salt, OPS_LIMIT_INTERACTIVE, MEM_LIMIT_INTERACTIVE,
//! };
//!
//! let passwd = b"some data from which a key will be derived";
//! let mut key = [0u8; 32];
//!
//! let salt = generate_salt().unwrap();
//! derive_key(passwd, &salt, OPS_LIMIT_INTERACTIVE, MEM_LIMIT_INTERACTIVE, &mut key).unwrap();
//!
//! // Do something cool with key
//! // Be sure to store the salt, operations limit, and memory limit alongside the key if it will
//! // need to be derived again!
//! ```

use thiserror::Error;

pub mod argon2i;
pub mod argon2id;
pub mod scrypt;

pub use argon2id::*;

/// Error type returned if something went wrong in the pbkdf module.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum PasswordHashError {
    /// The password provided was too short or too long for use with this algorithm.
    ///
    /// Passwords must be at least [`PASSWORD_LENGTH_MIN`] and at most
    /// [`PASSWORD_LENGTH_MAX`](struct@PASSWORD_LENGTH_MAX) bytes.
    #[error("password length outside acceptable range")]
    PasswordLengthInvalid,

    /// The operations limit was smaller than [`OPS_LIMIT_MIN`] or greater than [`OPS_LIMIT_MAX`].
    #[error("operations limit outside acceptable range")]
    OpsLimitInvalid,

    /// The memory limit was smaller than [`MEM_LIMIT_MIN`] or greater than
    /// [`MEM_LIMIT_MAX`](struct@MEM_LIMIT_MAX).
    #[error("memory limit outside acceptable range")]
    MemLimitInvalid,

    /// The requested output is too short or too long for use with this algorithm.
    ///
    /// The derived key size must be at least [`OUTPUT_LENGTH_MIN`] bytes and at most
    /// [`OUTPUT_LENGTH_MAX`](struct@OUTPUT_LENGTH_MAX) bytes.
    #[error("requested output length is too short or too long")]
    OutputLengthInvalid,

    /// The password hash failed.
    ///
    /// This is likely due to memory allocation failing, as the pbkdf API is one of the few
    /// portions of Sodium which requires dynamic memory allocation.
    #[error("password hash failed")]
    PasswordHashFailed,

    /// The password verification against the provided hash failed.
    ///
    /// This indicates that the password was incorrect for this hash, or potentially that
    /// calculating the hash failed, although this is unlikely in comparison to the former
    /// possibility.
    #[error("the password was incorrect for this hash")]
    PasswordIncorrect,
}

/// Possible results of [`requires_rehash`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RehashResult {
    /// The parameters of the hash match, a rehash is not required.
    ParametersMatch,

    /// The hash appears to be in the correct format, but the parameters differ from those
    /// specified.
    ///
    /// You may wish to compute a new hash the next time the user logs in.
    ParametersDiffer,

    /// The hash is not in the correct format.
    ///
    /// You may wish to compute a new hash the next time the user logs in.
    InvalidHash,
}

/// Implements the parts of a pbkdf module common to both the Argon2 and scrypt APIs.
macro_rules! pbkdf_module_common {
    (
        $opslim_min:expr,       // crypto_pwhash_OPSLIMIT_MIN
        $opslim_int:expr,       // crypto_pwhash_OPSLIMIT_INTERACTIVE
        $opslim_sen:expr,       // crypto_pwhash_OPSLIMIT_SENSITIVE
        $opslim_max:expr,       // crypto_pwhash_OPSLIMIT_MAX
        $memlim_min:expr,       // crypto_pwhash_MEMLIMIT_MIN
        $memlim_int:expr,       // crypto_pwhash_MEMLIMIT_INTERACTIVE
        $memlim_sen:expr,       // crypto_pwhash_MEMLIMIT_SENSITIVE
        $memlim_max:path,       // crypto_pwhash_memlimit_max
        $pwlen_min:expr,        // crypto_pwhash_PASSWD_MIN
        $pwlen_max:path,        // crypto_pwhash_passwd_max
        $outlen_min:expr,       // crypto_pwhash_BYTES_MIN
        $outlen_max:path,       // crypto_pwhash_bytes_max
        $salt_len:expr,         // crypto_pwhash_SALTBYTES
        $str_len:expr,          // crypto_pwhash_STRBYTES
        $pwhash_str:path,       // crypto_pwhash_str
        $pwhash_verify:path,    // crypto_pwhash_str_verify
        $str_needs_rehash:path, // crypto_pwhash_str_needs_rehash
    ) => {
        /// The minimum value for the operations limit.
        pub const OPS_LIMIT_MIN: usize = $opslim_min as usize;

        /// A baseline value for the operations limit for interactive, online use.
        pub const OPS_LIMIT_INTERACTIVE: usize = $opslim_int as usize;

        /// A baseline value for the operations limit for non-interactive/highly sensitive
        /// applications.
        pub const OPS_LIMIT_SENSITIVE: usize = $opslim_sen as usize;

        /// The maximum value for the operations limit.
        pub const OPS_LIMIT_MAX: usize = $opslim_max as usize;

        /// The minimum value for the memory limit.
        pub const MEM_LIMIT_MIN: usize = $memlim_min as usize;

        /// A baseline value for the memory limit for interactive, online use.
        pub const MEM_LIMIT_INTERACTIVE: usize = $memlim_int as usize;

        /// A baseline value for the memory limit for non-interactive/highly sensitive applications.
        pub const MEM_LIMIT_SENSITIVE: usize = $memlim_sen as usize;

        lazy_static::lazy_static! {
            /// The maximum value for the memory limit.
            pub static ref MEM_LIMIT_MAX: usize = unsafe {
                // SAFETY: This function just returns a constant value, and should always be safe
                // to call.
                $memlim_max()
            };
        }

        /// The minimum length for a password to hash.
        pub const PASSWORD_LENGTH_MIN: usize = $pwlen_min as usize;

        lazy_static::lazy_static! {
            /// The maximum length for a password to hash.
            pub static ref PASSWORD_LENGTH_MAX: usize = unsafe {
                // SAFETY: This function just returns a constant value, and should always be safe
                // to call.
                $pwlen_max() as usize
            };
        }

        /// The minimum output size for this algorithm.
        pub const OUTPUT_LENGTH_MIN: usize = $outlen_min as usize;

        lazy_static::lazy_static! {
            /// The maximum output size for this algorithm.
            pub static ref OUTPUT_LENGTH_MAX: usize = unsafe {
                // SAFETY: This function just returns a constant value, and should always be safe
                // to call.
                $outlen_max() as usize
            };
        }

        /// The length of a salt.
        pub const SALT_LENGTH: usize = $salt_len as usize;

        /// The maximum length of the string representation of a password hash.
        pub const STR_LENGTH_MAX: usize = $str_len as usize - 1;

        /// A salt for a password hash, used to introduce non-determinism into the algorithm.
        pub type Salt = [u8; SALT_LENGTH];

        /// Generate a random salt for use with [`derive_key`].
        pub fn generate_salt() -> Result<Salt, $crate::AlkaliError> {
            let mut salt = [0u8; SALT_LENGTH];
            $crate::random::fill_random(&mut salt)?;
            Ok(salt)
        }

        /// Hash a password, for later use to verify a provided password is the same as the
        /// original.
        ///
        /// This function is used when a user's password must be stored, so that we can later
        /// verify their identity. A hash of the password is calculated using this function. We can
        /// later verify a password provided by the user against this hash using the [`verify_str`]
        /// function. So the actual password never needs to be stored.
        ///
        /// The first argument to this function is the password from which the hash will be
        /// calculated. The second and third arguments are the operations and memory limits, which
        /// determine the computational complexity of the hash. These values should be chosen
        /// specifically for your application, see [Choosing Memory and Operations
        /// Limits](crate::hash::pbkdf#choosing-memory-and-operations-limits).
        ///
        /// If hashing is successful, a String will be returned containing the hash and the
        /// parameters used to calculate it (including a randomly-generated salt). This hash can
        /// later be used with [`verify_str`] to verify the password.
        ///
        /// # Security Concerns
        /// It is important to set the operations limit and memory limit to suitable values for your
        /// application. See [the section on this
        /// subject](crate::hash::pbkdf#choosing-memory-and-operations-limits).
        ///
        /// This function is not suitable for deriving keys for use with other cryptographic
        /// operations, and large parts of its output are predictable. You should instead use
        /// [`derive_key`], which only produces output suitable for use as key-data.
        pub fn hash_str(
            password: &str,
            ops_limit: usize,
            mem_limit: usize,
        ) -> Result<String, $crate::AlkaliError> {
            $crate::require_init()?;

            let mut out = [0u8; STR_LENGTH_MAX + 1];

            if password.len() < PASSWORD_LENGTH_MIN || password.len() > *PASSWORD_LENGTH_MAX {
                return Err($crate::hash::pbkdf::PasswordHashError::PasswordLengthInvalid.into());
            } else if ops_limit < OPS_LIMIT_MIN || ops_limit > OPS_LIMIT_MAX {
                return Err($crate::hash::pbkdf::PasswordHashError::OpsLimitInvalid.into());
            } else if mem_limit < MEM_LIMIT_MIN || mem_limit > *MEM_LIMIT_MAX {
                return Err($crate::hash::pbkdf::PasswordHashError::MemLimitInvalid.into());
            }

            let pwhash_result = unsafe {
                // SAFETY: The first argument to this function is a pointer to which a C-formatted
                // string will be written. This must have enough space to store `STRBYTES` bytes,
                // which we have defined `out` to be. When we use `out`, we will treat it as a
                // C-formatted string. The next two arguments are a pointer to a password to hash,
                // and the length of the password in bytes. We use `password.as_bytes().len()` to
                // specify the length, so it is correct for this pointer. The final two parameters
                // are the operations limit and memory limit, which are both just integers.
                $pwhash_str(
                    out.as_mut_ptr() as *mut libc::c_char,
                    password.as_bytes().as_ptr() as *const libc::c_char,
                    password.as_bytes().len() as libc::c_ulonglong,
                    ops_limit as libc::c_ulonglong,
                    mem_limit,
                )
            };

            if pwhash_result == 0 {
                // We need to take a slice up to & including the first nul byte here, to
                // successfully construct a CString.
                let hash_len = unsafe {
                    // SAFETY: This is a binding to the strnlen function from the C standard
                    // library. This function takes a pointer to a C-formatted string (with null
                    // byte) as an argument, and returns the (inclusive) length to the nul byte, up
                    // to a provided maximum number of bytes.  The $pwhash_str function above was
                    // used to fill the contents of this buffer, which Sodium guarantees with
                    // produce a valid C string, including null byte.  Therefore, it is safe to use
                    // strnlen to determine the length of the string, including the null byte.
                    libc::strnlen(out.as_ptr() as *const libc::c_char, out.len())
                };
                let output_string = std::ffi::CString::new(&out[..hash_len])
                    .unwrap()
                    .into_string()
                    .unwrap();
                Ok(output_string)
            } else {
                Err($crate::hash::pbkdf::PasswordHashError::PasswordHashFailed.into())
            }
        }

        /// Verify `password` matches the provided `hash`.
        ///
        /// The first argument to this function is the password to verify. The second argument is
        /// the hash against whiich the password will be checked, previously calculated using
        /// [`hash_str`].
        ///
        /// This function will return `Ok(())` if `password` is equal to the password used to
        /// calculated `hash`, or a [`PasswordHashError`](super::PasswordHashError) otherwise.
        pub fn verify_str(password: &str, hash: &str) -> Result<(), $crate::AlkaliError> {
            $crate::require_init()?;

            let hash = std::ffi::CString::new(hash).unwrap();
            let hash_ptr = hash.into_raw();

            let verification_result = unsafe {
                // SAFETY: The first argument to this function is a C-formatted string containing
                // the hash against which the password should be verified. We construct the
                // hash_ptr argument by building a CString from a valid Rust string, then calling
                // `into_raw`. The definition of CString in the Rust standard library says that
                // this produces a valid pointer to a C-formatted string. The second and third
                // arguments specify a pointer to a password to verify, and the length of the
                // password. We use `password.as_bytes()` to convert the password to bytes, and
                // use `password.as_bytes().len()` to calculate the length, so this is correct for
                // this pointer.
                $pwhash_verify(
                    hash_ptr,
                    password.as_bytes().as_ptr() as *const libc::c_char,
                    password.as_bytes().len() as libc::c_ulonglong,
                )
            };

            // Make sure we free the hash string's memory
            let _hash = unsafe {
                // SAFETY: This pointer was created using CString::into_raw, so it is safe to
                // create a CString from it.
                std::ffi::CString::from_raw(hash_ptr)
            };

            if verification_result == 0 {
                Ok(())
            } else {
                Err($crate::hash::pbkdf::PasswordHashError::PasswordIncorrect.into())
            }
        }

        /// Determine if `hash` is a valid hash string under the given parameters.
        ///
        /// This function is intended to be used if you update the parameters for the hash function
        /// used to store passwords. As users log in, if the password hash needs updating (as
        /// determined using this function), then the hash can be recalculated.
        ///
        /// Returns [`RehashResult::ParametersMatch`](super::RehashResult::ParametersMatch) if the
        /// hash appears to be in the correct format for a hash with the given paramaters. Returns
        /// [`RehashResult::ParametersDiffer`](super::RehashResult::ParametersDiffer) if the hash
        /// is in the correct format for this algorithm, but has different parameters. Returns
        /// [`RehashResult::InvalidHash`](super::RehashResult::InvalidHash) if the hash doesn't
        /// appear to be in the correct format for this algorithm.
        pub fn requires_rehash(
            hash: &str,
            ops_limit: usize,
            mem_limit: usize,
        ) -> Result<$crate::hash::pbkdf::RehashResult, $crate::AlkaliError> {
            use $crate::hash::pbkdf::RehashResult;

            $crate::require_init()?;

            let hash = std::ffi::CString::new(hash).unwrap();
            let hash_ptr = hash.into_raw();

            let rehash_result = unsafe {
                // SAFETY: The first argument to this function is a C-formatted string containing
                // the hash to check. We define the hash_ptr argument by building a CString from a
                // valid Rust string, then calling `into_raw`. The definition of CString in the Rust
                // standard library says that this produces a valid pointer to a C-formatted string.
                // The remaining two arguments, the operations and memory limits, are just integers.
                $str_needs_rehash(hash_ptr, ops_limit as libc::c_ulonglong, mem_limit)
            };

            // Make sure we free the hash string's memory
            let _hash = unsafe {
                // SAFETY: This pointer was created using CString::into_raw, so it is safe to
                // create a CString from it.
                std::ffi::CString::from_raw(hash_ptr)
            };

            match rehash_result {
                -1 => Ok(RehashResult::InvalidHash),
                0 => Ok(RehashResult::ParametersMatch),
                1 => Ok(RehashResult::ParametersDiffer),
                _ => unreachable!(),
            }
        }
    };
}

pub(crate) use pbkdf_module_common;

/// Generates the API for a `pbkdf` module based with the given functions & constants from Sodium.
macro_rules! pbkdf_module {
    (
        $opslim_min:expr,       // crypto_pwhash_OPSLIMIT_MIN
        $opslim_int:expr,       // crypto_pwhash_OPSLIMIT_INTERACTIVE
        $opslim_mod:expr,       // crypto_pwhash_OPSLIMIT_MODERATE
        $opslim_sen:expr,       // crypto_pwhash_OPSLIMIT_SENSITIVE
        $opslim_max:expr,       // crypto_pwhash_OPSLIMIT_MAX
        $memlim_min:expr,       // crypto_pwhash_MEMLIMIT_MIN
        $memlim_int:expr,       // crypto_pwhash_MEMLIMIT_INTERACTIVE
        $memlim_mod:expr,       // crypto_pwhash_MEMLIMIT_MODERATE
        $memlim_sen:expr,       // crypto_pwhash_MEMLIMIT_SENSITIVE
        $memlim_max:path,       // crypto_pwhash_memlimit_max
        $pwlen_min:expr,        // crypto_pwhash_PASSWD_MIN
        $pwlen_max:path,        // crypto_pwhash_passwd_max
        $outlen_min:expr,       // crypto_pwhash_BYTES_MIN
        $outlen_max:path,       // crypto_pwhash_bytes_max
        $salt_len:expr,         // crypto_pwhash_SALTBYTES
        $str_len:expr,          // crypto_pwhash_STRBYTES
        $alg_ident:expr,        // crypto_pwhash_ALG_NAME
        $pwhash:path,           // crypto_pwhash
        $pwhash_str:path,       // crypto_pwhash_str
        $pwhash_verify:path,    // crypto_pwhash_str_verify
        $str_needs_rehash:path, // crypto_pwhash_str_needs_rehash
    ) => {
        $crate::hash::pbkdf::pbkdf_module_common! {
            $opslim_min,
            $opslim_int,
            $opslim_sen,
            $opslim_max,
            $memlim_min,
            $memlim_int,
            $memlim_sen,
            $memlim_max,
            $pwlen_min,
            $pwlen_max,
            $outlen_min,
            $outlen_max,
            $salt_len,
            $str_len,
            $pwhash_str,
            $pwhash_verify,
            $str_needs_rehash,
        }

        /// A baseline value for the operations limit intended to be a more conservative choice for
        /// online use.
        pub const OPS_LIMIT_MODERATE: usize = $opslim_mod as usize;

        /// A baseline value for the memory limit intended to be a more conservative choice for
        /// online use.
        pub const MEM_LIMIT_MODERATE: usize = $memlim_mod as usize;

        /// Derive a key from a low-entropy input (i.e: a password).
        ///
        /// This function is used when a key, suitable for use with cryptographic algorithms which
        /// use a fixed-size input, must be derived deterministically from a variable-size,
        /// typically low-entropy source (like a password).
        ///
        /// The first argument to this function is the password from which the key is to be
        /// derived. The second argument is a [`Salt`] to use in the hash calculation, which
        /// introduces some non-determinism into the process (the same password will not produce the
        /// same key, unless the same salt is used). This should be generated randomly when the key
        /// is first derived using [`generate_salt`]. The third and fourth arguments are the
        /// operations and memory limits, which determine the computational complexity of the hash.
        /// These values should be chosen specifically for your application, see [Choosing Memory
        /// and Operations Limits](crate::hash::pbkdf#choosing-memory-and-operations-limits). The
        /// final argument is the buffer to which the derived key will be written. This can be of
        /// any length between [`OUTPUT_LENGTH_MIN`] and
        /// [`OUTPUT_LENGTH_MAX`](struct@OUTPUT_LENGTH_MAX) bytes.
        ///
        /// If key derivation is successful, the `key` buffer is filled with derived key data. If
        /// the derivation fails, a [`PasswordHashError`](super::PasswordHashError) will be
        /// returned.
        ///
        /// Key derivation is a deterministic operation dependent on the password, salt, operations
        /// limit, and memory limit. These values are **not** stored in the derived key, so they
        /// will need to be stored alongside it. When the same key is derived in the future, these
        /// same parameters must be used. None are secret.
        ///
        /// # Security Concerns
        /// It is important to set the operations limit and memory limit to suitable values for your
        /// application. See [the section on this
        /// subject](crate::hash::pbkdf#choosing-memory-and-operations-limits).
        ///
        /// To store a password to verify a user's identity, it's a better idea to use
        /// [`hash_str`], which includes the hash parameters in the generated string, and produces
        /// ASCII output which can easily be stored in any database. The [`verify_str`] function is
        /// also provided to verify a password matches a specific hash.
        pub fn derive_key(
            password: &[u8],
            salt: &Salt,
            ops_limit: usize,
            mem_limit: usize,
            key: &mut [u8],
        ) -> Result<(), $crate::AlkaliError> {
            $crate::require_init()?;

            if password.len() < PASSWORD_LENGTH_MIN || password.len() > *PASSWORD_LENGTH_MAX {
                return Err($crate::hash::pbkdf::PasswordHashError::PasswordLengthInvalid.into());
            } else if ops_limit < OPS_LIMIT_MIN || ops_limit > OPS_LIMIT_MAX {
                return Err($crate::hash::pbkdf::PasswordHashError::OpsLimitInvalid.into());
            } else if mem_limit < MEM_LIMIT_MIN || mem_limit > *MEM_LIMIT_MAX {
                return Err($crate::hash::pbkdf::PasswordHashError::MemLimitInvalid.into());
            } else if key.len() < OUTPUT_LENGTH_MIN || key.len() > *OUTPUT_LENGTH_MAX {
                return Err($crate::hash::pbkdf::PasswordHashError::OutputLengthInvalid.into());
            }

            let pwhash_result = unsafe {
                // SAFETY: This function takes 8 parameters. The first two specify a pointer to
                // which a key will be written, and the length of data to write to this pointer. We
                // use `key.len()` to specify the length of the data, which is equal to the length
                // of the buffer. The `key` type itself is a slice of `u8`s, so any data can be
                // written to it safely. The next two arguments are a pointer to a password, and
                // its length. We use `password.len()` to specify the length of the password, so
                // this is the correct length for the pointer. The next argument is a pointer to a
                // salt. We have defined the `Salt` type to be `SALTBYTES` bytes long, the expected
                // length of a salt for this function, so this is valid to use here. The next three
                // parameters are the operations limit, memory limit, and algorithm identifier,
                // which are all just integers. Therefore this function call is safe.
                $pwhash(
                    key.as_mut_ptr(),
                    key.len() as libc::c_ulonglong,
                    password.as_ptr() as *const libc::c_char,
                    password.len() as libc::c_ulonglong,
                    salt.as_ptr(),
                    ops_limit as libc::c_ulonglong,
                    mem_limit,
                    $alg_ident as libc::c_int,
                )
            };

            if pwhash_result == 0 {
                Ok(())
            } else {
                Err($crate::hash::pbkdf::PasswordHashError::PasswordHashFailed.into())
            }
        }
    };

    (
        $opslim_min:expr,       // crypto_pwhash_OPSLIMIT_MIN
        $opslim_int:expr,       // crypto_pwhash_OPSLIMIT_INTERACTIVE
        $opslim_sen:expr,       // crypto_pwhash_OPSLIMIT_SENSITIVE
        $opslim_max:expr,       // crypto_pwhash_OPSLIMIT_MAX
        $memlim_min:expr,       // crypto_pwhash_MEMLIMIT_MIN
        $memlim_int:expr,       // crypto_pwhash_MEMLIMIT_INTERACTIVE
        $memlim_sen:expr,       // crypto_pwhash_MEMLIMIT_SENSITIVE
        $memlim_max:path,       // crypto_pwhash_memlimit_max
        $pwlen_min:expr,        // crypto_pwhash_PASSWD_MIN
        $pwlen_max:path,        // crypto_pwhash_passwd_max
        $outlen_min:expr,       // crypto_pwhash_BYTES_MIN
        $outlen_max:path,       // crypto_pwhash_bytes_max
        $salt_len:expr,         // crypto_pwhash_SALTBYTES
        $str_len:expr,          // crypto_pwhash_STRBYTES
        $pwhash:path,           // crypto_pwhash
        $pwhash_str:path,       // crypto_pwhash_str
        $pwhash_verify:path,    // crypto_pwhash_str_verify
        $str_needs_rehash:path, // crypto_pwhash_str_needs_rehash
    ) => {
        $crate::hash::pbkdf::pbkdf_module_common! {
            $opslim_min,
            $opslim_int,
            $opslim_sen,
            $opslim_max,
            $memlim_min,
            $memlim_int,
            $memlim_sen,
            $memlim_max,
            $pwlen_min,
            $pwlen_max,
            $outlen_min,
            $outlen_max,
            $salt_len,
            $str_len,
            $pwhash_str,
            $pwhash_verify,
            $str_needs_rehash,
        }

        /// Derive a key from a low-entropy input (i.e: a password).
        ///
        /// This function is used when a key, suitable for use with cryptographic algorithms which
        /// use a fixed-size input, must be derived deterministically from a variable-size,
        /// typically low-entropy source (like a password).
        ///
        /// The first argument to this function is the password from which the key is to be
        /// derived. The second argument is a [`Salt`] to use in the hash calculation, which
        /// introduces some non-determinism into the process (the same password will not produce the
        /// same key, unless the same salt is used). This should be generated randomly when the key
        /// is first derived using [`generate_salt`]. The third and fourth arguments are the
        /// operations and memory limits, which determine the computational complexity of the hash.
        /// These values should be chosen specifically for your application, see [Choosing Memory
        /// and Operations Limits](crate::hash::pbkdf#choosing-memory-and-operations-limits). The
        /// final argument is the buffer to which the derived key will be written. This can be of
        /// any length between [`OUTPUT_LENGTH_MIN`] and
        /// [`OUTPUT_LENGTH_MAX`](struct@OUTPUT_LENGTH_MAX) bytes.
        ///
        /// If key derivation is successful, the `key` buffer is filled with derived key data. If
        /// the derivation fails, a [`PasswordHashError`](super::PasswordHashError) will be
        /// returned.
        ///
        /// Key derivation is a deterministic operation dependent on the password, salt, operations
        /// limit, and memory limit. These values are **not** stored in the derived key, so they
        /// will need to be stored alongside it. When the same key is derived in the future, these
        /// same parameters must be used. None are secret.
        ///
        /// # Security Concerns
        /// It is important to set the operations limit and memory limit to suitable values for your
        /// application. See [the section on this
        /// subject](crate::hash::pbkdf#choosing-memory-and-operations-limits).
        ///
        /// To store a password to verify a user's identity, it's a better idea to use
        /// [`hash_str`], which includes the hash parameters in the generated string, and produces
        /// ASCII output which can easily be stored in any database. The [`verify_str`] function is
        /// also provided to verify a password matches a specific hash.
        pub fn derive_key(
            password: &[u8],
            salt: &Salt,
            ops_limit: usize,
            mem_limit: usize,
            key: &mut [u8],
        ) -> Result<(), $crate::AlkaliError> {
            $crate::require_init()?;

            if password.len() < PASSWORD_LENGTH_MIN || password.len() > *PASSWORD_LENGTH_MAX {
                return Err($crate::hash::pbkdf::PasswordHashError::PasswordLengthInvalid.into());
            } else if ops_limit < OPS_LIMIT_MIN || ops_limit > OPS_LIMIT_MAX {
                return Err($crate::hash::pbkdf::PasswordHashError::OpsLimitInvalid.into());
            } else if mem_limit < MEM_LIMIT_MIN || mem_limit > *MEM_LIMIT_MAX {
                return Err($crate::hash::pbkdf::PasswordHashError::MemLimitInvalid.into());
            } else if key.len() < OUTPUT_LENGTH_MIN || key.len() > *OUTPUT_LENGTH_MAX {
                return Err($crate::hash::pbkdf::PasswordHashError::OutputLengthInvalid.into());
            }

            let pwhash_result = unsafe {
                // SAFETY: This function takes 8 parameters. The first two specify a pointer to
                // which a key will be written, and the length of data to write to this pointer. We
                // use `key.len()` to specify the length of the data, which is equal to the length
                // of the buffer. The `key` type itself is a slice of `u8`s, so any data can be
                // written to it safely. The next two arguments are a pointer to a password, and
                // its length. We use `password.len()` to specify the length of the password, so
                // this is the correct length for the pointer. The next argument is a pointer to a
                // salt. We have defined the `Salt` type to be `SALTBYTES` bytes long, the expected
                // length of a salt for this function, so this is valid to use here. The next three
                // parameters are the operations limit, memory limit, and algorithm identifier,
                // which are all just integers. Therefore this function call is safe.
                $pwhash(
                    key.as_mut_ptr(),
                    key.len() as libc::c_ulonglong,
                    password.as_ptr() as *const libc::c_char,
                    password.len() as libc::c_ulonglong,
                    salt.as_ptr(),
                    ops_limit as libc::c_ulonglong,
                    mem_limit,
                )
            };

            if pwhash_result == 0 {
                Ok(())
            } else {
                Err($crate::hash::pbkdf::PasswordHashError::PasswordHashFailed.into())
            }
        }
    };
}

pub(crate) use pbkdf_module;

/// Generates tests for the [`derive_key`] function of a `pbkdf` implementation. Takes test
/// vectors as arguments.
#[allow(unused_macros)]
macro_rules! kdf_tests {
    ( $( {
        pass: $pass:expr,
        salt: $salt:expr,
        ops: $opslim:expr,
        mem: $memlim:expr,
        out: $key:expr,
    }, )* ) => {
        #[test]
        fn key_derivation_test_vectors() -> Result<(), $crate::AlkaliError> {
            $(
                let mut actual_key = vec![0u8; $key.len()];
                super::derive_key(&$pass, &$salt, $opslim, $memlim, &mut actual_key)?;
                assert_eq!(&actual_key, &$key);
            )*

            Ok(())
        }

        #[test]
        fn key_derivation_invalid_params() -> Result<(), $crate::AlkaliError> {
            let password = b"Correct Horse Battery Staple";
            let salt = super::generate_salt()?;
            let mut key = vec![0; super::OUTPUT_LENGTH_MIN];

            assert!(super::derive_key(
                password,
                &salt,
                super::OPS_LIMIT_MIN,
                super::MEM_LIMIT_MIN,
                &mut key,
            ).is_ok());

            let mut key = vec![0; super::OUTPUT_LENGTH_MIN - 1];
            assert!(super::derive_key(
                password,
                &salt,
                super::OPS_LIMIT_MIN,
                super::MEM_LIMIT_MIN,
                &mut key
            )
            .is_err());
            let mut key = vec![0; super::OUTPUT_LENGTH_MIN];

            assert!(super::derive_key(
                password,
                &salt,
                super::OPS_LIMIT_MIN,
                super::MEM_LIMIT_MIN - 1,
                &mut key
            )
            .is_err());

            assert!(super::derive_key(
                password,
                &salt,
                super::OPS_LIMIT_MIN - 1,
                super::MEM_LIMIT_MIN,
                &mut key
            )
            .is_err());

            Ok(())
        }
    }
}

#[allow(unused_imports)]
pub(crate) use kdf_tests;

/// Generates some tests for the [`verify_str`] function of a `pbkdf` implementation. Takes test
/// vectors as arguments.
#[allow(unused_macros)]
macro_rules! verify_str_valid_tests {
    ( $( {
        pass: $pass:expr,
        hash: $hash:expr,
    }, )* ) => {
        #[test]
        fn verify_str_valid_strings() {
            $(
                assert!(super::verify_str(&$pass, &$hash).is_ok());
            )*
        }
    };
}

#[allow(unused_imports)]
pub(crate) use verify_str_valid_tests;

/// Generates some tests for the [`verify_str`] function of a `pbkdf` implementation. Takes test
/// vectors as arguments.
#[allow(unused_macros)]
macro_rules! verify_str_invalid_tests {
    ( $( {
        pass: $pass:expr,
        hash: $hash:expr,
    }, )* ) => {
        #[test]
        fn verify_str_invalid_strings() {
            $(
                assert!(super::verify_str(&$pass, &$hash).is_err());
            )*
        }
    }
}

#[allow(unused_imports)]
pub(crate) use verify_str_invalid_tests;

/// Generates tests for the [`requires_rehash`] function of a `pbkdf` implementation.
#[allow(unused_macros)]
macro_rules! needs_rehash_tests {
    () => {
        #[test]
        fn needs_rehash() -> Result<(), $crate::AlkaliError> {
            use $crate::hash::pbkdf::RehashResult;

            const OPS_LIMIT: usize = 3;
            const MEM_LIMIT: usize = 5000000;
            const PASSWORD: &'static str = "Correct Horse Battery Staple";

            let hash = super::hash_str(PASSWORD, OPS_LIMIT, MEM_LIMIT)?;

            assert_eq!(
                super::requires_rehash(&hash, OPS_LIMIT, MEM_LIMIT)?,
                RehashResult::ParametersMatch,
            );

            assert_eq!(
                super::requires_rehash(&hash, OPS_LIMIT, MEM_LIMIT / 2)?,
                RehashResult::ParametersDiffer,
            );
            assert_eq!(
                super::requires_rehash(&hash, OPS_LIMIT - 1, MEM_LIMIT)?,
                RehashResult::ParametersDiffer,
            );
            assert_eq!(
                super::requires_rehash(&hash, OPS_LIMIT, MEM_LIMIT * 2)?,
                RehashResult::ParametersDiffer,
            );
            assert_eq!(
                super::requires_rehash(&hash, OPS_LIMIT + 1, MEM_LIMIT)?,
                RehashResult::ParametersDiffer,
            );

            assert_eq!(
                super::requires_rehash("not valid", OPS_LIMIT, MEM_LIMIT)?,
                RehashResult::InvalidHash,
            );

            Ok(())
        }
    };
}

#[allow(unused_imports)]
pub(crate) use needs_rehash_tests;
