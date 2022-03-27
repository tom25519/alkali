//! The [Argon2id](https://en.wikipedia.org/wiki/Argon2) password-based key derivation algorithm.
//!
//! This algorithm is intended to strike a sensible balance between resistance to GPU-based attacks
//! and resisting side-channel analysis.

use super::pbkdf_module;
use libsodium_sys as sodium;

pbkdf_module! {
    sodium::crypto_pwhash_argon2id_OPSLIMIT_MIN,
    sodium::crypto_pwhash_argon2id_OPSLIMIT_INTERACTIVE,
    sodium::crypto_pwhash_argon2id_OPSLIMIT_MODERATE,
    sodium::crypto_pwhash_argon2id_OPSLIMIT_SENSITIVE,
    sodium::crypto_pwhash_argon2id_OPSLIMIT_MAX,
    sodium::crypto_pwhash_argon2id_MEMLIMIT_MIN,
    sodium::crypto_pwhash_argon2id_MEMLIMIT_INTERACTIVE,
    sodium::crypto_pwhash_argon2id_MEMLIMIT_MODERATE,
    sodium::crypto_pwhash_argon2id_MEMLIMIT_SENSITIVE,
    sodium::crypto_pwhash_argon2id_memlimit_max,
    sodium::crypto_pwhash_argon2id_PASSWD_MIN,
    sodium::crypto_pwhash_argon2id_passwd_max,
    sodium::crypto_pwhash_argon2id_BYTES_MIN,
    sodium::crypto_pwhash_argon2id_bytes_max,
    sodium::crypto_pwhash_argon2id_SALTBYTES,
    sodium::crypto_pwhash_argon2id_STRBYTES,
    sodium::crypto_pwhash_ALG_ARGON2ID13,
    sodium::crypto_pwhash_argon2id,
    sodium::crypto_pwhash_argon2id_str,
    sodium::crypto_pwhash_argon2id_str_verify,
    sodium::crypto_pwhash_argon2id_str_needs_rehash,
}

#[cfg(test)]
mod tests {
    use super::super::{
        kdf_tests, needs_rehash_tests, verify_password_invalid_tests, verify_password_valid_tests,
    };
    kdf_tests! [
        {
            pass: [0xa3, 0x47, 0xae, 0x92, 0xbc, 0xe9, 0xf8, 0x0f, 0x6f, 0x59, 0x5a, 0x44, 0x80,
                   0xfc, 0x9c, 0x2f, 0xe7, 0xe7, 0xd7, 0x14, 0x8d, 0x37, 0x1e, 0x94, 0x87, 0xd7,
                   0x5f, 0x5c, 0x23, 0x00, 0x8f, 0xfa, 0xe0, 0x65, 0x57, 0x7a, 0x92, 0x8f, 0xeb,
                   0xd9, 0xb1, 0x97, 0x3a, 0x5a, 0x95, 0x07, 0x3a, 0xcd, 0xbe, 0xb6, 0xa0, 0x30,
                   0xcf, 0xc0, 0xd7, 0x9c, 0xaa, 0x2d, 0xc5, 0xcd, 0x01, 0x1c, 0xef, 0x02, 0xc0,
                   0x8d, 0xa2, 0x32, 0xd7, 0x6d, 0x52, 0xdf, 0xbc, 0xa3, 0x8c, 0xa8, 0xdc, 0xbd,
                   0x66, 0x5b, 0x17, 0xd1, 0x66, 0x5f, 0x7c, 0xf5, 0xfe, 0x59, 0x77, 0x2e, 0xc9,
                   0x09, 0x73, 0x3b, 0x24, 0xde, 0x97, 0xd6, 0xf5, 0x8d, 0x22, 0x0b, 0x20, 0xc6,
                   0x0d, 0x7c, 0x07, 0xec, 0x1f, 0xd9, 0x3c, 0x52, 0xc3, 0x10, 0x20, 0x30, 0x0c,
                   0x6c, 0x1f, 0xac, 0xd7, 0x79, 0x37, 0xa5, 0x97, 0xc7, 0xa6],
            salt: [0x55, 0x41, 0xfb, 0xc9, 0x95, 0xd5, 0xc1, 0x97, 0xba, 0x29, 0x03, 0x46, 0xd2,
                   0xc5, 0x59, 0xde],
            ops:  5,
            mem:  7256678,
            out:  [0x18, 0xac, 0xec, 0x5d, 0x65, 0x07, 0x73, 0x9f, 0x20, 0x3d, 0x1f, 0x5d, 0x9f,
                   0x1d, 0x86, 0x2f, 0x7c, 0x2c, 0xda, 0xc4, 0xf1, 0x9d, 0x2b, 0xdf, 0xf6, 0x44,
                   0x87, 0xe6, 0x0d, 0x96, 0x9e, 0x3c, 0xed, 0x61, 0x53, 0x37, 0xb9, 0xee, 0xc6,
                   0xac, 0x44, 0x61, 0xc6, 0xca, 0x07, 0xf0, 0x93, 0x97, 0x41, 0xe5, 0x7c, 0x24,
                   0xd0, 0x00, 0x5c, 0x7e, 0xa1, 0x71, 0xa0, 0xee, 0x1e, 0x73, 0x48, 0x24, 0x9d,
                   0x13, 0x5b, 0x38, 0xf2, 0x22, 0xe4, 0xda, 0xd7, 0xb9, 0xa0, 0x33, 0xed, 0x83,
                   0xf5, 0xca, 0x27, 0x27, 0x73, 0x93, 0xe3, 0x16, 0x58, 0x20, 0x33, 0xc7, 0x4a,
                   0xff, 0xe2, 0x56, 0x6a, 0x2b, 0xea, 0x47, 0xf9, 0x1f, 0x0f, 0xd9, 0xfe, 0x49,
                   0xec, 0xe7, 0xe1, 0xf7, 0x9f, 0x3a, 0xd6, 0xe9, 0xb2, 0x3e, 0x02, 0x77, 0xc8,
                   0xec, 0xc4, 0xb3, 0x13, 0x22, 0x57, 0x48, 0xdd, 0x2a, 0x80, 0xf5, 0x67, 0x95,
                   0x34, 0xa0, 0x70, 0x0e, 0x24, 0x6a, 0x79, 0xa4, 0x9b, 0x3f, 0x74, 0xeb, 0x89,
                   0xec, 0x62, 0x05, 0xfe, 0x1e, 0xeb, 0x94, 0x1c, 0x73, 0xb1, 0xfc, 0xf1],
        },
        {
            pass: [0xe1, 0x25, 0xce, 0xe6, 0x1c, 0x8c, 0xb7, 0x77, 0x8d, 0x9e, 0x5a, 0xd0, 0xa6,
                   0xf5, 0xd9, 0x78, 0xce, 0x9f, 0x84, 0xde, 0x21, 0x3a, 0x85, 0x56, 0xd9, 0xff,
                   0xe2, 0x02, 0x02, 0x0a, 0xb4, 0xa6, 0xed, 0x90, 0x74, 0xa4, 0xeb, 0x34, 0x16,
                   0xf9, 0xb1, 0x68, 0xf1, 0x37, 0x51, 0x0f, 0x3a, 0x30, 0xb7, 0x0b, 0x96, 0xcb,
                   0xfa, 0x21, 0x9f, 0xf9, 0x9f, 0x6c, 0x6e, 0xaf, 0xfb, 0x15, 0xc0, 0x6b, 0x60,
                   0xe0, 0x0c, 0xc2, 0x89, 0x02, 0x77, 0xf0, 0xfd, 0x3c, 0x62, 0x21, 0x15, 0x77,
                   0x2f, 0x70, 0x48, 0xad, 0xae, 0xbe, 0xd8, 0x6e],
            salt: [0xf1, 0x19, 0x2d, 0xd5, 0xdc, 0x23, 0x68, 0xb9, 0xcd, 0x42, 0x13, 0x38, 0xb2,
                   0x24, 0x33, 0x45],
            ops:  4,
            mem:  7849083,
            out:  [0x26, 0xba, 0xb5, 0xf1, 0x01, 0x56, 0x0e, 0x48, 0xc7, 0x11, 0xda, 0x4f, 0x05,
                   0xe8, 0x1f, 0x5a, 0x38, 0x02, 0xb7, 0xa9, 0x3d, 0x51, 0x55, 0xb9, 0xca, 0xb1,
                   0x53, 0x06, 0x9c, 0xc4, 0x2b, 0x8e, 0x9f, 0x91, 0x0b, 0xfe, 0xad, 0x74, 0x76,
                   0x52, 0xa0, 0x70, 0x8d, 0x70, 0xe4, 0xde, 0x0b, 0xad, 0xa3, 0x72, 0x18, 0xbd,
                   0x20, 0x3a, 0x12, 0x01, 0xc3, 0x6b, 0x42, 0xf9, 0xa2, 0x69, 0xb6, 0x75, 0xb1,
                   0xf3, 0x0c, 0xfc, 0x36, 0xf3, 0x5a, 0x30, 0x30, 0xe9, 0xc7, 0xf5, 0x7d, 0xfb,
                   0xa0, 0xd3, 0x41, 0xa9, 0x74, 0xc1, 0x88, 0x6f, 0x70, 0x8c, 0x3e, 0x82, 0x97,
                   0xef, 0xbf, 0xe4, 0x11, 0xbb, 0x9d, 0x51, 0x37, 0x52, 0x64, 0xbd, 0x7c, 0x70,
                   0xd5, 0x7a, 0x8a, 0x56, 0xfc, 0x9d, 0xe2, 0xc1, 0xc9, 0x7c, 0x08, 0x77, 0x68,
                   0x03, 0xec, 0x2c, 0xd0, 0x14, 0x0b, 0xba, 0x8e, 0x61, 0xdc, 0x0f, 0x4a, 0xd3,
                   0xd3, 0xd1, 0xa8, 0x9b, 0x4b, 0x71, 0x0a, 0xf8, 0x1b, 0xfe, 0x35, 0xa0, 0xee,
                   0xa1, 0x93, 0xe1, 0x8a, 0x6d, 0xa0, 0xf5, 0xec, 0x05, 0x54, 0x2c, 0x9e, 0xef,
                   0xc4, 0x58, 0x44, 0x58, 0xe1, 0xda, 0x71, 0x56, 0x11, 0xba, 0x09, 0x61, 0x73,
                   0x84, 0x74, 0x8b, 0xd4, 0x3b, 0x9b, 0xf1, 0xf3, 0xa6, 0xdf, 0x4e, 0xcd, 0x09,
                   0x1d, 0x08, 0x75, 0xe0, 0x8d, 0x6e, 0x2f, 0xd8, 0xa5, 0xc7, 0xce, 0x08, 0x90,
                   0x4b, 0x51, 0x60, 0xcd, 0x38, 0x16, 0x7b, 0x76, 0xec, 0x76, 0xef, 0x2d, 0x31,
                   0x00, 0x49, 0x05, 0x5a, 0x56, 0x4d, 0xa2, 0x3d, 0x4e, 0xbd, 0x2b, 0x87, 0xe4,
                   0x21, 0xcc, 0x33, 0xc4, 0x01, 0xe1, 0x2d, 0x5c, 0xd8, 0xd9, 0x36, 0xc9, 0xba,
                   0xf7, 0x5e, 0xbd, 0xfb, 0x55, 0x7d, 0x34, 0x2d, 0x28, 0x58, 0xfc, 0x78, 0x1d,
                   0xa3, 0x18, 0x60],
        },
        {
            pass: [0x92, 0x26, 0x3c, 0xbf, 0x6a, 0xc3, 0x76, 0x49, 0x9f, 0x68, 0xa4, 0x28, 0x9d,
                   0x3b, 0xb5, 0x9e, 0x5a, 0x22, 0x33, 0x5e, 0xba, 0x63, 0xa3, 0x2e, 0x64, 0x10,
                   0x24, 0x91, 0x55, 0xb9, 0x56, 0xb6, 0xa3, 0xb4, 0x8d, 0x4a, 0x44, 0x90, 0x6b,
                   0x18, 0xb8, 0x97, 0x12, 0x73, 0x00, 0xb3, 0x75, 0xb8, 0xf8, 0x34, 0xf1, 0xce,
                   0xff, 0xc7, 0x08, 0x80, 0xa8, 0x85, 0xf4, 0x7c, 0x33, 0x87, 0x67, 0x17, 0xe3,
                   0x92, 0xbe, 0x57, 0xf7, 0xda, 0x3a, 0xe5, 0x8d, 0xa4, 0xfd, 0x1f, 0x43, 0xda,
                   0xa7, 0xe4, 0x4b, 0xb8, 0x2d, 0x37, 0x17, 0xaf, 0x43, 0x19, 0x34, 0x9c, 0x24,
                   0xcd, 0x31, 0xe4, 0x6d, 0x29, 0x58, 0x56, 0xb0, 0x44, 0x1b, 0x6b, 0x28, 0x99,
                   0x92, 0xa1, 0x1c, 0xed, 0x1c, 0xc3, 0xbf, 0x30, 0x11, 0x60, 0x45, 0x90, 0x24,
                   0x4a, 0x3e, 0xb7, 0x37, 0xff, 0x22, 0x11, 0x29, 0x21, 0x5e, 0x4e, 0x43, 0x47,
                   0xf4, 0x91, 0x5d, 0x41, 0x29, 0x2b, 0x51, 0x73, 0xd1, 0x96, 0xeb, 0x9a, 0xdd,
                   0x69, 0x3b, 0xe5, 0x31, 0x9f, 0xda, 0xdc, 0x24, 0x29, 0x06, 0x17, 0x8b, 0xb6,
                   0xc0, 0x28, 0x6c, 0x9b, 0x6c, 0xa6, 0x01, 0x27, 0x46, 0x71, 0x1f, 0x58, 0xc8,
                   0xc3, 0x92, 0x01, 0x6b, 0x2f, 0xdf, 0xc0, 0x9c, 0x64, 0xf0, 0xf6, 0xb6, 0xab,
                   0x7b],
            salt: [0x3b, 0x84, 0x0e, 0x20, 0xe9, 0x55, 0x5e, 0x9f, 0xb0, 0x31, 0xc4, 0xba, 0x1f,
                   0x17, 0x47, 0xce],
            ops:  3,
            mem:  7994791,
            out:  [0x6e, 0xb4, 0x5e, 0x66, 0x85, 0x82, 0xd6, 0x37, 0x88, 0xca, 0x8f, 0x6e, 0x93,
                   0x0c, 0xa6, 0x0b, 0x04, 0x5a, 0x79, 0x5f, 0xca, 0x98, 0x73, 0x44, 0xf9, 0xa7,
                   0xa1, 0x35, 0xaa, 0x3b, 0x51, 0x32, 0xb5, 0x0a, 0x34, 0xa3, 0x86, 0x4c, 0x26,
                   0x58, 0x1f, 0x1f, 0x56, 0xdd, 0x0b, 0xcb, 0xfa, 0xfb, 0xfa, 0x92, 0xcd, 0x9b,
                   0xff, 0x6b, 0x24, 0xa7, 0x34, 0xcf, 0xe8, 0x8f, 0x85, 0x4a, 0xef, 0x4b, 0xda,
                   0x0a, 0x79, 0x83, 0x12, 0x0f, 0x44, 0x93, 0x6e, 0x8f, 0xf3, 0x1d, 0x29, 0x72,
                   0x8a, 0xc0, 0x8c, 0xcc, 0xe6, 0xf3, 0xf9, 0x16, 0xb3, 0xc6, 0x39, 0x62, 0x75,
                   0x5c, 0x23, 0xa1, 0xfa, 0x9b, 0xb4, 0xe8, 0x82, 0x3f, 0xc8, 0x67, 0xbf, 0xd1,
                   0x8f, 0x28, 0x98, 0x0d, 0x94, 0xbc, 0x58, 0x74, 0x42, 0x3a, 0xb7, 0xf9, 0x6c,
                   0xc0, 0xab, 0x78, 0xd8, 0xfa, 0x21, 0xfb, 0xd0, 0x0c, 0xd3, 0xa1, 0xd9, 0x6a,
                   0x73, 0xfa, 0x43, 0x9c, 0xcc, 0x3f, 0xc4, 0xea, 0xb1, 0x59, 0x06, 0x77, 0xb0,
                   0x6c, 0xc7, 0x8b, 0x0f, 0x67, 0x4d, 0xfb, 0x68, 0x0f, 0x23, 0x02, 0x2f, 0xb9,
                   0x02, 0x02, 0x2d, 0xd8, 0x62, 0x08, 0x03, 0x22, 0x9c, 0x6d, 0xdf, 0x79, 0xa8,
                   0x15, 0x6c, 0xcf, 0xce, 0x48, 0xbb, 0xd7, 0x6c, 0x05, 0xab, 0x67, 0x06, 0x34,
                   0xf2, 0x06, 0xe5, 0xb2, 0xe8, 0x96, 0x23, 0x0b, 0xaa, 0x74, 0xa8, 0x56, 0x96,
                   0x4d, 0xbd, 0x85, 0x11, 0xac, 0xb7, 0x1d, 0x75, 0xa1, 0x50, 0x67, 0x66, 0xa1,
                   0x25, 0xd8, 0xce, 0x03, 0x7f, 0x1d, 0xb7, 0x20, 0x86, 0xeb, 0xc3, 0xbc, 0xca,
                   0xef, 0xbd, 0x8c, 0xd9, 0x38, 0x01, 0x67, 0xc2, 0x53, 0x03, 0x86, 0x54, 0x4e,
                   0xbf, 0xbe, 0xad, 0xbe, 0x23, 0x77, 0x84, 0xd1, 0x02, 0xbb, 0x92, 0xa1, 0x0f,
                   0xd2, 0x42],
        },
        {
            pass: [0x4a, 0x85, 0x7e, 0x2e, 0xe8, 0xaa, 0x9b, 0x60, 0x56, 0xf2, 0x42, 0x4e, 0x84,
                   0xd2, 0x4a, 0x72, 0x47, 0x33, 0x78, 0x90, 0x6e, 0xe0, 0x4a, 0x46, 0xcb, 0x05,
                   0x31, 0x15, 0x02, 0xd5, 0x25, 0x0b, 0x82, 0xad, 0x86, 0xb8, 0x3c, 0x8f, 0x20,
                   0xa2, 0x3d, 0xbb, 0x74, 0xf6, 0xda, 0x60, 0xb0, 0xb6, 0xec, 0xff, 0xd6, 0x71,
                   0x34, 0xd4, 0x59, 0x46, 0xac, 0x8e, 0xbf, 0xb3, 0x06, 0x42, 0x94, 0xbc, 0x09,
                   0x7d, 0x43, 0xce, 0xd6, 0x86, 0x42, 0xbf, 0xb8, 0xbb, 0xbd, 0xd0, 0xf5, 0x0b,
                   0x30, 0x11, 0x8f, 0x5e],
            salt: [0x39, 0xd8, 0x2e, 0xef, 0x32, 0x01, 0x0b, 0x8b, 0x79, 0xcc, 0x5b, 0xa8, 0x8e,
                   0xd5, 0x39, 0xfb],
            ops:  3,
            mem:  1432947,
            out:  [0x08, 0xd8, 0xcd, 0x33, 0x0c, 0x57, 0xe1, 0xb4, 0x64, 0x32, 0x41, 0xd0, 0x5b,
                   0xb4, 0x68, 0xba, 0x4e, 0xe4, 0xe9, 0x32, 0xcd, 0x08, 0x58, 0x81, 0x6b, 0xe9,
                   0xef, 0x15, 0x36, 0x0b, 0x27, 0xbb, 0xd0, 0x6a, 0x87, 0x13, 0x0e, 0xe9, 0x22,
                   0x22, 0xbe, 0x26, 0x7a, 0x29, 0xb8, 0x1f, 0x5a, 0xe8, 0xfe, 0x86, 0x13, 0x32,
                   0x4c, 0xfc, 0x48, 0x32, 0xdc, 0x49, 0x38, 0x7f, 0xd0, 0x60, 0x2f, 0x1c, 0x57,
                   0xb4, 0xd0, 0xf3, 0x85, 0x5d, 0xb9, 0x4f, 0xb7, 0xe1, 0x2e, 0xb0, 0x5f, 0x9a,
                   0x48, 0x4a, 0xed, 0x4a, 0x43, 0x07, 0xab, 0xf5, 0x86, 0xcd, 0x3d, 0x55, 0xc8,
                   0x09, 0xbc, 0x08, 0x15, 0x41, 0xe0, 0x0b, 0x68, 0x27, 0x72, 0xfb, 0x20, 0x66,
                   0x50, 0x4f, 0xf9, 0x35, 0xb8, 0xeb, 0xc5, 0x51, 0xa2, 0x08, 0x38, 0x82, 0xf8,
                   0x74, 0xbc, 0x0f, 0xae, 0x68, 0xe5, 0x68, 0x48, 0xae, 0x34, 0xc9, 0x10, 0x97,
                   0xc3, 0xbf, 0x0c, 0xca, 0x8e, 0x75, 0xc0, 0x79, 0x7e, 0xef, 0x3e, 0xfd, 0xe3,
                   0xf7, 0x5e, 0x00, 0x58, 0x15, 0x01, 0x8d, 0xb3, 0xcf, 0x7c, 0x10, 0x9a, 0x81,
                   0x22, 0x64, 0xc4, 0xde, 0x69, 0xdc, 0xb2, 0x23, 0x22, 0xdb, 0xbc, 0xfa, 0x44,
                   0x7f, 0x5b, 0x00, 0xec, 0xd1, 0xb0, 0x4a, 0x7b, 0xe1, 0x56, 0x9c, 0x8e, 0x55,
                   0x6a, 0xdb, 0x7b, 0xba, 0x48, 0xad, 0xf8, 0x1d],
        },
        {
            pass: [0xc7, 0xb0, 0x9a, 0xec, 0x68, 0x0e, 0x7b, 0x42, 0xfe, 0xdd, 0x7f, 0xc7, 0x92,
                   0xe7, 0x8b, 0x2f, 0x6c, 0x1b, 0xea, 0x8f, 0x4a, 0x88, 0x43, 0x20, 0xb6, 0x48,
                   0xf8, 0x1e, 0x8c, 0xf5, 0x15, 0xe8, 0xba, 0x9d, 0xcf, 0xb1, 0x1d, 0x43, 0xc4,
                   0xaa, 0xe1, 0x14, 0xc1, 0x73, 0x4a, 0xa6, 0x9c, 0xa8, 0x2d, 0x44, 0x99, 0x83,
                   0x65, 0xdb, 0x9c, 0x93, 0x74, 0x4f, 0xa2, 0x8b, 0x63, 0xfd, 0x16, 0x00, 0x0e,
                   0x82, 0x61, 0xcb, 0xbe, 0x08, 0x3e, 0x7e, 0x2d, 0xa1, 0xe5, 0xf6, 0x96, 0xbd,
                   0xe0, 0x83, 0x4f, 0xe5, 0x31, 0x46, 0xd7, 0xe0, 0xe3, 0x5e, 0x7d, 0xe9, 0x92,
                   0x0d, 0x04, 0x1f, 0x5a, 0x56, 0x21, 0xaa, 0xbe, 0x02, 0xda, 0x3e, 0x2b, 0x09,
                   0xb4, 0x05, 0xb7, 0x79, 0x37, 0xef, 0xef, 0x31, 0x97, 0xbd, 0x57, 0x72, 0xe4,
                   0x1f, 0xdb, 0x73, 0xfb, 0x52, 0x94, 0x47, 0x8e, 0x45, 0x20, 0x80, 0x63, 0xb5,
                   0xf5, 0x8e, 0x08, 0x9d, 0xbe, 0xb6, 0xd6, 0x34, 0x2a, 0x90, 0x9c, 0x13, 0x07,
                   0xb3, 0xff, 0xf5, 0xfe, 0x2c, 0xf4, 0xda, 0x56, 0xbd, 0xae, 0x50, 0x84,
                   0x8f],
            salt: [0x03, 0x9c, 0x05, 0x6d, 0x93, 0x3b, 0x47, 0x50, 0x32, 0x77, 0x7e, 0xdb, 0xaf,
                   0xfa, 0xc5, 0x0f],
            ops:  3,
            mem:  4886999,
            out:  [0xd6, 0xe9, 0xd6, 0xca, 0xbd, 0x42, 0xfb, 0x9b, 0xa7, 0x16, 0x2f, 0xe9, 0xb8,
                   0xe4, 0x1d, 0x59, 0xd3, 0xc7, 0x03, 0x47, 0x56, 0xcb, 0x46, 0x0c, 0x9a, 0xff,
                   0xe3, 0x93, 0x30, 0x8b, 0xd0, 0x22, 0x5c, 0xe0, 0x37, 0x1f, 0x2e, 0x6c, 0x3c,
                   0xa3, 0x2a, 0xca, 0x20, 0x02, 0xbf, 0x2d, 0x39, 0x09, 0xc6, 0xb6, 0xe7, 0xdf,
                   0xc4, 0xa0, 0x0e, 0x85, 0x0f, 0xf4, 0xf5, 0x70, 0xf8, 0xf7, 0x49, 0xd4, 0xbb,
                   0x6f, 0x00, 0x91, 0xe5, 0x54, 0xbe, 0x67, 0xa9, 0x09, 0x5a, 0xe1, 0xee, 0xfa,
                   0xa1, 0xa9, 0x33, 0x31, 0x6c, 0xbe, 0xc3, 0xc2, 0xfd, 0x4a, 0x14, 0xa5, 0xb6,
                   0x94, 0x1b, 0xda, 0x9b, 0x7e, 0xab, 0xd8, 0x21, 0xd7, 0x9a, 0xbd, 0xe2, 0x47,
                   0x5a, 0x53, 0xaf, 0x1a, 0x85, 0x71, 0xc7, 0xee, 0x46, 0x46, 0x0b, 0xe4, 0x15,
                   0x88, 0x2e, 0x0b, 0x39, 0x3f, 0x48, 0xc1, 0x2f, 0x74, 0x0a, 0x6a, 0x72, 0xcb,
                   0xa9, 0x77, 0x30, 0x00, 0x60, 0x2e, 0x13, 0xb4, 0x0d, 0x3d, 0xfa, 0x6a, 0xc1,
                   0xd4, 0xec, 0x43, 0xa8, 0x38, 0xb7, 0xe3, 0xe1, 0x65, 0xfe, 0xca, 0xd4, 0xb2,
                   0x49, 0x83, 0x89, 0xe6, 0x0a, 0x3f, 0xf9, 0xf0, 0xf8, 0xf4, 0xb9, 0xfc, 0xa1,
                   0x12, 0x6e, 0x64, 0xf4, 0x95, 0x01, 0xe3, 0x86, 0x90],
        },
        {
            pass: [0xb5, 0x40, 0xbe, 0xb0, 0x16, 0xa5, 0x36, 0x65, 0x24, 0xd4, 0x60, 0x51, 0x56,
                   0x49, 0x3f, 0x98, 0x74, 0x51, 0x4a, 0x5a, 0xa5, 0x88, 0x18, 0xcd, 0x0c, 0x6d,
                   0xff, 0xfa, 0xa9, 0xe9, 0x02, 0x05, 0xf1, 0x7b],
            salt: [0x44, 0x07, 0x1f, 0x6d, 0x18, 0x15, 0x61, 0x67, 0x0b, 0xda, 0x72, 0x8d, 0x43,
                   0xfb, 0x79, 0xb4],
            ops:  1,
            mem:  1631659,
            out:  [0x7f, 0xb7, 0x24, 0x09, 0xb0, 0x98, 0x7f, 0x81, 0x90, 0xc3, 0x72, 0x97, 0x10,
                   0xe9, 0x8c, 0x3f, 0x80, 0xc5, 0xa8, 0x72, 0x7d, 0x42, 0x5f, 0xdc, 0xde, 0x7f,
                   0x36, 0x44, 0xd4, 0x67, 0xfe, 0x97, 0x3f, 0x5b, 0x5f, 0xee, 0x68, 0x3b, 0xd3,
                   0xfc, 0xe8, 0x12, 0xcb, 0x9a, 0xe5, 0xe9, 0x92, 0x1a, 0x2d, 0x06, 0xc2, 0xf1,
                   0x90, 0x5e, 0x4e, 0x83, 0x96, 0x92, 0xf2, 0xb9, 0x34, 0xb6, 0x82, 0xf1, 0x1a,
                   0x2f, 0xe2, 0xb9, 0x04, 0x82, 0xea, 0x5d, 0xd2, 0x34, 0x86, 0x35, 0x16, 0xdb,
                   0xa6, 0xf5, 0x2d, 0xc0, 0x70, 0x2d, 0x32, 0x4e, 0xc7, 0x7d, 0x86, 0x0c, 0x2e,
                   0x18, 0x1f, 0x84, 0x47, 0x2b, 0xd7, 0x10, 0x4f, 0xed, 0xce, 0x07, 0x1f, 0xfa,
                   0x93, 0xc5, 0x30, 0x94, 0x94, 0xad, 0x51, 0x62, 0x3d, 0x21, 0x44, 0x47, 0xa7,
                   0xb2, 0xb1, 0x46, 0x2d, 0xc7, 0xd5, 0xd5, 0x5a, 0x1f, 0x6f, 0xd5, 0xb5, 0x4c,
                   0xe0, 0x24, 0x11, 0x8d, 0x86, 0xf0, 0xc6, 0x48, 0x9d, 0x16, 0x54, 0x5a, 0xaa,
                   0x87, 0xb6, 0x68, 0x9d, 0xad, 0x9f, 0x2f, 0xb4, 0x7f, 0xda, 0x98, 0x94, 0xf8,
                   0xe1, 0x2b, 0x87, 0xd9, 0x78, 0xb4, 0x83, 0xcc, 0xd4, 0xcc, 0x5f, 0xd9, 0x59,
                   0x5c, 0xdc, 0x7a, 0x81, 0x84, 0x52, 0xf9, 0x15, 0xce, 0x2f, 0x7d, 0xf9, 0x5e,
                   0xc1, 0x2b, 0x1c, 0x72, 0xe3, 0x78, 0x8d, 0x47, 0x34, 0x41, 0xd8, 0x84, 0xf9,
                   0x74, 0x8e, 0xb1, 0x47, 0x03, 0xc2, 0x1b, 0x45, 0xd8, 0x2f, 0xd6, 0x67, 0xb8,
                   0x5f, 0x5b, 0x2d, 0x98, 0xc1, 0x33, 0x03, 0xb3, 0xfe, 0x76, 0x28, 0x55, 0x31,
                   0xa8, 0x26, 0xb6, 0xfc, 0x0f, 0xe8, 0xe3, 0xdd, 0xde, 0xcf],
        },
        {
            pass: [0xa1, 0x49, 0x75, 0xc2, 0x6c, 0x08, 0x87, 0x55, 0xa8, 0xb7, 0x15, 0xff, 0x25,
                   0x28, 0xd6, 0x47, 0xcd, 0x34, 0x39, 0x87, 0xfc, 0xf4, 0xaa, 0x25, 0xe7, 0x19,
                   0x4a, 0x84, 0x17, 0xfb, 0x2b, 0x4b, 0x3f, 0x72, 0x68, 0xda, 0x9f, 0x31, 0x82,
                   0xb4, 0xcf, 0xb2, 0x2d, 0x13, 0x8b, 0x27, 0x49, 0xd6, 0x73, 0xa4, 0x7e, 0xcc,
                   0x75, 0x25, 0xdd, 0x15, 0xa0, 0xa3, 0xc6, 0x60, 0x46, 0x97, 0x17, 0x84, 0xbb,
                   0x63, 0xd7, 0xea, 0xe2, 0x4c, 0xc8, 0x4f, 0x26, 0x31, 0x71, 0x20, 0x75, 0xa1,
                   0x0e, 0x10, 0xa9, 0x6b, 0x0e, 0x0e, 0xe6, 0x7c, 0x43, 0xe0, 0x1c, 0x42, 0x3c,
                   0xb9, 0xc4, 0x4e, 0x53, 0x71, 0x01, 0x7e, 0x9c, 0x49, 0x69, 0x56, 0xb6, 0x32,
                   0x15, 0x8d, 0xa3, 0xfe, 0x12, 0xad, 0xde, 0xcb, 0x88, 0x91, 0x2e, 0x67, 0x59,
                   0xbc, 0x37, 0xf9, 0xaf, 0x2f, 0x45, 0xaf, 0x72, 0xc5, 0xca, 0xe3, 0xb1, 0x79,
                   0xff, 0xb6, 0x76, 0xa6, 0x97, 0xde, 0x6e, 0xbe, 0x45, 0xcd, 0x4c, 0x16, 0xd4,
                   0xa9, 0xd6, 0x42, 0xd2, 0x9d, 0xdc, 0x01, 0x86, 0xa0, 0xa4, 0x8c, 0xb6, 0xcd,
                   0x62, 0xbf, 0xc3, 0xdd, 0x22, 0x9d, 0x31, 0x3b, 0x30, 0x15, 0x60, 0x97, 0x1e,
                   0x74, 0x0e, 0x2c, 0xf1, 0xf9, 0x9a, 0x9a, 0x09, 0x0a, 0x5b, 0x28, 0x3f, 0x35,
                   0x47, 0x50, 0x57, 0xe9, 0x6d, 0x70, 0x64, 0xe2, 0xe0, 0xfc, 0x81, 0x98, 0x45,
                   0x91, 0x06, 0x8d, 0x55, 0xa3, 0xb4, 0x16, 0x9f, 0x22, 0xcc, 0xcb, 0x07, 0x45,
                   0xa2, 0x68, 0x94, 0x07, 0xea, 0x19, 0x01, 0xa0, 0xa7, 0x66, 0xeb, 0x99],
            salt: [0x3d, 0x96, 0x8b, 0x27, 0x52, 0xb8, 0x83, 0x84, 0x31, 0x16, 0x50, 0x59, 0x31,
                   0x9f, 0x3f, 0xf8],
            ops:  3,
            mem:  1784128,
            out:  [0x4e, 0x70, 0x2b, 0xc5, 0xf8, 0x91, 0xdf, 0x88, 0x4c, 0x6d, 0xda, 0xa2, 0x43,
                   0xaa, 0x84, 0x6c, 0xe3, 0xc0, 0x87, 0xfe, 0x93, 0x0f, 0xef, 0x0f, 0x36, 0xb3,
                   0xc2, 0xbe, 0x34, 0x16, 0x4c, 0xcc, 0x29, 0x5d, 0xb5, 0x09, 0x25, 0x47, 0x43,
                   0xf1, 0x8f, 0x94, 0x71, 0x59, 0xc8, 0x13, 0xbc, 0xd5, 0xdd, 0x8d, 0x94, 0xa3,
                   0xae, 0xc9, 0x3b, 0xbe, 0x57, 0x60, 0x5d, 0x1f, 0xad, 0x1a, 0xef, 0x11, 0x12,
                   0x68, 0x7c, 0x3d, 0x4e, 0xf1, 0xcb, 0x32, 0x9d, 0x21, 0xf1, 0x63, 0x2f, 0x62,
                   0x68, 0x18, 0xd7, 0x66, 0x91, 0x5d, 0x88, 0x6e, 0x8d, 0x81, 0x9e, 0x4b, 0x0b,
                   0x9c, 0x93, 0x07, 0xf4, 0xb6, 0xaf, 0xc0, 0x81, 0xe1, 0x3b, 0x0c, 0xf3, 0x1d,
                   0xb3, 0x82, 0xff, 0x1b, 0xf0, 0x5a, 0x16, 0xaa, 0xc7, 0xaf, 0x69, 0x63, 0x36,
                   0xd7, 0x5e, 0x99, 0xf8, 0x21, 0x63, 0xe0, 0xf3, 0x71, 0xe1, 0xd2, 0x5c, 0x4a,
                   0xdd, 0x80, 0x8e, 0x21, 0x56, 0x97, 0xad, 0x3f, 0x77, 0x9a, 0x51, 0xa4, 0x62,
                   0xf8, 0xbf, 0x52, 0x61, 0x0a, 0xf2, 0x1f, 0xc6, 0x9d, 0xba, 0x6b, 0x07, 0x26,
                   0x06, 0xf2, 0xda, 0xbc, 0xa7, 0xd4, 0xae, 0x1d, 0x91, 0xd9, 0x19],
        },
    ];

    verify_password_valid_tests! [
        {
            pass: "",
            hash: "$argon2id$v=19$m=4882,t=2,p=1$bA81arsiXysd3WbTRzmEOw$Nm8QBM+7RH1DXo9rvp5cwKE\
                   OOOfD2g6JuxlXihoNcpE",
        },
        {
            pass: "^T5H$JYt39n%K*j:W]!1s?vg!:jGi]Ax?..l7[p0v:1jHTpla9;]bUN;?bWyCbtqg ",
            hash: "$argon2id$v=19$m=4096,t=19,p=1$PkEgMTYtYnl0ZXMgc2FsdA$ltB/ue1kPtBMBGfsysMpPi\
                   gE6hiNEKZ9vs8vLNVDQGA",
        },
        {
            pass: "K3S=KyH#)36_?]LxeR8QNKw6X=gFbxai$C%29V*",
            hash: "$argon2id$v=19$m=4096,t=1,p=3$PkEgcHJldHR5IGxvbmcgc2FsdA$HUqx5Z1b/ZypnUrvvJ5\
                   UC2Q+T6Q1WwASK/Kr9dRbGA0",
        },
    ];

    verify_password_invalid_tests! [
        {
            pass: "",
            hash: "$argon2id$v=19$m=4096,t=0,p=1$X1NhbHQAAAAAAAAAAAAAAA$bWh++MKN1OiFHKgIWTLvIi1\
                   iHicmHH7+Fv3K88ifFfI",
        },
        {
            pass: "",
            hash: "$argon2id$v=19$m=2048,t=4,p=1$SWkxaUhpY21ISDcrRnYzSw$Mbg/Eck1kpZir5T9io7C64c\
                   pffdTBaORgyriLQFgQj8",
        },
        {
            pass: "^T5H$JYt39n%K*j:W]!1s?vg!:jGi]Ax?..l7[p0v:1jHTpla9;]bUN;?bWyCbtqg ",
            hash: "$argon2id$v=19$m=4096,t=0,p=1$PkEgMTYtYnl0ZXMgc2FsdA$ltB/ue1kPtBMBGfsysMpPig\
                   E6hiNEKZ9vs8vLNVDQGA",
        },
    ];

    needs_rehash_tests! {}
}
