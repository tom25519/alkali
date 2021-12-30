//! The [Argon2i](https://en.wikipedia.org/wiki/Argon2) password-based key derivation algorithm.
//!
//! This algorithm is intended to be highly resistant to side-channel attacks, but may be less
//! resistant to GPU-based attacks than [`argon2id`].

use super::pwhash_module;
use libsodium_sys as sodium;

pwhash_module! {
    sodium::crypto_pwhash_argon2i_OPSLIMIT_MIN,
    sodium::crypto_pwhash_argon2i_OPSLIMIT_INTERACTIVE,
    sodium::crypto_pwhash_argon2i_OPSLIMIT_MODERATE,
    sodium::crypto_pwhash_argon2i_OPSLIMIT_SENSITIVE,
    sodium::crypto_pwhash_argon2i_OPSLIMIT_MAX,
    sodium::crypto_pwhash_argon2i_MEMLIMIT_MIN,
    sodium::crypto_pwhash_argon2i_MEMLIMIT_INTERACTIVE,
    sodium::crypto_pwhash_argon2i_MEMLIMIT_MODERATE,
    sodium::crypto_pwhash_argon2i_MEMLIMIT_SENSITIVE,
    sodium::crypto_pwhash_argon2i_memlimit_max,
    sodium::crypto_pwhash_argon2i_PASSWD_MIN,
    sodium::crypto_pwhash_argon2i_passwd_max,
    sodium::crypto_pwhash_argon2i_BYTES_MIN,
    sodium::crypto_pwhash_argon2i_bytes_max,
    sodium::crypto_pwhash_argon2i_SALTBYTES,
    sodium::crypto_pwhash_argon2i_STRBYTES,
    sodium::crypto_pwhash_ALG_ARGON2I13,
    sodium::crypto_pwhash_argon2i,
    sodium::crypto_pwhash_argon2i_str,
    sodium::crypto_pwhash_argon2i_str_verify,
    sodium::crypto_pwhash_argon2i_str_needs_rehash,
}

#[cfg(test)]
mod tests {
    use super::super::{
        kdf_tests, needs_rehash_tests, verify_str_invalid_tests, verify_str_valid_tests,
    };

    kdf_tests! {
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
            out:  [0x23, 0xb8, 0x03, 0xc8, 0x4e, 0xaa, 0x25, 0xf4, 0xb4, 0x46, 0x34, 0xcc, 0x1e,
                   0x5e, 0x37, 0x79, 0x2c, 0x53, 0xfc, 0xd9, 0xb1, 0xeb, 0x20, 0xf8, 0x65, 0x32,
                   0x9c, 0x68, 0xe0, 0x9c, 0xbf, 0xa9, 0xf1, 0x96, 0x87, 0x57, 0x90, 0x1b, 0x38,
                   0x3f, 0xce, 0x22, 0x1a, 0xfe, 0x27, 0x71, 0x3f, 0x97, 0x91, 0x4a, 0x04, 0x13,
                   0x95, 0xbb, 0xe1, 0xfb, 0x70, 0xe0, 0x79, 0xe5, 0xbe, 0xd2, 0xc7, 0x14, 0x5b,
                   0x1f, 0x61, 0x54, 0x04, 0x6f, 0x59, 0x58, 0xe9, 0xb1, 0xb2, 0x90, 0x55, 0x45,
                   0x4e, 0x26, 0x4d, 0x1f, 0x22, 0x31, 0xc3, 0x16, 0xf2, 0x6b, 0xe2, 0xe3, 0x73,
                   0x8e, 0x83, 0xa8, 0x03, 0x15, 0xe9, 0xa0, 0x95, 0x1c, 0xe4, 0xb1, 0x37, 0xb5,
                   0x2e, 0x7d, 0x5e, 0xe7, 0xb3, 0x7f, 0x7d, 0x93, 0x6d, 0xce, 0xe5, 0x13, 0x62,
                   0xbc, 0xf7, 0x92, 0x59, 0x5e, 0x3c, 0x89, 0x6a, 0xd5, 0x04, 0x27, 0x34, 0xfc,
                   0x90, 0xc9, 0x2c, 0xae, 0x57, 0x2c, 0xe6, 0x3f, 0xf6, 0x59, 0xa2, 0xf7, 0x97,
                   0x4a, 0x3b, 0xd7, 0x30, 0xd0, 0x4d, 0x52, 0x5d, 0x25, 0x3c, 0xcc, 0x38],
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
            out:  [0x0b, 0xb3, 0x76, 0x9b, 0x06, 0x4b, 0x9c, 0x43, 0xa9, 0x46, 0x04, 0x76, 0xab,
                   0x38, 0xc4, 0xa9, 0xa2, 0x47, 0x0d, 0x55, 0xd4, 0xc9, 0x92, 0xc6, 0xe7, 0x23,
                   0xaf, 0x89, 0x5e, 0x4c, 0x07, 0xc0, 0x9a, 0xf4, 0x1f, 0x22, 0xf9, 0x0e, 0xab,
                   0x58, 0x3a, 0x0c, 0x36, 0x2d, 0x17, 0x7f, 0x46, 0x77, 0xf2, 0x12, 0x48, 0x2f,
                   0xd1, 0x45, 0xbf, 0xb9, 0xac, 0x62, 0x11, 0x63, 0x5e, 0x48, 0x46, 0x11, 0x22,
                   0xbb, 0x49, 0x09, 0x7b, 0x5f, 0xb0, 0x73, 0x9d, 0x2c, 0xd2, 0x2a, 0x39, 0xbf,
                   0x03, 0xd2, 0x68, 0xe7, 0x49, 0x5d, 0x4f, 0xd8, 0xd7, 0x10, 0xaa, 0x15, 0x62,
                   0x02, 0xf0, 0xa0, 0x6e, 0x93, 0x2f, 0xf5, 0x13, 0xe6, 0xe7, 0xc7, 0x6a, 0x4e,
                   0x98, 0xb6, 0xdf, 0x5c, 0xf9, 0x22, 0xf1, 0x24, 0x79, 0x1b, 0x10, 0x76, 0xad,
                   0x90, 0x4e, 0x68, 0x97, 0x27, 0x1f, 0x5d, 0x7d, 0x24, 0xc5, 0x92, 0x9e, 0x2a,
                   0x3b, 0x83, 0x6d, 0x0f, 0x2f, 0x26, 0x97, 0xc2, 0xd7, 0x58, 0xee, 0x79, 0xbf,
                   0x12, 0x64, 0xf3, 0xfa, 0xe6, 0x5f, 0x37, 0x44, 0xe0, 0xf6, 0xd7, 0xd0, 0x7e,
                   0xf6, 0xe8, 0xb3, 0x5b, 0x70, 0xc0, 0xf8, 0x8e, 0x90, 0x36, 0x32, 0x5b, 0xfb,
                   0x24, 0xac, 0x7f, 0x55, 0x03, 0x51, 0x48, 0x6d, 0xa8, 0x7a, 0xef, 0x10, 0xd6,
                   0xb0, 0xcb, 0x77, 0xd1, 0xcf, 0x6e, 0x31, 0xcf, 0x98, 0x39, 0x9c, 0x6f, 0x24,
                   0x1c, 0x60, 0x5c, 0x65, 0x30, 0xdf, 0xfb, 0x47, 0x64, 0x78, 0x4f, 0x6c, 0x0b,
                   0x0b, 0xf6, 0x01, 0xd4, 0xe4, 0x43, 0x1e, 0x8b, 0x18, 0xda, 0xbd, 0xc3, 0x07,
                   0x9c, 0x6e, 0x26, 0x43, 0x02, 0xad, 0xe7, 0x9f, 0x61, 0xcb, 0xd5, 0x49, 0x7c,
                   0x95, 0x48, 0x63, 0x40, 0xbb, 0x89, 0x1a, 0x73, 0x72, 0x23, 0x10, 0x0b, 0xe0,
                   0x42, 0x96, 0x50],
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
            out:  [0xe9, 0xaa, 0x07, 0x3b, 0x0b, 0x87, 0x2f, 0x15, 0xc0, 0x83, 0xd1, 0xd7, 0xce,
                   0x52, 0xc0, 0x9f, 0x49, 0x3b, 0x82, 0x7c, 0xa7, 0x8f, 0x13, 0xa0, 0x6c, 0x17,
                   0x21, 0xb4, 0x5b, 0x1e, 0x17, 0xb2, 0x4c, 0x04, 0xe1, 0x9f, 0xe8, 0x69, 0x33,
                   0x31, 0x35, 0x36, 0x01, 0x97, 0xa7, 0xeb, 0x55, 0x99, 0x4f, 0xee, 0x3e, 0x8d,
                   0x96, 0x80, 0xae, 0xdf, 0xdf, 0x76, 0x74, 0xf3, 0xad, 0x7b, 0x84, 0xd5, 0x9d,
                   0x7e, 0xab, 0x03, 0x57, 0x9f, 0xfc, 0x10, 0xc7, 0x09, 0x30, 0x93, 0xbc, 0x48,
                   0xec, 0x84, 0x25, 0x2a, 0xa1, 0xb3, 0x0f, 0x40, 0xf5, 0xe8, 0x38, 0xf1, 0x44,
                   0x3e, 0x15, 0xe2, 0x77, 0x2a, 0x39, 0xf4, 0xe7, 0x74, 0xeb, 0x05, 0x20, 0x97,
                   0xe8, 0x88, 0x1e, 0x94, 0xf1, 0x54, 0x57, 0xb7, 0x79, 0xfa, 0x2a, 0xf2, 0xbb,
                   0xc9, 0xa9, 0x93, 0x68, 0x76, 0x57, 0xc7, 0x70, 0x4a, 0xc8, 0xa3, 0x7c, 0x25,
                   0xc1, 0xdf, 0x42, 0x89, 0xeb, 0x4c, 0x70, 0xda, 0x45, 0xf2, 0xfd, 0x46, 0xbc,
                   0x0f, 0x78, 0x25, 0x97, 0x67, 0xd3, 0xdd, 0x47, 0x8a, 0x7c, 0x36, 0x9c, 0xf8,
                   0x66, 0x75, 0x8b, 0xc3, 0x6d, 0x9b, 0xd8, 0xe2, 0xe3, 0xc9, 0xfb, 0x0c, 0xf7,
                   0xfd, 0x60, 0x73, 0xeb, 0xf6, 0x30, 0xc1, 0xf6, 0x7f, 0xa7, 0xd3, 0x03, 0xc0,
                   0x7d, 0xa4, 0x0b, 0x36, 0x74, 0x9d, 0x15, 0x7e, 0xa3, 0x79, 0x65, 0xfe, 0xf8,
                   0x10, 0xf2, 0xea, 0x05, 0xae, 0x6f, 0xc7, 0xd9, 0x6a, 0x8f, 0x34, 0x70, 0xd7,
                   0x3e, 0x15, 0xb2, 0x2b, 0x42, 0xe8, 0xd6, 0x98, 0x6d, 0xbf, 0xe5, 0x30, 0x32,
                   0x56, 0xb2, 0xb3, 0x56, 0x03, 0x72, 0xc4, 0x45, 0x2f, 0xfb, 0x2a, 0x04, 0xfb,
                   0x7c, 0x66, 0x91, 0x48, 0x9f, 0x70, 0xcb, 0x46, 0x83, 0x1b, 0xe0, 0x67, 0x91,
                   0x17, 0xf7],
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
            out:  [0xc1, 0x21, 0x20, 0x9f, 0x0b, 0xa7, 0x0a, 0xed, 0x93, 0xd4, 0x92, 0x00, 0xe5,
                   0xdc, 0x82, 0xcc, 0xe0, 0x13, 0xce, 0xf2, 0x5e, 0xa3, 0x1e, 0x16, 0x0b, 0xf8,
                   0xdb, 0x3c, 0xf4, 0x48, 0xa5, 0x9d, 0x1a, 0x56, 0xf6, 0xc1, 0x92, 0x59, 0xe1,
                   0x8e, 0xa0, 0x20, 0x55, 0x3c, 0xb7, 0x57, 0x81, 0x76, 0x1d, 0x11, 0x2b, 0x2d,
                   0x94, 0x9a, 0x29, 0x75, 0x84, 0xc6, 0x5e, 0x60, 0xdf, 0x95, 0xad, 0x89, 0xc4,
                   0x10, 0x98, 0x25, 0xa3, 0x17, 0x1d, 0xc6, 0xf2, 0x0b, 0x1f, 0xd6, 0xb0, 0xcd,
                   0xfd, 0x19, 0x48, 0x61, 0xbc, 0x2b, 0x41, 0x42, 0x95, 0xbe, 0xe5, 0xc6, 0xc5,
                   0x26, 0x19, 0xe5, 0x44, 0xab, 0xce, 0x7d, 0x52, 0x06, 0x59, 0xc3, 0xd5, 0x1d,
                   0xe2, 0xc6, 0x0e, 0x89, 0x94, 0x8d, 0x83, 0x06, 0x95, 0xab, 0x38, 0xdc, 0xb7,
                   0x5d, 0xd7, 0xab, 0x06, 0xa4, 0x77, 0x0d, 0xd4, 0xbc, 0x7c, 0x8f, 0x33, 0x55,
                   0x19, 0xe0, 0x4b, 0x03, 0x84, 0x16, 0xb1, 0xa7, 0xdb, 0xd2, 0x5c, 0x02, 0x67,
                   0x86, 0xa8, 0x10, 0x5c, 0x5f, 0xfe, 0x7a, 0x09, 0x31, 0x36, 0x4f, 0x03, 0x76,
                   0xae, 0x57, 0x72, 0xbe, 0x39, 0xb5, 0x1d, 0x91, 0xd3, 0x28, 0x14, 0x64, 0xe0,
                   0xf3, 0xa1, 0x28, 0xe7, 0x15, 0x5a, 0x68, 0xe8, 0x7c, 0xf7, 0x96, 0x26, 0xff,
                   0xca, 0x0b, 0x2a, 0x30, 0x22, 0xfc, 0x84, 0x20],
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
            out:  [0x91, 0xc3, 0x37, 0xce, 0x89, 0x18, 0xa5, 0x80, 0x5a, 0x59, 0xb0, 0x0b, 0xd1,
                   0x81, 0x9d, 0x3e, 0xb4, 0x35, 0x68, 0x07, 0xcb, 0xd2, 0xa8, 0x0b, 0x27, 0x1c,
                   0x4b, 0x48, 0x2d, 0xce, 0x03, 0xf5, 0xb0, 0x2a, 0xe4, 0xeb, 0x83, 0x1f, 0xf6,
                   0x68, 0xcb, 0xb3, 0x27, 0xb9, 0x3c, 0x30, 0x0b, 0x41, 0xda, 0x48, 0x52, 0xe5,
                   0x54, 0x7b, 0xea, 0x83, 0x42, 0xd5, 0x18, 0xdd, 0x93, 0x11, 0xaa, 0xeb, 0x5f,
                   0x90, 0xec, 0xcf, 0x66, 0xd5, 0x48, 0xf9, 0x27, 0x56, 0x31, 0xf0, 0xb1, 0xfd,
                   0x4b, 0x29, 0x9c, 0xec, 0x5d, 0x2e, 0x86, 0xa5, 0x9e, 0x55, 0xdc, 0x7b, 0x3a,
                   0xfa, 0xb6, 0x20, 0x44, 0x47, 0xb2, 0x1d, 0x1e, 0xf1, 0xda, 0x82, 0x4a, 0xba,
                   0xf3, 0x1a, 0x25, 0xa0, 0xd6, 0x13, 0x5c, 0x4f, 0xe8, 0x1d, 0x34, 0xa0, 0x68,
                   0x16, 0xc8, 0xa6, 0xea, 0xb1, 0x91, 0x41, 0xf5, 0x68, 0x71, 0x08, 0x50, 0x0f,
                   0x37, 0x19, 0xa8, 0x62, 0xaf, 0x8c, 0x5f, 0xee, 0x36, 0xe1, 0x30, 0xc6, 0x99,
                   0x21, 0xe1, 0x1c, 0xe8, 0x3d, 0xfc, 0x72, 0xc5, 0xec, 0x3b, 0x86, 0x2c, 0x1b,
                   0xcc, 0xc5, 0xfd, 0x63, 0xad, 0x57, 0xf4, 0x32, 0xfb, 0xcc, 0xa6, 0xf9, 0xe1,
                   0x8d, 0x5a, 0x59, 0x01, 0x59, 0x50, 0xcd, 0xf0, 0x53],
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
            out:  [0xe9, 0x42, 0x95, 0x1d, 0xfb, 0xc2, 0xd5, 0x08, 0x29, 0x4b, 0x10, 0xf9, 0xe9,
                   0x7b, 0x47, 0xd0, 0xcd, 0x04, 0xe6, 0x68, 0xa0, 0x43, 0xcb, 0x95, 0x67, 0x9c,
                   0xc1, 0x13, 0x9d, 0xf7, 0xc2, 0x7c, 0xd5, 0x43, 0x67, 0x68, 0x87, 0x25, 0xbe,
                   0x9d, 0x06, 0x9f, 0x57, 0x04, 0xc1, 0x22, 0x23, 0xe7, 0xe4, 0xca, 0x18, 0x1f,
                   0xbd, 0x0b, 0xed, 0x18, 0xbb, 0x46, 0x34, 0x79, 0x5e, 0x54, 0x5a, 0x6c, 0x04,
                   0xa7, 0x30, 0x69, 0x33, 0xa4, 0x1a, 0x79, 0x4b, 0xae, 0xdb, 0xb6, 0x28, 0xd4,
                   0x1b, 0xc2, 0x85, 0xe0, 0xb9, 0x08, 0x40, 0x55, 0xae, 0x13, 0x6f, 0x6b, 0x63,
                   0x62, 0x4c, 0x87, 0x4f, 0x5a, 0x1e, 0x1d, 0x8b, 0xe7, 0xb0, 0xb7, 0x22, 0x7a,
                   0x17, 0x1d, 0x2d, 0x7e, 0xd5, 0x78, 0xd8, 0x8b, 0xfd, 0xcf, 0x18, 0x32, 0x31,
                   0x98, 0x96, 0x2d, 0x0d, 0xca, 0xd4, 0x12, 0x6f, 0xd3, 0xf2, 0x1a, 0xde, 0xb1,
                   0xe1, 0x1d, 0x66, 0x25, 0x2e, 0xa0, 0xc5, 0x8c, 0x91, 0x69, 0x6e, 0x91, 0x03,
                   0x1b, 0xfd, 0xcc, 0x2a, 0x9d, 0xc0, 0xe0, 0x28, 0xd1, 0x7b, 0x97, 0x05, 0xba,
                   0x2d, 0x7b, 0xcd, 0xcd, 0x1e, 0x3b, 0xa7, 0x5b, 0x4b, 0x1f, 0xea],
        },
    }

    verify_str_valid_tests! [
        {
            pass: "",
            hash: "$argon2i$v=19$m=4096,t=1,p=1$X1NhbHQAAAAAAAAAAAAAAA$bWh++MKN1OiFHKgIWTLvIi1i\
                   HicmHH7+Fv3K88ifFfI",
        },
        {
            pass: "",
            hash: "$argon2i$v=19$m=2048,t=4,p=1$SWkxaUhpY21ISDcrRnYzSw$Mbg/Eck1kpZir5T9io7C64cp\
                   ffdTBaORgyriLQFgQj8",
        },
        {
            pass: "^T5H$JYt39n%K*j:W]!1s?vg!:jGi]Ax?..l7[p0v:1jHTpla9;]bUN;?bWyCbtqg ",
            hash: "$argon2i$v=19$m=4096,t=3,p=2$X1NhbHQAAAAAAAAAAAAAAA$z/QMiU4lQxGsYNc/+K/bizws\
                   A1P11UG2dj/7+aILJ4I",
        },
        {
            pass: "K3S=KyH#)36_?]LxeR8QNKw6X=gFbxai$C%29V*",
            hash: "$argon2i$v=19$m=4096,t=3,p=1$X1NhbHQAAAAAAAAAAAAAAA$fu2Wsecyt+yPnBvSvYN16oP5\
                   ozRmkp0ixJ1YL19V3Uo",
        },
    ];

    verify_str_invalid_tests! [
        {
            pass: "",
            hash: "",
        },
        {
            pass: "",
            hash: "$argon2i$v=19$m=4096,t=1,p=1$X1NhbHQAAAAAAAAAAAAAAA$bWh++MKN1OiFHKgIWTLvIi1i\
                   HicmHH7+Fv3K88ifFfJ",
        },
        {
            pass: "",
            hash: "$argon2i$v=19$m=2048,t=4,p=1$TWkxaUhpY21ISDcrRnYzSw$Mbg/Eck1kpZir5T9io7C64cp\
                   ffdTBaORgyriLQFgQj8",
        },
        {
            pass: "J3S=KyH#)36_?]LxeR8QNKw6X=gFbxai$C%29V*",
            hash: "$argon2i$v=19$m=4096,t=3,p=1$X1NhbHQAAAAAAAAAAAAAAA$fu2Wsecyt+yPnBvSvYN16oP5\
                   ozRmkp0ixJ1YL19V3Uo",
        },
    ];

    needs_rehash_tests! {}
}
