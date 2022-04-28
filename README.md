# alkali
[![crates.io](https://img.shields.io/crates/v/alkali.svg)](https://crates.io/crates/alkali)
[![docs.rs](https://docs.rs/alkali/badge.svg)](https://docs.rs/alkali)
[![CI status](https://github.com/tom25519/alkali/actions/workflows/tests.yml/badge.svg?event=push)](https://github.com/tom25519/alkali/actions)

**Please note**: This is currently a work-in-progress, and isn't yet complete,
nor is it suitable for production usage.

Safe, idiomatic Rust bindings to the [Sodium](https://libsodium.org)
cryptographic library.

Sodium is a fast, modern cryptographic library written in C. This crate intends
to provide a higher-level API for making use of the constructs Sodium provides.
These constructs include simple-to-use symmetric and asymmetric authenticated
encryption, signatures, hashing, password derivation, and key exchange: In
short, the majority of operations required for most modern cryptographic
protocols.

The intention for this library is to be a spiritual successor to
[sodiumoxide](https://github.com/sodiumoxide/sodiumoxide), which is now
deprecated. Lots of design decisions here were inspired by this library, so
thanks to all of its contributors!

## Usage/Documentation
Comprehensive documentation for this library is available [on
docs.rs](https://docs.rs/alkali). The intention is for the entire library to be
well documented, with illustrative examples and information on security
concerns.

## Security/Vulnerability Disclosures
If you find a vulnerability in alkali, please immediately contact
`tom25519@pm.me` with details.

My [age](https://github.com/FiloSottile/age) public key (preferred) is:

```text
age1gglesedq4m2z9kc7urjhq3zlpc6qewcwpcna7s0lwh8k2c4e6fxqf3kdvq
```

## License
Licensed under either of:

 * Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
   http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or
   http://opensource.org/licenses/MIT)

at your option.

## Contribution
Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
