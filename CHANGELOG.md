# Changelog

## 0.3.0 (2023-03-11)
* Typed support for protecting hardened buffers via the `sodium_mprotect` API
  * The `alkali::mem` module now includes a number of marker types and traits to indicate the protection status of a
    hardened buffer
  * Hardened buffers now have an extra generic parameter `Mprotect`, which implements `alkali::mem::MprotectStatus`,
    indicating the protection status of the buffer (`alkali::mem::FullAccess`, `alkali::mem::ReadOnly`, or
    `alkali::mem::NoAccess`)
  * The `alkali::mem::ProtectReadOnly`, `alkali::mem::ProtectNoAccess`, and `alkali::mem::Unprotect` traits have been
    added, which can be used to protect or unprotect a hardened buffer
  * The `alkali::mem::MprotectReadable` trait has been added, which is implemented by `alkali::mem::FullAccess` and
    `alkali::mem::ReadOnly`, to indicate that a hardened buffer can be read from
* The `serde::Deserialize` implementation for `alkali::curve::ristretto255::Point` now raises an error if the point is
  not on the curve
* **Breaking API changes**:
  * Every hardened buffer type now has an extra generic parameter `Mprotect`, which implements
    `alkali::mem::MprotectStatus`. The `new_empty` and `zero` methods are now only implemented for `Buffer<FullAccess>`.
    The `try_clone` method is now only implemented for `Buffer<impl MprotectReadable>`. Trait implementations have also
    changed.
    * Affected types:
      * `alkali::asymmetric::cipher::Keypair`, `alkali::asymmetric::cipher::PrivateKey`,
        `alkali::asymmetric::cipher::Seed`, `alkali::asymmetric::cipher::SessionKey`
      * `alkali::asymmetric::kx::Keypair`, `alkali::asymmetric::kx::PrivateKey`, `alkali::asymmetric::kx::ReceiveKey`,
        `alkali::asymmetric::kx::Seed`, `alkali::asymmetric::kx::TransmitKey`
      * `alkali::asymmetric::seal::Keypair`, `alkali::asymmetric::seal::PrivateKey`, alkali::asymmetric::seal::Seed`
      * `alkali::asymmetric::sign::Keypair`, `alkali::asymmetric::sign::PrivateKey`, `alkali::asymmetric::sign::Seed`
      * `alkali::curve::curve25519::Scalar`
      * `alkali::curve::ed25519::Scalar`, `alkali::curve::ed25519::UnreducedScalar`
      * `alkali::curve::ristretto255::Scalar`, `alkali::curve::ristretto255::UnreducedScalar`
      * `alkali::hash::generic::Key`
      * `alkali::hash::kdf::Key`
      * `alkali::hash::short::Key`
      * `alkali::random::Seed`
      * `alkali::symmetric::aead::aes256gcm::Key`, `alkali::symmetric::aead::chacha20poly1305::Key`,
        `alkali::symmetric::aead::chacha20poly1305_ietf::Key`, `alkali::symmetric::aead::xchacha20poly1305_ietf::Key`
      * `alkali::symmetric::auth::Key`
      * `alkali::symmetric::cipher::Key`
      * `alkali::symmetric::cipher_stream::Key`
      * `alkali::symmetric::one_time_auth::Key`
      * `alkali::symmetric::stream::chacha20::Key`, `alkali::symmetric::stream::chacha20_ietf::Key`,
        `alkali::symmetric::stream::salsa20::Key`, `alkali::symmetric::stream::salsa208::Key`,
        `alkali::symmetric::stream::salsa2012::Key`, `alkali::symmetric::stream::xchacha20::Key`,
        `alkali::symmetric::stream::xsalsa20::Key`
    * Affected methods/functions:
      * Too many to list: Any method or function making use of the above types has been affected

## 0.2.0 (2023-02-14)
* Improved type safety for `kdf::derive_key` (Thank you @iazel!)
* Removed a number of potential panics (Thank you @iazel!)
* Implemented `Send` & `Sync` for hardened buffer types (Thank you @iazel!)
* Improved Serde support
* **Breaking API changes**:
  * The `serde` feature, enabling serde support, has been renamed to `use-serde`. This feature is still enabled by
    default.
  * `alkali::hash::kdf::derive_key`: The type of the `context` parameter for this function has been changed from `&str`
    to `&[u8; CONTEXT_LENGTH]`.
  * `alkali::hash::kdf::KDFError`: The `ContextLengthIncorrect` variant of this enum has been removed, and a new variant
    `ContextInvalid` has been added.
  * `alkali::asymmetric::sign::Signature`: This has been changed from a type alias to a `[u8; SIGNATURE_LENGTH]` to a
    `struct` with a single field of type `[u8; SIGNATURE_LENGTH]`.
  * `alkali::curve::ristretto255::Hash`: This has been changed from a type alias to a `[u8; HASH_LENGTH]` to a `struct`
    with a single field of type `[u8; HASH_LENGTH]`.
  * `alkali::hash::sha2::Digest`: This has been changed from a type alias to a `[u8; DIGEST_LENGTH]` to a `struct` with
    a single field of type `[u8; DIGEST_LENGTH]`.
  * `alkali::symmetric::auth::Tag`: This has been changed from a type alias to a `[u8; TAG_LENGTH]` to a `struct` with a
    single field of type `[u8; TAG_LENGTH]`.

## 0.1.0 (2022-05-13)
* Initial release
