# Changelog

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