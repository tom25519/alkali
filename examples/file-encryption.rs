//! Minimal symmetric file encryption example, using the [`symmetric::cipher_stream`
//! API](https://docs.rs/alkali/latest/alkali/symmetric/cipher_stream/index.html). This was
//! inspired by the [similar
//! example](https://doc.libsodium.org/secret-key_cryptography/secretstream#file-encryption-example-code)
//! from the Sodium documentation.
//!
//! This is only intended as an example to demonstrate usage of this library, and has not received
//! any independent review for security. It lacks many basic sanity checks, as well as any error
//! handling. **Please don't use this to encrypt your actual files!** Much better, more carefully
//! designed utilities already exist for this purpose :)
//!
//! ## Example usage:
//!
//! If you wish to encrypt "foo.txt", writing the result to "bar.enc", you would run the following:
//!
//! ```bash
//! cargo run --release --example file-encryption encrypt foo.txt bar.enc
//! ```
//!
//! And to decrypt "bar.enc", writing the result to "baz.txt", you would run the following:
//!
//! ```bash
//! cargo run --release --example file-encryption decrypt bar.enc baz.txt
//! ```

use alkali::hash::pbkdf;
use alkali::mem;
use alkali::symmetric::cipher_stream;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

const CHUNK_SIZE: usize = 4096;

/// Uses a Password-Based Key Derivation Function to derive an encryption key from the provided
/// password.
fn derive_key_from_password(
    password: &[u8],
    salt: &pbkdf::Salt,
) -> cipher_stream::Key<mem::FullAccess> {
    let mut key = cipher_stream::Key::new_empty().unwrap();

    println!("Deriving key...");
    pbkdf::derive_key(
        password,
        &salt,
        pbkdf::OPS_LIMIT_SENSITIVE,
        pbkdf::MEM_LIMIT_SENSITIVE,
        &mut key[..],
    )
    .unwrap();

    key
}

/// Encrypts `source`, writing the result to `dest`, using `password` to derive the encryption key.
fn encrypt_file<S, D>(source: &S, dest: &D, password: &[u8])
where
    S: AsRef<Path>,
    D: AsRef<Path>,
{
    let mut source = File::open(source).unwrap();
    let mut dest = File::options().write(true).create(true).open(dest).unwrap();

    // Derive an encryption key with a random salt
    let salt = pbkdf::generate_salt().unwrap();
    let key = derive_key_from_password(&password, &salt);

    // Prefix the output with the salt, so it can be used to derive the same key when decrypting
    dest.write_all(&salt).unwrap();

    let mut stream = cipher_stream::EncryptionStream::new(&key).unwrap();

    // Write the stream header to the file
    let header = stream.get_header();
    dest.write_all(&header).unwrap();

    // Read the file in chunks, and encrypt
    let mut buf_read = [0; CHUNK_SIZE];
    let mut buf_write = [0; CHUNK_SIZE + cipher_stream::OVERHEAD_LENGTH];
    'outer: loop {
        let mut read = 0;

        while read < CHUNK_SIZE {
            let current_read = source.read(&mut buf_read[read..]).unwrap();

            // Detect end of file, write final chunk
            if current_read == 0 {
                let to_write = stream
                    .finalise(&buf_read[..read], None, &mut buf_write)
                    .unwrap();
                dest.write_all(&buf_write[..to_write]).unwrap();
                break 'outer;
            }

            read += current_read;
        }

        stream.encrypt(&buf_read, None, &mut buf_write).unwrap();
        dest.write_all(&buf_write).unwrap();
    }

    // Clear the input buffer, which still contains plaintext
    alkali::mem::clear(&mut buf_read).unwrap();
}

/// Decrypts `source`, writing the result to `dest`, using `password` to derive the decryption key.
fn decrypt_file<S, D>(source: &S, dest: &D, password: &[u8])
where
    S: AsRef<Path>,
    D: AsRef<Path>,
{
    let mut source = File::open(source).unwrap();
    let mut dest = File::options().write(true).create(true).open(dest).unwrap();

    // Read the salt from the input
    let mut salt = [0; pbkdf::SALT_LENGTH];
    source.read_exact(&mut salt).unwrap();

    // Derive the decryption key from the password using the salt
    let key = derive_key_from_password(&password, &salt);

    // Read the header from the input
    let mut header = [0; cipher_stream::HEADER_LENGTH];
    source.read_exact(&mut header).unwrap();

    let mut stream = cipher_stream::DecryptionStream::new(&key, &header).unwrap();

    // Read the file in chunks, and decrypt
    let mut buf_read = [0; CHUNK_SIZE + cipher_stream::OVERHEAD_LENGTH];
    let mut buf_write = [0; CHUNK_SIZE];
    'outer: loop {
        let mut read = 0;

        while read < CHUNK_SIZE + cipher_stream::OVERHEAD_LENGTH {
            let current_read = source.read(&mut buf_read[read..]).unwrap();

            // Detect end of file, write final chunk
            if current_read == 0 {
                let (tag, to_write) = stream
                    .decrypt(&buf_read[..read], None, &mut buf_write)
                    .unwrap();

                if tag != cipher_stream::MessageType::Final {
                    panic!("End of file reached before the end of the stream!");
                }

                dest.write_all(&buf_write[..to_write]).unwrap();
                break 'outer;
            }

            read += current_read;
        }

        stream.decrypt(&buf_read, None, &mut buf_write).unwrap();
        dest.write_all(&buf_write).unwrap();
    }

    // Clear the output buffer, which still contains plaintext
    alkali::mem::clear(&mut buf_write).unwrap();
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        eprintln!("Usage: file-encryption mode source-file output-file");
        eprintln!("mode can be encrypt or decrypt");
        return;
    }

    // Ask the user to input a password for encryption
    let mut password = rpassword::read_password_from_tty(Some("Password: "))
        .unwrap()
        .into_bytes();

    match args[1].as_str() {
        "encrypt" => encrypt_file(&args[2], &args[3], &password),
        "decrypt" => decrypt_file(&args[2], &args[3], &password),
        _ => panic!("Unrecognised mode"),
    }

    // Clear the password from memory
    alkali::mem::clear(&mut password).unwrap();
}
