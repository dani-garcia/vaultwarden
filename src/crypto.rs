//
// PBKDF2 derivation
//
use std::num::NonZeroU32;

use data_encoding::{Encoding, HEXLOWER};
use ring::{digest, hmac, pbkdf2};

const DIGEST_ALG: pbkdf2::Algorithm = pbkdf2::PBKDF2_HMAC_SHA256;
const OUTPUT_LEN: usize = digest::SHA256_OUTPUT_LEN;

use rsa::{RsaPublicKey, Oaep};
use rsa::pkcs8::DecodePublicKey;
use sha1::Sha1;
use base64::{Engine as _, engine::general_purpose::STANDARD};

pub fn hash_password(secret: &[u8], salt: &[u8], iterations: u32) -> Vec<u8> {
    let mut out = vec![0u8; OUTPUT_LEN]; // Initialize array with zeros

    let iterations = NonZeroU32::new(iterations).expect("Iterations can't be zero");
    pbkdf2::derive(DIGEST_ALG, iterations, salt, secret, &mut out);

    out
}

pub fn verify_password_hash(secret: &[u8], salt: &[u8], previous: &[u8], iterations: u32) -> bool {
    let iterations = NonZeroU32::new(iterations).expect("Iterations can't be zero");
    pbkdf2::verify(DIGEST_ALG, iterations, salt, secret, previous).is_ok()
}

//
// HMAC
//
pub fn hmac_sign(key: &str, data: &str) -> String {
    let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, key.as_bytes());
    let signature = hmac::sign(&key, data.as_bytes());

    HEXLOWER.encode(signature.as_ref())
}

//
// Random values
//

/// Return an array holding `N` random bytes.
pub fn get_random_bytes<const N: usize>() -> [u8; N] {
    use ring::rand::{SecureRandom, SystemRandom};

    let mut array = [0; N];
    SystemRandom::new().fill(&mut array).expect("Error generating random values");

    array
}

/// Encode random bytes using the provided function.
pub fn encode_random_bytes<const N: usize>(e: Encoding) -> String {
    e.encode(&get_random_bytes::<N>())
}

/// Generates a random string over a specified alphabet.
pub fn get_random_string(alphabet: &[u8], num_chars: usize) -> String {
    // Ref: https://rust-lang-nursery.github.io/rust-cookbook/algorithms/randomness.html
    use rand::Rng;
    let mut rng = rand::rng();

    (0..num_chars)
        .map(|_| {
            let i = rng.random_range(0..alphabet.len());
            alphabet[i] as char
        })
        .collect()
}

/// Generates a random numeric string.
pub fn get_random_string_numeric(num_chars: usize) -> String {
    const ALPHABET: &[u8] = b"0123456789";
    get_random_string(ALPHABET, num_chars)
}

/// Generates a random alphanumeric string.
pub fn get_random_string_alphanum(num_chars: usize) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                              abcdefghijklmnopqrstuvwxyz\
                              0123456789";
    get_random_string(ALPHABET, num_chars)
}

pub fn generate_id<const N: usize>() -> String {
    encode_random_bytes::<N>(HEXLOWER)
}

pub fn generate_send_file_id() -> String {
    // Send File IDs are globally scoped, so make them longer to avoid collisions.
    generate_id::<32>() // 256 bits
}

use crate::db::models::AttachmentId;
pub fn generate_attachment_id() -> AttachmentId {
    // Attachment IDs are scoped to a cipher, so they can be smaller.
    AttachmentId(generate_id::<10>()) // 80 bits
}

/// Generates a numeric token for email-based verifications.
pub fn generate_email_token(token_size: u8) -> String {
    get_random_string_numeric(token_size as usize)
}

/// Generates a personal API key.
/// Upstream uses 30 chars, which is ~178 bits of entropy.
pub fn generate_api_key() -> String {
    get_random_string_alphanum(30)
}

//
// Constant time compare
//
pub fn ct_eq<T: AsRef<[u8]>, U: AsRef<[u8]>>(a: T, b: U) -> bool {
    use subtle::ConstantTimeEq;
    a.as_ref().ct_eq(b.as_ref()).into()
}

pub fn generate_akey_from_hex(org_key_hex: &str, user_public_key_pem: &str) -> String {
    // Convert hex → raw bytes
    let org_key_bytes = hex::decode(org_key_hex)
        .expect("Invalid hex for org key");

    // Parse PEM public key - add headers if missing and format properly
    let formatted_pem = if user_public_key_pem.starts_with("-----BEGIN") {
        user_public_key_pem.to_string()
    } else {
        // Split base64 content into 64-character lines for proper PEM format
        let base64_lines: Vec<String> = user_public_key_pem
            .chars()
            .collect::<Vec<char>>()
            .chunks(64)
            .map(|chunk| chunk.iter().collect())
            .collect();
        
        format!("-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----", 
                base64_lines.join("\n"))
    };

    println!("formatted_pem: {:?}", formatted_pem);

    let public_key = RsaPublicKey::from_public_key_pem(&formatted_pem)
        .expect("Invalid public key PEM");

    // Encrypt with RSA-OAEP using SHA1 (Vaultwarden convention for version 4)
    let padding = Oaep::new::<Sha1>();
    let mut rng = rsa::rand_core::OsRng;
    let encrypted = public_key.encrypt(&mut rng, padding, &org_key_bytes)
        .expect("Encryption failed");

    // Base64 encode and prefix with version "4."
    format!("4.{}", STANDARD.encode(encrypted))
}