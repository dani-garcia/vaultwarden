//
// PBKDF2 derivation
//
use std::num::NonZeroU32;

use data_encoding::{Encoding, HEXLOWER};
use ring::{digest, hmac, pbkdf2};

const DIGEST_ALG: pbkdf2::Algorithm = pbkdf2::PBKDF2_HMAC_SHA256;
const OUTPUT_LEN: usize = digest::SHA256_OUTPUT_LEN;

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
pub fn encode_random_bytes<const N: usize>(e: &Encoding) -> String {
    e.encode(&get_random_bytes::<N>())
}

/// Generates a random string over a specified alphabet.
pub fn get_random_string(alphabet: &[u8], num_chars: usize) -> String {
    // Ref: https://rust-lang-nursery.github.io/rust-cookbook/algorithms/randomness.html
    use rand::RngExt;
    let mut rng = rand::rng();

    (0..num_chars)
        .map(|_| {
            let i = rng.random_range(0..alphabet.len());
            char::from(alphabet[i])
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
    encode_random_bytes::<N>(&HEXLOWER)
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

//
// SHA256
//
pub fn sha256_hex(data: &[u8]) -> String {
    HEXLOWER.encode(digest::digest(&digest::SHA256, data).as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(data: &[u8]) -> String {
        HEXLOWER.encode(data)
    }

    #[test]
    fn hash_password_known_vectors() {
        // PBKDF2-HMAC-SHA256 test vectors from RFC 7914, section 11.
        // `hash_password` always derives a SHA256-sized (32-byte) key, which equals
        // the first half of the 64-byte output in the vectors.
        assert_eq!(
            hex(&hash_password(b"passwd", b"salt", 1)),
            "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc"
        );
        assert_eq!(
            hex(&hash_password(b"Password", b"NaCl", 80000)),
            "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56"
        );
        // The output is always a SHA256-sized digest, independent of the input length
        assert_eq!(hash_password(b"password", b"salt", 1).len(), 32);
    }

    #[test]
    fn verify_password_hash_round_trips() {
        let hash = hash_password(b"correct horse battery staple", b"NaCl", 128);

        assert!(verify_password_hash(b"correct horse battery staple", b"NaCl", &hash, 128));
        assert!(!verify_password_hash(b"Tr0ub4dor&3", b"NaCl", &hash, 128));
        assert!(!verify_password_hash(b"correct horse battery staple", b"Pepper", &hash, 128));
        assert!(!verify_password_hash(b"correct horse battery staple", b"NaCl", &hash, 129));
    }

    #[test]
    fn hmac_sign_known_vectors() {
        // HMAC-SHA1 test vectors from RFC 2202
        let key = "\u{0b}".repeat(20);
        assert_eq!(hmac_sign(&key, "Hi There"), "b617318655057264e28bc0b6fb378c8ef146be00");
        assert_eq!(hmac_sign("Jefe", "what do ya want for nothing?"), "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79");
        assert_ne!(
            hmac_sign("Jefe", "what do ya want for nothing?"),
            hmac_sign("Jefe", "what do ya want for something?")
        );
    }

    #[test]
    fn sha256_hex_known_vectors() {
        assert_eq!(sha256_hex(b"abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert_eq!(sha256_hex(b""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }

    #[test]
    fn ct_eq_compares_correctly() {
        assert!(ct_eq("letmein", "letmein"));
        assert!(ct_eq("", ""));
        assert!(ct_eq(b"bin\x00ary".as_slice(), b"bin\x00ary".as_slice()));
        assert!(!ct_eq("letmein", "letmeout"));
        // Length mismatches never compare equal
        assert!(!ct_eq("letmein", "letmein2"));
        assert!(!ct_eq("letmein2", "letmein"));
    }

    #[test]
    fn get_random_string_uses_alphabet_exactly() {
        assert_eq!(get_random_string(b"a", 40), "a".repeat(40));

        let s = get_random_string(b"ab", 64);
        assert_eq!(s.len(), 64);
        assert!(s.bytes().all(|b| b == b'a' || b == b'b'));
    }

    #[test]
    fn get_random_string_numeric_and_alphanum_charsets() {
        let numeric = get_random_string_numeric(10);
        assert_eq!(numeric.len(), 10);
        assert!(numeric.chars().all(|c| c.is_ascii_digit()));
        assert_eq!(get_random_string_numeric(0), "");

        let alphanum = get_random_string_alphanum(32);
        assert_eq!(alphanum.len(), 32);
        assert!(alphanum.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn random_values_vary_between_calls() {
        assert_ne!(get_random_bytes::<32>(), [0u8; 32]);
        assert_ne!(get_random_bytes::<32>(), get_random_bytes::<32>());
        assert_ne!(generate_id::<16>(), generate_id::<16>());
        assert_ne!(get_random_string_alphanum(64), get_random_string_alphanum(64));
    }

    #[test]
    fn encode_random_bytes_uses_encoding() {
        let s = encode_random_bytes::<15>(&data_encoding::BASE64);
        assert_eq!(s.len(), 20);
        assert!(s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/'));
    }

    #[test]
    fn generate_ids_have_expected_length_and_charset() {
        let id = generate_id::<10>();
        assert_eq!(id.len(), 20);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));

        // Send file IDs are globally scoped: 256 bits
        assert_eq!(generate_send_file_id().len(), 64);
        assert!(generate_send_file_id().chars().all(|c| c.is_ascii_hexdigit()));

        // Attachment IDs are scoped to a cipher: 80 bits
        let AttachmentId(attachment_id) = generate_attachment_id();
        assert_eq!(attachment_id.len(), 20);
        assert!(attachment_id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn tokens_and_api_keys_have_expected_length_and_charset() {
        let token = generate_email_token(6);
        assert_eq!(token.len(), 6);
        assert!(token.chars().all(|c| c.is_ascii_digit()));

        let api_key = generate_api_key();
        assert_eq!(api_key.len(), 30);
        assert!(api_key.chars().all(|c| c.is_ascii_alphanumeric()));
    }
}
