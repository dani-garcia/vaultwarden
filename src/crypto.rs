//
// PBKDF2 derivation
//

use ring::{digest, hmac, pbkdf2};

static DIGEST_ALG: &digest::Algorithm = &digest::SHA256;
const OUTPUT_LEN: usize = digest::SHA256_OUTPUT_LEN;

pub fn hash_password(secret: &[u8], salt: &[u8], iterations: u32) -> Vec<u8> {
    let mut out = vec![0u8; OUTPUT_LEN]; // Initialize array with zeros

    pbkdf2::derive(DIGEST_ALG, iterations, salt, secret, &mut out);

    out
}

pub fn verify_password_hash(secret: &[u8], salt: &[u8], previous: &[u8], iterations: u32) -> bool {
    pbkdf2::verify(DIGEST_ALG, iterations, salt, secret, previous).is_ok()
}

//
// HMAC
//
pub fn hmac_sign(key: &str, data: &str) -> String {
    use data_encoding::HEXLOWER;

    let key = hmac::SigningKey::new(&digest::SHA1, key.as_bytes());
    let signature = hmac::sign(&key, data.as_bytes());

    HEXLOWER.encode(signature.as_ref())
}

//
// Random values
//

pub fn get_random_64() -> Vec<u8> {
    get_random(vec![0u8; 64])
}

pub fn get_random(mut array: Vec<u8>) -> Vec<u8> {
    use ring::rand::{SecureRandom, SystemRandom};

    SystemRandom::new()
        .fill(&mut array)
        .expect("Error generating random values");

    array
}

//
// Constant time compare
//
pub fn ct_eq<T: AsRef<[u8]>, U: AsRef<[u8]>>(a: T, b: U) -> bool {
    use ring::constant_time::verify_slices_are_equal;

    verify_slices_are_equal(a.as_ref(), b.as_ref()).is_ok()
}
