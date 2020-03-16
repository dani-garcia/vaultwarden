//
// PBKDF2 derivation
//

use crate::error::Error;
use ring::{digest, hmac, pbkdf2};
use std::num::NonZeroU32;

static DIGEST_ALG: pbkdf2::Algorithm = pbkdf2::PBKDF2_HMAC_SHA256;
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
    use data_encoding::HEXLOWER;

    let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, key.as_bytes());
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

pub fn generate_token(token_size: u32) -> Result<String, Error> {
    if token_size > 19 {
        err!("Generating token failed")
    }

    // 8 bytes to create an u64 for up to 19 token digits
    let bytes = get_random(vec![0; 8]);
    let mut bytes_array = [0u8; 8];
    bytes_array.copy_from_slice(&bytes);

    let number = u64::from_be_bytes(bytes_array) % 10u64.pow(token_size);
    let token = format!("{:0size$}", number, size = token_size as usize);
    Ok(token)
}

//
// Constant time compare
//
pub fn ct_eq<T: AsRef<[u8]>, U: AsRef<[u8]>>(a: T, b: U) -> bool {
    use ring::constant_time::verify_slices_are_equal;

    verify_slices_are_equal(a.as_ref(), b.as_ref()).is_ok()
}
