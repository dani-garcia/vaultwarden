use data_encoding::BASE32;

use crate::api::EmptyResult;

pub fn validate_totp_code_str(totp_code: &str, secret: &str) -> EmptyResult {
    let totp_code: u64 = match totp_code.parse() {
        Ok(code) => code,
        _ => err!("TOTP code is not a number"),
    };

    validate_totp_code(totp_code, secret)
}

pub fn validate_totp_code(totp_code: u64, secret: &str) -> EmptyResult {
    validate_totp_code_with_time_step(totp_code, &secret, 30)
}

pub fn validate_totp_code_with_time_step(totp_code: u64, secret: &str, time_step: u64) -> EmptyResult {
    use oath::{totp_raw_now, HashType};

    let decoded_secret = match BASE32.decode(secret.as_bytes()) {
        Ok(s) => s,
        Err(_) => err!("Invalid TOTP secret"),
    };

    let generated = totp_raw_now(&decoded_secret, 6, 0, time_step, &HashType::SHA1);
    if generated != totp_code {
        err!("Invalid TOTP code");
    }

    Ok(())
}

pub fn validate_decode_key(key: &str) -> Result<Vec<u8>, crate::error::Error> {
    // Validate key as base32 and 20 bytes length
    let decoded_key: Vec<u8> = match BASE32.decode(key.as_bytes()) {
        Ok(decoded) => decoded,
        _ => err!("Invalid totp secret"),
    };

    if decoded_key.len() != 20 {
        err!("Invalid key length")
    }

    Ok(decoded_key)
}