use std::sync::Arc;

use base64;
use ring::{rand, digest, hmac, signature};
use ring::constant_time::verify_slices_are_equal;
use untrusted;

use errors::{Result, ErrorKind};


/// The algorithms supported for signing/verifying
#[derive(Debug, PartialEq, Copy, Clone, Serialize, Deserialize)]
pub enum Algorithm {
    /// HMAC using SHA-256
    HS256,
    /// HMAC using SHA-384
    HS384,
    /// HMAC using SHA-512
    HS512,

    /// RSASSA-PKCS1-v1_5 using SHA-256
    RS256,
    /// RSASSA-PKCS1-v1_5 using SHA-384
    RS384,
    /// RSASSA-PKCS1-v1_5 using SHA-512
    RS512,
}

/// The actual HS signing + encoding
fn sign_hmac(alg: &'static digest::Algorithm, key: &[u8], signing_input: &str) -> Result<String> {
    let signing_key = hmac::SigningKey::new(alg, key);
    let digest = hmac::sign(&signing_key, signing_input.as_bytes());

    Ok(
        base64::encode_config::<hmac::Signature>(&digest, base64::URL_SAFE_NO_PAD)
    )
}

/// The actual RSA signing + encoding
/// Taken from Ring doc https://briansmith.org/rustdoc/ring/signature/index.html
fn sign_rsa(alg: Algorithm, key: &[u8], signing_input: &str) -> Result<String> {
    let ring_alg = match alg {
        Algorithm::RS256 => &signature::RSA_PKCS1_SHA256,
        Algorithm::RS384 => &signature::RSA_PKCS1_SHA384,
        Algorithm::RS512 => &signature::RSA_PKCS1_SHA512,
        _ => unreachable!(),
    };

    let key_pair = Arc::new(
        signature::RSAKeyPair::from_der(untrusted::Input::from(key))
            .map_err(|_| ErrorKind::InvalidKey)?
    );
    let mut signing_state = signature::RSASigningState::new(key_pair)
        .map_err(|_| ErrorKind::InvalidKey)?;
    let mut signature = vec![0; signing_state.key_pair().public_modulus_len()];
    let rng = rand::SystemRandom::new();
    signing_state.sign(ring_alg, &rng, signing_input.as_bytes(), &mut signature)
        .map_err(|_| ErrorKind::InvalidKey)?;

    Ok(
        base64::encode_config::<[u8]>(&signature, base64::URL_SAFE_NO_PAD)
    )
}

/// Take the payload of a JWT, sign it using the algorithm given and return
/// the base64 url safe encoded of the result.
///
/// Only use this function if you want to do something other than JWT.
pub fn sign(signing_input: &str, key: &[u8], algorithm: Algorithm) -> Result<String> {
    match algorithm {
        Algorithm::HS256 => sign_hmac(&digest::SHA256, key, signing_input),
        Algorithm::HS384 => sign_hmac(&digest::SHA384, key, signing_input),
        Algorithm::HS512 => sign_hmac(&digest::SHA512, key, signing_input),

        Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512 => sign_rsa(algorithm, key, signing_input),
//        TODO: if PKCS1 is made prublic, remove the line above and uncomment below
//        Algorithm::RS256 => sign_rsa(&signature::RSA_PKCS1_SHA256, key, signing_input),
//        Algorithm::RS384 => sign_rsa(&signature::RSA_PKCS1_SHA384, key, signing_input),
//        Algorithm::RS512 => sign_rsa(&signature::RSA_PKCS1_SHA512, key, signing_input),
    }
}

/// See Ring RSA docs for more details
fn verify_rsa(alg: &signature::RSAParameters, signature: &str, signing_input: &str, key: &[u8]) -> Result<bool> {
    let signature_bytes = base64::decode_config(signature, base64::URL_SAFE_NO_PAD)?;
    let public_key_der = untrusted::Input::from(key);
    let message = untrusted::Input::from(signing_input.as_bytes());
    let expected_signature = untrusted::Input::from(signature_bytes.as_slice());

    let res = signature::verify(alg, public_key_der, message, expected_signature);

    Ok(res.is_ok())
}

/// Compares the signature given with a re-computed signature for HMAC or using the public key
/// for RSA.
///
/// Only use this function if you want to do something other than JWT.
///
/// `signature` is the signature part of a jwt (text after the second '.')
///
/// `signing_input` is base64(header) + "." + base64(claims)
pub fn verify(signature: &str, signing_input: &str, key: &[u8], algorithm: Algorithm) -> Result<bool> {
    match algorithm {
        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
            // we just re-sign the data with the key and compare if they are equal
            let signed = sign(signing_input, key, algorithm)?;
            Ok(verify_slices_are_equal(signature.as_ref(), signed.as_ref()).is_ok())
        },
        Algorithm::RS256 => verify_rsa(&signature::RSA_PKCS1_2048_8192_SHA256, signature, signing_input, key),
        Algorithm::RS384 => verify_rsa(&signature::RSA_PKCS1_2048_8192_SHA384, signature, signing_input, key),
        Algorithm::RS512 => verify_rsa(&signature::RSA_PKCS1_2048_8192_SHA512, signature, signing_input, key),
    }
}

impl Default for Algorithm {
    fn default() -> Self {
        Algorithm::HS256
    }
}
