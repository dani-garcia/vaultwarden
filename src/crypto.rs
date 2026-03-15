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
// Organization key generation for SSO auto-enrollment
//

use data_encoding::BASE64;

pub struct OrgKeys {
    pub public_key: String,
    pub encrypted_private_key: String,
    pub org_sym_key: Vec<u8>,
}

/// Generates organization keys: RSA-2048 keypair + 64-byte symmetric key.
/// Private key is encrypted as a type 2 EncString (AES-CBC-256 + HMAC-SHA256).
pub fn generate_org_keys() -> Result<OrgKeys, crate::error::Error> {
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;
    use openssl::sign::Signer;
    use openssl::symm::{encrypt as aes_encrypt, Cipher};

    let org_sym_key: [u8; 64] = get_random_bytes();
    let enc_key = &org_sym_key[..32];
    let mac_key = &org_sym_key[32..];

    let rsa = Rsa::generate(2048)?;
    let pkey = PKey::from_rsa(rsa)?;
    let pub_key_der = pkey.public_key_to_der()?;
    let public_key = BASE64.encode(&pub_key_der);
    let priv_key_der = pkey.private_key_to_der()?;

    let iv: [u8; 16] = get_random_bytes();
    let ciphertext = aes_encrypt(Cipher::aes_256_cbc(), enc_key, Some(&iv), &priv_key_der)?;

    let hmac_pkey = PKey::hmac(mac_key)?;
    let mut signer = Signer::new(openssl::hash::MessageDigest::sha256(), &hmac_pkey)?;
    signer.update(&iv)?;
    signer.update(&ciphertext)?;
    let mac = signer.sign_to_vec()?;

    let encrypted_private_key =
        format!("2.{}|{}|{}", BASE64.encode(&iv), BASE64.encode(&ciphertext), BASE64.encode(&mac));

    Ok(OrgKeys {
        public_key,
        encrypted_private_key,
        org_sym_key: org_sym_key.to_vec(),
    })
}

/// Encrypts the org symmetric key with a user's RSA public key (type 4 EncString, RSA-OAEP-SHA1).
pub fn encrypt_org_key_for_user(
    org_sym_key: &[u8],
    user_public_key_b64: &str,
) -> Result<String, crate::error::Error> {
    use openssl::encrypt::Encrypter;
    use openssl::pkey::PKey;
    use openssl::rsa::Padding;

    let user_pub_der = BASE64
        .decode(user_public_key_b64.as_bytes())
        .map_err(|e| crate::error::Error::new("Invalid user public key", e.to_string()))?;
    let user_pub = PKey::public_key_from_der(&user_pub_der)?;

    let mut encrypter = Encrypter::new(&user_pub)?;
    encrypter.set_rsa_padding(Padding::PKCS1_OAEP)?;
    encrypter.set_rsa_oaep_md(openssl::hash::MessageDigest::sha1())?;
    encrypter.set_rsa_mgf1_md(openssl::hash::MessageDigest::sha1())?;

    let buffer_len = encrypter.encrypt_len(org_sym_key)?;
    let mut encrypted = vec![0u8; buffer_len];
    let encrypted_len = encrypter.encrypt(org_sym_key, &mut encrypted)?;
    encrypted.truncate(encrypted_len);

    Ok(format!("4.{}", BASE64.encode(&encrypted)))
}

//
// Key Connector encrypted key storage
//
// Keys are encrypted with AES-256-GCM before writing to disk. The encryption
// key is derived via HKDF-SHA256 from SSO_KEY_CONNECTOR_SECRET with a unique
// per-file salt. File format: salt(32) || nonce(12) || ciphertext || tag(16).
//
// The secret never touches disk — it exists only as an env var. For stronger
// guarantees, source the secret from an external KMS at deployment time.
//

use std::path::PathBuf;

fn kc_keys_dir() -> PathBuf {
    PathBuf::from(crate::CONFIG.data_folder()).join("kc_keys")
}

fn org_keys_dir() -> PathBuf {
    PathBuf::from(crate::CONFIG.data_folder()).join("org_keys")
}

fn validate_storage_id(id: &str) -> Result<(), crate::error::Error> {
    if id.is_empty() || id.contains('/') || id.contains('\\') || id.contains("..") {
        return Err(crate::error::Error::new("Invalid storage identifier", ""));
    }
    Ok(())
}

/// Derives a per-key encryption key from the KC secret via HKDF-SHA256.
fn derive_kc_encryption_key(salt: &[u8]) -> Result<[u8; 32], crate::error::Error> {
    use ring::hkdf;

    let secret_hex = crate::CONFIG
        .sso_key_connector_secret()
        .ok_or_else(|| crate::error::Error::new("SSO_KEY_CONNECTOR_SECRET is required", ""))?;
    let secret = HEXLOWER
        .decode(secret_hex.as_bytes())
        .map_err(|e| crate::error::Error::new("Invalid SSO_KEY_CONNECTOR_SECRET", e.to_string()))?;
    if secret.len() != 32 {
        return Err(crate::error::Error::new("SSO_KEY_CONNECTOR_SECRET must be 64 hex chars", ""));
    }

    let hk_salt = hkdf::Salt::new(hkdf::HKDF_SHA256, salt);
    let prk = hk_salt.extract(&secret);
    let okm = prk
        .expand(&[b"vaultwarden-kc-key"], HkdfLen(32))
        .map_err(|_| crate::error::Error::new("HKDF expand failed", ""))?;
    let mut key = [0u8; 32];
    okm.fill(&mut key).map_err(|_| crate::error::Error::new("HKDF fill failed", ""))?;
    Ok(key)
}

// ring::hkdf requires a type implementing Len trait for output length
struct HkdfLen(usize);
impl ring::hkdf::KeyType for HkdfLen {
    fn len(&self) -> usize {
        self.0
    }
}

/// Encrypts data with AES-256-GCM. The `aad` (additional authenticated data) binds
/// the ciphertext to the owner's identity, preventing file-swapping attacks.
/// Returns: salt(32) || nonce(12) || ciphertext || tag(16).
fn encrypt_at_rest(plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, crate::error::Error> {
    use openssl::symm::{encrypt_aead, Cipher};

    let salt: [u8; 32] = get_random_bytes();
    let nonce: [u8; 12] = get_random_bytes();
    let key = derive_kc_encryption_key(&salt)?;

    let mut tag = [0u8; 16];
    let ciphertext = encrypt_aead(Cipher::aes_256_gcm(), &key, Some(&nonce), aad, plaintext, &mut tag)?;

    let mut out = Vec::with_capacity(32 + 12 + ciphertext.len() + 16);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    out.extend_from_slice(&tag);
    Ok(out)
}

fn decrypt_at_rest(data: &[u8], aad: &[u8]) -> Result<Vec<u8>, crate::error::Error> {
    use openssl::symm::{decrypt_aead, Cipher};

    if data.len() < 32 + 12 + 16 {
        return Err(crate::error::Error::new("Encrypted data too short", ""));
    }

    let salt = &data[..32];
    let nonce = &data[32..44];
    let tag = &data[data.len() - 16..];
    let ciphertext = &data[44..data.len() - 16];

    let key = derive_kc_encryption_key(salt)?;
    decrypt_aead(Cipher::aes_256_gcm(), &key, Some(nonce), aad, ciphertext, tag)
        .map_err(|e| crate::error::Error::new("Decryption failed (wrong secret?)", e.to_string()))
}

pub fn save_kc_key(user_uuid: &str, key: &str) -> Result<(), crate::error::Error> {
    validate_storage_id(user_uuid)?;
    let dir = kc_keys_dir();
    std::fs::create_dir_all(&dir)?;
    std::fs::write(dir.join(user_uuid), encrypt_at_rest(key.as_bytes(), user_uuid.as_bytes())?)?;
    Ok(())
}

pub fn load_kc_key(user_uuid: &str) -> Result<String, crate::error::Error> {
    validate_storage_id(user_uuid)?;
    let path = kc_keys_dir().join(user_uuid);
    let encrypted = std::fs::read(&path).map_err(|e| crate::error::Error::new("Key not found", e.to_string()))?;
    let plaintext = decrypt_at_rest(&encrypted, user_uuid.as_bytes())?;
    String::from_utf8(plaintext).map_err(|e| crate::error::Error::new("Invalid key data", e.to_string()))
}

pub fn has_kc_key(user_uuid: &str) -> bool {
    validate_storage_id(user_uuid).is_ok() && kc_keys_dir().join(user_uuid).exists()
}

pub fn save_org_sym_key(org_uuid: &str, key: &[u8]) -> Result<(), crate::error::Error> {
    validate_storage_id(org_uuid)?;
    let dir = org_keys_dir();
    std::fs::create_dir_all(&dir)?;
    std::fs::write(dir.join(org_uuid), encrypt_at_rest(key, org_uuid.as_bytes())?)?;
    Ok(())
}

pub fn load_org_sym_key(org_uuid: &str) -> Result<Vec<u8>, crate::error::Error> {
    validate_storage_id(org_uuid)?;
    let path = org_keys_dir().join(org_uuid);
    let encrypted = std::fs::read(&path).map_err(|e| crate::error::Error::new("Org key not found", e.to_string()))?;
    decrypt_at_rest(&encrypted, org_uuid.as_bytes())
}

#[cfg(test)]
mod kc_tests {
    use super::*;

    #[test]
    fn test_org_key_generation() {
        let keys = generate_org_keys().unwrap();
        assert!(!keys.public_key.is_empty());
        assert!(keys.encrypted_private_key.starts_with("2."));
        assert_eq!(keys.org_sym_key.len(), 64);
    }

    #[test]
    fn test_org_key_encrypt_for_user() {
        // Generate an org key and a user keypair, verify encryption produces type 4 EncString
        let org_keys = generate_org_keys().unwrap();

        use openssl::rsa::Rsa;
        use openssl::pkey::PKey;
        let rsa = Rsa::generate(2048).unwrap();
        let pkey = PKey::from_rsa(rsa).unwrap();
        let pub_der = pkey.public_key_to_der().unwrap();
        let pub_b64 = BASE64.encode(&pub_der);

        let akey = encrypt_org_key_for_user(&org_keys.org_sym_key, &pub_b64).unwrap();
        assert!(akey.starts_with("4."));

        // Verify we can decrypt it back
        use openssl::encrypt::Decrypter;
        use openssl::rsa::Padding;
        let encrypted_b64 = &akey[2..];
        let encrypted = BASE64.decode(encrypted_b64.as_bytes()).unwrap();
        let mut decrypter = Decrypter::new(&pkey).unwrap();
        decrypter.set_rsa_padding(Padding::PKCS1_OAEP).unwrap();
        decrypter.set_rsa_oaep_md(openssl::hash::MessageDigest::sha1()).unwrap();
        decrypter.set_rsa_mgf1_md(openssl::hash::MessageDigest::sha1()).unwrap();
        let buf_len = decrypter.decrypt_len(&encrypted).unwrap();
        let mut decrypted = vec![0u8; buf_len];
        let len = decrypter.decrypt(&encrypted, &mut decrypted).unwrap();
        decrypted.truncate(len);
        assert_eq!(decrypted, org_keys.org_sym_key);
    }
}
