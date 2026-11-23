//! A seeder API for the end-to-end tests, only in builds with the `unsafe_test_mode` feature: it creates accounts with
//! no checks at all, so it must never be in a release or a deployment.
//!
//! It answers the calls the SDK's live tests make to upstream's `util/SeederApi` (`POST /seed` with a scene,
//! `DELETE /seed/{playId}`), under `/test/seeder`. Each request needs HTTP basic auth with `TEST_SEEDER_USERNAME` and
//! `TEST_SEEDER_PASSWORD` from the environment; without both, every route answers 404. Seeding needs an `X-Play-Id`
//! header, and destroying a play deletes the accounts seeded under it. Plays are kept in memory, which is enough for a
//! test server that starts on an empty database.
//!
//! Scenes:
//! - `SingleUserScene`: a V1 account for an email and password, under a mangled address like upstream's, with
//!   PBKDF2 at upstream's default of 5000 iterations.
//! - `TestVectorUserScene`: one of the SDK's user test vectors (`test-vectors/users/*.json`), stored as it is: the
//!   account and its vault are already encrypted. Unlike upstream, the address isn't mangled, since our master
//!   password salt is the email, so a vector can be seeded once at a time. Text Sends are stored too.
//!
//! Ref: <https://github.com/bitwarden/server/blob/15c94ac58bf361a162381749c146d254a21b2098/util/SeederApi/Controllers/SeedController.cs#L11-L107>
//! Ref: <https://github.com/bitwarden/server/blob/15c94ac58bf361a162381749c146d254a21b2098/util/Seeder/Scenes/SingleUserScene.cs#L38-L154>

use std::{
    collections::HashMap,
    num::NonZeroU32,
    sync::{LazyLock, Mutex},
};

use chrono::Utc;
use data_encoding::{BASE64, HEXLOWER};
use openssl::{
    pkey::PKey,
    rsa::Rsa,
    symm::{Cipher, encrypt},
};
use ring::{hkdf, hmac, pbkdf2};
use rocket::{
    Request, Route,
    http::Status,
    request::{FromRequest, Outcome},
    serde::json::Json,
};
use serde_json::{Value, json};

use crate::{
    api::{
        ApiResult, JsonResult,
        core::{seed_cipher, seed_send},
    },
    crypto,
    db::{
        DbConn,
        models::{Folder, FolderId, KeyId, SignatureAlgorithm, User, UserId, UserKdfType, UserSignatureKeyPair},
    },
};

pub fn routes() -> Vec<Route> {
    routes![seed, destroy_play]
}

/// The accounts seeded under each play id.
static PLAYS: LazyLock<Mutex<HashMap<String, Vec<UserId>>>> = LazyLock::new(Mutex::default);

/// HTTP basic auth with `TEST_SEEDER_USERNAME` and `TEST_SEEDER_PASSWORD`.
struct SeederAuth;

#[rocket::async_trait]
impl<'r> FromRequest<'r> for SeederAuth {
    type Error = &'static str;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let (Ok(username), Ok(password)) =
            (std::env::var("TEST_SEEDER_USERNAME"), std::env::var("TEST_SEEDER_PASSWORD"))
        else {
            return Outcome::Error((Status::NotFound, "The test seeder is off"));
        };
        if username.is_empty() || password.is_empty() {
            return Outcome::Error((Status::NotFound, "The test seeder is off"));
        }
        let expected = format!("Basic {}", BASE64.encode(format!("{username}:{password}").as_bytes()));
        match request.headers().get_one("Authorization") {
            Some(given) if crypto::ct_eq(given, expected) => Outcome::Success(Self),
            _ => Outcome::Error((Status::Unauthorized, "Invalid test seeder credentials")),
        }
    }
}

/// The `X-Play-Id` header, which names the play a seeding belongs to.
struct PlayId(String);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for PlayId {
    type Error = &'static str;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        match request.headers().get_one("X-Play-Id").map(str::trim) {
            Some(play_id) if !play_id.is_empty() => Outcome::Success(Self(play_id.to_owned())),
            _ => Outcome::Error((Status::BadRequest, "Seeding needs an X-Play-Id header")),
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SeedRequest {
    template: String,
    arguments: Option<Value>,
}

#[post("/seed", data = "<data>")]
async fn seed(data: Json<SeedRequest>, _auth: SeederAuth, play: PlayId, conn: DbConn) -> JsonResult {
    let data = data.into_inner();
    let arguments = data.arguments.unwrap_or(Value::Null);
    let response = match data.template.as_str() {
        "SingleUserScene" => single_user_scene(serde_json::from_value(arguments)?, &play.0, &conn).await?,
        "TestVectorUserScene" => test_vector_user_scene(serde_json::from_value(arguments)?, &play.0, &conn).await?,
        other => err_code!(format!("Unknown scene {}", other.escape_debug()), Status::NotFound.code),
    };
    Ok(Json(response))
}

/// Records an account in its play as soon as it's saved, so that destroying the play removes it even when the rest of
/// the seeding fails.
fn track(play: &str, user_id: &UserId) {
    PLAYS.lock().unwrap().entry(play.to_owned()).or_default().push(user_id.clone());
}

/// Deletes the accounts seeded under `play_id`; an unknown play is a no-op, like upstream.
#[delete("/seed/<play_id>")]
async fn destroy_play(play_id: &str, _auth: SeederAuth, conn: DbConn) -> JsonResult {
    let user_ids = PLAYS.lock().unwrap().remove(play_id).unwrap_or_default();
    let mut remaining = Vec::new();
    let mut error = None;
    for user_id in &user_ids {
        let Some(user) = User::find_by_uuid(user_id, &conn).await else {
            continue;
        };
        if let Err(e) = user.delete(&conn).await {
            remaining.push(user_id.clone());
            error.get_or_insert(e);
        }
    }
    if let Some(error) = error {
        // Kept in the play, so that destroying it again retries them
        PLAYS.lock().unwrap().entry(play_id.to_owned()).or_default().extend(remaining);
        return Err(error);
    }
    Ok(Json(json!({ "userIds": user_ids })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SingleUserRequest {
    email: String,
    password: String,
    #[serde(default)]
    email_verified: bool,
    kdf_iterations: Option<u32>,
    #[serde(default)]
    enroll_in_email2_fa: bool,
    #[serde(default)]
    corrupt_private_key: bool,
}

/// Ref: <https://github.com/bitwarden/server/blob/15c94ac58bf361a162381749c146d254a21b2098/util/Seeder/Models/UserSeed.cs#L55>
const DEFAULT_KDF_ITERATIONS: u32 = 5_000;

async fn single_user_scene(request: SingleUserRequest, play: &str, conn: &DbConn) -> ApiResult<Value> {
    if request.enroll_in_email2_fa || request.corrupt_private_key {
        err!("enrollInEmail2Fa and corruptPrivateKey aren't supported")
    }
    let iterations = request.kdf_iterations.unwrap_or(DEFAULT_KDF_ITERATIONS);
    if !(5_000..=2_000_000).contains(&iterations) {
        err!("kdfIterations must be between 5000 and 2000000")
    }
    let Some((local, domain)) = request.email.split_once('@') else {
        err!("The email has no @")
    };
    // Like upstream's ManglerService: unique addresses for every seeding
    let mangled = format!("{}+{local}@{domain}", HEXLOWER.encode(&crypto::get_random_bytes::<4>()));

    let mut user = User::new(&mangled, None);
    let keys = V1Keys::new(&request.password, &user.master_password_salt(), iterations)?;
    user.client_kdf_type = UserKdfType::Pbkdf2 as i32;
    user.client_kdf_iter = iterations.cast_signed();
    user.client_kdf_memory = None;
    user.client_kdf_parallelism = None;
    user.private_key = Some(keys.private_key.clone());
    user.public_key = Some(keys.public_key.clone());
    if request.email_verified {
        user.verified_at = Some(Utc::now().naive_utc());
    }
    user.set_password(&keys.master_password_hash, Some(keys.wrapped_user_key.clone()), false, None, conn).await?;
    user.save(conn).await?;
    track(play, &user.uuid);

    let response = json!({
        "mangleMap": mangle_map(&request.email, &user.email),
        "result": {
            "userId": user.uuid,
            "kdf": "PBKDF2_SHA256",
            "kdfIterations": iterations,
            "key": keys.wrapped_user_key,
            "publicKey": keys.public_key,
            "privateKey": keys.private_key,
        },
    });
    Ok(response)
}

/// What a V1 client makes when it registers, from the master password.
struct V1Keys {
    /// The master password authentication hash, which the client logs in with.
    master_password_hash: String,
    /// The user key, wrapped by the stretched master key.
    wrapped_user_key: String,
    /// The PKCS#8 RSA private key, wrapped by the user key.
    private_key: String,
    /// The SPKI RSA public key.
    public_key: String,
}

impl V1Keys {
    fn new(password: &str, salt: &str, iterations: u32) -> ApiResult<Self> {
        let master_key = pbkdf2_sha256(password.as_bytes(), salt.as_bytes(), iterations);
        let master_password_hash = BASE64.encode(&pbkdf2_sha256(&master_key, password.as_bytes(), 1));
        let stretched_enc = hkdf_expand(&master_key, b"enc");
        let stretched_mac = hkdf_expand(&master_key, b"mac");

        let user_key = crypto::get_random_bytes::<64>();
        let wrapped_user_key = enc_string(&user_key, &stretched_enc, &stretched_mac)?;

        let key_pair = PKey::from_rsa(Rsa::generate(2048)?)?;
        let private_key = enc_string(&key_pair.private_key_to_pkcs8()?, &user_key[..32], &user_key[32..])?;
        let public_key = BASE64.encode(&key_pair.public_key_to_der()?);

        Ok(Self {
            master_password_hash,
            wrapped_user_key,
            private_key,
            public_key,
        })
    }
}

fn pbkdf2_sha256(secret: &[u8], salt: &[u8], iterations: u32) -> [u8; 32] {
    let mut out = [0u8; 32];
    let iterations = NonZeroU32::new(iterations).expect("iterations aren't zero");
    pbkdf2::derive(pbkdf2::PBKDF2_HMAC_SHA256, iterations, salt, secret, &mut out);
    out
}

/// HKDF-Expand with `key` as the pseudorandom key, as clients stretch the master key.
fn hkdf_expand(key: &[u8; 32], info: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    hkdf::Prk::new_less_safe(hkdf::HKDF_SHA256, key)
        .expand(&[info], hkdf::HKDF_SHA256)
        .and_then(|okm| okm.fill(&mut out))
        .expect("32 bytes is a valid HKDF-SHA256 length");
    out
}

/// An `AesCbc256_HmacSha256_B64` (type 2) EncString.
fn enc_string(plaintext: &[u8], enc_key: &[u8], mac_key: &[u8]) -> ApiResult<String> {
    let iv = crypto::get_random_bytes::<16>();
    let ciphertext = encrypt(Cipher::aes_256_cbc(), enc_key, Some(&iv), plaintext)?;
    let mac = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, mac_key), &[iv.as_slice(), &ciphertext].concat());
    Ok(format!("2.{}|{}|{}", BASE64.encode(&iv), BASE64.encode(&ciphertext), BASE64.encode(mac.as_ref())))
}

/// A user test vector; only what a server holds is read from it.
///
/// Ref: <https://github.com/bitwarden/sdk-internal/blob/ee307a55d5604e96b983595c6379cc9f76ca2f87/e2e/wasm/vectors/load.ts>
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TestVector {
    name: String,
    account: VectorAccount,
    unlock_methods: Vec<Value>,
    master_password_authentication_hash: Option<String>,
    raw_cryptographic_state: VectorRawCryptographicState,
    #[serde(default)]
    vault: VectorVault,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct VectorAccount {
    email: String,
    security_version: Option<i32>,
    account_cryptographic_state: Value,
}

/// The public halves the vector records; its private halves are never read.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct VectorRawCryptographicState {
    public_key: String,
    verifying_key: Option<String>,
    user_key_id: Option<String>,
}

#[derive(Default, Deserialize)]
struct VectorVault {
    #[serde(default)]
    ciphers: Vec<VectorItem>,
    #[serde(default)]
    folders: Vec<VectorItem>,
    #[serde(default)]
    sends: Vec<VectorItem>,
}

#[derive(Deserialize)]
struct VectorItem {
    id: String,
    encrypted: Value,
}

/// Upstream's scene, not merged there yet:
/// <https://github.com/bitwarden/server/blob/9614f3f54f78ad57090a1fd5228f9c2fac5cbfe2/util/Seeder/Scenes/TestVectorUserScene.cs#L43-L361>
async fn test_vector_user_scene(vector: TestVector, play: &str, conn: &DbConn) -> ApiResult<Value> {
    let Some(unlock) =
        vector.unlock_methods.iter().find_map(|m| m.pointer("/masterPasswordUnlock/master_password_unlock"))
    else {
        err!(format!("Vector {} has no master password unlock method", vector.name.escape_debug()))
    };
    let Some(hash) = vector.master_password_authentication_hash.as_deref() else {
        err!(format!("Vector {} records no master password authentication hash", vector.name.escape_debug()))
    };
    let (Some(wrapped_user_key), Some(salt)) = (unlock["masterKeyWrappedUserKey"].as_str(), unlock["salt"].as_str())
    else {
        err!("The master password unlock method has no wrapped user key or salt")
    };

    let mut user = User::new(&vector.account.email, Some(vector.name.clone()));
    if user.master_password_salt() != salt {
        err!("The vector's master password salt isn't its email, which is the only salt Vaultwarden supports")
    }
    if User::find_by_mail(&user.email, conn).await.is_some() {
        err!("This vector is already seeded: destroy its play first, its address can't be mangled")
    }

    apply_kdf(&mut user, &unlock["kdf"])?;
    let state = &vector.account.account_cryptographic_state;
    let (v2, private_key) = match (state.get("V1"), state.get("V2")) {
        (Some(v1), None) => (None, &v1["private_key"]),
        (None, Some(v2)) => (Some(v2), &v2["private_key"]),
        _ => err!("The account cryptographic state is neither V1 nor V2"),
    };
    user.private_key = Some(json_str(private_key, "private_key")?);
    user.public_key = Some(vector.raw_cryptographic_state.public_key.clone());
    let key_id = vector.raw_cryptographic_state.user_key_id.as_deref().or_else(|| unlock["containedKeyId"].as_str());
    user.key_id = key_id.map(|id| serde_json::from_value::<KeyId>(json!(id))).transpose()?;
    let signature_key_pair = match v2 {
        Some(v2) => {
            user.signed_public_key = Some(json_str(&v2["signed_public_key"], "signed_public_key")?);
            user.security_state = Some(json_str(&v2["security_state"], "security_state")?);
            user.security_version = Some(vector.account.security_version.unwrap_or(2));
            let Some(verifying_key) = vector.raw_cryptographic_state.verifying_key.clone() else {
                err!("A V2 vector needs its verifying key")
            };
            let algorithm = cose_signature_algorithm(&verifying_key)?;
            Some((algorithm, json_str(&v2["signing_key"], "signing_key")?, verifying_key))
        }
        None => None,
    };
    user.verified_at = Some(Utc::now().naive_utc());
    user.set_password(hash, Some(wrapped_user_key.to_owned()), false, None, conn).await?;
    user.save(conn).await?;
    track(play, &user.uuid);
    if let Some((algorithm, signing_key, verifying_key)) = signature_key_pair {
        UserSignatureKeyPair::new(user.uuid.clone(), algorithm, signing_key, verifying_key).save(conn).await?;
    }

    // The vault, already encrypted, under fresh ids
    let mut folder_ids = HashMap::new();
    let mut folder_ids_by_vector_id = serde_json::Map::new();
    for folder in &vector.vault.folders {
        let mut saved = Folder::new(user.uuid.clone(), json_str(&folder.encrypted["name"], "name")?);
        saved.save(conn).await?;
        folder_ids.insert(serde_json::from_value::<FolderId>(json!(folder.id))?, saved.uuid.clone());
        folder_ids_by_vector_id.insert(folder.id.clone(), json!(saved.uuid));
    }
    let mut cipher_ids = serde_json::Map::new();
    for cipher in vector.vault.ciphers {
        let cipher_id = seed_cipher(cipher.encrypted, &user.uuid, &folder_ids, conn).await?;
        cipher_ids.insert(cipher.id, json!(cipher_id));
    }
    for send in vector.vault.sends {
        seed_send(send.encrypted, &user.uuid, conn).await?;
    }

    let response = json!({
        "mangleMap": mangle_map(&vector.account.email, &user.email),
        "result": {
            "userId": user.uuid,
            "email": user.email,
            "cipherIds": cipher_ids,
            "folderIds": folder_ids_by_vector_id,
        },
    });
    Ok(response)
}

/// The vector's KDF: `{"pBKDF2": {"iterations"}}` or `{"argon2id": {"iterations", "memory", "parallelism"}}`.
fn apply_kdf(user: &mut User, kdf: &Value) -> ApiResult<()> {
    let int = |value: &Value| value.as_i64().and_then(|v| i32::try_from(v).ok());
    if let Some(iterations) = kdf.pointer("/pBKDF2/iterations").and_then(int) {
        user.client_kdf_type = UserKdfType::Pbkdf2 as i32;
        user.client_kdf_iter = iterations;
        user.client_kdf_memory = None;
        user.client_kdf_parallelism = None;
    } else if let Some(argon2) = kdf.get("argon2id") {
        let Some(iterations) = int(&argon2["iterations"]) else {
            err!("The Argon2id KDF has no iterations")
        };
        user.client_kdf_type = UserKdfType::Argon2id as i32;
        user.client_kdf_iter = iterations;
        user.client_kdf_memory = int(&argon2["memory"]);
        user.client_kdf_parallelism = int(&argon2["parallelism"]);
    } else {
        err!("Unknown KDF")
    }
    Ok(())
}

/// The signature algorithm a COSE verifying key names in its `alg` (label 3) entry.
fn cose_signature_algorithm(verifying_key: &str) -> ApiResult<SignatureAlgorithm> {
    const ALG: i128 = 3;
    const EDDSA: i128 = -8;
    const ML_DSA_44: i128 = -48;

    let Ok(bytes) = BASE64.decode(verifying_key.as_bytes()) else {
        err!("The verifying key isn't base64")
    };
    let Ok(serde_cbor_2::Value::Map(entries)) = serde_cbor_2::from_slice::<serde_cbor_2::Value>(&bytes) else {
        err!("The verifying key isn't a COSE key")
    };
    match entries.get(&serde_cbor_2::Value::Integer(ALG)) {
        Some(serde_cbor_2::Value::Integer(EDDSA)) => Ok(SignatureAlgorithm::Ed25519),
        Some(serde_cbor_2::Value::Integer(ML_DSA_44)) => Ok(SignatureAlgorithm::MlDsa44),
        _ => err!("The verifying key's algorithm isn't Ed25519 or ML-DSA-44"),
    }
}

/// Upstream's map from the address a scene was asked for to the one it stored.
fn mangle_map(requested: &str, stored: &str) -> Value {
    let mut map = serde_json::Map::new();
    map.insert(requested.to_owned(), json!(stored));
    Value::Object(map)
}

fn json_str(value: &Value, field: &str) -> ApiResult<String> {
    let Some(value) = value.as_str() else {
        err!(format!("The vector's {field} is missing"))
    };
    Ok(value.to_owned())
}

#[cfg(test)]
mod tests {
    use openssl::symm::decrypt;

    use super::*;

    // From sdk-internal's `test-vectors/users/v1-pbkdf2-min-iterations.json` (d9119f7af)
    const EMAIL: &str = "v1-pbkdf2-min-iterations@test.bitwarden.com";
    const PASSWORD: &str = "password-v1-pbkdf2-min-iterations";
    const ITERATIONS: u32 = 5_000;
    const AUTHENTICATION_HASH: &str = "4HcwTg4bQKEbuINCJGMqrij1yipl63Ugu/RazH2y7Qw=";
    const WRAPPED_USER_KEY: &str = "2.tl+DrZdn+fVyBVu+0c/Gvg==|9ivOLNtKbvirNaUnkGsEtysp9de53ibTSu88HLkDOGLig3t8nhvK5JIqxSY1/ukcr2Y/Ly9OJ12tXUGjIlJ/PtIEIdYj3gZDwhAflPUwtW8=|FD5WuIvviib3yWYcI3slmqBSqMf38Z0CMwttPG1w5DY=";
    const USER_KEY: &str = "49LghK4AVIybWSZFikb4nAn/BofxxBIoXv83EJWOP4taVMbR5XCfrbF2m/eUmfZdeFW7VybPYSGT/bmv5eeMBg==";

    /// Decrypts a type 2 EncString, checking its MAC.
    fn dec_string(enc_string: &str, enc_key: &[u8], mac_key: &[u8]) -> Vec<u8> {
        let parts: Vec<Vec<u8>> = enc_string
            .strip_prefix("2.")
            .unwrap()
            .split('|')
            .map(|part| BASE64.decode(part.as_bytes()).unwrap())
            .collect();
        let [iv, ciphertext, mac] = parts.as_slice() else {
            panic!("not three parts")
        };
        let key = hmac::Key::new(hmac::HMAC_SHA256, mac_key);
        hmac::verify(&key, &[iv.as_slice(), ciphertext].concat(), mac).unwrap();
        decrypt(Cipher::aes_256_cbc(), enc_key, Some(iv), ciphertext).unwrap()
    }

    #[test]
    fn derives_the_vectors_keys() {
        let master_key = pbkdf2_sha256(PASSWORD.as_bytes(), EMAIL.as_bytes(), ITERATIONS);
        assert_eq!(BASE64.encode(&pbkdf2_sha256(&master_key, PASSWORD.as_bytes(), 1)), AUTHENTICATION_HASH);

        let user_key =
            dec_string(WRAPPED_USER_KEY, &hkdf_expand(&master_key, b"enc"), &hkdf_expand(&master_key, b"mac"));
        assert_eq!(BASE64.encode(&user_key), USER_KEY);
    }

    #[test]
    fn makes_keys_a_client_can_open() {
        let keys = V1Keys::new(PASSWORD, EMAIL, ITERATIONS).unwrap();
        assert_eq!(keys.master_password_hash, AUTHENTICATION_HASH);

        let master_key = pbkdf2_sha256(PASSWORD.as_bytes(), EMAIL.as_bytes(), ITERATIONS);
        let user_key =
            dec_string(&keys.wrapped_user_key, &hkdf_expand(&master_key, b"enc"), &hkdf_expand(&master_key, b"mac"));
        assert_eq!(user_key.len(), 64);

        let pkcs8 = dec_string(&keys.private_key, &user_key[..32], &user_key[32..]);
        let private_key = PKey::private_key_from_pkcs8(&pkcs8).unwrap();
        assert_eq!(BASE64.encode(&private_key.public_key_to_der().unwrap()), keys.public_key);
    }
}
