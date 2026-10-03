#![cfg(all(unix, any(feature = "sqlite", feature = "sqlite_system")))]
// Synthetic HTTP/storage contracts. These do not prove PRF hardware or client decryption.
use diesel::{Connection, RunQueryDsl, connection::SimpleConnection};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use openssl::{hash::MessageDigest, rsa::Rsa};
use reqwest::{Client, Response, StatusCode};
use serde_json::{Value, json};
use std::{
    fs,
    net::SocketAddr,
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
const ORIGIN: &str = "http://localhost";
const PASSWORD: &str = "synthetic-master-password-hash";

// Real native-format AES/HMAC/RSA envelopes over disposable synthetic key material.
// These exercise wire validation; hardware PRF and stock-client decryption remain separate.
struct WrappedKeys {
    user_key: String,
    public_key: String,
    private_key: String,
}
struct KeyVectors {
    initial: WrappedKeys,
    updated: WrappedKeys,
    rotated: WrappedKeys,
    original_account_private_key: String,
    repaired_public_key: String,
    repaired_private_key: String,
}
fn keys() -> &'static KeyVectors {
    static KEYS: std::sync::LazyLock<KeyVectors> = std::sync::LazyLock::new(|| {
        use openssl::{
            encrypt::Encrypter,
            pkey::{PKey, Private},
            rsa::Padding,
            symm::{Cipher, encrypt},
        };
        fn aes(plain: &[u8], key: &[u8; 64]) -> String {
            let mut iv = [0; 16];
            openssl::rand::rand_bytes(&mut iv).unwrap();
            let ciphertext = encrypt(Cipher::aes_256_cbc(), &key[..32], Some(&iv), plain).unwrap();
            let mac_key = PKey::hmac(&key[32..]).unwrap();
            let mut mac = openssl::sign::Signer::new(MessageDigest::sha256(), &mac_key).unwrap();
            mac.update(&iv).unwrap();
            mac.update(&ciphertext).unwrap();
            format!(
                "2.{}|{}|{}",
                data_encoding::BASE64.encode(&iv),
                data_encoding::BASE64.encode(&ciphertext),
                data_encoding::BASE64.encode(&mac.sign_to_vec().unwrap())
            )
        }
        fn wrap(pair: &PKey<Private>, user_key: &[u8; 64]) -> WrappedKeys {
            let mut rsa = Encrypter::new(pair).unwrap();
            rsa.set_rsa_padding(Padding::PKCS1_OAEP).unwrap();
            rsa.set_rsa_oaep_md(MessageDigest::sha1()).unwrap();
            rsa.set_rsa_mgf1_md(MessageDigest::sha1()).unwrap();
            let mut ciphertext = vec![0; rsa.encrypt_len(user_key).unwrap()];
            let len = rsa.encrypt(user_key, &mut ciphertext).unwrap();
            ciphertext.truncate(len);
            WrappedKeys {
                user_key: format!("4.{}", data_encoding::BASE64.encode(&ciphertext)),
                public_key: aes(&pair.public_key_to_der().unwrap(), user_key),
                private_key: aes(&pair.private_key_to_pkcs8().unwrap(), &[0x33; 64]),
            }
        }
        let original = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let replacement = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let account_pair = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let repaired_public_key = data_encoding::BASE64.encode(&account_pair.public_key_to_der().unwrap());
        let original_account_private_key = aes(&account_pair.private_key_to_pkcs8().unwrap(), &[0x11; 64]);
        let repaired_private_key = aes(&account_pair.private_key_to_pkcs8().unwrap(), &[0x11; 64]);
        let initial = wrap(&original, &[0x11; 64]);
        let updated = wrap(&replacement, &[0x11; 64]);
        let mut rotated = wrap(&original, &[0x22; 64]);
        rotated.private_key.clone_from(&initial.private_key);
        KeyVectors {
            initial,
            updated,
            rotated,
            original_account_private_key,
            repaired_public_key,
            repaired_private_key,
        }
    });
    &KEYS
}

struct Fixture {
    path: PathBuf,
    process: Child,
    url: String,
    client: Client,
    user: String,
    device: String,
    token: String,
    postgres: Option<(String, String)>,
}
impl Fixture {
    async fn new(enabled: bool) -> Self {
        Self::with_policy(enabled, true).await
    }
    async fn with_policy(enabled: bool, sso_only: bool) -> Self {
        static CRYPTO: std::sync::Once = std::sync::Once::new();
        CRYPTO.call_once(|| rustls::crypto::ring::default_provider().install_default().unwrap());
        let id = || uuid::Uuid::new_v4().to_string();
        let path = std::env::temp_dir().join(format!("vaultwarden-passkey-test-{}", id()));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        let key = Rsa::generate(2048).unwrap().private_key_to_pem().unwrap();
        fs::write(path.join("rsa.pem"), &key).unwrap();
        fs::set_permissions(path.join("rsa.pem"), fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(path.join("config.json"), "{}").unwrap();
        fs::write(path.join("empty.env"), "").unwrap();
        fs::write(path.join("db.sqlite3"), "").unwrap();
        let log = fs::File::create(path.join("server.log")).unwrap();
        let postgres = local_postgres_database();
        let database_url = postgres
            .as_ref()
            .map_or_else(|| path.join("db.sqlite3").to_string_lossy().into_owned(), |(_, url)| url.clone());
        let mut command = Command::new(env!("CARGO_BIN_EXE_vaultwarden"));
        command
            .env_clear()
            .current_dir(&path)
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("DATA_FOLDER", &path)
            .env("DATABASE_URL", database_url)
            .env("CONFIG_FILE", path.join("config.json"))
            .env("ENV_FILE", path.join("empty.env"))
            .env("RSA_KEY_FILENAME", path.join("rsa"))
            .env("DOMAIN", ORIGIN)
            .env("ROCKET_ADDRESS", "127.0.0.1")
            .env("ROCKET_PORT", "0")
            .env("WEB_VAULT_ENABLED", "false")
            .env("ENABLE_WEBSOCKET", "false")
            .env("PUSH_ENABLED", "false")
            .env("DISABLE_ICON_DOWNLOAD", "true")
            .env("JOB_POLL_INTERVAL_MS", "0")
            .env("LOGIN_RATELIMIT_MAX_BURST", "100")
            .env("DATABASE_MAX_CONNS", "4")
            .env("DATABASE_MIN_CONNS", "1")
            .env("PASSKEYS_ENABLED", enabled.to_string())
            .env("SSO_ENABLED", sso_only.to_string())
            .env("SSO_ONLY", sso_only.to_string())
            .env("SSO_CLIENT_ID", "synthetic-client")
            .env("SSO_CLIENT_SECRET", "synthetic-secret")
            .env("SSO_AUTHORITY", "http://127.0.0.1:9")
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log));
        for name in ["DYLD_LIBRARY_PATH", "LD_LIBRARY_PATH"] {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
        let user = id();
        let device = id();
        let now = chrono::Utc::now().timestamp();
        let token = jsonwebtoken::encode(
            &Header::new(Algorithm::RS256),
            &json!({
                "nbf":now-30,"exp":now+3600,"iss":format!("{ORIGIN}|login"),"sub":user,
                "premium":true,"name":"Synthetic user","email":"user@example.test","email_verified":true,
                "sstamp":"synthetic-stamp","device":device,"devicetype":"14","client_id":"web",
                "scope":["api","offline_access"],"amr":["Application"]
            }),
            &EncodingKey::from_rsa_pem(&key).unwrap(),
        )
        .unwrap();
        let mut f = Self {
            path,
            process: command.spawn().unwrap(),
            url: String::new(),
            client: Client::builder().no_proxy().timeout(Duration::from_secs(15)).build().unwrap(),
            user,
            device,
            token,
            postgres,
        };
        let until = Instant::now() + Duration::from_secs(20);
        loop {
            assert!(
                f.process.try_wait().unwrap().is_none() && Instant::now() < until,
                "fixture failed: {}\n{}",
                f.path.display(),
                fs::read_to_string(f.path.join("server.log")).unwrap_or_default()
            );
            if f.url.is_empty() {
                let log = fs::read_to_string(f.path.join("server.log")).unwrap();
                if let Some(address) = log.split_inclusive('\n').find_map(|line| {
                    let (_, a) = line.strip_suffix('\n')?.split_once("Rocket has launched from http://")?;
                    let a = a.trim().parse::<SocketAddr>().ok()?;
                    (a.ip().is_loopback() && a.port() != 0).then_some(a)
                }) {
                    f.url = format!("http://{address}");
                }
            }
            if !f.url.is_empty()
                && let Ok(r) = f.client.get(format!("{}/alive", f.url)).send().await
                && r.status() == StatusCode::OK
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(40)).await;
        }
        let salt = [0u8; 64];
        let mut hash = [0u8; 32];
        openssl::pkcs5::pbkdf2_hmac(PASSWORD.as_bytes(), &salt, 1000, MessageDigest::sha256(), &mut hash).unwrap();
        let hash = data_encoding::HEXLOWER.encode(&hash);
        // All interpolated values are generated UUIDs or fixed synthetic fixture values.
        f.sql(&format!("INSERT INTO users (uuid,enabled,created_at,updated_at,login_verify_count,email,name,password_hash,salt,password_iterations,akey,private_key,security_stamp,equivalent_domains,excluded_globals,client_kdf_type,client_kdf_iter) VALUES ('{}',1,datetime('now'),datetime('now'),0,'user@example.test','Synthetic user',X'{hash}',zeroblob(64),1000,'synthetic-key','synthetic-private-key','synthetic-stamp','[]','[]',0,600000); INSERT INTO devices (uuid,user_uuid,created_at,updated_at,name,atype,refresh_token) VALUES ('{}','{}',datetime('now'),datetime('now'),'Synthetic browser',14,'synthetic-refresh');", f.user,f.device,f.user));
        f
    }
    fn sql(&self, sql: &str) {
        #[cfg(feature = "postgresql")]
        if let Some((_, url)) = &self.postgres {
            let mut c = diesel::pg::PgConnection::establish(url).unwrap();
            let sql = sql
                .replace("datetime('now')", "CURRENT_TIMESTAMP")
                .replace(",1,CURRENT_TIMESTAMP", ",true,CURRENT_TIMESTAMP")
                .replace("zeroblob(64)", "decode(repeat('00',64),'hex')");
            let sql = regex::Regex::new("X'([0-9a-f]+)'").unwrap().replace_all(&sql, "decode('$1','hex')");
            let sql = sql
                .replace("json_set(data,'$.createdAt',0)", "jsonb_set(data::jsonb,'{createdAt}','0')::text")
                .replace(
                    "json_set(data,'$.deviceUuid','another-device')",
                    "jsonb_set(data::jsonb,'{deviceUuid}','\"another-device\"')::text",
                )
                .replace(
                    "json_set(data,'$.accountKeyBinding','another-key')",
                    "jsonb_set(data::jsonb,'{accountKeyBinding}','\"another-key\"')::text",
                );
            c.batch_execute(&sql).unwrap();
            return;
        }

        let mut c =
            diesel::sqlite::SqliteConnection::establish(self.path.join("db.sqlite3").to_str().unwrap()).unwrap();
        c.batch_execute("PRAGMA busy_timeout=5000;").unwrap();
        c.batch_execute(sql).unwrap();
    }
    fn count(&self, table: &str) -> i64 {
        #[derive(diesel::QueryableByName)]
        struct Count {
            #[diesel(sql_type=diesel::sql_types::BigInt)]
            count: i64,
        }
        #[cfg(feature = "postgresql")]
        if let Some((_, url)) = &self.postgres {
            let mut c = diesel::pg::PgConnection::establish(url).unwrap();
            return diesel::sql_query(format!("SELECT count(*) AS count FROM {table}"))
                .get_result::<Count>(&mut c)
                .unwrap()
                .count;
        }
        let mut c =
            diesel::sqlite::SqliteConnection::establish(self.path.join("db.sqlite3").to_str().unwrap()).unwrap();
        diesel::sql_query(format!("SELECT count(*) AS count FROM {table}")).get_result::<Count>(&mut c).unwrap().count
    }
    async fn post(&self, path: &str, data: Value) -> Response {
        self.client.post(format!("{}{path}", self.url)).bearer_auth(&self.token).json(&data).send().await.unwrap()
    }
    async fn get(&self, path: &str) -> Value {
        let r = self.client.get(format!("{}{path}", self.url)).bearer_auth(&self.token).send().await.unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        r.json().await.unwrap()
    }
    async fn options(&self) -> Value {
        let r = self.post("/api/webauthn/attestation-options", json!({"masterPasswordHash":PASSWORD})).await;
        assert_eq!(r.status(), StatusCode::OK);
        r.json().await.unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        drop(self.process.kill());
        drop(self.process.wait());
        #[cfg(feature = "postgresql")]
        if let Some((admin, url)) = &self.postgres {
            let parsed = url::Url::parse(url).unwrap();
            let database = parsed.path().trim_start_matches('/');
            assert!(
                database.starts_with("vw_passkey_") && database.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            );
            if let Ok(mut conn) = diesel::pg::PgConnection::establish(admin) {
                drop(conn.batch_execute(&format!("DROP DATABASE {database} WITH (FORCE)")));
            }
        }
        drop(fs::remove_dir_all(&self.path));
    }
}

#[tokio::test]
async fn passkey_enrollment_requires_step_up_and_never_adds_an_sso_bypass() {
    let f = Fixture::new(true).await;
    for proof in [json!({}), json!({"masterPasswordHash":"wrong"})] {
        assert_eq!(f.post("/api/webauthn/attestation-options", proof).await.status(), StatusCode::BAD_REQUEST);
    }
    let options = f.options().await;
    assert_eq!(options["options"]["rp"]["id"], "localhost");
    assert_eq!(options["options"]["authenticatorSelection"]["userVerification"], "required");
    assert!(options["token"].as_str().is_some_and(|s| !s.is_empty()));
    assert_eq!(f.get("/api/webauthn").await["data"], json!([]));
    let public_options =
        f.client.get(format!("{}/identity/accounts/webauthn/assertion-options", f.url)).send().await.unwrap();
    assert!(!public_options.status().is_success());
    let r = f
        .client
        .post(format!("{}/identity/connect/token", f.url))
        .form(&[("grant_type", "webauthn"), ("client_id", "web"), ("token", "synthetic"), ("deviceResponse", "{}")])
        .send()
        .await
        .unwrap();
    assert!(!r.status().is_success());
    let sync = f.get("/api/sync").await;
    assert_eq!(sync["userDecryption"]["masterPasswordUnlock"]["masterKeyWrappedUserKey"], "synthetic-key");
    assert!(sync["userDecryption"]["webAuthnPrfOptions"].is_null());
    assert_eq!(f.count("web_authn_credentials"), 0);
}

#[tokio::test]
async fn passkey_disabled_preserves_existing_sync_and_list_and_denies_enrollment() {
    let f = Fixture::new(false).await;
    // The shared keypair endpoint retains its ordinary behavior with the new
    // feature disabled, including first initialization and serial replacement.
    f.sql(&format!("UPDATE users SET private_key=NULL,public_key=NULL WHERE uuid='{}'", f.user));
    for private_key in [&keys().original_account_private_key, &keys().repaired_private_key] {
        assert_eq!(
            f.post(
                "/api/accounts/keys",
                json!({"publicKey":keys().repaired_public_key,
            "encryptedPrivateKey":private_key})
            )
            .await
            .status(),
            StatusCode::OK
        );
    }

    assert!(
        !f.post("/api/webauthn/attestation-options", json!({"masterPasswordHash":PASSWORD}))
            .await
            .status()
            .is_success()
    );
    assert_eq!(f.get("/api/webauthn").await["data"], json!([]));
    let sync = f.get("/api/sync").await;
    assert_eq!(sync["userDecryption"]["masterPasswordUnlock"]["masterKeyWrappedUserKey"], "synthetic-key");
    assert!(sync["userDecryption"]["webAuthnPrfOptions"].is_null());
}

fn registration_with_key(
    options: &Value,
    origin: &str,
    uv: bool,
) -> (Value, openssl::ec::EcKey<openssl::pkey::Private>) {
    use openssl::{
        bn::{BigNum, BigNumContext},
        ec::{EcGroup, EcKey},
        nid::Nid,
    };
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let key = EcKey::generate(&group).unwrap();
    let (mut x, mut y, mut ctx) = (BigNum::new().unwrap(), BigNum::new().unwrap(), BigNumContext::new().unwrap());
    key.public_key().affine_coordinates_gfp(&group, &mut x, &mut y, &mut ctx).unwrap();
    let mut cose = vec![0xa5, 1, 2, 3, 0x26, 0x20, 1, 0x21, 0x58, 32];
    cose.extend(x.to_vec_padded(32).unwrap());
    cose.extend([0x22, 0x58, 32]);
    cose.extend(y.to_vec_padded(32).unwrap());
    let credential = uuid::Uuid::new_v4();
    let mut auth = openssl::sha::sha256(b"localhost").to_vec();
    auth.push(if uv {
        0x45
    } else {
        0x41
    });
    auth.extend([0; 4]);
    auth.extend([0; 16]);
    auth.extend([0, 16]);
    auth.extend(credential.as_bytes());
    auth.extend(cose);
    // Minimal standards-format 'none' attestation from a synthetic EC credential.
    // This exercises webauthn-rs verification; it does not simulate PRF hardware.
    let mut attestation = b"\xa3\x63fmt\x64none\x67attStmt\xa0\x68authData\x58".to_vec();
    attestation.push(u8::try_from(auth.len()).unwrap());
    attestation.extend(auth);
    let client = json!({"type":"webauthn.create","challenge":options["options"]["challenge"],"origin":origin,"crossOrigin":false});
    let encode = |b: &[u8]| data_encoding::BASE64URL_NOPAD.encode(b);
    let response = json!({"deviceResponse":{"id":encode(credential.as_bytes()),"rawId":encode(credential.as_bytes()),
        "response":{"attestationObject":encode(&attestation),"clientDataJson":encode(&serde_json::to_vec(&client).unwrap()),"transports":["usb"]},
        "type":"public-key","clientExtensionResults":{"prf":{"enabled":true}}},
        "name":"Synthetic passkey","token":options["token"],"supportsPrf":true,
        "encryptedUserKey":keys().initial.user_key.as_str(),"encryptedPublicKey":keys().initial.public_key.as_str(),"encryptedPrivateKey":keys().initial.private_key.as_str()});
    (response, key)
}

fn registration(options: &Value, origin: &str, uv: bool) -> Value {
    registration_with_key(options, origin, uv).0
}

#[tokio::test]
async fn passkey_registration_verifies_origin_uv_replay_and_complete_wrapped_keys() {
    let f = Fixture::new(true).await;
    for (origin, uv) in [("http://unrelated.example", true), (ORIGIN, false)] {
        let o = f.options().await;
        let r = f.post("/api/webauthn", registration(&o, origin, uv)).await;
        assert!(!r.status().is_success());
        assert_eq!(f.count("web_authn_credentials"), 0);
    }
    let o = f.options().await;
    let mut incomplete = registration(&o, ORIGIN, true);
    incomplete.as_object_mut().unwrap().remove("encryptedPrivateKey");
    assert!(!f.post("/api/webauthn", incomplete).await.status().is_success());
    assert_eq!(f.count("web_authn_credentials"), 0);
    let o = f.options().await;
    let data = registration(&o, ORIGIN, true);
    assert_eq!(f.post("/api/webauthn", data.clone()).await.status(), StatusCode::OK);
    assert!(!f.post("/api/webauthn", data).await.status().is_success());
    assert_eq!(f.count("web_authn_credentials"), 1);
    let list = f.get("/api/webauthn").await;
    assert_eq!(list["data"][0]["prfStatus"], 0);
    let sync = f.get("/api/sync").await;
    assert_eq!(
        sync["userDecryption"]["webAuthnPrfOptions"][0]["encryptedPrivateKey"],
        keys().initial.private_key.as_str()
    );
    assert_eq!(sync["userDecryption"]["masterPasswordUnlock"]["masterKeyWrappedUserKey"], "synthetic-key");
}

#[tokio::test]
async fn passkey_multiple_options_removal_and_password_wrapping_are_consistent() {
    let f = Fixture::new(true).await;
    for _ in 0..2 {
        let o = f.options().await;
        assert_eq!(f.post("/api/webauthn", registration(&o, ORIGIN, true)).await.status(), StatusCode::OK);
    }
    assert_eq!(f.get("/api/sync").await["userDecryption"]["webAuthnPrfOptions"].as_array().unwrap().len(), 2);
    let list = f.get("/api/webauthn").await;
    let id = list["data"][0]["id"].as_str().unwrap();
    assert_eq!(
        f.post(&format!("/api/webauthn/{id}/delete"), json!({"masterPasswordHash":PASSWORD})).await.status(),
        StatusCode::OK
    );
    assert_eq!(f.get("/api/sync").await["userDecryption"]["webAuthnPrfOptions"].as_array().unwrap().len(), 1);
    // A master-password wrapper/KDF change preserves the actual user key.
    f.sql(&format!("UPDATE users SET akey='new-master-wrapper',client_kdf_iter=650000 WHERE uuid='{}'", f.user));
    assert_eq!(f.get("/api/sync").await["userDecryption"]["webAuthnPrfOptions"].as_array().unwrap().len(), 1);
}

fn rotate_request(passkeys: &Value) -> Value {
    json!({"oldMasterKeyAuthenticationHash":PASSWORD,
        "accountUnlockData":{"emergencyAccessUnlockData":[],"organizationAccountRecoveryUnlockData":[],
            "passkeyUnlockData":passkeys,"masterPasswordUnlockData":{"kdfType":0,"kdfIterations":600_000,
            "kdfMemory":null,"kdfParallelism":null,"email":"user@example.test","masterKeyAuthenticationHash":PASSWORD,
            "masterKeyEncryptedUserKey":"new-master-wrapper"}},
        "accountKeys":{"userKeyEncryptedAccountPrivateKey":"new-account-private-wrapper","accountPublicKey":"synthetic-public-key"},
        "accountData":{"ciphers":[],"folders":[],"sends":[]}})
}

#[tokio::test]
async fn passkey_rotation_validates_before_mutation_and_rewraps_all_credentials() {
    let f = Fixture::new(true).await;
    f.sql(&format!("UPDATE users SET public_key='synthetic-public-key' WHERE uuid='{}'", f.user));
    let o = f.options().await;
    assert_eq!(f.post("/api/webauthn", registration(&o, ORIGIN, true)).await.status(), StatusCode::OK);
    let list = f.get("/api/webauthn").await;
    let id = list["data"][0]["id"].as_str().unwrap();
    assert_eq!(
        f.post("/api/accounts/key-management/rotate-user-account-keys", rotate_request(&json!([]))).await.status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        f.get("/api/sync").await["userDecryption"]["masterPasswordUnlock"]["masterKeyWrappedUserKey"],
        "synthetic-key"
    );
    for field in ["encryptedUserKey", "encryptedPublicKey"] {
        for invalid in [Value::Null, json!("not-an-encrypted-string")] {
            let mut changes = json!([{"id":id,"encryptedPublicKey":keys().rotated.public_key.as_str(),"encryptedUserKey":keys().rotated.user_key.as_str()}]);
            let expected = if invalid.is_null() {
                StatusCode::UNPROCESSABLE_ENTITY
            } else {
                StatusCode::BAD_REQUEST
            };
            changes[0][field] = invalid;
            assert_eq!(
                f.post("/api/accounts/key-management/rotate-user-account-keys", rotate_request(&changes))
                    .await
                    .status(),
                expected
            );
            assert_eq!(
                f.get("/api/sync").await["userDecryption"]["masterPasswordUnlock"]["masterKeyWrappedUserKey"],
                "synthetic-key"
            );
        }
    }
    let changes = json!([{"id":id,"encryptedPublicKey":keys().rotated.public_key.as_str(),"encryptedUserKey":keys().rotated.user_key.as_str()}]);
    assert_eq!(
        f.post("/api/accounts/key-management/rotate-user-account-keys", rotate_request(&changes)).await.status(),
        StatusCode::OK
    );
    // Read only synthetic persistence. Token invalidation is native rotation behavior.
    assert_eq!(
        f.count(&format!(
            "web_authn_credentials WHERE encrypted_user_key='{}' AND encrypted_private_key='{}'",
            keys().rotated.user_key,
            keys().initial.private_key
        )),
        1
    );
    assert_eq!(f.count("users WHERE akey='new-master-wrapper' AND private_key='new-account-private-wrapper'"), 1);
}

#[tokio::test]
async fn passkey_challenges_are_fresh_session_bound_and_consumed_exactly_once() {
    let f = Fixture::new(true).await;
    for change in [
        "json_set(data,'$.createdAt',0)",
        "json_set(data,'$.deviceUuid','another-device')",
        "json_set(data,'$.accountKeyBinding','another-key')",
    ] {
        let o = f.options().await;
        f.sql(&format!("UPDATE twofactor SET data={change} WHERE atype=1005"));
        assert!(!f.post("/api/webauthn", registration(&o, ORIGIN, true)).await.status().is_success());
        assert_eq!(f.count("web_authn_credentials"), 0);
    }
    let stale = f.options().await;
    let current = f.options().await;
    assert!(!f.post("/api/webauthn", registration(&stale, ORIGIN, true)).await.status().is_success());
    let data = registration(&current, ORIGIN, true);
    let (first, second) = tokio::join!(f.post("/api/webauthn", data.clone()), f.post("/api/webauthn", data));
    assert_eq!(usize::from(first.status().is_success()) + usize::from(second.status().is_success()), 1);
    assert_eq!(f.count("web_authn_credentials"), 1);
    assert_eq!(f.count("twofactor WHERE atype=1005"), 0);
}

#[tokio::test]
async fn passkey_prf_update_verifies_assertion_and_rejects_replay() {
    let f = Fixture::new(true).await;
    let o = f.options().await;
    let (registration, key) = registration_with_key(&o, ORIGIN, true);
    let credential = registration["deviceResponse"]["rawId"].clone();
    assert_eq!(f.post("/api/webauthn", registration).await.status(), StatusCode::OK);
    let response = f.post("/api/webauthn/assertion-options", json!({"masterPasswordHash":PASSWORD})).await;
    assert_eq!(response.status(), StatusCode::OK);
    let o: Value = response.json().await.unwrap();
    let client =
        json!({"type":"webauthn.get","challenge":o["options"]["challenge"],"origin":ORIGIN,"crossOrigin":false});
    let client = serde_json::to_vec(&client).unwrap();
    let mut auth = openssl::sha::sha256(b"localhost").to_vec();
    auth.push(5);
    auth.extend(1u32.to_be_bytes());
    let key = openssl::pkey::PKey::from_ec_key(key).unwrap();
    let mut signer = openssl::sign::Signer::new(MessageDigest::sha256(), &key).unwrap();
    signer.update(&auth).unwrap();
    signer.update(&openssl::sha::sha256(&client)).unwrap();
    let encode = |b: &[u8]| data_encoding::BASE64URL_NOPAD.encode(b);
    let data = json!({"token":o["token"],"deviceResponse":{"id":credential,"rawId":credential,"type":"public-key",
        "extensions":{},"response":{"authenticatorData":encode(&auth),"clientDataJson":encode(&client),"signature":encode(&signer.sign_to_vec().unwrap()),"userHandle":null}},
        "encryptedUserKey":keys().updated.user_key.as_str(),"encryptedPublicKey":keys().updated.public_key.as_str(),"encryptedPrivateKey":keys().updated.private_key.as_str()});
    let send = |data| f.client.put(format!("{}/api/webauthn", f.url)).bearer_auth(&f.token).json(&data).send();
    assert_eq!(send(data.clone()).await.unwrap().status(), StatusCode::OK);
    assert!(!send(data).await.unwrap().status().is_success());
    assert_eq!(
        f.get("/api/sync").await["userDecryption"]["webAuthnPrfOptions"][0]["encryptedPrivateKey"],
        keys().updated.private_key.as_str()
    );
}

#[tokio::test]
async fn passkey_credentials_cannot_be_read_or_removed_by_another_account() {
    let f = Fixture::new(true).await;
    let o = f.options().await;
    assert_eq!(f.post("/api/webauthn", registration(&o, ORIGIN, true)).await.status(), StatusCode::OK);
    let list = f.get("/api/webauthn").await;
    let id = list["data"][0]["id"].as_str().unwrap();
    let other = uuid::Uuid::new_v4().to_string();
    let device = uuid::Uuid::new_v4().to_string();
    f.sql(&format!("INSERT INTO users (uuid,enabled,created_at,updated_at,login_verify_count,email,name,password_hash,salt,password_iterations,akey,private_key,security_stamp,equivalent_domains,excluded_globals,client_kdf_type,client_kdf_iter) SELECT '{other}',enabled,created_at,updated_at,login_verify_count,'other@example.test','Other synthetic user',password_hash,salt,password_iterations,akey,private_key,'other-stamp',equivalent_domains,excluded_globals,client_kdf_type,client_kdf_iter FROM users WHERE uuid='{}'; INSERT INTO devices (uuid,user_uuid,created_at,updated_at,name,atype,refresh_token) VALUES ('{device}','{other}',datetime('now'),datetime('now'),'Other browser',14,'other-refresh');",f.user));
    let now = chrono::Utc::now().timestamp();
    let token=jsonwebtoken::encode(&Header::new(Algorithm::RS256),&json!({"nbf":now-30,"exp":now+3600,"iss":format!("{ORIGIN}|login"),"sub":other,"premium":true,"name":"Other user","email":"other@example.test","email_verified":true,"sstamp":"other-stamp","device":device,"devicetype":"14","client_id":"web","scope":["api","offline_access"],"amr":["Application"]}),&EncodingKey::from_rsa_pem(&fs::read(f.path.join("rsa.pem")).unwrap()).unwrap()).unwrap();
    let r = f.client.get(format!("{}/api/webauthn", f.url)).bearer_auth(&token).send().await.unwrap();
    assert_eq!(r.json::<Value>().await.unwrap()["data"], json!([]));
    assert_eq!(
        f.client
            .post(format!("{}/api/webauthn/{id}/delete", f.url))
            .bearer_auth(&token)
            .json(&json!({"masterPasswordHash":PASSWORD}))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert_eq!(f.get("/api/webauthn").await["data"].as_array().unwrap().len(), 1);
    let r = f.client.get(format!("{}/api/webauthn", f.url)).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
}

fn local_postgres_database() -> Option<(String, String)> {
    let Ok(value) = std::env::var("VW_PASSKEY_TEST_DATABASE_URL") else {
        return None;
    };
    let url = url::Url::parse(&value).expect("local test URL");
    assert_eq!(url.scheme(), "postgresql");
    assert_eq!(url.host_str(), Some("127.0.0.1"));
    assert!(url.username() == "passkey_test", "Expected the disposable test account");
    assert!(url.password() == Some("synthetic-passkey-test"), "Expected synthetic test credentials");
    assert_eq!(url.path(), "/postgres");
    assert!(url.fragment().is_none());
    let parameters = url.query_pairs().collect::<Vec<_>>();
    if !parameters.is_empty() {
        assert_eq!(parameters.len(), 1);
        assert_eq!(parameters[0].0, "host");
        let directory = PathBuf::from(parameters[0].1.as_ref());
        let canonical = directory.canonicalize().expect("private fixture socket directory");
        assert_eq!(canonical, directory);
        assert_eq!(directory.parent(), Some(std::env::temp_dir().canonicalize().unwrap().as_path()));
        assert!(directory.file_name().unwrap().to_str().unwrap().starts_with("vw-passkey-pg-"));
        assert_eq!(fs::metadata(&directory).unwrap().permissions().mode() & 0o777, 0o700);
    }
    #[cfg(feature = "postgresql")]
    {
        let database = format!("vw_passkey_{}", uuid::Uuid::new_v4().simple());
        let mut c = diesel::pg::PgConnection::establish(&value).unwrap();
        c.batch_execute(&format!("CREATE DATABASE {database}")).unwrap();
        let mut database_url = url.clone();
        database_url.set_path(&database);
        Some((value, database_url.to_string()))
    }
    #[cfg(not(feature = "postgresql"))]
    panic!("PostgreSQL fixture requires the postgresql feature");
}

#[tokio::test]
async fn passkey_rewrap_failure_rolls_back_account_keys_and_can_retry() {
    let f = Fixture::new(true).await;
    f.sql(&format!("UPDATE users SET public_key='synthetic-public-key' WHERE uuid='{}'", f.user));
    let o = f.options().await;
    assert_eq!(f.post("/api/webauthn", registration(&o, ORIGIN, true)).await.status(), StatusCode::OK);
    let list = f.get("/api/webauthn").await;
    let data = rotate_request(
        &json!([{"id":list["data"][0]["id"],"encryptedPublicKey":keys().rotated.public_key.as_str(),"encryptedUserKey":keys().rotated.user_key.as_str()}]),
    );
    if f.postgres.is_some() {
        f.sql("CREATE FUNCTION reject_rewrap() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'synthetic failure'; END;$$; CREATE TRIGGER reject_rewrap BEFORE UPDATE OF encrypted_user_key ON web_authn_credentials FOR EACH ROW EXECUTE FUNCTION reject_rewrap();");
    } else {
        f.sql("CREATE TRIGGER reject_rewrap BEFORE UPDATE OF encrypted_user_key ON web_authn_credentials BEGIN SELECT RAISE(ABORT,'synthetic failure'); END;");
    }
    assert!(!f.post("/api/accounts/key-management/rotate-user-account-keys", data.clone()).await.status().is_success());
    assert_eq!(f.count("users WHERE akey='synthetic-key' AND private_key='synthetic-private-key' AND security_stamp='synthetic-stamp'"),1);
    assert_eq!(f.get("/api/sync").await["userDecryption"]["webAuthnPrfOptions"].as_array().unwrap().len(), 1);
    if f.postgres.is_some() {
        f.sql("DROP TRIGGER reject_rewrap ON web_authn_credentials; DROP FUNCTION reject_rewrap();");
    } else {
        f.sql("DROP TRIGGER reject_rewrap;");
    }
    assert_eq!(f.post("/api/accounts/key-management/rotate-user-account-keys", data).await.status(), StatusCode::OK);
}

#[cfg(feature = "postgresql")]
struct PausedRotation {
    control: diesel::pg::PgConnection,
}
#[cfg(feature = "postgresql")]
impl PausedRotation {
    fn new(f: &Fixture) -> Self {
        let (_, url) = f.postgres.as_ref().expect("run through the disposable PostgreSQL gate");
        let mut control = diesel::pg::PgConnection::establish(url).unwrap();
        control.batch_execute("SELECT pg_advisory_lock(424242);").unwrap();
        f.sql("CREATE FUNCTION pause_rotation() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN PERFORM pg_advisory_xact_lock(424242); RETURN NEW; END;$$; CREATE TRIGGER pause_rotation AFTER UPDATE OF akey ON users FOR EACH ROW WHEN (NEW.akey='new-master-wrapper') EXECUTE FUNCTION pause_rotation();");
        Self {
            control,
        }
    }
    fn release(&mut self) {
        self.control.batch_execute("SELECT pg_advisory_unlock(424242);").unwrap();
    }
}
#[cfg(feature = "postgresql")]
impl Drop for PausedRotation {
    fn drop(&mut self) {
        drop(self.control.batch_execute("SELECT pg_advisory_unlock_all();"));
    }
}

#[cfg(feature = "postgresql")]
impl Fixture {
    async fn paused_rotation_data(&self) -> (Value, String) {
        assert!(self.postgres.is_some(), "PostgreSQL gate must supply a disposable database");
        self.sql(&format!("UPDATE users SET public_key='synthetic-public-key' WHERE uuid='{}'", self.user));
        let o = self.options().await;
        assert_eq!(self.post("/api/webauthn", registration(&o, ORIGIN, true)).await.status(), StatusCode::OK);
        let list = self.get("/api/webauthn").await;
        let id = list["data"][0]["id"].as_str().unwrap().to_owned();
        let folder = uuid::Uuid::new_v4();
        self.sql(&format!("INSERT INTO folders (uuid,user_uuid,created_at,updated_at,name) VALUES ('{folder}','{}',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,'original-folder-wrapper')",self.user));
        let mut data = rotate_request(
            &json!([{"id":id,"encryptedPublicKey":keys().rotated.public_key.as_str(),"encryptedUserKey":keys().rotated.user_key.as_str()}]),
        );
        data["accountData"]["folders"] = json!([{"id":folder,"name":"rotated-folder-wrapper"}]);
        (data, id)
    }
    fn start_rotation(&self, data: &Value) -> tokio::task::JoinHandle<Result<Response, reqwest::Error>> {
        let request = self
            .client
            .post(format!("{}/api/accounts/key-management/rotate-user-account-keys", self.url))
            .bearer_auth(&self.token)
            .json(data);
        tokio::spawn(async move { request.send().await })
    }
    async fn wait_for_database_wait(&self, condition: &str) {
        let until = Instant::now() + Duration::from_secs(3);
        while self.count(condition) == 0 {
            assert!(Instant::now() < until, "expected database wait did not occur");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
    async fn wait_for_paused_rotation(&self) {
        self.wait_for_database_wait("pg_locks WHERE database=(SELECT oid FROM pg_database WHERE datname=current_database()) AND locktype='advisory' AND objid=424242 AND NOT granted").await;
    }
    fn assert_original_key_state(&self) {
        assert_eq!(self.count("users WHERE akey='synthetic-key' AND private_key='synthetic-private-key' AND security_stamp='synthetic-stamp'"),1);
        assert_eq!(self.count("folders WHERE name='original-folder-wrapper'"), 1);
        assert_eq!(self.count("devices WHERE refresh_token='synthetic-refresh'"), 1);
        assert_eq!(
            self.count(&format!("web_authn_credentials WHERE encrypted_user_key='{}'", keys().initial.user_key)),
            1
        );
    }
}

#[cfg(feature = "postgresql")]
#[tokio::test]
#[ignore = "requires a disposable PostgreSQL instance; see tests/README.md"]
async fn passkey_postgres_rotation_serializes_deletion_and_stale_rotation() {
    for competing_action in ["delete", "rotate", "repair"] {
        let f = Fixture::new(true).await;
        let (data, id) = f.paused_rotation_data().await;
        let mut pause = PausedRotation::new(&f);
        let first = f.start_rotation(&data);
        f.wait_for_paused_rotation().await;
        let competing = if competing_action == "delete" {
            let request = f
                .client
                .post(format!("{}/api/webauthn/{id}/delete", f.url))
                .bearer_auth(&f.token)
                .json(&json!({"masterPasswordHash":PASSWORD}));
            tokio::spawn(async move { request.send().await })
        } else if competing_action == "repair" {
            let request = f.client.post(format!("{}/api/accounts/keys", f.url)).bearer_auth(&f.token).json(
                &json!({"publicKey":keys().repaired_public_key,"encryptedPrivateKey":keys().repaired_private_key}),
            );
            tokio::spawn(async move { request.send().await })
        } else {
            f.start_rotation(&data)
        };
        // A real PG wait proves the competing request reached the shared account lock.
        f.wait_for_database_wait("pg_stat_activity WHERE datname=current_database() AND wait_event='transactionid'")
            .await;
        assert!(!competing.is_finished());
        pause.release();
        assert_eq!(first.await.unwrap().unwrap().status(), StatusCode::OK);
        let result = competing.await.unwrap().unwrap();
        if competing_action == "delete" {
            assert_eq!(result.status(), StatusCode::OK);
        } else {
            assert!(!result.status().is_success());
        }
        assert_eq!(f.count("users WHERE akey='new-master-wrapper' AND private_key='new-account-private-wrapper'"), 1);
        assert_eq!(f.count("folders WHERE name='rotated-folder-wrapper'"), 1);
        assert_eq!(f.count("web_authn_credentials"), i64::from(competing_action != "delete"));
    }
}

#[cfg(feature = "postgresql")]
#[tokio::test]
#[ignore = "requires a disposable PostgreSQL instance; see tests/README.md"]
async fn passkey_postgres_cancelled_statement_rolls_back_and_retries() {
    let f = Fixture::new(true).await;
    let (data, _) = f.paused_rotation_data().await;
    let mut pause = PausedRotation::new(&f);
    let request = f.start_rotation(&data);
    f.wait_for_paused_rotation().await;
    // Target only the waiting statement in this test's generated database.
    f.sql("SELECT pg_cancel_backend(pid) FROM pg_locks WHERE database=(SELECT oid FROM pg_database WHERE datname=current_database()) AND locktype='advisory' AND objid=424242 AND NOT granted;");
    assert!(!request.await.unwrap().unwrap().status().is_success());
    f.assert_original_key_state();
    assert_eq!(f.get("/api/sync").await["userDecryption"]["webAuthnPrfOptions"].as_array().unwrap().len(), 1);
    pause.release();
    assert_eq!(f.post("/api/accounts/key-management/rotate-user-account-keys", data).await.status(), StatusCode::OK);
}

#[cfg(feature = "postgresql")]
#[tokio::test]
#[ignore = "requires a disposable PostgreSQL instance; see tests/README.md"]
async fn passkey_postgres_server_interruption_rolls_back_vault_and_keys() {
    let mut f = Fixture::new(true).await;
    let (data, _) = f.paused_rotation_data().await;
    let mut pause = PausedRotation::new(&f);
    let request = f.start_rotation(&data);
    f.wait_for_paused_rotation().await;
    f.process.kill().unwrap();
    f.process.wait().unwrap();
    assert!(request.await.unwrap().is_err());
    // PostgreSQL can finish a statement before noticing the client's closed socket.
    // Remove our artificial pause, then wait for all service sessions to exit;
    // there can be no client COMMIT after the server process has been killed.
    pause.release();
    drop(pause);
    let until = Instant::now() + Duration::from_secs(3);
    while f.count("pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid()") != 0 {
        assert!(Instant::now() < until);
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    f.assert_original_key_state();
}

#[tokio::test]
async fn passkey_native_registration_response_and_options_match_bitwarden() {
    let f = Fixture::new(true).await;
    let options = f.options().await;
    assert!(options["options"]["extensions"]["hmacCreateSecret"].is_null());
    let mut request = registration(&options, ORIGIN, true);
    // Match the pinned stock web DTO: standard-base64 rawId, empty client
    // extensions, and no transport hint (id itself stays base64url).
    let raw_id =
        data_encoding::BASE64URL_NOPAD.decode(request["deviceResponse"]["rawId"].as_str().unwrap().as_bytes()).unwrap();
    request["deviceResponse"]["rawId"] = json!(data_encoding::BASE64.encode(&raw_id));
    request["deviceResponse"]["extensions"] = json!({});
    request["deviceResponse"].as_object_mut().unwrap().remove("clientExtensionResults");
    request["deviceResponse"]["response"].as_object_mut().unwrap().remove("transports");
    let response = f.post("/api/webauthn", request).await;
    assert_eq!(response.status(), StatusCode::OK);
    let credential: Value = response.json().await.expect("native credential response JSON");
    assert_eq!(credential["object"], "webauthnCredential");
    assert_eq!(credential["name"], "Synthetic passkey");
    assert_eq!(credential["prfStatus"], 0);
    assert_eq!(credential["encryptedUserKey"], keys().initial.user_key);
    assert_eq!(credential["encryptedPublicKey"], keys().initial.public_key);
    assert!(credential.get("encryptedPrivateKey").is_none());
    assert!(
        f.get("/api/webauthn").await["data"][0] == credential,
        "keypair repair must preserve enabled passkey metadata"
    );
    assert_eq!(f.get("/api/sync").await["userDecryption"]["webAuthnPrfOptions"][0]["transports"], json!([]));
}

#[tokio::test]
async fn passkey_rejects_malformed_wrapped_keys_before_advertising_them() {
    let f = Fixture::new(true).await;
    for field in ["encryptedUserKey", "encryptedPublicKey", "encryptedPrivateKey"] {
        for invalid in [
            "plain text".to_owned(),
            "9.AAAA".to_owned(),
            "2.AA==|AA==|AA==".to_owned(),
            format!("4.{}", "A".repeat(2000)),
        ] {
            let options = f.options().await;
            let mut request = registration(&options, ORIGIN, true);
            request[field] = json!(invalid);
            assert_eq!(f.post("/api/webauthn", request).await.status(), StatusCode::BAD_REQUEST);
            assert_eq!(f.count("web_authn_credentials"), 0);
        }
    }
    assert!(f.get("/api/sync").await["userDecryption"]["webAuthnPrfOptions"].is_null());
}

#[tokio::test]
async fn passkey_excludes_registered_credentials_and_limits_enrollment_to_five() {
    let f = Fixture::new(true).await;
    let mut ids = Vec::new();
    for count in 0..5 {
        let options = f.options().await;
        let excluded = options["options"]["excludeCredentials"].as_array().unwrap();
        assert_eq!(excluded.len(), count);
        for id in &ids {
            assert!(excluded.iter().any(|item| &item["id"] == id));
        }
        let request = registration(&options, ORIGIN, true);
        ids.push(request["deviceResponse"]["rawId"].clone());
        assert_eq!(f.post("/api/webauthn", request).await.status(), StatusCode::OK);
    }
    assert_eq!(
        f.post("/api/webauthn/attestation-options", json!({"masterPasswordHash":PASSWORD})).await.status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(f.count("web_authn_credentials"), 5);
}

#[tokio::test]
async fn passkey_survives_account_keypair_repair_and_remains_in_rotation() {
    let f = Fixture::new(true).await;
    f.sql(&format!("UPDATE users SET private_key=NULL,public_key=NULL WHERE uuid='{}'", f.user));
    assert_eq!(
        f.post(
            "/api/accounts/keys",
            json!({"publicKey":keys().repaired_public_key,
        "encryptedPrivateKey":keys().original_account_private_key})
        )
        .await
        .status(),
        StatusCode::OK
    );
    let options = f.options().await;
    assert_eq!(f.post("/api/webauthn", registration(&options, ORIGIN, true)).await.status(), StatusCode::OK);
    let before = f.get("/api/sync").await["userDecryption"].clone();
    let credential = f.get("/api/webauthn").await["data"][0].clone();
    // Rewrapping the same account asymmetric pair changes ciphertext, but not
    // that pair or the user key. It must not hide an unchanged PRF keyset.
    let response = f
        .post(
            "/api/accounts/keys",
            json!({"publicKey":keys().repaired_public_key,
        "encryptedPrivateKey":keys().repaired_private_key}),
        )
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        f.get("/api/sync").await["userDecryption"] == before,
        "keypair repair must preserve both native unlock options"
    );
    assert!(
        f.get("/api/webauthn").await["data"][0] == credential,
        "keypair repair must preserve enabled passkey metadata"
    );

    let mut missing = rotate_request(&json!([]));
    missing["accountKeys"]["accountPublicKey"] = json!(keys().repaired_public_key);
    assert_eq!(
        f.post("/api/accounts/key-management/rotate-user-account-keys", missing).await.status(),
        StatusCode::BAD_REQUEST
    );
    let mut rotation = rotate_request(&json!([{"id":credential["id"],"encryptedUserKey":keys().rotated.user_key,
        "encryptedPublicKey":keys().rotated.public_key}]));
    rotation["accountKeys"]["accountPublicKey"] = json!(keys().repaired_public_key);
    assert_eq!(
        f.post("/api/accounts/key-management/rotate-user-account-keys", rotation).await.status(),
        StatusCode::OK
    );
    assert_eq!(
        f.count(&format!(
            "web_authn_credentials WHERE encrypted_user_key='{}' AND encrypted_private_key='{}'",
            keys().rotated.user_key,
            keys().initial.private_key
        )),
        1
    );
}

fn native_assertion(
    options: &Value,
    credential: &str,
    key: &openssl::ec::EcKey<openssl::pkey::Private>,
    user: &str,
    origin: &str,
    uv: bool,
) -> Value {
    let client =
        json!({"type":"webauthn.get","challenge":options["options"]["challenge"],"origin":origin,"crossOrigin":false});
    let client = serde_json::to_vec(&client).unwrap();
    let mut auth = openssl::sha::sha256(b"localhost").to_vec();
    auth.push(if uv {
        5
    } else {
        1
    });
    // Synced passkeys may always report zero; challenge consumption must still block replay.
    auth.extend(0u32.to_be_bytes());
    let key = openssl::pkey::PKey::from_ec_key(key.clone()).unwrap();
    let mut signer = openssl::sign::Signer::new(MessageDigest::sha256(), &key).unwrap();
    signer.update(&auth).unwrap();
    signer.update(&openssl::sha::sha256(&client)).unwrap();
    let encode = |b: &[u8]| data_encoding::BASE64URL_NOPAD.encode(b);
    let handle = uuid::Uuid::parse_str(user).unwrap();
    json!({"id":credential,"rawId":credential,"type":"public-key","extensions":{},
        "response":{"authenticatorData":encode(&auth),"clientDataJSON":encode(&client),
        "signature":encode(&signer.sign_to_vec().unwrap()),"userHandle":encode(handle.as_bytes())}})
}

#[tokio::test]
async fn native_passkey_login_uses_one_challenge_and_returns_prf_unlock() {
    let f = Fixture::with_policy(true, false).await;
    let registration_options = f.options().await;
    let (registration, key) = registration_with_key(&registration_options, ORIGIN, true);
    let credential = registration["deviceResponse"]["rawId"].as_str().unwrap().to_owned();
    assert_eq!(f.post("/api/webauthn", registration).await.status(), StatusCode::OK);
    let factor = uuid::Uuid::new_v4();
    f.sql(&format!(
        "INSERT INTO twofactor (uuid,user_uuid,atype,enabled,data,last_used) VALUES ('{factor}','{}',0,TRUE,'JBSWY3DPEHPK3PXP',0)",
        f.user
    ));
    let options: Value = f
        .client
        .get(format!("{}/identity/accounts/webauthn/assertion-options", f.url))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(options["options"]["userVerification"], "required");
    let response = native_assertion(&options, &credential, &key, &f.user, ORIGIN, true);
    let response = response.to_string();
    let token = options["token"].as_str().unwrap();
    let form = [
        ("grant_type", "webauthn"),
        ("scope", "api offline_access"),
        ("client_id", "web"),
        ("token", token),
        ("deviceResponse", response.as_str()),
        ("deviceIdentifier", f.device.as_str()),
        ("deviceName", "Synthetic browser"),
        ("deviceType", "14"),
    ];
    let first = f.client.post(format!("{}/identity/connect/token", f.url)).form(&form).send().await.unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    let result: Value = first.json().await.unwrap();
    assert!(result["access_token"].as_str().is_some_and(|v| !v.is_empty()));
    assert!(result["refresh_token"].as_str().is_some_and(|v| !v.is_empty()));
    assert_eq!(result["UserDecryptionOptions"]["WebAuthnPrfOption"]["EncryptedUserKey"], keys().initial.user_key);
    assert_eq!(f.count("twofactor WHERE atype=0"), 1);
    let second = f.client.post(format!("{}/identity/connect/token", f.url)).form(&form).send().await.unwrap();
    assert!(!second.status().is_success());
}

#[tokio::test]
async fn native_passkey_login_rejects_wrong_handle_origin_and_uv() {
    let f = Fixture::with_policy(true, false).await;
    let registration_options = f.options().await;
    let (registration, key) = registration_with_key(&registration_options, ORIGIN, true);
    let credential = registration["deviceResponse"]["rawId"].as_str().unwrap().to_owned();
    assert_eq!(f.post("/api/webauthn", registration).await.status(), StatusCode::OK);
    for case in 0..3 {
        let options: Value = f
            .client
            .get(format!("{}/identity/accounts/webauthn/assertion-options", f.url))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let origin = if case == 1 {
            "https://attacker.example"
        } else {
            ORIGIN
        };
        let mut response = native_assertion(&options, &credential, &key, &f.user, origin, case != 2);
        if case == 0 {
            response["response"]["userHandle"] =
                json!(data_encoding::BASE64URL_NOPAD.encode(uuid::Uuid::new_v4().as_bytes()));
        }
        let response = response.to_string();
        let form = [
            ("grant_type", "webauthn"),
            ("scope", "api offline_access"),
            ("client_id", "web"),
            ("token", options["token"].as_str().unwrap()),
            ("deviceResponse", response.as_str()),
            ("deviceIdentifier", f.device.as_str()),
            ("deviceName", "Synthetic browser"),
            ("deviceType", "14"),
        ];
        let result = f.client.post(format!("{}/identity/connect/token", f.url)).form(&form).send().await.unwrap();
        assert!(!result.status().is_success(), "case {case} unexpectedly authenticated");
    }
}

#[tokio::test]
async fn native_passkey_without_prf_keeps_master_password_unlock_and_refresh() {
    let f = Fixture::with_policy(true, false).await;
    let registration_options = f.options().await;
    let (mut registration, key) = registration_with_key(&registration_options, ORIGIN, true);
    let credential = registration["deviceResponse"]["rawId"].as_str().unwrap().to_owned();
    registration["supportsPrf"] = json!(false);
    for field in ["encryptedUserKey", "encryptedPublicKey", "encryptedPrivateKey"] {
        registration.as_object_mut().unwrap().remove(field);
    }
    assert_eq!(f.post("/api/webauthn", registration).await.status(), StatusCode::OK);
    let options: Value = f
        .client
        .get(format!("{}/identity/accounts/webauthn/assertion-options", f.url))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let response = native_assertion(&options, &credential, &key, &f.user, ORIGIN, true).to_string();
    let form = [
        ("grant_type", "webauthn"),
        ("scope", "api offline_access"),
        ("client_id", "web"),
        ("token", options["token"].as_str().unwrap()),
        ("deviceResponse", response.as_str()),
        ("deviceIdentifier", f.device.as_str()),
        ("deviceName", "Synthetic browser"),
        ("deviceType", "14"),
    ];
    let result: Value = f
        .client
        .post(format!("{}/identity/connect/token", f.url))
        .form(&form)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(result["UserDecryptionOptions"]["MasterPasswordUnlock"]["MasterKeyWrappedUserKey"], "synthetic-key");
    assert!(result["UserDecryptionOptions"].get("WebAuthnPrfOption").is_none());
    let refresh_token = result["refresh_token"].as_str().unwrap();
    let refresh: Value = f
        .client
        .post(format!("{}/identity/connect/token", f.url))
        .form(&[("grant_type", "refresh_token"), ("client_id", "web"), ("refresh_token", refresh_token)])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(refresh["access_token"].as_str().is_some_and(|v| !v.is_empty()));
}
