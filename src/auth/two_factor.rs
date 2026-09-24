use chrono::{TimeDelta, Utc};
use serde::{de::DeserializeOwned, ser::Serialize};
use std::sync::LazyLock;

use crate::{
    CONFIG,
    api::{ApiResult, EmptyResult},
    auth::{decode_jwt, encode_jwt},
    db::models::UserId,
};

static JWT_2FA_AUTH_ISSUER: LazyLock<String> = LazyLock::new(|| format!("{}|api.2fa", CONFIG.domain_origin()));

#[derive(Serialize, Deserialize)]
pub struct TwopFactorClaims<T> {
    // Not before
    pub nbf: i64,
    // Expiration time
    pub exp: i64,
    // Issuer
    pub iss: String,
    // Subject
    pub sub: UserId,

    pub enabled: bool,

    pub claims: T,
}

#[derive(Serialize, Deserialize)]
pub struct AuthenticatorClaims {
    pub key: String,
}

#[derive(Serialize, Deserialize)]
pub struct DuoClaims {
    data: Option<DuoData>,
}

#[derive(Serialize, Deserialize)]
pub struct WebauthnClaims {
    pub keys: Vec<i32>,
}

#[derive(Serialize, Deserialize)]
pub struct YubikeyClaims {
    pub keys: Vec<String>,
}

#[derive(Serialize, Deserialize, PartialEq)]
pub struct DuoData {
    pub host: String, // Duo API hostname
    pub ik: String,   // client id
    pub sk: String,   // client secret
}

impl DuoData {
    pub fn global() -> Option<Self> {
        match (CONFIG._enable_duo(), CONFIG.duo_host()) {
            (true, Some(host)) => Some(Self {
                host,
                ik: CONFIG.duo_ikey().unwrap(),
                sk: CONFIG.duo_skey().unwrap(),
            }),
            _ => None,
        }
    }
    pub fn msg(s: &str) -> Self {
        Self {
            host: s.into(),
            ik: s.into(),
            sk: s.into(),
        }
    }
    pub fn secret() -> Self {
        Self::msg("<global_secret>")
    }
    pub fn obscure(self) -> Self {
        let mut host = self.host;
        let mut ik = self.ik;
        let mut sk = self.sk;

        let digits = 4;
        let replaced = "************";

        host.replace_range(digits.., replaced);
        ik.replace_range(digits.., replaced);
        sk.replace_range(digits.., replaced);

        Self {
            host,
            ik,
            sk,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct EmailClaims {
    pub email: Option<String>,
}

fn token<T: Serialize>(user_id: UserId, enabled: bool, claims: T) -> String {
    let time_now = Utc::now();
    let claims = TwopFactorClaims {
        nbf: time_now.timestamp(),
        exp: (time_now + TimeDelta::try_minutes(5).unwrap()).timestamp(),
        iss: JWT_2FA_AUTH_ISSUER.to_string(),
        sub: user_id,
        enabled,
        claims,
    };
    encode_jwt(&claims)
}

fn validate<T: DeserializeOwned>(token: &str, user_id: &UserId, enabled: bool) -> ApiResult<T> {
    match decode_jwt::<TwopFactorClaims<T>>(token, JWT_2FA_AUTH_ISSUER.to_string()) {
        Ok(claims) => {
            if claims.sub != *user_id {
                err!("Invalid verification token: Invalid user");
            }
            if claims.enabled != enabled {
                err!("Invalid verification token: Invalid state");
            }
            Ok(claims.claims)
        }
        Err(err) => err!(format!("Failed to decode verification token: {err}")),
    }
}

pub fn authenticator_token(user_id: UserId, key: String, enabled: bool) -> String {
    token(
        user_id,
        enabled,
        AuthenticatorClaims {
            key,
        },
    )
}

pub fn validate_authenticator(token: &str, user_id: &UserId, key: &str, enabled: bool) -> EmptyResult {
    let claims = validate::<AuthenticatorClaims>(token, user_id, enabled)?;
    if claims.key != key {
        err!("Invalid verification token: Invalid key");
    }
    Ok(())
}

pub fn duo_token(user_id: UserId, data: Option<DuoData>, enabled: bool) -> String {
    token(
        user_id,
        enabled,
        DuoClaims {
            data,
        },
    )
}

// When disabling we check that it's the correct data
pub fn validate_duo(token: &str, user_id: &UserId, data: Option<&DuoData>, enabled: bool) -> EmptyResult {
    let claims = validate::<DuoClaims>(token, user_id, enabled)?;
    if enabled && claims.data.as_ref() != data {
        err!("Invalid verification token: Invalid duo data");
    }
    Ok(())
}

pub fn email_token(user_id: UserId, email: Option<String>, enabled: bool) -> String {
    token(
        user_id,
        enabled,
        EmailClaims {
            email,
        },
    )
}

// When disabling we check that it's the correct `email`
pub fn validate_email(token: &str, user_id: &UserId, email: String, enabled: bool) -> EmptyResult {
    let claims = validate::<EmailClaims>(token, user_id, enabled)?;
    if enabled && claims.email != Some(email) {
        err!("Invalid verification token: Invalid email");
    }
    Ok(())
}

pub fn webauthn_token(user_id: UserId, keys: Vec<i32>, enabled: bool) -> String {
    token(
        user_id,
        enabled,
        WebauthnClaims {
            keys,
        },
    )
}

pub fn validate_webauthn(token: &str, user_id: &UserId, keys: &[i32], enabled: bool) -> EmptyResult {
    let claims = validate::<WebauthnClaims>(token, user_id, enabled)?;
    if keys != claims.keys {
        err!("Invalid verification token: Invalid keys");
    }
    Ok(())
}

pub fn yubikey_token(user_id: UserId, keys: Vec<String>, enabled: bool) -> String {
    token(
        user_id,
        enabled,
        YubikeyClaims {
            keys,
        },
    )
}

pub fn validate_yubikey(token: &str, user_id: &UserId, keys: &Vec<String>, enabled: bool) -> EmptyResult {
    let claims = validate::<YubikeyClaims>(token, user_id, enabled)?;
    if *keys != claims.keys {
        err!("Invalid verification token: Invalid keys");
    }
    Ok(())
}
