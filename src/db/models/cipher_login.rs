use serde_json::{Map, Value};

use crate::util::validate_and_format_date;

/// Bitwarden SDK 3.x `Fido2Credential` deserializes with `deny_unknown_fields`.
/// Official Bitwarden projects login FIDO2 objects onto this allowlist;
/// echoing unknown keys makes iOS Autofill `get_assertion` fail as
/// `Ctap2(Vendor(VendorError(240)))` (SDK maps `find_credentials` errors to 0xF0).
const FIDO2_CREDENTIAL_KEYS: &[&str] = &[
    "credentialId",
    "keyType",
    "keyAlgorithm",
    "keyCurve",
    "keyValue",
    "rpId",
    "userHandle",
    "userName",
    "counter",
    "rpName",
    "userDisplayName",
    "discoverable",
    "creationDate",
];

const LOGIN_URI_KEYS: &[&str] = &["uri", "match", "uriChecksum"];

/// Normalize a login cipher `data` object for client/SDK consumption.
pub fn normalize_login_type_data(mut data: Value) -> Value {
    if !data.is_object() {
        return data;
    }

    // Official Bitwarden uses a nullable array. SDK `has_fido2` is
    // `fido2_credentials.is_some()`, so `[]` would mark every login as a passkey.
    let fido2 = match data.get("fido2Credentials") {
        Some(Value::Array(creds)) if !creds.is_empty() && creds.iter().all(Value::is_object) => {
            Value::Array(creds.iter().map(normalize_fido2_credential).collect())
        }
        _ => Value::Null,
    };
    data["fido2Credentials"] = fido2;

    if data.get("autofillOnPageLoad").is_none() {
        data["autofillOnPageLoad"] = Value::Null;
    }

    if let Some(Value::Array(uris)) = data.get_mut("uris") {
        for uri in uris.iter_mut() {
            *uri = project_object_keys(uri, LOGIN_URI_KEYS);
        }
    }

    data
}

const EPOCH_RFC3339: &str = "1970-01-01T00:00:00.000000Z";

fn normalize_fido2_credential(cred: &Value) -> Value {
    let mut projected = project_object_keys(cred, FIDO2_CREDENTIAL_KEYS);
    let creation = match projected.get("creationDate") {
        Some(Value::String(raw)) => validate_and_format_date(raw),
        _ => EPOCH_RFC3339.to_owned(),
    };
    projected["creationDate"] = Value::String(creation);
    projected
}

fn project_object_keys(value: &Value, allow: &[&str]) -> Value {
    let Some(obj) = value.as_object() else {
        return value.clone();
    };
    let mut out = Map::new();
    for key in allow {
        if let Some(v) = obj.get(*key) {
            out.insert((*key).to_owned(), v.clone());
        }
    }
    Value::Object(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn missing_fido2_credentials_becomes_null() {
        let out = normalize_login_type_data(json!({
            "username": "enc",
            "password": "enc"
        }));
        assert_eq!(out["fido2Credentials"], Value::Null);
        assert_eq!(out["autofillOnPageLoad"], Value::Null);
    }

    #[test]
    fn strips_unknown_fido2_keys_that_break_ios_sdk() {
        let out = normalize_login_type_data(json!({
            "fido2Credentials": [{
                "credentialId": "enc-id",
                "keyType": "enc-type",
                "keyAlgorithm": "enc-alg",
                "keyCurve": "enc-curve",
                "keyValue": "enc-key",
                "rpId": "enc-rp",
                "counter": "enc-counter",
                "discoverable": "enc-disc",
                "creationDate": "2024-06-07T14:12:36.150Z",
                "prf": {"enabled": true},
                "transports": ["internal"],
                "backupEligible": true
            }]
        }));
        let cred = &out["fido2Credentials"][0];
        assert_eq!(cred["credentialId"], "enc-id");
        assert_eq!(cred["keyValue"], "enc-key");
        assert!(cred.get("prf").is_none(), "unknown keys must be stripped for SDK deny_unknown_fields");
        assert!(cred.get("transports").is_none());
        assert!(cred.get("backupEligible").is_none());
    }

    #[test]
    fn normalizes_fido2_creation_date_to_rfc3339() {
        let out = normalize_login_type_data(json!({
            "fido2Credentials": [{
                "credentialId": "enc-id",
                "creationDate": "2024-06-07T14:12:36.150Z"
            }]
        }));
        assert_eq!(out["fido2Credentials"][0]["creationDate"], "2024-06-07T14:12:36.150000Z");
    }

    #[test]
    fn strips_unknown_uri_keys() {
        let out = normalize_login_type_data(json!({
            "uris": [{
                "uri": "enc-uri",
                "match": 0,
                "uriChecksum": "enc-cs",
                "extra": "nope"
            }]
        }));
        let uri = &out["uris"][0];
        assert_eq!(uri["uri"], "enc-uri");
        assert_eq!(uri["match"], 0);
        assert_eq!(uri["uriChecksum"], "enc-cs");
        assert!(uri.get("extra").is_none());
    }

    #[test]
    fn null_fido2_credentials_stays_null() {
        let out = normalize_login_type_data(json!({
            "fido2Credentials": null
        }));
        assert_eq!(out["fido2Credentials"], Value::Null);
    }

    #[test]
    fn stored_empty_fido2_array_becomes_null() {
        let out = normalize_login_type_data(json!({
            "fido2Credentials": []
        }));
        assert_eq!(out["fido2Credentials"], Value::Null);
    }

    #[test]
    fn malformed_stored_fido2_credentials_become_null() {
        let out = normalize_login_type_data(json!({
            "fido2Credentials": [7]
        }));
        assert_eq!(out["fido2Credentials"], Value::Null);
    }

    #[test]
    fn missing_creation_date_defaults_to_epoch() {
        let out = normalize_login_type_data(json!({
            "fido2Credentials": [{
                "credentialId": "enc-id"
            }]
        }));
        assert_eq!(out["fido2Credentials"][0]["creationDate"], EPOCH_RFC3339);
    }

    #[test]
    fn non_string_creation_date_defaults_to_epoch() {
        let out = normalize_login_type_data(json!({
            "fido2Credentials": [{
                "credentialId": "enc-id",
                "creationDate": 1717769556
            }]
        }));
        assert_eq!(out["fido2Credentials"][0]["creationDate"], EPOCH_RFC3339);
    }

    #[test]
    fn non_object_login_data_is_unchanged() {
        assert_eq!(normalize_login_type_data(Value::Null), Value::Null);
        assert_eq!(normalize_login_type_data(json!([])), json!([]));
    }

    #[test]
    fn normalize_is_idempotent_for_sdk_shaped_credentials() {
        let input = json!({
            "username": "enc",
            "fido2Credentials": [{
                "credentialId": "enc-id",
                "keyType": "enc-type",
                "keyAlgorithm": "enc-alg",
                "keyCurve": "enc-curve",
                "keyValue": "enc-key",
                "rpId": "enc-rp",
                "userHandle": "enc-uh",
                "userName": "enc-un",
                "counter": "enc-c",
                "rpName": "enc-rn",
                "userDisplayName": "enc-dn",
                "discoverable": "enc-d",
                "creationDate": "2024-06-07T14:12:36.150000Z"
            }],
            "autofillOnPageLoad": false
        });
        let once = normalize_login_type_data(input.clone());
        let twice = normalize_login_type_data(once.clone());
        assert_eq!(once, twice);
        assert_eq!(once["fido2Credentials"][0].as_object().unwrap().len(), 13);
    }
}
