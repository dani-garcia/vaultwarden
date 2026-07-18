//
// SCIM PatchOp parsing, RFC 7644 section 3.5.2, restricted to what the User
// endpoints support. Entra quirks handled here, all observed in real syncs:
//   - "op" arrives with any casing ("Replace", "Add").
//   - boolean values may arrive as strings ("True"/"False").
//   - an operation may have no "path", carrying a value object instead
//     ({"op":"replace","value":{"active":false}}).
//
use serde::Deserialize;
use serde_json::Value;

use crate::api::scim::{error::ScimError, models::ScimBool};

pub const PATCH_OP_URN: &str = "urn:ietf:params:scim:api:messages:2.0:PatchOp";

#[derive(Debug, Deserialize)]
pub struct PatchOp {
    #[serde(default)]
    pub schemas: Vec<String>,
    #[serde(rename = "Operations", default)]
    pub operations: Vec<PatchOperation>,
}

#[derive(Debug, Deserialize)]
pub struct PatchOperation {
    pub op: String,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub value: Option<Value>,
}

// What a User PATCH asked for, after normalization.
#[derive(Debug, Default, PartialEq)]
pub struct UserPatch {
    pub active: Option<bool>,
}

pub fn parse_user_patch(patch: &PatchOp) -> Result<UserPatch, ScimError> {
    if !patch.schemas.iter().any(|s| s == PATCH_OP_URN) {
        return Err(ScimError::bad_request("invalidValue", "Missing PatchOp schema"));
    }
    if patch.operations.is_empty() {
        return Err(ScimError::bad_request("invalidValue", "No operations provided"));
    }

    let mut result = UserPatch::default();

    for operation in &patch.operations {
        let op = operation.op.to_lowercase();
        if op != "replace" && op != "add" {
            return Err(ScimError::bad_request(
                "invalidValue",
                "Only add and replace operations are supported for Users",
            ));
        }

        match operation.path.as_deref() {
            Some(op_path) if op_path.eq_ignore_ascii_case("active") => {
                let value = operation.value.clone().unwrap_or(Value::Null);
                result.active = Some(coerce_bool(value)?);
            }
            Some(_) => {
                return Err(ScimError::bad_request("invalidPath", "Unsupported patch path"));
            }
            None => {
                // Path-less form: the value is an object of attribute => value.
                let Some(Value::Object(map)) = operation.value.as_ref() else {
                    return Err(ScimError::bad_request(
                        "invalidValue",
                        "Operation without path must carry an object value",
                    ));
                };
                for (attribute, value) in map {
                    if attribute.eq_ignore_ascii_case("active") {
                        result.active = Some(coerce_bool(value.clone())?);
                    } else {
                        return Err(ScimError::bad_request("invalidPath", "Unsupported patch attribute"));
                    }
                }
            }
        }
    }

    Ok(result)
}

fn coerce_bool(value: Value) -> Result<bool, ScimError> {
    serde_json::from_value::<ScimBool>(value)
        .map(|b| b.0)
        .map_err(|_| ScimError::bad_request("invalidValue", "Expected a boolean value for active"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn patch(payload: Value) -> Result<UserPatch, ScimError> {
        let parsed: PatchOp = serde_json::from_value(payload).expect("valid PatchOp json");
        parse_user_patch(&parsed)
    }

    fn ok_active(payload: Value) -> Option<bool> {
        patch(payload).expect("expected parse to succeed").active
    }

    #[test]
    fn replace_active_with_path() {
        let active = ok_active(json!({
            "schemas": [PATCH_OP_URN],
            "Operations": [{"op": "replace", "path": "active", "value": false}],
        }));
        assert_eq!(active, Some(false));
    }

    #[test]
    fn entra_casing_and_string_bool() {
        let active = ok_active(json!({
            "schemas": [PATCH_OP_URN],
            "Operations": [{"op": "Replace", "path": "active", "value": "False"}],
        }));
        assert_eq!(active, Some(false));
    }

    #[test]
    fn pathless_value_object() {
        let active = ok_active(json!({
            "schemas": [PATCH_OP_URN],
            "Operations": [{"op": "replace", "value": {"active": "True"}}],
        }));
        assert_eq!(active, Some(true));
    }

    #[test]
    fn rejects_bad_patches() {
        for (payload, expected_type) in [
            (
                json!({"schemas": [], "Operations": [{"op": "replace", "path": "active", "value": true}]}),
                "invalidValue",
            ),
            (json!({"schemas": [PATCH_OP_URN], "Operations": []}), "invalidValue"),
            (json!({"schemas": [PATCH_OP_URN], "Operations": [{"op": "remove", "path": "active"}]}), "invalidValue"),
            (
                json!({"schemas": [PATCH_OP_URN], "Operations": [{"op": "replace", "path": "displayName", "value": "x"}]}),
                "invalidPath",
            ),
            (
                json!({"schemas": [PATCH_OP_URN], "Operations": [{"op": "replace", "path": "active", "value": "maybe"}]}),
                "invalidValue",
            ),
            (json!({"schemas": [PATCH_OP_URN], "Operations": [{"op": "replace", "value": 3}]}), "invalidValue"),
        ] {
            match patch(payload.clone()) {
                Err(e) => assert_eq!(e.scim_type, Some(expected_type), "wrong scimType for {payload}"),
                Ok(p) => panic!("patch {payload} unexpectedly parsed to {p:?}"),
            }
        }
    }
}
