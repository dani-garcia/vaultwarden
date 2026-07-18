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
    pub external_id: Option<String>,
}

// Attributes Entra maps by default but Vaultwarden does not sync after
// creation. Accepted and ignored (RFC 7644 allows a service provider to
// treat immutable-for-it attributes this way in practice), because a 400
// here would surface as a sync error on every rename in the directory.
// user.name is global to the person across organizations; an org-scoped
// provisioning channel must not rewrite it.
fn is_ignored_user_attribute(path: &str) -> bool {
    let lower = path.to_lowercase();
    lower == "displayname"
        || lower == "name"
        || lower.starts_with("name.")
        || lower == "emails"
        || lower.starts_with("emails[")
        || lower == "username"
        || lower == "title"
        || lower == "roles"
        || lower == "preferredlanguage"
        || lower.starts_with("addresses")
        || lower.starts_with("phonenumbers")
        || lower.starts_with("urn:ietf:params:scim:schemas:extension:enterprise:2.0:user")
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
            Some(op_path) if op_path.eq_ignore_ascii_case("externalid") => {
                let Some(Value::String(external_id)) = operation.value.as_ref() else {
                    return Err(ScimError::bad_request("invalidValue", "externalId must be a string"));
                };
                result.external_id = Some(external_id.clone());
            }
            Some(op_path) if is_ignored_user_attribute(op_path) => {}
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
                    } else if attribute.eq_ignore_ascii_case("externalid") {
                        let Value::String(external_id) = value else {
                            return Err(ScimError::bad_request("invalidValue", "externalId must be a string"));
                        };
                        result.external_id = Some(external_id.clone());
                    } else if is_ignored_user_attribute(attribute) {
                        // Accepted, not synced; see is_ignored_user_attribute.
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
    fn entra_mapped_attributes_are_accepted_and_ignored() {
        for path in ["displayName", "name.givenName", "emails[type eq \"work\"].value", "title", "roles"] {
            let parsed = patch(json!({
                "schemas": [PATCH_OP_URN],
                "Operations": [
                    {"op": "replace", "path": path, "value": "whatever"},
                    {"op": "replace", "path": "active", "value": true},
                ],
            }))
            .unwrap_or_else(|_| panic!("path {path} must be ignored, not rejected"));
            assert_eq!(parsed.active, Some(true));
        }
    }

    #[test]
    fn externalid_patch_both_forms() {
        let parsed = patch(json!({
            "schemas": [PATCH_OP_URN],
            "Operations": [{"op": "replace", "path": "externalId", "value": "new-ext-1"}],
        }))
        .expect("valid");
        assert_eq!(parsed.external_id.as_deref(), Some("new-ext-1"));

        let parsed = patch(json!({
            "schemas": [PATCH_OP_URN],
            "Operations": [{"op": "replace", "value": {"externalId": "new-ext-2", "displayName": "ignored"}}],
        }))
        .expect("valid");
        assert_eq!(parsed.external_id.as_deref(), Some("new-ext-2"));
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
                json!({"schemas": [PATCH_OP_URN], "Operations": [{"op": "replace", "path": "wibble", "value": "x"}]}),
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

// ---------------------------------------------------------------------------
// Group PATCH
// ---------------------------------------------------------------------------

// What a Group PATCH asked for, after normalization. Member values are
// MembershipIds (the SCIM User id).
#[derive(Debug, Default, PartialEq)]
pub struct GroupPatch {
    pub display_name: Option<String>,
    pub external_id: Option<String>,
    pub add_members: Vec<String>,
    pub remove_members: Vec<String>,
    // Some(list) means full replacement of the member set.
    pub replace_members: Option<Vec<String>>,
}

// Entra removes single members with a filter path instead of a value list:
//     {"op": "Remove", "path": "members[value eq \"<id>\"]"}
// (the value-array form is only sent by apps created with the
// aadOptscim062020 feature flag). Both forms must work.
fn parse_members_filter_path(path: &str) -> Option<String> {
    let inner = path.strip_prefix("members[")?.strip_suffix(']')?;
    let (attribute, rest) = inner.split_once(char::is_whitespace)?;
    if !attribute.eq_ignore_ascii_case("value") {
        return None;
    }
    let (operator, rest) = rest.trim_start().split_once(char::is_whitespace)?;
    if !operator.eq_ignore_ascii_case("eq") {
        return None;
    }
    let value = rest.trim().strip_prefix('"')?.strip_suffix('"')?;
    if value.is_empty() {
        return None;
    }
    Some(value.to_owned())
}

// Extracts member ids from a PATCH value: either [{"value": "id"}, ...] or a
// single {"value": "id"} object.
fn member_values(value: Option<&Value>) -> Result<Vec<String>, ScimError> {
    let invalid = || ScimError::bad_request("invalidValue", "members value must be an array of {value} objects");
    let items: Vec<&Value> = match value {
        Some(Value::Array(items)) => items.iter().collect(),
        Some(single @ Value::Object(_)) => vec![single],
        _ => return Err(invalid()),
    };
    let mut ids = Vec::with_capacity(items.len());
    for item in items {
        let Some(Value::String(id)) = item.get("value") else {
            return Err(invalid());
        };
        ids.push(id.clone());
    }
    Ok(ids)
}

pub fn parse_group_patch(patch: &PatchOp) -> Result<GroupPatch, ScimError> {
    if !patch.schemas.iter().any(|s| s == PATCH_OP_URN) {
        return Err(ScimError::bad_request("invalidValue", "Missing PatchOp schema"));
    }
    if patch.operations.is_empty() {
        return Err(ScimError::bad_request("invalidValue", "No operations provided"));
    }

    let mut result = GroupPatch::default();

    for operation in &patch.operations {
        let op = operation.op.to_lowercase();
        match operation.path.as_deref() {
            Some(op_path) if op_path.eq_ignore_ascii_case("members") => match op.as_str() {
                "add" => result.add_members.append(&mut member_values(operation.value.as_ref())?),
                "remove" => result.remove_members.append(&mut member_values(operation.value.as_ref())?),
                "replace" => {
                    result
                        .replace_members
                        .get_or_insert_with(Vec::new)
                        .append(&mut member_values(operation.value.as_ref())?);
                }
                _ => return Err(ScimError::bad_request("invalidValue", "Unsupported operation on members")),
            },
            Some(op_path) if op_path.to_lowercase().starts_with("members[") => {
                let Some(member_id) = parse_members_filter_path(op_path) else {
                    return Err(ScimError::bad_request("invalidPath", "Unsupported members filter path"));
                };
                match op.as_str() {
                    // Entra's single-member removal form.
                    "remove" => result.remove_members.push(member_id),
                    "add" | "replace" => result.add_members.push(member_id),
                    _ => return Err(ScimError::bad_request("invalidValue", "Unsupported operation on members")),
                }
            }
            Some(op_path) if op_path.eq_ignore_ascii_case("displayname") => {
                let Some(Value::String(name)) = operation.value.as_ref() else {
                    return Err(ScimError::bad_request("invalidValue", "displayName must be a string"));
                };
                result.display_name = Some(name.clone());
            }
            Some(op_path) if op_path.eq_ignore_ascii_case("externalid") => {
                let Some(Value::String(external_id)) = operation.value.as_ref() else {
                    return Err(ScimError::bad_request("invalidValue", "externalId must be a string"));
                };
                result.external_id = Some(external_id.clone());
            }
            Some(_) => return Err(ScimError::bad_request("invalidPath", "Unsupported patch path for Groups")),
            None => {
                let Some(Value::Object(map)) = operation.value.as_ref() else {
                    return Err(ScimError::bad_request(
                        "invalidValue",
                        "Operation without path must carry an object value",
                    ));
                };
                for (attribute, value) in map {
                    if attribute.eq_ignore_ascii_case("displayname") {
                        let Value::String(name) = value else {
                            return Err(ScimError::bad_request("invalidValue", "displayName must be a string"));
                        };
                        result.display_name = Some(name.clone());
                    } else if attribute.eq_ignore_ascii_case("externalid") {
                        let Value::String(external_id) = value else {
                            return Err(ScimError::bad_request("invalidValue", "externalId must be a string"));
                        };
                        result.external_id = Some(external_id.clone());
                    } else if attribute.eq_ignore_ascii_case("members") {
                        match op.as_str() {
                            "add" => result.add_members.append(&mut member_values(Some(value))?),
                            "remove" => result.remove_members.append(&mut member_values(Some(value))?),
                            "replace" => {
                                result
                                    .replace_members
                                    .get_or_insert_with(Vec::new)
                                    .append(&mut member_values(Some(value))?);
                            }
                            _ => {
                                return Err(ScimError::bad_request("invalidValue", "Unsupported operation on members"));
                            }
                        }
                    } else {
                        return Err(ScimError::bad_request("invalidPath", "Unsupported patch attribute for Groups"));
                    }
                }
            }
        }
    }

    Ok(result)
}

#[cfg(test)]
mod group_tests {
    use super::*;

    fn patch(payload: Value) -> Result<GroupPatch, ScimError> {
        let parsed: PatchOp = serde_json::from_value(payload).expect("valid PatchOp json");
        parse_group_patch(&parsed)
    }

    #[test]
    fn add_and_remove_member_value_lists() {
        let parsed = patch(json!({
            "schemas": [PATCH_OP_URN],
            "Operations": [
                {"op": "Add", "path": "members", "value": [{"value": "member-1"}, {"value": "member-2"}]},
                {"op": "remove", "path": "members", "value": [{"value": "member-3"}]},
            ],
        }))
        .expect("valid");
        assert_eq!(parsed.add_members, vec!["member-1", "member-2"]);
        assert_eq!(parsed.remove_members, vec!["member-3"]);
    }

    #[test]
    fn entra_filter_path_removal() {
        let parsed = patch(json!({
            "schemas": [PATCH_OP_URN],
            "Operations": [{"op": "Remove", "path": "members[value eq \"member-9\"]"}],
        }))
        .expect("valid");
        assert_eq!(parsed.remove_members, vec!["member-9"]);
    }

    #[test]
    fn replace_members_and_rename() {
        let parsed = patch(json!({
            "schemas": [PATCH_OP_URN],
            "Operations": [
                {"op": "replace", "path": "members", "value": [{"value": "only-member"}]},
                {"op": "replace", "path": "displayName", "value": "New Group Name"},
            ],
        }))
        .expect("valid");
        assert_eq!(parsed.replace_members.as_deref(), Some(&["only-member".to_owned()][..]));
        assert_eq!(parsed.display_name.as_deref(), Some("New Group Name"));
    }

    #[test]
    fn group_patch_rejects_garbage() {
        for (payload, expected_type) in [
            (
                json!({"schemas": [PATCH_OP_URN], "Operations": [{"op": "remove", "path": "members[display eq \"x\"]"}]}),
                "invalidPath",
            ),
            (
                json!({"schemas": [PATCH_OP_URN], "Operations": [{"op": "add", "path": "members", "value": ["bare-string"]}]}),
                "invalidValue",
            ),
            (
                json!({"schemas": [PATCH_OP_URN], "Operations": [{"op": "add", "path": "wibble", "value": 1}]}),
                "invalidPath",
            ),
        ] {
            match patch(payload.clone()) {
                Err(e) => assert_eq!(e.scim_type, Some(expected_type), "wrong scimType for {payload}"),
                Ok(p) => panic!("group patch {payload} unexpectedly parsed to {p:?}"),
            }
        }
    }
}
