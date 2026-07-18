//
// Serde models for SCIM request bodies, RFC 7643.
//
// Deliberately NOT #[serde(deny_unknown_fields)]: RFC 7643 section 2.1
// requires service providers to ignore attributes they do not recognize, and
// Entra sends several (addresses, phoneNumbers, preferredLanguage, ...).
//
use serde::Deserialize;
use serde_json::Value;

// Entra sometimes sends booleans as strings ("True"/"False"), particularly in
// PATCH values. Accept both without losing strictness for other types.
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(try_from = "Value")]
pub struct ScimBool(pub bool);

impl TryFrom<Value> for ScimBool {
    type Error = String;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        match value {
            Value::Bool(b) => Ok(ScimBool(b)),
            Value::String(s) => match s.to_lowercase().as_str() {
                "true" => Ok(ScimBool(true)),
                "false" => Ok(ScimBool(false)),
                _ => Err(format!("not a boolean: {s:?}")),
            },
            other => Err(format!("not a boolean: {other}")),
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimName {
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub formatted: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimEmail {
    pub value: String,
    #[serde(default)]
    pub primary: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimUserRequest {
    pub user_name: Option<String>,
    pub external_id: Option<String>,
    pub display_name: Option<String>,
    pub name: Option<ScimName>,
    #[serde(default)]
    pub emails: Vec<ScimEmail>,
    pub active: Option<ScimBool>,
}

impl ScimUserRequest {
    // Entra maps userName to the login identifier; some tenants map the
    // routable address only into emails[]. Prefer userName when it looks like
    // an email, else fall back to the primary (or first) email value.
    pub fn email(&self) -> Option<&str> {
        let user_name = self.user_name.as_deref().filter(|v| v.contains('@'));
        let from_emails =
            self.emails.iter().find(|e| e.primary).or_else(|| self.emails.first()).map(|e| e.value.as_str());
        user_name.or(from_emails)
    }

    // Compose a display name the way the web vault shows members.
    pub fn display_name(&self) -> Option<String> {
        if let Some(display_name) = &self.display_name {
            return Some(display_name.clone());
        }
        if let Some(name) = &self.name {
            if let Some(formatted) = &name.formatted {
                return Some(formatted.clone());
            }
            let composed = match (&name.given_name, &name.family_name) {
                (Some(given), Some(family)) => Some(format!("{given} {family}")),
                (Some(given), None) => Some(given.clone()),
                (None, Some(family)) => Some(family.clone()),
                (None, None) => None,
            };
            return composed;
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scim_bool_coerces_entra_strings() {
        for (raw, expected) in [
            (json!(true), true),
            (json!(false), false),
            (json!("True"), true),
            (json!("true"), true),
            (json!("FALSE"), false),
            (json!("false"), false),
        ] {
            let b: ScimBool = serde_json::from_value(raw).expect("coercible");
            assert_eq!(b.0, expected);
        }
        for bad in [json!("yes"), json!(1), json!(null), json!({})] {
            assert!(serde_json::from_value::<ScimBool>(bad).is_err());
        }
    }

    #[test]
    fn email_prefers_username_then_primary_email() {
        let parsed: ScimUserRequest = serde_json::from_value(json!({
            "userName": "user@example.com",
            "emails": [{"value": "other@example.com", "primary": true}],
        }))
        .expect("valid");
        assert_eq!(parsed.email(), Some("user@example.com"));

        // Non-email userName (a bare UPN-less identifier) falls back to emails.
        let parsed: ScimUserRequest = serde_json::from_value(json!({
            "userName": "just-an-id",
            "emails": [{"value": "second@example.com"}, {"value": "first@example.com", "primary": true}],
        }))
        .expect("valid");
        assert_eq!(parsed.email(), Some("first@example.com"));

        let parsed: ScimUserRequest = serde_json::from_value(json!({})).expect("valid");
        assert_eq!(parsed.email(), None);
    }

    #[test]
    fn display_name_composition() {
        let parsed: ScimUserRequest = serde_json::from_value(json!({
            "name": {"givenName": "Ada", "familyName": "Lovelace"},
        }))
        .expect("valid");
        assert_eq!(parsed.display_name().as_deref(), Some("Ada Lovelace"));

        let parsed: ScimUserRequest = serde_json::from_value(json!({
            "displayName": "Display Wins",
            "name": {"formatted": "Formatted Loses"},
        }))
        .expect("valid");
        assert_eq!(parsed.display_name().as_deref(), Some("Display Wins"));

        // Unknown attributes are ignored per RFC 7643 section 2.1.
        let parsed: ScimUserRequest = serde_json::from_value(json!({
            "userName": "a@b.com",
            "preferredLanguage": "en-US",
            "addresses": [],
        }))
        .expect("unknown attrs must not fail");
        assert_eq!(parsed.email(), Some("a@b.com"));
    }
}
