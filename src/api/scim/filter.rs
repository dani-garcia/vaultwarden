//
// Minimal SCIM filter parser, RFC 7644 section 3.4.2.2.
//
// Only the form Entra uses for existence checks is supported:
//     attribute eq "value"
// Anything else (and/or, co, sw, grouping, valuePath) is rejected with
// scimType invalidFilter. That is the correct signal for a partially
// supported filter grammar; 501 would claim filtering is entirely absent.
//
use crate::api::scim::error::ScimError;

#[derive(Debug, PartialEq, Eq)]
pub struct EqFilter {
    // Lowercased: SCIM attribute names are case-insensitive (RFC 7643 s2.1).
    pub attribute: String,
    pub value: String,
}

pub fn parse_eq_filter(raw: &str) -> Result<EqFilter, ScimError> {
    let unsupported =
        || ScimError::bad_request("invalidFilter", "Only filters of the form `attr eq \"value\"` are supported");

    let trimmed = raw.trim();
    // Split "attr eq "value"" on whitespace, keeping the quoted tail intact.
    let (attribute, rest) = trimmed.split_once(char::is_whitespace).ok_or_else(unsupported)?;
    let rest = rest.trim_start();
    let (operator, rest) = rest.split_once(char::is_whitespace).ok_or_else(unsupported)?;
    if !operator.eq_ignore_ascii_case("eq") {
        return Err(unsupported());
    }

    let quoted = rest.trim();
    let value = quoted.strip_prefix('"').and_then(|v| v.strip_suffix('"')).ok_or_else(unsupported)?;
    if value.contains('"') || attribute.is_empty() || value.is_empty() {
        return Err(unsupported());
    }

    Ok(EqFilter {
        attribute: attribute.to_lowercase(),
        value: value.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(raw: &str) -> Result<EqFilter, ScimError> {
        parse_eq_filter(raw)
    }

    #[test]
    fn parses_username_eq() {
        let f = parse("userName eq \"john@example.com\"").expect("valid filter");
        assert_eq!(f.attribute, "username");
        assert_eq!(f.value, "john@example.com");
    }

    #[test]
    fn parses_externalid_eq_case_insensitive_attr_and_op() {
        let f = parse("ExternalId EQ \"abc-123\"").expect("valid filter");
        assert_eq!(f.attribute, "externalid");
        assert_eq!(f.value, "abc-123");
    }

    #[test]
    fn value_may_contain_spaces() {
        let f = parse("displayName eq \"Jane van Der Berg\"").expect("valid filter");
        assert_eq!(f.value, "Jane van Der Berg");
    }

    #[test]
    fn rejects_unsupported_grammar() {
        for raw in [
            "",
            "userName",
            "userName eq",
            "userName eq unquoted",
            "userName co \"x\"",
            "userName sw \"x\"",
            "userName eq \"a\" and active eq true",
            "emails[type eq \"work\"].value eq \"x\"",
            "userName eq \"broken",
            "userName eq \"\"",
        ] {
            let result = parse(raw);
            match result {
                Err(e) => assert_eq!(e.scim_type, Some("invalidFilter"), "wrong scimType for {raw:?}"),
                Ok(f) => panic!("filter {raw:?} unexpectedly parsed to {f:?}"),
            }
        }
    }
}
