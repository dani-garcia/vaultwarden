//
// SCIM discovery endpoints, RFC 7643 section 5 and RFC 7644 section 4.
//
// Static metadata, served behind the ScimToken guard like everything else
// under /scim. Entra ID does not require these for Test Connection (that only
// needs a 200 ListResponse on a userName filter), but other SCIM clients read
// them, and they are cheap.
//
use rocket::Route;
use serde_json::Value;

use crate::{
    CONFIG,
    api::scim::{ScimResponse, guard::ScimToken},
    db::models::OrganizationId,
};

pub fn routes() -> Vec<Route> {
    routes![service_provider_config, resource_types, schemas]
}

const LIST_RESPONSE_URN: &str = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
pub const USER_SCHEMA_URN: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
pub const GROUP_SCHEMA_URN: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";

fn scim_base(org_id: &OrganizationId) -> String {
    format!("{}/scim/v2/{org_id}", CONFIG.domain())
}

fn list_response(resources: &[Value]) -> Value {
    json!({
        "schemas": [LIST_RESPONSE_URN],
        "totalResults": resources.len(),
        "itemsPerPage": resources.len(),
        "startIndex": 1,
        "Resources": resources,
    })
}

#[expect(clippy::needless_pass_by_value, reason = "Rocket request guards are taken by value")]
#[get("/v2/<_>/ServiceProviderConfig")]
fn service_provider_config(token: ScimToken) -> ScimResponse {
    ScimResponse::ok(json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
        "documentationUri": "https://github.com/croftinator/vaultwarden-scim-v2",
        "patch": { "supported": true },
        "bulk": { "supported": false, "maxOperations": 0, "maxPayloadSize": 0 },
        "filter": { "supported": true, "maxResults": 200 },
        "changePassword": { "supported": false },
        "sort": { "supported": false },
        "etag": { "supported": false },
        "authenticationSchemes": [{
            "type": "oauthbearertoken",
            "name": "OAuth Bearer Token",
            "description": "Static bearer token generated per organization",
            "primary": true,
        }],
        "meta": {
            "resourceType": "ServiceProviderConfig",
            "location": format!("{}/ServiceProviderConfig", scim_base(&token.org_uuid)),
        },
    }))
}

#[expect(clippy::needless_pass_by_value, reason = "Rocket request guards are taken by value")]
#[get("/v2/<_>/ResourceTypes")]
fn resource_types(token: ScimToken) -> ScimResponse {
    let base = scim_base(&token.org_uuid);
    ScimResponse::ok(list_response(&[
        json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
            "id": "User",
            "name": "User",
            "endpoint": "/Users",
            "description": "Organization member",
            "schema": USER_SCHEMA_URN,
            "meta": { "resourceType": "ResourceType", "location": format!("{base}/ResourceTypes/User") },
        }),
        json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
            "id": "Group",
            "name": "Group",
            "endpoint": "/Groups",
            "description": "Organization group",
            "schema": GROUP_SCHEMA_URN,
            "meta": { "resourceType": "ResourceType", "location": format!("{base}/ResourceTypes/Group") },
        }),
    ]))
}

#[expect(clippy::needless_pass_by_value, reason = "Rocket request guards are taken by value")]
#[get("/v2/<_>/Schemas")]
fn schemas(token: ScimToken) -> ScimResponse {
    let base = scim_base(&token.org_uuid);
    ScimResponse::ok(list_response(&[
        json!({
            "id": USER_SCHEMA_URN,
            "name": "User",
            "description": "SCIM core User. Supported attributes: userName, externalId, name, displayName, emails, active.",
            "meta": { "resourceType": "Schema", "location": format!("{base}/Schemas/{USER_SCHEMA_URN}") },
        }),
        json!({
            "id": GROUP_SCHEMA_URN,
            "name": "Group",
            "description": "SCIM core Group. Supported attributes: displayName, externalId, members.",
            "meta": { "resourceType": "Schema", "location": format!("{base}/Schemas/{GROUP_SCHEMA_URN}") },
        }),
    ]))
}
