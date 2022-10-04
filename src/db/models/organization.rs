use num_traits::FromPrimitive;
use rocket::serde::json::Json;
use rocket::Route;
use serde_json::Value;

use crate::{
    api::{
        core::{CipherSyncData, CipherSyncType},
        EmptyResult, JsonResult, JsonUpcase, JsonUpcaseVec, Notify, NumberOrString, PasswordData, UpdateType,
    },
    auth::{decode_invite, AdminHeaders, Headers, ManagerHeaders, ManagerHeadersLoose, OwnerHeaders},
    db::{models::*, DbConn},
    mail,
    util::convert_json_key_lcase_first,
    CONFIG,
};

use futures::{stream, stream::StreamExt};

pub fn routes() -> Vec<Route> {
    routes![
        get_organization,
        create_organization,
        delete_organization,
        post_delete_organization,
        leave_organization,
        get_user_collections,
        get_org_collections,
        get_org_collection_detail,
        get_collection_users,
        put_collection_users,
        put_organization,
        post_organization,
        get_organization_sso,
        put_organization_sso,
        post_organization_collections,
        delete_organization_collection_user,
        post_organization_collection_delete_user,
        post_organization_collection_update,
        put_organization_collection_update,
        delete_organization_collection,
        post_organization_collection_delete,
        get_org_details,
        get_org_users,
        send_invite,
        reinvite_user,
        bulk_reinvite_user,
        confirm_invite,
        bulk_confirm_invite,
        accept_invite,
        get_user,
        edit_user,
        put_organization_user,
        delete_user,
        bulk_delete_user,
        post_delete_user,
        post_org_import,
        list_policies,
        list_policies_token,
        get_policy,
        put_policy,
        get_organization_tax,
        get_plans,
        get_plans_tax_rates,
        import,
        post_org_keys,
        bulk_public_keys,
        deactivate_organization_user,
        bulk_deactivate_organization_user,
        revoke_organization_user,
        bulk_revoke_organization_user,
        activate_organization_user,
        bulk_activate_organization_user,
        restore_organization_user,
        bulk_restore_organization_user,
        get_org_export
    ]
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct OrgData {
    BillingEmail: String,
    CollectionName: String,
    Key: String,
    Name: String,
    Keys: Option<OrgKeyData>,
    #[serde(rename = "PlanType")]
    _PlanType: NumberOrString, // Ignored, always use the same plan
}

#[derive(Deserialize, Debug)]
#[allow(non_snake_case)]
struct OrganizationUpdateData {
    BillingEmail: String,
    Name: String,
    Identifier: Option<String>,
}

#[derive(Deserialize, Debug)]
#[allow(non_snake_case)]
struct OrganizationSsoUpdateData {
    Enabled: Option<bool>,
    Data: Option<SsoOrganizationData>,
}

#[derive(Deserialize, Debug)]
#[allow(non_snake_case)]
struct NewCollectionData {
    Name: String,
}

/*
 From Bitwarden Entreprise




{
  "enabled": false,
  "data": {
    "acrValues": "requested authentication context class",
    "additionalEmailClaimTypes": "additinaional email",
    "additionalNameClaimTypes": "additioonal name claim tyeps",
    "additionalScopes": "additonal scopes",
    "additionalUserIdClaimTypes": "additoal userid",
    "authority": "authority",
    "clientId": "clientid",
    "clientSecret": "clientsecrte",
    "configType": 1,
    "expectedReturnAcrValue": "expectde acr",
    "getClaimsFromUserInfoEndpoint": true,
    "idpAllowUnsolicitedAuthnResponse": false,
    "idpArtifactResolutionServiceUrl": null,
    "idpBindingType": 1,
    "idpDisableOutboundLogoutRequests": false,
    "idpEntityId": null,
    "idpOutboundSigningAlgorithm": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
    "idpSingleLogoutServiceUrl": null,
    "idpSingleSignOnServiceUrl": null,
    "idpWantAuthnRequestsSigned": false
    "idpX509PublicCert": null,
    "keyConnectorEnabled": false,
    "keyConnectorUrl": null,
    "metadataAddress": "metadata adress",
    "redirectBehavior": 1,
    "spMinIncomingSigningAlgorithm": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
    "spNameIdFormat": 7,
    "spOutboundSigningAlgorithm": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
    "spSigningBehavior": 0,
    "spValidateCertificates": false,
    "spWantAssertionsSigned": false,
  }
}
*/

#[derive(Deserialize, Debug)]
#[allow(non_snake_case)]
struct SsoOrganizationData {
    // authority: Option<String>,
    // clientId: Option<String>,
    // clientSecret: Option<String>,
    AcrValues: Option<String>,
    AdditionalEmailClaimTypes: Option<String>,
    AdditionalNameClaimTypes: Option<String>,
    AdditionalScopes: Option<String>,
    AdditionalUserIdClaimTypes: Option<String>,
    Authority: Option<String>,
    ClientId: Option<String>,
    ClientSecret: Option<String>,
    ConfigType: Option<String>,
    ExpectedReturnAcrValue: Option<String>,
    GetClaimsFromUserInfoEndpoint: Option<bool>,
    IdpAllowUnsolicitedAuthnResponse: Option<bool>,
    IdpArtifactResolutionServiceUrl: Option<String>,
    IdpBindingType: Option<u8>,
    IdpDisableOutboundLogoutRequests: Option<bool>,
    IdpEntityId: Option<String>,
    IdpOutboundSigningAlgorithm: Option<String>,
    IdpSingleLogoutServiceUrl: Option<String>,
    IdpSingleSignOnServiceUrl: Option<String>,
    IdpWantAuthnRequestsSigned: Option<bool>,
    IdpX509PublicCert: Option<String>,
    KeyConnectorUrlY: Option<String>,
    KeyConnectorEnabled: Option<bool>,
    MetadataAddress: Option<String>,
    RedirectBehavior: Option<String>,
    SpMinIncomingSigningAlgorithm: Option<String>,
    SpNameIdFormat: Option<u8>,
    SpOutboundSigningAlgorithm: Option<String>,
    SpSigningBehavior: Option<u8>,
    SpValidateCertificates: Option<bool>,
    SpWantAssertionsSigned: Option<bool>,
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct OrgKeyData {
    EncryptedPrivateKey: String,
    PublicKey: String,
}

#[derive(Deserialize, Debug)]
#[allow(non_snake_case)]
struct OrgBulkIds {
    Ids: Vec<String>,
}

#[post("/organizations", data = "<data>")]
async fn create_organization(headers: Headers, data: JsonUpcase<OrgData>, conn: DbConn) -> JsonResult {
    if !CONFIG.is_org_creation_allowed(&headers.user.email) {
        err!("User not allowed to create organizations")
    }
    if OrgPolicy::is_applicable_to_user(&headers.user.uuid, OrgPolicyType::SingleOrg, None, &conn).await {
        err!(
            "You may not create an organization. You belong to an organization which has a policy that prohibits you from being a member of any other organization."
        )
    }

    let data: OrgData = data.into_inner().data;
    let (private_key, public_key) = if data.Keys.is_some() {
        let keys: OrgKeyData = data.Keys.unwrap();
        (Some(keys.EncryptedPrivateKey), Some(keys.PublicKey))
    } else {
        (None, None)
    };

    let org = Organization::new(data.Name, data.BillingEmail, private_key, public_key);
    let mut user_org = UserOrganization::new(headers.user.uuid, org.uuid.clone());
    let sso_config = SsoConfig::new(org.uuid.clone());
    let collection = Collection::new(org.uuid.clone(), data.CollectionName);

    user_org.akey = data.Key;
    user_org.access_all = true;
    user_org.atype = UserOrgType::Owner as i32;
    user_org.status = UserOrgStatus::Confirmed as i32;

    org.save(&conn).await?;
    user_org.save(&conn).await?;
    sso_config.save(&conn).await?;
    collection.save(&conn).await?;

    Ok(Json(org.to_json()))
}

#[delete("/organizations/<org_id>", data = "<data>")]
async fn delete_organization(
    org_id: String,
    data: JsonUpcase<PasswordData>,
    headers: OwnerHeaders,
    conn: DbConn,
) -> EmptyResult {
    let data: PasswordData = data.into_inner().data;
    let password_hash = data.MasterPasswordHash;

    if !headers.user.check_valid_password(&password_hash) {
        err!("Invalid password")
    }

    match Organization::find_by_uuid(&org_id, &conn).await {
        None => err!("Organization not found"),
        Some(org) => org.delete(&conn).await,
    }
}

#[post("/organizations/<org_id>/delete", data = "<data>")]
async fn post_delete_organization(
    org_id: String,
    data: JsonUpcase<PasswordData>,
    headers: OwnerHeaders,
    conn: DbConn,
) -> EmptyResult {
    delete_organization(org_id, data, headers, conn).await
}

#[post("/organizations/<org_id>/leave")]
async fn leave_organization(org_id: String, headers: Headers, conn: DbConn) -> EmptyResult {
    match UserOrganization::find_by_user_and_org(&headers.user.uuid, &org_id, &conn).await {
        None => err!("User not part of organization"),
        Some(user_org) => {
            if user_org.atype == UserOrgType::Owner
                && UserOrganization::count_confirmed_by_org_and_type(&org_id, UserOrgType::Owner, &conn).await <= 1
            {
                err!("The last owner can't leave")
            }

            user_org.delete(&conn).await
        }
    }
}

#[get("/organizations/<org_id>")]
async fn get_organization(org_id: String, _headers: OwnerHeaders, conn: DbConn) -> JsonResult {
    match Organization::find_by_uuid(&org_id, &conn).await {
        Some(organization) => Ok(Json(organization.to_json())),
        None => err!("Can't find organization details"),
    }
}

#[put("/organizations/<org_id>", data = "<data>")]
async fn put_organization(
    org_id: String,
    headers: OwnerHeaders,
    data: JsonUpcase<OrganizationUpdateData>,
    conn: DbConn,
) -> JsonResult {
    post_organization(org_id, headers, data, conn).await
}

#[post("/organizations/<org_id>", data = "<data>")]
async fn post_organization(
    org_id: String,
    _headers: OwnerHeaders,
    data: JsonUpcase<OrganizationUpdateData>,
    conn: DbConn,
) -> JsonResult {
    let data: OrganizationUpdateData = data.into_inner().data;

    let mut org = match Organization::find_by_uuid(&org_id, &conn).await {
        Some(organization) => organization,
        None => err!("Can't find organization details"),
    };

    org.name = data.Name;
    org.billing_email = data.BillingEmail;
    org.identifier = data.Identifier;

    org.save(&conn).await?;
    Ok(Json(org.to_json()))
}

#[get("/organizations/<org_id>/sso")]
async fn get_organization_sso(org_id: String, _headers: OwnerHeaders, conn: DbConn) -> JsonResult {
    match SsoConfig::find_by_org(&org_id, &conn).await {
        Some(sso_config) => {
            let config_json = Json(sso_config.to_json());
            Ok(config_json)
        }
        None => err!("Can't find organization sso config"),
    }
}

#[post("/organizations/<org_id>/sso", data = "<data>")]
async fn put_organization_sso(
    org_id: String,
    _headers: OwnerHeaders,
    data: JsonUpcase<OrganizationSsoUpdateData>,
    conn: DbConn,
) -> JsonResult {
    let p: OrganizationSsoUpdateData = data.into_inner().data;
    let d: SsoOrganizationData = p.Data.unwrap();

    // TODO remove after debugging
    println!(
        "
    p.Enabled: {:?},
    d.AcrValues: {:?},
    d.AdditionalEmailClaimTypes: {:?},
    d.AdditionalNameClaimTypes: {:?},
    d.AdditionalScopes: {:?},
    d.AdditionalUserIdClaimTypes: {:?},
    d.Authority: {:?},
    d.ClientId: {:?},
    d.ClientSecret: {:?},
    d.ConfigType: {:?},
    d.ExpectedReturnAcrValue: {:?},
    d.GetClaimsFromUserInfoEndpoint: {:?},
    d.IdpAllowUnsolicitedAuthnResponse: {:?},
    d.IdpArtifactResolutionServiceUrl: {:?},
    d.IdpBindingType: {:?},
    d.IdpDisableOutboundLogoutRequests: {:?},
    d.IdpEntityId: {:?},
    d.IdpOutboundSigningAlgorithm: {:?},
    d.IdpSingleLogoutServiceUrl: {:?},
    d.IdpSingleSignOnServiceUrl: {:?},
    d.IdpWantAuthnRequestsSigned: {:?},
    d.IdpX509PublicCert: {:?},
    d.KeyConnectorUrlY: {:?},
    d.KeyConnectorEnabled: {:?},
    d.MetadataAddress: {:?},
    d.RedirectBehavior: {:?},
    d.SpMinIncomingSigningAlgorithm: {:?},
    d.SpNameIdFormat: {:?},
    d.SpOutboundSigningAlgorithm: {:?},
    d.SpSigningBehavior: {:?},
    d.SpValidateCertificates: {:?},
    d.SpWantAssertionsSigned: {:?}",
        p.Enabled.unwrap_or_default(),
        d.AcrValues,
        d.AdditionalEmailClaimTypes,
        d.AdditionalNameClaimTypes,
        d.AdditionalScopes,
        d.AdditionalUserIdClaimTypes,
        d.Authority,
        d.ClientId,
        d.ClientSecret,
        d.ConfigType,
        d.ExpectedReturnAcrValue,
        d.GetClaimsFromUserInfoEndpoint,
        d.IdpAllowUnsolicitedAuthnResponse,
        d.IdpArtifactResolutionServiceUrl,
        d.IdpBindingType,
        d.IdpDisableOutboundLogoutRequests,
        d.IdpEntityId,
        d.IdpOutboundSigningAlgorithm,
        d.IdpSingleLogoutServiceUrl,
        d.IdpSingleSignOnServiceUrl,
        d.IdpWantAuthnRequestsSigned,
        d.IdpX509PublicCert,
        d.KeyConnectorUrlY,
        d.KeyConnectorEnabled,
        d.MetadataAddress,
        d.RedirectBehavior,
        d.SpMinIncomingSigningAlgorithm,
        d.SpNameIdFormat,
        d.SpOutboundSigningAlgorithm,
        d.SpSigningBehavior,
        d.SpValidateCertificates,
        d.SpWantAssertionsSigned
    );

    let mut sso_config = match SsoConfig::find_by_org(&org_id, &conn).await {
        Some(sso_config) => sso_config,
        None => SsoConfig::new(org_id),
    };

    sso_config.use_sso = p.Enabled.unwrap_or_default();

    // let sso_config_data = data.Data.unwrap();

    // TODO use real values
    sso_config.callback_path = "http://localhost:8000/#/sso".to_string(); //data.CallbackPath;
    sso_config.signed_out_callback_path = "http://localhost:8000/#/sso".to_string(); //data2.Data.unwrap().call

    sso_config.authority = d.Authority;
    sso_config.client_id = d.ClientId;
    sso_config.client_secret = d.ClientSecret;

    sso_config.save(&conn).await?;
    Ok(Json(sso_config.to_json()))
}

// GET /api/collections?writeOnly=false
#[get("/collections")]
async fn get_user_collections(headers: Headers, conn: DbConn) -> Json<Value> {
    Json(json!({
        "Data":
            Collection::find_by_user_uuid(&headers.user.uuid, &conn).await
            .iter()
            .map(Collection::to_json)
            .collect::<Value>(),
        "Object": "list",
        "ContinuationToken": null,
    }))
}

#[get("/organizations/<org_id>/collections")]
async fn get_org_collections(org_id: String, _headers: ManagerHeadersLoose, conn: DbConn) -> Json<Value> {
    Json(_get_org_collections(&org_id, &conn).await)
}

async fn _get_org_collections(org_id: &str, conn: &DbConn) -> Value {
    json!({
        "Data":
            Collection::find_by_organization(org_id, conn).await
            .iter()
            .map(Collection::to_json)
            .collect::<Value>(),
        "Object": "list",
        "ContinuationToken": null,
    })
}

#[post("/organizations/<org_id>/collections", data = "<data>")]
async fn post_organization_collections(
    org_id: String,
    headers: ManagerHeadersLoose,
    data: JsonUpcase<NewCollectionData>,
    conn: DbConn,
) -> JsonResult {
    let data: NewCollectionData = data.into_inner().data;

    let org = match Organization::find_by_uuid(&org_id, &conn).await {
        Some(organization) => organization,
        None => err!("Can't find organization details"),
    };

    // Get the user_organization record so that we can check if the user has access to all collections.
    let user_org = match UserOrganization::find_by_user_and_org(&headers.user.uuid, &org_id, &conn).await {
        Some(u) => u,
        None => err!("User is not part of organization"),
    };

    let collection = Collection::new(org.uuid, data.Name);
    collection.save(&conn).await?;

    // If the user doesn't have access to all collections, only in case of a Manger,
    // then we need to save the creating user uuid (Manager) to the users_collection table.
    // Else the user will not have access to his own created collection.
    if !user_org.access_all {
        CollectionUser::save(&headers.user.uuid, &collection.uuid, false, false, &conn).await?;
    }

    Ok(Json(collection.to_json()))
}

#[put("/organizations/<org_id>/collections/<col_id>", data = "<data>")]
async fn put_organization_collection_update(
    org_id: String,
    col_id: String,
    headers: ManagerHeaders,
    data: JsonUpcase<NewCollectionData>,
    conn: DbConn,
) -> JsonResult {
    post_organization_collection_update(org_id, col_id, headers, data, conn).await
}

#[post("/organizations/<org_id>/collections/<col_id>", data = "<data>")]
async fn post_organization_collection_update(
    org_id: String,
    col_id: String,
    _headers: ManagerHeaders,
    data: JsonUpcase<NewCollectionData>,
    conn: DbConn,
) -> JsonResult {
    let data: NewCollectionData = data.into_inner().data;

    let org = match Organization::find_by_uuid(&org_id, &conn).await {
        Some(organization) => organization,
        None => err!("Can't find organization details"),
    };

    let mut collection = match Collection::find_by_uuid(&col_id, &conn).await {
        Some(collection) => collection,
        None => err!("Collection not found"),
    };

    if collection.org_uuid != org.uuid {
        err!("Collection is not owned by organization");
    }

    collection.name = data.Name;
    collection.save(&conn).await?;

    Ok(Json(collection.to_json()))
}

#[delete("/organizations/<org_id>/collections/<col_id>/user/<org_user_id>")]
async fn delete_organization_collection_user(
    org_id: String,
    col_id: String,
    org_user_id: String,
    _headers: AdminHeaders,
    conn: DbConn,
) -> EmptyResult {
    let collection = match Collection::find_by_uuid(&col_id, &conn).await {
        None => err!("Collection not found"),
        Some(collection) => {
            if collection.org_uuid == org_id {
                collection
            } else {
                err!("Collection and Organization id do not match")
            }
        }
    };

    match UserOrganization::find_by_uuid_and_org(&org_user_id, &org_id, &conn).await {
        None => err!("User not found in organization"),
        Some(user_org) => {
            match CollectionUser::find_by_collection_and_user(&collection.uuid, &user_org.user_uuid, &conn).await {
                None => err!("User not assigned to collection"),
                Some(col_user) => col_user.delete(&conn).await,
            }
        }
    }
}

#[post("/organizations/<org_id>/collections/<col_id>/delete-user/<org_user_id>")]
async fn post_organization_collection_delete_user(
    org_id: String,
    col_id: String,
    org_user_id: String,
    headers: AdminHeaders,
    conn: DbConn,
) -> EmptyResult {
    delete_organization_collection_user(org_id, col_id, org_user_id, headers, conn).await
}

#[delete("/organizations/<org_id>/collections/<col_id>")]
async fn delete_organization_collection(
    org_id: String,
    col_id: String,
    _headers: ManagerHeaders,
    conn: DbConn,
) -> EmptyResult {
    match Collection::find_by_uuid(&col_id, &conn).await {
        None => err!("Collection not found"),
        Some(collection) => {
            if collection.org_uuid == org_id {
                collection.delete(&conn).await
            } else {
                err!("Collection and Organization id do not match")
            }
        }
    }
}

#[derive(Deserialize, Debug)]
#[allow(non_snake_case, dead_code)]
struct DeleteCollectionData {
    Id: String,
    OrgId: String,
}

#[post("/organizations/<org_id>/collections/<col_id>/delete", data = "<_data>")]
async fn post_organization_collection_delete(
    org_id: String,
    col_id: String,
    headers: ManagerHeaders,
    _data: JsonUpcase<DeleteCollectionData>,
    conn: DbConn,
) -> EmptyResult {
    delete_organization_collection(org_id, col_id, headers, conn).await
}

#[get("/organizations/<org_id>/collections/<coll_id>/details")]
async fn get_org_collection_detail(
    org_id: String,
    coll_id: String,
    headers: ManagerHeaders,
    conn: DbConn,
) -> JsonResult {
    match Collection::find_by_uuid_and_user(&coll_id, &headers.user.uuid, &conn).await {
        None => err!("Collection not found"),
        Some(collection) => {
            if collection.org_uuid != org_id {
                err!("Collection is not owned by organization")
            }

            Ok(Json(collection.to_json()))
        }
    }
}

#[get("/organizations/<org_id>/collections/<coll_id>/users")]
async fn get_collection_users(org_id: String, coll_id: String, _headers: ManagerHeaders, conn: DbConn) -> JsonResult {
    // Get org and collection, check that collection is from org
    let collection = match Collection::find_by_uuid_and_org(&coll_id, &org_id, &conn).await {
        None => err!("Collection not found in Organization"),
        Some(collection) => collection,
    };

    let user_list = stream::iter(CollectionUser::find_by_collection(&collection.uuid, &conn).await)
        .then(|col_user| async {
            let col_user = col_user; // Move out this single variable
            UserOrganization::find_by_user_and_org(&col_user.user_uuid, &org_id, &conn)
                .await
                .unwrap()
                .to_json_user_access_restrictions(&col_user)
        })
        .collect::<Vec<Value>>()
        .await;

    Ok(Json(json!(user_list)))
}

#[put("/organizations/<org_id>/collections/<coll_id>/users", data = "<data>")]
async fn put_collection_users(
    org_id: String,
    coll_id: String,
    data: JsonUpcaseVec<CollectionData>,
    _headers: ManagerHeaders,
    conn: DbConn,
) -> EmptyResult {
    // Get org and collection, check that collection is from org
    if Collection::find_by_uuid_and_org(&coll_id, &org_id, &conn).await.is_none() {
        err!("Collection not found in Organization")
    }

    // Delete all the user-collections
    CollectionUser::delete_all_by_collection(&coll_id, &conn).await?;

    // And then add all the received ones (except if the user has access_all)
    for d in data.iter().map(|d| &d.data) {
        let user = match UserOrganization::find_by_uuid(&d.Id, &conn).await {
            Some(u) => u,
            None => err!("User is not part of organization"),
        };

        if user.access_all {
            continue;
        }

        CollectionUser::save(&user.user_uuid, &coll_id, d.ReadOnly, d.HidePasswords, &conn).await?;
    }

    Ok(())
}

#[derive(FromForm)]
struct OrgIdData {
    #[field(name = "organizationId")]
    organization_id: String,
}

#[get("/ciphers/organization-details?<data..>")]
async fn get_org_details(data: OrgIdData, headers: Headers, conn: DbConn) -> Json<Value> {
    Json(_get_org_details(&data.organization_id, &headers.host, &headers.user.uuid, &conn).await)
}

async fn _get_org_details(org_id: &str, host: &str, user_uuid: &str, conn: &DbConn) -> Value {
    let ciphers = Cipher::find_by_org(org_id, conn).await;
    let cipher_sync_data = CipherSyncData::new(user_uuid, &ciphers, CipherSyncType::Organization, conn).await;

    let ciphers_json = stream::iter(ciphers)
        .then(|c| async {
            let c = c; // Move out this single variable
            c.to_json(host, user_uuid, Some(&cipher_sync_data), conn).await
        })
        .collect::<Vec<Value>>()
        .await;

    json!({
      "Data": ciphers_json,
      "Object": "list",
      "ContinuationToken": null,
    })
}

#[get("/organizations/<org_id>/users")]
async fn get_org_users(org_id: String, _headers: ManagerHeadersLoose, conn: DbConn) -> Json<Value> {
    let users_json = stream::iter(UserOrganization::find_by_org(&org_id, &conn).await)
        .then(|u| async {
            let u = u; // Move out this single variable
            u.to_json_user_details(&conn).await
        })
        .collect::<Vec<Value>>()
        .await;

    Json(json!({
        "Data": users_json,
        "Object": "list",
        "ContinuationToken": null,
    }))
}

#[post("/organizations/<org_id>/keys", data = "<data>")]
async fn post_org_keys(
    org_id: String,
    data: JsonUpcase<OrgKeyData>,
    _headers: AdminHeaders,
    conn: DbConn,
) -> JsonResult {
    let data: OrgKeyData = data.into_inner().data;

    let mut org = match Organization::find_by_uuid(&org_id, &conn).await {
        Some(organization) => {
            if organization.private_key.is_some() && organization.public_key.is_some() {
                err!("Organization Keys already exist")
            }
            organization
        }
        None => err!("Can't find organization details"),
    };

    org.private_key = Some(data.EncryptedPrivateKey);
    org.public_key = Some(data.PublicKey);

    org.save(&conn).await?;

    Ok(Json(json!({
        "Object": "organizationKeys",
        "PublicKey": org.public_key,
        "PrivateKey": org.private_key,
    })))
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct CollectionData {
    Id: String,
    ReadOnly: bool,
    HidePasswords: bool,
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct InviteData {
    Emails: Vec<String>,
    Type: NumberOrString,
    Collections: Option<Vec<CollectionData>>,
    AccessAll: Option<bool>,
}

#[post("/organizations/<org_id>/users/invite", data = "<data>")]
async fn send_invite(org_id: String, data: JsonUpcase<InviteData>, headers: AdminHeaders, conn: DbConn) -> EmptyResult {
    let data: InviteData = data.into_inner().data;

    let new_type = match UserOrgType::from_str(&data.Type.into_string()) {
        Some(new_type) => new_type as i32,
        None => err!("Invalid type"),
    };

    if new_type != UserOrgType::User && headers.org_user_type != UserOrgType::Owner {
        err!("Only Owners can invite Managers, Admins or Owners")
    }

    for email in data.Emails.iter() {
        let email = email.to_lowercase();
        let mut user_org_status = if CONFIG.mail_enabled() {
            UserOrgStatus::Invited as i32
        } else {
            UserOrgStatus::Accepted as i32 // Automatically mark user as accepted if no email invites
        };
        let user = match User::find_by_mail(&email, &conn).await {
            None => {
                if !CONFIG.invitations_allowed() {
                    err!(format!("User does not exist: {}", email))
                }

                if !CONFIG.is_email_domain_allowed(&email) {
                    err!("Email domain not eligible for invitations")
                }

                if !CONFIG.mail_enabled() {
                    let invitation = Invitation::new(email.clone());
                    invitation.save(&conn).await?;
                }

                let mut user = User::new(email.clone());
                user.save(&conn).await?;
                user_org_status = UserOrgStatus::Invited as i32;
                user
            }
            Some(user) => {
                if UserOrganization::find_by_user_and_org(&user.uuid, &org_id, &conn).await.is_some() {
                    err!(format!("User already in organization: {}", email))
                } else {
                    user
                }
            }
        };

        let mut new_user = UserOrganization::new(user.uuid.clone(), org_id.clone());
        let access_all = data.AccessAll.unwrap_or(false);
        new_user.access_all = access_all;
        new_user.atype = new_type;
        new_user.status = user_org_status;

        // If no accessAll, add the collections received
        if !access_all {
            for col in data.Collections.iter().flatten() {
                match Collection::find_by_uuid_and_org(&col.Id, &org_id, &conn).await {
                    None => err!("Collection not found in Organization"),
                    Some(collection) => {
                        CollectionUser::save(&user.uuid, &collection.uuid, col.ReadOnly, col.HidePasswords, &conn)
                            .await?;
                    }
                }
            }
        }

        new_user.save(&conn).await?;

        if CONFIG.mail_enabled() {
            let org_name = match Organization::find_by_uuid(&org_id, &conn).await {
                Some(org) => org.name,
                None => err!("Error looking up organization"),
            };

            mail::send_invite(
                &email,
                &user.uuid,
                Some(org_id.clone()),
                Some(new_user.uuid),
                &org_name,
                Some(headers.user.email.clone()),
            )
            .await?;
        }
    }

    Ok(())
}

#[post("/organizations/<org_id>/users/reinvite", data = "<data>")]
async fn bulk_reinvite_user(
    org_id: String,
    data: JsonUpcase<OrgBulkIds>,
    headers: AdminHeaders,
    conn: DbConn,
) -> Json<Value> {
    let data: OrgBulkIds = data.into_inner().data;

    let mut bulk_response = Vec::new();
    for org_user_id in data.Ids {
        let err_msg = match _reinvite_user(&org_id, &org_user_id, &headers.user.email, &conn).await {
            Ok(_) => String::from(""),
            Err(e) => format!("{:?}", e),
        };

        bulk_response.push(json!(
            {
                "Object": "OrganizationBulkConfirmResponseModel",
                "Id": org_user_id,
                "Error": err_msg
            }
        ))
    }

    Json(json!({
        "Data": bulk_response,
        "Object": "list",
        "ContinuationToken": null
    }))
}

#[post("/organizations/<org_id>/users/<user_org>/reinvite")]
async fn reinvite_user(org_id: String, user_org: String, headers: AdminHeaders, conn: DbConn) -> EmptyResult {
    _reinvite_user(&org_id, &user_org, &headers.user.email, &conn).await
}

async fn _reinvite_user(org_id: &str, user_org: &str, invited_by_email: &str, conn: &DbConn) -> EmptyResult {
    if !CONFIG.invitations_allowed() {
        err!("Invitations are not allowed.")
    }

    if !CONFIG.mail_enabled() {
        err!("SMTP is not configured.")
    }

    let user_org = match UserOrganization::find_by_uuid(user_org, conn).await {
        Some(user_org) => user_org,
        None => err!("The user hasn't been invited to the organization."),
    };

    if user_org.status != UserOrgStatus::Invited as i32 {
        err!("The user is already accepted or confirmed to the organization")
    }

    let user = match User::find_by_uuid(&user_org.user_uuid, conn).await {
        Some(user) => user,
        None => err!("User not found."),
    };

    let org_name = match Organization::find_by_uuid(org_id, conn).await {
        Some(org) => org.name,
        None => err!("Error looking up organization."),
    };

    if CONFIG.mail_enabled() {
        mail::send_invite(
            &user.email,
            &user.uuid,
            Some(org_id.to_string()),
            Some(user_org.uuid),
            &org_name,
            Some(invited_by_email.to_string()),
        )
        .await?;
    } else {
        let invitation = Invitation::new(user.email);
        invitation.save(conn).await?;
    }

    Ok(())
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct AcceptData {
    Token: String,
}

#[post("/organizations/<org_id>/users/<_org_user_id>/accept", data = "<data>")]
async fn accept_invite(
    org_id: String,
    _org_user_id: String,
    data: JsonUpcase<AcceptData>,
    conn: DbConn,
) -> EmptyResult {
    // The web-vault passes org_id and org_user_id in the URL, but we are just reading them from the JWT instead
    let data: AcceptData = data.into_inner().data;
    let claims = decode_invite(&data.Token)?;

    match User::find_by_mail(&claims.email, &conn).await {
        Some(_) => {
            Invitation::take(&claims.email, &conn).await;

            if let (Some(user_org), Some(org)) = (&claims.user_org_id, &claims.org_id) {
                let mut user_org = match UserOrganization::find_by_uuid_and_org(user_org, org, &conn).await {
                    Some(user_org) => user_org,
                    None => err!("Error accepting the invitation"),
                };

                if user_org.status != UserOrgStatus::Invited as i32 {
                    err!("User already accepted the invitation")
                }

                // This check is also done at accept_invite(), _confirm_invite, _activate_user(), edit_user(), admin::update_user_org_type
                // It returns different error messages per function.
                if user_org.atype < UserOrgType::Admin {
                    match OrgPolicy::is_user_allowed(&user_org.user_uuid, &org_id, false, &conn).await {
                        Ok(_) => {}
                        Err(OrgPolicyErr::TwoFactorMissing) => {
                            err!("You cannot join this organization until you enable two-step login on your user account");
                        }
                        Err(OrgPolicyErr::SingleOrgEnforced) => {
                            err!("You cannot join this organization because you are a member of an organization which forbids it");
                        }
                    }
                }

                user_org.status = UserOrgStatus::Accepted as i32;
                user_org.save(&conn).await?;
            }
        }
        None => err!("Invited user not found"),
    }

    if CONFIG.mail_enabled() {
        let mut org_name = CONFIG.invitation_org_name();
        if let Some(org_id) = &claims.org_id {
            org_name = match Organization::find_by_uuid(org_id, &conn).await {
                Some(org) => org.name,
                None => err!("Organization not found."),
            };
        };
        if let Some(invited_by_email) = &claims.invited_by_email {
            // User was invited to an organization, so they must be confirmed manually after acceptance
            mail::send_invite_accepted(&claims.email, invited_by_email, &org_name).await?;
        } else {
            // User was invited from /admin, so they are automatically confirmed
            mail::send_invite_confirmed(&claims.email, &org_name).await?;
        }
    }

    Ok(())
}

#[post("/organizations/<org_id>/users/confirm", data = "<data>")]
async fn bulk_confirm_invite(
    org_id: String,
    data: JsonUpcase<Value>,
    headers: AdminHeaders,
    conn: DbConn,
) -> Json<Value> {
    let data = data.into_inner().data;

    let mut bulk_response = Vec::new();
    match data["Keys"].as_array() {
        Some(keys) => {
            for invite in keys {
                let org_user_id = invite["Id"].as_str().unwrap_or_default();
                let user_key = invite["Key"].as_str().unwrap_or_default();
                let err_msg = match _confirm_invite(&org_id, org_user_id, user_key, &headers, &conn).await {
                    Ok(_) => String::from(""),
                    Err(e) => format!("{:?}", e),
                };

                bulk_response.push(json!(
                    {
                        "Object": "OrganizationBulkConfirmResponseModel",
                        "Id": org_user_id,
                        "Error": err_msg
                    }
                ));
            }
        }
        None => error!("No keys to confirm"),
    }

    Json(json!({
        "Data": bulk_response,
        "Object": "list",
        "ContinuationToken": null
    }))
}

#[post("/organizations/<org_id>/users/<org_user_id>/confirm", data = "<data>")]
async fn confirm_invite(
    org_id: String,
    org_user_id: String,
    data: JsonUpcase<Value>,
    headers: AdminHeaders,
    conn: DbConn,
) -> EmptyResult {
    let data = data.into_inner().data;
    let user_key = data["Key"].as_str().unwrap_or_default();
    _confirm_invite(&org_id, &org_user_id, user_key, &headers, &conn).await
}

async fn _confirm_invite(
    org_id: &str,
    org_user_id: &str,
    key: &str,
    headers: &AdminHeaders,
    conn: &DbConn,
) -> EmptyResult {
    if key.is_empty() || org_user_id.is_empty() {
        err!("Key or UserId is not set, unable to process request");
    }

    let mut user_to_confirm = match UserOrganization::find_by_uuid_and_org(org_user_id, org_id, conn).await {
        Some(user) => user,
        None => err!("The specified user isn't a member of the organization"),
    };

    if user_to_confirm.atype != UserOrgType::User && headers.org_user_type != UserOrgType::Owner {
        err!("Only Owners can confirm Managers, Admins or Owners")
    }

    if user_to_confirm.status != UserOrgStatus::Accepted as i32 {
        err!("User in invalid state")
    }

    // This check is also done at accept_invite(), _confirm_invite, _activate_user(), edit_user(), admin::update_user_org_type
    // It returns different error messages per function.
    if user_to_confirm.atype < UserOrgType::Admin {
        match OrgPolicy::is_user_allowed(&user_to_confirm.user_uuid, org_id, true, conn).await {
            Ok(_) => {}
            Err(OrgPolicyErr::TwoFactorMissing) => {
                err!("You cannot confirm this user because it has no two-step login method activated");
            }
            Err(OrgPolicyErr::SingleOrgEnforced) => {
                err!("You cannot confirm this user because it is a member of an organization which forbids it");
            }
        }
    }

    user_to_confirm.status = UserOrgStatus::Confirmed as i32;
    user_to_confirm.akey = key.to_string();

    if CONFIG.mail_enabled() {
        let org_name = match Organization::find_by_uuid(org_id, conn).await {
            Some(org) => org.name,
            None => err!("Error looking up organization."),
        };
        let address = match User::find_by_uuid(&user_to_confirm.user_uuid, conn).await {
            Some(user) => user.email,
            None => err!("Error looking up user."),
        };
        mail::send_invite_confirmed(&address, &org_name).await?;
    }

    user_to_confirm.save(conn).await
}

#[get("/organizations/<org_id>/users/<org_user_id>")]
async fn get_user(org_id: String, org_user_id: String, _headers: AdminHeaders, conn: DbConn) -> JsonResult {
    let user = match UserOrganization::find_by_uuid_and_org(&org_user_id, &org_id, &conn).await {
        Some(user) => user,
        None => err!("The specified user isn't a member of the organization"),
    };

    Ok(Json(user.to_json_details(&conn).await))
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct EditUserData {
    Type: NumberOrString,
    Collections: Option<Vec<CollectionData>>,
    AccessAll: bool,
}

#[put("/organizations/<org_id>/users/<org_user_id>", data = "<data>", rank = 1)]
async fn put_organization_user(
    org_id: String,
    org_user_id: String,
    data: JsonUpcase<EditUserData>,
    headers: AdminHeaders,
    conn: DbConn,
) -> EmptyResult {
    edit_user(org_id, org_user_id, data, headers, conn).await
}

#[post("/organizations/<org_id>/users/<org_user_id>", data = "<data>", rank = 1)]
async fn edit_user(
    org_id: String,
    org_user_id: String,
    data: JsonUpcase<EditUserData>,
    headers: AdminHeaders,
    conn: DbConn,
) -> EmptyResult {
    let data: EditUserData = data.into_inner().data;

    let new_type = match UserOrgType::from_str(&data.Type.into_string()) {
        Some(new_type) => new_type,
        None => err!("Invalid type"),
    };

    let mut user_to_edit = match UserOrganization::find_by_uuid_and_org(&org_user_id, &org_id, &conn).await {
        Some(user) => user,
        None => err!("The specified user isn't member of the organization"),
    };

    if new_type != user_to_edit.atype
        && (user_to_edit.atype >= UserOrgType::Admin || new_type >= UserOrgType::Admin)
        && headers.org_user_type != UserOrgType::Owner
    {
        err!("Only Owners can grant and remove Admin or Owner privileges")
    }

    if user_to_edit.atype == UserOrgType::Owner && headers.org_user_type != UserOrgType::Owner {
        err!("Only Owners can edit Owner users")
    }

    if user_to_edit.atype == UserOrgType::Owner && new_type != UserOrgType::Owner {
        // Removing owner permmission, check that there is at least one other confirmed owner
        if UserOrganization::count_confirmed_by_org_and_type(&org_id, UserOrgType::Owner, &conn).await <= 1 {
            err!("Can't delete the last owner")
        }
    }

    // This check is also done at accept_invite(), _confirm_invite, _activate_user(), edit_user(), admin::update_user_org_type
    // It returns different error messages per function.
    if new_type < UserOrgType::Admin {
        match OrgPolicy::is_user_allowed(&user_to_edit.user_uuid, &org_id, true, &conn).await {
            Ok(_) => {}
            Err(OrgPolicyErr::TwoFactorMissing) => {
                err!("You cannot modify this user to this type because it has no two-step login method activated");
            }
            Err(OrgPolicyErr::SingleOrgEnforced) => {
                err!("You cannot modify this user to this type because it is a member of an organization which forbids it");
            }
        }
    }

    user_to_edit.access_all = data.AccessAll;
    user_to_edit.atype = new_type as i32;

    // Delete all the odd collections
    for c in CollectionUser::find_by_organization_and_user_uuid(&org_id, &user_to_edit.user_uuid, &conn).await {
        c.delete(&conn).await?;
    }

    // If no accessAll, add the collections received
    if !data.AccessAll {
        for col in data.Collections.iter().flatten() {
            match Collection::find_by_uuid_and_org(&col.Id, &org_id, &conn).await {
                None => err!("Collection not found in Organization"),
                Some(collection) => {
                    CollectionUser::save(
                        &user_to_edit.user_uuid,
                        &collection.uuid,
                        col.ReadOnly,
                        col.HidePasswords,
                        &conn,
                    )
                    .await?;
                }
            }
        }
    }

    user_to_edit.save(&conn).await
}

#[delete("/organizations/<org_id>/users", data = "<data>")]
async fn bulk_delete_user(
    org_id: String,
    data: JsonUpcase<OrgBulkIds>,
    headers: AdminHeaders,
    conn: DbConn,
) -> Json<Value> {
    let data: OrgBulkIds = data.into_inner().data;

    let mut bulk_response = Vec::new();
    for org_user_id in data.Ids {
        let err_msg = match _delete_user(&org_id, &org_user_id, &headers, &conn).await {
            Ok(_) => String::from(""),
            Err(e) => format!("{:?}", e),
        };

        bulk_response.push(json!(
            {
                "Object": "OrganizationBulkConfirmResponseModel",
                "Id": org_user_id,
                "Error": err_msg
            }
        ))
    }

    Json(json!({
        "Data": bulk_response,
        "Object": "list",
        "ContinuationToken": null
    }))
}

#[delete("/organizations/<org_id>/users/<org_user_id>")]
async fn delete_user(org_id: String, org_user_id: String, headers: AdminHeaders, conn: DbConn) -> EmptyResult {
    _delete_user(&org_id, &org_user_id, &headers, &conn).await
}

async fn _delete_user(org_id: &str, org_user_id: &str, headers: &AdminHeaders, conn: &DbConn) -> EmptyResult {
    let user_to_delete = match UserOrganization::find_by_uuid_and_org(org_user_id, org_id, conn).await {
        Some(user) => user,
        None => err!("User to delete isn't member of the organization"),
    };

    if user_to_delete.atype != UserOrgType::User && headers.org_user_type != UserOrgType::Owner {
        err!("Only Owners can delete Admins or Owners")
    }

    if user_to_delete.atype == UserOrgType::Owner {
        // Removing owner, check that there is at least one other confirmed owner
        if UserOrganization::count_confirmed_by_org_and_type(org_id, UserOrgType::Owner, conn).await <= 1 {
            err!("Can't delete the last owner")
        }
    }

    user_to_delete.delete(conn).await
}

#[post("/organizations/<org_id>/users/<org_user_id>/delete")]
async fn post_delete_user(org_id: String, org_user_id: String, headers: AdminHeaders, conn: DbConn) -> EmptyResult {
    delete_user(org_id, org_user_id, headers, conn).await
}

#[post("/organizations/<org_id>/users/public-keys", data = "<data>")]
async fn bulk_public_keys(
    org_id: String,
    data: JsonUpcase<OrgBulkIds>,
    _headers: AdminHeaders,
    conn: DbConn,
) -> Json<Value> {
    let data: OrgBulkIds = data.into_inner().data;

    let mut bulk_response = Vec::new();
    // Check all received UserOrg UUID's and find the matching User to retreive the public-key.
    // If the user does not exists, just ignore it, and do not return any information regarding that UserOrg UUID.
    // The web-vault will then ignore that user for the folowing steps.
    for user_org_id in data.Ids {
        match UserOrganization::find_by_uuid_and_org(&user_org_id, &org_id, &conn).await {
            Some(user_org) => match User::find_by_uuid(&user_org.user_uuid, &conn).await {
                Some(user) => bulk_response.push(json!(
                    {
                        "Object": "organizationUserPublicKeyResponseModel",
                        "Id": user_org_id,
                        "UserId": user.uuid,
                        "Key": user.public_key
                    }
                )),
                None => debug!("User doesn't exist"),
            },
            None => debug!("UserOrg doesn't exist"),
        }
    }

    Json(json!({
        "Data": bulk_response,
        "Object": "list",
        "ContinuationToken": null
    }))
}

use super::ciphers::update_cipher_from_data;
use super::ciphers::CipherData;

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct ImportData {
    Ciphers: Vec<CipherData>,
    Collections: Vec<NewCollectionData>,
    CollectionRelationships: Vec<RelationsData>,
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct RelationsData {
    // Cipher index
    Key: usize,
    // Collection index
    Value: usize,
}

#[post("/ciphers/import-organization?<query..>", data = "<data>")]
async fn post_org_import(
    query: OrgIdData,
    data: JsonUpcase<ImportData>,
    headers: AdminHeaders,
    conn: DbConn,
    nt: Notify<'_>,
) -> EmptyResult {
    let data: ImportData = data.into_inner().data;
    let org_id = query.organization_id;

    let collections = stream::iter(data.Collections)
        .then(|coll| async {
            let collection = Collection::new(org_id.clone(), coll.Name);
            if collection.save(&conn).await.is_err() {
                err!("Failed to create Collection");
            }

            Ok(collection)
        })
        .collect::<Vec<_>>()
        .await;

    // Read the relations between collections and ciphers
    let mut relations = Vec::new();
    for relation in data.CollectionRelationships {
        relations.push((relation.Key, relation.Value));
    }

    let headers: Headers = headers.into();

    let ciphers = stream::iter(data.Ciphers)
        .then(|cipher_data| async {
            let mut cipher = Cipher::new(cipher_data.Type, cipher_data.Name.clone());
            update_cipher_from_data(&mut cipher, cipher_data, &headers, false, &conn, &nt, UpdateType::None).await.ok();
            cipher
        })
        .collect::<Vec<Cipher>>()
        .await;

    // Assign the collections
    for (cipher_index, coll_index) in relations {
        let cipher_id = &ciphers[cipher_index].uuid;
        let coll = &collections[coll_index];
        let coll_id = match coll {
            Ok(coll) => coll.uuid.as_str(),
            Err(_) => err!("Failed to assign to collection"),
        };

        CollectionCipher::save(cipher_id, coll_id, &conn).await?;
    }

    let mut user = headers.user;
    user.update_revision(&conn).await
}

#[get("/organizations/<org_id>/policies")]
async fn list_policies(org_id: String, _headers: AdminHeaders, conn: DbConn) -> Json<Value> {
    let policies = OrgPolicy::find_by_org(&org_id, &conn).await;
    let policies_json: Vec<Value> = policies.iter().map(OrgPolicy::to_json).collect();

    Json(json!({
        "Data": policies_json,
        "Object": "list",
        "ContinuationToken": null
    }))
}

#[get("/organizations/<org_id>/policies/token?<token>")]
async fn list_policies_token(org_id: String, token: String, conn: DbConn) -> JsonResult {
    let invite = crate::auth::decode_invite(&token)?;

    let invite_org_id = match invite.org_id {
        Some(invite_org_id) => invite_org_id,
        None => err!("Invalid token"),
    };

    if invite_org_id != org_id {
        err!("Token doesn't match request organization");
    }

    // TODO: We receive the invite token as ?token=<>, validate it contains the org id
    let policies = OrgPolicy::find_by_org(&org_id, &conn).await;
    let policies_json: Vec<Value> = policies.iter().map(OrgPolicy::to_json).collect();

    Ok(Json(json!({
        "Data": policies_json,
        "Object": "list",
        "ContinuationToken": null
    })))
}

#[get("/organizations/<org_id>/policies/<pol_type>")]
async fn get_policy(org_id: String, pol_type: i32, _headers: AdminHeaders, conn: DbConn) -> JsonResult {
    let pol_type_enum = match OrgPolicyType::from_i32(pol_type) {
        Some(pt) => pt,
        None => err!("Invalid or unsupported policy type"),
    };

    let policy = match OrgPolicy::find_by_org_and_type(&org_id, pol_type_enum, &conn).await {
        Some(p) => p,
        None => OrgPolicy::new(org_id, pol_type_enum, "{}".to_string()),
    };

    Ok(Json(policy.to_json()))
}

#[derive(Deserialize)]
struct PolicyData {
    enabled: bool,
    #[serde(rename = "type")]
    _type: i32,
    data: Option<Value>,
}

#[put("/organizations/<org_id>/policies/<pol_type>", data = "<data>")]
async fn put_policy(
    org_id: String,
    pol_type: i32,
    data: Json<PolicyData>,
    _headers: AdminHeaders,
    conn: DbConn,
) -> JsonResult {
    let data: PolicyData = data.into_inner();

    let pol_type_enum = match OrgPolicyType::from_i32(pol_type) {
        Some(pt) => pt,
        None => err!("Invalid or unsupported policy type"),
    };

    // When enabling the TwoFactorAuthentication policy, remove this org's members that do have 2FA
    if pol_type_enum == OrgPolicyType::TwoFactorAuthentication && data.enabled {
        for member in UserOrganization::find_by_org(&org_id, &conn).await.into_iter() {
            let user_twofactor_disabled = TwoFactor::find_by_user(&member.user_uuid, &conn).await.is_empty();

            // Policy only applies to non-Owner/non-Admin members who have accepted joining the org
            // Invited users still need to accept the invite and will get an error when they try to accept the invite.
            if user_twofactor_disabled
                && member.atype < UserOrgType::Admin
                && member.status != UserOrgStatus::Invited as i32
            {
                if CONFIG.mail_enabled() {
                    let org = Organization::find_by_uuid(&member.org_uuid, &conn).await.unwrap();
                    let user = User::find_by_uuid(&member.user_uuid, &conn).await.unwrap();

                    mail::send_2fa_removed_from_org(&user.email, &org.name).await?;
                }
                member.delete(&conn).await?;
            }
        }
    }

    // When enabling the SingleOrg policy, remove this org's members that are members of other orgs
    if pol_type_enum == OrgPolicyType::SingleOrg && data.enabled {
        for member in UserOrganization::find_by_org(&org_id, &conn).await.into_iter() {
            // Policy only applies to non-Owner/non-Admin members who have accepted joining the org
            // Exclude invited and revoked users when checking for this policy.
            // Those users will not be allowed to accept or be activated because of the policy checks done there.
            // We check if the count is larger then 1, because it includes this organization also.
            if member.atype < UserOrgType::Admin
                && member.status != UserOrgStatus::Invited as i32
                && UserOrganization::count_accepted_and_confirmed_by_user(&member.user_uuid, &conn).await > 1
            {
                if CONFIG.mail_enabled() {
                    let org = Organization::find_by_uuid(&member.org_uuid, &conn).await.unwrap();
                    let user = User::find_by_uuid(&member.user_uuid, &conn).await.unwrap();

                    mail::send_single_org_removed_from_org(&user.email, &org.name).await?;
                }
                member.delete(&conn).await?;
            }
        }
    }

    let mut policy = match OrgPolicy::find_by_org_and_type(&org_id, pol_type_enum, &conn).await {
        Some(p) => p,
        None => OrgPolicy::new(org_id, pol_type_enum, "{}".to_string()),
    };

    policy.enabled = data.enabled;
    policy.data = serde_json::to_string(&data.data)?;
    policy.save(&conn).await?;

    Ok(Json(policy.to_json()))
}

#[allow(unused_variables)]
#[get("/organizations/<org_id>/tax")]
fn get_organization_tax(org_id: String, _headers: Headers) -> Json<Value> {
    // Prevent a 404 error, which also causes Javascript errors.
    // Upstream sends "Only allowed when not self hosted." As an error message.
    // If we do the same it will also output this to the log, which is overkill.
    // An empty list/data also works fine.
    Json(_empty_data_json())
}

#[get("/plans")]
fn get_plans() -> Json<Value> {
    // Respond with a minimal json just enough to allow the creation of an new organization.
    Json(json!({
        "Object": "list",
        "Data": [{
            "Object": "plan",
            "Type": 0,
            "Product": 0,
            "Name": "Free",
            "NameLocalizationKey": "planNameFree",
            "DescriptionLocalizationKey": "planDescFree"
        }],
        "ContinuationToken": null
    }))
}

#[get("/plans/sales-tax-rates")]
fn get_plans_tax_rates(_headers: Headers) -> Json<Value> {
    // Prevent a 404 error, which also causes Javascript errors.
    Json(_empty_data_json())
}

fn _empty_data_json() -> Value {
    json!({
        "Object": "list",
        "Data": [],
        "ContinuationToken": null
    })
}

#[derive(Deserialize, Debug)]
#[allow(non_snake_case, dead_code)]
struct OrgImportGroupData {
    Name: String,       // "GroupName"
    ExternalId: String, // "cn=GroupName,ou=Groups,dc=example,dc=com"
    Users: Vec<String>, // ["uid=user,ou=People,dc=example,dc=com"]
}

#[derive(Deserialize, Debug)]
#[allow(non_snake_case)]
struct OrgImportUserData {
    Email: String, // "user@maildomain.net"
    #[allow(dead_code)]
    ExternalId: String, // "uid=user,ou=People,dc=example,dc=com"
    Deleted: bool,
}

#[derive(Deserialize, Debug)]
#[allow(non_snake_case)]
struct OrgImportData {
    #[allow(dead_code)]
    Groups: Vec<OrgImportGroupData>,
    OverwriteExisting: bool,
    Users: Vec<OrgImportUserData>,
}

#[post("/organizations/<org_id>/import", data = "<data>")]
async fn import(org_id: String, data: JsonUpcase<OrgImportData>, headers: Headers, conn: DbConn) -> EmptyResult {
    let data = data.into_inner().data;

    // TODO: Currently we aren't storing the externalId's anywhere, so we also don't have a way
    // to differentiate between auto-imported users and manually added ones.
    // This means that this endpoint can end up removing users that were added manually by an admin,
    // as opposed to upstream which only removes auto-imported users.

    // User needs to be admin or owner to use the Directry Connector
    match UserOrganization::find_by_user_and_org(&headers.user.uuid, &org_id, &conn).await {
        Some(user_org) if user_org.atype >= UserOrgType::Admin => { /* Okay, nothing to do */ }
        Some(_) => err!("User has insufficient permissions to use Directory Connector"),
        None => err!("User not part of organization"),
    };

    for user_data in &data.Users {
        if user_data.Deleted {
            // If user is marked for deletion and it exists, delete it
            if let Some(user_org) = UserOrganization::find_by_email_and_org(&user_data.Email, &org_id, &conn).await {
                user_org.delete(&conn).await?;
            }

        // If user is not part of the organization, but it exists
        } else if UserOrganization::find_by_email_and_org(&user_data.Email, &org_id, &conn).await.is_none() {
            if let Some(user) = User::find_by_mail(&user_data.Email, &conn).await {
                let user_org_status = if CONFIG.mail_enabled() {
                    UserOrgStatus::Invited as i32
                } else {
                    UserOrgStatus::Accepted as i32 // Automatically mark user as accepted if no email invites
                };

                let mut new_org_user = UserOrganization::new(user.uuid.clone(), org_id.clone());
                new_org_user.access_all = false;
                new_org_user.atype = UserOrgType::User as i32;
                new_org_user.status = user_org_status;

                new_org_user.save(&conn).await?;

                if CONFIG.mail_enabled() {
                    let org_name = match Organization::find_by_uuid(&org_id, &conn).await {
                        Some(org) => org.name,
                        None => err!("Error looking up organization"),
                    };

                    mail::send_invite(
                        &user_data.Email,
                        &user.uuid,
                        Some(org_id.clone()),
                        Some(new_org_user.uuid),
                        &org_name,
                        Some(headers.user.email.clone()),
                    )
                    .await?;
                }
            }
        }
    }

    // If this flag is enabled, any user that isn't provided in the Users list will be removed (by default they will be kept unless they have Deleted == true)
    if data.OverwriteExisting {
        for user_org in UserOrganization::find_by_org_and_type(&org_id, UserOrgType::User, &conn).await {
            if let Some(user_email) = User::find_by_uuid(&user_org.user_uuid, &conn).await.map(|u| u.email) {
                if !data.Users.iter().any(|u| u.Email == user_email) {
                    user_org.delete(&conn).await?;
                }
            }
        }
    }

    Ok(())
}

// Pre web-vault v2022.9.x endpoint
#[put("/organizations/<org_id>/users/<org_user_id>/deactivate")]
async fn deactivate_organization_user(
    org_id: String,
    org_user_id: String,
    headers: AdminHeaders,
    conn: DbConn,
) -> EmptyResult {
    _revoke_organization_user(&org_id, &org_user_id, &headers, &conn).await
}

// Pre web-vault v2022.9.x endpoint
#[put("/organizations/<org_id>/users/deactivate", data = "<data>")]
async fn bulk_deactivate_organization_user(
    org_id: String,
    data: JsonUpcase<Value>,
    headers: AdminHeaders,
    conn: DbConn,
) -> Json<Value> {
    bulk_revoke_organization_user(org_id, data, headers, conn).await
}

#[put("/organizations/<org_id>/users/<org_user_id>/revoke")]
async fn revoke_organization_user(
    org_id: String,
    org_user_id: String,
    headers: AdminHeaders,
    conn: DbConn,
) -> EmptyResult {
    _revoke_organization_user(&org_id, &org_user_id, &headers, &conn).await
}

#[put("/organizations/<org_id>/users/revoke", data = "<data>")]
async fn bulk_revoke_organization_user(
    org_id: String,
    data: JsonUpcase<Value>,
    headers: AdminHeaders,
    conn: DbConn,
) -> Json<Value> {
    let data = data.into_inner().data;

    let mut bulk_response = Vec::new();
    match data["Ids"].as_array() {
        Some(org_users) => {
            for org_user_id in org_users {
                let org_user_id = org_user_id.as_str().unwrap_or_default();
                let err_msg = match _revoke_organization_user(&org_id, org_user_id, &headers, &conn).await {
                    Ok(_) => String::from(""),
                    Err(e) => format!("{:?}", e),
                };

                bulk_response.push(json!(
                    {
                        "Object": "OrganizationUserBulkResponseModel",
                        "Id": org_user_id,
                        "Error": err_msg
                    }
                ));
            }
        }
        None => error!("No users to revoke"),
    }

    Json(json!({
        "Data": bulk_response,
        "Object": "list",
        "ContinuationToken": null
    }))
}

async fn _revoke_organization_user(
    org_id: &str,
    org_user_id: &str,
    headers: &AdminHeaders,
    conn: &DbConn,
) -> EmptyResult {
    match UserOrganization::find_by_uuid_and_org(org_user_id, org_id, conn).await {
        Some(mut user_org) if user_org.status > UserOrgStatus::Revoked as i32 => {
            if user_org.user_uuid == headers.user.uuid {
                err!("You cannot revoke yourself")
            }
            if user_org.atype == UserOrgType::Owner && headers.org_user_type != UserOrgType::Owner {
                err!("Only owners can revoke other owners")
            }
            if user_org.atype == UserOrgType::Owner
                && UserOrganization::count_confirmed_by_org_and_type(org_id, UserOrgType::Owner, conn).await <= 1
            {
                err!("Organization must have at least one confirmed owner")
            }

            user_org.revoke();
            user_org.save(conn).await?;
        }
        Some(_) => err!("User is already revoked"),
        None => err!("User not found in organization"),
    }
    Ok(())
}

// Pre web-vault v2022.9.x endpoint
#[put("/organizations/<org_id>/users/<org_user_id>/activate")]
async fn activate_organization_user(
    org_id: String,
    org_user_id: String,
    headers: AdminHeaders,
    conn: DbConn,
) -> EmptyResult {
    _restore_organization_user(&org_id, &org_user_id, &headers, &conn).await
}

// Pre web-vault v2022.9.x endpoint
#[put("/organizations/<org_id>/users/activate", data = "<data>")]
async fn bulk_activate_organization_user(
    org_id: String,
    data: JsonUpcase<Value>,
    headers: AdminHeaders,
    conn: DbConn,
) -> Json<Value> {
    bulk_restore_organization_user(org_id, data, headers, conn).await
}

#[put("/organizations/<org_id>/users/<org_user_id>/restore")]
async fn restore_organization_user(
    org_id: String,
    org_user_id: String,
    headers: AdminHeaders,
    conn: DbConn,
) -> EmptyResult {
    _restore_organization_user(&org_id, &org_user_id, &headers, &conn).await
}

#[put("/organizations/<org_id>/users/restore", data = "<data>")]
async fn bulk_restore_organization_user(
    org_id: String,
    data: JsonUpcase<Value>,
    headers: AdminHeaders,
    conn: DbConn,
) -> Json<Value> {
    let data = data.into_inner().data;

    let mut bulk_response = Vec::new();
    match data["Ids"].as_array() {
        Some(org_users) => {
            for org_user_id in org_users {
                let org_user_id = org_user_id.as_str().unwrap_or_default();
                let err_msg = match _restore_organization_user(&org_id, org_user_id, &headers, &conn).await {
                    Ok(_) => String::from(""),
                    Err(e) => format!("{:?}", e),
                };

                bulk_response.push(json!(
                    {
                        "Object": "OrganizationUserBulkResponseModel",
                        "Id": org_user_id,
                        "Error": err_msg
                    }
                ));
            }
        }
        None => error!("No users to restore"),
    }

    Json(json!({
        "Data": bulk_response,
        "Object": "list",
        "ContinuationToken": null
    }))
}

async fn _restore_organization_user(
    org_id: &str,
    org_user_id: &str,
    headers: &AdminHeaders,
    conn: &DbConn,
) -> EmptyResult {
    match UserOrganization::find_by_uuid_and_org(org_user_id, org_id, conn).await {
        Some(mut user_org) if user_org.status < UserOrgStatus::Accepted as i32 => {
            if user_org.user_uuid == headers.user.uuid {
                err!("You cannot restore yourself")
            }
            if user_org.atype == UserOrgType::Owner && headers.org_user_type != UserOrgType::Owner {
                err!("Only owners can restore other owners")
            }

            // This check is also done at accept_invite(), _confirm_invite, _activate_user(), edit_user(), admin::update_user_org_type
            // It returns different error messages per function.
            if user_org.atype < UserOrgType::Admin {
                match OrgPolicy::is_user_allowed(&user_org.user_uuid, org_id, false, conn).await {
                    Ok(_) => {}
                    Err(OrgPolicyErr::TwoFactorMissing) => {
                        err!("You cannot restore this user because it has no two-step login method activated");
                    }
                    Err(OrgPolicyErr::SingleOrgEnforced) => {
                        err!("You cannot restore this user because it is a member of an organization which forbids it");
                    }
                }
            }

            user_org.restore();
            user_org.save(conn).await?;
        }
        Some(_) => err!("User is already active"),
        None => err!("User not found in organization"),
    }
    Ok(())
}

// This is a new function active since the v2022.9.x clients.
// It combines the previous two calls done before.
// We call those two functions here and combine them our selfs.
//
// NOTE: It seems clients can't handle uppercase-first keys!!
//       We need to convert all keys so they have the first character to be a lowercase.
//       Else the export will be just an empty JSON file.
#[get("/organizations/<org_id>/export")]
async fn get_org_export(org_id: String, headers: AdminHeaders, conn: DbConn) -> Json<Value> {
    // Also both main keys here need to be lowercase, else the export will fail.
    Json(json!({
        "collections": convert_json_key_lcase_first(_get_org_collections(&org_id, &conn).await),
        "ciphers": convert_json_key_lcase_first(_get_org_details(&org_id, &headers.host, &headers.user.uuid, &conn).await),
    }))
}
