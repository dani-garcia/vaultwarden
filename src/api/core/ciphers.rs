use std::io::{Cursor, Read};

use rocket::{Route, Data};
use rocket::http::ContentType;
use rocket::response::status::BadRequest;

use rocket_contrib::{Json, Value};

use multipart::server::Multipart;

use db::DbConn;
use db::models::*;
use util;

use auth::Headers;

#[get("/sync")]
fn sync(headers: Headers, conn: DbConn) -> Result<Json, BadRequest<Json>> {
    let user = headers.user;

    let folders = Folder::find_by_user(&user.uuid, &conn);
    let folders_json: Vec<Value> = folders.iter().map(|c| c.to_json()).collect();

    let ciphers = Cipher::find_by_user(&user.uuid, &conn);
    let ciphers_json: Vec<Value> = ciphers.iter().map(|c| c.to_json()).collect();

    Ok(Json(json!({
        "Profile": user.to_json(),
        "Folders": folders_json,
        "Ciphers": ciphers_json,
        "Domains": {
            "EquivalentDomains": [],
            "GlobalEquivalentDomains": [],
            "Object": "domains",
        },
        "Object": "sync"
    })))
}


#[get("/ciphers")]
fn get_ciphers(headers: Headers, conn: DbConn) -> Result<Json, BadRequest<Json>> {
    let ciphers = Cipher::find_by_user(&headers.user.uuid, &conn);

    let ciphers_json: Vec<Value> = ciphers.iter().map(|c| c.to_json()).collect();

    Ok(Json(json!({
      "Data": ciphers_json,
      "Object": "list",
    })))
}

#[get("/ciphers/<uuid>")]
fn get_cipher(uuid: String, headers: Headers, conn: DbConn) -> Result<Json, BadRequest<Json>> {
    let cipher = match Cipher::find_by_uuid(&uuid, &conn) {
        Some(cipher) => cipher,
        None => err!("Cipher doesn't exist")
    };

    if cipher.user_uuid != headers.user.uuid {
        err!("Cipher is now owned by user")
    }

    Ok(Json(cipher.to_json()))
}

#[derive(Deserialize, Debug)]
#[allow(non_snake_case)]
struct CipherData {
    #[serde(rename = "type")]
    type_: i32,
    folderId: Option<String>,
    organizationId: Option<String>,
    name: Option<String>,
    notes: Option<String>,
    favorite: Option<bool>,
    login: Option<Value>,
    card: Option<Value>,
    fields: Option<Vec<Value>>,
}

#[post("/ciphers", data = "<data>")]
fn post_ciphers(data: Json<CipherData>, headers: Headers, conn: DbConn) -> Result<Json, BadRequest<Json>> {
    let mut cipher = Cipher::new(headers.user.uuid.clone(),
                                 data.type_,
                                 data.favorite.unwrap_or(false));

    if let Some(ref folder_id) = data.folderId {
        // TODO: Validate folder is owned by user
        cipher.folder_uuid = Some(folder_id.clone());
    }

    if let Some(ref org_id) = data.organizationId {
        cipher.organization_uuid = Some(org_id.clone());
    }

    cipher.data = match value_from_data(&data) {
        Ok(value) => {
            use serde_json;
            println!("--- {:?}", serde_json::to_string(&value));
            println!("--- {:?}", value.to_string());

            value.to_string()
        }
        Err(msg) => err!(msg)
    };

    cipher.save(&conn);

    Ok(Json(cipher.to_json()))
}

fn value_from_data(data: &CipherData) -> Result<Value, &'static str> {
    let mut values = json!({
        "Name": data.name,
        "Notes": data.notes
    });

    match data.type_ {
        1 /*Login*/ => {
            let login_data = match data.login {
                Some(ref login) => login.clone(),
                None => return Err("Login data missing")
            };

            if !copy_values(&login_data, &mut values) {
                return Err("Login data invalid");
            }
        }
        3 /*Card*/ => {
            let card_data = match data.card {
                Some(ref card) => card.clone(),
                None => return Err("Card data missing")
            };

            if !copy_values(&card_data, &mut values) {
                return Err("Card data invalid");
            }
        }
        _ => return Err("Unknown type")
    }

    if let Some(ref fields) = data.fields {
        values["Fields"] = Value::Array(fields.iter().map(|f| {
            use std::collections::BTreeMap;
            use serde_json;

            let empty_map: BTreeMap<String, Value> = BTreeMap::new();
            let mut value = serde_json::to_value(empty_map).unwrap();

            copy_values(&f, &mut value);

            value
        }).collect());
    } else {
        values["Fields"] = Value::Null;
    }

    Ok(values)
}

fn copy_values(from: &Value, to: &mut Value) -> bool {
    let map = match from.as_object() {
        Some(map) => map,
        None => return false
    };

    for (key, val) in map {
        to[util::upcase_first(key)] = val.clone();
    }

    true
}

#[post("/ciphers/import", data = "<data>")]
fn post_ciphers_import(data: Json<Value>, headers: Headers, conn: DbConn) -> Result<Json, BadRequest<Json>> {
    println!("{:#?}", data);
    err!("Not implemented")
}

#[post("/ciphers/<uuid>/attachment", format = "multipart/form-data", data = "<data>")]
fn post_attachment(uuid: String, data: Data, content_type: &ContentType, headers: Headers, conn: DbConn) -> Result<Json, BadRequest<Json>> {
    // TODO: Check if cipher exists

    let mut params = content_type.params();
    let boundary_pair = params.next().expect("No boundary provided"); // ("boundary", "----WebKitFormBoundary...")
    let boundary = boundary_pair.1;

    use data_encoding::BASE64URL;
    use crypto;
    use CONFIG;

    // TODO: Maybe use the same format as the official server?
    let attachment_id = BASE64URL.encode(&crypto::get_random_64());
    let path = format!("{}/{}/{}", CONFIG.attachments_folder,
                       headers.user.uuid, attachment_id);
    println!("Path {:#?}", path);

    let mut mp = Multipart::with_body(data.open(), boundary);
    match mp.save().with_dir(path).into_entries() {
        Some(entries) => {
            println!("Entries {:#?}", entries);

            let saved_file = &entries.files["data"][0]; // Only one file at a time
            let file_name = &saved_file.filename; // This is provided by the client, don't trust it
            let file_size = &saved_file.size;
        }
        None => err!("No data entries")
    }

    err!("Not implemented")
}

#[delete("/ciphers/<uuid>/attachment/<attachment_id>")]
fn delete_attachment(uuid: String, attachment_id: String, headers: Headers, conn: DbConn) -> Result<Json, BadRequest<Json>> {
    if uuid != headers.user.uuid {
        err!("Permission denied")
    }

    // Delete file

    // Delete entry in cipher

    err!("Not implemented")
}

#[post("/ciphers/<uuid>")]
fn post_cipher(uuid: String, headers: Headers, conn: DbConn) -> Result<Json, BadRequest<Json>> {
    put_cipher(uuid, headers, conn)
}

#[put("/ciphers/<uuid>")]
fn put_cipher(uuid: String, headers: Headers, conn: DbConn) -> Result<Json, BadRequest<Json>> { err!("Not implemented") }

#[delete("/ciphers/<uuid>")]
fn delete_cipher(uuid: String, headers: Headers, conn: DbConn) -> Result<Json, BadRequest<Json>> { err!("Not implemented") }

#[post("/ciphers/delete", data = "<data>")]
fn delete_all(data: Json<Value>, headers: Headers, conn: DbConn) -> Result<Json, BadRequest<Json>> {
    let password_hash = data["masterPasswordHash"].as_str().unwrap();

    let user = headers.user;

    if !user.check_valid_password(password_hash) {
        err!("Invalid password")
    }

    // Cipher::delete_from_user(&conn);

    err!("Not implemented")
}
