use std::path::Path;

use rocket::Data;
use rocket::http::ContentType;
use rocket::response::status::BadRequest;

use rocket_contrib::{Json, Value};

use multipart::server::{Multipart, SaveResult};
use multipart::server::save::SavedData;

use data_encoding::HEXLOWER;

use db::DbConn;
use db::models::*;

use util;
use crypto;

use auth::Headers;

use CONFIG;

#[get("/sync")]
fn sync(headers: Headers, conn: DbConn) -> Result<Json, BadRequest<Json>> {
    let user = &headers.user;

    let folders = Folder::find_by_user(&user.uuid, &conn);
    let folders_json: Vec<Value> = folders.iter().map(|c| c.to_json()).collect();

    let ciphers = Cipher::find_by_user(&user.uuid, &conn);
    let ciphers_json: Vec<Value> = ciphers.iter().map(|c| c.to_json(&headers.host, &conn)).collect();

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

    let ciphers_json: Vec<Value> = ciphers.iter().map(|c| c.to_json(&headers.host, &conn)).collect();

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
        err!("Cipher is not owned by user")
    }

    Ok(Json(cipher.to_json(&headers.host, &conn)))
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
        match Folder::find_by_uuid(folder_id, &conn) {
            Some(folder) => {
                if folder.user_uuid != headers.user.uuid {
                    err!("Folder is not owned by user")
                }
            }
            None => err!("Folder doesn't exist")
        }

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

    Ok(Json(cipher.to_json(&headers.host, &conn)))
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
    let cipher = match Cipher::find_by_uuid(&uuid, &conn) {
        Some(cipher) => cipher,
        None => err!("Cipher doesn't exist")
    };

    if cipher.user_uuid != headers.user.uuid {
        err!("Cipher is not owned by user")
    }

    let mut params = content_type.params();
    let boundary_pair = params.next().expect("No boundary provided");
    let boundary = boundary_pair.1;

    let base_path = Path::new(&CONFIG.attachments_folder).join(&cipher.uuid);

    Multipart::with_body(data.open(), boundary).foreach_entry(|mut field| {
        let name = field.headers.filename.unwrap(); // This is provided by the client, don't trust it

        let file_name = HEXLOWER.encode(&crypto::get_random(vec![0; 10]));
        let path = base_path.join(&file_name);

        let size = match field.data.save()
            .memory_threshold(0)
            .size_limit(None)
            .with_path(path) {
            SaveResult::Full(SavedData::File(_, size)) => size as i32,
            _ => return
        };

        let attachment = Attachment::new(file_name, cipher.uuid.clone(), name, size);
        println!("Attachment: {:#?}", attachment);
        attachment.save(&conn);
    });

    Ok(Json(cipher.to_json(&headers.host, &conn)))
}

#[post("/ciphers/<uuid>/attachment/<attachment_id>/delete", data = "<_data>")]
fn delete_attachment_post(uuid: String, attachment_id: String, _data: Json<Value>, headers: Headers, conn: DbConn) -> Result<(), BadRequest<Json>> {
    // Data contains a json object with the id, but we don't need it
    delete_attachment(uuid, attachment_id, headers, conn)
}

#[delete("/ciphers/<uuid>/attachment/<attachment_id>")]
fn delete_attachment(uuid: String, attachment_id: String, headers: Headers, conn: DbConn) -> Result<(), BadRequest<Json>> {
    let attachment = match Attachment::find_by_id(&attachment_id, &conn) {
        Some(attachment) => attachment,
        None => err!("Attachment doesn't exist")
    };

    if attachment.cipher_uuid != uuid {
        err!("Attachment from other cipher")
    }

    let cipher = match Cipher::find_by_uuid(&uuid, &conn) {
        Some(cipher) => cipher,
        None => err!("Cipher doesn't exist")
    };

    if cipher.user_uuid != headers.user.uuid {
        err!("Cipher is not owned by user")
    }

    // Delete file
    let file = attachment.get_file_path();
    util::delete_file(&file);

    // Delete entry in cipher
    attachment.delete(&conn);

    Ok(())
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
