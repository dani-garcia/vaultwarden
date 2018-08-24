use rocket::Route;
use rocket_contrib::Json;

use db::DbConn;
use api::JsonResult;
use auth::Headers;

pub fn routes() -> Vec<Route> {
    routes![negotiate]
}

#[post("/hub/negotiate")]
fn negotiate(_headers: Headers, _conn: DbConn) -> JsonResult {
    use data_encoding::BASE64URL;
    use crypto;

    // Store this in db?
    let conn_id = BASE64URL.encode(&crypto::get_random(vec![0u8; 16]));

    // TODO: Implement transports
    // Rocket WS support: https://github.com/SergioBenitez/Rocket/issues/90
    // Rocket SSE support: https://github.com/SergioBenitez/Rocket/issues/33
    Ok(Json(json!({
        "connectionId": conn_id,
        "availableTransports":[
                // {"transport":"WebSockets", "transferFormats":["Text","Binary"]},
                // {"transport":"ServerSentEvents", "transferFormats":["Text"]},
                // {"transport":"LongPolling", "transferFormats":["Text","Binary"]}
        ]
    })))
}