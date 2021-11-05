use std::sync::atomic::{AtomicBool, Ordering};

use rocket::Route;
use rocket_contrib::json::Json;
use serde_json::Value as JsonValue;

use crate::{api::EmptyResult, auth::Headers, Error, CONFIG};

pub fn routes() -> Vec<Route> {
    routes![negotiate, websockets_err]
}

static SHOW_WEBSOCKETS_MSG: AtomicBool = AtomicBool::new(true);

#[get("/hub")]
fn websockets_err() -> EmptyResult {
    if CONFIG.websocket_enabled()
        && SHOW_WEBSOCKETS_MSG.compare_exchange(true, false, Ordering::Relaxed, Ordering::Relaxed).is_ok()
    {
        err!(
            "
    ###########################################################
    '/notifications/hub' should be proxied to the websocket server or notifications won't work.
    Go to the Wiki for more info, or disable WebSockets setting WEBSOCKET_ENABLED=false.
    ###########################################################################################\n"
        )
    } else {
        Err(Error::empty())
    }
}

#[post("/hub/negotiate")]
fn negotiate(_headers: Headers) -> Json<JsonValue> {
    use crate::crypto;
    use data_encoding::BASE64URL;

    let conn_id = BASE64URL.encode(&crypto::get_random(vec![0u8; 16]));
    let mut available_transports: Vec<JsonValue> = Vec::new();

    if CONFIG.websocket_enabled() {
        available_transports.push(json!({"transport":"WebSockets", "transferFormats":["Text","Binary"]}));
    }

    // TODO: Implement transports
    // Rocket WS support: https://github.com/SergioBenitez/Rocket/issues/90
    // Rocket SSE support: https://github.com/SergioBenitez/Rocket/issues/33
    // {"transport":"ServerSentEvents", "transferFormats":["Text"]},
    // {"transport":"LongPolling", "transferFormats":["Text","Binary"]}
    Json(json!({
        "connectionId": conn_id,
        "availableTransports": available_transports
    }))
}

//
// Websockets server
//
use std::io;
use std::sync::Arc;
use std::thread;

use ws::{self, util::Token, Factory, Handler, Handshake, Message, Sender};

use chashmap::CHashMap;
use chrono::NaiveDateTime;
use serde_json::from_str;

use crate::db::models::{Cipher, Folder, Send, User};

use rmpv::Value;

fn serialize(val: Value) -> Vec<u8> {
    use rmpv::encode::write_value;

    let mut buf = Vec::new();
    write_value(&mut buf, &val).expect("Error encoding MsgPack");

    // Add size bytes at the start
    // Extracted from BinaryMessageFormat.js
    let mut size: usize = buf.len();
    let mut len_buf: Vec<u8> = Vec::new();

    loop {
        let mut size_part = size & 0x7f;
        size >>= 7;

        if size > 0 {
            size_part |= 0x80;
        }

        len_buf.push(size_part as u8);

        if size == 0 {
            break;
        }
    }

    len_buf.append(&mut buf);
    len_buf
}

fn serialize_date(date: NaiveDateTime) -> Value {
    let seconds: i64 = date.timestamp();
    let nanos: i64 = date.timestamp_subsec_nanos().into();
    let timestamp = nanos << 34 | seconds;

    let bs = timestamp.to_be_bytes();

    // -1 is Timestamp
    // https://github.com/msgpack/msgpack/blob/master/spec.md#timestamp-extension-type
    Value::Ext(-1, bs.to_vec())
}

fn convert_option<T: Into<Value>>(option: Option<T>) -> Value {
    match option {
        Some(a) => a.into(),
        None => Value::Nil,
    }
}

// Server WebSocket handler
pub struct WsHandler {
    out: Sender,
    user_uuid: Option<String>,
    users: WebSocketUsers,
}

const RECORD_SEPARATOR: u8 = 0x1e;
const INITIAL_RESPONSE: [u8; 3] = [0x7b, 0x7d, RECORD_SEPARATOR]; // {, }, <RS>

#[derive(Deserialize)]
struct InitialMessage {
    protocol: String,
    version: i32,
}

const PING_MS: u64 = 15_000;
const PING: Token = Token(1);

const ACCESS_TOKEN_KEY: &str = "access_token=";

impl WsHandler {
    fn err(&self, msg: &'static str) -> ws::Result<()> {
        self.out.close(ws::CloseCode::Invalid)?;

        // We need to specifically return an IO error so ws closes the connection
        let io_error = io::Error::from(io::ErrorKind::InvalidData);
        Err(ws::Error::new(ws::ErrorKind::Io(io_error), msg))
    }

    fn get_request_token(&self, hs: Handshake) -> Option<String> {
        use std::str::from_utf8;

        // Verify we have a token header
        if let Some(header_value) = hs.request.header("Authorization") {
            if let Ok(converted) = from_utf8(header_value) {
                if let Some(token_part) = converted.split("Bearer ").nth(1) {
                    return Some(token_part.into());
                }
            }
        };

        // Otherwise verify the query parameter value
        let path = hs.request.resource();
        if let Some(params) = path.split('?').nth(1) {
            let params_iter = params.split('&').take(1);
            for val in params_iter {
                if let Some(stripped) = val.strip_prefix(ACCESS_TOKEN_KEY) {
                    return Some(stripped.into());
                }
            }
        };

        None
    }
}

impl Handler for WsHandler {
    fn on_open(&mut self, hs: Handshake) -> ws::Result<()> {
        // Path == "/notifications/hub?id=<id>==&access_token=<access_token>"
        //
        // We don't use `id`, and as of around 2020-03-25, the official clients
        // no longer seem to pass `id` (only `access_token`).

        // Get user token from header or query parameter
        let access_token = match self.get_request_token(hs) {
            Some(token) => token,
            _ => return self.err("Missing access token"),
        };

        // Validate the user
        use crate::auth;
        let claims = match auth::decode_login(access_token.as_str()) {
            Ok(claims) => claims,
            Err(_) => return self.err("Invalid access token provided"),
        };

        // Assign the user to the handler
        let user_uuid = claims.sub;
        self.user_uuid = Some(user_uuid.clone());

        // Add the current Sender to the user list
        let handler_insert = self.out.clone();
        let handler_update = self.out.clone();

        self.users.map.upsert(user_uuid, || vec![handler_insert], |ref mut v| v.push(handler_update));

        // Schedule a ping to keep the connection alive
        self.out.timeout(PING_MS, PING)
    }

    fn on_message(&mut self, msg: Message) -> ws::Result<()> {
        if let Message::Text(text) = msg.clone() {
            let json = &text[..text.len() - 1]; // Remove last char

            if let Ok(InitialMessage {
                protocol,
                version,
            }) = from_str::<InitialMessage>(json)
            {
                if &protocol == "messagepack" && version == 1 {
                    return self.out.send(&INITIAL_RESPONSE[..]); // Respond to initial message
                }
            }
        }

        // If it's not the initial message, just echo the message
        self.out.send(msg)
    }

    fn on_timeout(&mut self, event: Token) -> ws::Result<()> {
        if event == PING {
            // send ping
            self.out.send(create_ping())?;

            // reschedule the timeout
            self.out.timeout(PING_MS, PING)
        } else {
            Ok(())
        }
    }
}

struct WsFactory {
    pub users: WebSocketUsers,
}

impl WsFactory {
    pub fn init() -> Self {
        WsFactory {
            users: WebSocketUsers {
                map: Arc::new(CHashMap::new()),
            },
        }
    }
}

impl Factory for WsFactory {
    type Handler = WsHandler;

    fn connection_made(&mut self, out: Sender) -> Self::Handler {
        WsHandler {
            out,
            user_uuid: None,
            users: self.users.clone(),
        }
    }

    fn connection_lost(&mut self, handler: Self::Handler) {
        // Remove handler
        if let Some(user_uuid) = &handler.user_uuid {
            if let Some(mut user_conn) = self.users.map.get_mut(user_uuid) {
                if let Some(pos) = user_conn.iter().position(|x| x == &handler.out) {
                    user_conn.remove(pos);
                }
            }
        }
    }
}

#[derive(Clone)]
pub struct WebSocketUsers {
    map: Arc<CHashMap<String, Vec<Sender>>>,
}

impl WebSocketUsers {
    fn send_update(&self, user_uuid: &str, data: &[u8]) -> ws::Result<()> {
        if let Some(user) = self.map.get(user_uuid) {
            for sender in user.iter() {
                sender.send(data)?;
            }
        }
        Ok(())
    }

    // NOTE: The last modified date needs to be updated before calling these methods
    pub fn send_user_update(&self, ut: UpdateType, user: &User) {
        let data = create_update(
            vec![("UserId".into(), user.uuid.clone().into()), ("Date".into(), serialize_date(user.updated_at))],
            ut,
        );

        self.send_update(&user.uuid, &data).ok();
    }

    pub fn send_folder_update(&self, ut: UpdateType, folder: &Folder) {
        let data = create_update(
            vec![
                ("Id".into(), folder.uuid.clone().into()),
                ("UserId".into(), folder.user_uuid.clone().into()),
                ("RevisionDate".into(), serialize_date(folder.updated_at)),
            ],
            ut,
        );

        self.send_update(&folder.user_uuid, &data).ok();
    }

    pub fn send_cipher_update(&self, ut: UpdateType, cipher: &Cipher, user_uuids: &[String]) {
        let user_uuid = convert_option(cipher.user_uuid.clone());
        let org_uuid = convert_option(cipher.organization_uuid.clone());

        let data = create_update(
            vec![
                ("Id".into(), cipher.uuid.clone().into()),
                ("UserId".into(), user_uuid),
                ("OrganizationId".into(), org_uuid),
                ("CollectionIds".into(), Value::Nil),
                ("RevisionDate".into(), serialize_date(cipher.updated_at)),
            ],
            ut,
        );

        for uuid in user_uuids {
            self.send_update(uuid, &data).ok();
        }
    }

    pub fn send_send_update(&self, ut: UpdateType, send: &Send, user_uuids: &[String]) {
        let user_uuid = convert_option(send.user_uuid.clone());

        let data = create_update(
            vec![
                ("Id".into(), send.uuid.clone().into()),
                ("UserId".into(), user_uuid),
                ("RevisionDate".into(), serialize_date(send.revision_date)),
            ],
            ut,
        );

        for uuid in user_uuids {
            self.send_update(uuid, &data).ok();
        }
    }
}

/* Message Structure
[
    1, // MessageType.Invocation
    {}, // Headers (map)
    null, // InvocationId
    "ReceiveMessage", // Target
    [ // Arguments
        {
            "ContextId": "app_id",
            "Type": ut as i32,
            "Payload": {}
        }
    ]
]
*/
fn create_update(payload: Vec<(Value, Value)>, ut: UpdateType) -> Vec<u8> {
    use rmpv::Value as V;

    let value = V::Array(vec![
        1.into(),
        V::Map(vec![]),
        V::Nil,
        "ReceiveMessage".into(),
        V::Array(vec![V::Map(vec![
            ("ContextId".into(), "app_id".into()),
            ("Type".into(), (ut as i32).into()),
            ("Payload".into(), payload.into()),
        ])]),
    ]);

    serialize(value)
}

fn create_ping() -> Vec<u8> {
    serialize(Value::Array(vec![6.into()]))
}

#[allow(dead_code)]
#[derive(PartialEq)]
pub enum UpdateType {
    CipherUpdate = 0,
    CipherCreate = 1,
    LoginDelete = 2,
    FolderDelete = 3,
    Ciphers = 4,

    Vault = 5,
    OrgKeys = 6,
    FolderCreate = 7,
    FolderUpdate = 8,
    CipherDelete = 9,
    SyncSettings = 10,

    LogOut = 11,

    SyncSendCreate = 12,
    SyncSendUpdate = 13,
    SyncSendDelete = 14,

    None = 100,
}

use rocket::State;
pub type Notify<'a> = State<'a, WebSocketUsers>;

pub fn start_notification_server() -> WebSocketUsers {
    let factory = WsFactory::init();
    let users = factory.users.clone();

    if CONFIG.websocket_enabled() {
        thread::spawn(move || {
            let mut settings = ws::Settings::default();
            settings.max_connections = 500;
            settings.queue_size = 2;
            settings.panic_on_internal = false;

            ws::Builder::new()
                .with_settings(settings)
                .build(factory)
                .unwrap()
                .listen((CONFIG.websocket_address().as_str(), CONFIG.websocket_port()))
                .unwrap();
        });
    }

    users
}
