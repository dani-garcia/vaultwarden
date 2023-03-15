use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use chrono::NaiveDateTime;
use futures::{SinkExt, StreamExt};
use rmpv::Value;
use rocket::Route;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::mpsc::Sender,
};
use tokio_tungstenite::{
    accept_hdr_async,
    tungstenite::{handshake, Message},
};

use crate::{
    api::EmptyResult,
    db::models::{Cipher, Folder, Send, User},
    Error, CONFIG,
};

pub fn routes() -> Vec<Route> {
    routes![websockets_err]
}

#[get("/hub")]
fn websockets_err() -> EmptyResult {
    static SHOW_WEBSOCKETS_MSG: AtomicBool = AtomicBool::new(true);

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

//
// Websockets server
//

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

const RECORD_SEPARATOR: u8 = 0x1e;
const INITIAL_RESPONSE: [u8; 3] = [0x7b, 0x7d, RECORD_SEPARATOR]; // {, }, <RS>

#[derive(Deserialize, Copy, Clone, Eq, PartialEq)]
struct InitialMessage<'a> {
    protocol: &'a str,
    version: i32,
}

static INITIAL_MESSAGE: InitialMessage<'static> = InitialMessage {
    protocol: "messagepack",
    version: 1,
};

// We attach the UUID to the sender so we can differentiate them when we need to remove them from the Vec
type UserSenders = (uuid::Uuid, Sender<Message>);
#[derive(Clone)]
pub struct WebSocketUsers {
    map: Arc<dashmap::DashMap<String, Vec<UserSenders>>>,
}

impl WebSocketUsers {
    async fn send_update(&self, user_uuid: &str, data: &[u8]) {
        if let Some(user) = self.map.get(user_uuid).map(|v| v.clone()) {
            for (_, sender) in user.iter() {
                if sender.send(Message::binary(data)).await.is_err() {
                    // TODO: Delete from map here too?
                }
            }
        }
    }

    // NOTE: The last modified date needs to be updated before calling these methods
    pub async fn send_user_update(&self, ut: UpdateType, user: &User) {
        let data = create_update(
            vec![("UserId".into(), user.uuid.clone().into()), ("Date".into(), serialize_date(user.updated_at))],
            ut,
            None,
        );

        self.send_update(&user.uuid, &data).await;
    }

    pub async fn send_logout(&self, user: &User, acting_device_uuid: Option<String>) {
        let data = create_update(
            vec![("UserId".into(), user.uuid.clone().into()), ("Date".into(), serialize_date(user.updated_at))],
            UpdateType::LogOut,
            acting_device_uuid,
        );

        self.send_update(&user.uuid, &data).await;
    }

    pub async fn send_folder_update(&self, ut: UpdateType, folder: &Folder, acting_device_uuid: &String) {
        let data = create_update(
            vec![
                ("Id".into(), folder.uuid.clone().into()),
                ("UserId".into(), folder.user_uuid.clone().into()),
                ("RevisionDate".into(), serialize_date(folder.updated_at)),
            ],
            ut,
            Some(acting_device_uuid.into()),
        );

        self.send_update(&folder.user_uuid, &data).await;
    }

    pub async fn send_cipher_update(
        &self,
        ut: UpdateType,
        cipher: &Cipher,
        user_uuids: &[String],
        acting_device_uuid: &String,
    ) {
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
            Some(acting_device_uuid.into()),
        );

        for uuid in user_uuids {
            self.send_update(uuid, &data).await;
        }
    }

    pub async fn send_send_update(&self, ut: UpdateType, send: &Send, user_uuids: &[String]) {
        let user_uuid = convert_option(send.user_uuid.clone());

        let data = create_update(
            vec![
                ("Id".into(), send.uuid.clone().into()),
                ("UserId".into(), user_uuid),
                ("RevisionDate".into(), serialize_date(send.revision_date)),
            ],
            ut,
            None,
        );

        for uuid in user_uuids {
            self.send_update(uuid, &data).await;
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
            "ContextId": acting_device_uuid || Nil,
            "Type": ut as i32,
            "Payload": {}
        }
    ]
]
*/
fn create_update(payload: Vec<(Value, Value)>, ut: UpdateType, acting_device_uuid: Option<String>) -> Vec<u8> {
    use rmpv::Value as V;

    let value = V::Array(vec![
        1.into(),
        V::Map(vec![]),
        V::Nil,
        "ReceiveMessage".into(),
        V::Array(vec![V::Map(vec![
            ("ContextId".into(), acting_device_uuid.map(|v| v.into()).unwrap_or_else(|| V::Nil)),
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
#[derive(Eq, PartialEq)]
pub enum UpdateType {
    SyncCipherUpdate = 0,
    SyncCipherCreate = 1,
    SyncLoginDelete = 2,
    SyncFolderDelete = 3,
    SyncCiphers = 4,

    SyncVault = 5,
    SyncOrgKeys = 6,
    SyncFolderCreate = 7,
    SyncFolderUpdate = 8,
    SyncCipherDelete = 9,
    SyncSettings = 10,

    LogOut = 11,

    SyncSendCreate = 12,
    SyncSendUpdate = 13,
    SyncSendDelete = 14,

    AuthRequest = 15,
    AuthRequestResponse = 16,

    None = 100,
}

pub type Notify<'a> = &'a rocket::State<WebSocketUsers>;

pub fn start_notification_server() -> WebSocketUsers {
    let users = WebSocketUsers {
        map: Arc::new(dashmap::DashMap::new()),
    };

    if CONFIG.websocket_enabled() {
        let users2 = users.clone();
        tokio::spawn(async move {
            let addr = (CONFIG.websocket_address(), CONFIG.websocket_port());
            info!("Starting WebSockets server on {}:{}", addr.0, addr.1);
            let listener = TcpListener::bind(addr).await.expect("Can't listen on websocket port");

            let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();
            CONFIG.set_ws_shutdown_handle(shutdown_tx);

            loop {
                tokio::select! {
                    Ok((stream, addr)) = listener.accept() => {
                        tokio::spawn(handle_connection(stream, users2.clone(), addr));
                    }

                    _ = &mut shutdown_rx => {
                        break;
                    }
                }
            }

            info!("Shutting down WebSockets server!")
        });
    }

    users
}

async fn handle_connection(stream: TcpStream, users: WebSocketUsers, addr: SocketAddr) -> Result<(), Error> {
    let mut user_uuid: Option<String> = None;

    info!("Accepting WS connection from {addr}");

    // Accept connection, do initial handshake, validate auth token and get the user ID
    use handshake::server::{Request, Response};
    let mut stream = accept_hdr_async(stream, |req: &Request, res: Response| {
        if let Some(token) = get_request_token(req) {
            if let Ok(claims) = crate::auth::decode_login(&token) {
                user_uuid = Some(claims.sub);
                return Ok(res);
            }
        }
        Err(Response::builder().status(401).body(None).unwrap())
    })
    .await?;

    let user_uuid = user_uuid.expect("User UUID should be set after the handshake");

    // Add a channel to send messages to this client to the map
    let entry_uuid = uuid::Uuid::new_v4();
    let (tx, mut rx) = tokio::sync::mpsc::channel(100);
    users.map.entry(user_uuid.clone()).or_default().push((entry_uuid, tx));

    let mut interval = tokio::time::interval(Duration::from_secs(15));
    loop {
        tokio::select! {
            res = stream.next() =>  {
                match res {
                    Some(Ok(message)) => {
                        // Respond to any pings
                        if let Message::Ping(ping) = message {
                            if stream.send(Message::Pong(ping)).await.is_err() {
                                break;
                            }
                            continue;
                        } else if let Message::Pong(_) = message {
                            /* Ignored */
                            continue;
                        }

                        // We should receive an initial message with the protocol and version, and we will reply to it
                        if let Message::Text(ref message) = message {
                            let msg = message.strip_suffix(RECORD_SEPARATOR as char).unwrap_or(message);

                            if serde_json::from_str(msg).ok() == Some(INITIAL_MESSAGE) {
                                stream.send(Message::binary(INITIAL_RESPONSE)).await?;
                                continue;
                            }
                        }

                        // Just echo anything else the client sends
                        if stream.send(message).await.is_err() {
                            break;
                        }
                    }
                    _ => break,
                }
            }

            res = rx.recv() => {
                match res {
                    Some(res) => {
                        if stream.send(res).await.is_err() {
                            break;
                        }
                    },
                    None => break,
                }
            }

            _= interval.tick() => {
                if stream.send(Message::Ping(create_ping())).await.is_err() {
                    break;
                }
            }
        }
    }

    info!("Closing WS connection from {addr}");

    //  Delete from map
    users.map.entry(user_uuid).or_default().retain(|(uuid, _)| uuid != &entry_uuid);
    Ok(())
}

fn get_request_token(req: &handshake::server::Request) -> Option<String> {
    const ACCESS_TOKEN_KEY: &str = "access_token=";

    if let Some(Ok(auth)) = req.headers().get("Authorization").map(|a| a.to_str()) {
        if let Some(token_part) = auth.strip_prefix("Bearer ") {
            return Some(token_part.to_owned());
        }
    }

    if let Some(params) = req.uri().query() {
        let params_iter = params.split('&').take(1);
        for val in params_iter {
            if let Some(stripped) = val.strip_prefix(ACCESS_TOKEN_KEY) {
                return Some(stripped.to_owned());
            }
        }
    }
    None
}
