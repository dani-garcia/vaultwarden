use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use chrono::NaiveDateTime;
use rmpv::Value;
use rocket::{
    futures::{SinkExt, StreamExt},
    Route,
};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::mpsc::Sender,
};
use tokio_tungstenite::{
    accept_hdr_async,
    tungstenite::{handshake, Message},
};

use crate::{
    auth::ClientIp,
    db::models::{Cipher, Folder, Send as DbSend, User},
    Error, CONFIG,
};

use once_cell::sync::Lazy;

static WS_USERS: Lazy<Arc<WebSocketUsers>> = Lazy::new(|| {
    Arc::new(WebSocketUsers {
        map: Arc::new(dashmap::DashMap::new()),
    })
});

pub fn routes() -> Vec<Route> {
    routes![websockets_hub]
}

#[derive(FromForm, Debug)]
struct WsAccessToken {
    access_token: Option<String>,
}

struct WSEntryMapGuard {
    users: Arc<WebSocketUsers>,
    user_uuid: String,
    entry_uuid: uuid::Uuid,
    addr: IpAddr,
}

impl WSEntryMapGuard {
    fn new(users: Arc<WebSocketUsers>, user_uuid: String, entry_uuid: uuid::Uuid, addr: IpAddr) -> Self {
        Self {
            users,
            user_uuid,
            entry_uuid,
            addr,
        }
    }
}

impl Drop for WSEntryMapGuard {
    fn drop(&mut self) {
        info!("Closing WS connection from {}", self.addr);
        if let Some(mut entry) = self.users.map.get_mut(&self.user_uuid) {
            entry.retain(|(uuid, _)| uuid != &self.entry_uuid);
        }
    }
}

#[get("/hub?<data..>")]
async fn websockets_hub<'r>(
    ws: rocket_ws::WebSocket,
    data: WsAccessToken,
    ip: ClientIp,
) -> Result<rocket_ws::Stream!['r], Error> {
    let addr = ip.ip;
    info!("Accepting Rocket WS connection from {addr}");

    let Some(token) = data.access_token else { err_code!("Invalid claim", 401) };
    let Ok(claims) = crate::auth::decode_login(&token) else { err_code!("Invalid token", 401) };

    let (mut rx, guard) = {
        let users = Arc::clone(&WS_USERS);

        // Add a channel to send messages to this client to the map
        let entry_uuid = uuid::Uuid::new_v4();
        let (tx, rx) = tokio::sync::mpsc::channel::<Message>(100);
        users.map.entry(claims.sub.clone()).or_default().push((entry_uuid, tx));

        // Once the guard goes out of scope, the connection will have been closed and the entry will be deleted from the map
        (rx, WSEntryMapGuard::new(users, claims.sub, entry_uuid, addr))
    };

    Ok({
        rocket_ws::Stream! { ws => {
            let mut ws = ws;
            let _guard = guard;
            let mut interval = tokio::time::interval(Duration::from_secs(15));
            loop {
                tokio::select! {
                    res = ws.next() =>  {
                        match res {
                            Some(Ok(message)) => {
                                match message {
                                    // Respond to any pings
                                    Message::Ping(ping) => yield Message::Pong(ping),
                                    Message::Pong(_) => {/* Ignored */},

                                    // We should receive an initial message with the protocol and version, and we will reply to it
                                    Message::Text(ref message) => {
                                        let msg = message.strip_suffix(RECORD_SEPARATOR as char).unwrap_or(message);

                                        if serde_json::from_str(msg).ok() == Some(INITIAL_MESSAGE) {
                                            yield Message::binary(INITIAL_RESPONSE);
                                            continue;
                                        }
                                    }
                                    // Just echo anything else the client sends
                                    _ => yield message,
                                }
                            }
                            _ => break,
                        }
                    }

                    res = rx.recv() => {
                        match res {
                            Some(res) => yield res,
                            None => break,
                        }
                    }

                    _ = interval.tick() => yield Message::Ping(create_ping())
                }
            }
        }}
    })
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
                if let Err(e) = sender.send(Message::binary(data)).await {
                    error!("Error sending WS update {e}");
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

    pub async fn send_send_update(&self, ut: UpdateType, send: &DbSend, user_uuids: &[String]) {
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

pub type Notify<'a> = &'a rocket::State<Arc<WebSocketUsers>>;

pub fn start_notification_server() -> Arc<WebSocketUsers> {
    let users = Arc::clone(&WS_USERS);
    if CONFIG.websocket_enabled() {
        let users2 = Arc::<WebSocketUsers>::clone(&users);
        tokio::spawn(async move {
            let addr = (CONFIG.websocket_address(), CONFIG.websocket_port());
            info!("Starting WebSockets server on {}:{}", addr.0, addr.1);
            let listener = TcpListener::bind(addr).await.expect("Can't listen on websocket port");

            let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();
            CONFIG.set_ws_shutdown_handle(shutdown_tx);

            loop {
                tokio::select! {
                    Ok((stream, addr)) = listener.accept() => {
                        tokio::spawn(handle_connection(stream, Arc::<WebSocketUsers>::clone(&users2), addr));
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

async fn handle_connection(stream: TcpStream, users: Arc<WebSocketUsers>, addr: SocketAddr) -> Result<(), Error> {
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

    let (mut rx, guard) = {
        // Add a channel to send messages to this client to the map
        let entry_uuid = uuid::Uuid::new_v4();
        let (tx, rx) = tokio::sync::mpsc::channel::<Message>(100);
        users.map.entry(user_uuid.clone()).or_default().push((entry_uuid, tx));

        // Once the guard goes out of scope, the connection will have been closed and the entry will be deleted from the map
        (rx, WSEntryMapGuard::new(users, user_uuid, entry_uuid, addr.ip()))
    };

    let _guard = guard;
    let mut interval = tokio::time::interval(Duration::from_secs(15));
    loop {
        tokio::select! {
            res = stream.next() =>  {
                match res {
                    Some(Ok(message)) => {
                        match message {
                            // Respond to any pings
                            Message::Ping(ping) => stream.send(Message::Pong(ping)).await?,
                            Message::Pong(_) => {/* Ignored */},

                            // We should receive an initial message with the protocol and version, and we will reply to it
                            Message::Text(ref message) => {
                                let msg = message.strip_suffix(RECORD_SEPARATOR as char).unwrap_or(message);

                                if serde_json::from_str(msg).ok() == Some(INITIAL_MESSAGE) {
                                    stream.send(Message::binary(INITIAL_RESPONSE)).await?;
                                    continue;
                                }
                            }
                            // Just echo anything else the client sends
                            _ => stream.send(message).await?,
                        }
                    }
                    _ => break,
                }
            }

            res = rx.recv() => {
                match res {
                    Some(res) => stream.send(res).await?,
                    None => break,
                }
            }

            _ = interval.tick() => stream.send(Message::Ping(create_ping())).await?
        }
    }

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
