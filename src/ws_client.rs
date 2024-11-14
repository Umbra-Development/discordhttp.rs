use crate::utils::{default_headers, merge_headermaps, ZlibStreamDecompressor, experiment_headers, configure_proxy };
use futures::lock::Mutex;
use futures::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use tokio::sync::mpsc;
use rquest::{Message, WebSocket};
use serde_json::json;
use tokio::time::Duration;
use futures::future;
use std::io::Read;
use rquest::tls::Impersonate;
use rquest::header::HeaderMap;
use serde_json::Value;

use std::sync::Arc;



pub struct WebsocketClientBuilder {
    minimal: bool,
    proxy: Option<rquest::Proxy>,
    token: Option<String>,
    buffer_size: usize,
}

impl WebsocketClientBuilder {
    fn new() -> WebsocketClientBuilder {
        WebsocketClientBuilder {
            minimal: false,
            proxy: None,
            token: None,
            buffer_size: 2 << 22,
        }
    }

    fn proxy(mut self, proxy: rquest::Proxy) -> WebsocketClientBuilder {
        self.proxy = Some(proxy);
        self
    }

    fn token<T: Into<String>>(mut self, token: T) -> WebsocketClientBuilder {
        self.token = Some(token.into());
        self
    }

    fn buffer_size(mut self, buffer_size: usize) -> WebsocketClientBuilder {
        self.buffer_size = buffer_size;
        self
    }

    fn minimal(mut self, minimal: bool) -> WebsocketClientBuilder {
        self.minimal = minimal;
        self
    }

    async fn connect(self, other_headers: Option<HeaderMap>) -> Arc<WebsocketClient> {
        let mut real_headers = default_headers(None);

        if let Some(other_headers) = other_headers {
            merge_headermaps(&mut real_headers, other_headers);
        }

        let builder = rquest::Client::builder()
            .impersonate(Impersonate::Chrome128)
            .cookie_store(true);
        let req = configure_proxy(builder, self.proxy)
            .build()
            .unwrap()
            .websocket("wss://gateway.discord.gg/?encoding=json&v=9&compress=zlib-stream")
            .send()
            .await
            .unwrap();

        let ws = req.into_websocket().await.unwrap();
        let (tx, rx) = ws.split();

        let (message_tx, message_rx) = mpsc::channel::<Message>(50);

        let client = WebsocketClient {
            message_tx: Mutex::new(message_tx),
            message_rx: Mutex::new(message_rx),
            token: self.token.expect("No token provided"),
            minimal: self.minimal,
            state: Mutex::new(WebsocketClientState::Init),
            session_id: Mutex::new(None),
        };

        let wrapped = Arc::new(client);
        let wrapped1 = wrapped.clone();
        let wrapped2 = wrapped.clone();

        wrapped2.start_sending(tx);
        if self.minimal {
            wrapped1.send_off_init().await;
        } else {
            wrapped1.start_receiving(rx, self.buffer_size);
        }

        wrapped
    }
}

pub struct WebsocketClient {
    message_tx: Mutex<mpsc::Sender<Message>>,
    message_rx: Mutex<mpsc::Receiver<Message>>,
    token: String,
    minimal: bool,
    state: Mutex<WebsocketClientState>,
    session_id: Mutex<Option<String>>,
}

#[derive(PartialEq, Copy, Clone)]
enum WebsocketClientState {
    Init,
    Connected,
    Disconnected,
}

impl WebsocketClient {
    pub fn builder() -> WebsocketClientBuilder {
        WebsocketClientBuilder::new()
    }

    pub async fn session_id(&self) -> Option<String> {
        let session_id = self.session_id.lock().await.clone();
        session_id
    }

    pub async fn ready(&self) -> bool {
        self.state.lock().await.clone() == WebsocketClientState::Connected
    }

    pub async fn closed(&self) -> bool {
        self.state.lock().await.clone() == WebsocketClientState::Disconnected
    }

    pub async fn close(&self) {
        self.send(Message::Close {
            code: rquest::CloseCode::Normal,
            reason: None,
        })
        .await;
    }

    fn start_sending(self: Arc<Self>, mut tx: SplitSink<WebSocket, Message>) {
        // let message_rx = Arc::clone(&self.message_rx);

        tokio::spawn(async move {
            let mut message_rx = self.message_rx.lock().await;
            while let Some(msg) = message_rx.recv().await {
                // println!("Sending: {}", msg.json::<Value>().unwrap());
                if tx.send(msg).await.is_err() {
                    eprintln!("Failed to send message");
                    break;
                }
            }
        });
    }

    fn start_receiving(self: Arc<Self>, mut rx: SplitStream<WebSocket>, buffer_size: usize) {
        let mut decompressor = ZlibStreamDecompressor::new(buffer_size);

        tokio::spawn(async move {
            while let Some(Ok(message)) = rx.next().await {
                match message {
                    Message::Binary(bytes) => {
                        if bytes.len() > 2000 && self.minimal {
                            continue;
                        }
                        match decompressor.decompress(&bytes) {
                            Ok(dcmp_str) => {
                                let json = serde_json::from_str::<Value>(&dcmp_str).unwrap();
                                self.handle_message(&json).await;
                            }
                            Err(why) => eprintln!("Failed to decompress binary: {}", why),
                        }
                    }
                    Message::Close { code, reason } => {
                        eprintln!("Connection closed: {} - {:?}", code, reason);
                        let mut state_lock = self.state.lock().await;
                        *state_lock = WebsocketClientState::Disconnected;
                        break;
                    }
                    _ => {
                        eprintln!("Received message: {:?}", message);
                    }
                }
            }
        });
    }

    async fn send_json(&self, message: &Value) {
        let tx = self.message_tx.lock().await;
        tx.send(Message::Text(serde_json::to_string(&message).unwrap()))
            .await
            .expect("Failed to send json message");
    }

    async fn send(&self, message: Message) {
        let tx = self.message_tx.lock().await;
        tx.send(message).await.expect("Failed to send message");
    }

    async fn send_off_init(&self) {
        let identify_payload = json!({
            "op": 2,
            "d": {
                "token": self.token,
                "capabilities": 30717,
                "properties": {
                    "os": "Linux",
                    "browser": "Chrome",
                    "device": "",
                    "system_locale": "en-US",
                    "browser_user_agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
                    "browser_version": "126.0.0.0",
                    "os_version": "",
                    "referrer": "",
                    "referring_domain": "",
                    "referrer_current": "",
                    "referring_domain_current": "",
                    "release_channel": "canary",
                    "client_build_number": 342931,
                    "client_event_source": null
                },
                "presence": {
                    "status": "unknown",
                    "since": 0,
                    "activities": [],
                    "afk": false
                },
                "compress": false,
                "client_state": {
                    "guild_versions": {}
                }
            }
        });

        self.send_json(&identify_payload).await;
    }

    pub async fn handle_message(&self, json: &Value) {
        // println!("Received: {}", json);
        match json["op"].as_i64() {
            Some(10) => {
                // HELLO event
                self.send_off_init().await;
            }
            Some(0) if json["t"] == "READY" => {
                if let Some(session_id) = json["d"]["session_id"].as_str() {
                    let mut session_id_lock = self.session_id.lock().await;
                    *session_id_lock = Some(session_id.to_string());

                    let mut state_lock = self.state.lock().await;
                    *state_lock = WebsocketClientState::Connected;
                }
            }
            _ => {}
        }
    }
}



#[tokio::test]
async fn test_discord_ws() {
    const AMT: usize = 1;

    let mut token_str = String::new();
    let mut file = std::fs::File::open("./tokens.txt").unwrap();
    file.read_to_string(&mut token_str).unwrap();
    let tokens: Vec<&str> = token_str.split("\n").into_iter().take(AMT).collect();

    let other_headers = experiment_headers(
        rquest::Client::builder()
            .impersonate_without_headers(Impersonate::Chrome126)
            .build()
            .unwrap(),
    )
    .await;

    let tasks = tokens.iter().map(|tok| {
        let tok = tok.to_string();
        let other_headers = other_headers.clone();
        async move {
            let client = WebsocketClient::builder()
                .token(&tok)
                .minimal(true)
                .connect(Some(other_headers))
                .await;

            // wait until session id is set
            while !client.closed().await {
                tokio::time::sleep(Duration::from_secs(1)).await;
                if let Some(session_id) = client.session_id().await {
                    println!("Session ID: {}", session_id);
                    break;
                }
            }
        }
    });

    futures::future::join_all(tasks).await;
}

