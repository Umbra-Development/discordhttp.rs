#![allow(unused_imports)]
use crate::types::HttpRequest;
use crate::utils::{default_headers, experiment_headers, merge_headermaps, ZlibStreamDecompressor};
use crate::{easy_headers, easy_params};
use flate2::write::{GzEncoder, ZlibEncoder};
use flate2::Compression;
use futures::lock::Mutex;
use futures::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use jsonwebtoken::{encode, EncodingKey, Header};
use rquest::boring::ssl::{SslConnector, SslCurve, SslMethod, SslOptions, SslVersion};
use tokio::sync::mpsc;
use tokio::time::Duration;
// Required for macro idfk why
use rquest::{header, HttpVersionPref, Message, WebSocket};
use rquest::{PseudoOrder::*, SettingsOrder::*};

use rquest::tls::{chrome, Http2Settings, Impersonate, ImpersonateSettings, TlsSettings, Version};
use rquest::{
    header::{HeaderMap, HeaderName, HeaderValue},
    Response,
};
use serde::Serialize;
use serde_json::{from_str, json, Value};
use std::any::Any;
use std::error::Error;
use std::io::{Read, Write};
use std::sync::Arc;

pub struct WebsocketClientBuilder {
    hb_only: bool,
    proxy: Option<rquest::Proxy>,
    token: Option<String>,
    buffer_size: usize,
}

impl WebsocketClientBuilder {
    fn new() -> WebsocketClientBuilder {
        WebsocketClientBuilder {
            hb_only: false,
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

    fn hb_only(mut self, hb_only: bool) -> WebsocketClientBuilder {
        self.hb_only = hb_only;
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
            state: Mutex::new(WebsocketClientState::Init),
            session_id: Mutex::new(None),
        };

        let wrapped = Arc::new(client);
        let wrapped1 = wrapped.clone();
        let wrapped2 = wrapped.clone();

        wrapped2.start_sending(tx);
        if self.hb_only {
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
        self.send(Message::Close { code: rquest::CloseCode::Normal, reason: None }).await;
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
                    Message::Binary(bytes) => match decompressor.decompress(&bytes) {
                        Ok(dcmp_str) => {
                            let json = serde_json::from_str::<Value>(&dcmp_str).unwrap();
                            self.handle_message(&json).await;
                        }
                        Err(why) => eprintln!("Failed to decompress binary: {}", why),
                    },
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
                    "status": "idle",
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

pub type Client = DiscordClient;

#[derive(Debug, Clone)]
pub struct DiscordClient {
    pub client: rquest::Client,
    pub proxy_info: Option<url::Url>,
}

impl DiscordClient {
    pub async fn new(proxy: Option<rquest::Proxy>) -> DiscordClient {
        let mut real_headers = default_headers(None);
        let other_headers = experiment_headers(
            rquest::Client::builder()
                .impersonate_without_headers(Impersonate::Chrome128)
                .build()
                .unwrap(),
        )
        .await;

        merge_headermaps(&mut real_headers, other_headers);

        let builder = rquest::Client::builder()
            .default_headers(real_headers)
            .cookie_store(true)
            .impersonate(Impersonate::Chrome126);
        // .use_preconfigured_tls(tls_preconfig())
        // .max_tls_version(Version::TLS_1_2);

        let client = configure_proxy(builder, proxy).build().unwrap();

        Self {
            client,
            proxy_info: None,
        }
    }
}

fn configure_proxy(
    builder: rquest::ClientBuilder,
    proxy: Option<rquest::Proxy>,
) -> rquest::ClientBuilder {
    if let Some(proxy) = proxy {
        builder.proxy(proxy)
    } else {
        builder
    }
}
impl DiscordClient {
    pub async fn send_request(&self, request: HttpRequest) -> Result<Response, Box<dyn Error>> {
        let builder = request.to_request_builder(&self.client);

        let response = builder.send().await?;
        Ok(response)
    }

    pub async fn send_base_request(&self, url: &str, additional_headers: HeaderMap<HeaderValue>) {
        let client = self
            .client
            .get(url)
            .headers(additional_headers)
            .send()
            .await
            .unwrap();
        println!("{}", client.text().await.unwrap());
    }
}

#[tokio::test]
async fn test_discord_ws() {
    let mut tokens = String::new();
    let mut file = std::fs::File::open("./tokens.txt").unwrap();
    file.read_to_string(&mut tokens).unwrap();
    let token = tokens
        .split("\n")
        .into_iter()
        .next()
        .expect("No tokens in file.");

    let other_headers = experiment_headers(
        rquest::Client::builder()
            .impersonate_without_headers(Impersonate::Chrome126)
            .build()
            .unwrap(),
    )
    .await;

    let client = WebsocketClient::builder()
        .token(token)
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

#[tokio::test]
async fn get_headers() {
    let client = DiscordClient::new(None).await;
    for _i in 0..10 {
        client
            .send_base_request("https://httpbin.org/headers", easy_headers!({"fake": "tA"}))
            .await;
    }
}
use futures::future;
use tokio::task;

#[tokio::test]
async fn token_join_leave() {
    const AMT: usize = 10;
    const COOKIE: &'static str = "__dcfduid=9b0e5a9096de11efbaea092ef1a07225; __sdcfduid=9b0e5a9196de11efbaea092ef1a072257d00d819c249039e1508fcd07f793ebea8a127f173ceeaedc7d17f650fa7794d; __stripe_mid=8fe3b13e-cfcb-4de9-9776-6528a1cfe46c2f5c0f; cf_clearance=exU208lykoMbx8B146R13MXXSsC0B_cngvsUEM2eEhQ-1730847161-1.2.1.1-fWDFrtsLtmF7JvaxV5edq8ekENFGijSZnk8XMY8YVmG6aZedfrLFEG.GwesQp0mAa.yByRNjS_gdLNx.KIYRQqgrEuPb6cCqIkbJPQnD_BTJaTIznsbEdPCChLBAuev6DNUbB6eblcaZqqnAGYX0E.YgRuNrFnzUkBljHJ6ayJEqSdu0HbvLzWYc.St2WB1Rgn69Ki1zKgGii.Pzy1XcGNvMQsHbHLNNFxsmRS.qmnjer67QwGQjN3HQbQMxCibiXwCyCpwo4sncWjMjzAZPE.7Lj7CfSGwMY9vhGZhE4g4ZrcogyQ9zQn8vXn2p7C7T29csyDyfM6kq3CxVHSHvlebVH1NBUcWjRZTWaX7nLwxEAWXx2Q8mXAsHIVJrtqTc; __cfruid=56f893338114801c9e7a339b039996ddd111473c-1730847636; _cfuvid=XUM_URznBabjhipaHwGNUZJ12RWMWHQe2i.O7Jf929o-1730854284096-0.0.1.1-604800000";
    const INVITE: &str = "8Aspy3uM";

    let mut tokens = String::new();
    let mut file = std::fs::File::open("./tokens.txt").unwrap();
    file.read_to_string(&mut tokens).unwrap();
    let vals = tokens
        .split('\n')
        .take(AMT)
        .map(|s| s.to_string())
        .collect::<Vec<String>>();

    let mut setup_headers = easy_headers!({
        "accept": "*/*",
        "accept-language": "en-US",
        "Accept-Encoding": "identity", // needed to not get gzip content
        "content-type": "application/json",
        "cookie": COOKIE,
        "priority": "u=1, i",
        "referer": "https://canary.discord.com/channels/@me/1295535782525796382",
        "sec-ch-ua": "\"Not/A)Brand\";v=\"8\", \"Chromium\";v=\"126\"",
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": "\"Linux\"",
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
        "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
        "x-debug-options": "bugReporterEnabled",
        "x-discord-locale": "en-US",
        "x-discord-timezone": "America/New_York",
        "x-super-properties": "eyJvcyI6IkxpbnV4IiwiYnJvd3NlciI6IkNocm9tZSIsImRldmljZSI6IiIsInN5c3RlbV9sb2NhbGUiOiJlbi1VUyIsImJyb3dzZXJfdXNlcl9hZ2VudCI6Ik1vemlsbGEvNS4wIChYMTE7IExpbnV4IHg4Nl82NCkgQXBwbGVXZWJLaXQvNTM3LjM2IChLSFRNTCwgbGlrZSBHZWNrbykgQ2hyb21lLzEyNi4wLjAuMCBTYWZhcmkvNTM3LjM2IiwiYnJvd3Nlcl92ZXJzaW9uIjoiMTI2LjAuMC4wIiwib3NfdmVyc2lvbiI6IiIsInJlZmVycmVyIjoiIiwicmVmZXJyaW5nX2RvbWFpbiI6IiIsInJlZmVycmVyX2N1cnJlbnQiOiIiLCJyZWZlcnJpbmdfZG9tYWluX2N1cnJlbnQiOiIiLCJyZWxlYXNlX2NoYW5uZWwiOiJjYW5hcnkiLCJjbGllbnRfYnVpbGRfbnVtYmVyIjozNDE5NjYsImNsaWVudF9ldmVudF9zb3VyY2UiOm51bGx9"
    });

    let client = DiscordClient::new(None).await;

    let tmp = vals.iter().next().unwrap();

    let mut tmp_headers = setup_headers.clone();
    tmp_headers.insert("authorization", tmp.parse().unwrap());
    let resp1 = client.send_request(HttpRequest::Get {
        endpoint: format!("/invites/{}", INVITE),
        params: Some(easy_params!({"with_counts": "true", "with_expiration": "true"})),
        additional_headers: Some(tmp_headers),
    });

    let resp = resp1.await.unwrap();
    let val = resp.json::<Value>().await.unwrap();

    let context_json = json!({
        "location": "Join Guild",
        "location_guild_id": val["guild"]["id"],
        "location_channel_id": val["channel"]["id"],
        "location_channel_type": val["channel"]["type"],
    });

    let x_context_properties = base64::encode(&serde_json::to_string(&context_json).unwrap());
    setup_headers.insert(
        "x-context-properties",
        HeaderValue::from_str(&x_context_properties).unwrap(),
    );

    let tasks: Vec<_> = vals.into_iter().map(|val| {
        let client = client.clone();
        let setup_headers = setup_headers.clone();
        let invite = INVITE.to_string();
        task::spawn(async move {
            let mut headers = setup_headers.clone();
            headers.insert("authorization", val.parse().unwrap());


            let ws_client = WebsocketClient::builder()
                .token(&val)
                .connect(Some(setup_headers.clone()))
                .await;

            for _i in 0..10 {
                if ws_client.closed().await {
                    return; // skip invalid token
                }
                if ws_client.ready().await {
                    break;
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }

            let session_id = ws_client.session_id().await.unwrap();
            

            // Join the server
            let resp = client
                .send_request(HttpRequest::Post {
                    endpoint: format!("/invites/{}", invite),
                    body: Some(json!({"session_id": session_id})),
                    additional_headers: Some(headers.clone()),
                })
                .await;

            match resp {
                Ok(response) if response.status().is_success() => {
                    println!("Token has joined the server: {}", val);
                }
                Ok(response) => {
                    let headers = response.headers();
                    let cookies = headers
                        .get_all("set-cookie")
                        .into_iter()
                        .map(|header_value| header_value.to_str().unwrap_or("").to_string())
                        .collect::<Vec<String>>();

                    println!(
                        "Token could not join the server: {}\n{}\n{}",
                        val,
                        response.status().as_str(),
                        response.url()
                    );
                    println!("{:?}", headers);
                    println!("{:?}", cookies);
                    // println!("{}", response.text().await.unwrap());
                }
                Err(e) => {
                    eprintln!("Failed to send join request for token {}: {}", val, e);
                }
            }
        })
    }).collect();

    // Await all join/leave tasks
    future::join_all(tasks).await;
}


use base64::engine::general_purpose::URL_SAFE;
use base64::Engine;

fn decode_user_id(token_part: &str) -> Option<String> {
    let padding_needed = (4 - token_part.len() % 4) % 4;
    let token_part_1 = format!("{}{}", token_part, "=".repeat(padding_needed));

    // Decode the Base64 string
    let decoded_bytes = URL_SAFE.decode(token_part_1).ok().expect("fuck");

    let user_id = String::from_utf8(decoded_bytes).ok()?;
    println!("{}", user_id);
    Some(user_id)
}

#[tokio::test]
async fn add_bot_to_server() {
    const COOKIE: &'static str = "__dcfduid=9b0e5a9096de11efbaea092ef1a07225; __sdcfduid=9b0e5a9196de11efbaea092ef1a072257d00d819c249039e1508fcd07f793ebea8a127f173ceeaedc7d17f650fa7794d; __stripe_mid=8fe3b13e-cfcb-4de9-9776-6528a1cfe46c2f5c0f; cf_clearance=nXbrVCxkJIbvMkaCBjB6m6fnI6bVSFL1jWW8fF_FVh0-1730855946-1.2.1.1-rGlyuprmEDG8_RI_Fa3YyQuXSLNPOaoXaTfOo7nK.8pRDu_KS35eKLNv19bjbHzsRV8a493fEuZDL56fvtunuWFusZFDHhdqXwFmB3EdWaOHmEinza2bmnuzAW1MUKj31KPWirt80WKy284G893GB.i8Pv2DhUN3p310h_LkGpAqFqrJc.x7HUh0xKZYSQfZgVluUEQdQZEPoNNXQRktOiS0.xuxccryXUYpm5ssgo3Us3WSsrhlH5aMfboRhzPORZ0jU5dbcRK3pGJcR61mKnacUe0modNvX3CWq04p0XGF0KYH4O.d5JmA5fB3yqIBT_t7N.B1wkCf1VJMyD82U8tbApqy3efnhyyFY6iJjuIIescT1AkJk.QL9vR3HiZh; __cfruid=2fba0c38444b871664ebad18b95e3d1cc28af509-1730855952; _cfuvid=0CqnUHwd4t0YJpbJrLtbgVvvIIb1Oig3O4erOsQ1b.s-1730857384992-0.0.1.1-604800000";
    // const BOT_ID: &str = "1196556567403831346";
    const SERVER_ID: &str = "1299815021794164838";

    let body = json!({
        "guild_id": SERVER_ID,
        "permissions": "0",
        "authorize": true,
        "integration_type": 0,
        "location_context": {
            "guild_id": SERVER_ID,
            // "channel_id": "1299815021794164841", // apparently unneeded.
            // "channel_type": 0
        }
    });

    let mut tokens = String::new();
    let mut file = std::fs::File::open("./auth_tokens.txt").unwrap();
    file.read_to_string(&mut tokens).unwrap();
    let token = tokens.split("\n").next().expect("No tokens in file.");

    let mut file1 = std::fs::File::open("./bot_tokens.txt").unwrap();
    let mut tokens1 = String::new();

    file1.read_to_string(&mut tokens1).unwrap();
    let bot_tokens = tokens1.split("\n").collect::<Vec<&str>>();

    // get user ids from tokens
    let tokens_and_user_ids = bot_tokens
        .into_iter()
        .map(|token| {
            (
                token,
                decode_user_id(token.split(".").nth(0).unwrap()).unwrap(),
            )
        })
        .collect::<Vec<(&str, String)>>();

    let setup_headers = easy_headers!({
        "accept": "*/*",
        "accept-language": "en-US",
        "Accept-Encoding": "identity", // needed to not get gzip content
        "authorization": token,
        "content-type": "application/json",
        "cookie": COOKIE,
        "priority": "u=1, i",
        // "referer": format!("https://canary.discord.com/channels/{}/{}", body["guild_id"], body["location_context"]["channel_id"]),
        "sec-ch-ua": "\"Not/A)Brand\";v=\"8\", \"Chromium\";v=\"126\"",
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": "\"Linux\"",
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
        "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
        "x-debug-options": "bugReporterEnabled",
        "x-discord-locale": "en-US",
        "x-discord-timezone": "America/New_York",
        "x-super-properties": "eyJvcyI6IkxpbnV4IiwiYnJvd3NlciI6IkNocm9tZSIsImRldmljZSI6IiIsInN5c3RlbV9sb2NhbGUiOiJlbi1VUyIsImJyb3dzZXJfdXNlcl9hZ2VudCI6Ik1vemlsbGEvNS4wIChYMTE7IExpbnV4IHg4Nl82NCkgQXBwbGVXZWJLaXQvNTM3LjM2IChLSFRNTCwgbGlrZSBHZWNrbykgQ2hyb21lLzEyNi4wLjAuMCBTYWZhcmkvNTM3LjM2IiwiYnJvd3Nlcl92ZXJzaW9uIjoiMTI2LjAuMC4wIiwib3NfdmVyc2lvbiI6IiIsInJlZmVycmVyIjoiIiwicmVmZXJyaW5nX2RvbWFpbiI6IiIsInJlZmVycmVyX2N1cnJlbnQiOiIiLCJyZWZlcnJpbmdfZG9tYWluX2N1cnJlbnQiOiIiLCJyZWxlYXNlX2NoYW5uZWwiOiJjYW5hcnkiLCJjbGllbnRfYnVpbGRfbnVtYmVyIjozNDIwNjMsImNsaWVudF9ldmVudF9zb3VyY2UiOm51bGx9"
    });

    use tokio::task;
    use tokio::try_join;

    futures::stream::iter(tokens_and_user_ids)
        .for_each_concurrent(None, |(token, user_id)| {
            let body = body.clone();
            let headers = setup_headers.clone();

            // Spawning each request as an async task
            async move {
                let client = DiscordClient::new(None).await;

                // Adding a bot
                let resp = client
                    .send_request(HttpRequest::Post {
                        endpoint: format!(
                            "/oauth2/authorize?client_id={}&scope=bot%20applications.commands",
                            user_id
                        ),
                        body: Some(body),
                        additional_headers: Some(headers),
                    })
                    .await;

                match resp {
                    Ok(response) => {
                        println!("{}", response.status().as_str());
                        if response.status().is_success() {
                            println!("Token has joined the server");
                            println!("{}", response.text().await.unwrap());
                        } else {
                            let headers = response.headers();
                            let cookies = headers
                                .get_all("set-cookie")
                                .into_iter()
                                .map(|header_value| header_value.to_str().unwrap_or("").to_string())
                                .collect::<Vec<String>>();

                            println!(
                                "Token could not join the server: \n{}\n{}",
                                response.status().as_str(),
                                response.url()
                            );
                            println!("{:?}", headers);
                            println!("{:?}", cookies);
                            println!("{}", response.text().await.unwrap());
                        }
                    }
                    Err(e) => {
                        println!("Request failed: {:?}", e);
                    }
                }
            }
        })
        .await;
}

#[tokio::test]
async fn friend_request_user() {
    const USERNAME: &str = "gen6442";
    const COOKIE: &str = "__dcfduid=0fcd91109d6611efae1ed79521365559; __sdcfduid=0fcd91119d6611efae1ed795213655598b948d3c4e7cc578aa33251431ebc69b61df95127d38dc547a44bc7473fee752; __cfruid=cd2fa6e43b05469121ae898f6ef1457336b61207-1731024714; _cfuvid=h6nmMqwDnSIhr4XXd8ff1xcx7Ja65elMtqugXC7Zd0Y-1731024714918-0.0.1.1-604800000; cf_clearance=goRmXw7HX3pV5vRIF0od.CU3GwuWF4.pZkSsRjXsRsc-1731024718-1.2.1.1-D8grOksTchA3sE9BLDIR4x7_oseYuBdfxTzVV1urGqa.DvNspCj0wn.nwKEFVR7K8KeohAg1GftGL1rOEN.PDmV4H9Gm47ygEVl7rji7Pv7ww2WZ4l.hxZQl4TjZAonXR6yj.pUaWNsW7UfCMP5UlaJhpgwLB2JFCLoNR8d9RAWkgkq0bPn9A3ScI6s6FZtzB6JJdVavs1tR19CatbXr8om.m2OF0hrzkx9x9DqauYZp5X29eXkQfLJsIBYcjAC.KAn6siozTPjTMs9qiJd9OROkXE81SPEyd4N4h4mjScXESw3TIQbqbK4KJI2MPG1vsqi0rghyHA7tRRMAI2mhuVF3ijfsHpx41cwbgceoJzzL9ecD1aWQuq_HvNnRGTXb";
    const AMT: usize = 1;

    let mut tokens = String::new();
    let mut file = std::fs::File::open("./tokens.txt").unwrap();
    file.read_to_string(&mut tokens).unwrap();
    let vals = tokens.split("\n").take(AMT).collect::<Vec<&str>>();

    let mut setup_headers = easy_headers!({
       "accept": "*/*",
       "accept-language": "en-US",
       "Accept-Encoding": "identity", // needed to not get gzip content
       "content-type": "application/json",
       "cookie": COOKIE,
       "priority": "u=1, i",
       // "referer": format!("https://canary.discord.com/channels/{}/{}", body["guild_id"], body["location_context"]["channel_id"]),
       "sec-ch-ua": "\"Not/A)Brand\";v=\"8\", \"Chromium\";v=\"126\"",
       "sec-ch-ua-mobile": "?0",
       "sec-ch-ua-platform": "\"Linux\"",
       "sec-fetch-dest": "empty",
       "sec-fetch-mode": "cors",
       "sec-fetch-site": "same-origin",
       "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
       "x-debug-options": "bugReporterEnabled",
       "x-discord-locale": "en-US",
       "x-discord-timezone": "America/New_York",
       "x-super-properties": "eyJvcyI6IkxpbnV4IiwiYnJvd3NlciI6IkNocm9tZSIsImRldmljZSI6IiIsInN5c3RlbV9sb2NhbGUiOiJlbi1VUyIsImJyb3dzZXJfdXNlcl9hZ2VudCI6Ik1vemlsbGEvNS4wIChYMTE7IExpbnV4IHg4Nl82NCkgQXBwbGVXZWJLaXQvNTM3LjM2IChLSFRNTCwgbGlrZSBHZWNrbykgQ2hyb21lLzEyNi4wLjAuMCBTYWZhcmkvNTM3LjM2IiwiYnJvd3Nlcl92ZXJzaW9uIjoiMTI2LjAuMC4wIiwib3NfdmVyc2lvbiI6IiIsInJlZmVycmVyIjoiIiwicmVmZXJyaW5nX2RvbWFpbiI6IiIsInJlZmVycmVyX2N1cnJlbnQiOiIiLCJyZWZlcnJpbmdfZG9tYWluX2N1cnJlbnQiOiIiLCJyZWxlYXNlX2NoYW5uZWwiOiJjYW5hcnkiLCJjbGllbnRfYnVpbGRfbnVtYmVyIjozNDIwNjMsImNsaWVudF9ldmVudF9zb3VyY2UiOm51bGx9"
    });

    let context_json = json!({
        "location": "Add Friend"
    });

    let x_context_properties = base64::encode(&serde_json::to_string(&context_json).unwrap());
    setup_headers.insert(
        "x-context-properties",
        HeaderValue::from_str(&x_context_properties).unwrap(),
    );

    let target = json!({
        "username": USERNAME,
        "discriminator": null

    });

    let client = DiscordClient::new(None).await;




    for val in vals {

        let mut headers = setup_headers.clone();
        headers.insert("authorization", val.parse().unwrap());

        let resp = client.send_request(HttpRequest::Post {
            endpoint: "/users/@me/relationships".to_string(),
            body: Some(target.clone()),
            additional_headers: Some(headers),
        });

        let resp = resp.await.unwrap();

        println!("{}", resp.status().as_str());

        match resp.status().as_u16() {
            204 => println!("Friend request sent to: {}", val),
            201 => println!("Friend request sent to: {}", val),
            304 => println!("Friend request already sent to: {}", val),
            400 => println!("Bad request: {}", val),
            403 => println!("Forbidden: {}", val),
            429 => println!("Rate limited: {}", val),
            500 => println!("Internal server error: {}", val),
            502 => println!("Bad gateway: {}", val),
            503 => println!("Service unavailable: {}", val),
            504 => println!("Gateway timeout: {}", val),
            _ => {
                println!("Unknown status code: {}", val);
                println!("{}", resp.text().await.unwrap());
            }
        }
    }
}

#[tokio::test]
async fn friend_request_user_alt() {
    const USER_ID: &str = "922877704200654849";
    const COOKIE: &str = "__dcfduid=0fcd91109d6611efae1ed79521365559; __sdcfduid=0fcd91119d6611efae1ed795213655598b948d3c4e7cc578aa33251431ebc69b61df95127d38dc547a44bc7473fee752; __cfruid=cd2fa6e43b05469121ae898f6ef1457336b61207-1731024714; _cfuvid=h6nmMqwDnSIhr4XXd8ff1xcx7Ja65elMtqugXC7Zd0Y-1731024714918-0.0.1.1-604800000; cf_clearance=goRmXw7HX3pV5vRIF0od.CU3GwuWF4.pZkSsRjXsRsc-1731024718-1.2.1.1-D8grOksTchA3sE9BLDIR4x7_oseYuBdfxTzVV1urGqa.DvNspCj0wn.nwKEFVR7K8KeohAg1GftGL1rOEN.PDmV4H9Gm47ygEVl7rji7Pv7ww2WZ4l.hxZQl4TjZAonXR6yj.pUaWNsW7UfCMP5UlaJhpgwLB2JFCLoNR8d9RAWkgkq0bPn9A3ScI6s6FZtzB6JJdVavs1tR19CatbXr8om.m2OF0hrzkx9x9DqauYZp5X29eXkQfLJsIBYcjAC.KAn6siozTPjTMs9qiJd9OROkXE81SPEyd4N4h4mjScXESw3TIQbqbK4KJI2MPG1vsqi0rghyHA7tRRMAI2mhuVF3ijfsHpx41cwbgceoJzzL9ecD1aWQuq_HvNnRGTXb";
    const AMT: usize = 1;

    let mut tokens = String::new();
    let mut file = std::fs::File::open("./tokens.txt").unwrap();
    file.read_to_string(&mut tokens).unwrap();
    let vals = tokens.split("\n").take(AMT).collect::<Vec<&str>>();

    let mut setup_headers = easy_headers!({
       "accept": "*/*",
       "accept-language": "en-US",
       "Accept-Encoding": "identity", // needed to not get gzip content
       "content-type": "application/json",
       "cookie": COOKIE,
       "priority": "u=1, i",
       // "referer": format!("https://canary.discord.com/channels/{}/{}", body["guild_id"], body["location_context"]["channel_id"]),
       "sec-ch-ua": "\"Not/A)Brand\";v=\"8\", \"Chromium\";v=\"126\"",
       "sec-ch-ua-mobile": "?0",
       "sec-ch-ua-platform": "\"Linux\"",
       "sec-fetch-dest": "empty",
       "sec-fetch-mode": "cors",
       "sec-fetch-site": "same-origin",
       "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
       "x-debug-options": "bugReporterEnabled",
       "x-discord-locale": "en-US",
       "x-discord-timezone": "America/New_York",
       "x-super-properties": "eyJvcyI6IkxpbnV4IiwiYnJvd3NlciI6IkNocm9tZSIsImRldmljZSI6IiIsInN5c3RlbV9sb2NhbGUiOiJlbi1VUyIsImJyb3dzZXJfdXNlcl9hZ2VudCI6Ik1vemlsbGEvNS4wIChYMTE7IExpbnV4IHg4Nl82NCkgQXBwbGVXZWJLaXQvNTM3LjM2IChLSFRNTCwgbGlrZSBHZWNrbykgQ2hyb21lLzEyNi4wLjAuMCBTYWZhcmkvNTM3LjM2IiwiYnJvd3Nlcl92ZXJzaW9uIjoiMTI2LjAuMC4wIiwib3NfdmVyc2lvbiI6IiIsInJlZmVycmVyIjoiIiwicmVmZXJyaW5nX2RvbWFpbiI6IiIsInJlZmVycmVyX2N1cnJlbnQiOiIiLCJyZWZlcnJpbmdfZG9tYWluX2N1cnJlbnQiOiIiLCJyZWxlYXNlX2NoYW5uZWwiOiJjYW5hcnkiLCJjbGllbnRfYnVpbGRfbnVtYmVyIjozNDIwNjMsImNsaWVudF9ldmVudF9zb3VyY2UiOm51bGx9"
    });

    let context_json = json!({
        "location": "bite size profile popout"
    });

    let x_context_properties = base64::encode(&serde_json::to_string(&context_json).unwrap());
    setup_headers.insert(
        "x-context-properties",
        HeaderValue::from_str(&x_context_properties).unwrap(),
    );

    let target = json!({});

    let client = DiscordClient::new(None).await;

    for val in vals {
        let mut headers = setup_headers.clone();
        headers.insert("authorization", val.parse().unwrap());

        let resp = client.send_request(HttpRequest::Put {
            endpoint: format!("/users/@me/relationships/{}", USER_ID),
            body: Some(target.clone()),
            additional_headers: Some(headers),
        });

        let resp = resp.await.unwrap();

        println!("{}", resp.status().as_str());

        match resp.status().as_u16() {
            204 => println!("Friend request sent to: {}", val),
            201 => println!("Friend request sent to: {}", val),
            304 => println!("Friend request already sent to: {}", val),
            400 => {
                println!("Bad request: {}", val);
                println!("{}", resp.text().await.unwrap());
            }
            403 => println!("Forbidden: {}", val),
            429 => println!("Rate limited: {}", val),
            500 => println!("Internal server error: {}", val),
            502 => println!("Bad gateway: {}", val),
            503 => println!("Service unavailable: {}", val),
            504 => println!("Gateway timeout: {}", val),
            _ => {
                println!("Unknown status code: {}", val);
                println!("{}", resp.text().await.unwrap());
            }
        }
    }
}

#[tokio::test]
async fn ja3_fingerprint_test() {
    let client = DiscordClient::new(None).await;
    let response = client
        .client
        .get("https://tools.scrapfly.io/api/tls")
        .send()
        .await
        .unwrap();

    println!(
        "{}",
        serde_json::to_string_pretty(&from_str::<Value>(&response.text().await.unwrap()).unwrap())
            .unwrap()
    );
}
