#![allow(unused_imports)]
use crate::{easy_headers, easy_params};
use tokio::sync::mpsc;
use tokio::time::Duration;
use futures_util::{SinkExt, StreamExt};
use crate::types::HttpRequest;
use crate::utils::{default_headers, experiment_headers, merge_headermaps, decompress_zlib};
use jsonwebtoken::{encode, EncodingKey, Header};
use rquest::boring::ssl::{SslConnector, SslCurve, SslMethod, SslOptions, SslVersion};
// Required for macro idfk why
use rquest::{header, HttpVersionPref, Message};
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
use std::io::Read;
use std::sync::Arc;


pub struct WebsocketClient {
    pub client: rquest::WebSocket,
}
impl WebsocketClient {
    pub async fn new(proxy: Option<rquest::Proxy>) -> WebsocketClient {
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
            .impersonate(Impersonate::Chrome128)
            .cookie_store(true); 
        let ws = configure_proxy(builder, proxy).build().unwrap()
            .websocket("wss://gateway.discord.gg/?encoding=json&v=9&compress=zlib-stream")
            .send().await.unwrap();
        Self { client: ws.into_websocket().await.unwrap() }
    }

    pub async fn connect_and_identify(&mut self, token: &str) -> Option<String> {
        let client = std::mem::replace(&mut self.client,
            rquest::Client::builder()
            .impersonate(Impersonate::Chrome128)
            .cookie_store(true)
            .build()
            .unwrap()
            .websocket("wss://gateway.discord.gg/?encoding=json&v=9&compress=zlib-stream")
            .send().await.unwrap().into_websocket().await.unwrap());
        // For some reason this takes ownership of self.client
        // So above code replaces client, so it doesn't shit itself here
        let (mut tx, mut rx) = client.split();
        let (message_tx, mut message_rx) = mpsc::channel::<Message>(50);
        
        // Task to receive message from mpsc rx to send to ws
        tokio::spawn(async move {
            while let Some(msg) = message_rx.recv().await {
                println!("Sending: {msg:?}");
                if let Err(e) = tx.send(msg).await {
                    eprintln!("Failed to send message: {}", e);
                    break;
                }
            }
        });

        let heartbeat_tx = message_tx.clone();
        tokio::spawn(async move {
            let mut interval_timer = tokio::time::interval(Duration::from_secs(45));
            interval_timer.tick().await; // First tick completes immediately
            loop {
                interval_timer.tick().await;
                let heartbeat_payload = json!({
                    "op": 1,
                    "d": null // or the last sequence number if keeping track
                });
                if heartbeat_tx
                    .send(Message::Text(heartbeat_payload.to_string()))
                    .await
                    .is_err()
                {
                    eprintln!("Failed to send heartbeat");
                    break;
                }
            }
        });

        // Yes I know the None is unreachable 
        loop {
            while let Some(Ok(message)) = rx.next().await {
                if let Message::Binary(bytes) = message {

                    if let Ok(val) = decompress_zlib(&bytes) {
                        let json: Value = serde_json::from_str(&val).unwrap();
                        println!("{} RECEIVED JSON", json);
                        match json["op"].as_i64() {
                            // HELLO event with heartbeat interval
                            Some(10) => {
                                // Send the IDENTIFY payload
                                let identify_payload = json!({
                                    "token": token,
                                    "properties": {
                                        "os": "Linux",
                                        "browser": "Chrome",
                                        "device": "",
                                        "system_locale": "en-US",
                                        "browser_user_agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
                                        "browser_version": "122.0.0.0",
                                        "os_version": "",
                                        "referrer": "",
                                        "referring_domain": "",
                                        "referrer_current": "",
                                        "referring_domain_current": "",
                                        "release_channel": "canary",
                                        "client_build_number": 342400,
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
                                });
                                message_tx
                                    .send(Message::Text(identify_payload.to_string()))
                                    .await
                                    .unwrap();
                            }
                            // READY event containing the session_id
                            Some(0) if json["t"] == "READY" => {
                                println!("IN READY{:?}", json);
                                if let Some(session_id) = json["d"]["session_id"].as_str() {
                                    println!("Session ID: {}", session_id);
                                    return Some(session_id.to_string());
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
        }

        None
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
async fn test_decoder() {
    let encoded = [120, 218, 52, 201, 65, 10, 131, 48, 16, 5, 208, 187, 252, 117, 82, 146, 210, 46, 58, 87, 49, 34, 211, 56, 84, 33, 85, 73, 70, 165, 132, 220, 189, 221, 116, 247, 224, 85, 40, 104, 217, 83, 50, 40, 127, 172, 27, 200, 59, 131, 17, 84, 49, 9, 103, 125, 10, 235, 48, 47, 42, 249, 224, 4, 186, 249, 235, 253, 247, 131, 102, 142, 2, 234, 208, 5, 188, 88, 229, 228, 143, 221, 242, 104, 247, 98, 133, 139, 122, 27, 173, 62, 166, 35, 192, 212, 128, 247, 28, 243, 90, 2, 200, 93, 92, 235, 209, 183, 246, 5, 0, 0, 255, 255];
    println!("{:?}", decompress_zlib(&encoded).unwrap());
}

#[tokio::test]
async fn test_ws() {
    let mut client = WebsocketClient::new(None).await;
    let id = client.connect_and_identify(
        "cocken"
    ).await;
    println!("{:?}", id);
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


#[tokio::test]
async fn token_join_leave() {
    const AMT: usize = 3;
    const COOKIE: &'static str = "__dcfduid=9b0e5a9096de11efbaea092ef1a07225; __sdcfduid=9b0e5a9196de11efbaea092ef1a072257d00d819c249039e1508fcd07f793ebea8a127f173ceeaedc7d17f650fa7794d; __stripe_mid=8fe3b13e-cfcb-4de9-9776-6528a1cfe46c2f5c0f; cf_clearance=exU208lykoMbx8B146R13MXXSsC0B_cngvsUEM2eEhQ-1730847161-1.2.1.1-fWDFrtsLtmF7JvaxV5edq8ekENFGijSZnk8XMY8YVmG6aZedfrLFEG.GwesQp0mAa.yByRNjS_gdLNx.KIYRQqgrEuPb6cCqIkbJPQnD_BTJaTIznsbEdPCChLBAuev6DNUbB6eblcaZqqnAGYX0E.YgRuNrFnzUkBljHJ6ayJEqSdu0HbvLzWYc.St2WB1Rgn69Ki1zKgGii.Pzy1XcGNvMQsHbHLNNFxsmRS.qmnjer67QwGQjN3HQbQMxCibiXwCyCpwo4sncWjMjzAZPE.7Lj7CfSGwMY9vhGZhE4g4ZrcogyQ9zQn8vXn2p7C7T29csyDyfM6kq3CxVHSHvlebVH1NBUcWjRZTWaX7nLwxEAWXx2Q8mXAsHIVJrtqTc; __cfruid=56f893338114801c9e7a339b039996ddd111473c-1730847636; _cfuvid=XUM_URznBabjhipaHwGNUZJ12RWMWHQe2i.O7Jf929o-1730854284096-0.0.1.1-604800000";
    const INVITE: &str = "SH3dNuWd";    

    let mut tokens = String::new();
    let mut file = std::fs::File::open("./tokens.txt").unwrap();
    file.read_to_string(&mut tokens).unwrap();
    let vals = tokens
        .split("\n")
        .into_iter()
        .take(AMT)
        .collect::<Vec<&str>>();

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
    setup_headers.insert("x-context-properties", HeaderValue::from_str(&x_context_properties).unwrap());
   
    for val in vals {
        let mut headers = setup_headers.clone();
        headers.insert("authorization", val.parse().unwrap());
        let shit = headers.clone();

        // Joining a server
        let resp = client
            .send_request(HttpRequest::Post {
                endpoint: format!("/invites/{}", INVITE),
                body: Some(json!({"session_id": Value::Null})),
                additional_headers: Some(headers),
            })
            .await
            .unwrap();
        println!("{}", resp.status().as_str());
        if resp.status().is_success() {
            println!("Token has joined the server: {}", val);
        } else {
            let headers = resp.headers();
            let cookies = headers
                .get_all("set-cookie")
                .into_iter()
                .map(|header_value| header_value.to_str().unwrap_or("").to_string())
                .collect::<Vec<String>>();

            println!(
                "Token could not join the server: {}\n{}\n{}",
                val,
                resp.status().as_str(),
                resp.url()
            );
            println!("{:?}", shit);
            println!("{:?}", headers);
            println!("{:?}", cookies);
            println!("{}", resp.text().await.unwrap())
        }

        // // Leaving a server
        // let resp = client.send_request(
        //     HttpRequest::Delete {
        //         endpoint: "/users/@me/guilds/1299815021794164838".to_string(),
        //         additional_headers: Some(easy_headers!({"authorization": val}))
        //     }
        // )
        // .await
        // .unwrap();
        // println!("{}", resp.status().as_str());
        // if resp.status().is_success() {
        //     println!("Token has left the server: {}", val)
        // } else {
        //     println!("Token could not leave the server: {}\n{}\n{}", val, resp.status().as_str(), resp.text().await.unwrap())
        // }
    }
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
            (token, decode_user_id(token.split(".").nth(0).unwrap()).unwrap())
        
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
    setup_headers.insert("x-context-properties", HeaderValue::from_str(&x_context_properties).unwrap());

    let target = json!({
        "username": USERNAME,
        "discriminator": null
    
    });

    let client = DiscordClient::new(None).await;

    for val in vals {
        let mut headers = setup_headers.clone();
        headers.insert("authorization", val.parse().unwrap());

        let resp = client
            .send_request(HttpRequest::Post {
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
            
            },
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
    setup_headers.insert("x-context-properties", HeaderValue::from_str(&x_context_properties).unwrap());

    let target = json!({});

    let client = DiscordClient::new(None).await;

    for val in vals {
        let mut headers = setup_headers.clone();
        headers.insert("authorization", val.parse().unwrap());

        let resp = client
            .send_request(HttpRequest::Put {
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
            },
            403 => println!("Forbidden: {}", val),
            429 => println!("Rate limited: {}", val),
            500 => println!("Internal server error: {}", val),
            502 => println!("Bad gateway: {}", val),
            503 => println!("Service unavailable: {}", val),
            504 => println!("Gateway timeout: {}", val),
            _ => {
                println!("Unknown status code: {}", val);
                println!("{}", resp.text().await.unwrap());
            
            },
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
