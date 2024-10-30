#![allow(unused_imports)]
use crate::easy_headers;
use crate::types::HttpRequest;
use crate::utils::{default_headers, experiment_headers, merge_headermaps};
// Required for macro idfk why

use rquest::tls::Impersonate;
use rquest::tls::Version;
use rquest::{
    header::{HeaderMap, HeaderName, HeaderValue},
    Response,
};
use serde_json::{Value, from_str};
use std::any::Any;
use std::error::Error;

pub type Client = DiscordClient;

#[derive(Debug, Clone)]
pub struct DiscordClient {
    pub client: rquest::Client,
    pub proxy_info: Option<url::Url>,
}

impl DiscordClient {
    pub async fn new() -> DiscordClient {
        // I have no idea atp, pls fix
        let mut real_headers = default_headers(None);
        let other_headers = experiment_headers(
            rquest::Client::builder()
                .impersonate_without_headers(Impersonate::Chrome128)
                .build()
                .unwrap(),
        )
        .await;
        merge_headermaps(&mut real_headers, other_headers);
        let client = rquest::Client::builder()
            .impersonate(Impersonate::Chrome128)
            .default_headers(real_headers)
            .cookie_store(true)
            .max_tls_version(Version::TLS_1_2)
            .build()
            .unwrap();

        Self {
            client,
            proxy_info: None,
        }
    }
}

impl DiscordClient {
    pub async fn send_request(&self, request: HttpRequest) -> Result<Response, Box<dyn Error>> {
        let builder = request.to_request_builder(&self.client);

        let response = builder.send().await?;
        Ok(response)
    }
}

#[tokio::test]
async fn request_builder_test() {
    let client = DiscordClient::new().await;
    for i in 0..20 {
        let response = client
            .send_request(HttpRequest::Get {
                endpoint: "/experiments".to_string(),
                params: None,
                additional_headers: Some(easy_headers!({"authorization": "token" })),
            })
            .await
            .unwrap();
        println!("{}", response.text().await.unwrap());
    }
}



// #[tokio::test]
// async fn ja3_fingerprint_test() {
//     let client = DiscordClient::new().await;
//     let response = client.client.get("https://tools.scrapfly.io/api/tls")
//         .send()
//         .await
//         .unwrap();
//
//     println!(
//         "{}",
//         from_str::<Value>(&response.text().await.unwrap()).unwrap()["ja3"]
//     );
// }


