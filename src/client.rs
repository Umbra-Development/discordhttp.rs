use crate::types::HttpRequest;
use crate::utils::{default_headers, experiment_headers, merge_headermaps};
use reqwest::Response;
use std::error::Error;

pub type Client = DiscordClient;

#[derive(Debug, Clone)]
pub struct DiscordClient {
    pub client: reqwest::Client,
    pub proxy_info: Option<url::Url>,
}

impl DiscordClient {
    pub async fn new() -> DiscordClient {
        // I have no idea atp, pls fix
        let mut real_headers = default_headers(None);
        let other_headers = experiment_headers(reqwest::Client::new()).await;
        merge_headermaps(&mut real_headers, other_headers);
        let client = reqwest::Client::builder()
            // You originally used the default implementation for rewqest::cookie::Jar
            // Pretty much does the same thing
            .default_headers(real_headers)
            .cookie_store(true)
            .use_rustls_tls()
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
    let client = DiscordClient::default();
    client
        .send_request(HttpRequest::Get {
            endpoint: "/users/@me".to_string(),
            params: None,
        })
        .await
        .unwrap();
}
