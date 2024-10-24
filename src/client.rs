use crate::types::{HttpRequest, SuperProperties};
use reqwest::Response;
use std::error::Error;

pub type Client = DiscordClient;

#[derive(Debug, Clone)]
pub struct DiscordClient {
    pub client: reqwest::Client,
    pub proxy_info: Option<url::Url>,
}

impl Default for DiscordClient {
    fn default() -> DiscordClient {
        let client = reqwest::Client::builder()
            // You originally used the default implementation for rewqest::cookie::Jar
            // Pretty much does the same thing
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
