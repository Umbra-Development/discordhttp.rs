use client::SpoofedClient;
use rquest::EmulationProviderFactory;
use types::HttpRequest;
pub mod client;
pub mod types;
pub mod utils;

#[tokio::test]
async fn ja3_test() {
    use client::SpoofedClient;

    let resp = SpoofedClient::new("https://tools.scrapfly.io/", None).send_request(HttpRequest::Get { endpoint: "api/tls".to_string(), params: None, additional_headers: None }).await;
    println!("{}", resp.unwrap().text().await.unwrap());
}
