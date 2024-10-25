use crate::easy_headers;
use crate::types::HttpRequest;
use crate::utils::{default_headers, experiment_headers, merge_headermaps};
use reqwest::header::{HeaderMap, HeaderValue, USER_AGENT};
use rustls::crypto::aws_lc_rs::cipher_suite::{
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
};
use rustls::crypto::aws_lc_rs::kx_group::X25519;
use rustls::crypto::{tls12, CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::CertificateDer;
use rustls::{
    CipherSuite, ClientConfig, ProtocolVersion, RootCertStore, SupportedCipherSuite,
    Tls13CipherSuite,
};
use webpki_roots::TLS_SERVER_ROOTS; // Import Mozilla root certificates
// Required for macro idfk why
use reqwest::{header::HeaderName, Response};
use std::any::Any;
use std::error::Error;
use std::sync::Arc;

pub type Client = DiscordClient;

#[derive(Debug, Clone)]
pub struct DiscordClient {
    pub client: reqwest::Client,
    pub proxy_info: Option<url::Url>,
}

// This function constructs a complete CryptoProvider.
pub fn build_crypto_provider() -> Arc<rustls::crypto::CryptoProvider> {
    return Arc::new(rustls::crypto::aws_lc_rs::default_provider());
}

pub fn build_webpki_verifier(
    provider: Arc<rustls::crypto::CryptoProvider>,
) -> Arc<rustls::client::WebPkiServerVerifier> {
    let roots: RootCertStore =
        RootCertStore::from_iter(TLS_SERVER_ROOTS.into_iter().map(|t| t.to_owned()));

    return rustls::client::WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider)
        .build()
        .unwrap();
}

impl DiscordClient {
    pub async fn new() -> DiscordClient {
        // I have no idea atp, pls fix
        let mut real_headers = default_headers(None);
        let other_headers = experiment_headers(reqwest::Client::new()).await;
        merge_headermaps(&mut real_headers, other_headers);

        let cprov = build_crypto_provider();
        let webpki_verifier = build_webpki_verifier(cprov.clone());
        // let prov_arc = build_crypto_provider();

        let mut tls = ClientConfig::builder_with_provider(cprov.clone())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_webpki_verifier(webpki_verifier)
            .with_no_client_auth();
        
        // Optionally, you can limit to specific cipher suites if desired (within Rustls limits)
        println!("{:?}", tls);

   
        let builder = reqwest::Client::builder()
            .default_headers(real_headers)
            // You originally used the default implementation for rewqest::cookie::Jar
            // Pretty much does the same thing
            // From what I read in docs you basically don't have to pass cookie argument yourself
            // Though ig might as well do it initially though
            .cookie_store(true)
            .use_preconfigured_tls(tls);

        let client = builder.build().unwrap();

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
    let response = client
        .send_request(HttpRequest::Get {
            endpoint: "/users/@me".to_string(),
            params: None,
            additional_headers: Some(easy_headers!({"authorization": "token" })),
        })
        .await
        .unwrap();
    println!("{}", response.text().await.unwrap());
}
