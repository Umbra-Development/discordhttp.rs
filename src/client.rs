#![allow(unused_imports)]
use crate::easy_headers;
use crate::types::HttpRequest;
use crate::utils::{default_headers, experiment_headers, merge_headermaps};
use rquest::boring::ssl::{SslConnector, SslVersion, SslCurve, SslMethod, SslOptions};
// Required for macro idfk why
use rquest::{
    header,
    HttpVersionPref,
};
use rquest::{PseudoOrder::*, SettingsOrder::*};

use rquest::tls::{chrome, Impersonate, ImpersonateSettings, TlsSettings, Http2Settings, Version};
use rquest::{
    header::{HeaderMap, HeaderName, HeaderValue},
    Response,
};
use serde_json::{from_str, json, Value};
use std::any::Any;
use std::error::Error;
use std::io::Read;

pub type Client = DiscordClient;

#[derive(Debug, Clone)]
pub struct DiscordClient {
    pub client: rquest::Client,
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
            .impersonate_without_headers(Impersonate::Chrome128)
            .default_headers(real_headers)
            .cookie_store(true)
            .use_preconfigured_tls(tls_preconfig())
            .pre_shared_key()
            .max_tls_version(Version::TLS_1_2);

        let client = configure_proxy(builder, proxy)
            .build()
            .unwrap();

        let tls_raw = ClientConfig::builder_with_provider(cprov.clone())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_webpki_verifier(webpki_verifier)
            .with_no_client_auth();
        

        let mut tls = Some(tls_raw.clone());
            if let Some(conn) =
                (&mut tls as &mut dyn Any).downcast_mut::<Option<rustls::ClientConfig>>()
            {
                println!("downcasted");
                let builder = reqwest::Client::builder()
            // .default_headers(real_headers)
            // .cookie_store(true)
            .use_preconfigured_tls(tls_raw);

        let client = builder.build().unwrap();

        return Self {
            client,
            proxy_info: None,
        }
            }
   
        todo!()
    }
}

fn configure_proxy(builder: rquest::ClientBuilder, proxy: Option<rquest::Proxy>) -> rquest::ClientBuilder {
    if let Some(proxy) = proxy {
        builder.proxy(proxy)
    } else {
        builder
    }
}


fn tls_preconfig() -> ImpersonateSettings {
    ImpersonateSettings::builder()

    .tls(
        TlsSettings::builder()
            .connector(Box::new(|| {
                let mut builder = SslConnector::builder(SslMethod::tls_client())?;
                builder.cert_store();
                builder.set_curves(&[SslCurve::X25519, SslCurve::SECP256R1, SslCurve::SECP384R1])?;
                builder.set_cipher_list(&[
                    "TLS_AES_128_GCM_SHA256",
                    "TLS_AES_256_GCM_SHA384",
                    "TLS_CHACHA20_POLY1305_SHA256",
                    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
                    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
                    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
                    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
                    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
                    "TLS_RSA_WITH_AES_128_GCM_SHA256",
                    "TLS_RSA_WITH_AES_256_GCM_SHA384",
                    "TLS_RSA_WITH_AES_128_CBC_SHA",
                    "TLS_RSA_WITH_AES_128_CBC_SHA"
                ].join(":"))?;
                
                Ok(builder)
            }))
            .tls_sni(true)
            .http_version_pref(HttpVersionPref::All)
            .application_settings(true)
            .pre_shared_key(true)
            .enable_ech_grease(true)
            .permute_extensions(true)
            .min_tls_version(Version::TLS_1_2)
            .max_tls_version(Version::TLS_1_2)
            .build(),
    )
    .http2(
        Http2Settings::builder()
            .initial_stream_window_size(6291456)
            .initial_connection_window_size(15728640)
            .max_concurrent_streams(1000)
            .max_header_list_size(262144)
            .header_table_size(65536)
            .enable_push(false)
            .headers_priority((0, 255, true))
            .headers_pseudo_order([Method, Scheme, Authority, Path])
            .settings_order(&[
                HeaderTableSize,
                EnablePush,
                MaxConcurrentStreams,
                InitialWindowSize,
                MaxFrameSize,
                MaxHeaderListSize,
                EnableConnectProtocol,
            ])
            .build(),
    )
    .build()
}


impl DiscordClient {
    pub async fn send_request(&self, request: HttpRequest) -> Result<Response, Box<dyn Error>> {
        let builder = request.to_request_builder(&self.client);

        let response = builder.send().await?;
        Ok(response)
    }
}

// #[tokio::test]
// async fn request_builder_test() {
//     let client = DiscordClient::new( None).await;
//     let response = client
//         .send_request(HttpRequest::Get {
//             endpoint: "/experiments".to_string(),
//             params: None,
//             additional_headers: Some(easy_headers!({"authorization": "token" })),
//         })
//         .await
//         .unwrap();
//     println!("{}", response.text().await.unwrap());
// }
//
#[tokio::test]
async fn token_join_leave() {
    let mut tokens = String::new();
    let mut file = std::fs::File::open("./tokens.txt").unwrap();
    file.read_to_string(&mut tokens).unwrap();
    let vals= tokens.split('\n').into_iter();
    
    let client = DiscordClient::new(None).await;
    for val in vals {
        // Joining a server
        let resp = client.send_request(
            HttpRequest::Post {
                endpoint: "/invites/PuJMXFPm".to_string(),
                body: Some(json!({"session_id": Value::Null})),
                additional_headers: Some(easy_headers!({"authorization": val}))
            }
        ).await
        .unwrap();
        println!("{}", resp.status().as_str());
        if resp.status().is_success() {
            println!("Token has joined the server: {}", val)
        } else {
            println!("Token could not join the server: {}\n{}\n{}", val, resp.status().as_str(), resp.text().await.unwrap())
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


