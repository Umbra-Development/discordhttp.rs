use crate::types::HttpRequest;
use rquest::{Client as RequestClient, EmulationProvider, Response, TlsConfig};
use rquest_util::Emulation;
pub struct SpoofedClient {
    root: String,
    client: RequestClient,
}

impl SpoofedClient {
    pub fn new(root: impl Into<String>) -> Self {
        let emulate = EmulationProvider::builder()
            .tls_config(
                TlsConfig::builder()
                    .enable_signed_cert_timestamps(true)
                    .enable_ech_grease(true)
                    .enable_ocsp_stapling(true)
                    .grease_enabled(true)
                    .verify_hostname(true)
                    .build()
            );
        let client = RequestClient::builder().emulation(Emulation::Chrome128).build();
         
        SpoofedClient {
            root: root.into(),
            client: client.unwrap(),
        }
    }

    pub async fn send_request(&self, request: HttpRequest) -> Result<Response, rquest::Error> {
        let builder = request.to_request_builder(&self.root.to_string(), &self.client);
        builder.send().await
    }
}

