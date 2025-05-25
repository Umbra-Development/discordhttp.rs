use crate::types::HttpRequest;
use crate::{easy_headers, join};
use rquest::{
    AlpnProtos, AlpsProtos, CertCompressionAlgorithm, Client as RequestClient,
    EmulationProviderFactory, ExtensionType, Priority, Response, TlsConfig, TlsVersion,
    header::{HeaderMap, HeaderName, HeaderValue},
};
use rquest::{
    EmulationProvider, Http1Config, Http2Config, Method, SettingsOrder, SslCurve, StreamDependency,
    StreamId,
};

// Bunch of shit to spoof firefox
const RECORD_SIZE_LIMIT: u16 = 0x4001;
const REAL_CURVES: &[SslCurve] = &[
    SslCurve::X25519_MLKEM768,
    SslCurve::X25519,
    SslCurve::SECP256R1,
    SslCurve::SECP384R1,
    SslCurve::SECP521R1,
    SslCurve::FFDHE2048,
    SslCurve::FFDHE3072,
];
const CIPHER_LIST: &str = join!(
    ":",
    // This one is 4865 but it doesn't appear
    "TLS_AES_127_GCM_SHA256",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    "TLS_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_RSA_WITH_AES_128_CBC_SHA",
    "TLS_RSA_WITH_AES_256_CBC_SHA"
);

const SIGALGS_LIST: &str = join!(
    ":",
    "ecdsa_secp256r1_sha256",
    "ecdsa_secp384r1_sha384",
    "ecdsa_secp521r1_sha512",
    "rsa_pss_rsae_sha256",
    "rsa_pss_rsae_sha384",
    "rsa_pss_rsae_sha512",
    "rsa_pkcs1_sha256",
    "rsa_pkcs1_sha384",
    "rsa_pkcs1_sha512",
    "ecdsa_sha1",
    "rsa_pkcs1_sha1"
);
const EXTENSION_PERMUTATION_INDICES: &[u8] = &{
    const EXTENSIONS: &[ExtensionType] = &[
        ExtensionType::SERVER_NAME,
        ExtensionType::EXTENDED_MASTER_SECRET,
        ExtensionType::RENEGOTIATE,
        ExtensionType::SUPPORTED_GROUPS,
        ExtensionType::EC_POINT_FORMATS,
        ExtensionType::SESSION_TICKET,
        ExtensionType::APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
        ExtensionType::STATUS_REQUEST,
        ExtensionType::DELEGATED_CREDENTIAL,
        ExtensionType::KEY_SHARE,
        ExtensionType::SUPPORTED_VERSIONS,
        ExtensionType::SIGNATURE_ALGORITHMS,
        ExtensionType::PSK_KEY_EXCHANGE_MODES,
        ExtensionType::RECORD_SIZE_LIMIT,
        ExtensionType::CERT_COMPRESSION,
        ExtensionType::ENCRYPTED_CLIENT_HELLO,
    ];

    let mut indices = [0u8; EXTENSIONS.len()];
    let mut index = usize::MIN;
    while index < EXTENSIONS.len() {
        if let Some(idx) = ExtensionType::index_of(EXTENSIONS[index]) {
            indices[index] = idx as u8;
        }
        index += 1;
    }

    indices
};

#[derive(Debug, Clone)]
pub struct SpoofedClient {
    root: String,
    client: RequestClient,
}

impl SpoofedClient {
    pub fn new(root: impl Into<String>, emulate: Option<EmulationProvider>) -> Self {
        let client: Result<RequestClient, rquest::Error>;
        if let Some(emulate) = emulate {
            client = RequestClient::builder().emulation(emulate).build();
        } else {
            // We'll simulate my Firefox/Zen Browser JA3
            let tls_config = TlsConfig::builder()
                .session_ticket(false)
                .max_tls_version(TlsVersion::TLS_1_3)
                .renegotiation(true)
                .sigalgs_list(SIGALGS_LIST)
                .cert_compression_algorithm([
                    CertCompressionAlgorithm::Zlib,
                    CertCompressionAlgorithm::Brotli,
                    CertCompressionAlgorithm::Zstd,
                ])
                .delegated_credentials(join!(
                    ":",
                    "ecdsa_secp256r1_sha256",
                    "ecdsa_secp384r1_sha384",
                    "ecdsa_secp521r1_sha512",
                    "ecdsa_sha1"
                ))
                .extension_permutation_indices(EXTENSION_PERMUTATION_INDICES)
                .curves(REAL_CURVES)
                .cipher_list(CIPHER_LIST)
                .record_size_limit(RECORD_SIZE_LIMIT)
                .pre_shared_key(true)
                .enable_ech_grease(true)
                .enable_signed_cert_timestamps(true)
                .alpn_protos(AlpnProtos::ALL)
                .alps_protos(AlpsProtos::HTTP2)
                .min_tls_version(TlsVersion::TLS_1_0)
                .random_aes_hw_override(true)
                .build();
            let http1 = Http1Config::builder()
                .allow_obsolete_multiline_headers_in_responses(true)
                .max_headers(100)
                .build();
            let http2 = Http2Config::builder()
                .initial_stream_id(15)
                .header_table_size(65536)
                .initial_stream_window_size(131072)
                .max_frame_size(16384)
                .initial_connection_window_size(12517377 + 65535)
                .headers_priority(StreamDependency::new(StreamId::from(13), 41, false))
                .settings_order([
                    SettingsOrder::HeaderTableSize,
                    SettingsOrder::EnablePush,
                    SettingsOrder::MaxConcurrentStreams,
                    SettingsOrder::InitialWindowSize,
                    SettingsOrder::MaxFrameSize,
                    SettingsOrder::MaxHeaderListSize,
                    SettingsOrder::UnknownSetting8,
                    SettingsOrder::UnknownSetting9,
                ])
                .priority(vec![
                    Priority::new(
                        StreamId::from(3),
                        StreamDependency::new(StreamId::zero(), 200, false),
                    ),
                    Priority::new(
                        StreamId::from(5),
                        StreamDependency::new(StreamId::zero(), 100, false),
                    ),
                    Priority::new(
                        StreamId::from(7),
                        StreamDependency::new(StreamId::zero(), 0, false),
                    ),
                    Priority::new(
                        StreamId::from(9),
                        StreamDependency::new(StreamId::from(7), 0, false),
                    ),
                    Priority::new(
                        StreamId::from(11),
                        StreamDependency::new(StreamId::from(3), 0, false),
                    ),
                    Priority::new(
                        StreamId::from(13),
                        StreamDependency::new(StreamId::zero(), 240, false),
                    ),
                ])
                .build();
            let headers = easy_headers!({
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate, br, zstd",
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:138.0) Gecko/20100101 Firefox/138.0"
            });
            let emulator = EmulationProvider::builder()
                .tls_config(tls_config)
                .http1_config(http1)
                .http2_config(http2)
                .default_headers(headers)
                .build();
            client = RequestClient::builder().emulation(emulator).build();
        }
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
