use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
use flate2::{Decompress, FlushDecompress};
use regex::Regex;
use rquest::header::{HeaderMap, HeaderName, HeaderValue};


use std::{io::ErrorKind, path::Path};
use std::string::FromUtf8Error;

use crate::types::SuperProperties;
use std::io::{self};

pub fn encode(s: &str) -> String {
    STANDARD_NO_PAD.encode(s)
}



pub struct ZlibStreamDecompressor {
    decompressor: Decompress,
    buffer: Vec<u8>, // Buffer to store decompressed data
    last_out: usize, // Last index of valid decompressed data in `self.buffer`
}

impl ZlibStreamDecompressor {
    pub fn new(buffer_size: usize) -> Self {
        Self {
            decompressor: Decompress::new(true),
            buffer: vec![0; buffer_size],
            last_out: 0
        }
    }

    pub fn decompress(&mut self, bytes: &[u8]) -> io::Result<String> {
        match self
            .decompressor
            .decompress(bytes, &mut self.buffer, FlushDecompress::Sync)
        {
            Ok(_status) => {
                // Append only the valid part of the decompressed data to `self.buffer`
                let bytes_written = self.decompressor.total_out() as usize;
                let diff = bytes_written - self.last_out;
                let decompressed_chunk = &self.buffer[..diff];
                self.last_out = bytes_written;

                Ok(std::str::from_utf8(&decompressed_chunk).unwrap().to_string())
            }
            Err(e) => Err(io::Error::new(ErrorKind::InvalidData, e)),
        }
    }
}

#[macro_export]
macro_rules! easy_headers {
    ( { $($key:tt : $value:expr),* $(,)? } ) => {{
        let mut headers = HeaderMap::new();
        $(
            let header_name = $key.parse::<HeaderName>().unwrap();
            let header_value = HeaderValue::from_str(&$value.to_string()).unwrap();
            headers.insert(header_name, header_value);
        )*
        headers
    }};
}

#[macro_export]
macro_rules! easy_params {
    ( { $($key:tt : $value:expr),* $(,)? } ) => {{
        let mut params = std::collections::HashMap::new();
        $(
            params.insert($key.to_string(), $value.to_string());
        )*
        params
    }};
}

pub fn decode(s: &str) -> Result<String, FromUtf8Error> {
    String::from_utf8(STANDARD_NO_PAD.decode(s).unwrap())
}

pub fn get_contents_vec<P: AsRef<Path>>(path: P) -> std::io::Result<Vec<String>> {
    let file = std::fs::read_to_string(path)?;
    Ok(file.split("\n").map(String::from).collect::<Vec<String>>())
}

pub fn merge_headermaps(first: &mut HeaderMap, second: HeaderMap) {
    for (key, value) in second {
        if let Some(key) = key {
            first.insert(key, value);
        }
    }
}

fn extract_browser_version(user_agent: &str, browser: &str) -> String {
    // Attempt to extract the version number based on browser type
    if browser == "Chrome" {
        user_agent
            .split("Chrome/")
            .nth(1)
            .and_then(|s| s.split_whitespace().next())
            .unwrap_or("Unknown")
            .to_string()
    } else if browser == "Firefox" {
        user_agent
            .split("Firefox/")
            .nth(1)
            .and_then(|s| s.split_whitespace().next())
            .unwrap_or("Unknown")
            .to_string()
    } else if browser == "Discord Client" {
        user_agent
            .split("discord/")
            .nth(1)
            .and_then(|s| s.split_whitespace().next())
            .unwrap_or("Unknown")
            .to_string()
    } else if browser == "Safari" {
        user_agent
            .split("Version/")
            .nth(1)
            .and_then(|s| s.split_whitespace().next())
            .unwrap_or("Unknown")
            .to_string()
    } else {
        "Unknown".to_string()
    }
}

fn build_super_properties(user_agent: &String) -> String {
    // Determine the OS and its version based on the user agent

    let (os, os_ver, distro) = if user_agent.contains("Windows") {
        ("Windows", "10", "\"Windows\"")
    } else if user_agent.contains("Linux") {
        ("Linux", "6.1.112-1-MANJARO", "\"Manjaro Linux\"")
    } else if user_agent.contains("Mac OS X") {
        ("macOS", "10.15.7", "\"Mac OS X\"")
    } else {
        ("Unknown", "Unknown", "\"Unknown\"")
    };

    let browser = if user_agent.contains("Discord") {
        "Discord Client"
    }
    // Determine the browser based on the user agent
    else if user_agent.contains("Chrome") {
        "Chrome"
    } else if user_agent.contains("Firefox") {
        "Firefox"
    } else {
        "Unknown"
    };

    // Extract the browser version from the user agent string
    let browser_version = extract_browser_version(user_agent, browser);

    // Example client version and build number, might vary depending on Discord client
    let client_version = "0.0.71";
    let client_build_number = 336973;

    // Create SuperProperties struct
    let super_properties = SuperProperties {
        os: os.to_string(),
        os_version: os_ver.to_string(),
        distro: distro.to_string(),
        browser: browser.to_string(),
        browser_user_agent: user_agent.to_string(),
        browser_version: browser_version.to_string(),
        client_version: client_version.to_string(),
        client_build_number,
        ..Default::default()
    };

    // Serialize SuperProperties to JSON and encode it in base64
    let strsuper = serde_json::to_string(&super_properties).unwrap();
    encode(&strsuper)

    // return "eyJvcyI6IkxpbnV4IiwiYnJvd3NlciI6IkRpc2NvcmQgQ2xpZW50IiwicmVsZWFzZV9jaGFubmVsIjoic3RhYmxlIiwiY2xpZW50X3ZlcnNpb24iOiIwLjAuNzEiLCJvc192ZXJzaW9uIjoiNi4xLjExMi0xLU1BTkpBUk8iLCJvc19hcmNoIjoieDY0IiwiYXBwX2FyY2giOiJ4NjQiLCJzeXN0ZW1fbG9jYWxlIjoiZW4tVVMiLCJicm93c2VyX3VzZXJfYWdlbnQiOiJNb3ppbGxhLzUuMCAoWDExOyBMaW51eCB4ODZfNjQpIEFwcGxlV2ViS2l0LzUzNy4zNiAoS0hUTUwsIGxpa2UgR2Vja28pIGRpc2NvcmQvMC4wLjcxIENocm9tZS8xMjguMC42NjEzLjM2IEVsZWN0cm9uLzMyLjAuMCBTYWZhcmkvNTM3LjM2IiwiYnJvd3Nlcl92ZXJzaW9uIjoiMzIuMC4wIiwid2luZG93X21hbmFnZXIiOiJLREUsdW5rbm93biIsImRpc3RybyI6IlwiTWFuamFybyBMaW51eFwiIiwiY2xpZW50X2J1aWxkX251bWJlciI6MzM2OTczLCJuYXRpdmVfYnVpbGRfbnVtYmVyIjpudWxsLCJjbGllbnRfZXZlbnRfc291cmNlIjpudWxsfQ==".to_string();
}

pub fn default_headers(user_agent: Option<String>) -> HeaderMap {
    let user_agent_1 = user_agent.unwrap_or(randua::new().safari().desktop().to_string());
    let context = "eyJsb2NhdGlvbiI6IlJlZ2lzdGVyIn0="
        .parse::<String>()
        .expect("valid");
    let super_properties = build_super_properties(&user_agent_1);
    let browser_regex =
        Regex::new(r"(?i)(firefox|chrome|safari|discord|electron)/([0-9\.]+)").unwrap();
    let platform_regex = Regex::new(r"\(([^;]+);").unwrap();

    let browser = browser_regex
        .captures(&user_agent_1)
        .map(|caps| (caps[1].to_string(), caps[2].to_string()))
        .unwrap_or(("Unknown".to_string(), "Unknown".to_string()));

    let platform = platform_regex
        .captures(&user_agent_1)
        .map(|caps| caps[1].to_string())
        .unwrap_or("Unknown".to_string());

    easy_headers!({
        "user-agent": user_agent_1,
        "host": "discord.com",
        "accept": "*/*",
        "accept-language": "en-US",
        "content-type": "application/json",
        "DNT": "1",
        "connection": "keep-alive",
        "x-super-properties": &super_properties,
        "x-debug-options": "bugReporterEnabled",
        "x-discord-timezone": "America/New_York",
        "sec-ch-ua": format!("\"Not;A=Brand\";v=\"24\", \"{}\";v=\"{}\"", browser.0, browser.1),
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": format!("\"{}\"", platform),
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
        "x-context-properties": context
    })
}
pub async fn experiment_headers(reqwest_client: rquest::Client) -> HeaderMap {
    let headers = default_headers(None);
    let resp = reqwest_client
        .get("https://discord.com/api/v9/experiments?with_guild_experiments=true")
        .headers(headers.clone())
        .send()
        .await
        .expect("msg");

    // println!("{:?}", resp.headers().clone());
    let cookies = resp
        .headers()
        .get_all("set-cookie")
        .into_iter()
        .map(|header_value| header_value.to_str().unwrap_or("").to_string())
        .map(|cookie| cookie.split(';').next().unwrap().to_string())
        .collect::<Vec<String>>();

    let final_cookie = cookies.join("; ");
    let text = resp.text().await.expect("msg");
    let result: serde_json::Value = serde_json::from_str(&text).unwrap();

    let fingerprint = result["fingerprint"].as_str().unwrap().to_string();

    easy_headers!({
        "x-fingerprint": &fingerprint,
        "cookie": &final_cookie,
    })
}

#[test]
fn encode_test() {
    let val = "1143657502941122580";
    assert_eq!(&encode(val), "MTE0MzY1NzUwMjk0MTEyMjU4MA")
}

#[test]
fn decode_test() {
    let val = "MTE0MzY1NzUwMjk0MTEyMjU4MA";
    assert_eq!(&decode(val).unwrap(), "1143657502941122580")
}

#[test]
fn headers_macro() {
    easy_headers!({
        "authorization" : "token",
        "foo" : format!("{}", 123)
    });
}
