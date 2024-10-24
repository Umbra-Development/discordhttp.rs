use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
use regex::Regex;
use reqwest::header::{HeaderMap, HeaderValue};
use std::path::Path;
use std::string::FromUtf8Error;

use crate::types::SuperProperties;

pub fn encode(s: &str) -> String {
    STANDARD_NO_PAD.encode(s)
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
    let mut headers = HeaderMap::new();
    // let cookie = format!(
    //     "__dcfduid={dcfduid}; __sdcfduid={sdcfduid}, locale=en-US",
    //     dcfduid = dcfduid(),
    //     sdcfduid = sdcfduid()
    // );
    let user_agent_1 = user_agent.unwrap_or(randua::new().safari().desktop().to_string());
    // let user_agent = ;
    let super_properties = build_super_properties(&user_agent_1);
    headers.insert("user-agent", HeaderValue::from_str(&user_agent_1).unwrap());
    // headers.insert("cookie", HeaderValue::from_str(&cookie).unwrap());
    headers.insert("host", HeaderValue::from_static("discord.com"));
    headers.insert("accept", HeaderValue::from_static("*/*"));
    headers.insert("accept-language", HeaderValue::from_static("en-US"));
    headers.insert("content-type", HeaderValue::from_static("application/json"));
    headers.insert("DNT", HeaderValue::from_static("1"));
    headers.insert("connecton", HeaderValue::from_static("keep-alive"));
    headers.insert(
        "x-super-properties",
        HeaderValue::from_str(&super_properties).unwrap(),
    );
    headers.insert(
        "x-debug-options",
        HeaderValue::from_static("bugReporterEnabled"),
    );

    headers.insert(
        "x-discord-timezone",
        HeaderValue::from_static("America/New_York"),
    );

    // Extract browser and version info using regex
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

    // Add sec-ch-ua header (For simplicity, using fixed version numbers for Chromium)
    headers.insert(
        "sec-ch-ua",
        HeaderValue::from_str(&format!(
            "\"Not;A=Brand\";v=\"24\", \"{}\";v=\"{}\"",
            browser.0, browser.1
        ))
        .unwrap(),
    );

    // Add sec-ch-ua-mobile header (assuming desktop, ?0)
    headers.insert("sec-ch-ua-mobile", HeaderValue::from_static("?0"));

    // Add sec-ch-ua-platform header (based on extracted platform)
    headers.insert(
        "sec-ch-ua-platform",
        HeaderValue::from_str(&format!("\"{}\"", platform)).unwrap(),
    );

    // Add sec-fetch-dest header
    headers.insert("sec-fetch-dest", HeaderValue::from_static("empty"));

    // Add sec-fetch-mode header
    headers.insert("sec-fetch-mode", HeaderValue::from_static("cors"));

    // Add sec-fetch-site header
    headers.insert("sec-fetch-site", HeaderValue::from_static("same-origin"));

    headers.insert(
        "x-context-properties",
        "eyJsb2NhdGlvbiI6IlJlZ2lzdGVyIn0=".parse().expect("valid"),
    );
    headers
}
pub async fn experiment_headers(reqwest_client: reqwest::Client) -> HeaderMap {
    let mut headers = default_headers(None);
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

    headers.insert(
        "x-fingerprint",
        HeaderValue::from_str(&fingerprint).expect("Failed to assign fingerprint"), // HeaderValue::from_static("878085544222003271.hYXin384hC-Q7MNGSdXmx75MYTI"),
    );

    headers.insert(
        "cookie",
        HeaderValue::from_str(&final_cookie).expect("Failed to assign cookies"), // HeaderValue::from_static("878085544222003271.hYXin384hC-Q7MNGSdXmx75MYTI"),
    );

    headers.remove("x-context-properties");

    headers
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
