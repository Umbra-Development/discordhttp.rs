use serde::{Deserialize, Serialize};
use serde_json::Value;
use base64::{prelude::BASE64_STANDARD, Engine};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterJson {
    pub consent: bool,
    pub date_of_birth: String,
    pub email: Option<String>,
    pub fingerprint: String,
    pub gift_code_sku_id: Option<String>,
    pub global_name: String,
    pub invite: Option<String>,
    pub password: Option<String>,
    pub username: String,
    // pub captcha_key:        Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SuperProperties {
    pub os: String,
    pub browser: String,
    pub device: String,
    pub system_locale: String,
    pub has_client_mods: bool,
    pub browser_user_agent: String,
    pub browser_version: String,
    pub os_version: String,
    pub referrer: String,
    pub referring_domain: String,
    pub referrer_current: String,
    pub referring_domain_current: String,
    pub release_channel: String,
    pub client_build_number: i64,
    pub client_event_source: Value,
    pub client_launch_id: String,
    pub client_heartbeat_session_id: String,
    pub client_app_state: String,
}

impl Default for SuperProperties {
    fn default() -> SuperProperties {
        // Running Vesktop client, stole it from there
        SuperProperties {
            os: "Linux".into(),
            browser: "Chrome".into(),
            device: "".into(),
            system_locale: "en-GB".into(),
            // Suprised there's actual detection like this lol, vesktop disables it by default
            // Would it be less telling to set it to True?
            has_client_mods: false,
            browser_user_agent: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36".into(),
            browser_version: "134.0.0.0".into(),
            os_version: "".into(),
            referrer: "".into(),
            referring_domain: "".into(),
            referrer_current: "".into(),
            referring_domain_current: "".into(),
            release_channel: "canary".into(),
            client_build_number: 402835,
            client_event_source: Value::Null,
            client_launch_id: "9208e676-a3db-4222-b31e-5ec29d90f946".into(),
            // Reliably we'd want to generate this
            client_heartbeat_session_id: "f40eacbc-572f-44a3-a954-01b3cb55dce8".into(),
            client_app_state: "focused".into()
        }
    }
}

impl SuperProperties {
    pub fn base64(&self) -> String {
        let json_str = serde_json::to_string(&self).unwrap();
        BASE64_STANDARD.encode(json_str)
    }
}

#[test]
fn base64_test() {
    let properties = SuperProperties::default();
    println!("{}", properties.base64());
}
