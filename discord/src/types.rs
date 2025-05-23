use serde::{Deserialize, Serialize};

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

#[derive(Debug, Serialize, Deserialize)]
pub struct SuperProperties {
    pub os: String,
    pub browser: String,
    pub release_channel: String,
    pub client_version: String,
    pub os_version: String,
    pub os_arch: String,
    pub app_arch: String,
    pub system_locale: String,
    pub browser_user_agent: String,
    pub browser_version: String,
    pub window_manager: String,
    pub distro: String,
    pub client_build_number: i32,
    pub native_build_number: Option<i32>,
    pub client_event_source: Option<String>,
}

impl Default for SuperProperties {
    fn default() -> SuperProperties {
        SuperProperties {
            os:                         "Linux".to_string(),
            browser:                    "Discord Client".to_string(),
            release_channel:            "stable".to_string(),
            client_version:             "0.0.71".to_string(),
            os_version:                 "6.1.112-1-MANJARO".to_string(),
            os_arch:                    "x64".to_string(),
            app_arch:                   "x64".to_string(),
            system_locale:              "en-US".to_string(),
            browser_user_agent:         "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) discord/0.0.71 Chrome/128.0.6613.36 Electron/32.0.0 Safari/537.36".to_string(),
            browser_version:            "32.0.0".to_string(),
            window_manager:             "KDE,unknown".to_string(),
            distro:                     "\"Manjaro Linux\"".to_string(),
            client_build_number:        336973,
            native_build_number:        None,
            client_event_source:        None,
        }
    }
}
