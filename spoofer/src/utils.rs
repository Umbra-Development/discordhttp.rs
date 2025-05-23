use rquest::header::{HeaderMap, HeaderName, HeaderValue};

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

pub fn merge_headermaps(first: &mut HeaderMap, second: HeaderMap) {
    for (key, value) in second {
        if let Some(key) = key {
            first.insert(key, value);
        }
    }
}
