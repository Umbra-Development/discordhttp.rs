use rquest::{
    Client as RequestClient, Method, RequestBuilder,
    header::{HeaderMap, HeaderValue},
};
use serde_json::Value;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub enum HttpRequest {
    Get {
        endpoint: String,
        params: Option<HashMap<String, String>>,
        additional_headers: Option<HeaderMap<HeaderValue>>,
    },
    Post {
        endpoint: String,
        body: Option<Value>,
        additional_headers: Option<HeaderMap<HeaderValue>>,
    },
    Put {
        endpoint: String,
        body: Option<Value>,
        additional_headers: Option<HeaderMap<HeaderValue>>,
    },
    Delete {
        endpoint: String,
        body: Option<Value>,
        additional_headers: Option<HeaderMap<HeaderValue>>,
    },
    Patch {
        endpoint: String,
        body: Option<Value>,
        additional_headers: Option<HeaderMap<HeaderValue>>,
    },
}

impl HttpRequest {
    pub fn to_request_builder(&self, root: &str, client: &RequestClient) -> RequestBuilder {
        match self {
            HttpRequest::Get {
                endpoint,
                params,
                additional_headers,
            } => {
                let mut request = client.request(Method::GET, format!("{}{}", root, endpoint));
                if let Some(params) = params {
                    request = request.query(&params);
                }
                if let Some(headers) = additional_headers {
                    request = request.headers(headers.to_owned())
                }
                request
            }
            HttpRequest::Post {
                endpoint,
                body,
                additional_headers,
            } => {
                let mut request = client.request(Method::POST, format!("{}{}", root, endpoint));
                if let Some(body) = body {
                    request = request.json(body);
                }
                if let Some(headers) = additional_headers {
                    request = request.headers(headers.to_owned())
                }
                request
            }
            HttpRequest::Put {
                endpoint,
                body,
                additional_headers,
            } => {
                let mut request = client.request(Method::PUT, format!("{}{}", root, endpoint));
                if let Some(body) = body {
                    request = request.json(body);
                }
                if let Some(headers) = additional_headers {
                    request = request.headers(headers.to_owned())
                }
                request
            }
            HttpRequest::Delete {
                endpoint,
                body,
                additional_headers,
            } => {
                let mut request = client.request(Method::DELETE, format!("{}{}", root, endpoint));
                if let Some(headers) = additional_headers {
                    request = request.headers(headers.to_owned())
                }

                if let Some(body) = body {
                    request = request.json(body);
                }
                request
            }
            HttpRequest::Patch {
                endpoint,
                body,
                additional_headers,
            } => {
                let mut request = client.request(Method::PATCH, format!("{}{}", root, endpoint));
                if let Some(body) = body {
                    request = request.json(body);
                }
                if let Some(headers) = additional_headers {
                    request = request.headers(headers.to_owned())
                }
                request
            }
        }
    }
}
