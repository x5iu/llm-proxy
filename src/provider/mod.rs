use std::fmt;
use std::sync::Arc;

use crate::http;

pub fn new_provider(
    kind: &str,
    host: &str,
    endpoint: &str,
    port: Option<u16>,
    tls: bool,
    api_key: Option<&str>,
    auth_keys: Arc<Vec<String>>,
    provider_auth_keys: Option<Vec<String>>,
) -> Result<Box<dyn Provider>, Box<dyn std::error::Error>> {
    match kind {
        "openai" => Ok(Box::new(OpenAIProvider::new(
            host,
            endpoint,
            port,
            tls,
            api_key,
            auth_keys,
            provider_auth_keys,
        )?)),
        "gemini" => Ok(Box::new(GeminiProvider::new(
            host,
            endpoint,
            port,
            tls,
            api_key,
            auth_keys,
            provider_auth_keys,
        )?)),
        "anthropic" => Ok(Box::new(AnthropicProvider::new(
            host,
            endpoint,
            port,
            tls,
            api_key,
            auth_keys,
            provider_auth_keys,
        )?)),
        _ => Err(format!("Unsupported provider type: {:?}", kind).into()),
    }
}

pub enum Type {
    OpenAI,
    Gemini,
    Anthropic,
}

impl fmt::Display for Type {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Type::OpenAI => write!(f, "openai"),
            Type::Gemini => write!(f, "gemini"),
            Type::Anthropic => write!(f, "anthropic"),
        }
    }
}

pub trait Provider {
    fn kind(&self) -> Type;
    fn host(&self) -> &str;
    fn endpoint(&self) -> &str;
    fn server_name(&self) -> rustls_pki_types::ServerName<'static>;
    fn sock_address(&self) -> &str;
    fn host_header(&self) -> &'static str;
    fn auth_query_key(&self) -> Option<&'static str>;
    fn auth_header(&self) -> Option<&'static str>;
    fn auth_header_key(&self) -> Option<&'static str>;
    fn authenticate(&self, auth: Option<&[u8]>) -> Result<(), AuthenticationError>;
    fn rewrite_first_header_block(&self, block: &[u8]) -> Option<Vec<u8>>;

    fn tls(&self) -> bool {
        true
    }
}

#[derive(Debug, thiserror::Error)]
#[error("Authentication error")]
pub struct AuthenticationError;

pub struct OpenAIProvider {
    host: &'static str,
    endpoint: &'static str,
    tls: bool,
    host_header: &'static str,
    auth_header: Option<&'static str>,
    sock_address: String,
    server_name: rustls_pki_types::ServerName<'static>,
    auth_keys: Arc<Vec<String>>,
    provider_auth_keys: Option<Vec<String>>,
}

impl OpenAIProvider {
    pub fn new(
        host: &str,
        endpoint: &str,
        port: Option<u16>,
        tls: bool,
        api_key: Option<&str>,
        auth_keys: Arc<Vec<String>>,
        provider_auth_keys: Option<Vec<String>>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let static_host = Box::leak(host.to_string().into_boxed_str());
        let static_endpoint = Box::leak(endpoint.to_string().into_boxed_str());
        let host_header = {
            let mut header = String::from("Host: ");
            header.push_str(static_endpoint);
            header.push_str("\r\n");
            Box::leak(header.into_boxed_str())
        };
        let auth_header = api_key.map(|api_key| {
            let mut header = String::from("Authorization: Bearer ");
            header.push_str(api_key);
            header.push_str("\r\n");
            &*Box::leak(header.into_boxed_str())
        });
        let server_name = (&*static_endpoint).try_into()?;
        let port = port.unwrap_or_else(|| if tls { 443 } else { 80 });
        let sock_address = format!("{}:{}", static_endpoint, port);
        Ok(Self {
            host: static_host,
            endpoint: static_endpoint,
            tls,
            host_header,
            auth_header,
            sock_address,
            server_name,
            auth_keys,
            provider_auth_keys,
        })
    }
}

impl Drop for OpenAIProvider {
    fn drop(&mut self) {
        unsafe {
            drop(Box::from_raw(self.host as *const str as *mut str));
            drop(Box::from_raw(self.endpoint as *const str as *mut str));
            drop(Box::from_raw(self.host_header as *const str as *mut str));
            if let Some(auth_header) = self.auth_header {
                drop(Box::from_raw(auth_header as *const str as *mut str));
            }
        }
    }
}

impl Provider for OpenAIProvider {
    fn kind(&self) -> Type {
        Type::OpenAI
    }

    fn host(&self) -> &str {
        self.host
    }

    fn endpoint(&self) -> &str {
        self.endpoint
    }

    fn server_name(&self) -> rustls_pki_types::ServerName<'static> {
        self.server_name.clone()
    }

    fn sock_address(&self) -> &str {
        &self.sock_address
    }

    fn host_header(&self) -> &'static str {
        self.host_header
    }

    fn auth_query_key(&self) -> Option<&'static str> {
        None
    }

    fn auth_header(&self) -> Option<&'static str> {
        self.auth_header
    }

    fn auth_header_key(&self) -> Option<&'static str> {
        Some(http::HEADER_AUTHORIZATION)
    }

    fn authenticate(&self, header: Option<&[u8]>) -> Result<(), AuthenticationError> {
        if self.auth_keys.is_empty() && self.provider_auth_keys.is_none() {
            return Ok(());
        }
        let Some(header) = header else {
            return Err(AuthenticationError);
        };
        let Ok(header_str) = std::str::from_utf8(header) else {
            #[cfg(debug_assertions)]
            log::error!(provider = "openai", header:serde = header.to_vec(); "invalid_authentication_header");
            return Err(AuthenticationError);
        };
        #[cfg(debug_assertions)]
        log::info!(provider = "openai", header = header_str; "authentication");
        if !http::is_header(header_str, http::HEADER_AUTHORIZATION) {
            return Err(AuthenticationError);
        }
        let Some(key) = header_str[http::HEADER_AUTHORIZATION.len()..].strip_prefix("Bearer ")
        else {
            return Err(AuthenticationError);
        };
        self.auth_keys
            .iter()
            .chain(self.provider_auth_keys.iter().flatten())
            .find(|&k| k == key.trim())
            .map(|_| ())
            .ok_or(AuthenticationError)
    }

    fn rewrite_first_header_block(&self, _: &[u8]) -> Option<Vec<u8>> {
        None
    }

    fn tls(&self) -> bool {
        self.tls
    }
}

pub struct GeminiProvider {
    host: &'static str,
    endpoint: &'static str,
    tls: bool,
    api_key: String,
    host_header: &'static str,
    sock_address: String,
    server_name: rustls_pki_types::ServerName<'static>,
    auth_keys: Arc<Vec<String>>,
    provider_auth_keys: Option<Vec<String>>,
}

impl GeminiProvider {
    pub fn new(
        host: &str,
        endpoint: &str,
        port: Option<u16>,
        tls: bool,
        api_key: Option<&str>,
        auth_keys: Arc<Vec<String>>,
        provider_auth_keys: Option<Vec<String>>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let Some(api_key) = api_key else {
            return Err("gemini: missing `api_key`".into());
        };
        let static_host = Box::leak(host.to_string().into_boxed_str());
        let static_endpoint = Box::leak(endpoint.to_string().into_boxed_str());
        let host_header = {
            let mut header = String::from("Host: ");
            header.push_str(static_endpoint);
            header.push_str("\r\n");
            Box::leak(header.into_boxed_str())
        };
        let server_name = (&*static_endpoint).try_into()?;
        let port = port.unwrap_or_else(|| if tls { 443 } else { 80 });
        let sock_address = format!("{}:{}", static_endpoint, port);
        Ok(GeminiProvider {
            host: static_host,
            endpoint: static_endpoint,
            tls,
            api_key: api_key.to_string(),
            host_header,
            sock_address,
            server_name,
            auth_keys,
            provider_auth_keys,
        })
    }
}

impl Drop for GeminiProvider {
    fn drop(&mut self) {
        unsafe {
            drop(Box::from_raw(self.host as *const str as *mut str));
            drop(Box::from_raw(self.endpoint as *const str as *mut str));
            drop(Box::from_raw(self.host_header as *const str as *mut str));
        }
    }
}

impl Provider for GeminiProvider {
    fn kind(&self) -> Type {
        Type::Gemini
    }

    fn host(&self) -> &str {
        self.host
    }

    fn endpoint(&self) -> &str {
        self.endpoint
    }

    fn server_name(&self) -> rustls_pki_types::ServerName<'static> {
        self.server_name.clone()
    }

    fn sock_address(&self) -> &str {
        &self.sock_address
    }

    fn host_header(&self) -> &'static str {
        self.host_header
    }

    fn auth_query_key(&self) -> Option<&'static str> {
        Some(http::QUERY_KEY_KEY)
    }

    fn auth_header(&self) -> Option<&'static str> {
        None
    }

    fn auth_header_key(&self) -> Option<&'static str> {
        None
    }

    fn authenticate(&self, key: Option<&[u8]>) -> Result<(), AuthenticationError> {
        if self.auth_keys.is_empty() && self.provider_auth_keys.is_none() {
            return Ok(());
        }
        let Some(key) = key else {
            return Err(AuthenticationError);
        };
        let Ok(key_str) = std::str::from_utf8(key) else {
            #[cfg(debug_assertions)]
            log::error!(provider = "gemini", key:serde = key.to_vec(); "invalid_authentication_key");
            return Err(AuthenticationError);
        };
        #[cfg(debug_assertions)]
        log::info!(provider = "gemini", key = key_str; "authentication");
        self.auth_keys
            .iter()
            .chain(self.provider_auth_keys.iter().flatten())
            .find(|&k| k == key_str.trim())
            .map(|_| ())
            .ok_or(AuthenticationError)
    }

    fn rewrite_first_header_block(&self, block: &[u8]) -> Option<Vec<u8>> {
        let Ok(block_str) = std::str::from_utf8(block) else {
            return None;
        };
        let Some(query_range) = http::get_auth_query_range(block_str, http::QUERY_KEY_KEY) else {
            return None;
        };
        let mut rewritten = Vec::with_capacity(block.len());
        rewritten.extend_from_slice(&block[..query_range.start]);
        rewritten.extend_from_slice(self.api_key.as_bytes());
        rewritten.extend_from_slice(&block[query_range.end..]);
        Some(rewritten)
    }

    fn tls(&self) -> bool {
        self.tls
    }
}

pub struct AnthropicProvider {
    host: &'static str,
    endpoint: &'static str,
    tls: bool,
    host_header: &'static str,
    auth_header: &'static str,
    sock_address: String,
    server_name: rustls_pki_types::ServerName<'static>,
    auth_keys: Arc<Vec<String>>,
    provider_auth_keys: Option<Vec<String>>,
}

impl AnthropicProvider {
    pub fn new(
        host: &str,
        endpoint: &str,
        port: Option<u16>,
        tls: bool,
        api_key: Option<&str>,
        auth_keys: Arc<Vec<String>>,
        provider_auth_keys: Option<Vec<String>>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let Some(api_key) = api_key else {
            return Err("anthropic: missing `api_key`".into());
        };
        let static_host = Box::leak(host.to_string().into_boxed_str());
        let static_endpoint = Box::leak(endpoint.to_string().into_boxed_str());
        let host_header = {
            let mut header = String::from("Host: ");
            header.push_str(static_endpoint);
            header.push_str("\r\n");
            Box::leak(header.into_boxed_str())
        };
        let auth_header = {
            let mut header = String::from("X-API-Key: ");
            header.push_str(api_key);
            header.push_str("\r\n");
            Box::leak(header.into_boxed_str())
        };
        let server_name = (&*static_endpoint).try_into()?;
        let port = port.unwrap_or_else(|| if tls { 443 } else { 80 });
        let sock_address = format!("{}:{}", static_endpoint, port);
        Ok(Self {
            host: static_host,
            endpoint: static_endpoint,
            tls,
            host_header,
            auth_header,
            sock_address,
            server_name,
            auth_keys,
            provider_auth_keys,
        })
    }
}

impl Drop for AnthropicProvider {
    fn drop(&mut self) {
        unsafe {
            drop(Box::from_raw(self.host as *const str as *mut str));
            drop(Box::from_raw(self.endpoint as *const str as *mut str));
            drop(Box::from_raw(self.host_header as *const str as *mut str));
            drop(Box::from_raw(self.auth_header as *const str as *mut str));
        }
    }
}

impl Provider for AnthropicProvider {
    fn kind(&self) -> Type {
        Type::Anthropic
    }

    fn host(&self) -> &str {
        self.host
    }

    fn endpoint(&self) -> &str {
        self.endpoint
    }

    fn server_name(&self) -> rustls_pki_types::ServerName<'static> {
        self.server_name.clone()
    }

    fn sock_address(&self) -> &str {
        &self.sock_address
    }

    fn host_header(&self) -> &'static str {
        self.host_header
    }

    fn auth_query_key(&self) -> Option<&'static str> {
        None
    }

    fn auth_header(&self) -> Option<&'static str> {
        Some(self.auth_header)
    }

    fn auth_header_key(&self) -> Option<&'static str> {
        Some(http::HEADER_X_API_KEY)
    }

    fn authenticate(&self, header: Option<&[u8]>) -> Result<(), AuthenticationError> {
        if self.auth_keys.is_empty() && self.provider_auth_keys.is_none() {
            return Ok(());
        }
        let Some(header) = header else {
            return Err(AuthenticationError);
        };
        let Ok(header_str) = std::str::from_utf8(header) else {
            #[cfg(debug_assertions)]
            log::error!(provider = "anthropic", header:serde = header.to_vec(); "invalid_authentication_header");
            return Err(AuthenticationError);
        };
        #[cfg(debug_assertions)]
        log::info!(provider = "anthropic", header = header_str; "authentication");
        if !http::is_header(header_str, http::HEADER_X_API_KEY) {
            return Err(AuthenticationError);
        }
        let key = &header_str[http::HEADER_X_API_KEY.len()..];
        self.auth_keys
            .iter()
            .chain(self.provider_auth_keys.iter().flatten())
            .find(|&k| k == key.trim())
            .map(|_| ())
            .ok_or(AuthenticationError)
    }

    fn rewrite_first_header_block(&self, _: &[u8]) -> Option<Vec<u8>> {
        None
    }

    fn tls(&self) -> bool {
        self.tls
    }
}
