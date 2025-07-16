use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::http;

pub fn new_provider(
    kind: &str,
    host: &str,
    endpoint: &str,
    port: Option<u16>,
    tls: bool,
    weight: f64,
    api_key: Option<&str>,
    auth_keys: Arc<Vec<String>>,
    provider_auth_keys: Option<Vec<String>>,
    health_check_config: Option<HealthCheckConfig>,
) -> Result<Box<dyn Provider>, Box<dyn std::error::Error>> {
    match kind {
        "openai" => Ok(Box::new(OpenAIProvider::new(
            host,
            endpoint,
            port,
            tls,
            weight,
            api_key,
            auth_keys,
            provider_auth_keys,
            health_check_config,
        )?)),
        "gemini" => Ok(Box::new(GeminiProvider::new(
            host,
            endpoint,
            port,
            tls,
            weight,
            api_key,
            auth_keys,
            provider_auth_keys,
            health_check_config,
        )?)),
        "anthropic" => Ok(Box::new(AnthropicProvider::new(
            host,
            endpoint,
            port,
            tls,
            weight,
            api_key,
            auth_keys,
            provider_auth_keys,
            health_check_config,
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

pub trait Provider: Send + Sync {
    fn kind(&self) -> Type;
    fn host(&self) -> &str;
    fn api_key(&self) -> Option<&str>;
    fn endpoint(&self) -> &str;
    fn server_name(&self) -> rustls_pki_types::ServerName<'static>;
    fn sock_address(&self) -> &str;
    fn host_header(&self) -> &'static str;
    fn auth_query_key(&self) -> Option<&'static str>;
    fn auth_header(&self) -> Option<&'static str>;
    fn auth_header_key(&self) -> Option<&'static str>;
    fn has_auth_keys(&self) -> bool;
    fn authenticate(&self, auth: Option<&[u8]>) -> Result<(), AuthenticationError>;
    fn authenticate_key(&self, key: &str) -> Result<(), AuthenticationError>;
    fn rewrite_first_header_block(&self, block: &[u8]) -> Option<Vec<u8>>;
    fn weight(&self) -> f64;

    fn tls(&self) -> bool {
        true
    }

    fn is_healthy(&self) -> bool;
    fn set_healthy(&self, healthy: bool);

    fn health_check<'a: 'stream, 'stream>(
        &'a self,
        #[allow(unused)] stream: &'stream mut dyn AsyncReadWrite,
    ) -> Pin<Box<dyn Future<Output=Result<(), Box<dyn std::error::Error>>> + Send + 'stream>>
    {
        Box::pin(async move { Ok(()) })
    }
}

pub trait AsyncReadWrite: AsyncRead + AsyncWrite + Unpin + Send + Sync {}

impl<T> AsyncReadWrite for T where T: AsyncRead + AsyncWrite + Unpin + Send + Sync {}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct HealthCheckConfig {
    method: Option<String>,
    path: String,
    body: Option<String>,
    headers: Option<Vec<String>>,
}

#[derive(Debug, thiserror::Error)]
#[error("Authentication error")]
pub struct AuthenticationError;

pub struct OpenAIProvider {
    host: &'static str,
    api_key: Option<String>,
    endpoint: &'static str,
    tls: bool,
    weight: f64,
    host_header: &'static str,
    auth_header: Option<&'static str>,
    sock_address: String,
    server_name: rustls_pki_types::ServerName<'static>,
    auth_keys: Arc<Vec<String>>,
    provider_auth_keys: Option<Vec<String>>,
    is_healthy: AtomicBool,
    health_check_config: Option<HealthCheckConfig>,
}

impl OpenAIProvider {
    pub fn new(
        host: &str,
        endpoint: &str,
        port: Option<u16>,
        tls: bool,
        weight: f64,
        api_key: Option<&str>,
        auth_keys: Arc<Vec<String>>,
        provider_auth_keys: Option<Vec<String>>,
        health_check_config: Option<HealthCheckConfig>,
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
            let mut header = String::from(http::HEADER_AUTHORIZATION);
            header.push_str("Bearer ");
            header.push_str(api_key);
            header.push_str("\r\n");
            &*Box::leak(header.into_boxed_str())
        });
        let server_name = (&*static_endpoint).try_into()?;
        let port = port.unwrap_or_else(|| if tls { 443 } else { 80 });
        let sock_address = format!("{}:{}", static_endpoint, port);
        Ok(Self {
            host: static_host,
            api_key: api_key.map(ToString::to_string),
            endpoint: static_endpoint,
            tls,
            weight,
            host_header,
            auth_header,
            sock_address,
            server_name,
            auth_keys,
            provider_auth_keys,
            is_healthy: AtomicBool::new(true),
            health_check_config,
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

    fn api_key(&self) -> Option<&str> {
        self.api_key.as_deref()
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

    fn has_auth_keys(&self) -> bool {
        self.auth_keys.len() > 0 || self.provider_auth_keys.is_some()
    }

    fn weight(&self) -> f64 {
        self.weight
    }

    fn authenticate(&self, header: Option<&[u8]>) -> Result<(), AuthenticationError> {
        if !self.has_auth_keys() {
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
        self.authenticate_key(&header_str[http::HEADER_AUTHORIZATION.len()..])
    }

    fn authenticate_key(&self, key: &str) -> Result<(), AuthenticationError> {
        self.auth_keys
            .iter()
            .chain(self.provider_auth_keys.iter().flatten())
            .find(|&k| k == key.trim_start_matches("Bearer ").trim())
            .map(|_| ())
            .ok_or(AuthenticationError)
    }

    fn rewrite_first_header_block(&self, _: &[u8]) -> Option<Vec<u8>> {
        None
    }

    fn tls(&self) -> bool {
        self.tls
    }

    fn is_healthy(&self) -> bool {
        self.is_healthy.load(Ordering::SeqCst)
    }

    fn set_healthy(&self, healthy: bool) {
        self.is_healthy.store(healthy, Ordering::SeqCst)
    }

    fn health_check<'a: 'stream, 'stream>(
        &'a self,
        stream: &'stream mut dyn AsyncReadWrite,
    ) -> Pin<Box<dyn Future<Output=Result<(), Box<dyn std::error::Error>>> + Send + 'stream>>
    {
        if let Some(ref cfg) = self.health_check_config {
            Box::pin(health_check(
                stream,
                self.endpoint().as_bytes(),
                cfg.method.as_ref().map(|v| v.as_bytes()).unwrap_or(b"GET"),
                cfg.path.as_bytes(),
                self.auth_header().map(|v| v.as_bytes()),
                cfg.headers
                    .as_deref()
                    .map(|v| v.iter().map(|x| x.trim().as_bytes())),
                cfg.body.as_ref().map(|v| v.as_bytes()).unwrap_or_default(),
            ))
        } else {
            Box::pin(async { Ok(()) })
        }
    }
}

pub struct GeminiProvider {
    host: &'static str,
    endpoint: &'static str,
    tls: bool,
    weight: f64,
    api_key: String,
    host_header: &'static str,
    auth_header: &'static str,
    sock_address: String,
    server_name: rustls_pki_types::ServerName<'static>,
    auth_keys: Arc<Vec<String>>,
    provider_auth_keys: Option<Vec<String>>,
    is_healthy: AtomicBool,
    health_check_config: Option<HealthCheckConfig>,
}

impl GeminiProvider {
    pub fn new(
        host: &str,
        endpoint: &str,
        port: Option<u16>,
        tls: bool,
        weight: f64,
        api_key: Option<&str>,
        auth_keys: Arc<Vec<String>>,
        provider_auth_keys: Option<Vec<String>>,
        health_check_config: Option<HealthCheckConfig>,
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
        let auth_header = {
            let mut header = String::from(http::HEADER_X_GOOG_API_KEY);
            header.push_str(api_key);
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
            weight,
            api_key: api_key.to_string(),
            host_header,
            auth_header,
            sock_address,
            server_name,
            auth_keys,
            provider_auth_keys,
            is_healthy: AtomicBool::new(true),
            health_check_config,
        })
    }
}

impl Drop for GeminiProvider {
    fn drop(&mut self) {
        unsafe {
            drop(Box::from_raw(self.host as *const str as *mut str));
            drop(Box::from_raw(self.endpoint as *const str as *mut str));
            drop(Box::from_raw(self.host_header as *const str as *mut str));
            drop(Box::from_raw(self.auth_header as *const str as *mut str));
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

    fn api_key(&self) -> Option<&str> {
        Some(self.api_key.as_str())
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
        Some(self.auth_header)
    }

    fn auth_header_key(&self) -> Option<&'static str> {
        Some(http::HEADER_X_GOOG_API_KEY)
    }

    fn has_auth_keys(&self) -> bool {
        self.auth_keys.len() > 0 || self.provider_auth_keys.is_some()
    }

    fn weight(&self) -> f64 {
        self.weight
    }

    fn authenticate(&self, key: Option<&[u8]>) -> Result<(), AuthenticationError> {
        if !self.has_auth_keys() {
            return Ok(());
        }
        let Some(key) = key else {
            return Err(AuthenticationError);
        };
        let Ok(mut key_str) = std::str::from_utf8(key) else {
            #[cfg(debug_assertions)]
            log::error!(provider = "gemini", key:serde = key.to_vec(); "invalid_authentication_key");
            return Err(AuthenticationError);
        };
        #[cfg(debug_assertions)]
        log::info!(provider = "gemini", key = key_str; "authentication");
        if http::is_header(key_str, http::HEADER_X_GOOG_API_KEY) {
            key_str = &key_str[http::HEADER_X_GOOG_API_KEY.len()..];
        }
        self.authenticate_key(key_str)
    }

    fn authenticate_key(&self, key: &str) -> Result<(), AuthenticationError> {
        self.auth_keys
            .iter()
            .chain(self.provider_auth_keys.iter().flatten())
            .find(|&k| k == key.trim())
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

    fn is_healthy(&self) -> bool {
        self.is_healthy.load(Ordering::SeqCst)
    }

    fn set_healthy(&self, healthy: bool) {
        self.is_healthy.store(healthy, Ordering::SeqCst)
    }

    fn health_check<'a: 'stream, 'stream>(
        &'a self,
        stream: &'stream mut dyn AsyncReadWrite,
    ) -> Pin<Box<dyn Future<Output=Result<(), Box<dyn std::error::Error>>> + Send + 'stream>>
    {
        if let Some(ref cfg) = self.health_check_config {
            Box::pin(async move {
                let path = format!("{}?key={}", cfg.path, self.api_key);
                health_check(
                    stream,
                    self.endpoint().as_bytes(),
                    cfg.method.as_ref().map(|v| v.as_bytes()).unwrap_or(b"GET"),
                    path.as_bytes(),
                    None,
                    cfg.headers
                        .as_deref()
                        .map(|v| v.iter().map(|x| x.trim().as_bytes())),
                    cfg.body.as_ref().map(|v| v.as_bytes()).unwrap_or_default(),
                )
                    .await
            })
        } else {
            Box::pin(async move { Ok(()) })
        }
    }
}

pub struct AnthropicProvider {
    host: &'static str,
    api_key: String,
    endpoint: &'static str,
    tls: bool,
    weight: f64,
    host_header: &'static str,
    auth_header: &'static str,
    sock_address: String,
    server_name: rustls_pki_types::ServerName<'static>,
    auth_keys: Arc<Vec<String>>,
    provider_auth_keys: Option<Vec<String>>,
    is_healthy: AtomicBool,
    health_check_config: Option<HealthCheckConfig>,
}

impl AnthropicProvider {
    pub fn new(
        host: &str,
        endpoint: &str,
        port: Option<u16>,
        tls: bool,
        weight: f64,
        api_key: Option<&str>,
        auth_keys: Arc<Vec<String>>,
        provider_auth_keys: Option<Vec<String>>,
        health_check_config: Option<HealthCheckConfig>,
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
            let mut header = String::from(http::HEADER_X_API_KEY);
            header.push_str(api_key);
            header.push_str("\r\n");
            Box::leak(header.into_boxed_str())
        };
        let server_name = (&*static_endpoint).try_into()?;
        let port = port.unwrap_or_else(|| if tls { 443 } else { 80 });
        let sock_address = format!("{}:{}", static_endpoint, port);
        Ok(Self {
            host: static_host,
            api_key: api_key.to_string(),
            endpoint: static_endpoint,
            tls,
            weight,
            host_header,
            auth_header,
            sock_address,
            server_name,
            auth_keys,
            provider_auth_keys,
            is_healthy: AtomicBool::new(true),
            health_check_config,
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

    fn api_key(&self) -> Option<&str> {
        Some(self.api_key.as_str())
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

    fn has_auth_keys(&self) -> bool {
        self.auth_keys.len() > 0 || self.provider_auth_keys.is_some()
    }

    fn weight(&self) -> f64 {
        self.weight
    }

    fn authenticate(&self, header: Option<&[u8]>) -> Result<(), AuthenticationError> {
        if !self.has_auth_keys() {
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
        self.authenticate_key(&header_str[http::HEADER_X_API_KEY.len()..])
    }

    fn authenticate_key(&self, key: &str) -> Result<(), AuthenticationError> {
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

    fn is_healthy(&self) -> bool {
        self.is_healthy.load(Ordering::SeqCst)
    }

    fn set_healthy(&self, healthy: bool) {
        self.is_healthy.store(healthy, Ordering::SeqCst)
    }

    fn health_check<'a: 'stream, 'stream>(
        &'a self,
        stream: &'stream mut dyn AsyncReadWrite,
    ) -> Pin<Box<dyn Future<Output=Result<(), Box<dyn std::error::Error>>> + Send + 'stream>>
    {
        if let Some(ref cfg) = self.health_check_config {
            Box::pin(health_check(
                stream,
                self.endpoint().as_bytes(),
                cfg.method.as_ref().map(|v| v.as_bytes()).unwrap_or(b"GET"),
                cfg.path.as_bytes(),
                self.auth_header().map(|v| v.as_bytes()),
                cfg.headers
                    .as_deref()
                    .map(|v| v.iter().map(|x| x.trim().as_bytes())),
                cfg.body.as_ref().map(|v| v.as_bytes()).unwrap_or_default(),
            ))
        } else {
            Box::pin(async move { Ok(()) })
        }
    }
}

async fn health_check(
    stream: &mut dyn AsyncReadWrite,
    endpoint: &[u8],
    method: &[u8],
    path: &[u8],
    authorization: Option<&[u8]>,
    headers: Option<impl Iterator<Item=&[u8]>>,
    req: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    stream.write_all(method).await?;
    stream.write_all(b" ").await?;
    stream.write_all(path).await?;
    stream.write_all(b" HTTP/1.1\r\n").await?;
    stream.write_all(b"Host: ").await?;
    stream.write_all(endpoint).await?;
    stream.write_all(b"\r\n").await?;
    stream.write_all(b"Connection: keep-alive\r\n").await?;
    stream.write_all(b"Content-Length: ").await?;
    stream.write_all(req.len().to_string().as_bytes()).await?;
    stream.write_all(b"\r\n").await?;
    if let Some(authorization) = authorization {
        stream.write_all(authorization).await?;
    }
    if let Some(headers) = headers {
        for header in headers {
            stream.write_all(header).await?;
            stream.write_all(b"\r\n").await?;
        }
    }
    stream.write_all(b"\r\n").await?;
    stream.write_all(req).await?;
    let response = http::Response::new(stream).await?;
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut parser = httparse::Response::new(&mut headers);
    parser.parse(response.payload.block())?;
    let Some(http_status_code) = parser.code else {
        return Err("unknown http status code".into());
    };
    if http_status_code / 100 != 2 {
        return Err(format!("invalid http status code: {}", http_status_code).into());
    }
    Ok(())
}
