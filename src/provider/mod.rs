use std::fmt;
use std::sync::Arc;

use crate::http;

pub fn new_provider(
    kind: &str,
    host: &str,
    endpoint: &str,
    api_key: &str,
    auth_keys: Arc<Vec<String>>,
    provider_auth_keys: Option<Vec<String>>,
) -> Result<Box<dyn Provider>, Box<dyn std::error::Error>> {
    match kind {
        "openai" => Ok(Box::new(OpenAIProvider::new(
            host,
            endpoint,
            api_key,
            auth_keys,
            provider_auth_keys,
        )?)),
        _ => Err(format!("Unsupported provider type: {:?}", kind).into()),
    }
}

pub enum Type {
    OpenAI,
    Anthropic,
}

impl fmt::Display for Type {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Type::OpenAI => write!(f, "openai"),
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
    fn auth_header(&self) -> &'static str;
    fn auth_header_key(&self) -> &'static str;
    fn authenticate(&self, header: Option<&[u8]>) -> Result<(), AuthenticationError>;
}

#[derive(Debug, thiserror::Error)]
#[error("Authentication error")]
pub struct AuthenticationError;

pub struct OpenAIProvider {
    host: &'static str,
    endpoint: &'static str,
    host_header: &'static str,
    auth_header: &'static str,
    sock_address: String,
    server_name: rustls_pki_types::ServerName<'static>,
    auth_keys: Arc<Vec<String>>,
    provider_auth_keys: Option<Vec<String>>,
}

impl OpenAIProvider {
    pub fn new(
        host: &str,
        endpoint: &str,
        api_key: &str,
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
        let auth_header = {
            let mut header = String::from("Authorization: Bearer ");
            header.push_str(api_key);
            header.push_str("\r\n");
            Box::leak(header.into_boxed_str())
        };
        let server_name = (&*static_endpoint).try_into()?;
        let sock_address = format!("{}:443", static_endpoint);
        Ok(Self {
            host: static_host,
            endpoint: static_endpoint,
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
            drop(Box::from_raw(self.auth_header as *const str as *mut str));
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

    fn auth_header(&self) -> &'static str {
        self.auth_header
    }

    fn auth_header_key(&self) -> &'static str {
        http::HEADER_AUTHORIZATION
    }

    fn authenticate(&self, header: Option<&[u8]>) -> Result<(), AuthenticationError> {
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
}
