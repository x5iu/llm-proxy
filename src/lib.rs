pub mod conn;
pub mod executor;
pub mod http;
pub mod provider;

use std::fmt::Formatter;
use std::fs;
use std::io;
use std::ops::Deref;
use std::path::Path;
use std::ptr;
use std::sync::atomic::{AtomicPtr, Ordering};
use std::sync::{Arc, Once};
use std::time::SystemTime;

use rand::seq::IndexedRandom;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls_pki_types::pem::PemObject;
use serde::de::SeqAccess;
use serde::Deserializer;
use structured_logger::json::new_writer;

use provider::{new_provider, Provider};

static PROG_ARGS: AtomicPtr<Arc<ProgArgs>> = AtomicPtr::new(ptr::null_mut());

fn args() -> Arc<ProgArgs> {
    unsafe { Arc::clone(&*PROG_ARGS.load(Ordering::SeqCst)) }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct Config<'a> {
    #[serde(skip_serializing)]
    cert_file: &'a str,
    #[serde(skip_serializing)]
    private_key_file: &'a str,
    providers: Vec<ProviderConfig<'a>>,
    #[serde(skip_serializing)]
    auth_keys: Option<Vec<String>>,
    health_check_interval: Option<u64>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct ProviderConfig<'a> {
    #[serde(rename = "type")]
    kind: &'a str,
    host: &'a str,
    endpoint: &'a str,
    port: Option<u16>,
    tls: Option<bool>,
    #[serde(skip_serializing)]
    #[serde(borrow)]
    api_key: Option<APIKeys<'a>>,
    #[serde(skip_serializing)]
    #[serde(borrow)]
    api_keys: Option<Vec<&'a str>>,
    #[serde(skip_serializing)]
    #[serde(rename = "auth_keys")]
    provider_auth_keys: Option<Vec<String>>,
    #[serde(rename = "health_check")]
    health_check_config: Option<provider::HealthCheckConfig>,
}

struct APIKeys<'a>(Vec<&'a str>);

impl<'a> APIKeys<'a> {
    fn pop(&mut self) -> Option<&'a str> {
        self.0.pop()
    }

    fn append(&mut self, others: Option<Vec<&'a str>>) {
        if let Some(others) = others {
            self.0.extend(others);
        }
    }
}

impl<'a> Deref for APIKeys<'a> {
    type Target = [&'a str];

    fn deref(&self) -> &Self::Target {
        self.0.as_slice()
    }
}

impl<'de: 'a, 'a> serde::Deserialize<'de> for APIKeys<'a> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct Visitor;

        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = APIKeys<'de>;

            fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
                formatter.write_str("string or array of strings")
            }

            fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(APIKeys(vec![v]))
            }

            fn visit_seq<A>(self, seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                serde::Deserialize::deserialize(serde::de::value::SeqAccessDeserializer::new(seq))
                    .map(APIKeys)
            }
        }

        deserializer.deserialize_any(Visitor)
    }
}

pub fn load_config(
    path: impl AsRef<Path>,
) -> Result<*mut Arc<ProgArgs>, Box<dyn std::error::Error>> {
    let metadata = fs::metadata(&path)?;
    let config_str = fs::read_to_string(&path)?;
    let config: Config = serde_yaml::from_str(&config_str)?;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        structured_logger::Builder::with_level("INFO")
            .with_target_writer("llm-proxy*", new_writer(io::stderr()))
            .init();
    });
    log::info!(config:serde = config; "load_config");
    let args = ProgArgs::from_config(config, metadata.modified()?)?;
    Ok(PROG_ARGS.swap(Box::into_raw(Box::new(Arc::new(args))), Ordering::SeqCst))
}

pub fn update_config(path: impl AsRef<Path>) -> Result<(), Box<dyn std::error::Error>> {
    let metadata = fs::metadata(&path)?;
    if metadata.modified()? > args().last_modified {
        unsafe {
            let ori_ptr = load_config(path)?;
            drop(Box::from_raw(ori_ptr));
        }
    }
    Ok(())
}

pub fn force_update_config(path: impl AsRef<Path>) -> Result<(), Box<dyn std::error::Error>> {
    unsafe {
        let ori_ptr = load_config(path)?;
        drop(Box::from_raw(ori_ptr));
        Ok(())
    }
}

pub struct ProgArgs {
    tls_server_config: Arc<rustls::ServerConfig>,
    providers: Vec<Box<dyn Provider>>,
    health_check_interval: u64,
    last_modified: SystemTime,
}

impl ProgArgs {
    fn from_config(
        mut config: Config,
        last_modified: SystemTime,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let certs =
            CertificateDer::pem_file_iter(config.cert_file)?.collect::<Result<Vec<_>, _>>()?;
        let private_key = PrivateKeyDer::from_pem_file(config.private_key_file)?;
        let mut tls_server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, private_key)?;
        tls_server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let auth_keys = Arc::new(config.auth_keys.unwrap_or_else(Vec::new));
        let mut providers = Vec::new();
        config.providers.sort_by_key(|provider| provider.host);
        for mut provider in config.providers {
            provider
                .api_key
                .as_mut()
                .map(|v| v.append(provider.api_keys));
            if let Some(api_keys @ [_, _, ..]) = provider.api_key.as_deref() {
                debug_assert!(api_keys.len() > 1);
                let health_check_config = provider.health_check_config.take();
                for api_key in api_keys {
                    providers.push(new_provider(
                        provider.kind,
                        provider.host,
                        provider.endpoint,
                        provider.port,
                        provider.tls.unwrap_or(true),
                        Some(api_key),
                        Arc::clone(&auth_keys),
                        provider.provider_auth_keys.clone(),
                        health_check_config.clone(),
                    )?);
                }
            } else {
                providers.push(new_provider(
                    provider.kind,
                    provider.host,
                    provider.endpoint,
                    provider.port,
                    provider.tls.unwrap_or(true),
                    provider.api_key.map(|mut v| v.pop()).flatten(),
                    Arc::clone(&auth_keys),
                    provider.provider_auth_keys.clone(),
                    provider.health_check_config.take(),
                )?);
            }
        }
        Ok(Self {
            tls_server_config: Arc::new(tls_server_config),
            providers,
            health_check_interval: config.health_check_interval.unwrap_or(60),
            last_modified,
        })
    }

    pub fn select_provider(&self, host: &str) -> Option<&dyn Provider> {
        let Some(start) = self.providers.iter().enumerate().find_map(|(i, provider)| {
            if provider.host() == host {
                Some(i)
            } else {
                None
            }
        }) else {
            return None;
        };
        let Some(end) = self
            .providers
            .iter()
            .rev()
            .enumerate()
            .map(|(i, provider)| (self.providers.len() - i - 1, provider))
            .find_map(|(i, provider)| {
                if provider.is_healthy() && provider.host() == host {
                    Some(i)
                } else {
                    None
                }
            })
        else {
            return None;
        };
        if start == end {
            return Some(&*self.providers[start]);
        }
        self.providers[start..=end]
            .choose(&mut rand::rng())
            .map(|provider| &**provider)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("IO error: {0}")]
    IO(
        #[source]
        #[from]
        io::Error,
    ),

    #[error("TLS error: {0}")]
    TLS(
        #[source]
        #[from]
        rustls::Error,
    ),

    #[error("h2 error: {0}")]
    H2(
        #[source]
        #[from]
        h2::Error,
    ),

    #[error("Header too large")]
    HeaderTooLarge,

    #[error("Invalid header")]
    InvalidHeader,
}
