pub mod conn;
pub mod executor;
pub mod http;
pub mod provider;

use std::fs;
use std::io;
use std::path::Path;
use std::ptr;
use std::sync::atomic::{AtomicPtr, Ordering};
use std::sync::{Arc, Once};
use std::time::SystemTime;

use rand::seq::IndexedRandom;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls_pki_types::pem::PemObject;

use structured_logger::json::new_writer;

use provider::{new_provider, Provider};

static PROG_ARGS: AtomicPtr<Arc<ProgArgs>> = AtomicPtr::new(ptr::null_mut());

fn args() -> Arc<ProgArgs> {
    unsafe { Arc::clone(&*PROG_ARGS.load(std::sync::atomic::Ordering::SeqCst)) }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct Config<'a> {
    #[serde(skip_serializing)]
    cert_file: &'a str,
    #[serde(skip_serializing)]
    private_key_file: &'a str,
    providers: Vec<ProviderConfig<'a>>,
    #[serde(skip_serializing)]
    auth_keys: Vec<String>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct ProviderConfig<'a> {
    #[serde(rename = "type")]
    kind: &'a str,
    host: &'a str,
    endpoint: &'a str,
    #[serde(skip_serializing)]
    api_key: &'a str,
    #[serde(skip_serializing)]
    #[serde(rename = "auth_keys")]
    provider_auth_keys: Option<Vec<String>>,
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
            .with_target_writer("gpt*", new_writer(io::stderr()))
            .init();
    });
    log::info!(config:serde = config; "config loaded");
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

pub struct ProgArgs {
    tls_server_config: Arc<rustls::ServerConfig>,
    providers: Vec<Box<dyn Provider>>,
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
        // Currently gpt only supports HTTP/1.1 protocol
        tls_server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let auth_keys = Arc::new(config.auth_keys);
        let mut providers = Vec::new();
        config.providers.sort_by_key(|provider| provider.host);
        for provider in config.providers {
            providers.push(new_provider(
                provider.kind,
                provider.host,
                provider.endpoint,
                provider.api_key,
                Arc::clone(&auth_keys),
                provider.provider_auth_keys,
            )?);
        }
        Ok(Self {
            tls_server_config: Arc::new(tls_server_config),
            providers,
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
                if provider.host() == host {
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
        std::io::Error,
    ),

    #[error("TLS error: {0}")]
    TLS(
        #[source]
        #[from]
        rustls::Error,
    ),

    #[error("Header too large")]
    HeaderTooLarge,

    #[error("Invalid header")]
    InvalidHeader,
}
