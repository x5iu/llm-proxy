pub mod conn;
pub mod executor;
pub mod http;
pub mod provider;

use std::fs;
use std::io;
use std::path::Path;
use std::ptr;
use std::sync::atomic::{AtomicPtr, Ordering};
use std::sync::Arc;
use std::time::SystemTime;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls_pki_types::pem::PemObject;

use structured_logger::json::new_writer;

use provider::{new_provider, Provider};

static PROG_ARGS: AtomicPtr<Arc<ProgArgs>> = AtomicPtr::new(ptr::null_mut());

fn args() -> Arc<ProgArgs> {
    unsafe { Arc::clone(&*PROG_ARGS.load(std::sync::atomic::Ordering::SeqCst)) }
}

#[derive(serde::Deserialize)]
struct Config<'a> {
    cert_file: &'a str,
    private_key_file: &'a str,
    providers: Vec<ProviderConfig<'a>>,
    auth_keys: Vec<String>,
}

#[derive(serde::Deserialize)]
struct ProviderConfig<'a> {
    #[serde(rename = "type")]
    kind: &'a str,
    host: &'a str,
    endpoint: &'a str,
    api_key: &'a str,
}

pub fn load_config(
    path: impl AsRef<Path>,
) -> Result<*mut Arc<ProgArgs>, Box<dyn std::error::Error>> {
    let metadata = fs::metadata(&path)?;
    let config_str = fs::read_to_string(&path)?;
    let config: Config = serde_yaml::from_str(&config_str)?;
    structured_logger::Builder::with_level("INFO")
        .with_target_writer("gpt*", new_writer(io::stderr()))
        .init();
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
        config: Config,
        last_modified: SystemTime,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let certs =
            CertificateDer::pem_file_iter(config.cert_file)?.collect::<Result<Vec<_>, _>>()?;
        let private_key = PrivateKeyDer::from_pem_file(config.private_key_file)?;
        let tls_server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, private_key)?;
        let auth_keys = Arc::new(config.auth_keys);
        let mut providers = Vec::new();
        for provider in config.providers {
            providers.push(new_provider(
                provider.kind,
                provider.host,
                provider.endpoint,
                provider.api_key,
                Arc::clone(&auth_keys),
            )?);
        }
        Ok(Self {
            tls_server_config: Arc::new(tls_server_config),
            providers,
            last_modified,
        })
    }

    pub fn select_provider(&self, host: &str) -> Option<&dyn Provider> {
        self.providers
            .iter()
            .map(|provider| &**provider)
            .find(|provider| provider.host() == host)
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
