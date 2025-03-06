pub mod conn;
pub mod executor;
pub mod http;

use std::fs;
use std::path::Path;
use std::ptr;
use std::sync::atomic::{AtomicPtr, Ordering};
use std::sync::Arc;
use std::time::SystemTime;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls_pki_types::pem::PemObject;

static PROG_ARGS: AtomicPtr<Arc<ProgArgs>> = AtomicPtr::new(ptr::null_mut());

fn args() -> Arc<ProgArgs> {
    unsafe { Arc::clone(&*PROG_ARGS.load(std::sync::atomic::Ordering::SeqCst)) }
}

#[derive(serde::Deserialize)]
struct Config<'a> {
    cert_file: &'a str,
    private_key_file: &'a str,
    host: &'a str,
    api_key: &'a str,
    auth_keys: Vec<String>,
}

pub fn load_config(
    path: impl AsRef<Path>,
) -> Result<*mut Arc<ProgArgs>, Box<dyn std::error::Error>> {
    let metadata = fs::metadata(&path)?;
    let config_str = fs::read_to_string(&path)?;
    let config: Config = serde_yaml::from_str(&config_str)?;
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
    tls_server_name: rustls_pki_types::ServerName<'static>,
    addr: String,
    host_header: &'static str,
    auth_header: &'static str,
    auth_keys: Vec<String>,
    last_modified: SystemTime,
}

impl Drop for ProgArgs {
    fn drop(&mut self) {
        unsafe {
            drop(Box::from_raw(self.host_header as *const str as *mut str));
            drop(Box::from_raw(self.auth_header as *const str as *mut str));
        }
    }
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
        let mut addr = String::from(config.host);
        addr.push_str(":443");
        let mut host_header = String::from("Host: ");
        host_header.push_str(config.host);
        host_header.push_str("\r\n");
        let mut auth_header = String::from("Authorization: Bearer ");
        auth_header.push_str(config.api_key);
        auth_header.push_str("\r\n");
        Ok(Self {
            tls_server_config: Arc::new(tls_server_config),
            tls_server_name: config.host.to_string().try_into()?,
            addr,
            host_header: Box::leak(host_header.into_boxed_str()),
            auth_header: Box::leak(auth_header.into_boxed_str()),
            auth_keys: config.auth_keys,
            last_modified,
        })
    }

    pub fn is_valid_key(&self, header: Option<&[u8]>) -> bool {
        let Some(header) = header else {
            return false;
        };
        let Ok(header_str) = std::str::from_utf8(header) else {
            return false;
        };
        if !http::is_header(header_str, http::HEADER_AUTHORIZATION) {
            return false;
        }
        let Some(key) = header_str[http::HEADER_AUTHORIZATION.len()..].strip_prefix("Bearer ")
        else {
            return false;
        };
        self.auth_keys.iter().any(|k| k == key.trim())
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
