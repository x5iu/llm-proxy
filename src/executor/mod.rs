use std::io;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use crossbeam::deque::Injector;

use crate::conn::{Conn, Pool, ProxyError};

pub struct Executor {
    conn_injector: Arc<Injector<Conn>>,
}

impl Executor {
    pub fn new() -> Self {
        Executor {
            conn_injector: Arc::new(Injector::new()),
        }
    }

    pub fn run_health_check(&self) {
        let mut pool = Pool::new(Arc::clone(&self.conn_injector));
        tokio::spawn(async move {
            loop {
                let p = crate::program();
                for provider in p.read().await.providers.iter() {
                    let provider_api_key = || {
                        provider
                            .api_key()
                            .map(|k| {
                                if let (Some(prefix), Some(suffix)) =
                                    (k.get(..3), k.get(k.len() - 4..))
                                {
                                    Some(format!("{}...{}", prefix, suffix))
                                } else {
                                    None
                                }
                            })
                            .flatten()
                    };
                    let fut = async {
                        let Ok(mut conn) = pool.get_outgoing_conn(&**provider).await else {
                            provider.set_healthy(false);
                            return;
                        };
                        if let Err(e) = provider.health_check(&mut conn).await {
                            log::warn!(provider = provider.host(), api_key = provider_api_key(), error = e.to_string(); "health_check_error");
                            provider.set_healthy(false);
                        } else {
                            provider.set_healthy(true);
                        }
                        pool.add(conn);
                    };
                    if tokio::time::timeout(Duration::from_secs(30), fut)
                        .await
                        .is_err()
                    {
                        log::warn!(provider = provider.host(), api_key = provider_api_key(); "health_check_timeout");
                        provider.set_healthy(false);
                    }
                }
                tokio::time::sleep(Duration::from_secs(p.read().await.health_check_interval)).await;
            }
        });
    }

    pub async fn execute(&self, stream: TcpStream) {
        let p = crate::program();
        let tls_acceptor =
            tokio_rustls::TlsAcceptor::from(Arc::clone(&p.read().await.tls_server_config));
        let mut tls_stream = match tls_acceptor.accept(stream).await {
            Ok(tls_stream) => tls_stream,
            #[cfg_attr(not(debug_assertions), allow(unused))]
            Err(e) => {
                #[cfg(debug_assertions)]
                log::error!(error = e.to_string(); "tls_accept_error");
                return;
            }
        };
        let mut pool = Pool::new(Arc::clone(&self.conn_injector));
        let alpn = tls_stream.get_ref().1.alpn_protocol();
        #[cfg(debug_assertions)]
        log::info!(alpn = alpn.map(|v| String::from_utf8_lossy(v)); "alpn_protocol");
        if matches!(alpn, Some(b"h2")) {
            #[cfg_attr(not(debug_assertions), allow(unused))]
            if let Err(e) = pool.proxy_h2(&mut tls_stream).await {
                #[cfg(debug_assertions)]
                log::error!(alpn = "h2", error = e.to_string(); "proxy_h2_error");
            }
        } else {
            match pool.proxy(&mut tls_stream).await {
                Err(ProxyError::Abort(e)) => {
                    if cfg!(debug_assertions)
                        || !matches!(&e, crate::Error::IO(io_error) if io_error.kind() == io::ErrorKind::BrokenPipe)
                    {
                        log::error!(alpn = "http/1.1", error = e.to_string(); "proxy_abort_error");
                    }
                }
                #[cfg(debug_assertions)]
                Err(ProxyError::Client(e)) => {
                    log::warn!(alpn = "http/1.1", error = e.to_string(); "proxy_client_error");
                }
                Err(ProxyError::Server(e)) => {
                    log::error!(alpn = "http/1.1", error = e.to_string(); "proxy_server_error");
                    #[allow(unused)]
                    tls_stream.write_all(
                        b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    ).await;
                }
                _ => (),
            }
        }
        #[allow(unused)]
        tls_stream.flush().await;
        #[allow(unused)]
        tls_stream.shutdown().await;
    }
}
