use std::sync::Arc;

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
        let pool = Pool::new(Arc::clone(&self.conn_injector));
        let prog_args = crate::static_ref_args();
        tokio::spawn(async move { prog_args.run_health_check(pool).await });
    }

    pub async fn execute(&self, stream: TcpStream) {
        let tls_acceptor =
            tokio_rustls::TlsAcceptor::from(Arc::clone(&crate::args().tls_server_config));
        let mut tls_stream = match tls_acceptor.accept(stream).await {
            Ok(tls_stream) => tls_stream,
            Err(e) => {
                log::error!(error = e.to_string(); "tls_accept_error");
                return;
            }
        };
        let mut pool = Pool::new(Arc::clone(&self.conn_injector));
        let alpn = tls_stream.get_ref().1.alpn_protocol();
        #[cfg(debug_assertions)]
        log::info!(alpn = alpn.map(|v| String::from_utf8_lossy(v)); "alpn_protocol");
        if matches!(alpn, Some(b"h2")) {
            if let Err(e) = pool.proxy_h2(&mut tls_stream).await {
                log::error!(alpn = "h2", error = e.to_string(); "proxy_h2_error");
            }
        } else {
            match pool.proxy(&mut tls_stream).await {
                Err(ProxyError::Abort(e)) => {
                    log::error!(alpn = "http/1.1", error = e.to_string(); "proxy_abort_error");
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
    }
}
