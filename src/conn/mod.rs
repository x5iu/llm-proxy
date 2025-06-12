use std::pin::{pin, Pin};
use std::sync::{Arc, LazyLock};
use std::task::{Context, Poll};

use tokio::io::{self, AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;

use crossbeam::deque::{Injector, Steal};

use crate::http;
use crate::provider::Provider;
use crate::Error;

static TLS_CLIENT_CONFIG: LazyLock<Arc<rustls::ClientConfig>> = LazyLock::new(|| {
    let root_store =
        rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    Arc::new(config)
});

type TlsIncomingStream = tokio_rustls::server::TlsStream<TcpStream>;
type TlsOutgoingStream = tokio_rustls::client::TlsStream<TcpStream>;

#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("Client error: {0}")]
    Client(Error),
    #[error("Server error: {0}")]
    Server(Error),
    #[error("Abort: {0}")]
    Abort(Error),
}

pub struct Pool {
    injector: Arc<Injector<Conn>>,
}

impl Pool {
    pub fn new(injector: Arc<Injector<Conn>>) -> Self {
        Self { injector }
    }

    pub async fn proxy(&mut self, mut incoming: &mut TlsIncomingStream) -> Result<(), ProxyError> {
        #[inline]
        async fn get_outgoing_conn(
            provider: &dyn Provider,
            pool: &mut Pool,
        ) -> Result<Conn, Error> {
            if let Some(conn) = pool.select(provider.endpoint()).await {
                Ok(conn)
            } else {
                let stream = TcpStream::connect(provider.sock_address()).await?;
                let conn = if provider.tls() {
                    let connector = new_tls_connector();
                    Conn::new_tls(provider.endpoint(), stream, connector).await?
                } else {
                    Conn::new(provider.endpoint(), stream)
                };
                Ok(conn)
            }
        }
        let mut is_invalid_key = false;
        let mut is_bad_request = false;
        loop {
            let mut request = match http::Request::new(&mut incoming).await {
                Ok(request) => request,
                Err(Error::HeaderTooLarge | Error::InvalidHeader) => {
                    is_bad_request = true;
                    break;
                }
                Err(e) => return Err(ProxyError::Client(e)),
            };
            let prog_args = crate::args();
            let Some(host) = request.host() else {
                is_bad_request = true;
                break;
            };
            let Some(provider) = prog_args.select_provider(host) else {
                is_bad_request = true;
                break;
            };
            if !provider.authenticate(request.auth_key()).is_ok() {
                #[cfg(debug_assertions)]
                log::error!(provider = provider.kind().to_string(), header:serde = request.auth_key().map(|header| header.to_vec()); "authentication_failed");
                is_invalid_key = true;
                break;
            }
            let mut outgoing = get_outgoing_conn(provider, self)
                .await
                .map_err(ProxyError::Server)?;
            request
                .write_to(&mut outgoing)
                .await
                .map_err(ProxyError::Server)?;
            let incoming_conn_keep_alive = request.payload.conn_keep_alive;
            drop(request);
            let mut response = http::Response::new(&mut outgoing)
                .await
                .map_err(ProxyError::Abort)?;
            response
                .write_to(&mut incoming)
                .await
                .map_err(ProxyError::Abort)?;
            let conn_keep_alive = response.payload.conn_keep_alive;
            drop(response);
            if !incoming_conn_keep_alive {
                break;
            }
            if conn_keep_alive {
                self.add(outgoing);
            }
        }
        if is_invalid_key {
            incoming
                .write_all(
                    b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await
                .map_err(|e| ProxyError::Client(e.into()))?;
        } else if is_bad_request {
            incoming
                .write_all(
                    b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await
                .map_err(|e| ProxyError::Client(e.into()))?;
        }
        Ok(())
    }
}

#[inline]
fn new_tls_connector() -> tokio_rustls::TlsConnector {
    tokio_rustls::TlsConnector::from(Arc::clone(&*TLS_CLIENT_CONFIG))
}

impl Pool {
    fn add(&mut self, conn: Conn) {
        self.injector.push(conn);
    }

    async fn select(&mut self, endpoint: &str) -> Option<Conn> {
        let mut retry_times = 0;
        while retry_times < 3 {
            let Steal::Success(mut conn) = self.injector.steal() else {
                retry_times += 1;
                continue;
            };
            if conn.endpoint != endpoint {
                let is_injector_empty = self.injector.is_empty();
                self.injector.push(conn);
                if is_injector_empty {
                    return None;
                }
            } else if conn.health_check().await.is_ok() {
                return Some(conn);
            }
            retry_times += 1;
        }
        None
    }
}

pub struct Conn {
    endpoint: String,
    stream: Stream,
}

impl Conn {
    pub fn new(endpoint: &str, stream: TcpStream) -> Self {
        Self {
            endpoint: endpoint.to_string(),
            stream: Stream::Tcp(stream),
        }
    }

    pub async fn new_tls(
        endpoint: &str,
        stream: TcpStream,
        connector: tokio_rustls::TlsConnector,
    ) -> Result<Self, Error> {
        let tls_stream = connector
            .connect(endpoint.to_owned().try_into().unwrap(), stream)
            .await?;
        Ok(Self {
            endpoint: endpoint.to_string(),
            stream: Stream::Tls(tls_stream),
        })
    }

    pub async fn health_check(&mut self) -> Result<(), Error> {
        self.stream.write_all(b"GET / HTTP/1.1\r\n").await?;
        self.stream.write_all(b"Host: ").await?;
        self.stream.write_all(self.endpoint.as_bytes()).await?;
        self.stream.write_all(b"\r\n").await?;
        self.stream
            .write_all(b"Connection: keep-alive\r\n\r\n")
            .await?;
        self.stream.flush().await?;
        let mut response = http::Response::new(&mut self.stream).await?;
        response.write_to(&mut io::empty()).await?;
        let conn_keep_alive = response.payload.conn_keep_alive;
        drop(response);
        if !conn_keep_alive {
            return Err(Error::IO(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "",
            )));
        }
        Ok(())
    }
}

impl AsyncRead for Conn {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        pin!(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for Conn {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        pin!(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        pin!(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        pin!(&mut self.stream).poll_shutdown(cx)
    }
}

enum Stream {
    Tcp(TcpStream),
    Tls(TlsOutgoingStream),
}

impl AsyncRead for Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match &mut *self {
            Stream::Tcp(stream) => pin!(stream).poll_read(cx, buf),
            Stream::Tls(stream) => pin!(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        match &mut *self {
            Stream::Tcp(stream) => pin!(stream).poll_write(cx, buf),
            Stream::Tls(stream) => pin!(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        match &mut *self {
            Stream::Tcp(stream) => pin!(stream).poll_flush(cx),
            Stream::Tls(stream) => pin!(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        match &mut *self {
            Stream::Tcp(stream) => pin!(stream).poll_shutdown(cx),
            Stream::Tls(stream) => pin!(stream).poll_shutdown(cx),
        }
    }
}
