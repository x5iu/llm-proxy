use std::io::Cursor;
use std::mem;
use std::pin::{pin, Pin};
use std::sync::{Arc, LazyLock};
use std::task::{Context, Poll};

use tokio::io::{self, AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;

use crossbeam::deque::{Injector, Steal};

use bytes::{Buf, Bytes};

use crate::http;
use crate::provider::Provider;
use crate::Error;

static TLS_CLIENT_CONFIG: LazyLock<Arc<rustls::ClientConfig>> = LazyLock::new(|| {
    let root_store =
        rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
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

#[derive(Clone)]
pub struct Pool {
    injector: Arc<Injector<Conn>>,
}

impl Pool {
    pub fn new(injector: Arc<Injector<Conn>>) -> Self {
        Self { injector }
    }

    #[inline]
    async fn get_outgoing_conn(&mut self, provider: &dyn Provider) -> Result<Conn, Error> {
        if let Some(conn) = self.select(provider.endpoint()).await {
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

    pub async fn proxy(&mut self, mut incoming: &mut TlsIncomingStream) -> Result<(), ProxyError> {
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
            let mut outgoing = self
                .get_outgoing_conn(provider)
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
            if conn_keep_alive {
                self.add(outgoing);
            }
            if !incoming_conn_keep_alive {
                break;
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

    pub async fn proxy_h2(&mut self, incoming: &mut TlsIncomingStream) -> Result<(), ProxyError> {
        macro_rules! invalid {
            ($respond:expr, $status:expr) => {{
                #[allow(unused)]
                $respond.send_response(
                    httplib::Response::builder()
                        .version(httplib::Version::HTTP_2)
                        .status($status)
                        .body(())
                        .unwrap(),
                    true,
                );
                ()
            }};
        }
        let mut stream = h2::server::handshake(incoming)
            .await
            .map_err(|e| ProxyError::Client(e.into()))?;
        while let Some(next) = stream.accept().await {
            let (mut request, mut respond) = next.map_err(|e| ProxyError::Client(e.into()))?;
            let mut pool = self.clone();
            tokio::spawn(async move {
                let prog_args = crate::args();
                let Some(authority) = request.uri().authority() else {
                    return invalid!(respond, 400);
                };
                let Some(provider) = prog_args.select_provider(authority.host()) else {
                    return invalid!(respond, 400);
                };
                let auth_key = if let Some(auth_header_key) = provider.auth_header_key() {
                    request
                        .headers()
                        .get(auth_header_key.trim_end_matches(|ch| ch == ' ' || ch == ':'))
                        .map(|v| v.to_str().ok())
                        .flatten()
                } else if let Some(auth_query_key) = provider.auth_query_key() {
                    request
                        .uri()
                        .query()
                        .map(|query| {
                            http::get_auth_query_range(query, auth_query_key)
                                .map(|range| &query[range])
                        })
                        .flatten()
                } else {
                    None
                };
                let Some(auth_key) = auth_key else {
                    return invalid!(respond, 401);
                };
                if !provider.authenticate_key(auth_key).is_ok() {
                    return invalid!(respond, 401);
                }
                request
                    .headers_mut()
                    .entry("Connection")
                    .or_insert(httplib::HeaderValue::from_static("keep-alive"));
                request
                    .headers_mut()
                    .entry("Host")
                    .or_insert(httplib::HeaderValue::from_str(provider.host()).unwrap());
                let mut req_headers = String::with_capacity(1024);
                for (key, value) in request.headers() {
                    // Skip Accept-Encoding header as HTTP/2 handles compression differently
                    if key.as_str().eq_ignore_ascii_case("Accept-Encoding") {
                        continue;
                    }
                    req_headers.push_str(key.as_str());
                    req_headers.push_str(": ");
                    req_headers.push_str(String::from_utf8_lossy(value.as_bytes()).as_ref());
                    req_headers.push_str("\r\n");
                }
                let req_str = format!(
                    "{} {} HTTP/1.1\r\n{}\r\n",
                    request.method(),
                    request
                        .uri()
                        .path_and_query()
                        .map(|pq| pq.as_str())
                        .unwrap_or("/"),
                    req_headers,
                );
                let req_reader = tokio::io::AsyncReadExt::chain(
                    req_str.as_bytes(),
                    H2StreamReader::new(request.into_body()),
                );
                let Ok(mut req) = http::Request::new(req_reader).await else {
                    return invalid!(respond, 400);
                };
                let Ok(mut outgoing) = pool.get_outgoing_conn(provider).await else {
                    return invalid!(respond, 502);
                };
                if let Err(_) = req.write_to(&mut outgoing).await {
                    return invalid!(respond, 502);
                };
                let Ok(mut response) = http::Response::new(&mut outgoing).await else {
                    return invalid!(respond, 502);
                };
                let mut headers = [httparse::EMPTY_HEADER; 64];
                let mut parser = httparse::Response::new(&mut headers);
                if let Err(_) = parser.parse(response.payload.block()) {
                    return invalid!(respond, 502);
                };
                let mut builder = httplib::Response::builder()
                    .version(httplib::Version::HTTP_2)
                    .status(parser.code.unwrap_or(502));
                let mut is_transfer_encoding_chunked = false;
                for header in parser.headers {
                    if header.name.eq_ignore_ascii_case("transfer-encoding")
                        && header.value.eq_ignore_ascii_case(b"chunked")
                    {
                        is_transfer_encoding_chunked = true;
                    }
                    if !is_http2_invalid_headers(header.name) {
                        builder = builder.header(header.name, header.value);
                    }
                }
                if matches!(&mut response.payload.body, http::Body::Unread(_))
                    && is_transfer_encoding_chunked
                {
                    let mut take = http::Body::Read(0..0);
                    mem::swap(&mut take, &mut response.payload.body);
                    let mut body = if let http::Body::Unread(reader) = take {
                        http::Body::Unread(Box::new(http::reader::ChunkedReader::data_only(reader)))
                    } else {
                        unreachable!();
                    };
                    mem::swap(&mut body, &mut response.payload.body);
                }
                let mut send = match respond.send_response(builder.body(()).unwrap(), false) {
                    Ok(send) => send,
                    Err(e) => {
                        log::error!(alpn = "h2", error = e.to_string(); "send_response_error");
                        return invalid!(respond, 502);
                    }
                };
                loop {
                    let block = match response
                        .payload
                        .next_block()
                        .await
                        .map(|block| block.map(|cow| cow.to_vec()))
                    {
                        Ok(block) => block,
                        Err(e) => {
                            log::error!(alpn = "h2", error = e.to_string(); "read_block_error");
                            return;
                        }
                    };
                    if matches!(
                        response.payload.state(),
                        http::ReadState::ReadBody | http::ReadState::UnreadBody
                    ) {
                        let (data, is_eos) = if let Some(block) = block {
                            send.reserve_capacity(block.len());
                            (Bytes::from(block), false)
                        } else {
                            (Bytes::from_static(b""), true)
                        };
                        if let Err(e) = send.send_data(data, is_eos) {
                            log::error!(alpn = "h2", error = e.to_string(); "send_data_error");
                            return;
                        }
                        if is_eos {
                            break;
                        }
                    }
                }
                if response.payload.conn_keep_alive {
                    drop(response);
                    pool.add(outgoing);
                }
            });
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

struct H2StreamReader {
    bytes: Option<Cursor<bytes::Bytes>>,
    stream: h2::RecvStream,
}

impl H2StreamReader {
    fn new(stream: h2::RecvStream) -> Self {
        H2StreamReader {
            bytes: None,
            stream,
        }
    }
}

impl AsyncRead for H2StreamReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if let Some(cursor) = &mut self.bytes {
            if cursor.has_remaining() {
                return pin!(cursor).poll_read(cx, buf);
            }
        }
        let stream = match self.stream.poll_data(cx) {
            Poll::Ready(Some(Ok(stream))) => stream,
            Poll::Ready(Some(Err(e))) => {
                return Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e)))
            }
            Poll::Ready(None) => return Poll::Ready(Ok(())),
            Poll::Pending => return Poll::Pending,
        };
        self.bytes = Some(Cursor::new(stream));
        self.poll_read(cx, buf)
    }
}

#[inline]
fn is_http2_invalid_headers(key: &str) -> bool {
    key.eq_ignore_ascii_case(httplib::header::CONNECTION.as_str())
        || key.eq_ignore_ascii_case(httplib::header::TRANSFER_ENCODING.as_str())
        || key.eq_ignore_ascii_case(httplib::header::UPGRADE.as_str())
        || key.eq_ignore_ascii_case("keep-alive")
        || key.eq_ignore_ascii_case("proxy-connection")
        || key.eq_ignore_ascii_case("content-length")
        || key.eq_ignore_ascii_case("content-encoding")
}
