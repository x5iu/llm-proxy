use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, LazyLock};
use std::time;

use crossbeam::deque::{Injector, Steal};

use crate::http;
use crate::Error;

static TLS_CLIENT_CONFIG: LazyLock<Arc<rustls::ClientConfig>> = LazyLock::new(|| {
    let root_store =
        rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    Arc::new(config)
});

type TlsIncomingStream<'a> = rustls::Stream<'a, rustls::ServerConnection, TcpStream>;
type TlsOutgoingStream<'a> = rustls::Stream<'a, rustls::ClientConnection, TcpStream>;

#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("Client error: {0}")]
    Client(Error),
    #[error("Server error: {0}")]
    Server(Error),
}

pub struct Pool {
    injector: Arc<Injector<Conn>>,
}

impl Pool {
    pub fn new(injector: Arc<Injector<Conn>>) -> Self {
        Self { injector }
    }

    pub fn proxy(&mut self, mut incoming: &mut TlsIncomingStream) -> Result<(), ProxyError> {
        #[inline]
        fn new_outgoing_conn() -> Result<Conn, ProxyError> {
            let stream = TcpStream::connect(&crate::args().addr)
                .map_err(|e| ProxyError::Server(e.into()))?;
            let client = new_tls_client().map_err(ProxyError::Server)?;
            let conn = Conn::new(stream, client);
            Ok(conn)
        }
        let mut conn_keep_alive = true;
        let mut is_invalid_key = false;
        let mut is_bad_request = false;
        let mut outgoing = if let Some(conn) = self.select() {
            conn
        } else {
            new_outgoing_conn()?
        };
        incoming
            .sock
            .set_read_timeout(Some(time::Duration::from_secs(30)))
            .map_err(|e| ProxyError::Client(e.into()))?;
        incoming
            .sock
            .set_write_timeout(Some(time::Duration::from_secs(30)))
            .map_err(|e| ProxyError::Client(e.into()))?;
        loop {
            let mut request = match http::Request::new(&mut incoming) {
                Ok(request) => request,
                Err(Error::HeaderTooLarge | Error::InvalidHeader) => {
                    is_bad_request = true;
                    break;
                }
                #[cfg(unix)]
                Err(Error::IO(e)) if e.kind() == io::ErrorKind::WouldBlock => {
                    break;
                }
                #[cfg(windows)]
                Err(Error::IO(e)) if e.kind() == io::ErrorKind::TimedOut => {
                    break;
                }
                Err(e) => return Err(ProxyError::Client(e)),
            };
            if !crate::args().is_valid_key(request.auth_header()) {
                is_invalid_key = true;
                break;
            }
            request
                .write_to(&mut outgoing)
                .map_err(ProxyError::Server)?;
            let incoming_conn_keep_alive = request.payload.conn_keep_alive;
            drop(request);
            let mut response = http::Response::new(&mut outgoing).map_err(ProxyError::Server)?;
            response
                .write_to(&mut incoming)
                .map_err(ProxyError::Client)?;
            conn_keep_alive = response.payload.conn_keep_alive;
            drop(response);
            if !incoming_conn_keep_alive {
                break;
            }
            if !conn_keep_alive {
                outgoing = new_outgoing_conn()?;
            }
        }
        if conn_keep_alive {
            self.add(outgoing);
        }
        if is_invalid_key {
            incoming
                .write_all(
                    b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .map_err(|e| ProxyError::Client(e.into()))?;
        } else if is_bad_request {
            incoming
                .write_all(
                    b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .map_err(|e| ProxyError::Client(e.into()))?;
        }
        Ok(())
    }
}

fn new_tls_client() -> Result<rustls::ClientConnection, Error> {
    let client = rustls::ClientConnection::new(
        TLS_CLIENT_CONFIG.clone(),
        crate::args().tls_server_name.clone(),
    )?;
    Ok(client)
}

impl Pool {
    fn add(&mut self, conn: Conn) {
        self.injector.push(conn);
    }

    fn select(&mut self) -> Option<Conn> {
        loop {
            let Steal::Success(mut conn) = self.injector.steal() else {
                return None;
            };
            if conn.health_check().is_ok() {
                return Some(conn);
            }
        }
    }
}

pub struct Conn {
    tls_stream: TlsOutgoingStream<'static>,
}

impl Conn {
    pub fn new(stream: TcpStream, client: rustls::ClientConnection) -> Self {
        let boxed_stream = Box::new(stream);
        let boxed_client = Box::new(client);
        let tls_stream = TlsOutgoingStream::new(Box::leak(boxed_client), Box::leak(boxed_stream));
        Self { tls_stream }
    }

    pub fn health_check(&mut self) -> Result<(), Error> {
        self.tls_stream.sock.set_nonblocking(true)?;
        match self.tls_stream.read(&mut [0; 1]) {
            Ok(0) => return Err(Error::IO(io::Error::new(io::ErrorKind::NotConnected, ""))),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => (),
            Err(e) => return Err(e.into()),
            _ => {
                return Err(Error::IO(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "",
                )))
            }
        }
        self.tls_stream.sock.set_nonblocking(false)?;
        let (ori_read_timeout, ori_write_timeout) = (
            self.tls_stream.sock.read_timeout()?,
            self.tls_stream.sock.write_timeout()?,
        );
        self.tls_stream
            .sock
            .set_read_timeout(Some(time::Duration::from_millis(200)))?;
        self.tls_stream
            .sock
            .set_write_timeout(Some(time::Duration::from_millis(200)))?;
        self.tls_stream.write_all(b"GET / HTTP/1.1\r\n")?;
        self.tls_stream
            .write_all(crate::args().host_header.as_bytes())?;
        self.tls_stream
            .write_all(crate::args().auth_header.as_bytes())?;
        self.tls_stream
            .write_all(b"Connection: keep-alive\r\n\r\n")?;
        self.tls_stream.flush()?;
        let mut response = http::Response::new(&mut self.tls_stream)?;
        response.write_to(&mut io::empty())?;
        drop(response);
        self.tls_stream.sock.set_read_timeout(ori_read_timeout)?;
        self.tls_stream.sock.set_write_timeout(ori_write_timeout)?;
        Ok(())
    }
}

impl Read for Conn {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.tls_stream.read(buf)
    }
}

impl Write for Conn {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.tls_stream.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.tls_stream.flush()
    }
}

impl Drop for Conn {
    fn drop(&mut self) {
        unsafe {
            drop(Box::from_raw(self.tls_stream.conn));
            drop(Box::from_raw(self.tls_stream.sock));
        }
    }
}
