pub mod reader;

use std::borrow::Cow;
use std::io::{Cursor, Read, Write};
use std::ops::Range;

use crate::Error;

use reader::{ChunkedReader, LimitedReader};

const DEFAULT_BUFFER_SIZE: usize = 4096;

const CRLF: &[u8] = b"\r\n";

pub(crate) const QUERY_KEY_KEY: &str = "key";

const HEADER_CONTENT_LENGTH: &str = "Content-Length: ";
const HEADER_TRANSFER_ENCODING: &str = "Transfer-Encoding: ";
const HEADER_HOST: &str = "Host: ";
pub(crate) const HEADER_AUTHORIZATION: &str = "Authorization: ";
pub(crate) const HEADER_X_API_KEY: &str = "X-API-Key: ";
const HEADER_CONNECTION: &str = "Connection: ";

const TRANSFER_ENCODING_CHUNKED: &str = "chunked";
const CONNECTION_KEEP_ALIVE: &str = "keep-alive";

const HEADER_CONNECTION_KEEP_ALIVE: &[u8] = b"Connection: keep-alive\r\n";

pub struct Request<'a> {
    pub(crate) payload: Payload<'a>,
}

impl<'a> Request<'a> {
    pub fn new<S: Read + 'a>(stream: S) -> Result<Request<'a>, Error> {
        Ok(Request {
            payload: Payload::read_from(stream, DEFAULT_BUFFER_SIZE)?,
        })
    }

    pub fn write_to<W: Write>(&mut self, writer: &mut W) -> Result<(), Error> {
        #[cfg(debug_assertions)]
        let mut payload_blocks = Vec::new();
        loop {
            let Some(block) = self.payload.next_block()? else {
                break;
            };
            if block.len() > 0 {
                #[cfg(debug_assertions)]
                payload_blocks.push(block.to_vec());
                writer.write_all(&block)?;
            }
        }
        writer.flush()?;
        #[cfg(debug_assertions)]
        log::info!(payload:serde = payload_blocks; "http_request_blocks");
        Ok(())
    }

    pub fn host(&self) -> Option<&str> {
        self.payload.host()
    }

    pub fn auth_key(&self) -> Option<&[u8]> {
        self.payload.auth_key()
    }
}

pub struct Response<'a> {
    pub(crate) payload: Payload<'a>,
}

impl<'a> Response<'a> {
    pub fn new<S: Read + 'a>(stream: S) -> Result<Response<'a>, Error> {
        Ok(Response {
            payload: Payload::read_from(stream, DEFAULT_BUFFER_SIZE)?,
        })
    }

    pub fn write_to<W: Write>(&mut self, writer: &mut W) -> Result<(), Error> {
        #[cfg(debug_assertions)]
        let mut payload_blocks = Vec::new();
        loop {
            let Some(block) = self.payload.next_block()? else {
                break;
            };
            if block.len() > 0 {
                #[cfg(debug_assertions)]
                payload_blocks.push(block.to_vec());
                writer.write_all(&block)?;
            }
        }
        writer.flush()?;
        #[cfg(debug_assertions)]
        log::info!(payload:serde = payload_blocks; "http_response_blocks");
        Ok(())
    }
}

pub(crate) struct Payload<'a> {
    internal_buffer: Box<[u8]>,
    first_block_length: usize,
    header_length: usize,
    host_range: Option<Range<usize>>,
    auth_range: Option<Range<usize>>,
    body: Body<'a>,
    state: ReadState,
    header_chunks: [Option<Range<usize>>; 4],
    header_current_chunk: usize,
    pub(crate) conn_keep_alive: bool,
}

macro_rules! select {
    ($host:expr => $provider:ident) => {
        let prog_args = crate::args();
        let Some($provider) = prog_args.select_provider($host) else {
            return Err(Error::InvalidHeader);
        };
    };
}

impl<'a> Payload<'a> {
    fn read_from<S: Read + 'a>(mut stream: S, buffer_size: usize) -> Result<Payload<'a>, Error> {
        #[inline]
        fn find_full_crlfs<S: Read>(
            stream: &mut S,
            block: &mut [u8],
        ) -> Result<(Vec<usize>, usize), Error> {
            let mut n = 0;
            loop {
                n += match stream.read(&mut block[n..]) {
                    Ok(0) => return Err(Error::InvalidHeader),
                    Ok(n) => n,
                    Err(e) => return Err(e.into()),
                };
                if let Some(crlfs) = find_crlfs(&block[..n]) {
                    return Ok((crlfs, n));
                } else {
                    if n >= block.len() {
                        return Err(Error::HeaderTooLarge);
                    } else {
                        continue;
                    }
                };
            }
        }
        let mut block = vec![0; buffer_size].into_boxed_slice();
        let (crlfs, advanced) = find_full_crlfs(&mut stream, &mut block)?;
        let Some(&first_double_crlf_index) = crlfs.last() else {
            return Err(Error::HeaderTooLarge);
        };
        let first_block = &block[..advanced];
        let header = &block[..first_double_crlf_index + CRLF.len()];
        let header_lines = HeaderLines::new(&crlfs, header);
        let mut content_length: Option<usize> = None;
        let mut transfer_encoding_chunked = false;
        let mut host_range: Option<Range<usize>> = None;
        let mut auth_range: Option<Range<usize>> = None;
        let mut header_chunks: [Option<Range<usize>>; 4] = [None, None, None, None];
        let mut conn_keep_alive = false;
        for line in header_lines.skip(1) {
            let Ok(header) = std::str::from_utf8(line) else {
                return Err(Error::InvalidHeader);
            };
            if is_header(header, HEADER_CONTENT_LENGTH) {
                content_length = match header[HEADER_CONTENT_LENGTH.len()..].parse() {
                    Ok(length) => Some(length),
                    Err(_) => return Err(Error::InvalidHeader),
                }
            } else if is_header(header, HEADER_TRANSFER_ENCODING) {
                if header[HEADER_TRANSFER_ENCODING.len()..].contains(TRANSFER_ENCODING_CHUNKED) {
                    transfer_encoding_chunked = true;
                }
            } else if is_header(header, HEADER_HOST) {
                let start = {
                    let block_start = &block[0] as *const u8 as usize;
                    let host_start = &line[0] as *const u8 as usize;
                    host_start - block_start
                };
                header_chunks[0] = Some(start..start + line.len());
                host_range = Some(start..start + line.len());
            } else if is_header(header, HEADER_CONNECTION) {
                let start = {
                    let block_start = &block[0] as *const u8 as usize;
                    let connection_start = &line[0] as *const u8 as usize;
                    connection_start - block_start
                };
                header_chunks[2] = Some(start..start + line.len());
                if header[HEADER_CONNECTION.len()..].eq_ignore_ascii_case(CONNECTION_KEEP_ALIVE) {
                    conn_keep_alive = true;
                }
            }
        }
        if let Some(host) = get_host(
            host_range
                .as_ref()
                .map(|range| &block[range.start..range.end]),
        ) {
            select!(host => provider);
            // Only when the provider has supplied a `api_key` will the authentication-related
            // content in the request headers be captured for later interception and replacement. If
            // the provider has not supplied a `api_key`, authentication-related content in the
            // request headers will not be intercepted or replaced, and the original authentication
            // information from the request will be used.
            if provider.auth_header().is_some() {
                if let Some(auth_header_key) = provider.auth_header_key() {
                    let header_lines = HeaderLines::new(&crlfs, header);
                    for line in header_lines.skip(1) {
                        let Ok(header) = std::str::from_utf8(line) else {
                            return Err(Error::InvalidHeader);
                        };
                        if is_header(header, auth_header_key) {
                            let start = {
                                let block_start = &block[0] as *const u8 as usize;
                                let auth_start = &line[0] as *const u8 as usize;
                                auth_start - block_start
                            };
                            header_chunks[1] = Some(start..start + line.len());
                            auth_range = Some(start..start + line.len());
                        }
                    }
                } else if let Some(auth_query_key) = provider.auth_query_key() {
                    let Some(request_line) = HeaderLines::new(&crlfs, header).next() else {
                        return Err(Error::InvalidHeader);
                    };
                    let Ok(request_line_str) = std::str::from_utf8(request_line) else {
                        return Err(Error::InvalidHeader);
                    };
                    auth_range = get_auth_query_range(request_line_str, auth_query_key);
                }
            }
        };
        let mut first_block_length = advanced;
        let header_length = header.len();
        let body = if let Some(real_content_length) = content_length {
            let block_remaining_size = first_block.len() - (header_length + CRLF.len());
            if real_content_length > block_remaining_size {
                Body::Unread(Box::new(LimitedReader::new(
                    stream,
                    real_content_length - block_remaining_size,
                )))
            } else {
                let start = header_length + CRLF.len();
                let end = start + real_content_length;
                Body::Read(start..end)
            }
        } else {
            if transfer_encoding_chunked {
                let (start, end) = (header_length + CRLF.len(), first_block_length);
                first_block_length = start;
                if start < end {
                    let already_read = Cursor::new(block[start..end].to_vec());
                    Body::Unread(Box::new(ChunkedReader::new(already_read.chain(stream))))
                } else {
                    Body::Unread(Box::new(ChunkedReader::new(stream)))
                }
            } else {
                Body::Read(0..0)
            }
        };
        Ok(Payload {
            internal_buffer: block,
            first_block_length,
            header_length,
            host_range,
            auth_range,
            body,
            state: ReadState::Start,
            header_chunks: split_header_chunks(header_chunks, header_length),
            header_current_chunk: 0,
            conn_keep_alive,
        })
    }

    fn host(&self) -> Option<&str> {
        get_host(self.host_header())
    }

    fn host_header(&self) -> Option<&[u8]> {
        if let Some(ref range) = self.host_range {
            Some(&self.internal_buffer[range.start..range.end])
        } else {
            None
        }
    }

    fn auth_key(&self) -> Option<&[u8]> {
        if let Some(ref range) = self.auth_range {
            Some(&self.internal_buffer[range.start..range.end])
        } else {
            None
        }
    }

    fn next_block(&mut self) -> Result<Option<Cow<[u8]>>, Error> {
        match self.state {
            ReadState::Start => {
                if self.header_current_chunk < self.header_chunks.len() {
                    if let Some(ref range) = self.header_chunks[self.header_current_chunk] {
                        let cur_idx = self.header_current_chunk;
                        self.header_current_chunk += 1;
                        #[cfg(debug_assertions)]
                        log::info!(step = "ReadState::Start"; "current_block:header_chunks({})", cur_idx);
                        if cur_idx == 0 {
                            if self.host_range.is_some() {
                                select!(self.host().unwrap() => provider);
                                if let Some(rewritten) = provider.rewrite_first_header_block(
                                    &self.internal_buffer[range.start..range.end],
                                ) {
                                    return Ok(Some(Cow::Owned(rewritten)));
                                }
                            }
                        }
                        return Ok(Some(Cow::Borrowed(
                            &self.internal_buffer[range.start..range.end],
                        )));
                    }
                }
                self.state = ReadState::HostHeader;
                self.next_block()
            }
            ReadState::HostHeader => {
                self.state = ReadState::AuthHeader;
                if self.host_range.is_some() {
                    #[cfg(debug_assertions)]
                    log::info!(step = "ReadState::HostHeader"; "current_block:host_header");
                    select!(self.host().unwrap() => provider);
                    Ok(Some(Cow::Borrowed(provider.host_header().as_bytes())))
                } else {
                    self.next_block()
                }
            }
            ReadState::AuthHeader => {
                self.state = ReadState::ConnectionHeader;
                if self.host_range.is_some() {
                    #[cfg(debug_assertions)]
                    log::info!(step = "ReadState::AuthHeader"; "current_block:auth_header");
                    select!(self.host().unwrap() => provider);
                    if let Some(auth_header) = provider.auth_header() {
                        Ok(Some(Cow::Borrowed(auth_header.as_bytes())))
                    } else {
                        self.next_block()
                    }
                } else {
                    self.next_block()
                }
            }
            ReadState::ConnectionHeader => {
                self.state = ReadState::FinishHeader;
                #[cfg(debug_assertions)]
                log::info!(step = "ReadState::ConnectionHeader"; "current_block:connection_header");
                Ok(Some(Cow::Borrowed(HEADER_CONNECTION_KEEP_ALIVE)))
            }
            ReadState::FinishHeader => {
                self.state = ReadState::ReadBody;
                #[cfg(debug_assertions)]
                log::info!(step = "ReadState::FinishHeader"; "current_block:finish_header");
                Ok(Some(Cow::Borrowed(CRLF)))
            }
            ReadState::ReadBody => {
                self.state = ReadState::UnreadBody;
                match &self.body {
                    Body::Read(range) => {
                        #[cfg(debug_assertions)]
                        log::info!(step = "ReadState::ReadBody"; "current_block:total_body_already_been_read");
                        Ok(Some(Cow::Borrowed(
                            &self.internal_buffer[range.start..range.end],
                        )))
                    }
                    Body::Unread(_) => {
                        let (start, end) =
                            (self.header_length + CRLF.len(), self.first_block_length);
                        if start < end {
                            #[cfg(debug_assertions)]
                            log::info!(step = "ReadState::ReadBody"; "current_block:body_already_been_read");
                            Ok(Some(Cow::Borrowed(&self.internal_buffer[start..end])))
                        } else {
                            self.next_block()
                        }
                    }
                }
            }
            ReadState::UnreadBody => {
                if let Body::Unread(reader) = &mut self.body {
                    match reader.read(&mut self.internal_buffer) {
                        Ok(0) => Ok(None),
                        Ok(n) => {
                            #[cfg(debug_assertions)]
                            log::info!(step = "ReadState::UnreadBody"; "current_block:body_in_stream");
                            Ok(Some(Cow::Borrowed(&self.internal_buffer[..n])))
                        }
                        Err(e) => Err(e.into()),
                    }
                } else {
                    Ok(None)
                }
            }
        }
    }
}

#[inline]
fn get_host(header: Option<&[u8]>) -> Option<&str> {
    header
        .map(|header| std::str::from_utf8(header).ok())
        .flatten()
        .map(|host| {
            if host[..HEADER_HOST.len()].eq_ignore_ascii_case(HEADER_HOST) {
                &host[HEADER_HOST.len()..]
            } else {
                host
            }
        })
}

#[inline]
pub(crate) fn get_auth_query_range(header: &str, key: &str) -> Option<Range<usize>> {
    let first_whitespace_idx = header.find(' ')?;
    let second_whitespace_idx = {
        let idx = header[first_whitespace_idx + 1..].find(' ')?;
        first_whitespace_idx + 1 + idx
    };
    let url = &header[first_whitespace_idx + 1..second_whitespace_idx];
    let question_mark_idx = url.find('?')?;
    let mut query = &url[question_mark_idx + 1..];
    if let Some(pound_sign_idx) = query.find('#') {
        query = &query[..pound_sign_idx]
    }
    let parts = query.split('&');
    for part in parts {
        if let Some(equal_sign_idx) = part.find('=') {
            let (qkey, qval) = part.split_at(equal_sign_idx);
            if qkey == key && qval.len() > 1 {
                let start = {
                    let header_start = &header.as_bytes()[0] as *const u8 as usize;
                    let part_start = &qval.as_bytes()[1] as *const u8 as usize;
                    part_start - header_start
                };
                let end = start + (qval.len() - 1);
                return Some(start..end);
            }
        }
    }
    None
}

#[inline]
pub(crate) fn is_header(header: &str, key: &str) -> bool {
    header.len() >= key.len() && header[..key.len()].eq_ignore_ascii_case(key)
}

#[inline]
fn split_header_chunks(
    mut header: [Option<Range<usize>>; 4],
    header_length: usize,
) -> [Option<Range<usize>>; 4] {
    header.sort_by_key(|range| range.as_ref().map(|r| r.start).unwrap_or(usize::MAX));
    match header {
        [Some(first), Some(second), Some(third), None] => [
            Some(0..first.start),
            Some(first.end + CRLF.len()..second.start),
            Some(second.end + CRLF.len()..third.start),
            Some(third.end + CRLF.len()..header_length),
        ],
        [Some(first), Some(second), None, None] => [
            Some(0..first.start),
            Some(first.end + CRLF.len()..second.start),
            Some(second.end + CRLF.len()..header_length),
            None,
        ],
        [Some(first), None, None, None] => [
            Some(0..first.start),
            Some(first.end + CRLF.len()..header_length),
            None,
            None,
        ],
        [None, None, None, None] => [Some(0..header_length), None, None, None],
        _ => unreachable!(),
    }
}

#[inline]
fn find_crlfs(buffer: &[u8]) -> Option<Vec<usize>> {
    let mut crlfs: Vec<usize> = buffer
        .windows(2)
        .enumerate()
        .filter(|(_, window)| window == &CRLF)
        .map(|(i, _)| i)
        .collect();
    if crlfs.is_empty() {
        None
    } else {
        match (0..(crlfs.len() - 1)).find(|&i| crlfs[i] + CRLF.len() == crlfs[i + 1]) {
            Some(end) => {
                crlfs.drain(end + 1..);
                Some(crlfs)
            }
            None => None,
        }
    }
}

struct HeaderLines<'a> {
    crlfs: std::slice::Iter<'a, usize>,
    header: &'a [u8],
    offset: usize,
}

impl<'a> HeaderLines<'a> {
    fn new(crlfs: &'a [usize], header: &'a [u8]) -> Self {
        Self {
            crlfs: crlfs.iter(),
            header,
            offset: 0,
        }
    }
}

impl<'a> Iterator for HeaderLines<'a> {
    type Item = &'a [u8];
    fn next(&mut self) -> Option<Self::Item> {
        self.crlfs.next().map(|&idx| {
            let line = &self.header[self.offset..idx];
            self.offset = idx + CRLF.len();
            line
        })
    }
}

enum Body<'a> {
    Read(Range<usize>),
    Unread(Box<dyn Read + 'a>),
}

#[derive(Copy, Clone)]
enum ReadState {
    Start,
    HostHeader,
    AuthHeader,
    ConnectionHeader,
    FinishHeader,
    ReadBody,
    UnreadBody,
}
