use std::io::{self, BufRead, Read};

use buf_reader::BufReader;

pub struct LimitedReader<R> {
    reader: R,
    content_length: usize,
}

impl<R> LimitedReader<R> {
    pub fn new(reader: R, content_length: usize) -> Self {
        Self {
            reader,
            content_length,
        }
    }
}

impl<R: Read> Read for LimitedReader<R> {
    fn read(&mut self, mut buf: &mut [u8]) -> io::Result<usize> {
        if self.content_length == 0 {
            return Ok(0);
        }
        if buf.len() > self.content_length {
            buf = &mut buf[..self.content_length];
        }
        let n = self.reader.read(buf)?;
        self.content_length -= n;
        Ok(n)
    }
}

pub struct ChunkedReader<R> {
    reader: BufReader<R>,
    unread_chunk_length: usize,
    finished: bool,
}

impl<R: Read> ChunkedReader<R> {
    pub fn new(reader: R) -> Self {
        Self {
            reader: BufReader::new(reader, super::DEFAULT_BUFFER_SIZE),
            unread_chunk_length: 0,
            finished: false,
        }
    }

    fn internal_read(&mut self, mut buf: &mut [u8]) -> io::Result<usize> {
        #[inline]
        fn find_crlf(buffer: &[u8]) -> Option<usize> {
            buffer.windows(2).position(|window| window == CRLF)
        }
        #[inline]
        fn find_next_crlf<R: Read>(reader: &mut BufReader<R>) -> io::Result<usize> {
            let mut buffer = reader.buffer();
            if let Some(idx) = find_crlf(buffer) {
                return Ok(idx);
            }
            let buffer_capacity = reader.capacity();
            while buffer.len() < buffer_capacity {
                buffer = reader.fill_buf()?;
                if let Some(idx) = find_crlf(buffer) {
                    return Ok(idx);
                }
            }
            Err(io::Error::new(io::ErrorKind::Other, "header line too long"))
        }
        use super::CRLF;
        let mut filled_bytes = 0;
        let total_buf_len = buf.len();
        while filled_bytes < total_buf_len {
            if self.unread_chunk_length == 0 {
                if self.finished {
                    break;
                }
                let idx = find_next_crlf(&mut self.reader)?;
                let buffer = self.reader.buffer();
                #[cfg(debug_assertions)]
                log::info!(buffer:serde = buffer.to_vec(), index = idx; "read_chunk_header_line");
                self.unread_chunk_length = {
                    let Ok(length_str) = std::str::from_utf8(&buffer[..idx]) else {
                        return Err(io::Error::new(
                            io::ErrorKind::Other,
                            "non-utf8 chunk length",
                        ));
                    };
                    let Ok(length) = usize::from_str_radix(length_str, 16) else {
                        return Err(io::Error::new(
                            io::ErrorKind::Other,
                            format!("invalid chunk length: \"{}\"", length_str),
                        ));
                    };
                    if length == 0 {
                        self.finished = true;
                    }
                    idx + CRLF.len() + length + CRLF.len()
                };
            }
            if self.unread_chunk_length < buf.len() {
                buf = &mut buf[..self.unread_chunk_length];
            }
            let n = self.reader.read(buf)?;
            if n == 0 {
                break;
            }
            buf = &mut buf[n..];
            self.unread_chunk_length -= n;
            filled_bytes += n;
        }
        Ok(filled_bytes)
    }
}

impl<R: Read> Read for ChunkedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.internal_read(buf) {
            Ok(n) => Ok(n),
            Err(e) => {
                // This log is recorded to diagnose the `illegal chunk header` and `InvalidChunkLength` error.
                log::error!(error = e.to_string(); "chunked_reader_error");
                Err(e)
            }
        }
    }
}

pub(crate) mod buf_reader {
    use std::io::{self, BufRead, Read};

    pub(crate) struct BufReader<R: ?Sized> {
        buf: Vec<u8>,
        inner: R,
    }

    impl<R: Read> BufReader<R> {
        pub(crate) fn new(inner: R, size: usize) -> Self {
            let buf = Vec::with_capacity(size);
            Self { buf, inner }
        }

        pub(crate) fn capacity(&self) -> usize {
            self.buf.capacity()
        }

        pub(crate) fn buffer(&self) -> &[u8] {
            &self.buf[..]
        }
    }

    impl<R: Read> Read for BufReader<R> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if buf.len() == 0 {
                return Ok(0);
            }
            if self.buf.len() == 0 {
                return self.inner.read(buf);
            }
            let mut r = &self.buf[..];
            match r.read(buf) {
                Ok(0) => unreachable!(),
                Err(e) => Err(e),
                Ok(n) => {
                    self.consume(n);
                    Ok(n)
                }
            }
        }
    }

    impl<R: Read> BufRead for BufReader<R> {
        fn fill_buf(&mut self) -> io::Result<&[u8]> {
            let (len, cap) = (self.buf.len(), self.buf.capacity());
            if len < cap {
                unsafe {
                    self.buf.set_len(cap);
                    let n = self.inner.read(&mut self.buf[len..cap])?;
                    if n == 0 {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "unexpected EOF",
                        ));
                    }
                    self.buf.set_len(len + n);
                }
            }
            Ok(&self.buf[..])
        }

        fn consume(&mut self, amt: usize) {
            self.buf.drain(..amt);
        }
    }
}
