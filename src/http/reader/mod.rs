use std::io::{self, BufRead, BufReader, Read};

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
            reader: BufReader::with_capacity(4096, reader),
            unread_chunk_length: 0,
            finished: false,
        }
    }
}

impl<R: Read> Read for ChunkedReader<R> {
    fn read(&mut self, mut buf: &mut [u8]) -> io::Result<usize> {
        use super::CRLF;
        let mut filled_bytes = 0;
        while filled_bytes < buf.len() {
            if self.unread_chunk_length == 0 {
                if self.finished {
                    break;
                }
                let buffer = self.reader.fill_buf()?;
                let Some(idx) = buffer.windows(2).position(|window| window == CRLF) else {
                    return Err(io::Error::new(io::ErrorKind::Other, "header line too long"));
                };
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
            self.unread_chunk_length -= n;
            filled_bytes += n;
        }
        Ok(filled_bytes)
    }
}
