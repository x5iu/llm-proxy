use std::io::{self};
use std::pin::{pin, Pin};
use std::task::{Context, Poll};

use super::CRLF;

use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncRead, ReadBuf};

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

impl<R: AsyncRead + Unpin + Send + Sync> AsyncRead for LimitedReader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.content_length == 0 {
            return Poll::Ready(Ok(()));
        }
        let max = std::cmp::min(self.content_length, buf.remaining());
        let mut real_buf = ReadBuf::new(&mut buf.initialize_unfilled()[..max]);
        let ret = pin!(&mut self.reader).poll_read(cx, &mut real_buf)?;
        let n = real_buf.filled().len();
        buf.advance(n);
        self.content_length -= n;
        ret.map(|_| Ok(()))
    }
}

pub struct ChunkedReader<R> {
    data_only: bool,
    reader: BufReader<R>,
    unread_chunk_length: usize,
    cleaning: bool,
    finished: bool,
}

impl<R: AsyncRead + Unpin + Send + Sync> ChunkedReader<R> {
    pub fn new(reader: R) -> Self {
        Self {
            data_only: false,
            reader: BufReader::new(reader, super::DEFAULT_BUFFER_SIZE),
            unread_chunk_length: 0,
            cleaning: false,
            finished: false,
        }
    }

    pub fn data_only(reader: R) -> ChunkedReader<R> {
        let mut reader = ChunkedReader::new(reader);
        reader.data_only = true;
        reader
    }

    fn internal_poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        #[inline]
        fn poll_find_next_crlf<R: AsyncRead + Unpin + Send + Sync>(
            reader: &mut BufReader<R>,
            cx: &mut Context<'_>,
        ) -> Poll<io::Result<usize>> {
            #[inline]
            fn find_crlf(buffer: &[u8]) -> Option<usize> {
                buffer.windows(2).position(|window| window == CRLF)
            }
            let mut buffer = reader.buffer();
            if let Some(idx) = find_crlf(buffer) {
                return Poll::Ready(Ok(idx));
            }
            let capacity = reader.capacity();
            while buffer.len() < capacity {
                let Poll::Ready(new_buffer) = Pin::new(&mut *reader).poll_fill_buf(cx)? else {
                    return Poll::Pending;
                };
                buffer = new_buffer;
                if let Some(idx) = find_crlf(buffer) {
                    return Poll::Ready(Ok(idx));
                }
            }
            Poll::Ready(Err(io::Error::new(
                io::ErrorKind::Other,
                "header line too longs",
            )))
        }
        if self.cleaning {
            if self.data_only {
                let buffer = if self.reader.buffer().len() < CRLF.len() {
                    let Poll::Ready(buffer) = Pin::new(&mut self.reader).poll_fill_buf(cx)? else {
                        return Poll::Pending;
                    };
                    buffer
                } else {
                    self.reader.buffer()
                };
                debug_assert_eq!(&buffer[..CRLF.len()], CRLF);
                self.reader.consume(CRLF.len());
            }
            self.cleaning = false;
        }
        if self.unread_chunk_length == 0 {
            if self.finished {
                return Poll::Ready(Ok(()));
            }
            let Poll::Ready(idx) = poll_find_next_crlf(&mut self.reader, cx)? else {
                return Poll::Pending;
            };
            let buffer = self.reader.buffer();
            #[cfg(debug_assertions)]
            log::info!(buffer:serde = buffer.to_vec(), index = idx; "read_chunk_header_line");
            self.unread_chunk_length = {
                let Ok(length_str) = std::str::from_utf8(&buffer[..idx]) else {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::Other,
                        "non-utf8 chunk length",
                    )));
                };
                let Ok(length) = usize::from_str_radix(length_str, 16) else {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::Other,
                        format!("invalid chunk length: \"{}\"", length_str),
                    )));
                };
                if length == 0 {
                    self.finished = true;
                }
                if self.data_only {
                    self.reader.consume(idx + CRLF.len());
                    length
                } else {
                    idx + CRLF.len() + length + CRLF.len()
                }
            };
        }
        let max = std::cmp::min(self.unread_chunk_length, buf.remaining());
        let mut real_buf = ReadBuf::new(&mut buf.initialize_unfilled()[..max]);
        let poll = pin!(&mut self.reader).poll_read(cx, &mut real_buf)?;
        let n = real_buf.filled().len();
        self.unread_chunk_length -= n;
        self.cleaning = self.unread_chunk_length == 0;
        buf.advance(n);
        poll.map(|_| Ok(()))
    }
}

impl<R: AsyncRead + Unpin + Send + Sync> AsyncRead for ChunkedReader<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        match self.internal_poll_read(cx, buf) {
            Poll::Ready(Err(e)) => {
                // This log is recorded to diagnose the `illegal chunk header` and `InvalidChunkLength` error.
                log::error!(error = e.to_string(); "chunked_reader_error");
                Poll::Ready(Err(e))
            }
            ret => ret,
        }
    }
}

pub(crate) mod buf_reader {
    use std::io::{self};
    use std::pin::{pin, Pin};
    use std::task::{Context, Poll};

    use tokio::io::{AsyncBufRead, AsyncRead, ReadBuf};

    pub(crate) struct BufReader<R: ?Sized> {
        buf: Vec<u8>,
        inner: R,
    }

    impl<R> BufReader<R> {
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

    impl<R: AsyncRead + Unpin + Send + Sync> AsyncRead for BufReader<R> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if buf.remaining() == 0 {
                return Poll::Ready(Ok(()));
            }
            if self.buf.len() == 0 {
                return pin!(&mut self.inner).poll_read(cx, buf);
            }
            let mut real_buf = ReadBuf::new(buf.initialize_unfilled());
            #[allow(unused)]
            pin!(&self.buf[..]).poll_read(cx, &mut real_buf)?;
            let n = real_buf.filled().len();
            self.consume(n);
            buf.advance(n);
            Poll::Ready(Ok(()))
        }
    }

    impl<R: AsyncRead + Unpin + Send + Sync> AsyncBufRead for BufReader<R> {
        fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
            let me = self.get_mut();
            let (len, cap) = (me.buf.len(), me.buf.capacity());
            if len < cap {
                unsafe {
                    me.buf.set_len(cap);
                    let mut buf = ReadBuf::new(&mut me.buf[len..cap]);
                    let poll = pin!(&mut me.inner).poll_read(cx, &mut buf)?;
                    let n = buf.filled().len();
                    me.buf.set_len(len + n);
                    if poll.is_pending() {
                        return Poll::Pending;
                    }
                }
            }
            Poll::Ready(Ok(&me.buf[..]))
        }

        fn consume(self: Pin<&mut Self>, amt: usize) {
            self.get_mut().buf.drain(..amt);
        }
    }
}
