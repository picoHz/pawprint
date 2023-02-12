use crate::tls::TlsInspctor;
use std::pin::Pin;
use std::sync::Mutex;
use std::task;
use std::task::Poll;
use std::{io::IoSlice, sync::Arc};
use tokio::io::{self, AsyncRead, AsyncWrite, ReadBuf};
use tokio_rustls::server::TlsStream;

const HTTP2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

pin_project_lite::pin_project! {
    pub struct Http2Inspector {
        #[pin]
        inner: TlsStream<TlsInspctor>,

        buf: Vec<u8>,
        frames: Arc<Mutex<Vec<Vec<u8>>>>
    }
}

impl Http2Inspector {
    pub fn new(inner: TlsStream<TlsInspctor>) -> Self {
        Self {
            inner,
            buf: Vec::new(),
            frames: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn frames(&self) -> Arc<Mutex<Vec<Vec<u8>>>> {
        self.frames.clone()
    }
}

impl AsyncRead for Http2Inspector {
    #[inline]
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let len = buf.filled().len();
        let me = self.project();
        let poll = me.inner.poll_read(cx, buf);

        let plen = HTTP2_PREFACE.len();
        let not_http2 = me.buf.len() >= plen && !me.buf.starts_with(HTTP2_PREFACE);
        if !not_http2 {
            me.buf.extend(&buf.filled()[len..]);
            if me.buf.len() > plen {
                let (frame_len, ty) = parse_frame(&me.buf[plen..]);
                if frame_len > 0 {
                    let frame = me.buf.drain(plen..plen + frame_len).collect::<Vec<_>>();
                    if matches!(ty, 1 | 2 | 4 | 8) {
                        me.frames.lock().unwrap().push(frame);
                    }
                }
            }
        }

        poll
    }
}

impl AsyncWrite for Http2Inspector {
    #[inline]
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.project().inner.poll_write(cx, buf)
    }

    #[inline]
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        self.project().inner.poll_write_vectored(cx, bufs)
    }

    #[inline]
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    #[inline]
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_shutdown(cx)
    }

    #[inline]
    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

const FRAME_HEADER_LEN: usize = 9;

fn parse_frame(data: &[u8]) -> (usize, u8) {
    if data.len() < FRAME_HEADER_LEN {
        return (0, 0);
    }
    let header = &data[..FRAME_HEADER_LEN];
    let length = ((header[0] as usize) << 16) + ((header[1] as usize) << 8) + header[2] as usize;
    let ty = header[3];
    let payload = &data[FRAME_HEADER_LEN..];
    if payload.len() < length {
        return (0, 0);
    }
    (FRAME_HEADER_LEN + length, ty)
}
