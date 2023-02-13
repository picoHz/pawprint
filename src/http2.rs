use crate::tls::TlsInspctor;
use httlib_hpack::Decoder;
use serde_derive::Serialize;
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
        frames: Arc<Mutex<Vec<Frame>>>
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

    pub fn frames(&self) -> Arc<Mutex<Vec<Frame>>> {
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
            while me.buf.len() > plen {
                let (frame_len, frame) = parse_frame(&me.buf[plen..]);
                if frame_len > 0 {
                    me.buf.drain(plen..plen + frame_len);
                    if let Some(frame) = frame {
                        me.frames.lock().unwrap().push(frame);
                    }
                } else {
                    break;
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

fn parse_frame(data: &[u8]) -> (usize, Option<Frame>) {
    if data.len() < FRAME_HEADER_LEN {
        return (0, None);
    }
    let header = &data[..FRAME_HEADER_LEN];
    let length = u32::from_be_bytes([0, header[0], header[1], header[2]]) as usize;
    let ty = header[3];
    let flags = header[4];
    let stream_id = u32::from_be_bytes([header[5] & 0x7f, header[6], header[7], header[8]]);
    let payload = &data[FRAME_HEADER_LEN..];
    if payload.len() < length {
        return (0, None);
    }
    let frame = (ty, flags, stream_id, &payload[..length]).try_into().ok();
    (FRAME_HEADER_LEN + length, frame)
}

#[derive(Debug, Serialize)]
#[serde(tag = "frame_type", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Frame {
    Headers(HeadersFrame),
    Settings(SettingsFrame),
    Priority(PriorityFrame),
    WindowUpdate(WindowUpdateFrame),
}

impl TryFrom<(u8, u8, u32, &[u8])> for Frame {
    type Error = ();

    fn try_from((ty, flags, stream_id, payload): (u8, u8, u32, &[u8])) -> Result<Self, ()> {
        match ty {
            0x1 => (flags, stream_id, payload).try_into().map(Frame::Headers),
            0x2 => (stream_id, payload).try_into().map(Frame::Priority),
            0x4 => (stream_id, payload).try_into().map(Frame::Settings),
            0x8 => (stream_id, payload).try_into().map(Frame::WindowUpdate),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct HeadersFrame {
    pub stream_id: u32,
    pub pseudo_headers: Vec<String>,
}

impl TryFrom<(u8, u32, &[u8])> for HeadersFrame {
    type Error = ();

    fn try_from((flags, stream_id, payload): (u8, u32, &[u8])) -> Result<Self, ()> {
        let mut fragment_offset = 0;
        let padded = flags & 0x8 != 0;
        if padded {
            fragment_offset += 1;
        }
        if flags & 0x20 != 0 {
            fragment_offset += 5;
        }
        if payload.len() < fragment_offset {
            return Err(());
        }
        let padding_len = if padded { payload[0] as usize } else { 0 };
        let data = &payload[fragment_offset..];
        if data.len() < padding_len {
            return Err(());
        };
        let mut decoder = Decoder::default();
        let mut buf = data[..data.len() - padding_len].to_vec();
        let mut dst = Vec::new();
        if decoder.decode(&mut buf, &mut dst).is_err() {
            return Err(());
        }

        let mut pseudo_headers = Vec::new();
        for (name, _, _) in dst {
            if let Ok(name) = String::from_utf8(name) {
                if name.starts_with(':') {
                    pseudo_headers.push(name);
                }
            }
        }
        Ok(HeadersFrame {
            stream_id,
            pseudo_headers,
        })
    }
}

#[derive(Debug, Serialize)]
pub struct SettingsFrame {
    pub stream_id: u32,
    pub settings: Vec<Setting>,
}

#[derive(Debug, Serialize)]
pub struct Setting {
    pub id: u16,
    pub value: u32,
}

impl TryFrom<(u32, &[u8])> for SettingsFrame {
    type Error = ();

    fn try_from((stream_id, payload): (u32, &[u8])) -> Result<Self, ()> {
        let settings = payload
            .chunks_exact(6)
            .map(|data| Setting {
                id: u16::from_be_bytes([data[0], data[1]]),
                value: u32::from_be_bytes([data[2], data[3], data[4], data[5]]),
            })
            .collect();
        Ok(SettingsFrame {
            stream_id,
            settings,
        })
    }
}

#[derive(Debug, Serialize)]
pub struct PriorityFrame {
    pub stream_id: u32,
    pub priority: Priority,
}

#[derive(Debug, Serialize)]
pub struct Priority {
    pub dep_stream_id: u32,
    pub weight: u8,
    pub exclusive: bool,
}

impl TryFrom<(u32, &[u8])> for PriorityFrame {
    type Error = ();

    fn try_from((stream_id, payload): (u32, &[u8])) -> Result<Self, ()> {
        if payload.len() != 5 {
            return Err(());
        }
        let exclusive = payload[0] & 0x80 != 0;
        let dep_stream_id =
            u32::from_be_bytes([payload[0] & 0x7f, payload[1], payload[2], payload[3]]);
        Ok(PriorityFrame {
            stream_id,
            priority: Priority {
                dep_stream_id,
                weight: payload[4],
                exclusive,
            },
        })
    }
}

#[derive(Debug, Serialize)]
pub struct WindowUpdateFrame {
    pub stream_id: u32,
    pub window_size_increment: u32,
}

impl TryFrom<(u32, &[u8])> for WindowUpdateFrame {
    type Error = ();

    fn try_from((stream_id, payload): (u32, &[u8])) -> Result<Self, ()> {
        if payload.len() != 4 {
            return Err(());
        }
        let window_size_increment =
            u32::from_be_bytes([payload[0] & 0x7f, payload[1], payload[2], payload[3]]);
        Ok(WindowUpdateFrame {
            stream_id,
            window_size_increment,
        })
    }
}
