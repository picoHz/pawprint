use rustls::internal::msgs::codec::{Codec, Reader};
use rustls::internal::msgs::handshake::{
    ClientHelloPayload, HandshakeMessagePayload, HandshakePayload,
};
use rustls::internal::msgs::message::{Message, MessagePayload, OpaqueMessage};
use rustls::ProtocolVersion;
use std::io::IoSlice;
use std::pin::Pin;
use std::task;
use std::task::Poll;
use tokio::io::{self, AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

pin_project_lite::pin_project! {
    pub struct TlsInspctor {
        #[pin]
        inner: TcpStream,

        buf: Vec<u8>,
        handshake: Option<TlsHandshake>,
    }
}

impl TlsInspctor {
    pub fn new(inner: TcpStream) -> TlsInspctor {
        Self {
            inner,
            buf: Vec::new(),
            handshake: None,
        }
    }

    pub fn handshake(&self) -> Option<&TlsHandshake> {
        self.handshake.as_ref()
    }
}

impl AsyncRead for TlsInspctor {
    #[inline]
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let len = buf.filled().len();
        let me = self.project();
        let poll = me.inner.poll_read(cx, buf);

        if me.handshake.is_none() {
            me.buf.extend(&buf.filled()[len..]);
            *me.handshake = parse_client_hello(me.buf);
        }

        poll
    }
}

impl AsyncWrite for TlsInspctor {
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

fn parse_client_hello(data: &[u8]) -> Option<TlsHandshake> {
    let mut reader = Reader::init(data);
    let msg = OpaqueMessage::read(&mut reader).ok()?;
    let msg = TryInto::<Message>::try_into(msg.into_plain_message()).ok()?;
    if let MessagePayload::Handshake {
        parsed:
            HandshakeMessagePayload {
                payload: HandshakePayload::ClientHello(payload),
                ..
            },
        ..
    } = msg.payload
    {
        let version = ProtocolVersion::read_bytes(&data[1..]).unwrap();
        Some(TlsHandshake {
            record_version: version,
            hello: payload,
        })
    } else {
        None
    }
}

#[derive(Debug)]
pub struct TlsHandshake {
    pub record_version: ProtocolVersion,
    pub hello: ClientHelloPayload,
}

pub fn is_not_grease(v: &u16) -> bool {
    *v & 0x0f0f != 0x0a0a
}
