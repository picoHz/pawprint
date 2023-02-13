use rustls::internal::msgs::handshake::ClientHelloPayload;
use serde_derive::Serialize;

use crate::{akamai::Akamai, http2::Frame, ja3::Ja3};

#[derive(Clone, Serialize)]
pub struct Report {
    pub tls: Option<TlsReport>,
    pub http2: Option<Http2Report>,
}

#[derive(Clone, Serialize)]
pub struct TlsReport {
    pub ja3: Ja3,
    pub ja3_sort_ext: Ja3,
}

impl TlsReport {
    pub fn new(hello: &ClientHelloPayload) -> Self {
        Self {
            ja3: Ja3::new(hello, false),
            ja3_sort_ext: Ja3::new(hello, true),
        }
    }
}

#[derive(Clone, Serialize)]
pub struct Http2Report {
    pub akamai: Akamai,
}

impl Http2Report {
    pub fn new(frames: &[Frame]) -> Option<Self> {
        if frames.is_empty() {
            None
        } else {
            Some(Self {
                akamai: Akamai::new(frames),
            })
        }
    }
}
