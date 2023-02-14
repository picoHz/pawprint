use crate::{
    akamai::Akamai,
    http2::Frame,
    ja3::Ja3,
    tls::TlsHandshake,
    ts1::{Ts1Http2, Ts1Tls},
};
use serde_derive::Serialize;

#[derive(Clone, Serialize)]
pub struct Report {
    pub tls: Option<TlsReport>,
    pub http2: Option<Http2Report>,
}

#[derive(Clone, Serialize)]
pub struct TlsReport {
    pub ja3: Ja3,
    pub ja3_sort_ext: Ja3,
    pub ts1: Ts1Tls,
}

impl TlsReport {
    pub fn new(handshake: &TlsHandshake) -> Self {
        Self {
            ja3: Ja3::new(&handshake.hello, false),
            ja3_sort_ext: Ja3::new(&handshake.hello, true),
            ts1: Ts1Tls::new(handshake),
        }
    }
}

#[derive(Clone, Serialize)]
pub struct Http2Report {
    pub akamai: Akamai,
    pub ts1: Ts1Http2,
}

impl Http2Report {
    pub fn new(frames: &[Frame]) -> Option<Self> {
        if frames.is_empty() {
            None
        } else {
            Some(Self {
                akamai: Akamai::new(frames),
                ts1: Ts1Http2::new(frames),
            })
        }
    }
}
