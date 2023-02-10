use rustls::internal::msgs::handshake::ClientHelloPayload;
use serde_derive::Serialize;

use crate::ja3::Ja3;

#[derive(Serialize)]
pub struct Report {
    pub tls: Option<TlsReport>,
}

#[derive(Serialize)]
pub struct TlsReport {
    pub ja3: Ja3,
    pub ja3_sort_ext: Ja3,
}

impl Report {
    pub fn new(hello: Option<&ClientHelloPayload>) -> Self {
        let tls = hello.map(|hello| TlsReport {
            ja3: Ja3::new(hello, false),
            ja3_sort_ext: Ja3::new(hello, true),
        });
        Self { tls }
    }
}
