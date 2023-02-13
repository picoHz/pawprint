use rustls::internal::msgs::handshake::{ClientExtension, ClientHelloPayload};
use serde_derive::Serialize;

#[derive(Clone, Serialize)]
pub struct Ja3 {
    pub md5: String,
    pub str: String,
}

impl Ja3 {
    pub fn new(hello: &ClientHelloPayload, sort_ext: bool) -> Self {
        let version = hello.client_version.get_u16();
        let ciphers = hello
            .cipher_suites
            .iter()
            .map(|cipher| cipher.get_u16())
            .filter(is_not_grease)
            .map(|n| n.to_string())
            .collect::<Vec<_>>();
        let ciphers = ciphers.join("-");

        let mut extensions = hello
            .extensions
            .iter()
            .map(|ext| ext.get_type().get_u16())
            .filter(is_not_grease)
            .map(|n| n.to_string())
            .collect::<Vec<_>>();

        if sort_ext {
            extensions.sort();
        }

        let extensions = extensions.join("-");

        let curves = hello
            .extensions
            .iter()
            .filter_map(|ext| match ext {
                ClientExtension::NamedGroups(curves) => Some(curves),
                _ => None,
            })
            .flatten()
            .map(|curve| curve.get_u16())
            .filter(is_not_grease)
            .map(|n| n.to_string())
            .collect::<Vec<_>>();
        let curves = curves.join("-");

        let points = hello
            .extensions
            .iter()
            .filter_map(|ext| match ext {
                ClientExtension::ECPointFormats(points) => Some(points),
                _ => None,
            })
            .flatten()
            .map(|points| points.get_u8())
            .map(|n| n.to_string())
            .collect::<Vec<_>>();
        let points = points.join("-");

        let ja3 = format!("{version},{ciphers},{extensions},{curves},{points}");
        let md5 = md5::compute(&ja3);

        Self {
            md5: format!("{md5:x}"),
            str: ja3,
        }
    }
}

fn is_not_grease(v: &u16) -> bool {
    *v & 0x0f0f != 0x0a0a
}
