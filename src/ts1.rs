use crate::{
    http2::Frame,
    tls::{is_not_grease, TlsHandshake},
};
use base64::{engine::general_purpose, Engine as _};
use rustls::{
    internal::msgs::{codec::Codec, enums::ExtensionType, handshake::ClientExtension},
    ProtocolVersion,
};
use serde::Serialize;
use serde_derive::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Clone, Serialize)]
pub struct Ts1Signature {
    pub client_hello: Ts1ClientHello,
}

#[derive(Clone, Serialize)]
pub struct Ts1ClientHello {
    #[serde(serialize_with = "serialize_version")]
    pub record_version: ProtocolVersion,

    #[serde(serialize_with = "serialize_version")]
    pub handshake_version: ProtocolVersion,

    pub ciphersuites: Vec<Value>,
    pub comp_methods: Vec<u8>,
    pub extensions: Vec<TlsExtension>,
    pub sesion_id_length: usize,
}

fn serialize_version<S>(version: &ProtocolVersion, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let text = match version {
        ProtocolVersion::TLSv1_0 => "TLS_VERSION_1_0",
        ProtocolVersion::TLSv1_1 => "TLS_VERSION_1_1",
        ProtocolVersion::TLSv1_2 => "TLS_VERSION_1_2",
        ProtocolVersion::TLSv1_3 => "TLS_VERSION_1_3",
        _ => "",
    };
    text.serialize(serializer)
}

fn grease_list(iter: impl Iterator<Item = u16>) -> impl Iterator<Item = Value> {
    iter.map(|item| {
        if is_not_grease(&item) {
            Value::Number(item.into())
        } else {
            Value::String("GREASE".into())
        }
    })
}

impl Ts1Signature {
    fn new(handshake: &TlsHandshake) -> Self {
        let ciphers = grease_list(
            handshake
                .hello
                .cipher_suites
                .iter()
                .map(|cipher| cipher.get_u16()),
        )
        .collect::<Vec<_>>();

        let comp_methods = handshake
            .hello
            .compression_methods
            .iter()
            .map(|cipher| cipher.get_u8())
            .collect::<Vec<_>>();

        let extensions = handshake
            .hello
            .extensions
            .iter()
            .map(TlsExtension::new)
            .collect();

        Self {
            client_hello: Ts1ClientHello {
                record_version: handshake.record_version,
                handshake_version: handshake.hello.client_version,
                ciphersuites: ciphers,
                comp_methods,
                extensions,
                sesion_id_length: handshake.hello.session_id.len(),
            },
        }
    }
}

#[derive(Clone, Serialize)]
pub struct TlsExtension {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub length: Option<usize>,

    #[serde(flatten)]
    pub inner: ExtensionVariant,
}

impl TlsExtension {
    fn new(ext: &ClientExtension) -> Self {
        let ty = ext.get_type();
        let mut buf = Vec::new();
        ext.encode(&mut buf);
        let data = &buf[4..];

        match ext {
            ClientExtension::ServerName(_) => Self {
                length: None,
                inner: ExtensionVariant::Named(NamedExtension::ServerName),
            },
            ClientExtension::CertificateStatusRequest(_) => {
                let status_request_type = data.first().copied().unwrap_or_default();
                Self {
                    length: Some(data.len()),
                    inner: ExtensionVariant::Named(NamedExtension::StatusRequest {
                        status_request_type,
                    }),
                }
            }
            ClientExtension::NamedGroups(curves) => {
                let supported_groups = grease_list(
                    curves
                        .iter()
                        .map(|curve| curve.get_u16())
                        .filter(is_not_grease),
                )
                .collect();
                Self {
                    length: Some(data.len()),
                    inner: ExtensionVariant::Named(NamedExtension::SupportedGroups {
                        supported_groups,
                    }),
                }
            }
            ClientExtension::ECPointFormats(points) => {
                let ec_point_formats = points.iter().map(|points| points.get_u8()).collect();
                Self {
                    length: Some(data.len()),
                    inner: ExtensionVariant::Named(NamedExtension::EcPointFormats {
                        ec_point_formats,
                    }),
                }
            }
            ClientExtension::SignatureAlgorithms(sigs) => {
                let sig_hash_algs = sigs.iter().map(|points| points.get_u16()).collect();
                Self {
                    length: Some(data.len()),
                    inner: ExtensionVariant::Named(NamedExtension::SignatureAlgorithms {
                        sig_hash_algs,
                    }),
                }
            }
            ClientExtension::Protocols(alpn) => {
                let alpn_list = alpn
                    .iter()
                    .filter_map(|proto| std::str::from_utf8(&proto.0).ok())
                    .map(|s| s.to_string())
                    .collect();
                Self {
                    length: Some(data.len()),
                    inner: ExtensionVariant::Named(
                        NamedExtension::ApplicationLayerProtocolNegotiation { alpn_list },
                    ),
                }
            }
            ClientExtension::Unknown(r) if r.typ == ExtensionType::Padding => Self {
                length: None,
                inner: ExtensionVariant::Named(NamedExtension::Padding),
            },
            _ if ty.get_u16() == 0x16 => Self {
                length: Some(data.len()),
                inner: ExtensionVariant::Named(NamedExtension::EncryptThenMac),
            },
            _ => {
                if is_not_grease(&ty.get_u16()) {
                    Self {
                        length: Some(data.len()),
                        inner: ExtensionVariant::Unknown {
                            ext_type: ext.get_type().get_u16(),
                        },
                    }
                } else {
                    let data = general_purpose::STANDARD.encode(data);
                    Self {
                        length: Some(data.len()),
                        inner: ExtensionVariant::Named(NamedExtension::Grease { data }),
                    }
                }
            }
        }
    }
}

#[derive(Clone, Serialize)]
#[serde(untagged)]
pub enum ExtensionVariant {
    Named(NamedExtension),
    Unknown {
        #[serde(rename = "type")]
        ext_type: u16,
    },
}

#[derive(Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum NamedExtension {
    ServerName,
    Padding,
    StatusRequest {
        status_request_type: u8,
    },
    SupportedGroups {
        supported_groups: Vec<Value>,
    },
    EcPointFormats {
        ec_point_formats: Vec<u8>,
    },
    SignatureAlgorithms {
        sig_hash_algs: Vec<u16>,
    },
    ApplicationLayerProtocolNegotiation {
        alpn_list: Vec<String>,
    },
    EncryptThenMac,

    #[serde(rename = "GREASE")]
    Grease {
        #[serde(skip_serializing_if = "String::is_empty")]
        data: String,
    },
}

#[derive(Clone, Serialize)]
pub struct Ts1Tls {
    pub sha1: String,
    pub text: String,
}

impl Ts1Tls {
    pub fn new(handshake: &TlsHandshake) -> Self {
        let signature = Ts1Signature::new(handshake);
        let value = serde_json::to_value(signature).unwrap_or_default();
        let text = canonical_json(value);
        Self {
            sha1: sha1_smol::Sha1::from(&text).hexdigest(),
            text,
        }
    }
}

#[derive(Clone, Serialize)]
pub struct Ts1Http2 {
    pub sha1: String,
    pub text: String,
}

impl Ts1Http2 {
    pub fn new(frames: &[Frame]) -> Self {
        let frames = frames
            .iter()
            .map(|frame| match frame {
                Frame::Unknown(ty) => FrameSignature::Unnamed { frame_type: *ty },
                _ => FrameSignature::Named(frame),
            })
            .collect::<Vec<_>>();
        let value = serde_json::to_value(frames).unwrap_or_default();
        let text = canonical_json(value);
        Self {
            sha1: sha1_smol::Sha1::from(&text).hexdigest(),
            text,
        }
    }
}

#[derive(Serialize)]
#[serde(untagged)]
enum FrameSignature<'a> {
    Named(&'a Frame),
    Unnamed { frame_type: u8 },
}

fn canonical_json(value: Value) -> String {
    match value {
        Value::Array(array) => {
            let inner = array
                .into_iter()
                .map(canonical_json)
                .collect::<Vec<_>>()
                .join(", ");
            format!("[{inner}]")
        }
        Value::Object(object) => {
            let inner = object
                .into_iter()
                .collect::<BTreeMap<_, _>>()
                .into_iter()
                .map(|(key, value)| format!("{}: {}", Value::String(key), canonical_json(value)))
                .collect::<Vec<_>>()
                .join(", ");
            format!("{{{inner}}}")
        }
        _ => value.to_string(),
    }
}
