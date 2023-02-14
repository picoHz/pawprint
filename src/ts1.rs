use crate::http2::Frame;
use serde_derive::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;

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
