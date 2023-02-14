use std::collections::BTreeMap;

use crate::http2::Frame;
use serde_derive::Serialize;
use serde_json::Value;

#[derive(Clone, Serialize)]
pub struct Ts1Http2 {
    pub sha1: String,
    pub text: String,
}

impl Ts1Http2 {
    pub fn new(frames: &[Frame]) -> Self {
        let last = frames
            .iter()
            .position(|frame| matches!(frame, Frame::Headers(_)))
            .unwrap_or(0);
        let value = serde_json::to_value(&frames[..last + 1]).unwrap_or_default();
        let text = canonical_json(value);
        Self {
            sha1: sha1_smol::Sha1::from(&text).hexdigest(),
            text,
        }
    }
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
                .map(|(key, value)| format!("{key}: {}", canonical_json(value)))
                .collect::<Vec<_>>()
                .join(", ");
            format!("{{{inner}}}")
        }
        _ => value.to_string(),
    }
}
