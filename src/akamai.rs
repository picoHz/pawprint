use serde_derive::Serialize;

use crate::http2::Frame;

#[derive(Clone, Serialize)]
pub struct Akamai {
    pub sha1: String,
    pub str: String,
}

impl Akamai {
    pub fn new(frames: &[Frame]) -> Self {
        let mut settings = Vec::new();
        let mut window_update = "00".to_string();
        let mut priority_frames = Vec::new();
        let mut headers = Vec::new();
        for frame in frames {
            match frame {
                Frame::Settings(frame) => {
                    for item in &frame.settings {
                        settings.push(format!("{}:{}", item.id, item.value));
                    }
                }
                Frame::WindowUpdate(frame) => {
                    window_update = frame.window_size_increment.to_string();
                }
                Frame::Priority(frame) => {
                    let stream_id = frame.stream_id;
                    let exlusive = frame.priority.exclusive as u8;
                    let dep_stream_id = frame.priority.dep_stream_id;
                    let weight = frame.priority.weight;
                    priority_frames
                        .push(format!("{stream_id}:{exlusive}:{dep_stream_id}:{weight}"));
                }
                Frame::Headers(frame) => {
                    headers = frame
                        .pseudo_headers
                        .iter()
                        .filter_map(|header| match header.as_str() {
                            ":method" => Some("m"),
                            ":path" => Some("p"),
                            ":authority" => Some("a"),
                            ":scheme" => Some("s"),
                            _ => None,
                        })
                        .collect::<Vec<_>>();
                }
            }
        }
        let settings = settings.join(";");
        let priority_frames = if priority_frames.is_empty() {
            "0".to_string()
        } else {
            priority_frames.join(",")
        };
        let headers = if headers.is_empty() {
            String::new()
        } else {
            format!("|{}", headers.join(","))
        };
        let str = format!("{settings}|{window_update}|{priority_frames}{headers}");
        Self {
            sha1: sha1_smol::Sha1::from(&str).hexdigest(),
            str,
        }
    }
}
