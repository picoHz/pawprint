use crate::report::Report;
use http::{Request, Response, StatusCode};
use hyper::Body;
use include_dir::{include_dir, Dir};
use sailfish::TemplateOnce;
use serde_querystring::UrlEncodedQS;
use std::{convert::Infallible, path::Path};

static STATIC_DIR: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/static");

#[derive(TemplateOnce)]
#[template(path = "index.stpl")]
struct IndexTemplate {
    report: Report,
}

const IDENTICON_SIZE: usize = 32;

pub async fn handle_request(
    req: Request<Body>,
    report: Report,
) -> Result<Response<Body>, Infallible> {
    let path = req.uri().path();
    match path {
        "/" => {
            let ctx = IndexTemplate { report };
            return Ok(Response::builder()
                .header("Content-Type", "text/html")
                .body(Body::from(ctx.render_once().unwrap()))
                .unwrap());
        }
        "/index.json" => {
            return Ok(Response::builder()
                .header("Content-Type", "application/json")
                .body(Body::from(serde_json::to_string_pretty(&report).unwrap()))
                .unwrap());
        }
        "/identicon.png" => {
            let query = req.uri().query().unwrap_or_default();
            let hex = UrlEncodedQS::parse(query.as_bytes())
                .value(b"hex")
                .flatten()
                .unwrap_or_default();
            let seed = hex::decode(hex).unwrap_or_default();
            let data =
                eth_blockies::eth_blockies_png_data(seed, (IDENTICON_SIZE, IDENTICON_SIZE), true);
            return Ok(Response::builder()
                .header("Content-Type", "image/png")
                .body(Body::from(data))
                .unwrap());
        }
        _ => {}
    }

    if let Some(file) = STATIC_DIR.get_file(path.trim_start_matches('/')) {
        return Ok(Response::builder()
            .header("Content-Type", path_to_mime(path))
            .body(Body::from(file.contents()))
            .unwrap());
    }

    Ok(Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(Body::from("404"))
        .unwrap())
}

fn path_to_mime(path: &str) -> &'static str {
    let ext = Path::new(path)
        .extension()
        .unwrap_or_default()
        .to_str()
        .unwrap_or_default();
    mimext::ext_to_mime(ext)
        .get(0)
        .unwrap_or(&"application/octet-stream")
}
