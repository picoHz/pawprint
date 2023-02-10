use crate::report::Report;
use http::{Request, Response, StatusCode};
use hyper::Body;
use include_dir::{include_dir, Dir};
use sailfish::TemplateOnce;
use std::{convert::Infallible, path::Path, sync::Arc};

static STATIC_DIR: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/static");

#[derive(TemplateOnce)]
#[template(path = "index.stpl")]
struct IndexTemplate {
    report: Arc<Report>,
}

pub async fn handle_request(
    req: Request<Body>,
    report: Arc<Report>,
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
                .body(Body::from(
                    serde_json::to_string_pretty(report.as_ref()).unwrap(),
                ))
                .unwrap())
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
    match ext {
        "css" => "text/css",
        "png" => "image/png",
        "svg" => "image/svg+xml",
        "ico" => "image/x-icon",
        "xml" | "webmanifest" => "application/xml",
        _ => "application/octet-stream",
    }
}