use anyhow::Result;
use clap::Parser;
use http::Request;
use hyper::{server::conn::Http, service::service_fn, Body};
use std::fs::File;
use std::io::{self, BufReader};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_rustls::rustls::{self, Certificate, PrivateKey};
use tokio_rustls::TlsAcceptor;

mod handler;
mod ja3;
mod report;
mod tls;

use handler::*;
use report::*;
use tls::*;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Socket address
    addr: SocketAddr,

    /// Certificate chain file
    #[arg(long)]
    certs: PathBuf,

    /// Private key file
    #[arg(long)]
    key: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let certs = load_certs(&args.certs)?;
    let key = load_key(&args.key)?;

    let mut config = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    config.alpn_protocols = vec!["h2".as_bytes().to_vec(), "http/1.1".as_bytes().to_vec()];

    let acceptor = TlsAcceptor::from(Arc::new(config));

    println!("🐾 Listening on {}", args.addr);
    let listener = TcpListener::bind(&args.addr).await?;

    loop {
        let (stream, _peer_addr) = listener.accept().await?;
        let acceptor = acceptor.clone();

        let stream = TlsInspctor::new(stream);

        let fut = async move {
            let stream = acceptor.accept(stream).await?;
            let ctx = Arc::new(Report::new(stream.get_ref().0.client_hello()));

            tokio::task::spawn(async move {
                if let Err(http_err) = Http::new()
                    .serve_connection(
                        stream,
                        service_fn(|req: Request<Body>| {
                            let ctx = ctx.clone();
                            async move { handle_request(req, ctx.clone()).await }
                        }),
                    )
                    .await
                {
                    eprintln!("Error while serving HTTP connection: {http_err}");
                }
            });

            Ok(()) as io::Result<()>
        };

        tokio::spawn(async move {
            if let Err(err) = fut.await {
                eprintln!("Error: {err:?}");
            }
        });
    }
}

fn load_certs(path: &Path) -> io::Result<Vec<Certificate>> {
    let mut reader = BufReader::new(File::open(path)?);
    let certs = rustls_pemfile::certs(&mut reader)?;
    Ok(certs.into_iter().map(Certificate).collect())
}

fn load_key(path: &Path) -> Result<PrivateKey> {
    use rustls_pemfile::Item;
    let keyfile = std::fs::File::open(path)?;
    let mut reader = BufReader::new(keyfile);

    while let Some(key) = rustls_pemfile::read_one(&mut reader)? {
        match key {
            Item::RSAKey(key) | Item::PKCS8Key(key) | Item::ECKey(key) => {
                return Ok(PrivateKey(key))
            }
            _ => {}
        }
    }

    Err(anyhow::anyhow!("key not found"))
}
