use clap::Parser;
use http::StatusCode;
use http::{
    HeaderMap, HeaderValue, Request, Response, Version, method::Method, response, uri::PathAndQuery,
};
use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::service::service_fn;
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder,
};
use rustls::ServerConfig;
use rustls::pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::fs::read;
use tokio::net::TcpListener;
use tokio_rustls::{TlsAcceptor, rustls};
use tracing::{error, info, trace_span, warn};
fn clean_path<'a>(path: &'a str) -> String {
    let mut root = String::from("assets/");
    root.push_str(
        &path
            .trim_start_matches("/")
            .replace("../", "")
            .replace("./", ""),
    );
    println!("{}", root);
    root
}
async fn handle_post_request<T>(
    path_and_query: &PathAndQuery,
    headers: &HeaderMap<HeaderValue>,
    body: &T,
) -> () {
    if let Some(object) = path_and_query.path().strip_prefix("/target") {
        if let Some(method) = object.strip_prefix("/ip_addr") {
            match method {
                "" => {}
                "/location" => {}
                "/" => {}
                _ => {}
            }
        }
    }
}

async fn handle_get_request(path_and_query: &PathAndQuery) -> io::Result<Response<Full<Bytes>>> {
    match read(clean_path(path_and_query.path())).await {
        Ok(o) => Ok(Response::builder()
            .status(StatusCode::OK)
            .version(Version::HTTP_3)
            .body(Full::new(Bytes::from(o)))
            .unwrap()),
        Err(e) => Err(e),
    }
}
//async fn handle_get_request() {}

const _404: Bytes = Bytes::from_static(&[]);
async fn handle_request(request: Request<Incoming>) -> Result<Response<Full<Bytes>>, http::Error> {
    match request.method() {
        &Method::GET => match handle_get_request(request.uri().path_and_query().unwrap()).await {
            Ok(o) => Ok(o),
            Err(e) => Ok(Response::builder()
                .status(404)
                .version(Version::HTTP_3)
                .body(Full::new(_404))?),
        },
        &Method::CONNECT => match request.uri() {
            _ => Ok(Response::builder()
                .status(502)
                .version(Version::HTTP_3)
                .body(Full::new(_404))?),
        },
        _ => {
            return Ok(Response::builder()
                .status(405)
                .version(Version::HTTP_3)
                .body(Full::new(_404))?);
        }
    }
}
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_span_events(tracing_subscriber::fmt::format::FmtSpan::FULL)
        .with_writer(std::io::stderr)
        .with_max_level(tracing::Level::INFO)
        .init();

    let addr = "127.0.0.1:8080".parse::<SocketAddr>()?;
    let certs = CertificateDer::pem_file_iter("cert.pem")?.collect::<Result<Vec<_>, _>>()?;
    let key = PrivateKeyDer::from_pem_file("key.pem")?;
    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    let acceptor = TlsAcceptor::from(Arc::new(server_config));
    let listener = TcpListener::bind(&addr).await?;
    info!("listening on {}", addr);
    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            let stream = acceptor.accept(stream).await?;
            match Builder::new(TokioExecutor::new())
                .serve_connection_with_upgrades(TokioIo::new(stream), service_fn(handle_request))
                .await
            {
                Ok(o) => {
                    info!("{:?}", o)
                }
                Err(e) => {
                    warn!("Error Hanling server accept {}", e)
                }
            }
            Ok(()) as std::io::Result<()>
        });
    }
}
