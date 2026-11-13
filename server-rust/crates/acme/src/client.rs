//! ACME HTTP transport over `reqwest` with the system trust roots (the stack the rest of the
//! workspace already vets), so `instant-acme`'s own `hyper-rustls` client and its platform-verifier
//! dependency tree stay out of the build. A private test CA (pebble) can be trusted explicitly.
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use instant_acme::{BodyWrapper, BytesResponse, Error, HttpClient};
use std::{future::Future, path::Path, pin::Pin};

pub struct Transport(reqwest::Client);

fn other(e: impl std::error::Error + Send + Sync + 'static) -> Error {
    Error::Other(Box::new(e))
}

impl Transport {
    pub fn new(extra_root: Option<&Path>) -> Result<Self, String> {
        let mut builder = reqwest::Client::builder().timeout(std::time::Duration::from_secs(30));
        if let Some(path) = extra_root {
            let pem = std::fs::read(path).map_err(|e| format!("acme: read CA root: {e}"))?;
            let cert = reqwest::Certificate::from_pem(&pem).map_err(|e| format!("acme: CA root: {e}"))?;
            builder = builder.add_root_certificate(cert);
        }
        builder.build().map(Self).map_err(|e| format!("acme: http client: {e}"))
    }
}

impl HttpClient for Transport {
    fn request(
        &self,
        req: http::Request<BodyWrapper<Bytes>>,
    ) -> Pin<Box<dyn Future<Output = Result<BytesResponse, Error>> + Send>> {
        let client = self.0.clone();
        Box::pin(async move {
            let (parts, body) = req.into_parts();
            let payload = body.collect().await.map_err(other)?.to_bytes();
            let response = client
                .request(parts.method, parts.uri.to_string())
                .headers(parts.headers)
                .body(payload)
                .send()
                .await
                .map_err(other)?;
            let mut builder = http::Response::builder().status(response.status());
            for (name, value) in response.headers() {
                builder = builder.header(name, value);
            }
            let body = response.bytes().await.map_err(other)?;
            Ok(BytesResponse::from(builder.body(Full::new(body)).map_err(other)?))
        })
    }
}
