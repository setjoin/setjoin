//! Go-compatible MTA-STS HTTPS transport over the shared SSRF guard.
use futures_util::future::BoxFuture;
use setjoin_smtp::outbound::PolicyFetch;
use std::io::Write;

const LIMIT: usize = 65536;
pub struct HttpPolicyFetch {
    client: reqwest::Client,
    guard: bool,
}
impl Default for HttpPolicyFetch {
    fn default() -> Self {
        Self::new()
    }
}
impl HttpPolicyFetch {
    pub fn new() -> Self {
        Self {
            client: crate::webhook::safe_http_client(std::time::Duration::from_secs(10)),
            guard: true,
        }
    }
    /// Trust/dial seam for a caller-owned local TLS peer, never production wiring.
    pub fn with_client_for_tests(client: reqwest::Client) -> Self {
        Self {
            client,
            guard: false,
        }
    }
}
#[derive(Default)]
struct Bounded(Vec<u8>);
impl Write for Bounded {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        let n = bytes.len().min(LIMIT - self.0.len());
        if n == 0 {
            return Err(std::io::Error::other("decoded policy body limit"));
        }
        self.0.extend_from_slice(&bytes[..n]);
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl PolicyFetch for HttpPolicyFetch {
    fn get<'a>(&'a self, url: &'a str) -> BoxFuture<'a, Result<Vec<u8>, String>> {
        Box::pin(async move {
            let parsed = url::Url::parse(url).map_err(|e| e.to_string())?;
            if parsed.scheme() != "https" || (self.guard && !crate::ssrf::valid_url(url)) {
                return Err("MTA-STS policy URL must be HTTPS to a public host".into());
            }
            let mut response = self
                .client
                .get(parsed)
                .header(reqwest::header::ACCEPT_ENCODING, "gzip")
                .send()
                .await
                .map_err(|e| e.to_string())?;
            if response.status() != reqwest::StatusCode::OK {
                return Err(format!(
                    "httpsGet: {url} returned {}",
                    response.status().as_u16()
                ));
            }
            let gzip = response
                .headers()
                .get(reqwest::header::CONTENT_ENCODING)
                .and_then(|v| v.to_str().ok())
                .is_some_and(|s| s.eq_ignore_ascii_case("gzip"));
            if gzip {
                // Go's Transport decompresses gzip before LimitReader applies.
                // Bound the decoder's output too: a compressed bomb never builds
                // an unbounded buffer while the HTTP deadline remains in force.
                let mut decoder = flate2::write::GzDecoder::new(Bounded::default());
                while let Some(chunk) = response.chunk().await.map_err(|e| e.to_string())? {
                    let result = decoder.write_all(&chunk);
                    if decoder.get_ref().0.len() == LIMIT {
                        return Ok(decoder.get_ref().0.clone());
                    }
                    result.map_err(|e| e.to_string())?;
                }
                decoder.try_finish().map_err(|e| e.to_string())?;
                Ok(decoder.get_ref().0.clone())
            } else {
                let mut body = Vec::new();
                while let Some(chunk) = response.chunk().await.map_err(|e| e.to_string())? {
                    let n = chunk.len().min(LIMIT - body.len());
                    body.extend_from_slice(&chunk[..n]);
                    if body.len() == LIMIT {
                        break;
                    }
                }
                Ok(body)
            }
        })
    }
}
