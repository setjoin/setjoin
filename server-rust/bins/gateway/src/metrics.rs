//! Counts attempted forwards at the Go boundary, including failed dials and
//! requests a Rust adapter declines. Fixed family labels bound cardinality.

use std::sync::atomic::{AtomicU64, Ordering};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::Response;

use crate::Body;

pub const PATH: &str = "/_gateway/metrics";

/// 1 when the continuity signing key did not load, so Continuity/* is left to Go (#377).
pub static CONTINUITY_SIGNER_MISSING: AtomicU64 = AtomicU64::new(0);

pub struct GoProxies([AtomicU64; 23]);

impl Default for GoProxies {
    fn default() -> Self {
        Self(std::array::from_fn(|_| AtomicU64::new(0)))
    }
}

impl GoProxies {
    pub fn increment(&self, family: usize) {
        self.0[family].fetch_add(1, Ordering::Relaxed);
    }

    pub fn response(&self, head: bool) -> Response<Body> {
        let counts: Vec<_> = self.0.iter().map(|c| c.load(Ordering::Relaxed)).collect();
        let mut body = format!(
            "# HELP setjoin_gateway_proxied_to_go_total Requests forwarded to any Go HTTP upstream, including failed attempts.\n# TYPE setjoin_gateway_proxied_to_go_total counter\nsetjoin_gateway_proxied_to_go_total {}\n# HELP setjoin_gateway_proxied_to_go_by_family_total Requests forwarded to Go by route family (F00 is unclassified).\n# TYPE setjoin_gateway_proxied_to_go_by_family_total counter\n",
            counts.iter().sum::<u64>()
        );
        for (family, count) in counts.iter().enumerate() {
            body.push_str(&format!("setjoin_gateway_proxied_to_go_by_family_total{{family=\"F{family:02}\"}} {count}\n"));
        }
        body.push_str(&format!(
            "# HELP setjoin_gateway_jmap_continuity_signer_missing 1 when Continuity/* stays with Go because the signing key did not load.\n# TYPE setjoin_gateway_jmap_continuity_signer_missing gauge\nsetjoin_gateway_jmap_continuity_signer_missing {}\n",
            CONTINUITY_SIGNER_MISSING.load(Ordering::Relaxed)
        ));
        Response::builder()
            .header("content-type", "text/plain; version=0.0.4; charset=utf-8")
            .body(
                Full::new(if head {
                    Bytes::new()
                } else {
                    Bytes::from(body)
                })
                .map_err(|never| match never {})
                .boxed(),
            )
            .expect("static metrics headers")
    }
}
