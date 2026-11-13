//! Go's `ssrf.ValidateURL`: the cheap fail-fast check at subscribe time. A host
//! name that later resolves to an internal address is the fetcher's dial-time
//! guard to refuse; this only rejects bad schemes, missing hosts and literal
//! internal addresses.
use std::net::IpAddr;
pub use setjoin_authz::ssrf::blocked;

/// `true` when Go's `ValidateURL` accepts `raw`.
pub fn valid_url(raw: &str) -> bool {
    let Ok(url) = url::Url::parse(raw) else {
        return false;
    };
    if url.scheme() != "http" && url.scheme() != "https" {
        return false;
    }
    match url.host() {
        None => false,
        Some(url::Host::Domain(domain)) => !domain.is_empty(),
        Some(url::Host::Ipv4(ip)) => !blocked(IpAddr::V4(ip)),
        Some(url::Host::Ipv6(ip)) => !blocked(IpAddr::V6(ip)),
    }
}
