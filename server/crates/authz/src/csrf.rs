//! Go's CSRF Origin/Referer check (`shared/middleware/csrf.go`) for the
//! unsafe HTTP methods, evaluated against what Go would see behind
//! the gateway: `X-Forwarded-Host` = the inbound `Host` (falling back to the
//! same `Host` when it is not a single host token) and `X-Forwarded-Proto` =
//! the gateway's resolved scheme. `false` means Go would answer 403, so the
//! global HTTP boundary answers the denial.

use hyper::header::{HeaderMap, HOST};

pub fn allows(headers: &HeaderMap, scheme: &str) -> bool {
    let header = |name: &str| -> Option<Option<&str>> {
        match headers.get(name) {
            None => Some(None),
            Some(v) => v.to_str().ok().map(Some),
        }
    };
    let (Some(host), Some(origin), Some(referer), Some(fetch_site)) = (
        header(HOST.as_str()),
        header("origin"),
        header("referer"),
        header("sec-fetch-site"),
    ) else {
        return false; // non-UTF-8 header: let Go decide
    };
    let host = host.unwrap_or("");
    let expected = sanitized_host(host).unwrap_or(host);

    // Go's Header.Get returns the first value; empty counts as absent.
    if let Some(origin) = origin.filter(|o| !o.is_empty()) {
        return origin_matches(origin, expected, scheme);
    }
    if let Some(referer) = referer.filter(|r| !r.is_empty()) {
        if !origin_matches(referer, expected, scheme) {
            return false;
        }
    }
    fetch_site != Some("cross-site")
}

fn sanitized_host(v: &str) -> Option<&str> {
    (!v.is_empty()
        && v.len() <= 255
        && v.bytes().all(|c| {
            c.is_ascii_alphanumeric() || matches!(c, b'.' | b'-' | b'_' | b':' | b'[' | b']')
        }))
    .then_some(v)
}

/// The same parsed scheme/host tuple as frozen Go's net/url.
fn origin_matches(raw: &str, expected_host: &str, scheme: &str) -> bool {
    let Ok(parsed) = crate::go_url::go_url_parse(raw) else {
        return false;
    };
    if parsed.host.is_empty() || !parsed.scheme.eq_ignore_ascii_case(scheme) {
        return false;
    }
    let (host, port) = split_host_port(&parsed.host, &parsed.scheme);
    let (want_host, want_port) = split_host_port(expected_host, scheme);
    host.eq_ignore_ascii_case(want_host) && port == want_port
}

fn split_host_port<'a>(hostport: &'a str, scheme: &str) -> (&'a str, &'a str) {
    let default = if scheme.eq_ignore_ascii_case("https") {
        "443"
    } else {
        "80"
    };
    // Bracketed IPv6 literal: "[v6]:port" or portless "[v6]". Strip brackets
    // in both forms so equivalent origins like "[::1]" and "[::1]:443" match.
    if let Some(stripped) = hostport.strip_prefix('[') {
        if let Some((h, p)) = stripped.split_once("]:") {
            if !h.is_empty() && !h.contains(['[', ']']) {
                return (h, p);
            }
        }
        if let Some(h) = stripped.strip_suffix(']') {
            if !h.is_empty() && !h.contains(['[', ']']) {
                return (h, default);
            }
        }
        return (hostport, default);
    }
    match hostport.split_once(':') {
        Some((h, p)) if !p.contains(':') => (h, p),
        _ => (hostport, default),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::HeaderValue;

    fn h(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
        let mut m = HeaderMap::new();
        for (k, v) in pairs {
            m.append(*k, HeaderValue::from_static(v));
        }
        m
    }

    #[test]
    fn same_origin_and_headerless_clients_pass() {
        let host = ("host", "mail.example.com");
        assert!(allows(
            &h(&[host, ("origin", "https://mail.example.com")]),
            "https"
        ));
        assert!(allows(
            &h(&[host, ("origin", "https://mail.example.com:443")]),
            "https"
        ));
        assert!(allows(
            &h(&[
                ("host", "localhost:38090"),
                ("origin", "http://localhost:38090")
            ]),
            "http"
        ));
        assert!(allows(
            &h(&[host, ("referer", "https://mail.example.com/inbox")]),
            "https"
        ));
        assert!(
            allows(&h(&[host]), "https"),
            "native/curl clients send neither"
        );
    }

    #[test]
    fn what_go_rejects_is_not_served() {
        let host = ("host", "mail.example.com");
        for headers in [
            h(&[host, ("origin", "https://evil.example")]),
            h(&[host, ("origin", "http://mail.example.com")]),
            h(&[host, ("origin", "https://mail.example.com:8443")]),
            h(&[host, ("origin", "null")]),
            h(&[host, ("referer", "https://evil.example/x")]),
            h(&[host, ("sec-fetch-site", "cross-site")]),
        ] {
            assert!(!allows(&headers, "https"), "{headers:?}");
        }
    }

    #[test]
    fn ipv6_origins_with_and_without_ports_normalize_consistently() {
        for (scheme, host, origin) in [
            ("https", "[::1]", "https://[::1]"),
            ("https", "[::1]", "https://[::1]:443"),
            ("https", "[::1]:443", "https://[::1]"),
            ("https", "[::1]:443", "https://[::1]:443"),
            ("http", "[::1]", "http://[::1]"),
            ("http", "[::1]", "http://[::1]:80"),
            ("http", "[::1]:80", "http://[::1]"),
            ("http", "[::1]:80", "http://[::1]:80"),
            ("https", "[::1]:8443", "https://[::1]:8443"),
            ("https", "[2001:DB8::1]", "https://[2001:db8::1]:443"),
            ("https", "[2001:db8::1]:443", "https://[2001:DB8::1]"),
        ] {
            assert!(
                allows(&h(&[("host", host), ("origin", origin)]), scheme),
                "expected allow: scheme={scheme} host={host} origin={origin}"
            );
            assert!(
                allows(&h(&[("host", host), ("referer", origin)]), scheme),
                "expected referer allow: scheme={scheme} host={host} referer={origin}"
            );
        }

        for (scheme, host, origin) in [
            ("https", "[::1]", "https://[::1]:8443"),
            ("https", "[::1]:8443", "https://[::1]"),
            ("https", "[::1]", "https://[::1]:80"),
            ("http", "[::1]", "http://[::1]:443"),
            ("https", "[::1]", "http://[::1]"),
            ("https", "[::1]", "https://[::2]"),
            ("https", "[::1]", "https://[::2]:443"),
            ("https", "[::1]:443", "https://[::2]"),
            ("https", "[::1]", "https://[::1]:"),
            ("https", "[::1]", "https://[::1"),
        ] {
            assert!(
                !allows(&h(&[("host", host), ("origin", origin)]), scheme),
                "expected deny: scheme={scheme} host={host} origin={origin}"
            );
        }
    }
}
