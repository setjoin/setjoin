//! Frozen Go's ServeMux answer for an `/auth/*` spelling no inventory row claims
//! (#357, #378). Every `/auth` registration sits on the pinned API mux, so a bare
//! spelling of a subtree registration (`/auth/totp`, `/auth/%74otp`) gets ServeMux's
//! trailing-slash redirect; anything else falls to the root fallback (SPA or 404).
use crate::inventory::Inventory;
use crate::Body;
use hyper::header::HeaderValue;
use hyper::{Method, Request, Response, StatusCode};

/// ServeMux's redirect when only `path + "/"` names an F21 subtree registration.
/// Matching uses decoded segments (Go's `exactMatch`); an escaped `/` stays inside its
/// segment and never matches. `Location` is the row literal plus the raw query.
pub(crate) fn slash_redirect(
    inventory: &Inventory,
    r: &Request<Body>,
    proto: &'static str,
) -> Option<Response<Body>> {
    let raw = r.uri().path();
    if !raw.starts_with("/auth/") || raw.ends_with('/') || *r.method() == Method::CONNECT {
        return None;
    }
    let mut decoded = String::new();
    for segment in raw.split('/').skip(1) {
        let bytes = crate::inventory::unescape(segment);
        if bytes.contains(&b'/') {
            return None;
        }
        decoded.push('/');
        decoded.push_str(std::str::from_utf8(&bytes).ok()?);
    }
    let slash = format!("{decoded}/");
    let route = inventory.find(r.method(), &slash)?;
    if route.family != 21 || route.path != slash || !route.path.starts_with("/auth/") {
        return None;
    }
    let location = match r.uri().query() {
        Some(query) if !query.is_empty() => format!("{slash}?{query}"),
        _ => slash,
    };
    Some(redirect(r, proto, &location))
}

fn redirect(r: &Request<Body>, proto: &'static str, location: &str) -> Response<Body> {
    let id = crate::jmap::reply::request_id(
        r.headers().get("x-request-id"),
        crate::jmap::random().unwrap_or([0; 16]),
    );
    let body = if *r.method() == Method::GET {
        format!("<a href=\"{}\">Temporary Redirect</a>.\n\n", html(location))
    } else {
        String::new()
    };
    let mut response = crate::jmap::reply::response(body, proto, id);
    *response.status_mut() = StatusCode::TEMPORARY_REDIRECT;
    response.headers_mut().remove("content-type");
    if matches!(*r.method(), Method::GET | Method::HEAD) {
        response.headers_mut().insert(
            "content-type",
            HeaderValue::from_static("text/html; charset=utf-8"),
        );
    }
    if let Ok(value) = HeaderValue::from_str(location) {
        response.headers_mut().insert("location", value);
    }
    response
}

fn html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&#34;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::{BodyExt, Full};

    const METHODS: [&str; 8] = [
        "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "CONNECT",
    ];

    fn request(method: &str, uri: &str) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(uri)
            .body(
                Full::new(bytes::Bytes::new())
                    .map_err(|n| match n {})
                    .boxed(),
            )
            .unwrap()
    }

    fn inventory() -> Inventory {
        Inventory::parse(crate::inventory::BUNDLED).expect("bundled inventory")
    }

    #[test]
    fn redirects_follow_go_for_bare_decoded_and_queried_spellings() {
        let inventory = inventory();
        for (method, uri, location) in [
            ("POST", "/auth/totp?x=1", "/auth/totp/?x=1"),
            ("GET", "/auth/%74otp", "/auth/totp/"),
            (
                "GET",
                "/auth/totp?//evil.example",
                "/auth/totp/?//evil.example",
            ),
            ("HEAD", "/auth/webauthn", "/auth/webauthn/"),
        ] {
            let reply = slash_redirect(&inventory, &request(method, uri), "http").expect(uri);
            assert_eq!(reply.status(), StatusCode::TEMPORARY_REDIRECT, "{uri}");
            assert_eq!(reply.headers()["location"], location, "{uri}");
        }
        for (method, uri) in [
            ("GET", "/auth/unknown"),
            ("GET", "/auth/totp/"),
            ("GET", "/auth/totp%2F"),
            ("POST", "/auth/login%2Fx"),
            ("GET", "//evil.example/auth/totp"),
            ("GET", "/auth/totp/..%2F"),
            ("CONNECT", "/auth/totp"),
            ("GET", "/chat"),
        ] {
            assert!(
                slash_redirect(&inventory, &request(method, uri), "http").is_none(),
                "{method} {uri}"
            );
        }
    }

    /// Every method x every bundled row: a redirect fires only for the bare spelling of
    /// a gateway/auth F21 `/auth/.../` subtree row, and always points at that row.
    #[test]
    fn a_redirect_fires_only_for_f21_auth_subtree_rows() {
        let inventory = inventory();
        let doc: serde_json::Value = serde_json::from_str(crate::inventory::BUNDLED).unwrap();
        let rows = doc["routes"].as_array().unwrap();
        let subtree = |path: &str| {
            rows.iter().any(|r| {
                matches!(r["listener"].as_str(), Some("gateway" | "auth"))
                    && r["family"] == "F21"
                    && r["path"] == path
                    && path.starts_with("/auth/")
                    && path.ends_with('/')
            })
        };
        for row in rows {
            let Some(path) = row["path"].as_str() else {
                continue;
            };
            if path.contains('{') || !matches!(row["listener"].as_str(), Some("gateway" | "auth")) {
                continue;
            }
            let bare = if path.len() > 1 {
                path.strip_suffix('/').unwrap_or(path)
            } else {
                path
            };
            if bare.is_empty() {
                continue;
            }
            for method in METHODS {
                let reply = slash_redirect(&inventory, &request(method, bare), "http");
                let expected = bare != path && method != "CONNECT" && subtree(path);
                assert_eq!(reply.is_some(), expected, "{method} {bare}");
                if let Some(reply) = reply {
                    assert_eq!(reply.headers()["location"], path, "{method} {bare}");
                }
            }
        }
    }

    /// Coordinator question (#357 v2): an `/auth/*` spelling no row claims never carries
    /// a route bucket, so Go's guest belt (lib.rs) never fires for it.
    #[test]
    fn unmatched_auth_spellings_carry_no_route_bucket() {
        let inventory = inventory();
        for uri in [
            "/auth/unknown",
            "/auth/unknown/deeper",
            "/auth/login%2Fx",
            "/auth/totp",
            "/auth/%74otp",
            "/auth/admin",
            "/auth/me/app-passwords/a/b",
        ] {
            for method in METHODS {
                let method: hyper::Method = method.parse().unwrap();
                if inventory.find(&method, uri).is_none() {
                    assert!(
                        !crate::jmap::limit::has_route_limit(&method, uri),
                        "{method} {uri}"
                    );
                }
            }
        }
    }
}
