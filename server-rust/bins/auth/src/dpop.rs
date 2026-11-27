//! Native DPoP admission and token-binding helpers (#352).
use super::*;
use setjoin_identity::session::Session;
use std::net::Ipv6Addr;

pub(super) enum AccessError {
    Unauthorized,
    WrongType,
    TokenBinding,
}

fn forwarded_proto_token(v: &str) -> Option<&'static str> {
    let trimmed = v.trim();
    if trimmed.eq_ignore_ascii_case("http") {
        Some("http")
    } else if trimmed.eq_ignore_ascii_case("https") {
        Some("https")
    } else {
        None
    }
}

fn valid_port(port: &str) -> bool {
    !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) && port.parse::<u16>().is_ok()
}

/// Accepts a single sanitized host[:port] (hostname, IPv4, or bracketed IPv6);
/// mirrors Go `authserver/internal/token.sanitizedForwardedHost`.
fn sanitized_forwarded_host(v: &str) -> Option<&str> {
    let v = v.trim();
    if v.is_empty()
        || v.chars()
            .any(|c| matches!(c, ' ' | ',' | '\t' | '/' | '\\' | '@' | '?' | '#'))
        || v.contains("..")
    {
        return None;
    }
    if v.starts_with('[') {
        let closing = v.find(']')?;
        let rest = &v[closing + 1..];
        if !rest.is_empty() && (!rest.starts_with(':') || !valid_port(&rest[1..])) {
            return None;
        }
        if v[1..closing].parse::<Ipv6Addr>().is_err() {
            return None;
        }
        return Some(v);
    }
    if let Some((host, port)) = v.split_once(':') {
        if host.is_empty()
            || host.contains(['[', ']'])
            || port.contains(['[', ']', ':'])
            || !valid_port(port)
        {
            return None;
        }
        return Some(v);
    }
    if v.contains(['[', ']', ':']) {
        return None;
    }
    Some(v)
}

impl AuthServer {
    /// Reconstructs the client-facing `htu` URI (scheme + host + escaped path,
    /// without query string), mirroring Go `token.dpopClientFacingURI`.
    pub(super) fn dpop_client_facing_uri(req: &Request<Body>) -> String {
        if let Some(auth_meta) = req
            .extensions()
            .get::<setjoin_authz::auth_authority::AuthRequestMeta>()
        {
            let host = req
                .uri()
                .authority()
                .map(|a| a.as_str())
                .or_else(|| req.headers().get("host").and_then(|v| v.to_str().ok()))
                .unwrap_or("");
            let path = req.uri().path();
            let path = if path.is_empty() { "/" } else { path };
            return format!("{}://{host}{path}", auth_meta.proto);
        }
        let mut scheme = if req
            .extensions()
            .get::<ConnectionMeta>()
            .is_some_and(|m| m.tls)
        {
            "https"
        } else {
            "http"
        };
        if let Some(proto) = req
            .headers()
            .get("x-forwarded-proto")
            .and_then(|v| v.to_str().ok())
            .and_then(forwarded_proto_token)
        {
            scheme = proto;
        }
        let mut host = req
            .uri()
            .authority()
            .map(|a| a.as_str())
            .or_else(|| req.headers().get("host").and_then(|v| v.to_str().ok()))
            .unwrap_or("");
        if let Some(forwarded) = req
            .headers()
            .get("x-forwarded-host")
            .and_then(|v| v.to_str().ok())
            .and_then(sanitized_forwarded_host)
        {
            host = forwarded;
        }
        let path = req.uri().path();
        let path = if path.is_empty() { "/" } else { path };
        format!("{scheme}://{host}{path}")
    }

    pub(super) fn dpop_admission_denied(path: &str) -> Response<Body> {
        let mut r = Self::push_problem(401, "Unauthorized", Some("dpop_admission"), path);
        r.headers_mut().insert(
            "www-authenticate",
            hyper::header::HeaderValue::from_static("Bearer realm=\"authserver\""),
        );
        r
    }

    /// Runs the full session-acceptance funnel once per presented token:
    /// signature, access-type parity, positive-match revocation snapshot, and
    /// DPoP proof-of-possession for `cnf`-bound tokens.
    pub(super) fn verify_presented_access(
        &self,
        req: &Request<Body>,
        token: &str,
        require_ath: bool,
    ) -> Result<Session, AccessError> {
        if token.is_empty() {
            return Err(AccessError::Unauthorized);
        }
        let legacy = self.legacy.as_ref().ok_or(AccessError::Unauthorized)?;
        let session = Session::verify(token, self.keys.as_deref(), legacy, &self.config.issuer)
            .ok_or(AccessError::Unauthorized)?;
        if session.text("typ") != "access" {
            return Err(AccessError::WrongType);
        }
        if self.revocations.contains(&session) {
            return Err(AccessError::Unauthorized);
        }
        if let Some(jkt) = session.bound_jkt() {
            let uri = Self::dpop_client_facing_uri(req);
            let proof = req
                .headers()
                .get("dpop")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0.0, |d| d.as_secs_f64());
            let valid = if require_ath {
                setjoin_authz::dpop::verify(
                    proof,
                    req.method().as_str(),
                    &uri,
                    jkt,
                    now,
                    &self.dpop_replay,
                    token,
                )
            } else {
                setjoin_authz::dpop::verify_without_ath(
                    proof,
                    req.method().as_str(),
                    &uri,
                    jkt,
                    now,
                    &self.dpop_replay,
                )
            };
            if !valid {
                return Err(AccessError::TokenBinding);
            }
        }
        Ok(session)
    }

    /// Evaluates `dpop_jwk` and `feature.token_binding` once before minting or
    /// irreversible completion effects. Malformed/unsupported JWKs degrade to
    /// unbound (`Ok(None)`); flag-read DB errors fail closed with 500 (#454).
    pub(super) async fn resolve_dpop_cnf(
        &self,
        dpop_jwk: Option<&Value>,
        path: &str,
    ) -> Result<Option<String>, Response<Body>> {
        let Some(jwk) =
            dpop_jwk.filter(|v| !matches!(v, Value::Object(m) if m.is_empty()) && !v.is_null())
        else {
            return Ok(None);
        };
        let enabled = match login::enabled(&self.app_db, "feature.token_binding").await {
            Ok(v) => v,
            Err(_) => return Err(Self::failure(500, "internal error", path)),
        };
        if !enabled {
            return Ok(None);
        }
        Ok(setjoin_authz::dpop::thumbprint(jwk))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req_with(uri: &str, headers: &[(&str, &str)], tls: bool) -> Request<Body> {
        let mut builder = Request::get(uri);
        for (k, v) in headers {
            builder = builder.header(*k, *v);
        }
        let mut req = builder.body(body("")).unwrap();
        if tls {
            req.extensions_mut().insert(ConnectionMeta {
                peer: "127.0.0.1:40000".parse().unwrap(),
                tls: true,
            });
        }
        req
    }

    #[test]
    fn client_facing_uri_matches_go_sanitization() {
        assert_eq!(
            AuthServer::dpop_client_facing_uri(&req_with(
                "/auth/me?ignored=1",
                &[("host", "mail.example.com")],
                false
            )),
            "http://mail.example.com/auth/me"
        );
        assert_eq!(
            AuthServer::dpop_client_facing_uri(&req_with(
                "/auth/me",
                &[("host", "mail.example.com")],
                true
            )),
            "https://mail.example.com/auth/me"
        );
        assert_eq!(
            AuthServer::dpop_client_facing_uri(&req_with(
                "/auth/webauthn/credential/a%2Fb/name?x=1",
                &[
                    ("host", "internal:8443"),
                    ("x-forwarded-proto", "  HTTPS "),
                    ("x-forwarded-host", " [::1]:8443 "),
                ],
                false
            )),
            "https://[::1]:8443/auth/webauthn/credential/a%2Fb/name"
        );
        assert_eq!(
            AuthServer::dpop_client_facing_uri(&req_with(
                "/auth/me",
                &[
                    ("host", "fallback.test:8080"),
                    ("x-forwarded-proto", "https, http"),
                    ("x-forwarded-host", "evil.test, good.test"),
                ],
                false
            )),
            "http://fallback.test:8080/auth/me"
        );
        for bad_host in [
            "",
            "evil.test/path",
            "user@evil.test",
            "a..b.test",
            ":8443",
            "example.com:",
            "example.com:99999",
            "example.com:abc",
            "a:b:c",
            "[::1",
            "[::1]foo",
            "[::1]:bad",
            "[127.0.0.1]",
            "example.com]",
        ] {
            assert_eq!(
                AuthServer::dpop_client_facing_uri(&req_with(
                    "http://safe.test",
                    &[("host", "safe.test"), ("x-forwarded-host", bad_host)],
                    true
                )),
                "https://safe.test/",
                "bad forwarded host {bad_host:?}"
            );
        }
    }
}
