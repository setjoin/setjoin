//! F06 slice `trace`: HTTP side of the admin message trace (list, CSV export, timeline) and
//! the user delivery trace. Reads live in `setjoin_mail_security::trace`; the inbound
//! user trace fetches the raw header block from the loopback JMAP download as Go does and
//! parses its `Received:` chain with `setjoin_mail_security::received`.
use crate::admin_identity_input::query;
use crate::mail_security::{segment, Action};
use crate::mailboxes::bare;
use crate::{Body, RequestContext};
use hyper::{Request, Response};
use setjoin_authz::principals::{AdminPermissionProof, TxFactory};
use setjoin_authz::Authorized;
use setjoin_mail_security::received::{self, Identity};
use setjoin_mail_security::trace as db;

/// Default loopback JMAP download base when no explicit HTTP listen port is configured.
pub const DEFAULT_JMAP_BASE: &str = "http://127.0.0.1/jmap/download";

/// Derive the plaintext loopback JMAP download base URL from a gateway/HTTP listen address
/// such as `:8080`, `0.0.0.0:8090`, `[::]:8090`, `127.0.0.1:8090`, `[::1]:8090`, or
/// `http://127.0.0.1:8090` (#248). Rejects `https://`, TLS port 443, userinfo, and invalid
/// authority strings, falling back cleanly to [`DEFAULT_JMAP_BASE`].
pub fn jmap_base_from_listen_addr(addr: &str) -> String {
    let trimmed = addr.trim();
    if trimmed.is_empty() {
        return DEFAULT_JMAP_BASE.to_owned();
    }
    let (has_http_scheme, authority) = if let Some(idx) = trimmed.find("://") {
        let scheme = &trimmed[..idx];
        if !scheme.eq_ignore_ascii_case("http") {
            return DEFAULT_JMAP_BASE.to_owned();
        }
        let rest = &trimmed[idx + 3..];
        (true, rest.split(['/', '?', '#']).next().unwrap_or(""))
    } else {
        if trimmed.contains(['/', '?', '#']) {
            return DEFAULT_JMAP_BASE.to_owned();
        }
        (false, trimmed)
    };
    if authority.is_empty() || authority.contains('@') || authority.ends_with(':') {
        return DEFAULT_JMAP_BASE.to_owned();
    }
    let candidate = if !has_http_scheme {
        if let Some(rest) = authority.strip_prefix(':') {
            format!("127.0.0.1:{rest}")
        } else if let Some(rest) = authority.strip_prefix("*:") {
            format!("127.0.0.1:{rest}")
        } else {
            authority.to_owned()
        }
    } else {
        authority.to_owned()
    };
    let Ok(parsed) = candidate.parse::<hyper::http::uri::Authority>() else {
        return DEFAULT_JMAP_BASE.to_owned();
    };
    let host = parsed.host();
    if host.is_empty() {
        return DEFAULT_JMAP_BASE.to_owned();
    }
    let port = match parsed.port_u16() {
        Some(0) | Some(443) => return DEFAULT_JMAP_BASE.to_owned(),
        Some(p) => p,
        None if has_http_scheme => 80,
        None => return DEFAULT_JMAP_BASE.to_owned(),
    };
    let target_host = match host {
        "0.0.0.0" | "[::]" => "127.0.0.1",
        other => other,
    };
    if port == 80 {
        format!("http://{target_host}/jmap/download")
    } else {
        format!("http://{target_host}:{port}/jmap/download")
    }
}

/// What the user trace needs besides the database: Go's `serverIdentityHostnames(cfg)`
/// (from `HOSTNAME` / `INTERNAL_DOMAINS`) and the loopback download base.
#[derive(Clone)]
pub struct TraceConfig {
    pub identity: Option<Identity>,
    pub jmap_base: String,
    client: Option<reqwest::Client>,
}

impl TraceConfig {
    pub fn from_settings(settings: &crate::configuration::Settings) -> Self {
        let host = settings.string("hostname");
        let host = if host.is_empty() {
            "localhost"
        } else {
            host.as_str()
        };
        let internal = settings.string("internal.domains");
        let internal = if internal.is_empty() {
            host
        } else {
            internal.as_str()
        };
        let listen = std::env::var("GATEWAY_LISTEN")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .unwrap_or_else(|| settings.string("listen.addr"));
        Self::new(Some(Identity::from_config(host, internal)))
            .with_jmap_base(&jmap_base_from_listen_addr(&listen))
    }
    pub fn from_env() -> Self {
        Self::from_env_lookup(|k| std::env::var(k).ok())
    }
    fn from_env_lookup(get: impl Fn(&str) -> Option<String>) -> Self {
        let host = get("HOSTNAME").filter(|v| !v.is_empty());
        let internal = match get("INTERNAL_DOMAINS") {
            Some(v) => v,
            None => host.clone().unwrap_or_else(|| "localhost".into()),
        };
        let listen = get("GATEWAY_LISTEN")
            .filter(|v| !v.trim().is_empty())
            .or_else(|| get("LISTEN_ADDR").filter(|v| !v.trim().is_empty()));
        let cfg = Self::new(Some(Identity::from_config(
            host.as_deref().unwrap_or("localhost"),
            &internal,
        )));
        match listen {
            Some(addr) => cfg.with_jmap_base(&jmap_base_from_listen_addr(&addr)),
            None => cfg,
        }
    }
    pub fn new(identity: Option<Identity>) -> Self {
        Self {
            identity,
            jmap_base: DEFAULT_JMAP_BASE.to_owned(),
            // Go's `http.DefaultClient`: redirects followed, loopback never proxied.
            client: reqwest::Client::builder().no_proxy().build().ok(),
        }
    }
    pub fn with_jmap_base(mut self, base: &str) -> Self {
        self.jmap_base = base.to_owned();
        self
    }
}

/// `fetchHeaderBytes`: the first MiB of the download, `None` on any failure or non-200.
async fn fetch_header_bytes(config: &TraceConfig, r: &Request<Body>, url: &str) -> Option<Vec<u8>> {
    let client = config.client.as_ref()?;
    let mut request = client.get(url);
    // Go forwards the first Authorization and Cookie values when non-empty.
    for name in ["authorization", "cookie"] {
        if let Some(v) = r.headers().get(name).filter(|v| !v.is_empty()) {
            request = request.header(name, v.clone());
        }
    }
    let mut response = tokio::time::timeout(std::time::Duration::from_secs(30), request.send())
        .await
        .ok()?
        .ok()?;
    if response.status() != reqwest::StatusCode::OK {
        return None;
    }
    let mut out: Vec<u8> = vec![];
    while out.len() < received::MAX_HEADER_BYTES {
        let chunk = tokio::time::timeout(std::time::Duration::from_secs(30), response.chunk())
            .await
            .ok()?;
        match chunk {
            Ok(Some(bytes)) => out.extend_from_slice(&bytes),
            Ok(None) => break,
            // `io.ReadAll` returns the bytes read so far with the error, and Go discards it
            // only when the error is non-nil.
            Err(_) => return None,
        }
    }
    out.truncate(received::MAX_HEADER_BYTES);
    Some(out)
}

/// A query value that PostgreSQL would refuse as text (invalid UTF-8): Go's query fails.
fn bad_text(r: &Request<Body>, name: &str) -> bool {
    crate::compliance_export::query_bytes(r.uri(), name)
        .is_some_and(|v| std::str::from_utf8(&v).is_err())
}

fn filters(r: &Request<Body>) -> Option<db::Filters> {
    let get = |name: &str| query(r.uri(), name).unwrap_or_default();
    if ["from", "to", "subject", "event", "status"]
        .iter()
        .any(|n| bad_text(r, n))
    {
        return None;
    }
    Some(db::Filters {
        from: get("from"),
        to: get("to"),
        subject: get("subject"),
        event: get("event"),
        status: get("status"),
        date_from: get("dateFrom"),
        date_to: get("dateTo"),
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle(
    what: Action,
    r: Request<Body>,
    c: &RequestContext,
    id: &str,
    factory: &TxFactory,
    auth: &Authorized,
    client_ip: &str,
    admin: Option<&AdminPermissionProof>,
    config: &TraceConfig,
) -> Response<Body> {
    let head = r.method() == hyper::Method::HEAD;
    let reply = |body: String, status: u16| {
        // net/http buffers 2 KiB of a handler's output; a larger single write is flushed
        // before the handler returns and sent chunked.
        let chunked = body.len() > 2048 && !head;
        let mut response = crate::jmap::reply::response(body, c.identity.proto, id.to_owned());
        *response.status_mut() = hyper::StatusCode::from_u16(status).expect("status");
        if chunked {
            response.headers_mut().insert(
                "transfer-encoding",
                hyper::header::HeaderValue::from_static("chunked"),
            );
        }
        response
    };
    let db_error = || bare(500, "database error", c, id);
    let path = r.uri().path().to_owned();
    match what {
        Action::TraceList => {
            let Some(admin) = admin else {
                return bare(403, "Forbidden", c, id);
            };
            let Some(f) = filters(&r) else {
                return db_error();
            };
            let get = |name: &str| query(r.uri(), name).unwrap_or_default();
            let (limit, offset) = db::page(&get("limit"), &get("offset"));
            match db::admin_list(factory, admin, &f, limit, offset).await {
                Ok(body) => reply(body, 200),
                Err(_) => db_error(),
            }
        }
        Action::TraceExport => {
            let Some(admin) = admin else {
                return bare(403, "Forbidden", c, id);
            };
            let result = match filters(&r) {
                Some(f) => db::admin_export(factory, admin, &f).await,
                None => Ok(db::export_empty()),
            };
            match result {
                Ok(body) => {
                    let mut response = reply(body, 200);
                    let headers = response.headers_mut();
                    headers.insert(
                        "content-type",
                        hyper::header::HeaderValue::from_static("text/csv"),
                    );
                    headers.insert(
                        "content-disposition",
                        hyper::header::HeaderValue::from_static(
                            "attachment; filename=\"message-trace.csv\"",
                        ),
                    );
                    response
                }
                Err(_) => db_error(),
            }
        }
        Action::TraceTimeline => {
            let Some(admin) = admin else {
                return bare(403, "Forbidden", c, id);
            };
            let raw = crate::inventory::unescape(path.split('/').nth(4).unwrap_or(""));
            if std::str::from_utf8(&raw).is_err() {
                return db_error();
            }
            let message_id = segment(&path, 4);
            match db::timeline(factory, admin, &message_id).await {
                Ok(body) => reply(body, 200),
                Err(_) => db_error(),
            }
        }
        Action::MessageTrace => {
            let Some(identity) = config.identity.as_ref() else {
                return bare(503, "service unavailable", c, id);
            };
            let Ok(email_id) = segment(&path, 3).parse::<i64>() else {
                return bare(400, "invalid email ID", c, id);
            };
            let Ok(mb) = factory
                .mint_primary_mailbox_from_authorized(auth, client_ip)
                .await
            else {
                return db_error();
            };
            let Ok(cap) = mb.require_read() else {
                return bare(403, "Forbidden", c, id);
            };
            let om = match db::owned(factory, &cap, email_id).await {
                Ok(Some(om)) => om,
                Ok(None) => return bare(404, "email not found", c, id),
                Err(_) => return db_error(),
            };
            if db::is_sent(factory, &cap, &om).await {
                return reply(
                    db::outbound(factory, &cap, &om, &config.jmap_base).await,
                    200,
                );
            }
            let url = db::download_url(&config.jmap_base, &om);
            match fetch_header_bytes(config, &r, &url).await {
                Some(raw) => reply(
                    received::parse_trace(&raw, identity).unwrap_or_default(),
                    200,
                ),
                None => reply(received::empty_trace(), 200),
            }
        }
        _ => unreachable!("only trace actions are dispatched here"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jmap_base_derives_from_listen_addr_with_clean_fallback() {
        assert_eq!(jmap_base_from_listen_addr(":80"), DEFAULT_JMAP_BASE);
        assert_eq!(jmap_base_from_listen_addr("0.0.0.0:80"), DEFAULT_JMAP_BASE);
        assert_eq!(jmap_base_from_listen_addr("[::]:80"), DEFAULT_JMAP_BASE);
        assert_eq!(
            jmap_base_from_listen_addr("127.0.0.1:80"),
            DEFAULT_JMAP_BASE
        );
        assert_eq!(
            jmap_base_from_listen_addr(":8080"),
            "http://127.0.0.1:8080/jmap/download"
        );
        assert_eq!(
            jmap_base_from_listen_addr("0.0.0.0:8090"),
            "http://127.0.0.1:8090/jmap/download"
        );
        assert_eq!(
            jmap_base_from_listen_addr("[::]:8090"),
            "http://127.0.0.1:8090/jmap/download"
        );
        assert_eq!(
            jmap_base_from_listen_addr("127.0.0.1:8090"),
            "http://127.0.0.1:8090/jmap/download"
        );
        assert_eq!(
            jmap_base_from_listen_addr("[::1]:8090"),
            "http://[::1]:8090/jmap/download"
        );
        assert_eq!(
            jmap_base_from_listen_addr("[::1]:80"),
            "http://[::1]/jmap/download"
        );
        assert_eq!(
            jmap_base_from_listen_addr("localhost:3000"),
            "http://localhost:3000/jmap/download"
        );
        assert_eq!(
            jmap_base_from_listen_addr("http://127.0.0.1"),
            DEFAULT_JMAP_BASE
        );
        assert_eq!(
            jmap_base_from_listen_addr("http://127.0.0.1:8090"),
            "http://127.0.0.1:8090/jmap/download"
        );
        assert_eq!(
            jmap_base_from_listen_addr("https://127.0.0.1:8443"),
            DEFAULT_JMAP_BASE
        );
        assert_eq!(jmap_base_from_listen_addr(":443"), DEFAULT_JMAP_BASE);
        assert_eq!(
            jmap_base_from_listen_addr("bad host:8080"),
            DEFAULT_JMAP_BASE
        );
        assert_eq!(
            jmap_base_from_listen_addr("user@127.0.0.1:8080"),
            DEFAULT_JMAP_BASE
        );
        assert_eq!(jmap_base_from_listen_addr(""), DEFAULT_JMAP_BASE);
        assert_eq!(jmap_base_from_listen_addr(":0"), DEFAULT_JMAP_BASE);
        assert_eq!(jmap_base_from_listen_addr("127.0.0.1:"), DEFAULT_JMAP_BASE);
        assert_eq!(jmap_base_from_listen_addr("not-an-addr"), DEFAULT_JMAP_BASE);

        let tls_env = TraceConfig::from_env_lookup(|k| match k {
            "LISTEN_ADDR" => Some(":443".into()),
            _ => None,
        });
        assert_eq!(tls_env.jmap_base, DEFAULT_JMAP_BASE);
    }
}
