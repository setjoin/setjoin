//! F06 slice `trace`: HTTP side of the admin message trace (list, CSV export, timeline) and
//! the user delivery trace. Reads live in `setjoin_mail_security::trace`; the inbound
//! user trace fetches the raw header block from the loopback JMAP download as Go does and
//! parses its `Received:` chain with `setjoin_mail_security::received`.
use crate::admin_identity_input::query;
use crate::mail_security::{segment, Action};
use crate::mailboxes::bare;
use crate::{Body, RequestContext};
use hyper::{Request, Response};
use setjoin_authz::AuthContext;
use setjoin_mail_security::received::{self, Identity};
use setjoin_mail_security::trace as db;
use setjoin_pg::ScopedExecutor;

/// Go's `http://127.0.0.1/jmap/download` (main.go builds both user trace handlers with it).
pub const DEFAULT_JMAP_BASE: &str = "http://127.0.0.1/jmap/download";

/// What the user trace needs besides the database: Go's `serverIdentityHostnames(cfg)`
/// (from `HOSTNAME` / `INTERNAL_DOMAINS`) and the loopback download base.
#[derive(Clone)]
pub struct TraceConfig {
    /// `None` when `SETJOIN_CONFIG` may set the names: the user trace stays with Go.
    pub identity: Option<Identity>,
    pub jmap_base: String,
    client: Option<reqwest::Client>,
}

impl TraceConfig {
    pub fn from_env() -> Self {
        let env = |name: &str| std::env::var(name).ok();
        let identity = if env("SETJOIN_CONFIG").is_some_and(|v| !v.is_empty()) {
            None
        } else {
            let host = env("HOSTNAME").filter(|v| !v.is_empty());
            let internal = match env("INTERNAL_DOMAINS") {
                Some(v) => v,
                None => host.clone().unwrap_or_else(|| "localhost".into()),
            };
            Some(Identity::from_config(
                host.as_deref().unwrap_or("localhost"),
                &internal,
            ))
        };
        Self::new(identity)
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
    actor: &AuthContext,
    worker: &ScopedExecutor,
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
            let Some(f) = filters(&r) else {
                return db_error();
            };
            let get = |name: &str| query(r.uri(), name).unwrap_or_default();
            let (limit, offset) = db::page(&get("limit"), &get("offset"));
            match db::admin_list(worker, &f, limit, offset).await {
                Ok(body) => reply(body, 200),
                Err(_) => db_error(),
            }
        }
        Action::TraceExport => {
            let result = match filters(&r) {
                Some(f) => db::admin_export(worker, &f).await,
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
            let raw = crate::inventory::unescape(path.split('/').nth(4).unwrap_or(""));
            if std::str::from_utf8(&raw).is_err() {
                return db_error();
            }
            let message_id = segment(&path, 4);
            match db::timeline(worker, &message_id).await {
                Ok(body) => reply(body, 200),
                Err(_) => db_error(),
            }
        }
        Action::MessageTrace => {
            let Some(identity) = config.identity.as_ref() else {
                return c.upstream.forward(r, &c.identity).await;
            };
            let Ok(email_id) = segment(&path, 3).parse::<i64>() else {
                return bare(400, "invalid email ID", c, id);
            };
            let om = match db::owned(worker, email_id, actor.user_id()).await {
                Ok(Some(om)) => om,
                Ok(None) => return bare(404, "email not found", c, id),
                Err(_) => return db_error(),
            };
            if db::is_sent(worker, &om).await {
                return reply(db::outbound(worker, &om, &config.jmap_base).await, 200);
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
