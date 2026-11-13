//! F06 slice `smime`: HTTP side of the admin S/MIME trust-anchor routes and the user
//! client-certificate status. Reads, writes and certificate parsing live in
//! `setjoin_mail_security::smime`; this file mirrors Go's request handling
//! (`ParseMultipartForm(1 MiB)`, `FormValue`, `FormFile`) and renders Go's exact answers.
use crate::mail_security::Action;
use crate::mailboxes::{bare, unknown_outcome};
use crate::{Body, RequestContext};
use hyper::{Method, Request, Response};
use setjoin_authz::AuthContext;
use setjoin_mail_security::smime as db;
use setjoin_pg::{CommandOutcome, ScopedExecutor};

/// Routes of this slice; the shared `action()` table consults this first.
pub(crate) fn action(method: &Method, path: &str) -> Option<Action> {
    let reads = matches!(*method, Method::GET | Method::HEAD);
    match path {
        "/api/admin/smime/trust-anchors" if reads => Some(Action::SmimeList),
        "/api/admin/smime/trust-anchors" if *method == Method::POST => Some(Action::SmimeImport),
        "/api/user/cert-status" if reads => Some(Action::CertStatus),
        _ => {
            let id = path.strip_prefix("/api/admin/smime/trust-anchors/")?;
            (*method == Method::DELETE && !id.is_empty() && !id.contains('/'))
                .then_some(Action::SmimeDelete)
        }
    }
}

/// Go's `url.ParseQuery` error: a `;` or a bad percent escape anywhere in the query. The
/// request still parses; the error surfaces at the end of `ParseMultipartForm`.
pub(crate) fn bad_query(raw: &str) -> bool {
    if raw.contains(';') {
        return true;
    }
    let bytes = raw.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = |at: usize| bytes.get(at).is_some_and(u8::is_ascii_hexdigit);
            if !(hex(i + 1) && hex(i + 2)) {
                return true;
            }
            i += 2;
        }
        i += 1;
    }
    false
}

/// What the handler reads from `r.FormValue("label")` and `r.FormFile("cert")`.
struct Form {
    label: Option<String>,
    cert: Option<Vec<u8>>,
}

/// `http.MaxBytesReader(1 MiB)` + `ParseMultipartForm(1 MiB)`. `Err` is Go's "failed to
/// parse form". Query values come first in `r.Form`, so a `label` in the query wins.
async fn parse_form(r: &mut Request<Body>) -> Result<Form, ()> {
    use http_body_util::BodyExt;
    const CAP: usize = 1 << 20;
    let boundary = r
        .headers()
        .get(hyper::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| multer::parse_boundary(v).ok())
        .ok_or(())?;
    let mut bytes = Vec::new();
    while let Some(frame) = r.body_mut().frame().await {
        let frame = frame.map_err(|_| ())?;
        if let Ok(data) = frame.into_data() {
            if data.len() > CAP - bytes.len() {
                return Err(());
            }
            bytes.extend_from_slice(&data);
        }
    }
    let stream = futures_util::stream::once(async move {
        Ok::<_, std::convert::Infallible>(bytes::Bytes::from(bytes))
    });
    let mut form = multer::Multipart::new(stream, boundary);
    let (mut label, mut cert) = (None, None);
    while let Some(field) = form.next_field().await.map_err(|_| ())? {
        let name = field.name().map(str::to_owned);
        let file = field.file_name().is_some_and(|n| !n.is_empty());
        let data = field.bytes().await.map_err(|_| ())?;
        match (name.as_deref(), file) {
            (Some("label"), false) if label.is_none() => {
                label = Some(String::from_utf8_lossy(&data).into_owned())
            }
            (Some("cert"), true) if cert.is_none() => cert = Some(data.to_vec()),
            _ => {}
        }
    }
    if bad_query(r.uri().query().unwrap_or("")) {
        return Err(());
    }
    if let Some(value) = crate::admin_identity_input::query(r.uri(), "label") {
        label = Some(value);
    }
    Ok(Form { label, cert })
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle(
    what: Action,
    mut r: Request<Body>,
    c: &RequestContext,
    id: &str,
    operation: [u8; 16],
    actor: &AuthContext,
    worker: &ScopedExecutor,
    domain_scope: i64,
) -> Response<Body> {
    let head = r.method() == Method::HEAD;
    let reply = |body: String| {
        let chunked = body.len() > 2048 && !head;
        let mut response = crate::jmap::reply::response(body, c.identity.proto, id.to_owned());
        if chunked {
            response.headers_mut().insert(
                "transfer-encoding",
                hyper::header::HeaderValue::from_static("chunked"),
            );
        }
        response
    };
    match what {
        Action::CertStatus => reply(db::cert_status_body(
            r.extensions().get::<setjoin_tls::PeerCertificate>().map(|leaf| leaf.0.as_ref()),
        )),
        Action::SmimeList => match db::list(worker, domain_scope).await {
            Ok(body) => reply(body),
            Err(_) => bare(500, "database error", c, id),
        },
        Action::SmimeImport => {
            let Ok(form) = parse_form(&mut r).await else {
                return bare(400, "failed to parse form", c, id);
            };
            let label = form.label.unwrap_or_default().trim().to_owned();
            let label = if label.is_empty() {
                "imported".to_owned()
            } else {
                label
            };
            let Some(cert) = form.cert else {
                return bare(400, "missing cert file", c, id);
            };
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs() as i64);
            let certs = match db::validate_chain(&cert, now) {
                Ok(certs) => certs,
                Err(db::ChainError::Expired) => {
                    return bare(400, "certificate is already expired", c, id)
                }
                Err(db::ChainError::Invalid) => {
                    return bare(400, "not a valid PEM certificate", c, id)
                }
            };
            match db::import(worker, actor, &label, &certs, domain_scope, operation).await {
                CommandOutcome::Committed(_) => reply(db::import_body(&certs[0].fingerprint)),
                CommandOutcome::RolledBack(_) => bare(500, "failed to store trust anchor", c, id),
                CommandOutcome::Unknown { operation } => unknown_outcome(operation, c, id),
            }
        }
        Action::SmimeDelete => {
            let segment = crate::mail_security::segment(r.uri().path(), 5);
            let Some(target) = segment.parse::<i64>().ok() else {
                return bare(400, "invalid id", c, id);
            };
            match db::delete(worker, actor, target, domain_scope, operation).await {
                CommandOutcome::Committed(true) => reply(db::ok_body()),
                CommandOutcome::Committed(false) => bare(404, "trust anchor not found", c, id),
                CommandOutcome::RolledBack(_) => bare(500, "database error", c, id),
                CommandOutcome::Unknown { operation } => unknown_outcome(operation, c, id),
            }
        }
        _ => unreachable!("only smime actions are dispatched here"),
    }
}
