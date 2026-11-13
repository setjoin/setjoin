//! F06 slice `tls`: HTTP side of the TLS status, `tls_*` configuration, certificate import
//! and outbound TLS policy routes. Reads and writes live in `setjoin_mail_security::tls`;
//! this file decodes the requests as Go's handlers do (`json.Decoder`, `DecodeJSON`,
//! `ParseMultipartForm`), owns the certificate directory and renders Go's exact answers.
use crate::mail_security::Action;
use crate::mail_security_input as input;
use crate::mailboxes::{bare, unknown_outcome};
use crate::{Body, RequestContext};
use hyper::{Request, Response};
use setjoin_authz::AuthContext;
use setjoin_mail_security::tls as db;
use setjoin_pg::{CommandOutcome, ScopedExecutor};

/// Go's default `tls.autocert_cache_dir`.
pub const DEFAULT_CACHE_DIR: &str = "/var/cache/mailserver/autocert";

/// The directory `POST /admin/tls/import-cert` writes: `cfg.TLSAutocertCacheDir + "/imported"`.
/// Go's `TLS_AUTOCERT_CACHE_DIR` environment override is honoured; when it is unset and a
/// `SETJOIN_CONFIG` file might set the key, Rust cannot know the directory and the route is
/// left to Go (`None`).
pub fn import_dir_from_env() -> Option<String> {
    let base = std::env::var("TLS_AUTOCERT_CACHE_DIR").unwrap_or_default();
    if base.is_empty() {
        if std::env::var("SETJOIN_CONFIG").is_ok_and(|v| !v.is_empty()) {
            return None;
        }
        return Some(format!("{DEFAULT_CACHE_DIR}/imported"));
    }
    Some(format!("{base}/imported"))
}

/// Go's `ParseMultipartForm(10 MiB)` + `FormFile` for the `cert` and `key` parts.
async fn form_files(r: &mut Request<Body>) -> Result<(Option<Vec<u8>>, Option<Vec<u8>>), ()> {
    use http_body_util::BodyExt;
    const CAP: usize = 10 << 20;
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
    let (mut cert, mut key) = (None, None);
    while let Some(field) = form.next_field().await.map_err(|_| ())? {
        let name = field.name().map(str::to_owned);
        let file = field.file_name().is_some_and(|n| !n.is_empty());
        let data = field.bytes().await.map_err(|_| ())?;
        match (name.as_deref(), file) {
            (Some("cert"), true) if cert.is_none() => cert = Some(data.to_vec()),
            (Some("key"), true) if key.is_none() => key = Some(data.to_vec()),
            _ => {}
        }
    }
    Ok((cert, key))
}

/// `os.Create` + copy + `os.Chmod(0600)`: the copy's error is ignored as in Go.
fn write_private(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o666)
        .open(path)?;
    let _ = file.write_all(data);
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    Ok(())
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
    import_dir: Option<&str>,
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
    let no_content = || {
        let mut response =
            crate::jmap::reply::response(String::new(), c.identity.proto, id.to_owned());
        *response.status_mut() = hyper::StatusCode::NO_CONTENT;
        response.headers_mut().remove("content-type");
        response
    };
    let ip = c.identity.client_ip.to_string();
    match what {
        Action::TlsStatus => {
            let status = db::status_input(worker).await;
            let mut cert = None;
            if status.enabled && !status.cache_dir.is_empty() && !status.domains.is_empty() {
                let path = db::cert_cache_path(&status.cache_dir, &status.domains[0]);
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_secs() as i64);
                cert = tokio::task::spawn_blocking(move || db::cert_info(&path, now))
                    .await
                    .ok()
                    .flatten();
            }
            reply(db::status_body(&status, cert.as_ref()), 200)
        }
        Action::TlsConfigGet => match db::config_get(worker).await {
            Ok(body) => reply(body, 200),
            Err(_) => bare(500, "database error", c, id),
        },
        Action::TlsConfigPut => {
            let Ok(body) = input::lenient::<serde_json::Value>(&mut r).await else {
                return bare(400, "invalid JSON", c, id);
            };
            let values = match body {
                serde_json::Value::Null => serde_json::Map::new(),
                serde_json::Value::Object(map) => map,
                _ => return bare(400, "invalid JSON", c, id),
            };
            match db::config_set(worker, actor, &ip, &values, operation).await {
                Ok(()) => no_content(),
                Err(db::SetError::Outcome(CommandOutcome::Unknown { operation })) => {
                    unknown_outcome(operation, c, id)
                }
                Err(_) => bare(500, "database error", c, id),
            }
        }
        Action::TlsImportCert => {
            let Some(import_dir) = import_dir else {
                return c.upstream.forward(r, &c.identity).await;
            };
            let Ok((cert, key)) = form_files(&mut r).await else {
                return bare(400, "failed to parse form", c, id);
            };
            let Some(cert) = cert else {
                return bare(400, "cert file required", c, id);
            };
            let Some(key) = key else {
                return bare(400, "key file required", c, id);
            };
            let dir = std::path::PathBuf::from(import_dir);
            let made = {
                use std::os::unix::fs::DirBuilderExt;
                std::fs::DirBuilder::new()
                    .recursive(true)
                    .mode(0o700)
                    .create(&dir)
            };
            if made.is_err() {
                return bare(500, "storage error", c, id);
            }
            let cert_path = dir.join("custom.cert.pem");
            let key_path = dir.join("custom.key.pem");
            if write_private(&cert_path, &cert).is_err() || write_private(&key_path, &key).is_err()
            {
                return bare(500, "storage error", c, id);
            }
            let (cert_text, key_text) = (
                cert_path.to_string_lossy().into_owned(),
                key_path.to_string_lossy().into_owned(),
            );
            // Go logs a failed audit write and still answers 200.
            if let CommandOutcome::Unknown { operation } =
                db::import_audit(worker, actor, &ip, &cert_text, &key_text, operation).await
            {
                return unknown_outcome(operation, c, id);
            }
            reply(db::import_body(&cert_text, &key_text), 200)
        }
        Action::PolicyGet => reply(db::policy_get(worker).await, 200),
        Action::PolicyPut => {
            let Ok(body) = input::one_capped::<input::TlsPolicy>(&mut r, 1 << 20).await else {
                return bare(400, "invalid JSON", c, id);
            };
            if let Some(detail) = db::validate_policy(&body.enforce, &body.skip, &body.mode) {
                return bare(400, &detail, c, id);
            }
            let (enforce, skip) = (
                body.enforce.unwrap_or_default(),
                body.skip.unwrap_or_default(),
            );
            match db::policy_put(worker, actor, &enforce, &skip, &body.mode, operation).await {
                CommandOutcome::Committed(()) => no_content(),
                CommandOutcome::RolledBack(_) => bare(500, "database error", c, id),
                CommandOutcome::Unknown { operation } => unknown_outcome(operation, c, id),
            }
        }
        _ => unreachable!("only tls actions are dispatched here"),
    }
}
