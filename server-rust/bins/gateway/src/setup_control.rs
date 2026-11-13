//! The unix setup control socket (#305): `POST /setup/preflight` and `POST /setup/restore`,
//! gated by the one-time `X-Setup-Token`, exactly as frozen Go's `startSetupControlSocket`.
//! The socket is born 0700 (umask) and chmod 0600, its directory is held to 0750, and the public
//! mux never registers these routes. Rust starts it only with `RUST_WORKERS_ON=setup-control`
//! plus `GO_WORKERS_OFF=setup-control`.
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::{body::Incoming, header, Method, Request, Response, StatusCode};
use serde_json::{json, Map, Value};
use setjoin_backup::{restore, store::Store};
use setjoin_pg::workers::{WorkerConnection, WorkerDatabase};
use std::{
    os::unix::fs::{FileTypeExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::net::UnixListener;

pub const NAME: &str = "setup-control";
pub const DEFAULT_SOCKET: &str = "/run/setjoin/control.sock";

/// Go's `DecodeJSON` cap.
const BODY_LIMIT: usize = 1 << 20;
const FINALIZE_TIMEOUT: Duration = Duration::from_secs(15);

pub struct Control {
    pub db: WorkerDatabase,
    /// The primary blob store restore writes to; `None` answers 503 like Go's nil driver.
    pub primary: Option<Store>,
    pub token: String,
}

/// Go's `storage.NewDriver` for `cfg.S3*` (primary store of the setup handler).
pub fn primary_from_env(get: &dyn Fn(&str) -> Option<String>) -> Result<Store, String> {
    let value = |name: &str, legacy: &str, default: &str| {
        get(name)
            .filter(|s| !s.is_empty())
            .or_else(|| get(legacy).filter(|s| !s.is_empty()))
            .unwrap_or_else(|| default.into())
    };
    let secure = match value("S3_SECURE", "MINIO_SECURE", "false").as_str() {
        "true" | "True" | "TRUE" | "1" | "t" | "T" => true,
        "false" | "False" | "FALSE" | "0" | "f" | "F" => false,
        _ => return Err("S3_SECURE must be a boolean".into()),
    };
    let endpoint = value("S3_ENDPOINT", "MINIO_ENDPOINT", "127.0.0.1:9000");
    let endpoint = if endpoint.contains("://") {
        endpoint
    } else {
        format!(
            "{}://{}",
            if secure { "https" } else { "http" },
            endpoint.trim()
        )
    };
    Store::driver(
        "s3",
        &endpoint,
        "",
        &value("S3_BUCKET", "MINIO_BUCKET", "mailblobs"),
        &value("S3_ACCESS_KEY", "MINIO_ACCESS_KEY", ""),
        &value("S3_SECRET_KEY", "MINIO_SECRET_KEY", ""),
    )
}

/// Go's bind sequence for the socket; returns the listener or Go's error text.
pub fn bind(socket: &Path) -> Result<UnixListener, String> {
    if !socket.is_absolute() {
        return Err("setup control socket must be an absolute path".into());
    }
    let dir = socket.parent().unwrap_or(Path::new("/"));
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o750)
            .create(dir)
            .map_err(|e| format!("create setup control directory: {e}"))?;
    }
    if let Ok(meta) = std::fs::symlink_metadata(dir) {
        let perm = meta.permissions().mode() & 0o777;
        if meta.is_dir() && perm & 0o027 != 0 {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o750))
                .map_err(|e| format!("tighten setup control directory permissions: {e}"))?;
            eprintln!(
                "setjoin-gateway: tightened setup control directory permissions dir={} old={perm}",
                dir.display()
            );
        }
    }
    match std::fs::symlink_metadata(socket) {
        Ok(meta) => {
            if !meta.file_type().is_socket() {
                return Err("setup control path exists and is not a socket".into());
            }
            if std::os::unix::net::UnixStream::connect(socket).is_ok() {
                return Err("setup control socket is already active".into());
            }
            std::fs::remove_file(socket)
                .map_err(|e| format!("remove stale setup control socket: {e}"))?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(format!("inspect setup control socket: {e}")),
    }
    // Born 0700 so no local process connects between listen(2) and the chmod (CWE-368).
    let old = unsafe { libc::umask(0o077) };
    let listener = std::os::unix::net::UnixListener::bind(socket);
    unsafe { libc::umask(old) };
    let listener = listener.map_err(|e| format!("listen on setup control socket: {e}"))?;
    if let Err(e) = std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o600)) {
        let _ = std::fs::remove_file(socket);
        return Err(format!("secure setup control socket: {e}"));
    }
    listener.set_nonblocking(true).map_err(|e| e.to_string())?;
    UnixListener::from_std(listener).map_err(|e| e.to_string())
}

/// Serve until `stop` resolves, then remove the socket (as Go's shutdown goroutine does).
pub async fn serve(
    listener: UnixListener,
    path: PathBuf,
    control: Arc<Control>,
    stop: impl std::future::Future<Output = ()>,
) {
    use hyper::service::service_fn;
    use hyper_util::rt::{TokioIo, TokioTimer};
    tokio::pin!(stop);
    loop {
        let accepted = tokio::select! {biased; () = &mut stop => break, r = listener.accept() => r};
        let Ok((stream, _)) = accepted else { continue };
        let control = control.clone();
        tokio::spawn(async move {
            let service = service_fn(move |req| {
                let control = control.clone();
                async move { Ok::<_, std::convert::Infallible>(control.handle(req).await) }
            });
            let _ = hyper::server::conn::http1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(Duration::from_secs(5))
                .serve_connection(TokioIo::new(stream), service)
                .await;
        });
    }
    drop(listener);
    let _ = std::fs::remove_file(path);
}

type Resp = Response<Full<Bytes>>;

fn text(status: StatusCode, body: &'static str, allow: Option<&'static str>) -> Resp {
    let mut b = Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8");
    if let Some(allow) = allow {
        b = b.header(header::ALLOW, allow);
    }
    b.header("x-content-type-options", "nosniff")
        .body(Full::new(Bytes::from(body)))
        .unwrap()
}

/// Go's `httputil.WriteProblemStatus`.
fn problem(status: u16, detail: &str) -> Resp {
    Response::builder()
        .status(status)
        .header(header::CACHE_CONTROL, "no-store")
        .header(header::CONTENT_TYPE, "application/problem+json")
        .body(Full::new(Bytes::from(
            crate::problem::Problem::new(status, detail).body(),
        )))
        .unwrap()
}

/// Go's `httputil.WriteJSON` (encoder newline, HTML escaping).
fn json_response(status: u16, value: &Value) -> Resp {
    let body = serde_json::to_string(value)
        .unwrap()
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026")
        + "\n";
    Response::builder()
        .status(status)
        .header(header::CACHE_CONTROL, "no-store")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(body)))
        .unwrap()
}

struct RestoreRequest {
    provider: String,
    endpoint: String,
    region: String,
    bucket: String,
    access_key: String,
    secret_key: String,
    kind: String,
    hashes: Vec<String>,
}

/// Go's `json.Decoder` into `restoreRequest`: case-insensitive keys, wrong types fail, one value.
fn decode(body: &[u8]) -> Result<RestoreRequest, ()> {
    let mut stream = serde_json::Deserializer::from_slice(body).into_iter::<Value>();
    let first = stream.next().ok_or(())?.map_err(|_| ())?;
    if stream.next().is_some() {
        return Err(());
    }
    let Value::Object(object) = first else {
        return Err(());
    };
    let fields: Map<String, Value> = object
        .into_iter()
        .map(|(k, v)| (k.to_lowercase(), v))
        .collect();
    let string = |name: &str| match fields.get(name) {
        None | Some(Value::Null) => Ok(String::new()),
        Some(Value::String(s)) => Ok(s.clone()),
        Some(_) => Err(()),
    };
    let hashes = match fields.get("hashes") {
        None | Some(Value::Null) => vec![],
        Some(Value::Array(items)) => items
            .iter()
            .map(|v| match v {
                Value::String(s) => Ok(s.clone()),
                Value::Null => Ok(String::new()),
                _ => Err(()),
            })
            .collect::<Result<_, _>>()?,
        Some(_) => return Err(()),
    };
    Ok(RestoreRequest {
        provider: string("provider")?,
        endpoint: string("endpoint")?,
        region: string("region")?,
        bucket: string("bucket")?,
        access_key: string("access_key")?,
        secret_key: string("secret_key")?,
        kind: string("type")?,
        hashes,
    })
}

impl RestoreRequest {
    fn valid(&self) -> bool {
        !self.bucket.is_empty()
            && !self.access_key.is_empty()
            && !self.secret_key.is_empty()
            && matches!(self.kind.as_str(), "full" | "config" | "blobs")
    }
}

impl Control {
    pub async fn handle(&self, req: Request<Incoming>) -> Resp {
        let path = req.uri().path().to_owned();
        let preflight = match path.as_str() {
            "/setup/preflight" => true,
            "/setup/restore" => false,
            _ => return text(StatusCode::NOT_FOUND, "404 page not found\n", None),
        };
        if req.method() != Method::POST {
            return text(
                StatusCode::METHOD_NOT_ALLOWED,
                "Method Not Allowed\n",
                Some("POST"),
            );
        }
        if self.token.is_empty() {
            eprintln!("setjoin-gateway: setup call refused: SETJOIN_SETUP_TOKEN is not configured");
            return problem(503, "setup token not configured");
        }
        let provided = req
            .headers()
            .get("x-setup-token")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if !token_matches(provided, &self.token) {
            eprintln!("setjoin-gateway: setup call refused: invalid setup token");
            return problem(403, "invalid setup token");
        }
        let body = match Limited::new(req.into_body(), BODY_LIMIT).collect().await {
            Ok(collected) => collected.to_bytes(),
            Err(_) => return problem(400, "invalid JSON body"),
        };
        let Ok(request) = decode(&body) else {
            return problem(400, "invalid JSON body");
        };
        if !request.valid() {
            return problem(
                400,
                "Invalid restore configuration. Check the required fields.",
            );
        }
        let conn = match self.db.connect().await {
            Ok(conn) => conn,
            Err(e) => {
                eprintln!("setjoin-gateway: restore: database unavailable: {e}");
                return problem(500, "internal error");
            }
        };
        // A restore or preflight must never run against a populated system.
        match restore::user_count(&conn).await {
            Err(e) => {
                eprintln!("setjoin-gateway: restore: user count check failed: {e}");
                return problem(500, "internal error");
            }
            Ok(n) if n > 0 => return problem(409, "Setup already completed"),
            Ok(_) => {}
        }
        let Some(primary) = &self.primary else {
            return problem(503, "restore unavailable: primary storage not configured");
        };
        let backup = match Store::driver(
            &request.provider,
            &request.endpoint,
            &request.region,
            &request.bucket,
            &request.access_key,
            &request.secret_key,
        ) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("setjoin-gateway: restore: backup driver init failed: {e}");
                return problem(400, "failed to connect to backup provider");
            }
        };
        if preflight {
            self.preflight(&conn, &backup).await
        } else {
            self.restore(&conn, primary, &backup, &request).await
        }
    }

    async fn preflight(&self, conn: &WorkerConnection, backup: &Store) -> Resp {
        let manifest = match restore::download_manifest(backup).await {
            Ok(m) => m,
            Err(e) => {
                eprintln!("setjoin-gateway: preflight: manifest download failed: {e}");
                return problem(400, "backup manifest missing or unreadable");
            }
        };
        let domains = restore::domain_count(conn).await.unwrap_or(0);
        json_response(
            200,
            &json!({
                "timestamp": manifest.timestamp,
                "blob_count": manifest.blob_count,
                "blob_total_size_bytes": manifest.blob_total_size_bytes,
                "config_size_bytes": manifest.config_size_bytes,
                "user_count": 0,
                "domain_count": domains,
                "warnings": [],
            }),
        )
    }

    async fn restore(
        &self,
        conn: &WorkerConnection,
        primary: &Store,
        backup: &Store,
        request: &RestoreRequest,
    ) -> Resp {
        let job = match restore::start_job(conn, &request.kind).await {
            Ok(id) => id,
            Err(e) => {
                eprintln!("setjoin-gateway: restore: could not claim restore slot: {e}");
                return problem(409, "a restore is already in progress");
            }
        };
        let mut errors: Vec<String> = Vec::new();
        let mut keys = 0;
        let mut blobs = 0;
        let mut hard: Option<String> = None;
        if matches!(request.kind.as_str(), "config" | "full") {
            match restore::restore_config(conn, backup).await {
                Ok(n) => keys = n,
                Err(e) => hard = Some(format!("restore config: {e}")),
            }
        }
        if hard.is_none() && matches!(request.kind.as_str(), "blobs" | "full") {
            if request.hashes.is_empty() {
                match restore::download_manifest(backup).await {
                    Ok(manifest) => {
                        let (n, errs) =
                            restore::restore_from_manifest(primary, backup, &manifest).await;
                        blobs = n;
                        errors = errs;
                    }
                    Err(e) => hard = Some(format!("download manifest: {e}")),
                }
            } else {
                let (n, errs) =
                    restore::restore_missing_blobs(primary, backup, &request.hashes).await;
                blobs = n;
                errors = errs;
            }
        }
        let outcome = match (&hard, errors.first()) {
            (Some(e), _) => Some(e.clone()),
            (None, Some(first)) => {
                Some(format!("{} restore error(s); first: {first}", errors.len()))
            }
            _ => None,
        };
        // Always release the slot and record the outcome, on a context that survives the caller.
        if let Ok(Err(e)) | Err(e) = tokio::time::timeout(
            FINALIZE_TIMEOUT,
            restore::finish_job(conn, job, outcome.as_deref()),
        )
        .await
        .map_err(|_| "finish timed out".to_string())
        {
            eprintln!("setjoin-gateway: restore: finish job failed: {e} job_id={job}");
        }
        let (status, label) = if hard.is_some() {
            (500, "failed")
        } else {
            (200, "completed")
        };
        json_response(
            status,
            &json!({
                "status": label,
                "restore_job_id": job,
                "restored_config_keys": keys,
                "restored_blobs": blobs,
                "errors": errors,
            }),
        )
    }
}

/// Constant-time comparison through ring's HMAC verification under a throwaway key (ring exposes no
/// public constant-time equality; `hmac::verify` is the audited primitive).
fn token_matches(provided: &str, expected: &str) -> bool {
    use ring::{hmac, rand};
    let Ok(key) = hmac::Key::generate(hmac::HMAC_SHA256, &rand::SystemRandom::new()) else {
        return false;
    };
    hmac::verify(
        &key,
        provided.as_bytes(),
        hmac::sign(&key, expected.as_bytes()).as_ref(),
    )
    .is_ok()
}
