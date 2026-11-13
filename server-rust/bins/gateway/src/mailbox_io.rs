//! F05 slice `mailboxes`: admin mailbox import and export (#425).
//!
//! `POST /admin/mailboxes/{id}/import` reads an MBOX, EML or ZIP-of-EML upload,
//! writes each message's raw bytes to the content-addressed object store (key =
//! SHA-256 hex) and calls the `import_message` reducer; `GET .../export` streams
//! a mailbox back as MBOX or a ZIP of EML. Both run on the worker credential
//! with the actor and the live domain scope inside the reducer/SELECT predicate
//! (`admin_can_reach_mailbox`), as Go's `ImportExportHandler`. The MIME work is
//! `setjoin_mailboxes::mimeutil`, a port of Go's `mimeutil`; the export ZIP is
//! `setjoin_mailboxes::ziparchive::ZipStream`. See the crate DOX.
use crate::mailboxes::{bare, segment, segment_path};
use crate::recovery_worker::ObjectStore;
use crate::{Body, BoxFuture, Intercept, RequestContext};
use bytes::Bytes;
use hyper::{Method, Request, Response};
use setjoin_authz::token::KeySource;
use setjoin_authz::AuthContext;
use setjoin_mailboxes::import_export as db;
use setjoin_mailboxes::mimeutil::{self, ImportFields};
use setjoin_mailboxes::ziparchive::{self, Archive, ZipStream};
use setjoin_pg::{CommandOutcome, ScopedExecutor};
use sha2::{Digest, Sha256};
use std::sync::Arc;

pub struct MailboxIoRoute<K: KeySource + 'static, S: ObjectStore + 'static> {
    pub exec: ScopedExecutor,
    /// The `setjoin_worker` credential: every read and write of this slice.
    pub worker: ScopedExecutor,
    pub store: Arc<S>,
    pub keys: Arc<K>,
    pub issuer: String,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Io {
    Import,
    Export,
}

pub(crate) fn action(method: &Method, path: &str) -> Option<Io> {
    let reads = matches!(*method, Method::GET | Method::HEAD);
    let table: [(bool, &str, Io); 2] = [
        (
            *method == Method::POST,
            "/api/admin/mailboxes/{id}/import",
            Io::Import,
        ),
        (reads, "/api/admin/mailboxes/{id}/export", Io::Export),
    ];
    table
        .iter()
        .filter(|(ok, pattern, _)| *ok && crate::inventory::path_score(pattern, path).is_some())
        .max_by_key(|(_, pattern, _)| crate::inventory::path_score(pattern, path))
        .map(|(_, _, io)| *io)
}

/// Go's `http.MaxBytesReader` / `ParseMultipartForm` bound.
const CAP: usize = 50 << 20;
/// Go's `bufferBeforeChunkingSize`: output beyond it is sent chunked.
const CHUNKING: usize = 2048;
/// `mailboxExportRecheckEvery`.
const RECHECK_EVERY: usize = 50;

/// Go's `url.ParseQuery`: pairs in order, bad pairs dropped, and whether any was.
pub(crate) fn parse_query(raw: Option<&str>) -> (Vec<(String, String)>, bool) {
    fn unquote(text: &str) -> Option<String> {
        let bytes = text.as_bytes();
        let mut out = Vec::new();
        let mut i = 0;
        while i < bytes.len() {
            match bytes[i] {
                b'%' => {
                    let hex = |b: Option<&u8>| b.and_then(|b| (*b as char).to_digit(16));
                    let (a, b) = (hex(bytes.get(i + 1)), hex(bytes.get(i + 2)));
                    out.push((a? * 16 + b?) as u8);
                    i += 3;
                }
                b'+' => {
                    out.push(b' ');
                    i += 1;
                }
                b => {
                    out.push(b);
                    i += 1;
                }
            }
        }
        Some(crate::guests_input::go_utf8(&out))
    }
    let (mut pairs, mut bad) = (Vec::new(), false);
    for pair in raw.unwrap_or("").split('&') {
        if pair.is_empty() {
            continue;
        }
        if pair.contains(';') {
            bad = true;
            continue;
        }
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        match (unquote(key), unquote(value)) {
            (Some(key), Some(value)) => pairs.push((key, value)),
            _ => bad = true,
        }
    }
    (pairs, bad)
}

/// What Go's `ParseMultipartForm` + `FormFile("file")` + `FormValue` see.
struct Upload {
    values: Vec<(String, String)>,
    file: Option<(String, Vec<u8>)>,
}

async fn upload(r: &mut Request<Body>) -> Result<Upload, ()> {
    use http_body_util::BodyExt;
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
    let mut out = Upload {
        values: Vec::new(),
        file: None,
    };
    let mut parts = 0;
    while let Some(field) = form.next_field().await.map_err(|_| ())? {
        parts += 1;
        if parts > 1000 {
            return Err(());
        }
        let name = field.name().unwrap_or("").to_owned();
        let filename = field
            .file_name()
            .filter(|n| !n.is_empty())
            .map(str::to_owned);
        let data = field.bytes().await.map_err(|_| ())?;
        if name.is_empty() {
            continue;
        }
        match filename {
            Some(filename) => {
                if name == "file" && out.file.is_none() {
                    out.file = Some((filename, data.to_vec()));
                }
            }
            None => out
                .values
                .push((name, String::from_utf8_lossy(&data).into_owned())),
        }
    }
    Ok(out)
}

/// `filepath.Base` on Linux.
fn go_base(path: &str) -> String {
    if path.is_empty() {
        return ".".into();
    }
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        return "/".into();
    }
    trimmed.rsplit('/').next().unwrap_or(trimmed).to_owned()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// One entry of Go's `failed` list; keys render in `encoding/json` map order.
struct Failure {
    index: Option<usize>,
    file: Option<Vec<u8>>,
    error: &'static str,
}

impl Failure {
    fn json(&self) -> String {
        let q = |text: &str| {
            setjoin_mailboxes::go_escape(&serde_json::to_string(text).expect("string"))
        };
        let mut out = format!("{{\"error\":{}", q(self.error));
        if let Some(file) = &self.file {
            out.push_str(&format!(",\"file\":{}", q(&mimeutil::go_lossy(file))));
        }
        if let Some(i) = self.index {
            out.push_str(&format!(",\"index\":{i}"));
        }
        out.push('}');
        out
    }
}

const GENERIC: &str = "Import failed for this message. The file may be malformed.";
const REVOKED: &str = "Not imported: administrative authority was revoked during the import.";

enum Fail {
    Revoked,
    Generic,
}

impl Fail {
    fn text(&self) -> &'static str {
        match self {
            Fail::Revoked => REVOKED,
            Fail::Generic => GENERIC,
        }
    }
}

/// Everything one import needs besides the message.
struct Importer<'a, S: ObjectStore> {
    worker: &'a ScopedExecutor,
    store: &'a S,
    actor: &'a AuthContext,
    scope: i64,
    mailbox: i64,
    tag: Option<i64>,
}

impl<S: ObjectStore> Importer<'_, S> {
    /// Go's `importRawMessage`: parse, upload the raw bytes, then the reducer.
    async fn raw(&self, raw: &[u8]) -> Result<(), Fail> {
        let fields = ImportFields::parse(raw);
        let message_id = if fields.message_id.is_empty() {
            let random = crate::jmap::random().ok_or(Fail::Generic)?;
            format!(
                "<imported-{}@{}>",
                hex(&random),
                chrono::Utc::now().timestamp()
            )
            .into_bytes()
        } else {
            fields.message_id.clone()
        };
        let reference = hex(&Sha256::digest(raw));
        self.store
            .put(&reference, raw, "message/rfc822")
            .await
            .map_err(|_| Fail::Generic)?;
        // Postgres refuses invalid UTF-8 and NUL in a text parameter: that is the
        // reducer call failing in Go, after the upload.
        let strings = db::Strings::of(&fields, &message_id).ok_or(Fail::Generic)?;
        let operation = crate::jmap::random().ok_or(Fail::Generic)?;
        match db::import_message(
            self.worker,
            self.actor,
            self.scope,
            self.mailbox,
            self.tag,
            &strings,
            &fields,
            raw.len() as i64,
            &reference,
            operation,
        )
        .await
        {
            CommandOutcome::Committed(Some(_)) => Ok(()),
            CommandOutcome::Committed(None) => Err(Fail::Revoked),
            _ => Err(Fail::Generic),
        }
    }

    async fn mbox(&self, data: &[u8]) -> (usize, Vec<Failure>) {
        // Split on lines starting "From " (more than five bytes long).
        let mut msgs: Vec<Vec<u8>> = Vec::new();
        let mut current: Vec<u8> = Vec::new();
        for line in data.split(|c| *c == b'\n') {
            if line.len() > 5
                && &line[..5] == b"From "
                && (current.is_empty() || current.last() == Some(&b'\n'))
            {
                if !current.is_empty() {
                    msgs.push(std::mem::take(&mut current));
                }
                current.clear();
                continue;
            }
            current.extend_from_slice(line);
            current.push(b'\n');
        }
        if !current.is_empty() {
            msgs.push(current);
        }
        let (mut imported, mut failed) = (0, Vec::new());
        for (i, raw) in msgs.iter().enumerate() {
            if mimeutil::trim_space(raw).is_empty() {
                continue;
            }
            match self.raw(raw).await {
                Ok(()) => imported += 1,
                Err(e) => failed.push(Failure {
                    index: Some(i),
                    file: None,
                    error: e.text(),
                }),
            }
        }
        (imported, failed)
    }

    async fn eml(&self, data: &[u8]) -> (usize, Vec<Failure>) {
        match self.raw(data).await {
            Ok(()) => (1, Vec::new()),
            Err(e) => (
                0,
                vec![Failure {
                    index: None,
                    file: None,
                    error: e.text(),
                }],
            ),
        }
    }

    async fn zip(&self, data: &[u8]) -> (usize, Vec<Failure>) {
        let only = |error: &'static str| {
            (
                0,
                vec![Failure {
                    index: None,
                    file: None,
                    error,
                }],
            )
        };
        let Ok(mut archive) = Archive::open(data) else {
            return only("Invalid ZIP file. The file may be corrupted.");
        };
        if archive.validate().is_err() {
            return only("ZIP file exceeds the safe import limits.");
        }
        let (mut imported, mut failed, mut expanded) = (0, Vec::new(), 0i64);
        for i in 0..archive.len() {
            let Ok(name) = archive.name(i) else {
                continue;
            };
            if !mimeutil::to_lower(&name).ends_with(b".eml") {
                continue;
            }
            let limit = ziparchive::MAX_ENTRY_BYTES.min(ziparchive::MAX_EXPANDED_BYTES - expanded);
            let raw = match archive.read(i, limit) {
                Ok(raw) => raw,
                Err(()) => {
                    failed.push(Failure {
                        index: None,
                        file: Some(name),
                        error: "Failed to process file inside ZIP.",
                    });
                    continue;
                }
            };
            expanded += raw.len() as i64;
            match self.raw(&raw).await {
                Ok(()) => imported += 1,
                Err(e) => failed.push(Failure {
                    index: None,
                    file: Some(name),
                    error: e.text(),
                }),
            }
        }
        (imported, failed)
    }
}

/// `safeFilename`.
fn safe_filename(message_id: &str) -> Vec<u8> {
    let trimmed = message_id.trim_matches(|c| c == '<' || c == '>');
    let mut s: Vec<u8> = trimmed
        .bytes()
        .map(|b| {
            if matches!(b, b'/' | b'\\' | b':') {
                b'_'
            } else {
                b
            }
        })
        .collect();
    s.truncate(80);
    if s.is_empty() {
        s = b"message".to_vec();
    }
    s
}

/// minio's `GetObject` refuses an invalid object name before any request.
fn object_name_ok(name: &str) -> bool {
    !name.is_empty() && name.len() <= 1024
}

/// The chunked body of a large export, fed by the producer task.
struct ChunkBody {
    first: Option<Bytes>,
    rx: tokio::sync::mpsc::Receiver<Bytes>,
}

impl hyper::body::Body for ChunkBody {
    type Data = Bytes;
    type Error = crate::BoxError;
    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Bytes>, Self::Error>>> {
        if let Some(first) = self.first.take() {
            return std::task::Poll::Ready(Some(Ok(hyper::body::Frame::data(first))));
        }
        self.rx
            .poll_recv(cx)
            .map(|chunk| chunk.map(|b| Ok(hyper::body::Frame::data(b))))
    }
}

struct Export<S: ObjectStore> {
    worker: ScopedExecutor,
    store: Arc<S>,
    actor: i64,
    scope: i64,
    mailbox: i64,
    mbox: bool,
    rows: Vec<(String, String)>,
}

impl<S: ObjectStore + 'static> Export<S> {
    /// `exportStreamRevoked`: any failure of the re-check stops the stream.
    async fn revoked(&self, i: usize) -> bool {
        if i == 0 || !i.is_multiple_of(RECHECK_EVERY) {
            return false;
        }
        !matches!(
            db::reach(&self.worker, self.actor, self.scope, self.mailbox).await,
            Ok(db::Reach::Allowed)
        )
    }

    /// An object's bytes; a failed read leaves nothing, as Go's ignored `io.Copy`.
    async fn object(&self, reference: &str) -> Vec<u8> {
        self.store
            .read(reference, usize::MAX)
            .await
            .unwrap_or_default()
    }

    async fn produce(self, tx: tokio::sync::mpsc::Sender<Bytes>) {
        let mut zip = ZipStream::new();
        for (i, (message_id, reference)) in self.rows.iter().enumerate() {
            if self.revoked(i).await {
                break;
            }
            let chunk = if self.mbox {
                if !object_name_ok(reference) {
                    continue;
                }
                let mut out = format!(
                    "From {message_id} {}\n",
                    chrono::Utc::now().format("%a, %d %b %Y %H:%M:%S UTC")
                )
                .into_bytes();
                out.extend(self.object(reference).await);
                out.push(b'\n');
                out
            } else {
                let name = [
                    format!("{}_", i + 1).into_bytes(),
                    safe_filename(message_id),
                    b".eml".to_vec(),
                ]
                .concat();
                let data = if object_name_ok(reference) {
                    self.object(reference).await
                } else {
                    Vec::new()
                };
                zip.entry(&name, &data)
            };
            if tx.send(Bytes::from(chunk)).await.is_err() {
                return;
            }
        }
        if !self.mbox {
            let _ = tx.send(Bytes::from(zip.finish())).await;
        }
    }
}

impl<K: KeySource + 'static, S: ObjectStore + 'static> Intercept for MailboxIoRoute<K, S> {
    fn requires_session(&self, _req: &Request<Body>) -> bool { true }
    fn matches(&self, r: &Request<Body>) -> bool {
        action(r.method(), r.uri().path()).is_some()
    }
    fn admits_member(&self, headers: hyper::HeaderMap, scheme: &'static str) -> BoxFuture<bool> {
        let (exec, keys, issuer) = (self.exec.clone(), self.keys.clone(), self.issuer.clone());
        Box::pin(async move {
            setjoin_authz::authorize_request(&exec, &keys, &issuer, &headers, scheme)
                .await
                .is_some()
        })
    }
    fn handle(&self, mut r: Request<Body>, c: RequestContext) -> BoxFuture<Response<Body>> {
        let (exec, worker, store, keys, issuer) = (
            self.exec.clone(),
            self.worker.clone(),
            self.store.clone(),
            self.keys.clone(),
            self.issuer.clone(),
        );
        Box::pin(async move {
            let Some(what) = action(r.method(), r.uri().path()) else {
                return c.upstream.forward(r, &c.identity).await;
            };
            let Some(auth) = setjoin_authz::authorize_request(
                &exec,
                &keys,
                &issuer,
                r.headers(),
                c.identity.proto,
            )
            .await
            else {
                return c.upstream.forward(r, &c.identity).await;
            };
            let Some(operation) = crate::jmap::random() else {
                return bare(503, "service unavailable", &c, "");
            };
            let id = crate::jmap::reply::request_id(r.headers().get("x-request-id"), operation);
            let actor = auth.context();
            let Ok(authority) = setjoin_mailboxes::authority(&exec, actor).await else {
                return c.upstream.forward(r, &c.identity).await;
            };
            let path = r.uri().path().to_owned();
            let go_path = segment_path(&path);
            let required: &[&str] = match what {
                Io::Import => &setjoin_mailboxes::USERS_CREATE,
                Io::Export => &setjoin_mailboxes::MAIL_EXPORT,
            };
            if !authority.allows_any(required) {
                let _ = setjoin_mailboxes::console_denied(
                    &exec,
                    actor,
                    &go_path,
                    &required.join("|"),
                    operation,
                )
                .await;
                return bare(403, "Forbidden", &c, &id);
            }
            let scope = authority.domain_scope();
            let actor_id = actor.user_id();
            let head = r.method() == Method::HEAD;
            let reply = |body: String| {
                // net/http buffers 2 KiB of a handler's output; a larger single
                // write is flushed before the handler returns and sent chunked.
                let chunked = body.len() > CHUNKING && !head;
                let mut response = crate::jmap::reply::response(body, c.identity.proto, id.clone());
                if chunked {
                    response.headers_mut().insert(
                        "transfer-encoding",
                        hyper::header::HeaderValue::from_static("chunked"),
                    );
                }
                response
            };
            // `httputil.WriteError`: a minimal problem, empty instance, no language.
            let full = |status: u16, detail: &str| bare(status, detail, &c, &id);
            let Ok(mailbox) = segment(&path, 4).parse::<i64>() else {
                return full(400, "invalid mailbox id");
            };
            if mailbox <= 0 {
                return full(400, "invalid mailbox id");
            }
            match db::reach(&worker, actor_id, scope, mailbox).await {
                Ok(db::Reach::Allowed) => {}
                Ok(db::Reach::OutOfScope) => {
                    return full(403, "target mailbox not within your administrative scope")
                }
                Ok(db::Reach::NotFound) => return full(404, "mailbox not found"),
                Err(_) => return full(500, "database error"),
            }
            let (query, bad_query) = parse_query(r.uri().query());
            let query_value = |name: &str| {
                query
                    .iter()
                    .find(|(k, _)| k == name)
                    .map(|(_, v)| v.clone())
            };
            match what {
                Io::Import => {
                    let form = upload(&mut r).await;
                    let Ok(form) = form else {
                        return full(400, "invalid multipart form");
                    };
                    if bad_query {
                        return full(400, "invalid multipart form");
                    }
                    let Some((filename, data)) = form.file else {
                        return full(400, "file required");
                    };
                    let folder = query_value("folder_id").or_else(|| {
                        form.values
                            .iter()
                            .find(|(k, _)| k == "folder_id")
                            .map(|(_, v)| v.clone())
                    });
                    let mut tag = None;
                    if let Some(folder) = folder.filter(|f| !f.is_empty()) {
                        if let Some(fid) = folder.parse::<i64>().ok().filter(|f| *f > 0) {
                            tag = db::folder_to_tag(&worker, mailbox, fid).await;
                        }
                    }
                    let filename = go_base(&filename);
                    let name = filename.to_lowercase();
                    let importer = Importer {
                        worker: &worker,
                        store: &*store,
                        actor,
                        scope,
                        mailbox,
                        tag,
                    };
                    let (imported, failed) = if name.ends_with(".mbox") {
                        importer.mbox(&data).await
                    } else if name.ends_with(".eml") {
                        importer.eml(&data).await
                    } else if name.ends_with(".zip") {
                        importer.zip(&data).await
                    } else {
                        return full(400, "unsupported file type (use .mbox, .eml, or .zip)");
                    };
                    let after = serde_json::json!({
                        "file": filename,
                        "imported": imported,
                        "failed": failed.len(),
                    })
                    .to_string();
                    if let Some(audit_operation) = crate::jmap::random() {
                        let _ = db::audit_import(
                            &worker,
                            actor,
                            mailbox,
                            &after,
                            &c.identity.client_ip.to_string(),
                            audit_operation,
                        )
                        .await;
                    }
                    let failed_json = if failed.is_empty() {
                        "null".to_owned()
                    } else {
                        format!(
                            "[{}]",
                            failed
                                .iter()
                                .map(Failure::json)
                                .collect::<Vec<_>>()
                                .join(",")
                        )
                    };
                    reply(format!(
                        "{{\"failed\":{failed_json},\"imported\":{imported}}}\n"
                    ))
                }
                Io::Export => {
                    let mbox = query_value("format").as_deref() == Some("mbox");
                    let mut tag = None;
                    if let Some(folder) = query_value("folder_id") {
                        if let Some(fid) = folder.parse::<i64>().ok().filter(|f| *f > 0) {
                            tag = db::folder_to_tag(&worker, mailbox, fid).await;
                        }
                    }
                    let rows = match db::export_rows(&worker, actor_id, scope, mailbox, tag).await {
                        Ok(rows) => rows,
                        Err(_) => return full(500, "database error"),
                    };
                    let (content_type, disposition) = if mbox {
                        ("application/mbox", "attachment; filename=\"export.mbox\"")
                    } else {
                        ("application/zip", "attachment; filename=\"export.zip\"")
                    };
                    let (tx, mut rx) = tokio::sync::mpsc::channel::<Bytes>(4);
                    tokio::spawn(
                        Export {
                            worker: worker.clone(),
                            store: store.clone(),
                            actor: actor_id,
                            scope,
                            mailbox,
                            mbox,
                            rows,
                        }
                        .produce(tx),
                    );
                    // Collect up to the chunking threshold: a short export is sent
                    // with a Content-Length, a longer one chunked, as net/http does.
                    let mut buffered: Vec<u8> = Vec::new();
                    let mut ended = false;
                    while buffered.len() <= CHUNKING {
                        match rx.recv().await {
                            Some(chunk) => buffered.extend_from_slice(&chunk),
                            None => {
                                ended = true;
                                break;
                            }
                        }
                    }
                    let mut response =
                        crate::jmap::reply::response(String::new(), c.identity.proto, id.clone());
                    {
                        let h = response.headers_mut();
                        h.insert(
                            "content-type",
                            hyper::header::HeaderValue::from_static(content_type),
                        );
                        h.insert(
                            "content-disposition",
                            hyper::header::HeaderValue::from_static(disposition),
                        );
                    }
                    if ended || head {
                        // HEAD sends no body; the whole output was produced as Go does.
                        if head && !ended {
                            while rx.recv().await.is_some() {}
                        }
                        use http_body_util::BodyExt;
                        *response.body_mut() = http_body_util::Full::new(Bytes::from(buffered))
                            .map_err(|never| match never {})
                            .boxed();
                    } else {
                        response.headers_mut().insert(
                            "transfer-encoding",
                            hyper::header::HeaderValue::from_static("chunked"),
                        );
                        use http_body_util::BodyExt;
                        *response.body_mut() = ChunkBody {
                            first: Some(Bytes::from(buffered)),
                            rx,
                        }
                        .boxed();
                    }
                    response
                }
            }
        })
    }
}
