//! Finalization: verified object → mandatory scan → MIME projection → reducer.
use crate::{
    recovery::{go_json, problem, rejection_response, RecoveryCommands},
    Body, BoxFuture, Intercept, RequestContext,
};
use hyper::{Method, Request, Response};
use serde_json::{json, Value};
use setjoin_authz::token::KeySource;
use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

pub trait MalwareScanner: Send + Sync {
    fn scan<'a>(
        &'a self,
        raw: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send + 'a>>;
}
trait ScannerStream: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> ScannerStream for T {}
type Connection = (BufReader<Box<dyn ScannerStream>>, Instant);
pub struct ClamAV {
    address: String,
    connection: tokio::sync::Mutex<Option<Connection>>,
}
impl ClamAV {
    pub fn new(address: String) -> Self {
        Self {
            address,
            connection: tokio::sync::Mutex::new(None),
        }
    }
}
impl MalwareScanner for ClamAV {
    fn scan<'a>(
        &'a self,
        raw: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send + 'a>> {
        Box::pin(async move {
            let mut cached = self.connection.lock().await;
            if cached
                .as_ref()
                .is_some_and(|(_, at)| at.elapsed() >= Duration::from_secs(30))
            {
                *cached = None;
            }
            let exchange = async {
                if cached.is_none() {
                    let stream: Box<dyn ScannerStream> = if self.address.starts_with(['/', '.']) {
                        Box::new(
                            tokio::net::UnixStream::connect(&self.address)
                                .await
                                .map_err(|e| e.to_string())?,
                        )
                    } else {
                        Box::new(
                            tokio::net::TcpStream::connect(&self.address)
                                .await
                                .map_err(|e| e.to_string())?,
                        )
                    };
                    *cached = Some((BufReader::new(stream), Instant::now()));
                }
                let (stream, _) = cached.as_mut().expect("scanner connected");
                stream
                    .get_mut()
                    .write_all(b"nINSTREAM\n")
                    .await
                    .map_err(|e| e.to_string())?;
                for chunk in raw.chunks(4096) {
                    stream
                        .get_mut()
                        .write_u32(chunk.len() as u32)
                        .await
                        .map_err(|e| e.to_string())?;
                    stream
                        .get_mut()
                        .write_all(chunk)
                        .await
                        .map_err(|e| e.to_string())?;
                }
                stream
                    .get_mut()
                    .write_u32(0)
                    .await
                    .map_err(|e| e.to_string())?;
                let mut response = String::new();
                let n = stream
                    .read_line(&mut response)
                    .await
                    .map_err(|e| e.to_string())?;
                if n == 0 || !response.ends_with('\n') {
                    return Err("clamd incomplete response".into());
                }
                let response = response.trim();
                if response.ends_with("OK") {
                    return Ok(String::new());
                }
                if response.contains("FOUND") {
                    let parts: Vec<_> = response.split(' ').collect();
                    if parts.len() >= 3 {
                        return Ok(parts[parts.len() - 2].into());
                    }
                }
                Err("clamd scan failed".into())
            };
            let result = tokio::time::timeout(Duration::from_secs(30), exchange)
                .await
                .unwrap_or_else(|_| Err("clamd timeout".into()));
            if result.is_err() {
                *cached = None;
            }
            result
        })
    }
}

pub struct FinalizeRoute<K: KeySource + 'static>(
    pub Arc<RecoveryCommands<K>>,
    pub Option<Arc<dyn MalwareScanner>>,
);
impl<K: KeySource + 'static> Intercept for FinalizeRoute<K> {
    fn requires_session(&self, _req: &Request<Body>) -> bool { true }
    fn matches(&self, r: &Request<Body>) -> bool {
        r.method() == Method::POST && target(r.uri().path()).is_some()
    }
    fn admits_member(&self, h: hyper::HeaderMap, s: &'static str) -> BoxFuture<bool> {
        let commands = self.0.clone();
        Box::pin(async move { commands.authorize(&h, s).await.is_some() })
    }
    fn handle(&self, r: Request<Body>, c: RequestContext) -> BoxFuture<Response<Body>> {
        let commands = self.0.clone();
        let scanner = self.1.clone();
        Box::pin(async move {
            let Some(a) = commands.authorize(r.headers(), c.identity.proto).await else {
                return c.upstream.forward(r, &c.identity).await;
            };
            let operation = crate::jmap::random().expect("OS random");
            let id = crate::jmap::reply::request_id(r.headers().get("x-request-id"), operation);
            let fail = |detail| problem(400, detail, c.identity.proto, id.clone());
            let raw_session = target(r.uri().path()).expect("matched route");
            let session = String::from_utf8(crate::inventory::unescape(raw_session))
                .ok()
                .and_then(|v| setjoin_blobs::recovery_uuid(&v));
            let Some(session) = session else {
                return problem(400, "invalid recovery identifier", c.identity.proto, id);
            };
            let Ok(Some(meta)) =
                setjoin_blobs::finalize_item(&commands.worker_exec, a.context(), &session).await
            else {
                return fail("mail recovery operation failed");
            };
            let Some(reference) = meta.reference else {
                return fail("mail recovery operation failed");
            };
            if matches!(
                meta.status.as_str(),
                "quarantined" | "deduplicated" | "rejected"
            ) {
                if let Ok(Some(raw)) =
                    setjoin_blobs::replay_finalize(&commands.worker_exec, a.context(), &session)
                        .await
                {
                    if let Ok(value) = serde_json::from_str::<Value>(&raw) {
                        let mut response =
                            crate::jmap::reply::response(go_json(&value), c.identity.proto, id);
                        *response.status_mut() = hyper::StatusCode::CREATED;
                        return response;
                    }
                }
            }
            if reference.is_empty() || meta.size <= 0 || meta.size > 50 << 20 {
                return fail("mail recovery operation failed");
            }
            let Some(store) = &commands.store else {
                return fail("mail recovery operation failed");
            };
            let Ok(raw) = store.read(&reference, (50 << 20) + 1).await else {
                return fail("mail recovery operation failed");
            };
            if raw.len() > 50 << 20 {
                return fail("mail recovery operation failed");
            }
            let Some(scanner) = scanner else {
                return fail("mail recovery operation failed");
            };
            let Ok(virus) = scanner.scan(&raw).await else {
                return fail("mail recovery operation failed");
            };
            let malware = if virus.is_empty() {
                "clean"
            } else {
                "infected"
            };
            let mut reason = if virus.is_empty() {
                None
            } else {
                Some("malware_detected")
            };
            let parsed = match parse_message(&raw, &meta.eligibility) {
                Some(parsed) => parsed,
                None => {
                    reason = Some("malformed_message");
                    empty_parsed(&meta.eligibility)
                }
            };
            let artifact =
                crate::jmap::reply::request_id(None, crate::jmap::random().expect("OS random"));
            let parsed = parsed.to_string();
            match setjoin_blobs::quarantine(
                &commands.worker_exec,
                a.context(),
                setjoin_blobs::Quarantine {
                    session: &session,
                    artifact: &artifact,
                    parsed: &parsed,
                    malware,
                    rejection: reason,
                },
                operation,
            )
            .await
            {
                setjoin_pg::CommandOutcome::Committed(raw) => {
                    let value: Value = serde_json::from_str(&raw).expect("reducer JSON");
                    let mut response =
                        crate::jmap::reply::response(go_json(&value), c.identity.proto, id);
                    *response.status_mut() = hyper::StatusCode::CREATED;
                    response
                }
                setjoin_pg::CommandOutcome::RolledBack(error) => {
                    rejection_response(&error, &r, &c, id, "mail recovery operation failed", 400)
                }
                setjoin_pg::CommandOutcome::Unknown { operation } => {
                    let mut response =
                        problem(503, "recovery upload outcome unknown", c.identity.proto, id);
                    response.headers_mut().insert(
                        "x-operation-id",
                        setjoin_pg::operation_hex(operation).parse().expect("hex"),
                    );
                    response
                }
            }
        })
    }
}
fn target(path: &str) -> Option<&str> {
    let value = path
        .strip_prefix("/api/recovery/uploads/")?
        .strip_suffix("/finalize")?;
    (!value.is_empty() && !value.contains('/')).then_some(value)
}
fn empty_parsed(eligibility: &str) -> Value {
    json!({"messageId":"","subject":"","fromAddr":"","fromName":"","toAddrs":null,"ccAddrs":null,"bccAddrs":null,"inReplyTo":"","references":"","bodyText":"","bodyHtml":"","receivedAt":"","eligibility":eligibility})
}
fn parse_message(raw: &[u8], eligibility: &str) -> Option<Value> {
    if raw.is_empty()
        || raw.len() > 50 << 20
        || !matches!(eligibility, "received" | "sent-terminal")
    {
        return None;
    }
    let parsed = mailparse::parse_mail(raw).ok()?;
    let text = String::from_utf8_lossy(raw);
    let (from_name, from_addr) = address(&header(&text, "From"));
    if from_addr.is_empty() || from_addr.len() > 320 {
        return None;
    }
    let now = chrono::Utc::now();
    let received = chrono::DateTime::parse_from_rfc2822(&header(&text, "Date"))
        .ok()
        .filter(|d| {
            *d < now + chrono::Duration::minutes(5)
                && *d
                    > now
                        .checked_sub_months(chrono::Months::new(240))
                        .unwrap_or(now)
        })
        .map(|v| v.with_timezone(&chrono::Utc))
        .unwrap_or(now);
    let content_type = header(&text, "Content-Type");
    let multipart = content_type.to_lowercase().contains("multipart");
    let (mut plain, mut html) = if multipart {
        let mut plain = String::new();
        let mut html = String::new();
        walk_parts(&parsed, &mut plain, &mut html);
        (plain, html)
    } else {
        let body = split_body(raw).unwrap_or_default();
        let decoded = decode_charset(body, &content_type);
        (
            decoded.clone(),
            if content_type.to_lowercase().contains("text/html") {
                decoded
            } else {
                String::new()
            },
        )
    };
    truncate_bytes(&mut plain, 64 << 10);
    truncate_bytes(&mut html, 64 << 10);
    Some(
        json!({"messageId":header(&text,"Message-ID"),"subject":header(&text,"Subject"),"fromAddr":from_addr,"fromName":from_name,"toAddrs":addresses(&header(&text,"To")),"ccAddrs":addresses(&header(&text,"Cc")),"bccAddrs":addresses(&header(&text,"Bcc")),"inReplyTo":header(&text,"In-Reply-To"),"references":header(&text,"References"),"bodyText":plain,"bodyHtml":html,"receivedAt":received.format("%Y-%m-%dT%H:%M:%SZ").to_string(),"eligibility":eligibility}),
    )
}
fn header(raw: &str, name: &str) -> String {
    let end = raw
        .find("\r\n\r\n")
        .or_else(|| raw.find("\n\n"))
        .unwrap_or(raw.len());
    let mut unfolded = Vec::<String>::new();
    for line in raw[..end].split('\n') {
        let line = line.trim_end_matches('\r');
        if line.starts_with([' ', '\t']) {
            if let Some(last) = unfolded.last_mut() {
                last.push(' ');
                last.push_str(line.trim());
            }
        } else {
            unfolded.push(line.into());
        }
    }
    for line in unfolded {
        if let Some((key, value)) = line.split_once(':') {
            if key.trim().eq_ignore_ascii_case(name) {
                let value = value.trim();
                if value.starts_with("=?")
                    && value.ends_with("?=")
                    && value.matches("?=").count() == 1
                {
                    if let Ok((header, _)) =
                        mailparse::parse_header(format!("{name}: {value}").as_bytes())
                    {
                        return header.get_value();
                    }
                }
                return value.into();
            }
        }
    }
    String::new()
}
fn address(value: &str) -> (String, String) {
    if let Ok(list) = mailparse::addrparse(value) {
        if list.len() == 1 {
            if let mailparse::MailAddr::Single(a) = &list[0] {
                return (a.display_name.clone().unwrap_or_default(), a.addr.clone());
            }
        }
    }
    let trimmed = value.trim();
    let email = if let Some((_, rest)) = trimmed.split_once('<') {
        rest.split_once('>').map(|v| v.0).unwrap_or(trimmed)
    } else {
        trimmed.trim_matches(['<', '>'])
    };
    (String::new(), email.into())
}
fn addresses(value: &str) -> Value {
    if value.is_empty() {
        return json!([]);
    }
    let single = |name: String, email: String| {
        if name.is_empty() {
            json!({"email":email})
        } else {
            json!({"name":name,"email":email})
        }
    };
    if let Ok(list) = mailparse::addrparse(value) {
        let mut result = Vec::new();
        for addr in list.iter() {
            match addr {
                mailparse::MailAddr::Single(a) => result.push(single(
                    a.display_name.clone().unwrap_or_default(),
                    a.addr.clone(),
                )),
                mailparse::MailAddr::Group(g) => {
                    for a in &g.addrs {
                        result.push(single(
                            a.display_name.clone().unwrap_or_default(),
                            a.addr.clone(),
                        ));
                    }
                }
            }
        }
        json!(result)
    } else {
        json!(value
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| {
                let (n, e) = address(s);
                single(n, e)
            })
            .collect::<Vec<_>>())
    }
}
fn split_body(raw: &[u8]) -> Option<&[u8]> {
    raw.windows(4)
        .position(|v| v == b"\r\n\r\n")
        .map(|i| &raw[i + 4..])
        .or_else(|| {
            raw.windows(2)
                .position(|v| v == b"\n\n")
                .map(|i| &raw[i + 2..])
        })
}
fn decode_charset(body: &[u8], content_type: &str) -> String {
    let body = std::str::from_utf8(body)
        .map(|s| s.trim().as_bytes())
        .unwrap_or_else(|_| body.trim_ascii());
    let charset = mailparse::parse_content_type(content_type)
        .params
        .get("charset")
        .cloned()
        .unwrap_or_default();
    if charset.is_empty()
        || charset.eq_ignore_ascii_case("utf-8")
        || charset.eq_ignore_ascii_case("us-ascii")
    {
        return String::from_utf8_lossy(body).into();
    }
    encoding_rs::Encoding::for_label(charset.as_bytes())
        .map(|e| e.decode(body).0.into_owned())
        .unwrap_or_else(|| String::from_utf8_lossy(body).into())
}
fn walk_parts(part: &mailparse::ParsedMail<'_>, plain: &mut String, html: &mut String) {
    for child in &part.subparts {
        let text = String::from_utf8_lossy(child.raw_bytes);
        let ct = header(&text, "Content-Type");
        let headers = text
            .split_once("\r\n\r\n")
            .or_else(|| text.split_once("\n\n"))
            .map(|p| p.0)
            .unwrap_or(&text)
            .to_lowercase();
        if plain.is_empty() && headers.contains("content-type: text/plain") {
            *plain = decode_charset(split_body(child.raw_bytes).unwrap_or_default(), &ct);
        }
        if html.is_empty() && headers.contains("content-type: text/html") {
            *html = decode_charset(split_body(child.raw_bytes).unwrap_or_default(), &ct);
        }
        walk_parts(child, plain, html);
    }
}
fn truncate_bytes(value: &mut String, limit: usize) {
    if value.len() > limit {
        let bytes = value.as_bytes()[..limit].to_vec();
        *value = String::from_utf8_lossy(&bytes).into();
    }
}
