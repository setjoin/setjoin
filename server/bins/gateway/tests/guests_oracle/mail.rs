//! Observe token-bearing delivery, validating digest binding before normalization.
use crate::common::{self, BoxError};
use hyper::Response;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
pub type Captures = Arc<Mutex<Vec<(String, Vec<u8>)>>>;
pub async fn endpoint(fail: bool) -> (std::net::SocketAddr, Captures) {
    let captures = Arc::new(Mutex::new(vec![]));
    let output = captures.clone();
    let addr = common::fake_upstream(move |r| {
        let output = output.clone();
        async move {
            if r.method() == hyper::Method::PUT {
                use http_body_util::BodyExt;
                let path = r.uri().path().to_owned();
                let (parts, body) = r.into_parts();
                let request = hyper::Request::from_parts(parts, ());
                let bytes = body.collect().await.unwrap().to_bytes().to_vec();
                common::s3::observe(&request, &bytes).expect("valid storage signature");
                let bytes = if request
                    .headers()
                    .get("x-amz-content-sha256")
                    .is_some_and(|h| h == "STREAMING-AWS4-HMAC-SHA256-PAYLOAD")
                {
                    let mut rest = bytes.as_slice();
                    let mut decoded = vec![];
                    loop {
                        let end = rest
                            .windows(2)
                            .position(|s| s == b"\r\n")
                            .expect("chunk line");
                        let line = std::str::from_utf8(&rest[..end]).unwrap();
                        let size =
                            usize::from_str_radix(line.split(';').next().unwrap(), 16).unwrap();
                        rest = &rest[end + 2..];
                        if size == 0 {
                            break;
                        }
                        decoded.extend_from_slice(&rest[..size]);
                        rest = &rest[size + 2..];
                    }
                    decoded
                } else {
                    bytes
                };
                output.lock().unwrap().push((path, bytes));
                Response::builder()
                    .status(if fail { 503 } else { 200 })
                    .header("etag", "\"stored\"")
                    .body(common::full(""))
                    .unwrap()
            } else {
                Response::new(common::full(
                    "<LocationConstraint>us-east-1</LocationConstraint>",
                ))
            }
        }
    })
    .await;
    (addr, captures)
}
pub async fn observe(
    c: &tokio_postgres::Client,
    email: &str,
    guest: i64,
    captures: &Captures,
    domain: &str,
    wire: bool,
) -> Result<(Value, Vec<String>), BoxError> {
    use mailparse::MailHeaderMap;
    use sha2::{Digest, Sha256};
    let queue = c
        .query(
            "SELECT to_jsonb(t)::text FROM outbound_queue t WHERE $1=ANY(rcpt_addrs) ORDER BY id",
            &[&email],
        )
        .await?
        .iter()
        .map(|r| serde_json::from_str::<Value>(&r.get::<_, String>(0)))
        .collect::<Result<Vec<_>, _>>()?;
    let items = captures.lock().unwrap().clone();
    let mut mail = vec![];
    let mut wire_mimes = vec![];
    let mut token_hash = vec![];
    let mut objects = std::collections::BTreeMap::new();
    for (path, bytes) in items {
        let checksum = hex(&Sha256::digest(&bytes));
        if path != format!("/mailblobs/invite/{checksum}.eml") {
            return Err(format!("MIME object checksum mismatch: {path}").into());
        }
        let parsed = mailparse::parse_mail(&bytes)?;
        let body = parsed.get_body()?;
        let token = body
            .split("?token=")
            .nth(1)
            .and_then(|s| s.split_whitespace().next())
            .ok_or("missing credential")?;
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        if URL_SAFE_NO_PAD.decode(token)?.len() != 32 {
            return Err("bad entropy width".into());
        }
        let hash = hex(&Sha256::digest(token.as_bytes()));
        let invite = c
            .query_one(
                "SELECT token_hash FROM guest_invites WHERE guest_user_id=$1 AND token_hash=$2",
                &[&guest, &hash],
            )
            .await?;
        if invite.get::<_, String>(0) != hash {
            return Err("token not bound to committed digest".into());
        }
        token_hash.push(hash);
        if parsed.headers.get_first_value("To").as_deref() != Some(&format!("<{email}>")) {
            return Err("wrong recipient".into());
        }
        let message = parsed
            .headers
            .get_first_value("Message-ID")
            .ok_or("message ID")?;
        if !message.starts_with("<invite/") || !message.ends_with("@host.test>") {
            return Err("bad message namespace".into());
        }
        objects.insert(
            path.strip_prefix("/mailblobs/")
                .ok_or("bucket path")?
                .to_owned(),
            message.clone(),
        );
        chrono::DateTime::parse_from_rfc2822(
            &parsed.headers.get_first_value("Date").ok_or("date")?,
        )?;
        if wire {
            wire_mimes.push(wire_mime(
                &bytes,
                email,
                domain,
                token,
                &message,
                &parsed.headers.get_first_value("Date").ok_or("date")?,
            )?);
        }
        let mut headers = serde_json::Map::new();
        for h in &parsed.headers {
            headers.insert(h.get_key(), json!(h.get_value()));
        }
        headers.insert("Message-ID".into(), json!("<invite/id@host.test>"));
        headers.insert("Date".into(), json!("<timestamp>"));
        let mut value = json!({"headers":headers,"body":body.replace(token,"<token>"),"content_type":"message/rfc822","object_key":"invite/<sha256>.eml"});
        replace(&mut value, email, "guest@outside.test");
        replace(&mut value, domain, "host.test");
        mail.push(value);
    }
    let mut queue = json!(queue);
    for row in queue.as_array_mut().ok_or("queue")? {
        let id = row["id"].as_i64().ok_or("queue id")?;
        if id <= 0 {
            return Err("bad queue ID".into());
        }
        row["id"] = json!("<queue>");
        let reference = row["raw_ref"].as_str().ok_or("raw_ref")?;
        if !reference.starts_with("invite/") || reference.len() != 75 {
            return Err("bad queued reference".into());
        }
        if objects.get(reference).map(String::as_str) != row["message_id"].as_str() {
            return Err("queue does not reference its stored MIME".into());
        }
        row["raw_ref"] = json!("invite/<sha256>.eml");
        row["message_id"] = json!("<invite/id@host.test>");
        for key in ["created_at", "next_attempt_at", "queued_at"] {
            if let Some(s) = row[key].as_str() {
                chrono::DateTime::parse_from_rfc3339(s)?;
                row[key] = json!("<timestamp>");
            }
        }
    }
    replace(&mut queue, email, "guest@outside.test");
    replace(&mut queue, domain, "host.test");
    let mut value = json!({"mail":mail,"queue":queue});
    if wire {
        value["wire_mime"] = json!(wire_mimes);
    }
    Ok((value, token_hash))
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
pub fn replace(v: &mut Value, from: &str, to: &str) {
    match v {
        Value::String(s) => *s = s.replace(from, to),
        Value::Array(xs) => {
            for x in xs {
                replace(x, from, to)
            }
        }
        Value::Object(xs) => {
            for x in xs.values_mut() {
                replace(x, from, to)
            }
        }
        _ => {}
    }
}
/// Serial test process only; restore deployment configuration on every exit.
pub struct Environment(Vec<(&'static str, Option<std::ffi::OsString>)>);
impl Environment {
    pub fn new(endpoint: std::net::SocketAddr) -> Self {
        let fields = [
            ("S3_ENDPOINT", format!("http://{endpoint}")),
            ("S3_ACCESS_KEY", "test-access".into()),
            ("S3_SECRET_KEY", "test-secret".into()),
            ("S3_BUCKET", "mailblobs".into()),
            ("S3_SECURE", "false".into()),
        ];
        let old = fields
            .iter()
            .map(|(k, _)| (*k, std::env::var_os(k)))
            .collect();
        for (k, v) in fields {
            std::env::set_var(k, v)
        }
        Self(old)
    }
}
impl Drop for Environment {
    fn drop(&mut self) {
        for (k, v) in &self.0 {
            if let Some(v) = v {
                std::env::set_var(k, v)
            } else {
                std::env::remove_var(k)
            }
        }
    }
}

/// Equal-width masks retain Go's exact header spelling, QP byte offsets and
/// total MIME size, while validating the variable values before this step.
fn wire_mime(
    bytes: &[u8],
    email: &str,
    domain: &str,
    token: &str,
    message: &str,
    date: &str,
) -> Result<Value, BoxError> {
    let text = std::str::from_utf8(bytes)?;
    if !text.is_ascii() {
        return Err("wire fixture must be ASCII before QP decoding".into());
    }
    let split = text.find("\r\n\r\n").ok_or("MIME separator")? + 4;
    let header = text[..split]
        .replace(domain, &"d".repeat(domain.len()))
        .replace(email, &"e".repeat(email.len()))
        .replace(message, &"m".repeat(message.len()))
        .replace(date, &"t".repeat(date.len()));
    let mut rest = &text[split..];
    let mut body = String::new();
    let mut breaks = vec![];
    while let Some(at) = rest.find("=\r\n") {
        body.push_str(&rest[..at]);
        breaks.push(body.len());
        rest = &rest[at + 3..];
    }
    body.push_str(rest);
    let body = body
        .replace(domain, &"d".repeat(domain.len()))
        .replace(token, &"T".repeat(token.len()));
    if header.len() + body.len() + breaks.len() * 3 != bytes.len() {
        return Err("wire normalization changed widths".into());
    }
    Ok(json!({"headers":header,"body":body,"soft_break_offsets":breaks,"size":bytes.len()}))
}
