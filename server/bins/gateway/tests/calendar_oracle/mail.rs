//! The mail the booking routes queue: the fake object store records every PUT
//! (its SigV4 signature is checked), and the outbound queue rows are read back.
//! Message ids, dates, boundaries, tokens and days are masked after their shape
//! is validated, so Go and Rust compare on everything else.
use crate::common::{self, BoxError};
use hyper::Response;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex};

pub type Captures = Arc<Mutex<Vec<(String, Vec<u8>)>>>;

pub async fn endpoint() -> (std::net::SocketAddr, Captures) {
    let captures: Captures = Arc::new(Mutex::new(vec![]));
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
                    .status(200)
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

/// Wait for the detached sends of a confirmed booking to reach the queue.
pub async fn settle(c: &tokio_postgres::Client, mark: i64, rows: usize) -> Result<(), BoxError> {
    for _ in 0..200 {
        let n: i64 = c
            .query_one("SELECT count(*) FROM outbound_queue WHERE id>$1", &[&mark])
            .await?
            .get(0);
        if n as usize >= rows {
            return Ok(());
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    Err(format!("expected {rows} queued messages").into())
}

fn hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// `Date`, `Message-ID`, the boundary, DTSTAMP, the UID and the token vary per run.
fn normalize(text: &str, d: &str, names: &dyn Fn(&str) -> String) -> String {
    let compact = d.replace('-', "");
    let long = chrono::NaiveDate::parse_from_str(d, "%Y-%m-%d")
        .map(|day| day.format("%A, %B %-d, %Y").to_string())
        .unwrap_or_default();
    let mut out = String::new();
    for (i, line) in text.split("\r\n").enumerate() {
        if i > 0 {
            out.push_str("\r\n");
        }
        let line = if line.starts_with("Date: ") {
            "Date: <date>".to_owned()
        } else if let Some(rest) = line.strip_prefix("Message-ID: <") {
            let (local, domain) = rest.split_once('@').unwrap_or((rest, ""));
            let local: String = local.chars().filter(|c| !c.is_ascii_digit()).collect();
            format!("Message-ID: <{local}<n>@{domain}")
        } else if line.starts_with("DTSTAMP:") {
            "DTSTAMP:<stamp>".to_owned()
        } else if line.starts_with("UID:") {
            "UID:<uid>".to_owned()
        } else {
            line.to_owned()
        };
        out.push_str(&line);
    }
    // boundary=mailserver-imip-<nanos>
    let mut masked = String::new();
    let mut rest = out.as_str();
    while let Some(at) = rest.find("mailserver-imip-") {
        masked.push_str(&rest[..at + 16]);
        rest = &rest[at + 16..];
        let digits = rest.chars().take_while(char::is_ascii_digit).count();
        masked.push_str("<n>");
        rest = &rest[digits..];
    }
    masked.push_str(rest);
    let result = masked;
    names(
        &result
            .replace(&compact, "<D-compact>")
            .replace(&long, "<D-long>")
            .replace(d, "<D>"),
    )
}

pub async fn observe(
    c: &tokio_postgres::Client,
    mark: i64,
    captures: &Captures,
    capture_mark: usize,
    names: &dyn Fn(&str) -> String,
    d: &str,
) -> Result<Vec<Value>, BoxError> {
    let queue = c
        .query(
            "SELECT message_id, from_addr, rcpt_addrs, raw_ref, status, dkim_signed, attempt_count, mailbox_id IS NOT NULL FROM outbound_queue WHERE id>$1 ORDER BY id",
            &[&mark],
        )
        .await?;
    let items = captures.lock().unwrap()[capture_mark..].to_vec();
    let mut out = vec![];
    for row in &queue {
        let message: String = row.get(0);
        let reference: String = row.get(3);
        let object = items
            .iter()
            .find(|(path, _)| path == &format!("/mailblobs/{reference}"))
            .ok_or_else(|| format!("no stored object for {reference}"))?;
        let checksum = hex(&object.1);
        let prefix = reference.rsplit_once('/').map_or("", |(p, _)| p);
        if reference != format!("{prefix}/{checksum}.eml") {
            return Err(format!("object key is not content-addressed: {reference}").into());
        }
        let text = String::from_utf8(object.1.clone())?;
        // Soft line breaks of the quoted-printable body are layout, recorded by
        // offset; the verification token (equal-width mask) is validated first.
        let split = text.find("\r\n\r\n").map_or(0, |at| at + 4);
        let (head, body) = text.split_at(split);
        let mut joined = String::new();
        let mut breaks = vec![];
        let mut rest = body;
        while let Some(at) = rest.find("=\r\n") {
            joined.push_str(&rest[..at]);
            breaks.push(joined.len());
            rest = &rest[at + 3..];
        }
        joined.push_str(rest);
        let mut joined = joined;
        if let Some(at) = joined.find("token=3D") {
            let token: String = joined[at + 8..]
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
                .collect();
            use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
            if URL_SAFE_NO_PAD.decode(&token)?.len() != 32 {
                return Err("bad verification token entropy".into());
            }
            let found: i64 = c
                .query_one(
                    "SELECT count(*) FROM booking_requests WHERE verify_token_hash=$1",
                    &[&hex(token.as_bytes())],
                )
                .await?
                .get(0);
            if found != 1 {
                return Err("token not bound to a committed digest".into());
            }
            joined = joined.replace(&token, &"T".repeat(token.len()));
        }
        let normalized = json!({
            "headers": normalize(head, d, names),
            "body": normalize(&joined, d, names),
            "soft_break_offsets": breaks,
            "size": object.1.len(),
        });
        let (local, domain) = message.split_once('@').unwrap_or((message.as_str(), ""));
        let local: String = local.chars().filter(|ch| !ch.is_ascii_digit()).collect();
        let message_domain = domain.to_owned();
        out.push(json!({
            "message_id": names(&if prefix == "imip" { "<event-uid>".to_owned() } else { format!("{local}<n>@{message_domain}") }),
            "from": names(&row.get::<_, String>(1)),
            "to": row.get::<_, Vec<String>>(2).iter().map(|a| names(a)).collect::<Vec<_>>(),
            "object_prefix": prefix,
            "status": row.get::<_, String>(4),
            "dkim_signed": row.get::<_, bool>(5),
            "attempts": row.get::<_, i32>(6),
            "mailbox_bound": row.get::<_, bool>(7),
            "mime": normalized,
        }));
    }
    out.sort_by_key(|v| v["object_prefix"].as_str().unwrap_or("").to_owned());
    Ok(out)
}
