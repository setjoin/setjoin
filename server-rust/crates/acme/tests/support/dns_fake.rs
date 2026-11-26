//! In-process DNS/provider API peripheral for #413 DNS-01 tests.
//! Pure-Rust port of the former Go fake (Cloudflare HTTP, Route53 XML/SigV4, RFC2136 UDP/TSIG).
use base64::Engine;
use hickory_proto::{
    op::{Message, MessageType, OpCode, ResponseCode},
    rr::{
        rdata::{
            tsig::{make_tsig_record, message_tbs, signed_bitmessage_to_buf, TsigAlgorithm, TSIG},
            A, NS, SOA,
        },
        Name, RData, Record, RecordType,
    },
};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    net::Ipv4Addr,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    task::JoinHandle,
};

const CF_TOKEN: &str = "public-test-token";
const AWS_ACCESS_KEY: &str = "public-access";
const AWS_SECRET_KEY: &str = "public-secret";
const TSIG_KEY_NAME: &str = "fixture-key.";
const TSIG_SECRET_B64: &str = "cHVibGljLXRlc3Qta2V5";

pub struct PublishGate {
    pub started: PathBuf,
    pub release: PathBuf,
}

pub struct DnsFake {
    pub http_url: String,
    pub dns_addr: String,
    http_task: JoinHandle<()>,
    dns_task: JoinHandle<()>,
}

impl Drop for DnsFake {
    fn drop(&mut self) {
        self.http_task.abort();
        self.dns_task.abort();
    }
}

struct State {
    journal_path: PathBuf,
    events: Vec<Value>,
    records: HashMap<String, Vec<String>>,
}

impl State {
    fn new(journal_path: PathBuf) -> Self {
        let mut records = HashMap::new();
        records.insert(
            "_acme-challenge.example.test.".to_owned(),
            vec!["\"keep\"".to_owned()],
        );
        Self {
            journal_path,
            events: Vec::new(),
            records,
        }
    }

    fn journal(&mut self, event: Value) {
        self.events.push(event);
        let bytes = serde_json::to_vec(&self.events).expect("serialize dns fake journal");
        std::fs::write(&self.journal_path, bytes).expect("write dns fake journal");
    }
}

fn normalize_value(v: &str) -> String {
    if v == "\"keep\"" || v == "keep" {
        return v.to_owned();
    }
    let trimmed = v.trim_matches('"');
    match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(trimmed) {
        Ok(raw) if raw.len() == 32 => v.replace(trimmed, "$CHALLENGE"),
        _ => format!("INVALID-TXT:{v}"),
    }
}

impl DnsFake {
    pub async fn start(
        journal_path: PathBuf,
        allow_unsigned: bool,
        gate: Option<PublishGate>,
    ) -> Self {
        let state = Arc::new(Mutex::new(State::new(journal_path)));
        let gate = gate.map(Arc::new);

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake provider HTTP listener");
        let http_url = format!("http://{}", listener.local_addr().unwrap());
        let http_state = state.clone();
        let http_task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let state = http_state.clone();
                let gate = gate.clone();
                tokio::spawn(async move {
                    let _ = handle_http(stream, state, gate).await;
                });
            }
        });

        let udp = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind fake DNS UDP socket");
        let dns_addr = udp.local_addr().unwrap().to_string();
        let dns_state = state;
        let dns_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                let Ok((len, peer)) = udp.recv_from(&mut buf).await else {
                    break;
                };
                if let Some(reply) = handle_dns(&buf[..len], &dns_state, allow_unsigned) {
                    let _ = udp.send_to(&reply, peer).await;
                }
            }
        });

        Self {
            http_url,
            dns_addr,
            http_task,
            dns_task,
        }
    }
}

struct HttpRequest {
    method: String,
    path: String,
    raw_query: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl HttpRequest {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    fn query_param(&self, key: &str) -> String {
        for part in self.raw_query.split('&') {
            if part.is_empty() {
                continue;
            }
            let (k, v) = part.split_once('=').unwrap_or((part, ""));
            if percent_decode(k) == key {
                return percent_decode(v);
            }
        }
        String::new()
    }
}

async fn read_http_request(stream: &mut TcpStream) -> Option<HttpRequest> {
    let mut buf = Vec::with_capacity(2048);
    let mut chunk = [0u8; 2048];
    let header_end = loop {
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos;
        }
        let n = stream.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > 1024 * 1024 {
            return None;
        }
    };
    let head = std::str::from_utf8(&buf[..header_end]).ok()?;
    let mut lines = head.split("\r\n");
    let request_line = lines.next()?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next()?.to_owned();
    let target = parts.next()?;
    let (path, raw_query) = match target.split_once('?') {
        Some((p, q)) => (p.to_owned(), q.to_owned()),
        None => (target.to_owned(), String::new()),
    };
    let mut headers = Vec::new();
    let mut content_length = 0usize;
    for line in lines {
        if let Some((name, val)) = line.split_once(':') {
            let name = name.trim().to_ascii_lowercase();
            let val = val.trim().to_owned();
            if name == "content-length" {
                content_length = val.parse().ok()?;
            }
            headers.push((name, val));
        }
    }
    let body_start = header_end + 4;
    while buf.len() < body_start + content_length {
        let n = stream.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    let body = buf[body_start..body_start + content_length].to_vec();
    Some(HttpRequest {
        method,
        path,
        raw_query,
        headers,
        body,
    })
}

async fn write_http_response(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &str,
) -> std::io::Result<()> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        _ => "Internal Server Error",
    };
    let resp = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(resp.as_bytes()).await?;
    stream.shutdown().await
}

async fn handle_http(
    mut stream: TcpStream,
    state: Arc<Mutex<State>>,
    gate: Option<Arc<PublishGate>>,
) -> std::io::Result<()> {
    let Some(req) = read_http_request(&mut stream).await else {
        return Ok(());
    };
    if req.path.starts_with("/client/v4/") {
        if req.header("authorization") != Some(&format!("Bearer {CF_TOKEN}")) {
            return write_http_response(&mut stream, 403, "text/plain", "auth").await;
        }
        if req.path == "/client/v4/zones" {
            let name = req.query_param("name");
            state
                .lock()
                .unwrap()
                .journal(json!({"api": "cf", "op": "zone", "name": name}));
            return write_http_response(
                &mut stream,
                200,
                "application/json",
                r#"{"success":true,"result":[{"id":"zone-id","name":"example.test"}]}"#,
            )
            .await;
        }
        if req.method == "POST" {
            let Ok(mut record) =
                serde_json::from_slice::<serde_json::Map<String, Value>>(&req.body)
            else {
                return write_http_response(&mut stream, 400, "text/plain", "json").await;
            };
            let content = record
                .get("content")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            let name = record
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            record.insert("content".into(), json!(normalize_value(&content)));
            state
                .lock()
                .unwrap()
                .journal(json!({"api": "cf", "op": "present", "record": record}));
            if let Some(gate) = gate {
                std::fs::write(&gate.started, b"published")?;
                let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
                while !gate.release.exists() {
                    if tokio::time::Instant::now() >= deadline {
                        return write_http_response(
                            &mut stream,
                            500,
                            "text/plain",
                            "publish gate timed out",
                        )
                        .await;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }
            let id = if name.contains(".alt.") {
                "record-id-alt"
            } else {
                "record-id"
            };
            let body = json!({
                "success": true,
                "result": {"id": id, "type": "TXT", "name": name, "content": "fixture"}
            })
            .to_string();
            return write_http_response(&mut stream, 200, "application/json", &body).await;
        }
        if req.method == "DELETE" {
            state
                .lock()
                .unwrap()
                .journal(json!({"api": "cf", "op": "cleanup", "path": req.path}));
            return write_http_response(
                &mut stream,
                200,
                "application/json",
                r#"{"success":true,"result":{"id":"record-id"}}"#,
            )
            .await;
        }
        return write_http_response(&mut stream, 400, "text/plain", "unknown CF call").await;
    }

    if !verify_aws_sigv4(&req) {
        return write_http_response(&mut stream, 403, "text/plain", "signature").await;
    }

    if req.path == "/2013-04-01/hostedzonesbyname" {
        state
            .lock()
            .unwrap()
            .journal(json!({"api": "r53", "op": "zones"}));
        let body = r#"<ListHostedZonesByNameResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/"><HostedZones><HostedZone><Id>/hostedzone/ZFIXTURE</Id><Name>example.test.</Name><Config><PrivateZone>false</PrivateZone></Config></HostedZone></HostedZones><IsTruncated>false</IsTruncated><MaxItems>100</MaxItems></ListHostedZonesByNameResponse>"#;
        return write_http_response(&mut stream, 200, "text/xml", body).await;
    }
    if req.method == "GET" && req.path.ends_with("/rrset") {
        let name = req.query_param("name");
        let kind = req.query_param("type");
        let values = {
            let mut st = state.lock().unwrap();
            st.journal(json!({"api": "r53", "op": "records", "name": name, "type": kind}));
            st.records.get(&name).cloned().unwrap_or_default()
        };
        let mut body = String::from(
            r#"<ListResourceRecordSetsResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/"><ResourceRecordSets>"#,
        );
        if !values.is_empty() {
            body.push_str(&format!(
                "<ResourceRecordSet><Name>{name}</Name><Type>TXT</Type><TTL>0</TTL><ResourceRecords>"
            ));
            for v in &values {
                body.push_str(&format!(
                    "<ResourceRecord><Value>{v}</Value></ResourceRecord>"
                ));
            }
            body.push_str("</ResourceRecords></ResourceRecordSet>");
        }
        body.push_str(
            "</ResourceRecordSets><IsTruncated>false</IsTruncated><MaxItems>100</MaxItems></ListResourceRecordSetsResponse>",
        );
        return write_http_response(&mut stream, 200, "text/xml", &body).await;
    }
    if req.method == "POST" && req.path.ends_with("/rrset") {
        let Ok(change) = parse_r53_change(&req.body) else {
            return write_http_response(&mut stream, 400, "text/plain", "xml").await;
        };
        let norm: Vec<String> = change.values.iter().map(|v| normalize_value(v)).collect();
        {
            let mut st = state.lock().unwrap();
            st.journal(json!({
                "api": "r53",
                "op": change.action,
                "name": change.name,
                "ttl": change.ttl,
                "values": norm,
            }));
            if change.action == "DELETE" {
                st.records.remove(&change.name);
            } else {
                st.records.insert(change.name, change.values);
            }
        }
        let body = r#"<ChangeResourceRecordSetsResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/"><ChangeInfo><Id>/change/fixture</Id><Status>INSYNC</Status><SubmittedAt>2026-01-01T00:00:00Z</SubmittedAt></ChangeInfo></ChangeResourceRecordSetsResponse>"#;
        return write_http_response(&mut stream, 200, "text/xml", body).await;
    }
    write_http_response(&mut stream, 400, "text/plain", "unknown R53 call").await
}

struct R53Change {
    action: String,
    name: String,
    ttl: i64,
    values: Vec<String>,
}

fn parse_r53_change(body: &[u8]) -> Result<R53Change, String> {
    #[derive(Deserialize)]
    struct Req {
        #[serde(rename = "ChangeBatch")]
        batch: Batch,
    }
    #[derive(Deserialize)]
    struct Batch {
        #[serde(rename = "Changes")]
        changes: Changes,
    }
    #[derive(Deserialize)]
    struct Changes {
        #[serde(rename = "Change", default)]
        items: Vec<Item>,
    }
    #[derive(Deserialize)]
    struct Item {
        #[serde(rename = "Action")]
        action: String,
        #[serde(rename = "ResourceRecordSet")]
        set: Set,
    }
    #[derive(Deserialize)]
    struct Set {
        #[serde(rename = "Name")]
        name: String,
        #[serde(rename = "TTL")]
        ttl: i64,
        #[serde(rename = "ResourceRecords")]
        records: Records,
    }
    #[derive(Deserialize)]
    struct Records {
        #[serde(rename = "ResourceRecord", default)]
        items: Vec<Rec>,
    }
    #[derive(Deserialize)]
    struct Rec {
        #[serde(rename = "Value")]
        value: String,
    }
    let text = std::str::from_utf8(body).map_err(|e| e.to_string())?;
    let parsed: Req = quick_xml::de::from_str(text).map_err(|e| e.to_string())?;
    if parsed.batch.changes.items.len() != 1 {
        return Err("changes != 1".into());
    }
    let item = parsed.batch.changes.items.into_iter().next().unwrap();
    Ok(R53Change {
        action: item.action,
        name: item.set.name,
        ttl: item.set.ttl,
        values: item
            .set
            .records
            .items
            .into_iter()
            .map(|r| r.value)
            .collect(),
    })
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(&mut out, "{b:02x}");
    }
    out
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(hex) = std::str::from_utf8(&bytes[i + 1..i + 3]) {
                if let Ok(val) = u8::from_str_radix(hex, 16) {
                    out.push(val);
                    i += 3;
                    continue;
                }
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn aws_uri_encode(s: &str, encode_slash: bool) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        let keep = b.is_ascii_alphanumeric()
            || matches!(b, b'-' | b'_' | b'.' | b'~')
            || (!encode_slash && b == b'/');
        if keep {
            out.push(b as char);
        } else {
            use std::fmt::Write;
            let _ = write!(&mut out, "%{b:02X}");
        }
    }
    out
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let tag = ring::hmac::sign(&ring::hmac::Key::new(ring::hmac::HMAC_SHA256, key), data);
    tag.as_ref().try_into().unwrap()
}

/// Independent AWS Signature Version 4 verifier (mirrors official SDK rules).
fn verify_aws_sigv4(req: &HttpRequest) -> bool {
    let Some(auth) = req.header("authorization") else {
        return false;
    };
    let Some(amz_date) = req.header("x-amz-date") else {
        return false;
    };
    if amz_date.len() != 16 || !amz_date.ends_with('Z') {
        return false;
    }
    let Some(rest) = auth.strip_prefix("AWS4-HMAC-SHA256 ") else {
        return false;
    };
    let mut credential = None;
    let mut signed_headers = None;
    let mut signature = None;
    for part in rest.split(',') {
        let part = part.trim();
        if let Some(v) = part.strip_prefix("Credential=") {
            credential = Some(v);
        } else if let Some(v) = part.strip_prefix("SignedHeaders=") {
            signed_headers = Some(v);
        } else if let Some(v) = part.strip_prefix("Signature=") {
            signature = Some(v);
        }
    }
    let (Some(credential), Some(signed_headers), Some(signature)) =
        (credential, signed_headers, signature)
    else {
        return false;
    };
    let cred_parts: Vec<&str> = credential.split('/').collect();
    if cred_parts.len() != 5 {
        return false;
    }
    let (access_key, date, region, service, term) = (
        cred_parts[0],
        cred_parts[1],
        cred_parts[2],
        cred_parts[3],
        cred_parts[4],
    );
    if access_key != AWS_ACCESS_KEY
        || region != "us-east-1"
        || service != "route53"
        || term != "aws4_request"
        || !amz_date.starts_with(date)
    {
        return false;
    }

    let payload_hash = hex_lower(&Sha256::digest(&req.body));
    if let Some(hdr_hash) = req.header("x-amz-content-sha256") {
        if hdr_hash != payload_hash {
            return false;
        }
    }

    let canonical_uri = if req.path.is_empty() {
        "/".to_owned()
    } else {
        aws_uri_encode(&percent_decode(&req.path), false)
    };
    let mut query_pairs: Vec<(String, String)> = req
        .raw_query
        .split('&')
        .filter(|s| !s.is_empty())
        .map(|part| {
            let (k, v) = part.split_once('=').unwrap_or((part, ""));
            (
                aws_uri_encode(&percent_decode(k), true),
                aws_uri_encode(&percent_decode(v), true),
            )
        })
        .collect();
    query_pairs.sort();
    let canonical_query = query_pairs
        .into_iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&");

    let mut canonical_headers = String::new();
    for name in signed_headers.split(';') {
        let vals: Vec<String> = req
            .headers
            .iter()
            .filter(|(k, _)| k == name)
            .map(|(_, v)| v.split_whitespace().collect::<Vec<_>>().join(" "))
            .collect();
        if vals.is_empty() {
            return false;
        }
        canonical_headers.push_str(name);
        canonical_headers.push(':');
        canonical_headers.push_str(&vals.join(","));
        canonical_headers.push('\n');
    }

    let canonical_request = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        req.method, canonical_uri, canonical_query, canonical_headers, signed_headers, payload_hash
    );
    let canonical_hash = hex_lower(&Sha256::digest(canonical_request.as_bytes()));
    let scope = format!("{date}/{region}/{service}/aws4_request");
    let string_to_sign = format!("AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{canonical_hash}");

    let k_date = hmac_sha256(format!("AWS4{AWS_SECRET_KEY}").as_bytes(), date.as_bytes());
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, service.as_bytes());
    let k_signing = hmac_sha256(&k_service, b"aws4_request");
    let expected = hex_lower(&hmac_sha256(&k_signing, string_to_sign.as_bytes()));

    expected.len() == signature.len()
        && openssl::memcmp::eq(expected.as_bytes(), signature.as_bytes())
}

fn tsig_hmac(algorithm: &TsigAlgorithm, secret: &[u8], data: &[u8]) -> Option<Vec<u8>> {
    let digest = match algorithm {
        TsigAlgorithm::HmacSha1 => openssl::hash::MessageDigest::sha1(),
        TsigAlgorithm::HmacSha224 => openssl::hash::MessageDigest::sha224(),
        TsigAlgorithm::HmacSha256 => openssl::hash::MessageDigest::sha256(),
        TsigAlgorithm::HmacSha384 => openssl::hash::MessageDigest::sha384(),
        TsigAlgorithm::HmacSha512 => openssl::hash::MessageDigest::sha512(),
        _ => return None,
    };
    let key = openssl::pkey::PKey::hmac(secret).ok()?;
    let mut signer = openssl::sign::Signer::new(digest, &key).ok()?;
    signer.update(data).ok()?;
    signer.sign_to_vec().ok()
}

fn handle_dns(packet: &[u8], state: &Arc<Mutex<State>>, allow_unsigned: bool) -> Option<Vec<u8>> {
    let req = Message::from_vec(packet).ok()?;
    let mut reply = Message::query();
    reply.metadata.id = req.metadata.id;
    reply.metadata.message_type = MessageType::Response;
    reply.metadata.op_code = req.metadata.op_code;
    reply.metadata.authoritative = true;
    reply.metadata.recursion_desired = req.metadata.recursion_desired;
    for q in &req.queries {
        reply.add_query(q.clone());
    }

    if req.metadata.op_code == OpCode::Update {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
        let secret = base64::engine::general_purpose::STANDARD
            .decode(TSIG_SECRET_B64)
            .ok()?;
        let expected_name = Name::from_ascii(TSIG_KEY_NAME).ok()?;

        let verified_tsig = match &req.signature {
            None => {
                if !allow_unsigned {
                    reply.metadata.response_code = ResponseCode::NotAuth;
                    return reply.to_vec().ok();
                }
                None
            }
            Some(_) => {
                let Ok((tbs, tsig_rr)) = signed_bitmessage_to_buf(packet, None, true) else {
                    reply.metadata.response_code = ResponseCode::NotAuth;
                    return reply.to_vec().ok();
                };
                let valid = tsig_rr.name == expected_name
                    && tsig_rr.data.time.abs_diff(now) <= u64::from(tsig_rr.data.fudge)
                    && tsig_hmac(&tsig_rr.data.algorithm, &secret, &tbs).is_some_and(|expected| {
                        expected.len() == tsig_rr.data.mac.len()
                            && openssl::memcmp::eq(&expected, &tsig_rr.data.mac)
                    });
                if !valid {
                    reply.metadata.response_code = ResponseCode::NotAuth;
                    return reply.to_vec().ok();
                }
                Some((tsig_rr.name, tsig_rr.data.algorithm, tsig_rr.data.mac))
            }
        };

        {
            let mut st = state.lock().unwrap();
            for rr in &req.authorities {
                let mut vals = Vec::new();
                if let RData::TXT(txt) = &rr.data {
                    for chunk in &txt.txt_data {
                        vals.push(normalize_value(&String::from_utf8_lossy(chunk)));
                    }
                }
                st.journal(json!({
                    "api": "rfc2136",
                    "op": u16::from(rr.dns_class),
                    "name": rr.name.to_utf8(),
                    "ttl": rr.ttl,
                    "values": vals,
                }));
            }
        }

        if let Some((key_name, algorithm, req_mac)) = verified_tsig {
            let mut pre = TSIG::new(
                algorithm.clone(),
                now,
                300,
                Vec::new(),
                reply.metadata.id,
                None,
                Vec::new(),
            );
            let mut tbs = Vec::new();
            tbs.extend_from_slice(&(req_mac.len() as u16).to_be_bytes());
            tbs.extend_from_slice(&req_mac);
            tbs.extend_from_slice(&message_tbs(&reply, &pre, &key_name).ok()?);
            pre.mac = tsig_hmac(&algorithm, &secret, &tbs)?;
            reply.set_signature(Box::new(make_tsig_record(key_name, pre)));
        }
        return reply.to_vec().ok();
    }

    let zone = Name::from_ascii("example.test.").ok()?;
    let ns = Name::from_ascii("ns.example.test.").ok()?;
    let mbox = Name::from_ascii("hostmaster.example.test.").ok()?;
    for q in &req.queries {
        match q.query_type() {
            RecordType::SOA => {
                reply.add_answer(Record::from_rdata(
                    zone.clone(),
                    60,
                    RData::SOA(SOA::new(ns.clone(), mbox.clone(), 1, 60, 60, 3600, 60)),
                ));
            }
            RecordType::NS => {
                reply.add_answer(Record::from_rdata(
                    zone.clone(),
                    60,
                    RData::NS(NS(ns.clone())),
                ));
            }
            RecordType::A => {
                reply.add_answer(Record::from_rdata(
                    q.name().clone(),
                    60,
                    RData::A(A(Ipv4Addr::LOCALHOST)),
                ));
            }
            _ => {}
        }
    }
    reply.to_vec().ok()
}
