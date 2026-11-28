//! S3 system-boundary fixture and declared MBOX volatile fields.
use crate::common::{self, BoxError};
use hyper::Response;
use serde_json::{json, Value};
use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
};
pub type Calls = Arc<Mutex<Vec<Value>>>;

pub async fn s3(label: &str) -> (SocketAddr, Calls) {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let seen = calls.clone();
    let label = label.to_owned();
    let address=common::fake_upstream(move |r|{let seen=seen.clone();let label=label.clone();async move {
        let path=r.uri().path().to_owned();
        if path.starts_with("/mailblobs/compl1/export-") {
            let checked=common::s3::observe(&r,&[]);
            let name=path.strip_prefix("/mailblobs/compl1/export-").unwrap().to_owned();
            seen.lock().unwrap().push(match checked {Ok(_)=>json!({"method":r.method().as_str(),"key":name,"signature_valid":true}),Err(e)=>json!({"signature_error":e})});
            let mut body=format!("From: sender@example.test\r\nSubject: Raw {name}\r\n\r\nEvidence {name}\r\n").into_bytes();
            if matches!(label.as_str(),"large"|"huge-head") {body.extend(std::iter::repeat_n(b'x',5000));}
            if label=="binary" {body.extend_from_slice(&[0,255,128,13,10]);}
            if label=="missing-blob" && name=="a" {return Response::builder().status(404).body(common::full("<Error><Code>NoSuchKey</Code></Error>")).unwrap();}
            let mut response=Response::builder().header("content-type","message/rfc822").header("etag","\"compl1-test\"");
            if label!="success" {response=response.header("last-modified","Mon, 02 Nov 2026 01:00:00 GMT");}
            return response.body(common::full(body)).unwrap();
        }
        if r.uri().query().unwrap_or("").starts_with("location") {
            return Response::builder().header("content-type","application/xml").body(common::full("<LocationConstraint xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">us-east-1</LocationConstraint>")).unwrap();
        }
        Response::builder().header("x-amz-bucket-region","us-east-1").header("content-type","application/xml").body(common::full("<ListBucketResult><Name>mailblobs</Name><IsTruncated>false</IsTruncated></ListBucketResult>")).unwrap()
    }}).await;
    (address, calls)
}

pub fn normalize(raw: &[u8], ids: &str, a: i64, b: i64) -> Result<Value, BoxError> {
    let mut out = Vec::new();
    for line in raw.split_inclusive(|c| *c == b'\n') {
        let mut replaced = false;
        for prefix in [
            b"From custody-chain@mailserver ".as_slice(),
            b"From sender@example.test ".as_slice(),
        ] {
            if let Some(date) = line
                .strip_prefix(prefix)
                .and_then(|s| s.strip_suffix(b"\r\n"))
            {
                chrono::NaiveDateTime::parse_from_str(
                    std::str::from_utf8(date)?,
                    "%a %b %d %H:%M:%S %Y",
                )?;
                out.extend_from_slice(prefix);
                out.extend_from_slice(b"<timestamp>\r\n");
                replaced = true;
                break;
            }
        }
        if replaced {
            continue;
        }
        if let Some(date) = line
            .strip_prefix(b"X-Custody-Requested-At: ")
            .and_then(|s| s.strip_suffix(b"\r\n"))
        {
            chrono::DateTime::parse_from_rfc3339(std::str::from_utf8(date)?)?;
            out.extend_from_slice(b"X-Custody-Requested-At: <timestamp>\r\n");
            continue;
        }
        if let Some(hash) = line
            .strip_prefix(b"X-Custody-Checksum: sha256:")
            .and_then(|s| s.strip_suffix(b"\r\n"))
        {
            if hash.len() != 64
                || !hash
                    .iter()
                    .all(|c| c.is_ascii_digit() || matches!(c, b'a'..=b'f'))
            {
                return Err("invalid custody checksum".into());
            }
            // Only digests of fixture-generated IDs are volatile. Constant-ID
            // cases retain Go's literal digest as the independent SHA oracle.
            if ids
                .split(',')
                .any(|id| id == a.to_string() || id == b.to_string())
            {
                out.extend_from_slice(b"X-Custody-Checksum: sha256:<fixture-id-digest>\r\n");
                continue;
            }
        }
        if let Some(value) = line
            .strip_prefix(b"X-Custody-Message-ID: ")
            .and_then(|s| s.strip_suffix(b"\r\n"))
        {
            if value == a.to_string().as_bytes() {
                out.extend_from_slice(b"X-Custody-Message-ID: <message-a>\r\n");
                continue;
            }
            if value == b.to_string().as_bytes() {
                out.extend_from_slice(b"X-Custody-Message-ID: <message-b>\r\n");
                continue;
            }
        }
        if let Some(value) = line
            .strip_prefix(b"X-Custody-Message-IDs: ")
            .and_then(|s| s.strip_suffix(b"\r\n"))
        {
            if let Ok(value) = std::str::from_utf8(value) {
                let fixed = value
                    .split(',')
                    .map(|id| {
                        if id == a.to_string() {
                            "<message-a>".to_owned()
                        } else if id == b.to_string() {
                            "<message-b>".to_owned()
                        } else {
                            id.to_owned()
                        }
                    })
                    .collect::<Vec<_>>()
                    .join(",");
                out.extend_from_slice(format!("X-Custody-Message-IDs: {fixed}\r\n").as_bytes());
                continue;
            }
        }
        out.extend_from_slice(line);
    }
    Ok(match String::from_utf8(out.clone()) {
        Ok(text) => json!(text),
        Err(_) => {
            use base64::{engine::general_purpose::STANDARD, Engine};
            json!({"base64":STANDARD.encode(out)})
        }
    })
}
