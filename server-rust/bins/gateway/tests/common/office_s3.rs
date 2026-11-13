//! Independent SigV4 verifier at the fake storage HTTP boundary.
use hmac::{Hmac, Mac};
use hyper::Request;
use sha2::{Digest, Sha256};

pub fn observe<B>(request: &Request<B>, body: &[u8]) -> Result<serde_json::Value, String> {
    let header = |name: &str| {
        request
            .headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| format!("missing S3 {name}"))
    };
    let authorization = header("authorization")?
        .strip_prefix("AWS4-HMAC-SHA256 ")
        .ok_or("unexpected S3 signer")?;
    let fields: std::collections::HashMap<_, _> = authorization
        .split(',')
        .filter_map(|part| part.trim().split_once('='))
        .collect();
    let field = |name| {
        fields
            .get(name)
            .copied()
            .ok_or_else(|| format!("missing signing field {name}"))
    };
    let credential: Vec<_> = field("Credential")?.split('/').collect();
    let date = header("x-amz-date")?;
    chrono::NaiveDateTime::parse_from_str(date, "%Y%m%dT%H%M%SZ")
        .map_err(|_| "invalid signing date")?;
    if credential.len() != 5
        || credential[0] != "test-access"
        || credential[1] != &date[..8]
        || credential[3] != "s3"
        || credential[4] != "aws4_request"
    {
        return Err("invalid credential scope".into());
    }
    let signed = field("SignedHeaders")?;
    let mut canonical_headers = String::new();
    for name in signed.split(';') {
        let values: Result<Vec<_>, _> = request
            .headers()
            .get_all(name)
            .iter()
            .map(|value| value.to_str())
            .collect();
        let value = values.map_err(|_| "non-ASCII signing header")?.join(",");
        canonical_headers.push_str(&format!(
            "{name}:{}\n",
            value.split_whitespace().collect::<Vec<_>>().join(" ")
        ));
    }
    let payload = header("x-amz-content-sha256")?;
    if !(payload == "UNSIGNED-PAYLOAD"
        && (matches!(
            *request.method(),
            hyper::Method::GET | hyper::Method::HEAD | hyper::Method::DELETE
        ) || (request.method() == hyper::Method::PUT
            && request.headers().contains_key("x-amz-copy-source")))
        && body.is_empty())
        && payload != "STREAMING-AWS4-HMAC-SHA256-PAYLOAD"
        && payload != format!("{:x}", Sha256::digest(body))
    {
        return Err("incorrect S3 payload hash".into());
    }
    let query = request.uri().query().unwrap_or("");
    if !matches!(query, "" | "location=") {
        return Err("unexpected cleanup query".into());
    }
    let canonical = format!(
        "{}\n{}\n{query}\n{canonical_headers}\n{signed}\n{payload}",
        request.method(),
        request.uri().path()
    );
    let scope = credential[1..].join("/");
    let input = format!(
        "AWS4-HMAC-SHA256\n{date}\n{scope}\n{:x}",
        Sha256::digest(canonical.as_bytes())
    );
    let mac = |key: &[u8], text: &str| {
        let mut h = Hmac::<Sha256>::new_from_slice(key).unwrap();
        h.update(text.as_bytes());
        h.finalize().into_bytes().to_vec()
    };
    let mut key = mac(b"AWS4test-secret", credential[1]);
    for part in &credential[2..] {
        key = mac(&key, part);
    }
    let expected = mac(&key, &input)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    if expected != field("Signature")? {
        return Err("invalid S3 signature".into());
    }
    let decoded = if payload == "STREAMING-AWS4-HMAC-SHA256-PAYLOAD" {
        let decoded = streaming_body(body, &key, date, &scope, field("Signature")?)?;
        if header("x-amz-decoded-content-length")?
            .parse::<usize>()
            .map_err(|_| "invalid decoded size")?
            != decoded.len()
        {
            return Err("streamed S3 decoded size differs".into());
        }
        decoded
    } else {
        body.to_vec()
    };
    let observed_body = if request.method() == hyper::Method::PUT {
        serde_json::json!({"sha256":format!("{:x}",Sha256::digest(&decoded)),"length":decoded.len()})
    } else {
        serde_json::json!(
            std::str::from_utf8(&decoded).map_err(|_| "unexpected binary cleanup body")?
        )
    };
    Ok(serde_json::json!({
        "method":request.method().as_str(),"uri":request.uri().to_string(),"body":observed_body,
        "sha256":payload,"scope":format!("test-access/<date>/{}",credential[2..].join("/")),"signed_headers":signed,"signature_valid":true,
    }))
}

/// Verify every signed HTTP chunk, including the final empty chunk, before
/// observing the object bytes. This is independent of both production clients.
fn streaming_body(
    mut wire: &[u8],
    key: &[u8],
    date: &str,
    scope: &str,
    initial: &str,
) -> Result<Vec<u8>, String> {
    let mut decoded = Vec::new();
    let mut previous = initial.to_owned();
    loop {
        let end = wire
            .windows(2)
            .position(|value| value == b"\r\n")
            .ok_or("missing signed chunk line")?;
        let line = std::str::from_utf8(&wire[..end]).map_err(|_| "invalid signed chunk line")?;
        let (size, signature) = line
            .split_once(";chunk-signature=")
            .ok_or("missing chunk signature")?;
        let size = usize::from_str_radix(size, 16).map_err(|_| "invalid chunk size")?;
        wire = &wire[end + 2..];
        if wire.len() < size + 2 || &wire[size..size + 2] != b"\r\n" {
            return Err("incomplete signed chunk".into());
        }
        let chunk = &wire[..size];
        let input = format!(
            "AWS4-HMAC-SHA256-PAYLOAD\n{date}\n{scope}\n{previous}\n{:x}\n{:x}",
            Sha256::digest([]),
            Sha256::digest(chunk)
        );
        let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(|_| "invalid signing key")?;
        mac.update(input.as_bytes());
        let expected = mac
            .finalize()
            .into_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        if signature != expected {
            return Err("invalid S3 chunk signature".into());
        }
        previous = signature.to_owned();
        decoded.extend_from_slice(chunk);
        wire = &wire[size + 2..];
        if size == 0 {
            if !wire.is_empty() {
                return Err("unexpected signed upload trailer".into());
            }
            return Ok(decoded);
        }
    }
}
