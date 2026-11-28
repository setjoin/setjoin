//! A byte-exact HTTP/1.1 client for the control API: no URL normalisation, no
//! header insertion beyond what a case names (so `//start` and `%zz` reach the server as written).

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    /// Lower-cased names, sorted, `date` removed.
    pub headers: Vec<(String, String)>,
    pub body: String,
}

pub struct Request<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub headers: &'a [(&'a str, &'a str)],
    pub body: &'a [u8],
}

pub async fn send(port: u16, request: &Request<'_>) -> Result<Response, String> {
    let mut stream = TcpStream::connect(("127.0.0.1", port))
        .await
        .map_err(|e| e.to_string())?;
    let mut raw = format!(
        "{} {} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n",
        request.method, request.path, port
    )
    .into_bytes();
    for (name, value) in request.headers {
        raw.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
    }
    if !request.body.is_empty() || request.method == "POST" {
        raw.extend_from_slice(format!("Content-Length: {}\r\n", request.body.len()).as_bytes());
    }
    raw.extend_from_slice(b"\r\n");
    raw.extend_from_slice(request.body);
    // A server may answer and close before a large body is consumed: ignore a late write error.
    let _ = stream.write_all(&raw).await;
    let mut out = Vec::new();
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(15),
        stream.read_to_end(&mut out),
    )
    .await;
    parse(&out, request.method == "HEAD")
}

fn parse(raw: &[u8], head: bool) -> Result<Response, String> {
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| format!("no response head in {} bytes", raw.len()))?;
    let head_text = String::from_utf8_lossy(&raw[..split]).into_owned();
    let mut lines = head_text.split("\r\n");
    let status_line = lines.next().unwrap_or_default();
    let status: u16 = status_line
        .split(' ')
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| format!("bad status line {status_line:?}"))?;
    let mut headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_owned()))
        .filter(|(k, _)| k != "date")
        .collect();
    headers.sort();
    let chunked = headers
        .iter()
        .any(|(k, v)| k == "transfer-encoding" && v.eq_ignore_ascii_case("chunked"));
    let body_bytes = &raw[split + 4..];
    let body = if head {
        String::new()
    } else if chunked {
        String::from_utf8_lossy(&dechunk(body_bytes)).into_owned()
    } else {
        String::from_utf8_lossy(body_bytes).into_owned()
    };
    if chunked {
        headers.retain(|(k, _)| k != "transfer-encoding");
    }
    Ok(Response {
        status,
        headers,
        body,
    })
}

/// Decode a chunked body (the client side of the framing difference documented in the DOX).
fn dechunk(mut rest: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    while let Some(eol) = rest.windows(2).position(|w| w == b"\r\n") {
        let size =
            usize::from_str_radix(String::from_utf8_lossy(&rest[..eol]).trim(), 16).unwrap_or(0);
        rest = &rest[eol + 2..];
        if size == 0 || rest.len() < size {
            break;
        }
        out.extend_from_slice(&rest[..size]);
        rest = rest.get(size + 2..).unwrap_or_default();
    }
    out
}
