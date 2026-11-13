//! A minimal keep-alive HTTP/1.1 client (std only): enough to POST the
//! webmail's mark-read body and read a `Content-Length` or chunked reply.
//! One connection per load worker, reopened after any transport error, so a
//! measured latency never includes a hidden retry.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

#[derive(Debug, PartialEq, Eq)]
pub enum Framing {
    Length(usize),
    Chunked,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Head {
    pub status: u16,
    /// Bytes up to and including the blank line.
    pub len: usize,
    pub framing: Framing,
    pub close: bool,
}

/// `Ok(None)` = need more bytes; `Err` = not a reply this client understands.
pub fn parse_head(buf: &[u8]) -> Result<Option<Head>, String> {
    let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") else {
        return Ok(None);
    };
    let text = std::str::from_utf8(&buf[..end]).map_err(|_| "non-UTF-8 head")?;
    let mut lines = text.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let status = status_line
        .split(' ')
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| format!("bad status line {status_line:?}"))?;
    let (mut length, mut chunked, mut close) = (None, false, false);
    for line in lines {
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        let (k, v) = (k.trim().to_ascii_lowercase(), v.trim().to_ascii_lowercase());
        match k.as_str() {
            "content-length" => length = Some(v.parse().map_err(|_| "bad content-length")?),
            "transfer-encoding" => chunked = v.contains("chunked"),
            "connection" => close = v == "close",
            _ => {}
        }
    }
    let framing = match (chunked, length) {
        (true, _) => Framing::Chunked,
        (false, Some(n)) => Framing::Length(n),
        (false, None) if status == 204 || status == 304 => Framing::Length(0),
        (false, None) => return Err("reply without length".into()),
    };
    Ok(Some(Head {
        status,
        len: end + 4,
        framing,
        close,
    }))
}

/// Decodes a complete chunked body: `Some((body, consumed))`, or `None` when
/// more bytes are needed. Trailers are skipped.
pub fn decode_chunked(buf: &[u8]) -> Result<Option<(Vec<u8>, usize)>, String> {
    let mut body = Vec::new();
    let mut i = 0;
    loop {
        let Some(nl) = buf[i..].windows(2).position(|w| w == b"\r\n") else {
            return Ok(None);
        };
        let size_txt = std::str::from_utf8(&buf[i..i + nl]).map_err(|_| "bad chunk size")?;
        let size = usize::from_str_radix(size_txt.split(';').next().unwrap_or("").trim(), 16)
            .map_err(|_| format!("bad chunk size {size_txt:?}"))?;
        i += nl + 2;
        if size == 0 {
            // Trailers end with an empty line.
            let Some(end) = buf[i..].windows(2).position(|w| w == b"\r\n") else {
                return Ok(None);
            };
            if end == 0 {
                return Ok(Some((body, i + 2)));
            }
            let Some(t) = buf[i..].windows(4).position(|w| w == b"\r\n\r\n") else {
                return Ok(None);
            };
            return Ok(Some((body, i + t + 4)));
        }
        if buf.len() < i + size + 2 {
            return Ok(None);
        }
        body.extend_from_slice(&buf[i..i + size]);
        i += size + 2;
    }
}

pub fn post_request(host: &str, path: &str, headers: &[(&str, &str)], body: &str) -> Vec<u8> {
    let mut r = format!("POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n", body.len());
    for (k, v) in headers {
        r.push_str(&format!("{k}: {v}\r\n"));
    }
    r.push_str("\r\n");
    r.push_str(body);
    r.into_bytes()
}

pub struct Reply {
    pub status: u16,
    pub body: String,
}

/// One keep-alive connection to `addr`.
pub struct Client {
    addr: String,
    conn: Option<TcpStream>,
    timeout: Duration,
}

impl Client {
    pub fn new(addr: &str, timeout: Duration) -> Client {
        Client {
            addr: addr.into(),
            conn: None,
            timeout,
        }
    }

    /// Sends `request` and reads one reply. Any error drops the connection
    /// (the next call reconnects) and is reported, never retried.
    pub fn send(&mut self, request: &[u8]) -> Result<Reply, String> {
        let r = self.try_send(request);
        if r.as_ref().map_or(true, |(_, close)| *close) {
            self.conn = None;
        }
        r.map(|(reply, _)| reply)
    }

    fn try_send(&mut self, request: &[u8]) -> Result<(Reply, bool), String> {
        if self.conn.is_none() {
            let s = TcpStream::connect(&self.addr).map_err(|e| format!("connect: {e}"))?;
            s.set_nodelay(true).ok();
            s.set_read_timeout(Some(self.timeout)).ok();
            s.set_write_timeout(Some(self.timeout)).ok();
            self.conn = Some(s);
        }
        let s = self.conn.as_mut().unwrap();
        s.write_all(request).map_err(|e| format!("write: {e}"))?;
        let mut buf = Vec::with_capacity(2048);
        let mut chunk = [0u8; 4096];
        let head = loop {
            if let Some(h) = parse_head(&buf)? {
                break h;
            }
            let n = s.read(&mut chunk).map_err(|e| format!("read: {e}"))?;
            if n == 0 {
                return Err("connection closed before reply".into());
            }
            buf.extend_from_slice(&chunk[..n]);
        };
        let body = loop {
            let rest = &buf[head.len..];
            match head.framing {
                Framing::Length(n) if rest.len() >= n => break rest[..n].to_vec(),
                Framing::Chunked => {
                    if let Some((b, _)) = decode_chunked(rest)? {
                        break b;
                    }
                }
                _ => {}
            }
            let n = s.read(&mut chunk).map_err(|e| format!("read: {e}"))?;
            if n == 0 {
                return Err("connection closed mid-body".into());
            }
            buf.extend_from_slice(&chunk[..n]);
        };
        Ok((
            Reply {
                status: head.status,
                body: String::from_utf8_lossy(&body).into_owned(),
            },
            head.close,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn head_needs_the_blank_line() {
        assert_eq!(
            parse_head(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n"),
            Ok(None)
        );
        let h = parse_head(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc")
            .unwrap()
            .unwrap();
        assert_eq!(
            h,
            Head {
                status: 200,
                len: 38,
                framing: Framing::Length(3),
                close: false
            }
        );
    }

    #[test]
    fn head_reads_chunked_and_close() {
        let h = parse_head(
            b"HTTP/1.1 502 Bad Gateway\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            (h.status, h.framing, h.close),
            (502, Framing::Chunked, true)
        );
        assert!(parse_head(b"HTTP/1.1 200 OK\r\n\r\n").is_err());
    }

    #[test]
    fn chunked_body_decodes_only_when_complete() {
        let full = b"4\r\nWiki\r\n5;x=1\r\npedia\r\n0\r\n\r\n";
        assert_eq!(
            decode_chunked(full),
            Ok(Some((b"Wikipedia".to_vec(), full.len())))
        );
        assert_eq!(decode_chunked(&full[..10]), Ok(None));
        assert_eq!(decode_chunked(&full[..full.len() - 1]), Ok(None));
    }

    #[test]
    fn client_keeps_the_connection_and_reconnects_after_close() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap().to_string();
        let server = std::thread::spawn(move || {
            let mut accepted = 0;
            for conn in l.incoming().take(2) {
                accepted += 1;
                let mut c = conn.unwrap();
                let mut buf = [0u8; 4096];
                // First connection serves two requests; the second one replies then closes.
                let replies = if accepted == 1 { 2 } else { 1 };
                for _ in 0..replies {
                    let n = c.read(&mut buf).unwrap();
                    assert!(std::str::from_utf8(&buf[..n]).unwrap().ends_with("{}"));
                    c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                        .unwrap();
                }
                drop(c);
            }
            accepted
        });
        let mut cl = Client::new(&addr, Duration::from_secs(5));
        let req = post_request("x", "/jmap", &[], "{}");
        assert_eq!(cl.send(&req).unwrap().body, "ok");
        assert_eq!(cl.send(&req).unwrap().status, 200);
        // The server closed: the next send fails once, then reconnects.
        assert!(cl.send(&req).is_err());
        assert_eq!(cl.send(&req).unwrap().body, "ok");
        assert_eq!(server.join().unwrap(), 2);
    }
}
