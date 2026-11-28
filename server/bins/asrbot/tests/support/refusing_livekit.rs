//! A LiveKit endpoint that refuses everything with a fixed status and records the raw
//! requests: the failed `/rtc` upgrade and the `/rtc/validate` GET the client makes after it.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Seen {
    pub method: String,
    pub target: String,
    pub header_names: Vec<String>,
    pub authorization: Vec<String>,
    pub user_agent: Vec<String>,
}

pub struct RefusingLiveKit {
    pub addr: SocketAddr,
    pub seen: Arc<Mutex<Vec<Seen>>>,
}

impl RefusingLiveKit {
    pub async fn start(status_line: &'static str, body: &'static str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = seen.clone();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let log = log.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 8192];
                    let mut filled = 0;
                    loop {
                        let Ok(n) = stream.read(&mut buf[filled..]).await else {
                            return;
                        };
                        if n == 0 {
                            return;
                        }
                        filled += n;
                        if buf[..filled].windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }
                    let text = String::from_utf8_lossy(&buf[..filled]).into_owned();
                    let mut lines = text.split("\r\n");
                    let mut first = lines.next().unwrap_or_default().split(' ');
                    let (method, target) = (
                        first.next().unwrap_or_default().to_owned(),
                        first.next().unwrap_or_default().to_owned(),
                    );
                    let headers: Vec<(String, String)> = lines
                        .filter_map(|l| l.split_once(':'))
                        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_owned()))
                        .collect();
                    let pick = |name: &str| {
                        headers
                            .iter()
                            .filter(|(k, _)| k == name)
                            .map(|(_, v)| v.clone())
                            .collect::<Vec<_>>()
                    };
                    let mut names: Vec<String> = headers.iter().map(|(k, _)| k.clone()).collect();
                    names.sort();
                    log.lock().unwrap().push(Seen {
                        method,
                        target,
                        header_names: names,
                        authorization: pick("authorization"),
                        user_agent: pick("user-agent"),
                    });
                    let reply = format!("HTTP/1.1 {status_line}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
                    let _ = stream.write_all(reply.as_bytes()).await;
                    let _ = stream.shutdown().await;
                });
            }
        });
        Self { addr, seen }
    }

    pub fn url(&self) -> String {
        format!("ws://{}", self.addr)
    }
}
