//! Frozen clamd framing, serialized connection reuse and fail-closed scan errors.
use crate::BoxStream;
use std::{sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UnixStream},
    sync::Mutex,
    time::Instant,
};
const TIMEOUT: Duration = Duration::from_secs(30);
struct Cached {
    stream: BoxStream,
    at: Instant,
}
pub(crate) struct ClamAv {
    addr: String,
    cached: Mutex<Option<Cached>>,
}
impl ClamAv {
    pub fn new(addr: String) -> Arc<Self> {
        Arc::new(Self {
            addr,
            cached: Mutex::new(None),
        })
    }
    async fn exchange(&self, data: Option<&[u8]>) -> Result<Vec<u8>, ()> {
        let mut cache = self.cached.lock().await;
        let cached = cache.take().filter(|c| c.at.elapsed() < TIMEOUT);
        let mut cached = if let Some(c) = cached {
            c
        } else {
            let stream: BoxStream = tokio::time::timeout(TIMEOUT, async {
                if self.addr.starts_with(['/', '.']) {
                    Ok::<BoxStream, std::io::Error>(Box::new(
                        UnixStream::connect(&self.addr).await?,
                    ))
                } else {
                    Ok::<BoxStream, std::io::Error>(Box::new(TcpStream::connect(&self.addr).await?))
                }
            })
            .await
            .map_err(|_| ())?
            .map_err(|_| ())?;
            Cached {
                stream,
                at: Instant::now(),
            }
        };
        let reply = tokio::time::timeout(TIMEOUT, async {
            let stream = &mut cached.stream;
            if let Some(data) = data {
                stream.write_all(b"nINSTREAM\n").await?;
                for chunk in data.chunks(4096) {
                    stream.write_u32(chunk.len() as u32).await?;
                    stream.write_all(chunk).await?;
                }
                stream.write_u32(0).await?;
            } else {
                stream.write_all(b"nPING\n").await?;
            }
            stream.flush().await?;
            let mut reply = Vec::new();
            loop {
                let byte = stream.read_u8().await?;
                reply.push(byte);
                if byte == b'\n' {
                    break;
                }
            }
            Ok::<_, std::io::Error>(reply)
        })
        .await
        .map_err(|_| ())?
        .map_err(|_| ())?;
        // A cancellation/error drops the taken connection; only an entire valid
        // exchange can put it back. Go invalidates after protocol errors too.
        let valid = if data.is_none() {
            reply.windows(4).any(|w| w == b"PONG")
        } else {
            scan_reply(&reply).is_ok()
        };
        if valid {
            *cache = Some(cached);
            Ok(reply)
        } else {
            Err(())
        }
    }
    pub async fn ping(&self) {
        let _ = self.exchange(None).await;
    }
    pub async fn scan(&self, data: &[u8]) -> Result<Vec<u8>, ()> {
        scan_reply(&self.exchange(Some(data)).await?)
    }
}
fn scan_reply(reply: &[u8]) -> Result<Vec<u8>, ()> {
    let reply = setjoin_mime::trim_space(reply);
    if reply.ends_with(b"OK") {
        return Ok(Vec::new());
    }
    if reply.windows(5).any(|w| w == b"FOUND") {
        let words: Vec<&[u8]> = reply.split(|b| *b == b' ').collect();
        if words.len() >= 3 {
            return Ok(words[words.len() - 2].to_vec());
        }
    }
    Err(())
}
