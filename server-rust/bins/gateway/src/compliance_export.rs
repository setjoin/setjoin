//! Go's 2 KiB response buffer with bounded, cancellation-aware MBOX streaming.
use crate::{recovery_worker::S3Store, Body, RequestContext};
use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::Response;
use setjoin_pg::ScopedExecutor;
use sha2::{Digest, Sha256};
use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::sync::{mpsc, oneshot};
enum Ready {
    Full(Vec<u8>),
    Stream,
}
pub(crate) struct Writer {
    prefix: Vec<u8>,
    head: bool,
    overflow: bool,
    ready: Option<oneshot::Sender<Ready>>,
    tx: mpsc::Sender<Bytes>,
}
impl Writer {
    pub(crate) async fn write(&mut self, bytes: Bytes) -> Result<(), String> {
        if self.head && self.overflow {
            return Ok(());
        }
        if self.ready.is_some() && self.prefix.len() + bytes.len() <= 2048 {
            self.prefix.extend_from_slice(&bytes);
            return Ok(());
        }
        if self.head {
            self.overflow = true;
            self.prefix.clear();
            return Ok(());
        }
        if let Some(ready) = self.ready.take() {
            ready.send(Ready::Stream).map_err(|_| "client closed")?;
            self.tx
                .send(Bytes::from(std::mem::take(&mut self.prefix)))
                .await
                .map_err(|_| "client closed")?;
        }
        self.tx
            .send(bytes)
            .await
            .map_err(|_| "client closed".into())
    }
    pub(crate) fn finish(mut self) {
        if let Some(ready) = self.ready.take() {
            let _ = ready.send(if self.head && self.overflow {
                Ready::Stream
            } else {
                Ready::Full(self.prefix)
            });
        }
    }
}
struct Stream(mpsc::Receiver<Bytes>);
impl hyper::body::Body for Stream {
    type Data = Bytes;
    type Error = crate::BoxError;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<hyper::body::Frame<Bytes>, Self::Error>>> {
        self.0
            .poll_recv(cx)
            .map(|item| item.map(|bytes| Ok(hyper::body::Frame::data(bytes))))
    }
}
pub(crate) struct Selection {
    pub head: bool,
    pub actor: i64,
    pub case: i64,
    pub ids: Vec<i64>,
    pub original: Vec<String>,
    pub raw: Vec<u8>,
}
pub(crate) async fn response(
    exec: ScopedExecutor,
    store: Option<Arc<S3Store>>,
    selection: Selection,
    c: &RequestContext,
    request_id: String,
) -> Response<Body> {
    let Selection {
        head,
        actor,
        case,
        ids,
        original,
        raw,
    } = selection;
    let now = chrono::Utc::now();
    let disposition = format!(
        "attachment; filename=ediscovery-{}.mbox",
        now.format("%Y%m%d-%H%M%S")
    );
    let (ready, rx) = oneshot::channel();
    let (tx, chunks) = mpsc::channel(2);
    let closed = tx.clone();
    tokio::spawn(async move {
        let work = async move {
            let mut w = Writer {
                prefix: Vec::new(),
                head,
                overflow: false,
                ready: Some(ready),
                tx,
            };
            let digest = Sha256::digest(&raw);
            let mut header=format!("From custody-chain@mailserver {}\r\nX-Custody-Case-ID: {case}\r\nX-Custody-Message-Count: {}\r\nX-Custody-Checksum: sha256:{digest:x}\r\nX-Custody-Requested-At: {}\r\nX-Custody-Message-IDs: ",now.format("%a %b %d %H:%M:%S %Y"),original.len(),now.to_rfc3339_opts(chrono::SecondsFormat::Secs,true)).into_bytes();
            header.extend_from_slice(&raw);
            header.extend_from_slice(b"\r\n\r\n");
            if w.write(Bytes::from(header)).await.is_err() {
                return;
            }
            for (id, key, from, subject, date) in
                setjoin_compliance::export::messages(&exec, &ids, actor).await
            {
                if w.write(Bytes::from(format!(
                    "From {from} {date}\r\nSubject: {subject}\r\nX-Custody-Message-ID: {id}\r\n"
                )))
                .await
                .is_err()
                {
                    return;
                }
                if !key.is_empty() {
                    if let Some(store) = &store {
                        let _ = store.compliance_copy(&key, &mut w).await;
                    }
                }
                if w.write(Bytes::from_static(b"\r\n")).await.is_err() {
                    return;
                }
            }
            w.finish();
        };
        tokio::select! {_=closed.closed()=>{},_=work=>{}}
    });
    let mut r = crate::jmap::reply::response(String::new(), c.identity.proto, request_id);
    match rx.await {
        Ok(Ready::Full(bytes)) => {
            *r.body_mut() = http_body_util::Full::new(Bytes::from(bytes))
                .map_err(|never| match never {})
                .boxed();
        }
        Ok(Ready::Stream) => {
            *r.body_mut() = Stream(chunks).boxed();
            r.headers_mut()
                .insert("transfer-encoding", "chunked".parse().unwrap());
        }
        Err(_) => {}
    }
    r.headers_mut()
        .insert("content-type", "application/mbox".parse().unwrap());
    r.headers_mut()
        .insert("content-disposition", disposition.parse().unwrap());
    r
}

/// Go Query().Get semantics, retaining invalid UTF-8 for the custody digest.
/// Audit JSON separately uses Go's per-byte replacement through go_utf8.
pub(crate) fn query_bytes(uri: &hyper::Uri, name: &str) -> Option<Vec<u8>> {
    fn decode(value: &str) -> Option<Vec<u8>> {
        let bytes = value.as_bytes();
        let mut out = Vec::new();
        let mut i = 0;
        while i < bytes.len() {
            match bytes[i] {
                b'+' => out.push(b' '),
                b'%' => {
                    let hi = (*bytes.get(i + 1)? as char).to_digit(16)?;
                    let lo = (*bytes.get(i + 2)? as char).to_digit(16)?;
                    out.push((hi * 16 + lo) as u8);
                    i += 2;
                }
                b => out.push(b),
            }
            i += 1;
        }
        Some(out)
    }
    for pair in uri.query()?.split('&') {
        if pair.is_empty() || pair.contains(';') {
            continue;
        }
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let (Some(key), Some(value)) = (decode(key), decode(value)) else {
            continue;
        };
        if key == name.as_bytes() {
            return Some(value);
        }
    }
    None
}

/// Shared Go 2 KiB framing for bounded artifact producers. Cancellation drops
/// the producer future (and its snapshot/socket); HEAD still drains the work.
pub(crate) async fn stream<F, Fut>(
    head: bool,
    kind: &'static str,
    disposition: String,
    c: &RequestContext,
    id: String,
    produce: F,
) -> Response<Body>
where
    F: FnOnce(Writer) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let (ready, rx) = oneshot::channel();
    let (tx, chunks) = mpsc::channel(2);
    let closed = tx.clone();
    let writer = Writer {
        prefix: Vec::new(),
        head,
        overflow: false,
        ready: Some(ready),
        tx,
    };
    tokio::spawn(async move {
        tokio::select! {_=closed.closed()=>{},_=produce(writer)=>{}}
    });
    let mut r = crate::jmap::reply::response(String::new(), c.identity.proto, id);
    match rx.await {
        Ok(Ready::Full(bytes)) => {
            *r.body_mut() = http_body_util::Full::new(Bytes::from(bytes))
                .map_err(|never| match never {})
                .boxed()
        }
        Ok(Ready::Stream) => {
            *r.body_mut() = Stream(chunks).boxed();
            r.headers_mut()
                .insert("transfer-encoding", "chunked".parse().unwrap());
        }
        Err(_) => {}
    }
    r.headers_mut()
        .insert("content-type", kind.parse().unwrap());
    r.headers_mut()
        .insert("content-disposition", disposition.parse().unwrap());
    r
}
