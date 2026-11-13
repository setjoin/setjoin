//! Resource bounds for the public and loopback HTTP listeners.
use std::time::Duration;

#[derive(Clone, Copy, Debug)]
pub struct HttpLimits {
    /// Total header/body read budget, without extending it for trickled bytes.
    pub read: Duration,
    /// Handler and complete response-write budget.
    pub write: Duration,
    /// Keep-alive time between requests; h2 control frames do not refresh it.
    pub idle: Duration,
    /// Shared capacity across HTTP, HTTPS, handshakes and upgraded transports.
    pub max_connections: usize,
}

impl Default for HttpLimits {
    fn default() -> Self {
        Self {
            read: Duration::from_secs(30),
            write: Duration::from_secs(120),
            idle: Duration::from_secs(120),
            max_connections: 1024,
        }
    }
}

impl HttpLimits {
    pub(crate) fn validate(self) -> Result<(), String> {
        if self.read.is_zero()
            || self.write.is_zero()
            || self.idle.is_zero()
            || self.max_connections == 0
            || self.max_connections > tokio::sync::Semaphore::MAX_PERMITS
        {
            return Err(
                "HTTP deadlines and connection capacity must be positive and supported".into(),
            );
        }
        Ok(())
    }
}

use crate::{Body, BoxError};
use hyper::body::{Body as HttpBody, Frame, SizeHint};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::sync::watch;
use tokio::time::Instant;

#[derive(Clone, Copy)]
struct Deadlines {
    read: Option<Instant>,
    write: Instant,
}

#[derive(Clone)]
struct State {
    next_id: u64,
    requests: std::collections::BTreeMap<u64, Deadlines>,
    idle_since: Instant,
    header: Option<Instant>,
    pending_write: Option<Instant>,
    last_write: Option<Instant>,
    response_unflushed: bool,
}

pub(crate) struct Activity {
    state: watch::Sender<State>,
    limits: HttpLimits,
}

impl Activity {
    pub(crate) fn new(limits: HttpLimits) -> Arc<Self> {
        Arc::new(Self {
            limits,
            state: watch::channel(State {
                next_id: 0,
                requests: Default::default(),
                idle_since: Instant::now(),
                header: Some(Instant::now() + limits.read),
                pending_write: None,
                last_write: None,
                response_unflushed: false,
            })
            .0,
        })
    }

    pub(crate) fn start(self: &Arc<Self>, empty: bool) -> (ActiveRequest, Option<Reading>) {
        let mut id = 0;
        self.state.send_modify(|state| {
            id = state.next_id;
            state.next_id += 1;
            state.last_write = Some(Instant::now() + self.limits.write);
            let deadline = state
                .header
                .take()
                .unwrap_or_else(|| Instant::now() + self.limits.read);
            state.requests.insert(
                id,
                Deadlines {
                    read: (!empty).then_some(deadline),
                    write: Instant::now() + self.limits.write,
                },
            );
        });
        (
            ActiveRequest {
                activity: self.clone(),
                id,
            },
            (!empty).then(|| Reading {
                activity: self.clone(),
                id,
            }),
        )
    }

    fn input(&self, http2: bool) {
        self.state.send_if_modified(|state| {
            if http2 {
                if state.header.take().is_some() {
                    state.idle_since = Instant::now();
                    true
                } else {
                    false
                }
            } else if state.header.is_none()
                && state
                    .requests
                    .values()
                    .all(|request| request.read.is_none())
            {
                state.header = Some(Instant::now() + self.limits.read);
                true
            } else {
                false
            }
        });
    }

    fn write_started(&self) {
        self.state.send_if_modified(|state| {
            if state.pending_write.is_some() {
                return false;
            }
            state.pending_write = Some(
                state
                    .requests
                    .values()
                    .map(|request| request.write)
                    .min()
                    .or(state.last_write)
                    .unwrap_or_else(|| Instant::now() + self.limits.write),
            );
            true
        });
    }

    fn write_flushed(&self) {
        self.state.send_if_modified(|state| {
            let pending = state.pending_write.take().is_some();
            // Control frames (including PING ACKs) must never refresh idle.
            if state.response_unflushed && state.requests.is_empty() {
                state.idle_since = Instant::now();
                state.response_unflushed = false;
                return true;
            }
            pending
        });
    }

    pub(crate) async fn expired(&self) {
        let mut receiver = self.state.subscribe();
        loop {
            let deadline =
                {
                    let state = receiver.borrow_and_update();
                    state
                        .header
                        .into_iter()
                        .chain(state.pending_write)
                        .chain(state.requests.values().flat_map(|request| {
                            request.read.into_iter().chain(Some(request.write))
                        }))
                        .chain(
                            (state.requests.is_empty()
                                && state.pending_write.is_none()
                                && state.header.is_none())
                            .then_some(state.idle_since + self.limits.idle),
                        )
                        .min()
                };
            match deadline {
                Some(deadline) if deadline <= Instant::now() => return,
                Some(deadline) => tokio::select! {
                    _ = tokio::time::sleep_until(deadline) => {},
                    _ = receiver.changed() => {},
                },
                None => {
                    let _ = receiver.changed().await;
                }
            }
        }
    }
}

pub(crate) struct ActiveRequest {
    activity: Arc<Activity>,
    id: u64,
}
impl Drop for ActiveRequest {
    fn drop(&mut self) {
        self.activity.state.send_modify(|state| {
            state.requests.remove(&self.id);
            state.idle_since = Instant::now();
            state.response_unflushed = true;
        });
    }
}

pub(crate) struct Reading {
    activity: Arc<Activity>,
    id: u64,
}
impl Drop for Reading {
    fn drop(&mut self) {
        self.activity.state.send_modify(|state| {
            if let Some(request) = state.requests.get_mut(&self.id) {
                request.read = None;
            }
        });
    }
}

pub(crate) struct RequestBody {
    inner: Body,
    reading: Option<Reading>,
}
impl RequestBody {
    pub(crate) fn new(inner: Body, reading: Option<Reading>) -> Self {
        Self { inner, reading }
    }
}
impl HttpBody for RequestBody {
    type Data = bytes::Bytes;
    type Error = BoxError;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let result = Pin::new(&mut self.inner).poll_frame(cx);
        if matches!(result, Poll::Ready(None) | Poll::Ready(Some(Err(_))))
            || self.inner.is_end_stream()
        {
            self.reading.take();
        }
        result
    }
    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }
    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

/// Observe the first HTTP/1 byte separately from keep-alive idle waiting.
/// Hyper's header timer includes that idle wait; Go starts ReadTimeout on input.
/// Detection also covers h2c before hyper's auto engine has selected HTTP/2.
pub(crate) struct HttpIo<S> {
    inner: S,
    activity: Arc<Activity>,
    http2: Option<bool>,
    prefix: Vec<u8>,
    // The upgraded transport retains capacity until its socket is dropped.
    _permit: tokio::sync::OwnedSemaphorePermit,
}
impl<S> HttpIo<S> {
    pub(crate) fn new(
        inner: S,
        activity: Arc<Activity>,
        http2: Option<bool>,
        permit: tokio::sync::OwnedSemaphorePermit,
    ) -> Self {
        Self {
            inner,
            activity,
            http2,
            prefix: Vec::new(),
            _permit: permit,
        }
    }
}
impl<S: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for HttpIo<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &result {
            let input = &buf.filled()[before..];
            if !input.is_empty() {
                const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
                if self.http2 != Some(false) && self.prefix.len() < PREFACE.len() {
                    let remaining = PREFACE.len() - self.prefix.len();
                    self.prefix
                        .extend_from_slice(&input[..input.len().min(remaining)]);
                    if !PREFACE.starts_with(&self.prefix) {
                        self.http2 = Some(false);
                    } else if self.prefix.len() == PREFACE.len() {
                        self.http2 = Some(true);
                    }
                }
                self.activity
                    .input(self.http2 == Some(true) && self.prefix.len() == PREFACE.len());
            }
        }
        result
    }
}
impl<S: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for HttpIo<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.activity.write_started();
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let result = Pin::new(&mut self.inner).poll_flush(cx);
        if result.is_ready() {
            self.activity.write_flushed();
        }
        result
    }
    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        self.activity.write_started();
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

pub(crate) struct ResponseBody {
    inner: Body,
    active: Option<Arc<ActiveRequest>>,
}

// Hyper may retain a final DATA frame in its HTTP/2 flow-control queue after
// dropping the Body. Keep the request alive until every queued byte is consumed.
// Bytes::from_owner preserves zero-copy payloads, including slices and clones.
struct OutputChunk {
    data: bytes::Bytes,
    _active: Arc<ActiveRequest>,
}
impl AsRef<[u8]> for OutputChunk {
    fn as_ref(&self) -> &[u8] {
        self.data.as_ref()
    }
}
impl ResponseBody {
    pub(crate) fn new(inner: Body, active: ActiveRequest) -> Self {
        let active = if inner.is_end_stream() {
            None
        } else {
            Some(Arc::new(active))
        };
        Self { inner, active }
    }
}
impl HttpBody for ResponseBody {
    type Data = bytes::Bytes;
    type Error = BoxError;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let result = Pin::new(&mut self.inner).poll_frame(cx);
        let result = match result {
            Poll::Ready(Some(Ok(frame))) => {
                Poll::Ready(Some(Ok(frame.map_data(|data| match &self.active {
                    Some(active) => bytes::Bytes::from_owner(OutputChunk {
                        data,
                        _active: active.clone(),
                    }),
                    None => data,
                }))))
            }
            result => result,
        };
        if matches!(result, Poll::Ready(None) | Poll::Ready(Some(Err(_))))
            || self.inner.is_end_stream()
        {
            self.active.take();
        }
        result
    }
    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }
    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}
