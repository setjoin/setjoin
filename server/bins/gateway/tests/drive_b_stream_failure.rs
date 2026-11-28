//! The front door preserves a committed streaming head on a failed byte stream.
use http_body_util::BodyExt;
use hyper::{
    body::{Bytes, Frame},
    Request, Response,
};
use setjoin_gateway::{
    BoxFuture, Config, Gateway, Intercept, RequestContext, RouteTable, TrustedProxies,
};
use std::{
    pin::Pin,
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

struct TruncatedBody {
    flushed: bool,
}
impl hyper::body::Body for TruncatedBody {
    type Data = Bytes;
    type Error = Box<dyn std::error::Error + Send + Sync + 'static>;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if !self.flushed {
            self.flushed = true;
            let waker = cx.waker().clone();
            tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                waker.wake();
            });
            return Poll::Pending;
        }
        Poll::Ready(Some(Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "truncated stream",
        )))))
    }
    fn size_hint(&self) -> hyper::body::SizeHint {
        hyper::body::SizeHint::with_exact(10)
    }
}

struct TruncatedStreamRoute;
impl Intercept for TruncatedStreamRoute {
    fn matches(&self, req: &Request<setjoin_gateway::Body>) -> bool {
        req.uri().path() == "/api/drive/versions/1/content"
    }
    fn handle(
        &self,
        _req: Request<setjoin_gateway::Body>,
        _ctx: RequestContext,
    ) -> BoxFuture<Response<setjoin_gateway::Body>> {
        Box::pin(async {
            Response::builder()
                .status(200)
                .header("content-length", "10")
                .header("content-type", "application/octet-stream")
                .body(TruncatedBody { flushed: false }.boxed())
                .unwrap()
        })
    }
}

#[tokio::test]
async fn truncated_upstream_keeps_its_committed_status_and_length() {
    let gateway = Gateway::new(
        Config {
            upstream: None,
            trusted_proxies: TrustedProxies::parse("").unwrap(),
            upstream_header_timeout: setjoin_gateway::proxy::DEFAULT_HEADER_TIMEOUT,
            edge_limit: None,
        },
        RouteTable::proxy_all().with(TruncatedStreamRoute),
    )
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(gateway.serve(listener));
    let mut socket = tokio::net::TcpStream::connect(addr).await.unwrap();
    socket.write_all(b"GET /api/drive/versions/1/content HTTP/1.1\r\nHost: mail.test\r\nConnection: close\r\n\r\n").await.unwrap();
    let mut bytes = Vec::new();
    socket.read_to_end(&mut bytes).await.unwrap();
    task.abort();
    let _ = task.await;
    let response = String::from_utf8(bytes).unwrap();
    assert!(
        response.starts_with("HTTP/1.1 200 OK\r\n"),
        "committed upstream head lost: {response:?}"
    );
    assert!(response
        .to_ascii_lowercase()
        .contains("content-length: 10\r\n"));
    assert!(
        response.ends_with("\r\n\r\n"),
        "truncated upstream invented content"
    );
}
