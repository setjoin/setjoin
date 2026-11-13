//! The front door preserves a committed upstream head on a failed byte stream.
use setjoin_gateway::{Config, Gateway, RouteTable, TrustedProxies};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
#[tokio::test]
async fn truncated_upstream_keeps_its_committed_status_and_length() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream = listener.local_addr().unwrap();
    let peer = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        let mut bytes = [0; 1024];
        while !request.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = socket.read(&mut bytes).await.unwrap();
            assert_ne!(n, 0);
            request.extend_from_slice(&bytes[..n]);
        }
        socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\n").await.unwrap();
        socket.shutdown().await.unwrap();
    });
    let gateway = Gateway::new(
        Config {
            upstream: Some(format!("http://{upstream}").parse().unwrap()),
            trusted_proxies: TrustedProxies::parse("").unwrap(),
            upstream_header_timeout: setjoin_gateway::proxy::DEFAULT_HEADER_TIMEOUT,
            edge_limit: None,
        },
        RouteTable::proxy_all(),
    )
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(gateway.serve(listener));
    let mut socket = tokio::net::TcpStream::connect(addr).await.unwrap();
    socket.write_all(b"GET /api/drive/versions/1/content HTTP/1.1\r\nHost: mail.test\r\nConnection: close\r\n\r\n").await.unwrap();
    let mut bytes = Vec::new();
    socket.read_to_end(&mut bytes).await.unwrap();
    peer.await.unwrap();
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
