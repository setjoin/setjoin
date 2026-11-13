//! A LiveKit-shaped endpoint that accepts the signalling upgrade, says nothing,
//! and closes the connection after `hold`: keeps a room "started" for a while
//! without a real join, for control-API scenarios.

use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpListener;

pub struct HoldWs {
    pub addr: SocketAddr,
}

impl HoldWs {
    pub async fn start(hold: Duration) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind hold");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    if let Ok(ws) = tokio_tungstenite::accept_async(stream).await {
                        tokio::time::sleep(hold).await;
                        drop(ws);
                    }
                });
            }
        });
        Self { addr }
    }

    pub fn url(&self) -> String {
        format!("ws://{}", self.addr)
    }
}
