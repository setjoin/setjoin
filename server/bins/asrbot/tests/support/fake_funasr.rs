//! A FunASR-shaped WebSocket peripheral: records every frame, answers speech
//! with a partial and the 2pass final after `{"is_speaking":false}`, like the
//! pinned runtime (final ~immediately after the closing frame, then close).

use futures_util::{SinkExt, StreamExt};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    Text(String),
    /// A binary frame: only its length is kept (the audio itself is run-specific).
    Binary(usize),
}

#[derive(Default)]
pub struct Observed {
    pub connections: usize,
    /// (request target, header name -> value) of each upgrade, in connection order.
    pub upgrades: Vec<(String, Vec<(String, String)>)>,
    /// (connection index, frame)
    pub frames: Vec<(usize, Frame)>,
}

pub struct FakeFunasr {
    pub addr: SocketAddr,
    pub observed: Arc<Mutex<Observed>>,
}

impl FakeFunasr {
    /// `partial_text`/`final_text` are what the fake "recognises".
    pub async fn start(partial_text: &'static str, final_text: &'static str) -> Self {
        Self::start_with(partial_text, final_text, None).await
    }

    /// `drop_first_after`: abruptly close the first connection after that many binary frames.
    pub async fn start_with(
        partial_text: &'static str,
        final_text: &'static str,
        drop_first_after: Option<usize>,
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind funasr");
        let addr = listener.local_addr().expect("addr");
        let observed = Arc::new(Mutex::new(Observed::default()));
        let shared = observed.clone();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let shared = shared.clone();
                tokio::spawn(async move {
                    let capture = shared.clone();
                    let callback = move |request: &tokio_tungstenite::tungstenite::handshake::server::Request,
                                         response: tokio_tungstenite::tungstenite::handshake::server::Response| {
                        let headers = request.headers().iter().map(|(k, v)| (k.as_str().to_owned(), v.to_str().unwrap_or("").to_owned())).collect();
                        let target = request.uri().path_and_query().map(|p| p.as_str().to_owned()).unwrap_or_default();
                        capture.lock().unwrap().upgrades.push((target, headers));
                        Ok(response)
                    };
                    let Ok(mut ws) = tokio_tungstenite::accept_hdr_async(stream, callback).await
                    else {
                        return;
                    };
                    let index = {
                        let mut o = shared.lock().unwrap();
                        o.connections += 1;
                        o.connections
                    };
                    let mut sent_partial = false;
                    let mut binary_seen = 0usize;
                    while let Some(Ok(message)) = ws.next().await {
                        match message {
                            Message::Text(text) => {
                                let text = text.to_string();
                                shared
                                    .lock()
                                    .unwrap()
                                    .frames
                                    .push((index, Frame::Text(text.clone())));
                                if text.contains("\"is_speaking\":false") {
                                    let _ = ws
                                        .send(Message::text(format!(
                                            "{{\"text\":\"{final_text}\",\"is_final\":true}}"
                                        )))
                                        .await;
                                    let _ = ws.close(None).await;
                                    return;
                                }
                            }
                            Message::Binary(bytes) => {
                                shared
                                    .lock()
                                    .unwrap()
                                    .frames
                                    .push((index, Frame::Binary(bytes.len())));
                                binary_seen += 1;
                                if index == 1 && drop_first_after == Some(binary_seen) {
                                    return; // drop the TCP connection without a close frame
                                }
                                if !sent_partial {
                                    sent_partial = true;
                                    let _ = ws
                                        .send(Message::text(format!(
                                            "{{\"text\":\"{partial_text}\",\"is_final\":false}}"
                                        )))
                                        .await;
                                }
                            }
                            _ => {}
                        }
                    }
                });
            }
        });
        Self { addr, observed }
    }

    pub fn url(&self) -> String {
        format!("ws://{}", self.addr)
    }
}
