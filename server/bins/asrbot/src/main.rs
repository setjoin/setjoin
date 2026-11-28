//! `asrbotd`: joins a meeting's LiveKit room as an unhidden, publish-nothing
//! participant, streams subscribed audio through FunASR and publishes
//! `{t:'cc',...}` caption frames. Driven by the gateway's loopback-only
//! control API; it holds no DB/S3 credential and mints no LiveKit token.

use serde_json::json;
use setjoin_asrbot::config::Config;
use setjoin_asrbot::control::{validate_loopback, validate_token, Server};
use setjoin_asrbot::log::{self, s};
use setjoin_asrbot::registry::RoomRegistry;
use setjoin_asrbot::serve::serve;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

#[tokio::main]
async fn main() {
    let cfg = Config::from_env();
    if let Err(err) = validate_loopback(&cfg.listen) {
        log::error("refusing to start", &[("err", s(err))]);
        std::process::exit(1);
    }
    if let Err(err) = validate_token(&cfg.token) {
        log::error("refusing to start", &[("err", s(err))]);
        std::process::exit(1);
    }

    let runner = Arc::new(setjoin_asrbot::session::Sessions::new(&cfg));
    let rooms = Arc::new(RoomRegistry::new(cfg.max_meetings, runner));
    let server = Arc::new(Server::new(rooms, cfg.token.clone()));

    let shutdown = CancellationToken::new();
    // Go logs the "listening" line from the serving goroutine before ListenAndServe
    // can fail, so a failed bind is announced, then reported.
    let serving = {
        let (listen, shutdown, cfg) = (cfg.listen.clone(), shutdown.clone(), cfg.clone());
        tokio::spawn(async move {
            log::info(
                "asrbotd listening",
                &[
                    ("addr", s(&cfg.listen)),
                    ("livekit_url", s(&cfg.livekit_url)),
                    ("funasr_url", s(&cfg.funasr_url)),
                    ("max_meetings", json!(cfg.max_meetings)),
                    ("max_active_tracks", json!(cfg.max_active_tracks)),
                ],
            );
            match bind(&listen).await {
                Ok(listener) => serve(listener, server, shutdown, Duration::from_secs(5)).await,
                Err(err) => {
                    log::error("control server failed", &[("err", s(err.to_string()))]);
                    shutdown.cancel();
                }
            }
        })
    };

    wait_for_signal(&shutdown).await;
    log::info("shutting down", &[]);
    shutdown.cancel();
    let _ = serving.await;
}

/// Go's `net.Listen("tcp", addr)` failure text: `listen tcp <addr>: bind: <reason>`.
#[derive(Debug)]
struct ListenError(String);

impl std::fmt::Display for ListenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

async fn bind(addr: &str) -> Result<TcpListener, ListenError> {
    let mut resolved: Vec<std::net::SocketAddr> = tokio::net::lookup_host(addr)
        .await
        .map_err(|e| ListenError(format!("listen tcp: lookup {addr}: {e}")))?
        .collect();
    // Go listens on the IPv4 address when a name resolves to both families.
    resolved.sort_by_key(|a| !a.is_ipv4());
    let first = resolved.first().copied().ok_or_else(|| {
        ListenError(format!(
            "listen tcp: lookup {addr}: no suitable address found"
        ))
    })?;
    TcpListener::bind(first).await.map_err(|e| {
        let reason = match e.kind() {
            std::io::ErrorKind::AddrInUse => "address already in use".to_owned(),
            std::io::ErrorKind::PermissionDenied => "permission denied".to_owned(),
            std::io::ErrorKind::AddrNotAvailable => "cannot assign requested address".to_owned(),
            _ => e.to_string(),
        };
        ListenError(format!("listen tcp {first}: bind: {reason}"))
    })
}

async fn wait_for_signal(shutdown: &CancellationToken) {
    use tokio::signal::unix::{signal, SignalKind};
    let (Ok(mut term), Ok(mut int)) = (
        signal(SignalKind::terminate()),
        signal(SignalKind::interrupt()),
    ) else {
        shutdown.cancelled().await;
        return;
    };
    tokio::select! {
        _ = term.recv() => {}
        _ = int.recv() => {}
        _ = shutdown.cancelled() => {}
    }
}
