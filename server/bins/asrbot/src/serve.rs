//! The HTTP accept loop with `net/http.Server` resource bounds
//! (ReadHeaderTimeout 5s, ReadTimeout 10s, IdleTimeout 60s).

use crate::control::Server;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use std::convert::Infallible;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

const IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const READ_HEADER_TIMEOUT: Duration = Duration::from_secs(5);

/// Serve until `shutdown` fires, then give open connections `grace` to finish.
pub async fn serve(
    listener: TcpListener,
    server: Arc<Server>,
    shutdown: CancellationToken,
    grace: Duration,
) {
    let mut connections = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            accepted = listener.accept() => {
                let Ok((stream, _)) = accepted else { continue };
                connections.spawn(connection(stream, server.clone(), shutdown.clone()));
            }
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
        }
    }
    let _ = tokio::time::timeout(grace, async {
        while connections.join_next().await.is_some() {}
    })
    .await;
}

async fn connection(
    stream: tokio::net::TcpStream,
    server: Arc<Server>,
    shutdown: CancellationToken,
) {
    let in_flight = Arc::new(AtomicUsize::new(0));
    let last_active = Arc::new(std::sync::Mutex::new(Instant::now()));
    let (flight, active) = (in_flight.clone(), last_active.clone());
    let service = service_fn(move |req| {
        let (server, flight, active) = (server.clone(), flight.clone(), active.clone());
        async move {
            flight.fetch_add(1, Ordering::SeqCst);
            let resp = server.handle(req).await;
            *active.lock().unwrap_or_else(|e| e.into_inner()) = Instant::now();
            flight.fetch_sub(1, Ordering::SeqCst);
            Ok::<_, Infallible>(resp)
        }
    });
    let conn = http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(READ_HEADER_TIMEOUT)
        .keep_alive(true)
        .serve_connection(TokioIo::new(stream), service);
    tokio::pin!(conn);
    let mut stopping = false;
    loop {
        let idle_deadline = *last_active.lock().unwrap_or_else(|e| e.into_inner()) + IDLE_TIMEOUT;
        tokio::select! {
            _ = &mut conn => return,
            _ = shutdown.cancelled(), if !stopping => {
                stopping = true;
                conn.as_mut().graceful_shutdown();
            }
            _ = tokio::time::sleep_until(idle_deadline) => {
                if in_flight.load(Ordering::SeqCst) == 0 {
                    conn.as_mut().graceful_shutdown();
                    // Nothing in flight: finish the connection and leave.
                    let _ = tokio::time::timeout(Duration::from_secs(1), &mut conn).await;
                    return;
                }
            }
        }
    }
}
