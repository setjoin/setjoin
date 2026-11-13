//! Process counters behind `GET /metrics` (`gateway_requests_total` and
//! friends). Go counts these in `RecordRequest`/`IncConn`; the Rust front door
//! sees every request, so it counts them at the same two seams.
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

pub static REQUESTS: AtomicU64 = AtomicU64::new(0);
pub static ERRORS: AtomicU64 = AtomicU64::new(0);
pub static STATUS_4XX: AtomicU64 = AtomicU64::new(0);
pub static STATUS_5XX: AtomicU64 = AtomicU64::new(0);
pub static DURATION_MS: AtomicU64 = AtomicU64::new(0);
pub static CONNECTIONS: AtomicI64 = AtomicI64::new(0);

/// `RecordRequest`.
pub fn record(duration: std::time::Duration, status: u16) {
    REQUESTS.fetch_add(1, Ordering::Relaxed);
    DURATION_MS.fetch_add(duration.as_millis() as u64, Ordering::Relaxed);
    if status >= 500 {
        ERRORS.fetch_add(1, Ordering::Relaxed);
        STATUS_5XX.fetch_add(1, Ordering::Relaxed);
    } else if status >= 400 {
        ERRORS.fetch_add(1, Ordering::Relaxed);
        STATUS_4XX.fetch_add(1, Ordering::Relaxed);
    }
}

/// Holds one active connection for its lifetime (`IncConn`/`DecConn`).
pub struct Connection;

impl Connection {
    pub fn open() -> Self {
        CONNECTIONS.fetch_add(1, Ordering::Relaxed);
        Self
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        CONNECTIONS.fetch_sub(1, Ordering::Relaxed);
    }
}

pub fn snapshot() -> setjoin_static::metrics::Process {
    // Resident set size stands in for Go's `runtime.MemStats.Alloc`.
    let memory_bytes = std::fs::read_to_string("/proc/self/statm")
        .ok()
        .and_then(|s| s.split_whitespace().nth(1)?.parse::<u64>().ok())
        .map_or(0, |pages| pages * 4096);
    setjoin_static::metrics::Process {
        requests: REQUESTS.load(Ordering::Relaxed),
        errors: ERRORS.load(Ordering::Relaxed),
        status_4xx: STATUS_4XX.load(Ordering::Relaxed),
        status_5xx: STATUS_5XX.load(Ordering::Relaxed),
        duration_ms: DURATION_MS.load(Ordering::Relaxed),
        active_connections: CONNECTIONS.load(Ordering::Relaxed),
        memory_bytes,
        tasks: tokio::runtime::Handle::try_current()
            .map_or(0, |h| h.metrics().num_alive_tasks() as u64),
    }
}
