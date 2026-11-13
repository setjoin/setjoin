//! `security-event-delivery` (#304): drains the durable `security_event_outbox`,
//! mirroring frozen Go's `secevents.Worker` statement for statement.
//!
//! Go constructs the worker with a nil sink (no production sink is admitted, the
//! L2-C4 behaviour stays OFF), and a nil sink is fully inert: no connection, no
//! claim, no sweep, no retention. The executable does the same; a [`Sink`] can
//! only be injected by tests (and later by the ticket that admits a producer).
//! The outbox is FORCE-RLS deny-all, so the worker runs on the worker credential.
//!
//! Delivery is at-least-once. Every settlement is fenced on the `claim_generation`
//! the claim returned, so a lapsed lease cannot overwrite a newer claimant.
use setjoin_pg::{
    workers::{WorkerConnection, WorkerDatabase},
    Type,
};
use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    time::{Duration, Instant},
};

pub const NAME: &str = "security-event-delivery";
/// Go's `workerInterval`.
pub const INTERVAL: Duration = Duration::from_secs(3);
const MAX_ATTEMPTS: i32 = 5;
/// Go's `leaseWindow`.
const LEASE_WINDOW: Duration = Duration::from_secs(120);
/// Go's `settleTimeout`.
const SETTLE_TIMEOUT: Duration = Duration::from_secs(5);
const EXHAUSTED_SWEEP_LIMIT: i64 = 100;
const DEFAULT_DRAIN_BATCH: usize = 200;
const RETENTION_SWEEP_INTERVAL: Duration = Duration::from_secs(3600);
/// Go's `DefaultDeliverDeadline`.
pub const DEFAULT_DELIVER_DEADLINE: Duration = Duration::from_secs(90);

/// One claimed outbox row; `id` is the stable dedupe key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Event {
    pub id: i64,
    pub event_type: String,
    /// The outbox payload as PostgreSQL's `jsonb::text`.
    pub payload: String,
    /// Post-increment attempt count.
    pub attempts: i32,
}

pub type SinkFuture<'a> = Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>>;

/// The delivery target. The worker drops the returned future at the per-delivery
/// deadline or on shutdown, which is Go's context cancellation.
pub trait Sink: Send + Sync {
    fn deliver(&self, event: Event) -> SinkFuture<'_>;
}

const CLAIM: &str = "
UPDATE security_event_outbox
   SET attempts = attempts + 1,
       claim_generation = claim_generation + 1,
       next_attempt_at = now() + make_interval(secs => $1)
 WHERE id = (
   SELECT id FROM security_event_outbox
    WHERE status = 'pending'
      AND next_attempt_at <= now()
      AND attempts < $2
    ORDER BY next_attempt_at, id
    FOR UPDATE SKIP LOCKED
    LIMIT 1
 )
 RETURNING id, event_type, payload::text, attempts, claim_generation";

const DONE: &str = "
UPDATE security_event_outbox
   SET status = 'done', delivered_at = now(), next_attempt_at = now(),
       last_error = NULL, claim_generation = 0
 WHERE id = $1 AND status = 'pending' AND claim_generation = $2";

const RETRY: &str = "
UPDATE security_event_outbox
   SET status = 'pending', next_attempt_at = now() + make_interval(secs => $3),
       last_error = $4
 WHERE id = $1 AND status = 'pending' AND claim_generation = $2";

const FAIL: &str = "
UPDATE security_event_outbox
   SET status = 'failed', next_attempt_at = now(), last_error = $3,
       claim_generation = 0
 WHERE id = $1 AND status = 'pending' AND claim_generation = $2";

const EXHAUSTED: &str = "
UPDATE security_event_outbox
   SET status = 'failed',
       next_attempt_at = now(),
       claim_generation = 0,
       last_error = 'delivery attempts exhausted without settlement (' || attempts || ' attempts)'
 WHERE id IN (
   SELECT id FROM security_event_outbox
    WHERE status = 'pending'
      AND attempts >= $1
      AND next_attempt_at <= now()
    ORDER BY next_attempt_at, id
    LIMIT $2
 )
 AND status = 'pending'";

const PRUNE: &str = "SELECT security_event_outbox_prune()";

pub struct SecurityEventDelivery {
    db: WorkerDatabase,
    sink: Option<Arc<dyn Sink>>,
    deliver_deadline: Duration,
    drain_batch: usize,
    retention_interval: Duration,
    connection: tokio::sync::Mutex<Option<WorkerConnection>>,
    /// When the retention sweep last succeeded; `None` sweeps on the first tick.
    last_retention: std::sync::Mutex<Option<Instant>>,
}

impl SecurityEventDelivery {
    /// `sink` is `None` in production: the drain is then inert, as in Go.
    pub fn new(db: WorkerDatabase, sink: Option<Arc<dyn Sink>>) -> Self {
        Self {
            db,
            sink,
            deliver_deadline: DEFAULT_DELIVER_DEADLINE,
            drain_batch: DEFAULT_DRAIN_BATCH,
            retention_interval: RETENTION_SWEEP_INTERVAL,
            connection: tokio::sync::Mutex::new(None),
            last_retention: std::sync::Mutex::new(None),
        }
    }

    /// Go's `SetDeliverDeadline`: refuses a deadline that leaves no settlement
    /// margin under the lease (Go panics at startup).
    pub fn with_deliver_deadline(mut self, deadline: Duration) -> Self {
        assert!(
            !deadline.is_zero() && deadline + SETTLE_TIMEOUT < LEASE_WINDOW,
            "secevents: deliver deadline must be >0 and leave a settlement margin under the lease"
        );
        self.deliver_deadline = deadline;
        self
    }

    pub fn with_drain_batch(mut self, batch: usize) -> Self {
        self.drain_batch = batch;
        self
    }

    pub fn with_retention_interval(mut self, interval: Duration) -> Self {
        self.retention_interval = interval;
        self
    }

    /// Go's `Run`: the first drain is immediate, then one per interval. On stop
    /// an in-flight delivery is cancelled and still settles.
    pub async fn run_until(self, stop: impl Future<Output = ()> + Send) {
        eprintln!(
            "secevents: security-event delivery worker started sink_configured={}",
            self.sink.is_some()
        );
        if self.sink.is_none() {
            eprintln!("secevents: nil sink - drain inert, outbox rows and attempts untouched (no production sink admitted; behavior OFF)");
        }
        let (cancel, cancelled) = tokio::sync::watch::channel(false);
        let this = &self;
        let drain = async move {
            let mut ticks = tokio::time::interval_at(tokio::time::Instant::now(), INTERVAL);
            ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            let mut watch = cancelled.clone();
            loop {
                tokio::select! {
                    _ = ticks.tick() => {}
                    _ = watch.wait_for(|c| *c) => return,
                }
                this.tick(&cancelled).await;
                if *cancelled.borrow() {
                    return;
                }
            }
        };
        tokio::pin!(drain);
        tokio::pin!(stop);
        tokio::select! {
            _ = &mut drain => {}
            _ = &mut stop => {
                let _ = cancel.send(true);
                (&mut drain).await;
            }
        }
        eprintln!("secevents: security-event delivery worker stopped");
    }

    /// One drain with no shutdown signal (the first, immediate drain of `Run`).
    pub async fn drain_once(&self) {
        let (_keep, never) = tokio::sync::watch::channel(false);
        self.tick(&never).await;
    }

    /// One drain: a bounded batch, the exhausted-claim sweep, then the
    /// rate-limited retention sweep.
    pub async fn tick(&self, cancelled: &tokio::sync::watch::Receiver<bool>) {
        if self.sink.is_none() || *cancelled.borrow() {
            return;
        }
        let mut slot = self.connection.lock().await;
        if slot.is_none() {
            match self.db.connect().await {
                Ok(c) => *slot = Some(c),
                Err(_) => {
                    eprintln!("secevents: process failed");
                    return;
                }
            }
        }
        let conn = slot.as_ref().expect("connected above");
        let mut broken = false;
        for _ in 0..self.drain_batch {
            match self.process_one(conn, cancelled).await {
                Ok(true) => {}
                Ok(false) => break,
                Err(_) => {
                    if !*cancelled.borrow() {
                        eprintln!("secevents: process failed");
                    }
                    broken = true;
                    break;
                }
            }
        }
        if !broken {
            broken = self.terminalize_exhausted(conn, cancelled).await;
        }
        if !broken {
            broken = self.prune_delivered(conn, cancelled).await;
        }
        if broken {
            // Go's pool replaces a broken connection; do the same next tick.
            *slot = None;
        }
    }

    async fn process_one(
        &self,
        conn: &WorkerConnection,
        cancelled: &tokio::sync::watch::Receiver<bool>,
    ) -> Result<bool, String> {
        let lease = LEASE_WINDOW.as_secs_f64();
        let rows = conn
            .query(
                CLAIM,
                &[(&lease, Type::FLOAT8), (&MAX_ATTEMPTS, Type::INT4)],
            )
            .await?;
        let Some(row) = rows.first() else {
            return Ok(false);
        };
        let event = Event {
            id: row.get(0),
            event_type: row.get(1),
            payload: row.get(2),
            attempts: row.get(3),
        };
        let generation: i32 = row.get(4);
        let sink = self.sink.as_ref().expect("checked in tick").clone();
        let outcome = {
            let mut cancelled = cancelled.clone();
            tokio::select! {
                result = sink.deliver(event.clone()) => Outcome::Returned(result),
                _ = tokio::time::sleep(self.deliver_deadline) => Outcome::Deadline,
                _ = cancelled.wait_for(|c| *c) => Outcome::Cancelled,
            }
        };
        self.settle(conn, &event, generation, outcome).await;
        Ok(true)
    }

    /// Settles fenced: done on success; on failure a capped-backoff retry or,
    /// at the attempt cap, terminal failed. Cancellation does not skip it.
    async fn settle(&self, conn: &WorkerConnection, ev: &Event, generation: i32, outcome: Outcome) {
        let error = match outcome {
            Outcome::Returned(Ok(())) => None,
            other => Some(settle_cause(self.deliver_deadline, other)),
        };
        if let Some(cause) = &error {
            eprintln!(
                "secevents: delivery failed event_id={} event_type={} attempt={} cause={cause}",
                ev.id, ev.event_type, ev.attempts
            );
        }
        let work = async {
            match &error {
                None => {
                    conn.execute(DONE, &[(&ev.id, Type::INT8), (&generation, Type::INT4)])
                        .await
                }
                Some(cause) if ev.attempts >= MAX_ATTEMPTS => {
                    conn.execute(
                        FAIL,
                        &[
                            (&ev.id, Type::INT8),
                            (&generation, Type::INT4),
                            (cause, Type::TEXT),
                        ],
                    )
                    .await
                }
                Some(cause) => {
                    let backoff = backoff_for(ev.attempts).as_secs_f64();
                    conn.execute(
                        RETRY,
                        &[
                            (&ev.id, Type::INT8),
                            (&generation, Type::INT4),
                            (&backoff, Type::FLOAT8),
                            (cause, Type::TEXT),
                        ],
                    )
                    .await
                }
            }
        };
        match tokio::time::timeout(SETTLE_TIMEOUT, work).await {
            Ok(Ok(0)) => eprintln!(
                "secevents: stale settlement ignored (claim superseded) event_id={} claim_generation={generation}",
                ev.id
            ),
            Ok(Ok(_)) => {}
            _ => eprintln!(
                "secevents: fenced settlement failed (row stays leased until expiry) event_id={} claim_generation={generation}",
                ev.id
            ),
        }
    }

    /// Returns whether the session should be dropped.
    async fn terminalize_exhausted(
        &self,
        conn: &WorkerConnection,
        cancelled: &tokio::sync::watch::Receiver<bool>,
    ) -> bool {
        match conn
            .execute(
                EXHAUSTED,
                &[
                    (&MAX_ATTEMPTS, Type::INT4),
                    (&EXHAUSTED_SWEEP_LIMIT, Type::INT8),
                ],
            )
            .await
        {
            Ok(0) => false,
            Ok(rows) => {
                eprintln!("secevents: terminalized claims exhausted without settlement (crash cycles) rows={rows}");
                false
            }
            Err(_) => {
                if !*cancelled.borrow() {
                    eprintln!("secevents: exhausted-claim sweep failed");
                }
                true
            }
        }
    }

    async fn prune_delivered(
        &self,
        conn: &WorkerConnection,
        cancelled: &tokio::sync::watch::Receiver<bool>,
    ) -> bool {
        if *cancelled.borrow() {
            return false;
        }
        let due = self
            .last_retention
            .lock()
            .unwrap()
            .is_none_or(|at| at.elapsed() >= self.retention_interval);
        if !due {
            return false;
        }
        match conn.query(PRUNE, &[]).await {
            Ok(rows) => {
                *self.last_retention.lock().unwrap() = Some(Instant::now());
                let pruned: i64 = rows.first().map_or(0, |r| r.get(0));
                if pruned > 0 {
                    eprintln!("secevents: retention pruned delivered outbox rows rows={pruned}");
                }
                false
            }
            Err(_) => {
                if !*cancelled.borrow() {
                    eprintln!("secevents: retention sweep failed");
                }
                true
            }
        }
    }
}

enum Outcome {
    Returned(Result<(), String>),
    Deadline,
    Cancelled,
}

/// Go's `settleCause`: the sink's text capped at 2048 bytes, prefixed when the
/// failure was the deadline or a cancellation.
fn settle_cause(deadline: Duration, outcome: Outcome) -> String {
    match outcome {
        Outcome::Returned(Ok(())) => String::new(),
        Outcome::Returned(Err(text)) => cap(&text),
        Outcome::Deadline => format!(
            "delivery deadline exceeded ({}): context deadline exceeded",
            go_duration(deadline)
        ),
        Outcome::Cancelled => "delivery cancelled: context canceled".into(),
    }
}

fn cap(text: &str) -> String {
    if text.len() <= 2048 {
        return text.to_owned();
    }
    // Go slices bytes; keep a valid UTF-8 prefix (Go would send invalid text).
    let mut end = 2048;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_owned()
}

/// Go's `min(1min * 2^attempts, 1h)` with the shift guard.
fn backoff_for(attempts: i32) -> Duration {
    let attempts = attempts.clamp(1, 6) as u32;
    Duration::from_secs(60 * (1u64 << attempts)).min(Duration::from_secs(3600))
}

/// `time.Duration.String` for the values this worker prints.
fn go_duration(d: Duration) -> String {
    let nanos = d.as_nanos();
    if nanos == 0 {
        return "0s".into();
    }
    if nanos < 1_000_000_000 {
        let (value, unit) = if nanos < 1_000 {
            (nanos as f64, "ns")
        } else if nanos < 1_000_000 {
            (nanos as f64 / 1e3, "µs")
        } else {
            (nanos as f64 / 1e6, "ms")
        };
        return format!("{}{unit}", trim_fraction(value));
    }
    let total = nanos as f64 / 1e9;
    let hours = (total / 3600.0).floor() as u64;
    let minutes = ((total - hours as f64 * 3600.0) / 60.0).floor() as u64;
    let seconds = total - hours as f64 * 3600.0 - minutes as f64 * 60.0;
    let mut out = String::new();
    if hours > 0 {
        out.push_str(&format!("{hours}h"));
    }
    if hours > 0 || minutes > 0 {
        out.push_str(&format!("{minutes}m"));
    }
    out.push_str(&format!("{}s", trim_fraction(seconds)));
    out
}

fn trim_fraction(value: f64) -> String {
    let text = format!("{value:.9}");
    text.trim_end_matches('0').trim_end_matches('.').to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn go_duration_matches_go() {
        assert_eq!(go_duration(Duration::from_secs(90)), "1m30s");
        assert_eq!(go_duration(Duration::from_millis(100)), "100ms");
        assert_eq!(go_duration(Duration::from_secs(3600)), "1h0m0s");
        assert_eq!(go_duration(Duration::from_millis(1500)), "1.5s");
    }

    #[test]
    fn backoff_is_capped_exponential() {
        let minutes: Vec<u64> = (0..8).map(|a| backoff_for(a).as_secs() / 60).collect();
        assert_eq!(minutes, vec![2, 2, 4, 8, 16, 32, 60, 60]);
    }
}
