//! #304: seed-plus-one-tick oracle for `security-event-delivery`. Frozen Go's
//! real `secevents.Worker.Run` (overlay `tests/conformance/drain/
//! secevents_tick_test.go.txt`) runs its immediate first drain over a seeded
//! `security_event_outbox`; the Rust worker's drain must leave the same rows
//! and hand the same events to the sink in the same order.
//!
//! `nil-sink` is Go's production posture: nothing may change. The other cases
//! inject a sink that answers by event type (the production binary never does).
//!
//! Record: `GOFREE_RECORD_DRAIN=all|case,case` (+ `GOFREE_GO_SOURCE`); delete a
//! golden to re-record it. Replay needs no Go.
mod drain_oracle;
use drain_oracle::{settle, BoxError, GoTick};
use serde_json::{json, Value};
use setjoin_conformance::harness::Db;
use setjoin_gateway::secevents::{Event, SecurityEventDelivery, Sink, SinkFuture};
use setjoin_pg::workers::WorkerDatabase;
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio_postgres::{Client, SimpleQueryMessage};

static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[derive(Default)]
struct Case {
    name: &'static str,
    /// Go's production nil sink when false.
    sink: bool,
    deadline_ms: u64,
    batch: usize,
    seed: Vec<String>,
    /// Row lock held by a second session across the drain (SKIP LOCKED).
    lock: Option<&'static str>,
}

/// One outbox row. `next` is seconds from now; `delivered_days` ages a done row.
fn row(
    label: &str,
    ty: &str,
    status: &str,
    attempts: i32,
    next: i64,
    delivered_days: Option<i64>,
    generation: i32,
) -> String {
    let delivered = delivered_days.map_or("NULL".to_string(), |d| {
        format!("now() - interval '{d} days'")
    });
    format!(
        "INSERT INTO security_event_outbox(event_type,payload,status,attempts,next_attempt_at,delivered_at,claim_generation) \
         VALUES ('{ty}','{{\"label\":\"{label}\"}}','{status}',{attempts},now() + interval '{next} seconds',{delivered},{generation})"
    )
}

fn pending(label: &str, ty: &str, attempts: i32, next: i64) -> String {
    row(label, ty, "pending", attempts, next, None, 0)
}

fn cases() -> Vec<Case> {
    // The drain batch is shrunk to 20 (Go: the unexported `drainBatch`) so the
    // bound is reachable inside the overlay's single drain.
    let batch = vec![
        "INSERT INTO security_event_outbox(event_type,payload,next_attempt_at) \
         SELECT 'sec.ok', json_build_object('label','n'||lpad(g::text,3,'0'))::jsonb, now() - interval '1 hour' \
         FROM generate_series(1,25) g"
            .to_string(),
    ];
    vec![
        Case {
            name: "secevents-nil-sink",
            sink: false,
            seed: vec![
                pending("due", "sec.ok", 0, -60),
                pending("exhausted", "sec.ok", 5, -60),
                row("old-done", "sec.ok", "done", 0, -60, Some(200), 0),
                row("failed", "sec.ok", "failed", 5, -60, None, 0),
            ],
            ..Default::default()
        },
        Case {
            name: "secevents-deliver-order-and-sweep",
            sink: true,
            seed: vec![
                pending("a-later", "sec.ok", 0, -60),
                pending("b-earlier", "sec.ok", 0, -600),
                pending("c-not-due", "sec.ok", 0, 3600),
                pending("d-exhausted", "sec.ok", 5, -60),
                pending("e-exhausted-leased", "sec.ok", 5, 3600),
                row("f-failed", "sec.ok", "failed", 5, -60, None, 0),
                row("g-reclaim", "sec.ok", "pending", 2, -60, None, 7),
            ],
            ..Default::default()
        },
        Case {
            name: "secevents-failure-backoff-and-cap",
            sink: true,
            seed: vec![
                pending("first-fail", "sec.fail", 0, -60),
                pending("third-fail", "sec.fail", 2, -60),
                pending("fourth-fail", "sec.fail", 3, -60),
                pending("cap-fail", "sec.fail", 4, -60),
                pending("long-error", "sec.long", 0, -60),
                pending("ok-beside", "sec.ok", 0, -60),
            ],
            ..Default::default()
        },
        Case {
            name: "secevents-skip-locked",
            sink: true,
            seed: vec![
                pending("locked", "sec.ok", 0, -600),
                pending("free", "sec.ok", 0, -60),
            ],
            lock: Some("SELECT id FROM security_event_outbox WHERE payload->>'label'='locked' FOR UPDATE"),
            ..Default::default()
        },
        Case {
            name: "secevents-batch-bound",
            sink: true,
            batch: 20,
            seed: batch,
            ..Default::default()
        },
        Case {
            name: "secevents-delivery-deadline",
            sink: true,
            deadline_ms: 100,
            seed: vec![
                pending("blocks", "sec.block", 0, -60),
                pending("after", "sec.ok", 0, -30),
            ],
            ..Default::default()
        },
        Case {
            name: "secevents-stale-settlement",
            sink: true,
            seed: vec![
                pending("stolen-ok", "sec.steal", 0, -60),
                pending("stolen-late", "sec.steal", 4, -30),
            ],
            ..Default::default()
        },
        Case {
            name: "secevents-retention-default",
            sink: true,
            seed: vec![
                row("done-100d", "sec.ok", "done", 1, 0, Some(100), 0),
                row("done-10d", "sec.ok", "done", 1, 0, Some(10), 0),
                row("failed-200d", "sec.ok", "failed", 5, 0, None, 0),
                pending("pending-future", "sec.ok", 0, 3600),
            ],
            ..Default::default()
        },
        Case {
            name: "secevents-retention-configured",
            sink: true,
            seed: vec![
                "INSERT INTO system_config(key,value) VALUES ('security_event_outbox_retain_days','5') ON CONFLICT(key) DO UPDATE SET value='5'".into(),
                row("done-10d", "sec.ok", "done", 1, 0, Some(10), 0),
                row("done-2d", "sec.ok", "done", 1, 0, Some(2), 0),
            ],
            ..Default::default()
        },
        Case {
            name: "secevents-retention-bad-config",
            sink: true,
            seed: vec![
                "INSERT INTO system_config(key,value) VALUES ('security_event_outbox_retain_days','\"abc\"') ON CONFLICT(key) DO UPDATE SET value='\"abc\"'".into(),
                row("done-100d", "sec.ok", "done", 1, 0, Some(100), 0),
                pending("due", "sec.ok", 0, -60),
            ],
            ..Default::default()
        },
    ]
}

/// Answers by event type like the Go overlay's sink.
struct TestSink {
    log: Mutex<Vec<Value>>,
    dsn: String,
}

impl Sink for TestSink {
    fn deliver(&self, event: Event) -> SinkFuture<'_> {
        self.log.lock().unwrap().push(
            json!({"type": event.event_type, "payload": event.payload, "attempts": event.attempts}),
        );
        let dsn = self.dsn.clone();
        Box::pin(async move {
            if event.event_type.starts_with("sec.fail") {
                Err(format!("sink refused {}", event.event_type))
            } else if event.event_type.starts_with("sec.long") {
                Err("x".repeat(3000))
            } else if event.event_type.starts_with("sec.steal") {
                let client = tokio_connect(&dsn).await.map_err(|e| e.to_string())?;
                client
                    .execute(
                        "UPDATE security_event_outbox SET claim_generation = claim_generation + 1 WHERE id = $1",
                        &[&event.id],
                    )
                    .await
                    .map_err(|e| e.to_string())?;
                Ok(())
            } else if event.event_type.starts_with("sec.block") {
                std::future::pending().await
            } else {
                Ok(())
            }
        })
    }
}

#[tokio::test]
async fn secevents_seed_plus_one_tick() -> Result<(), BoxError> {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(db) = Db::for_case("secevents-tick") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let record = std::env::var("GOFREE_RECORD_DRAIN").ok();
    let only = std::env::var("GOFREE_DRAIN_ONLY").ok();
    let listed = |filter: &Option<String>, name: &str| {
        filter
            .as_deref()
            .is_none_or(|f| f == "all" || f.split(',').any(|t| t == name))
    };
    let mut failures = Vec::new();
    let mut ran = 0;
    for case in cases() {
        let recording = record.is_some() && listed(&record, case.name);
        if record.is_some() && !recording || !listed(&only, case.name) {
            continue;
        }
        ran += 1;
        let result = run_case(&db, &owner, &case, recording).await;
        let _ = owner
            .batch_execute(
                "DELETE FROM security_event_outbox; DELETE FROM system_config WHERE key='security_event_outbox_retain_days'",
            )
            .await;
        if let Err(error) = result {
            failures.push(format!("{}: {error}", case.name));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    assert!(ran > 0, "no case selected");
    Ok(())
}

async fn run_case(db: &Db, owner: &Client, case: &Case, recording: bool) -> Result<(), BoxError> {
    owner
        .batch_execute(
            "DELETE FROM security_event_outbox; DELETE FROM system_config WHERE key='security_event_outbox_retain_days'",
        )
        .await?;
    for sql in &case.seed {
        owner.batch_execute(sql).await?;
    }
    let before = observe_rows(owner).await?;
    let holder = db.connect().await?;
    if let Some(sql) = case.lock {
        holder.batch_execute("BEGIN").await?;
        holder.batch_execute(sql).await?;
    }
    let deliveries: Vec<Value> = if recording {
        let log = drain_oracle::repo_root()?.join(format!("test-results/gofree-{}.log", case.name));
        let _ = std::fs::remove_file(&log);
        let mut env = vec![
            ("GOFREE_SECEVENTS_DSN".to_string(), db.dsn.clone()),
            (
                "GOFREE_SECEVENTS_SINK".into(),
                if case.sink { "test" } else { "none" }.into(),
            ),
            (
                "GOFREE_SECEVENTS_LOG".into(),
                format!("/src/test-results/gofree-{}.log", case.name),
            ),
        ];
        if case.batch > 0 {
            env.push(("GOFREE_SECEVENTS_BATCH".into(), case.batch.to_string()));
        }
        if case.deadline_ms > 0 {
            env.push((
                "GOFREE_SECEVENTS_DEADLINE_MS".into(),
                case.deadline_ms.to_string(),
            ));
        }
        GoTick {
            package: "internal/secevents",
            overlay: "secevents_tick_test.go.txt",
            test: "TestGoFreeSecEventsTick",
            file: "gofree_secevents_tick_test.go",
            env,
            docker: vec![],
        }
        .run()?;
        let text = std::fs::read_to_string(&log).unwrap_or_default();
        text.lines()
            .map(serde_json::from_str)
            .collect::<Result<_, _>>()?
    } else {
        let sink = Arc::new(TestSink {
            log: Mutex::default(),
            dsn: db.dsn.clone(),
        });
        let mut worker = SecurityEventDelivery::new(
            WorkerDatabase::new(&db.dsn)?,
            case.sink.then(|| sink.clone() as Arc<dyn Sink>),
        );
        if case.deadline_ms > 0 {
            worker = worker.with_deliver_deadline(Duration::from_millis(case.deadline_ms));
        }
        if case.batch > 0 {
            worker = worker.with_drain_batch(case.batch);
        }
        worker.drain_once().await;
        let log = sink.log.lock().unwrap().clone();
        log
    };
    if case.lock.is_some() {
        holder.batch_execute("ROLLBACK").await?;
    }
    let mut rows = observe_rows(owner).await?;
    // The Go run compiles after the seed, so a seeded timestamp drifts by
    // minutes; only rows the drain rewrote carry a meaningful offset.
    for row in rows.as_array_mut().unwrap() {
        let seeded = before
            .as_array()
            .unwrap()
            .iter()
            .find(|b| b["label"] == row["label"]);
        if seeded.is_some_and(|b| b["next_raw"] == row["next_raw"]) {
            row["next_attempt_s"] = json!("unchanged");
        }
        row.as_object_mut().unwrap().remove("next_raw");
    }
    if recording && case.sink && rows.as_array() == strip(&before).as_array() {
        return Err(format!("Go's drain changed nothing: {rows}").into());
    }
    settle(
        case.name,
        json!({"rows": rows, "deliveries": deliveries}),
        recording,
    )
}

/// Rows keyed by their label; ids differ between runs, `next_attempt_at` is
/// bucketed to 30 s from now.
async fn observe_rows(owner: &Client) -> Result<Value, BoxError> {
    let mut rows = Vec::new();
    for message in owner
        .simple_query(
            "SELECT payload->>'label', status, attempts::text, claim_generation::text, \
                    coalesce(last_error,'<null>'), (delivered_at IS NOT NULL)::text, \
                    (round(extract(epoch FROM next_attempt_at - now())/30)*30)::bigint::text, \
                    next_attempt_at::text \
               FROM security_event_outbox ORDER BY payload->>'label'",
        )
        .await?
    {
        if let SimpleQueryMessage::Row(row) = message {
            rows.push(json!({
                "label": row.get(0), "status": row.get(1), "attempts": row.get(2),
                "claim_generation": row.get(3), "last_error": row.get(4),
                "delivered": row.get(5), "next_attempt_s": row.get(6),
                "next_raw": row.get(7),
            }));
        }
    }
    Ok(Value::Array(rows))
}

/// `rows` without the seed-only fields, to tell whether the drain changed anything.
fn strip(rows: &Value) -> Value {
    let mut rows = rows.clone();
    for row in rows.as_array_mut().unwrap() {
        let row = row.as_object_mut().unwrap();
        row.remove("next_raw");
        row.insert("next_attempt_s".into(), json!("unchanged"));
    }
    rows
}

async fn tokio_connect(dsn: &str) -> Result<Client, tokio_postgres::Error> {
    let (client, connection) = tokio_postgres::connect(dsn, tokio_postgres::NoTls).await?;
    tokio::spawn(connection);
    Ok(client)
}
