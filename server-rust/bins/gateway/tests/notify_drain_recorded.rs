//! #408: seed-plus-one-tick oracle for `notify-intent-drain`. Frozen Go's real
//! `notifyjobs.Worker.Run` (overlay `tests/conformance/drain/`) runs one tick
//! over a seeded `notify_intents` queue; the Rust worker's tick must leave the
//! same rows and emit the same `pg_notify` payloads in the same order.
//!
//! Record: `GOFREE_RECORD_DRAIN=all|case,case` (+ `GOFREE_GO_SOURCE`); delete a
//! golden to re-record it. Replay needs no Go.
mod drain_oracle;
use drain_oracle::{settle, BoxError, GoTick};
use serde_json::{json, Map, Value};
use setjoin_conformance::harness::{Db, Listener};
use setjoin_gateway::notify_drain::NotifyIntentDrain;
use setjoin_pg::workers::WorkerDatabase;
use tokio_postgres::{Client, SimpleQueryMessage};

static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
const CHANNELS: [&str; 4] = [
    "gofree-drain-a",
    "gofree-drain-b",
    "gofree-drain-bulk",
    "gofree-drain-locked",
];

struct Case {
    name: &'static str,
    seed: &'static [&'static str],
    /// Row-level lock held across the tick (SKIP LOCKED).
    lock: Option<&'static str>,
}

const CASES: &[Case] = &[
    Case {
        name: "notify-drain-order-and-dedupe",
        seed: &["INSERT INTO notify_intents(channel,payload) VALUES ('gofree-drain-a','p1'),('gofree-drain-a','p1'),('gofree-drain-b','p2'),('gofree-drain-a','p3'),('gofree-drain-a','p1')"],
        lock: None,
    },
    Case {
        name: "notify-drain-batch-loop",
        // 501 rows: the tick drains a full batch of 500, then the remainder.
        seed: &["INSERT INTO notify_intents(channel,payload) SELECT 'gofree-drain-bulk','n'||lpad(g::text,4,'0') FROM generate_series(1,501) g"],
        lock: None,
    },
    Case {
        name: "notify-drain-skip-locked",
        seed: &["INSERT INTO notify_intents(channel,payload) VALUES ('gofree-drain-locked','locked'),('gofree-drain-locked','free')"],
        lock: Some("SELECT id FROM notify_intents WHERE payload='locked' FOR UPDATE"),
    },
    Case {
        name: "notify-drain-idle",
        seed: &[],
        lock: None,
    },
    Case {
        name: "notify-drain-decoupled-reducer",
        // feature.notify_decouple ON: a reducer's app_notify writes an intent
        // instead of notifying; only the drain makes the event visible.
        seed: &[
            "INSERT INTO feature_toggles(key,enabled,description) VALUES ('feature.notify_decouple',true,'x') ON CONFLICT(key) DO UPDATE SET enabled=true",
            "SELECT app_notify('gofree-drain-a','from-reducer')",
        ],
        lock: None,
    },
];

#[tokio::test]
async fn notify_drain_seed_plus_one_tick() -> Result<(), BoxError> {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(db) = Db::for_case("notify-drain-tick") else {
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
    let toggle_before: Option<bool> = owner
        .query_opt(
            "SELECT enabled FROM feature_toggles WHERE key='feature.notify_decouple'",
            &[],
        )
        .await?
        .map(|r| r.get(0));
    let mut failures = Vec::new();
    let mut ran = 0;
    for case in CASES {
        let recording = record.is_some() && listed(&record, case.name);
        if record.is_some() && !recording || !listed(&only, case.name) {
            continue;
        }
        ran += 1;
        let result = run_case(&db, &owner, case, recording).await;
        let _ = owner.batch_execute("DELETE FROM notify_intents").await;
        if let Err(error) = result {
            failures.push(format!("{}: {error}", case.name));
        }
    }
    owner
        .execute(
            "UPDATE feature_toggles SET enabled=$1 WHERE key='feature.notify_decouple'",
            &[&toggle_before.unwrap_or(false)],
        )
        .await?;
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    assert!(ran > 0, "no case selected");
    Ok(())
}

async fn run_case(db: &Db, owner: &Client, case: &Case, recording: bool) -> Result<(), BoxError> {
    owner
        .batch_execute(
            "DELETE FROM notify_intents; UPDATE feature_toggles SET enabled=false WHERE key='feature.notify_decouple'",
        )
        .await?;
    for sql in case.seed {
        owner.batch_execute(sql).await?;
    }
    let mut listeners = Vec::new();
    for channel in CHANNELS {
        listeners.push(db.listen(channel).await?);
    }
    // The lock holder is a second session whose transaction outlives the tick.
    let holder = db.connect().await?;
    if let Some(sql) = case.lock {
        holder.batch_execute("BEGIN").await?;
        holder.batch_execute(sql).await?;
    }
    if recording {
        GoTick {
            package: "internal/notifyjobs",
            overlay: "notify_tick_test.go.txt",
            test: "TestGoFreeNotifyDrainTick",
            file: "gofree_notify_tick_test.go",
            env: vec![("GOFREE_DRAIN_DSN".into(), db.dsn.clone())],
            docker: vec![],
        }
        .run()?;
    } else {
        let worker = NotifyIntentDrain::new(WorkerDatabase::new(&db.dsn)?);
        worker.tick().await;
    }
    let observation = observe(owner, &mut listeners).await?;
    if case.lock.is_some() {
        holder.batch_execute("ROLLBACK").await?;
    }
    if recording && case.name != "notify-drain-idle" {
        let drained = observation["notifies"]
            .as_object()
            .is_some_and(|m| m.values().any(|v| !v.as_array().unwrap().is_empty()));
        if !drained {
            return Err(format!("Go's tick changed nothing: {observation}").into());
        }
    }
    settle(case.name, observation, recording)
}

async fn observe(owner: &Client, listeners: &mut [Listener]) -> Result<Value, BoxError> {
    let mut remaining = Vec::new();
    for message in owner
        .simple_query("SELECT channel||':'||payload FROM notify_intents ORDER BY id")
        .await?
    {
        if let SimpleQueryMessage::Row(row) = message {
            remaining.push(row.get(0).unwrap_or("<null>").to_string());
        }
    }
    let mut notifies = Map::new();
    for (channel, listener) in CHANNELS.iter().zip(listeners.iter_mut()) {
        let payloads = listener.drain(owner).await?;
        notifies.insert((*channel).into(), json!(payloads));
    }
    Ok(json!({"remaining":remaining,"notifies":notifies}))
}
