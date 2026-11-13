//! #411: seed-plus-one-tick oracle for the `blob-cleanup` worker. Frozen Go's
//! real `blob.Handler` cleanup steps (recording overlay
//! `tests/conformance/drain/blob_cleanup_tick_test.go.txt`, run in the CI image
//! through `drain_oracle::GoTick`) run over a seeded database with a MinIO
//! client pointed at an owned fake S3. The Rust worker must leave the same rows
//! and make the same S3 requests. Nothing reaches a real store.
//!
//! Record: `GOFREE_RECORD_DRAIN=all|case,case` (+ `GOFREE_GO_SOURCE`); delete a
//! golden to re-record it. Replay needs no Go.
mod common;
mod drain_oracle;
#[path = "drive_workers_oracle/fake_s3.rs"]
#[allow(dead_code)]
mod fake_s3;
use drain_oracle::{settle, BoxError, GoTick};
use fake_s3::DriveS3;
use serde_json::{json, Value};
use setjoin_conformance::harness::Db;
use setjoin_gateway::{blob_cleanup::BlobCleanup, recovery_worker::S3Store};
use setjoin_pg::workers::WorkerDatabase;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, sync::Arc};
use tokio_postgres::Client;

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
const HOUR: i64 = 3600;

fn sha(label: &str) -> String {
    format!("{:x}", Sha256::digest(label.as_bytes()))
}

#[derive(Default)]
struct Case {
    name: &'static str,
    /// SQL; `{sha:label}` becomes the label's SHA-256, `{mb}` the fixture mailbox.
    seed: Vec<String>,
    /// Object keys present in the store (take `{sha:..}`).
    objects: Vec<String>,
    reject_delete: Vec<String>,
    /// `(key, refusals)`: the first N deletes of the key fail.
    flaky_delete: Vec<(String, u32)>,
    ticks: u32,
}

/// A blob row with its queue row: `ref_count`, minutes since scheduled, delay.
fn blob(label: &str, refs: i32, scheduled_ago_min: i64, delay: i32) -> Vec<String> {
    vec![
        format!("INSERT INTO blobs(sha256,minio_ref,size_bytes,ref_count) VALUES ('{{sha:{label}}}','gofree-b2/{label}',5,{refs})"),
        format!("INSERT INTO blob_cleanup_queue(blob_sha256,scheduled_at,delay_minutes) VALUES ('{{sha:{label}}}',now()-interval '{scheduled_ago_min} minutes',{delay})"),
    ]
}

fn cases() -> Vec<Case> {
    let mut queue = Case {
        name: "blob-queue",
        ..Default::default()
    };
    for (label, refs, ago, delay) in [
        ("due", 0, 60, 5),
        ("not-due", 0, 0, 60),
        ("grace-held", 0, 60, 1440),
        ("grace-over", 0, 1500, 1440),
        ("live-stale-queue", 2, 600, 5),
        ("no-object", 0, 60, 5),
    ] {
        queue.seed.extend(blob(label, refs, ago, delay));
        if label != "no-object" {
            queue.objects.push(format!("{{sha:{label}}}"));
        }
    }
    // A blob without a queue row is never a candidate.
    queue.seed.push("INSERT INTO blobs(sha256,minio_ref,size_bytes,ref_count) VALUES ('{sha:unqueued}','gofree-b2/unqueued',5,0)".into());
    queue.objects.push("{sha:unqueued}".into());
    // Several due blobs in one tick.
    for i in 0..6 {
        queue.seed.extend(blob(&format!("many-{i}"), 0, 30, 5));
        queue.objects.push(format!("{{sha:many-{i}}}"));
    }

    // Storage failures: the row is already gone, so the same tick retries the
    // removal (step 3), and a later tick retries again from the ledger.
    let mut retry = Case {
        name: "blob-retry",
        ticks: 3,
        reject_delete: vec!["{sha:stuck}".into()],
        flaky_delete: vec![
            ("{sha:flaky-once}".into(), 1),
            ("{sha:flaky-twice}".into(), 2),
        ],
        ..Default::default()
    };
    for label in ["stuck", "flaky-once", "flaky-twice", "fine"] {
        retry.seed.extend(blob(label, 0, 60, 5));
        retry.objects.push(format!("{{sha:{label}}}"));
    }

    // orphaned_message_blobs: exact keys, inline text, still-referenced keys,
    // refused deletes (stay queued, no same-tick retry) and a later tick.
    let mut orphans = Case {
        name: "blob-orphans",
        ticks: 2,
        reject_delete: vec!["inbound/{sha:refused}".into()],
        flaky_delete: vec![("{sha:flaky}".into(), 1)],
        ..Default::default()
    };
    for key in [
        "inbound/{sha:in}",
        "blobs/{sha:out}",
        "{sha:bare}",
        "dmarc/{sha:report}.eml",
        "system:welcome:42",
        "dsn/7/8",
        "weird key+plus/é",
        "inbound/{sha:refused}",
        "{sha:flaky}",
        "inbound/{sha:referenced}",
        "inbound/{sha:no-object}",
    ] {
        orphans.seed.push(format!(
            "INSERT INTO orphaned_message_blobs(raw_ref) VALUES ($k${key}$k$)"
        ));
        if !key.contains("no-object") {
            orphans.objects.push(key.to_owned());
        }
    }
    orphans.seed.push("INSERT INTO orphaned_message_blobs(raw_ref) VALUES (E'Message-ID: <inline@x.test>\\r\\nSubject: draft\\r\\n\\r\\nbody')".into());
    orphans
        .seed
        .push("INSERT INTO orphaned_message_blobs(raw_ref) VALUES (E'single\\nbreak')".into());
    orphans.seed.push("INSERT INTO messages(mailbox_id,folder_id,message_id,from_addr,thread_id,raw_ref,size_bytes) VALUES ({mb},1,'gofree-blobs2-ref','a@x.test','t','inbound/{sha:referenced}',1)".into());

    // Both queues in one tick, in Go's order, and a blob that is also an
    // orphaned raw_ref.
    let mut both = Case {
        name: "blob-both-queues",
        ..Default::default()
    };
    both.seed.extend(blob("shared", 0, 60, 5));
    both.objects.push("{sha:shared}".into());
    both.seed
        .push("INSERT INTO orphaned_message_blobs(raw_ref) VALUES ('{sha:shared}')".into());
    both.seed.extend(blob("alone", 0, 60, 5));
    both.objects.push("{sha:alone}".into());
    both.seed
        .push("INSERT INTO orphaned_message_blobs(raw_ref) VALUES ('inbound/{sha:raw}')".into());
    both.objects.push("inbound/{sha:raw}".into());

    // An idle tick: nothing queued, nothing requested.
    let idle = Case {
        name: "blob-idle",
        ..Default::default()
    };
    vec![queue, retry, orphans, both, idle]
}

struct Fixture {
    user: i64,
    domain: i64,
    mailbox: i64,
}

fn render(fixture: &Fixture, text: &str, labels: &mut BTreeMap<String, String>) -> String {
    let mut out = text.replace("{mb}", &fixture.mailbox.to_string());
    while let Some(start) = out.find("{sha:") {
        let end = start + out[start..].find('}').expect("sha placeholder");
        let label = out[start + 5..end].to_owned();
        let hash = sha(&label);
        labels.insert(hash.clone(), format!("<{label}>"));
        out.replace_range(start..=end, &hash);
    }
    out
}

fn db_text(e: tokio_postgres::Error) -> String {
    e.as_db_error()
        .map(|d| d.to_string())
        .unwrap_or_else(|| e.to_string())
}

/// The tick acts on every due zero-ref blob and every orphaned ref, so each
/// case starts (and ends) with those tables clear of anything foreign.
const CLEAN: &str = "DELETE FROM blob_cleanup_queue; DELETE FROM orphaned_message_blobs;
    DELETE FROM messages WHERE message_id LIKE 'gofree-blobs2-%';
    DELETE FROM blobs WHERE ref_count=0 OR minio_ref LIKE 'gofree-b2/%';";

async fn fixture(owner: &Client) -> Result<Fixture, BoxError> {
    owner.batch_execute(CLEAN).await.map_err(db_text)?;
    owner.batch_execute("DELETE FROM mailboxes WHERE email='gofree-blobs2-a@gofree-blobs2.test'; DELETE FROM users WHERE username='gofree-blobs2-a'; DELETE FROM domains WHERE name='gofree-blobs2.test'").await?;
    let domain: i64 = owner
        .query_one(
            "INSERT INTO domains(name) VALUES ('gofree-blobs2.test') RETURNING id",
            &[],
        )
        .await?
        .get(0);
    let user: i64 = owner.query_one("INSERT INTO users(username,domain_id,email,display_name) VALUES ('gofree-blobs2-a',$1,'gofree-blobs2-a@gofree-blobs2.test','A') RETURNING id", &[&domain]).await?.get(0);
    let mailbox: i64 = owner.query_one("INSERT INTO mailboxes(user_id,domain_id,email,display_name,is_primary) VALUES ($1,$2,'gofree-blobs2-a@gofree-blobs2.test','A',true) RETURNING id", &[&user, &domain]).await?.get(0);
    Ok(Fixture {
        user,
        domain,
        mailbox,
    })
}

async fn reset(owner: &Client) -> Result<(), BoxError> {
    owner.batch_execute(CLEAN).await.map_err(db_text)?;
    Ok(())
}

async fn teardown(owner: &Client, fixture: &Fixture) {
    let _ = reset(owner).await;
    let _ = owner
        .batch_execute(&format!(
            "DELETE FROM mailboxes WHERE id={}; DELETE FROM users WHERE id={}; DELETE FROM domains WHERE id={}",
            fixture.mailbox, fixture.user, fixture.domain
        ))
        .await;
}

async fn column(owner: &Client, sql: &str) -> Result<Vec<String>, BoxError> {
    Ok(owner
        .query(sql, &[])
        .await?
        .iter()
        .map(|r| r.get::<_, String>(0))
        .collect())
}

const OBSERVE: &[(&str, &str)] = &[
    ("blobs", "SELECT sha256||'|rc='||ref_count||'|'||minio_ref FROM blobs WHERE minio_ref LIKE 'gofree-b2/%' ORDER BY 1"),
    ("queue", "SELECT blob_sha256||'|delay='||delay_minutes FROM blob_cleanup_queue ORDER BY 1"),
    ("orphans", "SELECT raw_ref FROM orphaned_message_blobs ORDER BY 1"),
];

/// Label every known digest and order requests as a multiset.
fn normalize(value: Value, labels: &BTreeMap<String, String>) -> Value {
    let mut text = value.to_string();
    for (hash, label) in labels {
        text = text.replace(hash, label);
    }
    let mut value: Value = serde_json::from_str(&text).unwrap();
    if let Some(requests) = value["s3"]["requests"].as_array_mut() {
        requests.sort_by_key(|r| r.to_string());
    }
    value
}

async fn run_case(
    db: &Db,
    owner: &Client,
    fixture: &Fixture,
    s3: &DriveS3,
    case: &Case,
    recording: bool,
) -> Result<(), BoxError> {
    reset(owner).await?;
    s3.reset();
    let mut labels = BTreeMap::new();
    for sql in &case.seed {
        let sql = render(fixture, sql, &mut labels);
        owner
            .batch_execute(&sql)
            .await
            .map_err(|e| format!("seed `{sql}`: {}", db_text(e)))?;
    }
    for key in &case.objects {
        s3.put(&render(fixture, key, &mut labels), b"x", HOUR);
    }
    for key in &case.reject_delete {
        s3.reject_delete(&render(fixture, key, &mut labels));
    }
    for (key, times) in &case.flaky_delete {
        s3.flaky_delete(&render(fixture, key, &mut labels), *times);
    }
    let ticks = case.ticks.max(1);
    if recording {
        GoTick {
            package: "internal/blob",
            overlay: "blob_cleanup_tick_test.go.txt",
            test: "TestGoFreeBlobCleanupTick",
            file: "gofree_blob_cleanup_tick_test.go",
            env: vec![
                ("GOFREE_DRAIN_DSN".into(), db.dsn.clone()),
                (
                    "GOFREE_DRAIN_S3".into(),
                    format!("127.0.0.1:{}", s3.addr.port()),
                ),
                ("GOFREE_BLOB_TICKS".into(), ticks.to_string()),
            ],
            docker: vec![],
        }
        .run()?;
    } else {
        let store = Arc::new(S3Store::new(
            &format!("http://127.0.0.1:{}", s3.addr.port()),
            "mailblobs",
            "test-access",
            "test-secret",
        )?);
        let worker = BlobCleanup::new(WorkerDatabase::new(&db.dsn)?, store);
        for _ in 0..ticks {
            worker.tick().await;
        }
    }
    let mut observation = serde_json::Map::new();
    for (label, sql) in OBSERVE {
        observation.insert((*label).into(), json!(column(owner, sql).await?));
    }
    observation.insert(
        "s3".into(),
        json!({"requests": s3.take_log(), "keys": s3.keys()}),
    );
    settle(
        case.name,
        normalize(Value::Object(observation), &labels),
        recording,
    )
}

// Multi-threaded: the blocking Go container run must not stall the fake S3.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn blob_cleanup_seed_plus_one_tick() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("blob-cleanup-tick") else {
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
    let all = cases();
    let selected: Vec<&Case> = all
        .iter()
        .filter(|c| {
            let recording = record.is_some() && listed(&record, c.name);
            !(record.is_some() && !recording || !listed(&only, c.name))
        })
        .collect();
    if selected.is_empty() {
        return Ok(());
    }
    let s3 = DriveS3::start().await;
    let fixture = fixture(&owner).await?;
    let mut failures = Vec::new();
    for case in selected {
        let recording = record.is_some() && listed(&record, case.name);
        if let Err(error) = run_case(&db, &owner, &fixture, &s3, case, recording).await {
            failures.push(format!("{}: {error}", case.name));
        }
        let _ = reset(&owner).await;
    }
    teardown(&owner, &fixture).await;
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    Ok(())
}
