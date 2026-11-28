//! #328: seed-plus-one-tick oracle for the `smime-trust-listener` config listener. Frozen Go's
//! real wiring (overlay `smime_trust_tick_test.go.txt` in `tests/conformance/drain/`:
//! `db.NewListener` + `Subscribe` calling `InvalidateSMIMETrustCache`, and the real
//! `smimeRootsForDomain` pool builder) is run over a seeded `smime_trust_anchors`: the pools
//! of several recipient domains are observed (which probe certificates each trusts), the table
//! is changed, the pools are observed again (still the cached ones), one
//! `pg_notify('smime_trust_changed')` arrives and the pools are observed a third time. The
//! Rust `TrustCache` + `SmimeTrustListener` must produce the same three observations.
//!
//! Record: `GOFREE_RECORD_DRAIN=all|case,case` (+ `GOFREE_GO_SOURCE`); replay needs no Go.
mod common;
mod drain_oracle;

use drain_oracle::{settle, BoxError, GoTick};
use serde_json::{json, Value};
use setjoin_conformance::harness::Db;
use setjoin_gateway::smime_trust::SmimeTrustListener;
use setjoin_mail_security::smime::{parse_chain, trust::TrustCache};
use setjoin_pg::ScopedExecutor;
use std::sync::Arc;

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
const A: &str = include_str!("../../../tests/conformance/mail-security/smime-certs/a.pem");
const B: &str = include_str!("../../../tests/conformance/mail-security/smime-certs/b.pem");
const C: &str = include_str!("../../../tests/conformance/mail-security/smime-certs/c.pem");
const D: &str = include_str!("../../../tests/conformance/mail-security/smime-certs/d.pem");
const NOCN: &str = include_str!("../../../tests/conformance/mail-security/smime-certs/nocn.pem");
const X: i64 = 910_001;
const Y: i64 = 910_002;
const Z: i64 = 910_003;

fn fp(pem: &str) -> String {
    parse_chain(pem.as_bytes()).unwrap().remove(0).fingerprint
}

#[derive(Clone)]
struct Row {
    pem: String,
    fingerprint: String,
    domain: Option<i64>,
}
fn row(pem: &str, fingerprint: &str, domain: Option<i64>) -> Row {
    Row {
        pem: pem.into(),
        fingerprint: fingerprint.into(),
        domain,
    }
}

struct Case {
    name: &'static str,
    seed: Vec<Row>,
    delete: Vec<String>,
    insert: Vec<Row>,
    break_table: bool,
}

fn cases() -> Vec<Case> {
    // a (domain X), d (deployment-wide), a bundle b+c authorized only for b (domain Y),
    // an empty fingerprint, an unparseable PEM, and a certificate stored under another
    // certificate's fingerprint (domain X, so it never grants trust once a's own row is gone).
    let seed = vec![
        row(A, &fp(A), Some(X)),
        row(D, &fp(D), None),
        row(&format!("{B}{C}"), &fp(B), Some(Y)),
        row(NOCN, "", None),
        row("garbage", "zz", None),
        row(A, &fp(D), Some(X)),
    ];
    vec![
        Case {
            name: "smime-trust-seed-plus-tick",
            seed: seed.clone(),
            delete: vec![fp(A)],
            insert: vec![row(C, &fp(C), None), row(A, &fp(A), Some(Z))],
            break_table: false,
        },
        Case {
            name: "smime-trust-notify-without-change",
            seed: seed.clone(),
            delete: vec![],
            insert: vec![],
            break_table: false,
        },
        Case {
            name: "smime-trust-empty-table",
            seed: vec![],
            delete: vec![],
            insert: vec![row(B, &fp(B), None)],
            break_table: false,
        },
        Case {
            name: "smime-trust-table-missing",
            seed,
            delete: vec![],
            insert: vec![],
            break_table: true,
        },
    ]
}

fn scenario(case: &Case) -> Value {
    let rows = |rows: &[Row]| -> Vec<Value> {
        rows.iter()
            .map(|r| json!({"pem": r.pem, "fingerprint": r.fingerprint, "domain": r.domain}))
            .collect()
    };
    json!({
        "domains": [X, Y, Z, 0],
        "seed": rows(&case.seed),
        "probes": [A, B, C, D, NOCN],
        "delete_fingerprints": case.delete,
        "insert": rows(&case.insert),
        "break_table": case.break_table,
    })
}

async fn insert(owner: &tokio_postgres::Client, r: &Row) -> Result<(), BoxError> {
    owner
        .execute(
            "INSERT INTO smime_trust_anchors (label, cert_pem, fingerprint, domain_id) VALUES ('oracle', $1, $2, $3)",
            &[&r.pem, &r.fingerprint, &r.domain],
        )
        .await?;
    Ok(())
}

async fn observe(cache: &TrustCache, worker: &ScopedExecutor) -> Value {
    let probes: Vec<String> = [A, B, C, D, NOCN].iter().map(|p| fp(p)).collect();
    let mut out = serde_json::Map::new();
    for domain in [X, Y, Z, 0] {
        let pool = cache.pool_for(worker, domain).await;
        let mut row = serde_json::Map::new();
        for (i, f) in probes.iter().enumerate() {
            row.insert(
                ((b'a' + i as u8) as char).to_string(),
                json!(pool.trusts(f)),
            );
        }
        out.insert(domain.to_string(), Value::Object(row));
    }
    Value::Object(out)
}

#[tokio::test(flavor = "multi_thread")]
async fn smime_trust_seed_plus_one_tick() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("smime-trust-tick") else {
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
    let stash: Vec<String> = owner
        .query("SELECT to_jsonb(s)::text FROM smime_trust_anchors s", &[])
        .await?
        .iter()
        .map(|r| r.get(0))
        .collect();
    let mut failures = Vec::new();
    let mut ran = 0;
    for case in cases() {
        let label = case.name;
        let recording = record.is_some() && listed(&record, label);
        if record.is_some() && !recording || !listed(&only, label) {
            continue;
        }
        ran += 1;
        let result = run_case(&db, &owner, &case, recording, false).await;
        let _ = owner
            .batch_execute("ALTER TABLE IF EXISTS smime_trust_anchors_gofree_hidden RENAME TO smime_trust_anchors")
            .await;
        if let Err(error) = result {
            failures.push(format!("{label}: {error}"));
        }
    }
    owner
        .batch_execute(
            "BEGIN; SET LOCAL session_replication_role=replica; DELETE FROM smime_trust_anchors;",
        )
        .await?;
    for row in &stash {
        owner
            .execute("INSERT INTO smime_trust_anchors SELECT * FROM jsonb_populate_record(NULL::smime_trust_anchors, $1::text::jsonb)", &[row])
            .await?;
    }
    owner.batch_execute("COMMIT;").await?;
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    assert!(ran > 0, "no case selected");
    Ok(())
}

async fn run_case(
    db: &Db,
    owner: &tokio_postgres::Client,
    case: &Case,
    recording: bool,
    mutant: bool,
) -> Result<(), BoxError> {
    owner
        .batch_execute("DELETE FROM smime_trust_anchors")
        .await?;
    let observation = if recording {
        for r in &case.seed {
            insert(owner, r).await?;
        }
        let root = drain_oracle::repo_root()?;
        let folder = root.join("test-results/gofree-drainw");
        std::fs::create_dir_all(&folder)?;
        let file = folder.join(format!("{}.scenario.json", case.name));
        let out = folder.join(format!("{}.out.json", case.name));
        let _ = std::fs::remove_file(&out);
        std::fs::write(&file, serde_json::to_vec(&scenario(case))?)?;
        let inside = |p: &std::path::Path| {
            format!(
                "/src/test-results/gofree-drainw/{}",
                p.file_name().unwrap().to_string_lossy()
            )
        };
        GoTick {
            package: "internal/smtp",
            overlay: "smime_trust_tick_test.go.txt",
            test: "TestGoFreeSMIMETrustTick",
            file: "gofree_smime_trust_tick_test.go",
            env: vec![
                ("GOFREE_DRAIN_DSN".into(), db.dsn.clone()),
                ("GOFREE_SMIME_DIRECT_DSN".into(), db.dsn.clone()),
                ("GOFREE_SMIME_SCENARIO".into(), inside(&file)),
                ("GOFREE_SMIME_OUT".into(), inside(&out)),
            ],
            docker: vec![],
        }
        .run()?;
        serde_json::from_slice::<Value>(&std::fs::read(&out)?)?
    } else {
        for r in &case.seed {
            insert(owner, r).await?;
        }
        let worker = ScopedExecutor::from_dsn(&db.dsn, 4).map_err(|e| e.0)?;
        let cache = Arc::new(TrustCache::new());
        let listener = Arc::new(SmimeTrustListener::new(cache.clone(), db.dsn.clone()));
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(listener.clone().run_until(async move {
            let _ = stopped.await;
        }));
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while !listener.listening() {
            if std::time::Instant::now() > deadline {
                return Err("the listener never connected".into());
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        let seeded = observe(&cache, &worker).await;
        for f in &case.delete {
            owner
                .execute(
                    "DELETE FROM smime_trust_anchors WHERE fingerprint = $1",
                    &[f],
                )
                .await?;
        }
        for r in &case.insert {
            insert(owner, r).await?;
        }
        if case.break_table {
            owner
                .batch_execute(
                    "ALTER TABLE smime_trust_anchors RENAME TO smime_trust_anchors_gofree_hidden",
                )
                .await?;
        }
        let cached = observe(&cache, &worker).await;
        if !mutant {
            owner
                .batch_execute("SELECT pg_notify('smime_trust_changed', '1')")
                .await?;
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while !mutant && cache.cached_domains() != 0 {
            if std::time::Instant::now() > deadline {
                return Err("cache not invalidated by the notification".into());
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        let after = observe(&cache, &worker).await;
        let _ = stop.send(());
        task.await?;
        json!({"seeded": seeded, "cached": cached, "after_tick": after})
    };
    if mutant {
        // The planted fault never delivers the notification: the stale cache must fail the golden.
        let error = settle(case.name, observation, false)
            .err()
            .ok_or("planted missing-notification mutant survived")?;
        if !error.to_string().contains("after_tick") {
            return Err(format!("mutant failed outside the after-tick pools: {error}").into());
        }
        println!("MUTANT-REJECTED: smime-trust-listener :: no-invalidate");
        return Ok(());
    }
    settle(case.name, observation, recording)
}

/// Planted mutant: a listener that never invalidates leaves the pre-change pools in place.
#[tokio::test(flavor = "multi_thread")]
async fn smime_trust_mutant_missing_invalidation_is_rejected() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("smime-trust-mutant") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let stash: Vec<String> = owner
        .query("SELECT to_jsonb(s)::text FROM smime_trust_anchors s", &[])
        .await?
        .iter()
        .map(|r| r.get(0))
        .collect();
    let case = cases().remove(0);
    let result = run_case(&db, &owner, &case, false, true).await;
    owner
        .batch_execute(
            "BEGIN; SET LOCAL session_replication_role=replica; DELETE FROM smime_trust_anchors;",
        )
        .await?;
    for row in &stash {
        owner
            .execute("INSERT INTO smime_trust_anchors SELECT * FROM jsonb_populate_record(NULL::smime_trust_anchors, $1::text::jsonb)", &[row])
            .await?;
    }
    owner.batch_execute("COMMIT;").await?;
    result
}
