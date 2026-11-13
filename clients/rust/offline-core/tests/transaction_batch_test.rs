//! E4-I native transaction batch + bundled migration entries — the store-level
//! positive/negative oracles the freeze requires
//! (retired-docs:verification/2026-09-08-connectivity-native-transaction-freeze.md):
//! paired refusals and success, atomicity on both sides of commit, and reopen
//! assertions. The bridge shapes (`db.transactionBatch`/`db.migrateStore`)
//! transport these exact payloads as JSON strings.

use guard_core::GuardCore;
use offline_core::OfflineCore;
use std::sync::Arc;

const BUDGET: &str = r#"{"maxStatements":64,"maxParamBytes":1048576}"#;

fn core(dir: &tempfile::TempDir, pass: &str) -> Arc<OfflineCore> {
    let vault = dir.path().join("guard.db").to_string_lossy().to_string();
    let guard = GuardCore::new(vault, pass.to_string()).expect("vault open");
    OfflineCore::new(guard)
}

fn opened_core(dir: &tempfile::TempDir) -> Arc<OfflineCore> {
    let c = core(dir, "correct horse");
    let path = dir.path().join("mail.db").to_string_lossy().to_string();
    c.open_store("mail".into(), path, "standard".into())
        .expect("open mail store");
    c
}

fn seed_table(c: &OfflineCore) {
    // Ordinary exec runs SINGLE allowlisted statements — DDL for the fixture.
    c.exec(
        "mail".into(),
        "CREATE TABLE ledger (id INTEGER PRIMARY KEY, amount INTEGER NOT NULL)".into(),
        "[]".into(),
    )
    .expect("seed table");
}

fn ledger_count(c: &OfflineCore) -> i64 {
    let rows = c
        .query("mail".into(), "SELECT count(*) AS n FROM ledger".into(), "[]".into())
        .expect("count query");
    rows.parse::<serde_json::Value>().expect("rows json")[0]["n"]
        .as_i64()
        .expect("n")
}

// ── happy path ────────────────────────────────────────────────────────────────

#[test]
fn batch_commits_atomically_and_counts_changed_rows() {
    let dir = tempfile::tempdir().unwrap();
    let c = opened_core(&dir);
    seed_table(&c);
    let statements = r#"[
        {"sql": "INSERT INTO ledger (amount) VALUES (?1)", "params": [10]},
        {"sql": "INSERT INTO ledger (amount) VALUES (?1)", "params": [20]},
        {"sql": "UPDATE ledger SET amount = amount + 1 WHERE id = 1"}
    ]"#;
    let changed = c
        .transaction_batch("mail".into(), statements.into(), BUDGET.into())
        .expect("batch commits");
    assert_eq!(changed, 3, "two inserts + one update");
    assert_eq!(ledger_count(&c), 2);
    // Reads are admitted per the freeze's read/DML contract; they contribute
    // no changed rows.
    let changed = c
        .transaction_batch(
            "mail".into(),
            r#"[{"sql": "SELECT amount FROM ledger WHERE amount >= ?1", "params": [0]}]"#.into(),
            BUDGET.into(),
        )
        .expect("read batch commits");
    assert_eq!(changed, 0);
}

#[test]
fn batch_runs_through_the_migrated_mail_schema() {
    let dir = tempfile::tempdir().unwrap();
    let c = opened_core(&dir);
    let version = c.migrate_store("mail".into(), 2).expect("migrate to v2");
    assert_eq!(version, 2);
    let changed = c
        .transaction_batch(
            "mail".into(),
            r#"[
                {"sql": "INSERT INTO messages (id, thread_id, received_at) VALUES (?1, ?2, ?3)",
                 "params": ["m1", "t1", 100]},
                {"sql": "INSERT INTO message_tags (message_id, tag_id, received_at) VALUES (?1, ?2, ?3)",
                 "params": ["m1", "inbox", 100]}
            ]"#.into(),
            BUDGET.into(),
        )
        .expect("job batch over the mail schema");
    assert_eq!(changed, 2);
    let rows = c
        .query(
            "mail".into(),
            "SELECT id FROM messages WHERE id = ?1".into(),
            r#"["m1"]"#.into(),
        )
        .expect("query");
    assert!(rows.contains("m1"));
}

// ── refused shapes (no effects, refusal before mutation) ──────────────────────

#[test]
fn batch_refuses_every_forbidden_shape_before_any_statement_runs() {
    let dir = tempfile::tempdir().unwrap();
    let c = opened_core(&dir);
    seed_table(&c);
    let refusals: Vec<(&str, String)> = vec![
        ("empty-batch", "[]".into()),
        (
            "too-many-statements",
            r#"[{"sql": "INSERT INTO ledger (amount) VALUES (1)"},{"sql": "INSERT INTO ledger (amount) VALUES (2)"}]"#.into(),
        ),
        (
            "budget-exceeded",
            r#"[{"sql": "INSERT INTO ledger (amount) VALUES (?1)", "params": ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]}]"#.into(),
        ),
        ("transaction-control", r#"[{"sql": "BEGIN"}]"#.into()),
        ("transaction-control", r#"[{"sql": "COMMIT"}]"#.into()),
        ("transaction-control", r#"[{"sql": "ROLLBACK"}]"#.into()),
        ("transaction-control", r#"[{"sql": "SAVEPOINT sp1"}]"#.into()),
        ("transaction-control", r#"[{"sql": "RELEASE sp1"}]"#.into()),
        ("ddl", r#"[{"sql": "CREATE TABLE stolen (x)}]"#.into()),
        ("ddl", r#"[{"sql": "DROP TABLE ledger"}]"#.into()),
        ("ddl", r#"[{"sql": "ALTER TABLE ledger ADD COLUMN x"}]"#.into()),
        ("pragma", r#"[{"sql": "PRAGMA key = 'x'"}]"#.into()),
        ("attach", r#"[{"sql": "ATTACH DATABASE '/tmp/evil.db' AS evil"}]"#.into()),
        (
            "multi-statement",
            r#"[{"sql": "INSERT INTO ledger (amount) VALUES (1); INSERT INTO ledger (amount) VALUES (2)"}]"#.into(),
        ),
        (
            "bad-params",
            r#"[{"sql": "INSERT INTO ledger (amount) VALUES (?1)", "params": {"not": "array"}}]"#.into(),
        ),
        ("bad-budget", r#"[{"sql": "INSERT INTO ledger (amount) VALUES (1)"}]"#.into()),
    ];
    for (case, statements) in &refusals {
        let budget = if *case == "bad-budget" {
            r#"{"maxStatements":0,"maxParamBytes":0}"#
        } else if *case == "too-many-statements" {
            r#"{"maxStatements":1,"maxParamBytes":1048576}"#
        } else if *case == "budget-exceeded" {
            r#"{"maxStatements":64,"maxParamBytes":16}"#
        } else {
            BUDGET
        };
        let res = c.transaction_batch("mail".into(), statements.clone(), budget.into());
        assert!(res.is_err(), "{case} must be refused");
    }
    // Refusal precedes mutation: the ledger holds exactly the seed state and
    // no smuggled object ever materialized.
    assert_eq!(ledger_count(&c), 0);
    let rows = c
        .query(
            "mail".into(),
            "SELECT count(*) AS n FROM sqlite_master WHERE type = 'table' AND name = 'stolen'".into(),
            "[]".into(),
        )
        .expect("sqlite_master query");
    assert_eq!(rows.parse::<serde_json::Value>().unwrap()[0]["n"], 0, "no DDL ran");
}

#[test]
fn batch_refuses_an_unopened_store_and_foreign_shapes_fail_closed() {
    let dir = tempfile::tempdir().unwrap();
    let c = core(&dir, "p");
    let res = c.transaction_batch(
        "mail".into(),
        r#"[{"sql": "SELECT 1"}]"#.into(),
        BUDGET.into(),
    );
    assert!(res.is_err(), "un-opened store must refuse");
    let res = c.transaction_batch(
        "mail".into(),
        "not json at all".into(),
        BUDGET.into(),
    );
    assert!(res.is_err(), "malformed statements JSON must refuse");
    let res = c.transaction_batch(
        "mail".into(),
        r#"[{"sql": "SELECT 1"}]"#.into(),
        "not json".into(),
    );
    assert!(res.is_err(), "malformed budget JSON must refuse");
}

// ── atomicity: one bad statement rolls back the WHOLE batch ──────────────────

#[test]
fn one_bad_statement_rolls_back_the_entire_batch() {
    let dir = tempfile::tempdir().unwrap();
    let c = opened_core(&dir);
    seed_table(&c);
    // Statement 2 references a missing column: the SQL-level failure must undo
    // statement 1 and never run statement 3.
    let statements = r#"[
        {"sql": "INSERT INTO ledger (amount) VALUES (?1)", "params": [111]},
        {"sql": "UPDATE ledger SET nonexistent_column = 1 WHERE id = 1"},
        {"sql": "INSERT INTO ledger (amount) VALUES (?1)", "params": [333]}
    ]"#;
    let err = c
        .transaction_batch("mail".into(), statements.into(), BUDGET.into())
        .expect_err("mid-batch failure");
    assert!(
        err.to_string().to_lowercase().contains("no such column"),
        "the SQL failure itself must surface: {err}"
    );
    assert_eq!(ledger_count(&c), 0, "statement 1 was rolled back");
    // The connection is reusable afterwards: a valid batch still commits.
    let changed = c
        .transaction_batch(
            "mail".into(),
            r#"[{"sql": "INSERT INTO ledger (amount) VALUES (?1)", "params": [7]}]"#.into(),
            BUDGET.into(),
        )
        .expect("post-rollback batch commits");
    assert_eq!(changed, 1);
}

// E6 Astra P3: COMMIT is a statement-failure class too — the commit-failure
// path used to propagate WITHOUT a rollback attempt, leaving the transaction
// open on the shared connection (every later batch then failed with
// "cannot start a transaction within a transaction"; only a store reopen
// recovered). Injection mirrors the statement-failure pattern: a DEFERRABLE
// INITIALLY DEFERRED foreign key only fires at COMMIT, so every statement
// succeeds and the COMMIT itself fails (the opened store runs with
// PRAGMA foreign_keys=ON).
#[test]
fn a_failing_commit_rolls_back_and_leaves_the_store_usable() {
    let dir = tempfile::tempdir().unwrap();
    let c = opened_core(&dir);
    c.exec(
        "mail".into(),
        "CREATE TABLE parent (id INTEGER PRIMARY KEY)".into(),
        "[]".into(),
    )
    .expect("parent table");
    c.exec(
        "mail".into(),
        "CREATE TABLE child (id INTEGER PRIMARY KEY, pid INTEGER NOT NULL \
         REFERENCES parent(id) DEFERRABLE INITIALLY DEFERRED)"
            .into(),
        "[]".into(),
    )
    .expect("child table");
    let parent_count = || {
        c.query("mail".into(), "SELECT count(*) AS n FROM parent".into(), "[]".into())
            .expect("parent count")
            .parse::<serde_json::Value>()
            .expect("rows json")[0]["n"]
            .as_i64()
            .expect("n")
    };
    let child_count = || {
        c.query("mail".into(), "SELECT count(*) AS n FROM child".into(), "[]".into())
            .expect("child count")
            .parse::<serde_json::Value>()
            .expect("rows json")[0]["n"]
            .as_i64()
            .expect("n")
    };

    // Statement 2 violates the deferred FK; the violation only surfaces when
    // the batch COMMITs.
    let statements = r#"[
        {"sql": "INSERT INTO parent (id) VALUES (1)"},
        {"sql": "INSERT INTO child (id, pid) VALUES (10, 99)"}
    ]"#;
    let err = c
        .transaction_batch("mail".into(), statements.into(), BUDGET.into())
        .expect_err("commit-time foreign key failure");
    assert!(
        err.to_string().to_lowercase().contains("foreign key"),
        "the COMMIT failure itself must surface: {err}"
    );
    assert_eq!(parent_count(), 0, "the batch rolled back: no parent row");
    assert_eq!(child_count(), 0, "the batch rolled back: no child row");
    // The connection is reusable afterwards — an open transaction left behind
    // by the failed COMMIT would make this next batch fail outright.
    let changed = c
        .transaction_batch(
            "mail".into(),
            r#"[{"sql": "INSERT INTO parent (id) VALUES (?1)", "params": [2]}]"#.into(),
            BUDGET.into(),
        )
        .expect("post-commit-failure batch commits");
    assert_eq!(changed, 1);
    assert_eq!(parent_count(), 1);
}

#[test]
fn batch_failure_between_versions_leaves_committed_steps_intact() {
    // Crash/rollback on one side of a step boundary: committed versions
    // persist, interrupted steps roll back and retry.
    let dir = tempfile::tempdir().unwrap();
    let c = opened_core(&dir);
    let v1_sql = offline_core::migrations::MAIL_MANIFEST_STEPS[0]
        .statements
        .iter()
        .map(|s| format!("{s};"))
        .collect::<String>();
    c.exec_schema_init("mail".into(), v1_sql).expect("v1 via init seam");
    // A job batch that fails mid-way leaves the v1 schema state untouched.
    let err = c
        .transaction_batch(
            "mail".into(),
            r#"[
                {"sql": "INSERT INTO meta_mail (key, value) VALUES (?1, ?2)", "params": ["k", "v"]},
                {"sql": "INSERT INTO missing_table (x) VALUES (1)"}
            ]"#
            .into(),
            BUDGET.into(),
        )
        .expect_err("second statement fails");
    assert!(err.to_string().contains("missing_table") || err.to_string().to_lowercase().contains("no such table"), "{err}");
    let rows = c
        .query(
            "mail".into(),
            "SELECT count(*) AS n FROM meta_mail WHERE key = 'k'".into(),
            "[]".into(),
        )
        .expect("query");
    assert_eq!(rows.parse::<serde_json::Value>().unwrap()[0]["n"], 0, "first insert rolled back");
    // Migration still completes over the intact v1 state.
    let version = c.migrate_store("mail".into(), 2).expect("migrate");
    assert_eq!(version, 2);
}

// ── migrate_store: bundled manifest, refusals, reopen persistence ────────────

#[test]
fn migrate_store_refuses_foreign_apps_and_bad_versions() {
    let dir = tempfile::tempdir().unwrap();
    let c = opened_core(&dir);
    // The 'drive' store is open too, so its refusal is the foreign-app
    // manifest check, not merely "store not open".
    let drive_path = dir.path().join("drive.db").to_string_lossy().to_string();
    c.open_store("drive".into(), drive_path, "standard".into())
        .expect("open drive store");
    for (app, target) in [("drive", 2), ("evil", 2), ("mail", 0), ("mail", 3), ("mail", -1)] {
        let res = c.migrate_store(app.into(), target);
        assert!(res.is_err(), "migrate {app}@{target} must refuse");
    }
    // Nothing was created for the refused targets.
    let rows = c
        .query(
            "mail".into(),
            "SELECT count(*) AS n FROM sqlite_master WHERE type = 'table' AND name = 'optional_jobs'"
                .into(),
            "[]".into(),
        )
        .expect("query");
    assert_eq!(rows.parse::<serde_json::Value>().unwrap()[0]["n"], 0);
}

#[test]
fn migrate_store_reopens_at_version_and_survives_a_new_engine() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mail.db").to_string_lossy().to_string();
    {
        let c = core(&dir, "reopen pass");
        c.open_store("mail".into(), path.clone(), "standard".into())
            .expect("open");
        assert_eq!(c.migrate_store("mail".into(), 2).expect("migrate"), 2);
        c.transaction_batch(
            "mail".into(),
            r#"[{"sql": "INSERT INTO optional_jobs (job_id, account_id, work_class, deadline_utc, coalescing_key) VALUES (?1, ?2, ?3, ?4, ?5)",
                 "params": ["j1", "acc", "delta", "2026-01-01T00:00:00Z", "ck-1"]}]"#
                .into(),
            BUDGET.into(),
        )
        .expect("batch over optional_jobs");
    }
    // A fresh engine (same vault passphrase → same per-appKey SQLCipher key)
    // reopens the store: the schema generation and the committed job row persist.
    let c2 = core(&dir, "reopen pass");
    c2.open_store("mail".into(), path, "standard".into()).expect("reopen");
    assert_eq!(c2.migrate_store("mail".into(), 2).expect("re-migrate is a no-op"), 2);
    let rows = c2
        .query(
            "mail".into(),
            "SELECT job_id FROM optional_jobs WHERE job_id = ?1".into(),
            r#"["j1"]"#.into(),
        )
        .expect("query");
    assert!(rows.contains("j1"), "durable job row survives reopen");
}

#[test]
fn migrate_store_recovers_an_interrupted_v2_and_legacy_dev_stores() {
    let dir = tempfile::tempdir().unwrap();
    let c = opened_core(&dir);
    // Legacy dev store: v1-era DDL WITHOUT the eligibility column, applied via
    // the ordinary authorized init seam (the historical path) — one batch,
    // because the seam is one-shot per connection. The legacy recovery table
    // is derived from the v1 manifest statement minus the eligibility line
    // (the historical U6 shape).
    let v1_recovery = offline_core::migrations::MAIL_MANIFEST_STEPS[0]
        .statements
        .iter()
        .find(|s| s.contains("CREATE TABLE IF NOT EXISTS recovery_artifacts"))
        .expect("v1 recovery DDL");
    let legacy_ddl: String = v1_recovery
        .lines()
        .filter(|line| !line.contains("eligibility"))
        .collect::<Vec<_>>()
        .join("\n");
    // One optional table only: an interrupted v2 (the table itself carries the
    // full manifest DDL — the legacy non-atomic batch aborted between
    // statements — so the v2 indexes over its columns still apply).
    let legacy = format!(
        "{legacy_ddl}; {};",
        offline_core::migrations::MAIL_MANIFEST_STEPS[1].statements[0]
    );
    c.exec_schema_init("mail".into(), legacy).expect("legacy init");
    let version = c.migrate_store("mail".into(), 2).expect("recovery migrate");
    assert_eq!(version, 2);
    // The eligibility column landed through the legacy replay (read from the
    // live DDL — the same source detection uses).
    let rows = c
        .query(
            "mail".into(),
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'recovery_artifacts'"
                .into(),
            "[]".into(),
        )
        .expect("query");
    assert!(
        rows.contains("eligibility"),
        "replay added the eligibility column: {rows}"
    );
    // The interrupted optional-work table completed.
    let rows = c
        .query(
            "mail".into(),
            "SELECT count(*) AS n FROM sqlite_master WHERE type = 'table' AND name = 'attachment_transfers'"
                .into(),
            "[]".into(),
        )
        .expect("query");
    assert_eq!(rows.parse::<serde_json::Value>().unwrap()[0]["n"], 1);
}
