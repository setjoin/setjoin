//! E4-I bundled per-app migration manifest — the NATIVE trust-path copy.
//!
//! Authority: retired-docs:verification/2026-09-08-connectivity-native-transaction-freeze.md
//! ("Registered migrations, not caller registration"). The manifest is a finite,
//! bundled constant compiled into the application artifact; `migrate_store`
//! loads THIS copy through the installer/application-update trust path — never
//! from a WebView request, arbitrary URL, filesystem path or a runtime
//! `register` call (no register entry exists). Ordinary job callers cannot
//! register/replace migrations, supply migration SQL or grant themselves DDL
//! rights. The TS mirror (`$lib/offline/migrations.ts`) owns the schema
//! definitions; this file is its byte-for-byte SQL transcription, versioned in
//! lock-step (v1 base schema, v2 optional-work tables — content-minimal).
//!
//! Detection mirrors the TS `detectMailSchemaVersion` exactly: sqlite_master
//! DDL is the source of truth (the historical U6 probe's source, kept because
//! PRAGMA reads are refused by every shell gate). Each applied step commits its
//! statements plus the `meta_mail.schema_version` row in ONE transaction; an
//! interrupted step rolls back and can retry; jobs cannot interleave migration
//! (the caller holds the per-store connection for the whole plan).

use crate::store::OfflineError;
use rusqlite::Connection;

/// Current mail schema version produced by this bundled manifest.
pub const MAIL_SCHEMA_VERSION: i64 = 2;

/// The `meta_mail` key carrying the migration version row (audit/observability;
/// detection itself reads sqlite_master DDL, never this row).
const SCHEMA_VERSION_KEY: &str = "schema_version";

/// One declared migration step: schema version AFTER this step commits.
#[derive(Debug, PartialEq, Eq)]
pub struct MailMigrationStep {
    pub id: &'static str,
    pub target_version: i64,
    pub statements: &'static [&'static str],
}

/// The pre-versioning dev-store eligibility upgrade (historical U6 replay).
pub const MAIL_U6_ELIGIBILITY_REPLAY: &str =
    "ALTER TABLE recovery_artifacts ADD COLUMN eligibility TEXT NOT NULL DEFAULT 'received'";

/// The bundled mail manifest steps (v1 base, v2 optional work) — the SQL
/// transcription of `MAIL_MIGRATION_MANIFEST` in `$lib/offline/migrations.ts`.
pub const MAIL_MANIFEST_STEPS: &[MailMigrationStep] = &[
    MailMigrationStep {
        id: "mail-v1-base",
        target_version: 1,
        statements: &[
            "CREATE TABLE IF NOT EXISTS messages (
  id TEXT PRIMARY KEY,
  thread_id TEXT NOT NULL DEFAULT '',
  received_at INTEGER NOT NULL DEFAULT 0,
  flags TEXT NOT NULL DEFAULT '[]',
  has_attachment INTEGER NOT NULL DEFAULT 0,
  cache_state TEXT NOT NULL DEFAULT 'meta',
  synced_at INTEGER NOT NULL DEFAULT 0,
  from_ TEXT NOT NULL DEFAULT '',
  to_ TEXT NOT NULL DEFAULT '',
  cc TEXT NOT NULL DEFAULT '',
  bcc TEXT NOT NULL DEFAULT '',
  subject TEXT NOT NULL DEFAULT '',
  preview TEXT NOT NULL DEFAULT '',
  version INTEGER NOT NULL DEFAULT 0,
  dirty_fields TEXT NOT NULL DEFAULT '[]'
)",
            "CREATE INDEX IF NOT EXISTS idx_messages_received ON messages(received_at DESC)",
            "CREATE INDEX IF NOT EXISTS idx_messages_thread ON messages(thread_id)",
            "CREATE TABLE IF NOT EXISTS message_tags (
  message_id TEXT NOT NULL,
  tag_id TEXT NOT NULL,
  received_at INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (message_id, tag_id)
)",
            "CREATE INDEX IF NOT EXISTS idx_message_tags_tag ON message_tags(tag_id, received_at DESC)",
            "CREATE TABLE IF NOT EXISTS bodies (
  id TEXT PRIMARY KEY,
  html_body TEXT NOT NULL DEFAULT '',
  text_body TEXT NOT NULL DEFAULT '',
  inline_refs TEXT NOT NULL DEFAULT '[]'
)",
            "CREATE TABLE IF NOT EXISTS mailboxes (
  id TEXT PRIMARY KEY,
  role TEXT NOT NULL DEFAULT '',
  name TEXT NOT NULL DEFAULT '',
  counts TEXT NOT NULL DEFAULT '{}'
)",
            "CREATE TABLE IF NOT EXISTS sync_issues (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  kind TEXT NOT NULL,
  action_type TEXT NOT NULL,
  payload TEXT NOT NULL DEFAULT '{}',
  error TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL DEFAULT 0
)",
            "CREATE TABLE IF NOT EXISTS meta_mail (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL DEFAULT ''
)",
            "CREATE TABLE IF NOT EXISTS action_queue (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  type TEXT NOT NULL,
  payload TEXT NOT NULL DEFAULT '{}',
  status TEXT NOT NULL DEFAULT 'pending',
  attempts INTEGER NOT NULL DEFAULT 0,
  last_error TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL DEFAULT 0
)",
            "CREATE INDEX IF NOT EXISTS idx_action_queue_status ON action_queue(status, created_at)",
            "CREATE TABLE IF NOT EXISTS recovery_artifacts (
  artifact_identity TEXT PRIMARY KEY,
  message_id TEXT NOT NULL,
  account_id TEXT NOT NULL,
  mailbox_id TEXT NOT NULL,
  installation_id TEXT NOT NULL,
  raw_sha256 TEXT NOT NULL,
  raw_size INTEGER NOT NULL,
  received_at INTEGER NOT NULL,
  timeline_generation TEXT NOT NULL,
  boot_epoch TEXT NOT NULL,
  state_watermark TEXT NOT NULL,
  receipt TEXT NOT NULL,
  eligibility TEXT NOT NULL DEFAULT 'received',
  verified_at INTEGER NOT NULL,
  retained_until INTEGER,
  status TEXT NOT NULL DEFAULT 'covered'
)",
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_recovery_artifacts_message ON recovery_artifacts(account_id, message_id, raw_sha256)",
            "CREATE INDEX IF NOT EXISTS idx_recovery_artifacts_received ON recovery_artifacts(received_at DESC)",
            "CREATE TABLE IF NOT EXISTS recovery_artifact_items (
  artifact_identity TEXT NOT NULL,
  item_id TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  size INTEGER NOT NULL,
  role TEXT NOT NULL,
  PRIMARY KEY (artifact_identity, item_id),
  FOREIGN KEY (artifact_identity) REFERENCES recovery_artifacts(artifact_identity) ON DELETE CASCADE
)",
            "CREATE TABLE IF NOT EXISTS recovery_uploads (
  artifact_identity TEXT NOT NULL,
  incident_id TEXT NOT NULL,
  session_id TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  device_id TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (artifact_identity, incident_id),
  UNIQUE (session_id),
  FOREIGN KEY (artifact_identity) REFERENCES recovery_artifacts(artifact_identity) ON DELETE CASCADE
)",
            "CREATE VIRTUAL TABLE IF NOT EXISTS messages_fts USING fts5(
  id UNINDEXED, subject, body, addrs, tokenize = 'unicode61'
)",
        ],
    },
    MailMigrationStep {
        id: "mail-v2-optional-work",
        target_version: 2,
        statements: &[
            "CREATE TABLE IF NOT EXISTS optional_jobs (
  job_id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL,
  work_class TEXT NOT NULL,
  state TEXT NOT NULL DEFAULT 'queued',
  trigger_generation INTEGER NOT NULL DEFAULT 0,
  coalescing_key TEXT NOT NULL UNIQUE,
  attempts INTEGER NOT NULL DEFAULT 0,
  deadline_utc TEXT NOT NULL,
  queued_at_utc_ms INTEGER NOT NULL DEFAULT 0,
  retry_at_utc_ms INTEGER,
  step_kind TEXT NOT NULL DEFAULT 'delta',
  checkpoint_version INTEGER,
  checkpoint_cursor TEXT,
  lease_owner TEXT,
  lease_expires_at_ms INTEGER,
  result_state TEXT,
  result_json TEXT
)",
            "CREATE INDEX IF NOT EXISTS idx_optional_jobs_due ON optional_jobs(state, retry_at_utc_ms)",
            "CREATE INDEX IF NOT EXISTS idx_optional_jobs_account ON optional_jobs(account_id, state)",
            "CREATE TABLE IF NOT EXISTS attachment_transfers (
  job_id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL,
  blob_sha256 TEXT NOT NULL,
  etag TEXT NOT NULL,
  expected_size INTEGER NOT NULL,
  expected_sha256 TEXT NOT NULL,
  committed_bytes INTEGER NOT NULL DEFAULT 0,
  state TEXT NOT NULL DEFAULT 'queued',
  deadline_utc TEXT NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  checkpoint_version INTEGER NOT NULL DEFAULT 1
)",
            "CREATE INDEX IF NOT EXISTS idx_attachment_transfers_account ON attachment_transfers(account_id, state)",
        ],
    },
];

/// Detection of the current on-disk schema generation (mirror of the TS
/// `DetectedSchema`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DetectedSchema {
    pub version: i64,
    /// True for pre-versioning dev stores whose DDL lacks `eligibility`.
    pub needs_legacy_eligibility_replay: bool,
}

fn word_tokens(ddl: &str) -> impl Iterator<Item = &str> {
    ddl.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
}

/// Detect the schema generation from the store's own `sqlite_master` DDL — the
/// exact algorithm of TS `detectMailSchemaVersion`:
/// - v2 is reported ONLY when BOTH optional-work tables exist (a partially
///   migrated store must recover by replaying the v2 step);
/// - v2 is never reported as current while `recovery_artifacts` still lacks
///   its `eligibility` column (an interrupted legacy init reports the replay).
pub fn detect_schema_version(conn: &Connection) -> Result<DetectedSchema, OfflineError> {
    let mut stmt = conn.prepare(
        "SELECT name, sql FROM sqlite_master WHERE type IN ('table') \
         AND name IN ('recovery_artifacts','optional_jobs','attachment_transfers')",
    )?;
    let mut names: Vec<String> = Vec::new();
    let mut recovery_ddl = String::new();
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let name: String = row.get(0)?;
        let sql: String = row.get::<_, Option<String>>(1)?.unwrap_or_default();
        if name == "recovery_artifacts" {
            recovery_ddl = sql;
        }
        names.push(name);
    }
    let has = |n: &str| names.iter().any(|x| x == n);
    let legacy_eligibility_missing =
        has("recovery_artifacts") && !word_tokens(&recovery_ddl).any(|t| t == "eligibility");
    if has("optional_jobs") && has("attachment_transfers") {
        return Ok(DetectedSchema {
            version: MAIL_SCHEMA_VERSION,
            needs_legacy_eligibility_replay: legacy_eligibility_missing,
        });
    }
    if has("recovery_artifacts") {
        if legacy_eligibility_missing {
            return Ok(DetectedSchema { version: 0, needs_legacy_eligibility_replay: true });
        }
        // A store at v1 (or an interrupted v2 with one optional table) replays
        // the v2 step; every statement is idempotent IF NOT EXISTS.
        return Ok(DetectedSchema { version: 1, needs_legacy_eligibility_replay: false });
    }
    Ok(DetectedSchema { version: 0, needs_legacy_eligibility_replay: false })
}

/// Admission refusal causes (mirror of the TS `MigrationRefusalReason`; the
/// digest-mismatch cause cannot occur here — the manifest is a bundled
/// constant, not a caller-supplied value).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationRefusal {
    UnknownVersion,
    AheadVersion,
    Downgrade,
    ForeignApp,
}

impl std::fmt::Display for MigrationRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let reason = match self {
            MigrationRefusal::UnknownVersion => "unknown-version",
            MigrationRefusal::AheadVersion => "ahead-version",
            MigrationRefusal::Downgrade => "downgrade",
            MigrationRefusal::ForeignApp => "foreign-app",
        };
        f.write_str(reason)
    }
}

/// The admitted migration plan: ordered steps plus the legacy replay, with the
/// version the store ends at.
#[derive(Debug, PartialEq, Eq)]
pub struct MigrationPlan {
    pub steps: Vec<&'static MailMigrationStep>,
    pub legacy_replays: &'static [&'static str],
    pub resulting_version: i64,
}

/// Pure admission planner over the BUNDLED manifest only. Refuses unknown,
/// ahead and downgrade targets, and any app whose namespace the manifest does
/// not cover, before any statement is produced.
pub fn plan_migration(
    app_key: &str,
    detected: &DetectedSchema,
    target_version: i64,
) -> Result<MigrationPlan, MigrationRefusal> {
    // The bundled manifest covers exactly the 'mail' namespace; other apps'
    // schemas stay owned by their own lanes (fail closed).
    if app_key != "mail" {
        return Err(MigrationRefusal::ForeignApp);
    }
    // Refusal order mirrors TS planMigration: ahead beats unknown, and a
    // target below the manifest floor is not a version at all.
    if target_version > MAIL_SCHEMA_VERSION {
        return Err(MigrationRefusal::AheadVersion);
    }
    if target_version < 1 {
        return Err(MigrationRefusal::UnknownVersion);
    }
    if target_version < detected.version {
        return Err(MigrationRefusal::Downgrade);
    }
    let mut steps: Vec<&'static MailMigrationStep> = Vec::new();
    if detected.version < 1 {
        steps.push(&MAIL_MANIFEST_STEPS[0]);
    }
    if detected.version < 2 && target_version >= 2 {
        steps.push(&MAIL_MANIFEST_STEPS[1]);
    }
    // The replay rides whenever the store actually lacks the eligibility
    // column — including an interrupted legacy init that already created the
    // optional tables ("at v2" never implies "replay done").
    let legacy_replays: &'static [&'static str] = if detected.needs_legacy_eligibility_replay {
        &[MAIL_U6_ELIGIBILITY_REPLAY]
    } else {
        &[]
    };
    let resulting_version = steps
        .last()
        .map(|s| s.target_version)
        .unwrap_or(detected.version.max(target_version));
    Ok(MigrationPlan { steps, legacy_replays, resulting_version })
}

/// Commit ONE transaction: the given statements plus the version row.
fn commit_step(
    conn: &Connection,
    statements: &[&str],
    version_row: Option<i64>,
) -> Result<(), OfflineError> {
    conn.execute_batch("BEGIN IMMEDIATE")?;
    let exec_all = || -> Result<(), OfflineError> {
        for statement in statements {
            conn.execute_batch(statement)?;
        }
        if let Some(v) = version_row {
            conn.execute(
                "INSERT OR REPLACE INTO meta_mail (key, value) VALUES (?1, ?2)",
                rusqlite::params![SCHEMA_VERSION_KEY, v.to_string()],
            )?;
        }
        Ok(())
    };
    match exec_all() {
        Ok(()) => conn.execute_batch("COMMIT")?,
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK");
            return Err(e);
        }
    }
    Ok(())
}

/// Apply the bundled mail migrations to `target_version` under the same
/// per-store serialization as every other store entry. Each declared step
/// commits its statements plus its version row atomically; the legacy
/// eligibility replay commits atomically AFTER the steps it rides with. An
/// interrupted step rolls back entirely and can retry. Returns the resulting
/// schema version.
pub fn apply_migrations(
    conn: &Connection,
    app_key: &str,
    target_version: i64,
) -> Result<i64, OfflineError> {
    let detected = detect_schema_version(conn)?;
    let plan = plan_migration(app_key, &detected, target_version)
        .map_err(|r| OfflineError::Database(format!("migration refused: {r}")))?;
    for step in &plan.steps {
        commit_step(conn, step.statements, Some(step.target_version))?;
    }
    if !plan.legacy_replays.is_empty() {
        commit_step(conn, plan.legacy_replays, Some(plan.resulting_version))?;
    }
    Ok(plan.resulting_version)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundled_manifest_is_finite_ordered_and_content_minimal() {
        let versions: Vec<i64> = MAIL_MANIFEST_STEPS.iter().map(|s| s.target_version).collect();
        assert_eq!(versions, vec![1, 2]);
        assert_eq!(MAIL_MANIFEST_STEPS[0].id, "mail-v1-base");
        assert_eq!(MAIL_MANIFEST_STEPS[1].id, "mail-v2-optional-work");
        // The optional-work tables stay content-minimal (no bearer/subject/URL
        // columns) — the same leak guard the TS manifest test enforces.
        let v2: String = MAIL_MANIFEST_STEPS[1]
            .statements
            .join("\n")
            .to_ascii_lowercase();
        for forbidden in ["bearer", "token", "subject", "sender", "filename", "body", "url"] {
            assert!(!v2.contains(forbidden), "column leak: {forbidden}");
        }
    }

    #[test]
    fn planner_refuses_unknown_ahead_downgrade_and_foreign_apps() {
        let fresh = DetectedSchema { version: 0, needs_legacy_eligibility_replay: false };
        assert_eq!(plan_migration("drive", &fresh, 2), Err(MigrationRefusal::ForeignApp));
        assert_eq!(plan_migration("mail", &fresh, 0), Err(MigrationRefusal::UnknownVersion));
        assert_eq!(plan_migration("mail", &fresh, 3), Err(MigrationRefusal::AheadVersion));
        let current = DetectedSchema { version: 2, needs_legacy_eligibility_replay: false };
        assert_eq!(plan_migration("mail", &current, 1), Err(MigrationRefusal::Downgrade));
    }

    #[test]
    fn planner_plans_fresh_v1_and_current_stores_with_legacy_replay() {
        let fresh = DetectedSchema { version: 0, needs_legacy_eligibility_replay: false };
        let plan = plan_migration("mail", &fresh, 2).expect("fresh plan");
        assert_eq!(plan.steps.iter().map(|s| s.target_version).collect::<Vec<_>>(), vec![1, 2]);
        assert!(plan.legacy_replays.is_empty());
        assert_eq!(plan.resulting_version, 2);

        let v1 = DetectedSchema { version: 1, needs_legacy_eligibility_replay: false };
        let plan = plan_migration("mail", &v1, 2).expect("v1 plan");
        assert_eq!(plan.steps.iter().map(|s| s.target_version).collect::<Vec<_>>(), vec![2]);

        let current = DetectedSchema { version: 2, needs_legacy_eligibility_replay: false };
        let plan = plan_migration("mail", &current, 2).expect("current plan");
        assert!(plan.steps.is_empty());
        assert_eq!(plan.resulting_version, 2);

        // Legacy dev store: replay rides from version 0 AND from an "at v2"
        // store whose eligibility column never landed (interrupted legacy init).
        let legacy = DetectedSchema { version: 0, needs_legacy_eligibility_replay: true };
        let plan = plan_migration("mail", &legacy, 2).expect("legacy plan");
        assert_eq!(plan.legacy_replays.len(), 1);
        assert!(plan.legacy_replays[0].contains("ALTER TABLE recovery_artifacts"));
        let at_v2 = DetectedSchema { version: 2, needs_legacy_eligibility_replay: true };
        let plan = plan_migration("mail", &at_v2, 2).expect("v2+replay plan");
        assert!(plan.steps.is_empty());
        assert_eq!(plan.legacy_replays.len(), 1);
        assert_eq!(plan.resulting_version, 2);
    }

    #[test]
    fn apply_migrations_creates_the_full_schema_and_version_row_atomically() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let c = Connection::open(dir.path().join("m.db")).expect("open");
        let v = apply_migrations(&c, "mail", 2).expect("apply to 2");
        assert_eq!(v, 2);
        for table in [
            "messages",
            "message_tags",
            "bodies",
            "mailboxes",
            "sync_issues",
            "meta_mail",
            "action_queue",
            "recovery_artifacts",
            "recovery_artifact_items",
            "recovery_uploads",
            "optional_jobs",
            "attachment_transfers",
        ] {
            let n: i64 = c
                .query_row(
                    "SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?1",
                    [table],
                    |r| r.get(0),
                )
                .expect("count");
            assert_eq!(n, 1, "table {table} exists");
        }
        // Version row + FTS virtual table present.
        let row: String = c
            .query_row(
                "SELECT value FROM meta_mail WHERE key = 'schema_version'",
                [],
                |r| r.get(0),
            )
            .expect("version row");
        assert_eq!(row, "2");
        let fts: i64 = c
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='messages_fts'",
                [],
                |r| r.get(0),
            )
            .expect("fts");
        assert_eq!(fts, 1);
        // Re-applying on a current store is a clean no-op at the same version.
        let again = apply_migrations(&c, "mail", 2).expect("idempotent reopen");
        assert_eq!(again, 2);
    }

    #[test]
    fn interrupted_step_rolls_back_and_retries() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let c = Connection::open(dir.path().join("m.db")).expect("open");
        // A store at v1 (apply only the v1 step through the public path by
        // targeting a manifest version… the public entry always targets the
        // bundled version, so simulate v1 by applying step 0 alone).
        commit_step(&c, MAIL_MANIFEST_STEPS[0].statements, Some(1)).expect("v1");
        let detected = detect_schema_version(&c).expect("detect");
        assert_eq!(detected.version, 1, "v1-only store is detected at v1");
        // Simulate an interrupted v2: optional_jobs exists, attachment_transfers
        // does not. Detection must report v1 (replayable), never a phantom v2.
        c.execute_batch(MAIL_MANIFEST_STEPS[1].statements[0]).expect("partial v2");
        let detected = detect_schema_version(&c).expect("detect");
        assert_eq!(detected.version, 1, "partial v2 must stay recoverable");
        let v = apply_migrations(&c, "mail", 2).expect("recovery apply");
        assert_eq!(v, 2);
        let detected = detect_schema_version(&c).expect("detect");
        assert_eq!(detected.version, 2);
    }

    #[test]
    fn legacy_dev_store_gains_the_eligibility_column_through_the_public_path() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let c = Connection::open(dir.path().join("m.db")).expect("open");
        // Legacy-era table WITHOUT the eligibility column: the historical U6
        // DDL shape — otherwise identical to the v1 manifest statement (the
        // indexes over account/message/sha/received columns already existed).
        let v1_recovery = MAIL_MANIFEST_STEPS[0]
            .statements
            .iter()
            .find(|s| s.contains("CREATE TABLE IF NOT EXISTS recovery_artifacts"))
            .expect("v1 recovery DDL");
        let legacy_ddl: String = v1_recovery
            .lines()
            .filter(|line| !line.contains("eligibility"))
            .collect::<Vec<_>>()
            .join("\n");
        c.execute_batch(&legacy_ddl).expect("legacy table");
        let detected = detect_schema_version(&c).expect("detect");
        assert_eq!(detected.version, 0);
        assert!(detected.needs_legacy_eligibility_replay);
        let v = apply_migrations(&c, "mail", 2).expect("apply over legacy");
        assert_eq!(v, 2);
        // The eligibility column now exists in the live DDL (the same source
        // detection reads) and no longer reports a needed replay.
        let ddl: String = c
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'recovery_artifacts'",
                [],
                |r| r.get(0),
            )
            .expect("live DDL");
        assert!(
            word_tokens(&ddl).any(|t| t == "eligibility"),
            "replay added the eligibility column: {ddl}"
        );
        let detected = detect_schema_version(&c).expect("detect");
        assert_eq!(detected.version, 2);
        assert!(!detected.needs_legacy_eligibility_replay);
    }

    #[test]
    fn downgrade_and_ahead_targets_are_refused_without_effects() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let c = Connection::open(dir.path().join("m.db")).expect("open");
        apply_migrations(&c, "mail", 2).expect("apply");
        let err = apply_migrations(&c, "mail", 1).expect_err("downgrade refused");
        assert!(err.to_string().contains("downgrade"), "{err}");
        let err = apply_migrations(&c, "mail", 9).expect_err("ahead refused");
        assert!(err.to_string().contains("ahead-version"), "{err}");
        let err = apply_migrations(&c, "drive", 2).expect_err("foreign app refused");
        assert!(err.to_string().contains("foreign-app"), "{err}");
        // The store is untouched and still current.
        let detected = detect_schema_version(&c).expect("detect");
        assert_eq!(detected.version, 2);
    }
}
