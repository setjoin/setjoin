use guard_core::GuardCore;
use offline_core::OfflineCore;
use std::sync::Arc;

fn core(dir: &tempfile::TempDir, pass: &str) -> Arc<OfflineCore> {
    let vault = dir.path().join("guard.db").to_string_lossy().to_string();
    let guard = GuardCore::new(vault, pass.to_string()).expect("vault open");
    OfflineCore::new(guard)
}

// The miniature fixture DDL, split into its statements. Under the r2 contract
// (med-offcore-sqlguard-001) ordinary `exec` runs SINGLE allowlisted
// statements only, so a caller that is not the authorized schema-init path
// applies DDL statement-by-statement — exactly what these tests mirror. The
// REAL application schema is covered further down (real-schema compatibility).
const MAIL_SCHEMA_STATEMENTS: [&str; 2] = [
    "CREATE TABLE IF NOT EXISTS messages (id TEXT PRIMARY KEY, received_at INTEGER, subject TEXT)",
    "CREATE VIRTUAL TABLE IF NOT EXISTS messages_fts USING fts5(id UNINDEXED, subject, body, addrs)",
];

/// Apply the fixture DDL through ordinary exec, one statement at a time —
/// the ordinary-caller contract (single allowlisted statements only).
fn apply_mail_schema_statements(c: &OfflineCore) {
    for stmt in MAIL_SCHEMA_STATEMENTS {
        c.exec("mail".into(), stmt.to_string(), "[]".into())
            .unwrap_or_else(|e| panic!("single-statement DDL must exec ({e}): {stmt}"));
    }
}

// mc_messages schema used by the SM4 profile tests.
// The TS layer would apply this; replicated here for the feature-gated tests.
#[cfg(feature = "sm4-page-cipher")]
const MC_MAIL_SCHEMA: &str =
    "CREATE TABLE IF NOT EXISTS mc_messages (id TEXT PRIMARY KEY, mailbox_id INTEGER, json TEXT NOT NULL DEFAULT '{}');";

#[test]
fn test_store_crud_and_fts() {
    let dir = tempfile::tempdir().unwrap();
    let c = core(&dir, "correct horse");
    let path = dir.path().join("mail.db").to_string_lossy().to_string();
    c.open_store("mail".into(), path, "standard".into())
        .expect("open mail store");
    assert!(c.is_open("mail".into()));
    apply_mail_schema_statements(&c);

    c.exec(
        "mail".into(),
        "INSERT INTO messages (id, received_at, subject) VALUES (?1, ?2, ?3)".into(),
        r#"["m1", 100, "Quarterly Report"]"#.into(),
    )
    .unwrap();
    c.exec(
        "mail".into(),
        "INSERT INTO messages_fts (id, subject, body, addrs) VALUES (?1, ?2, ?3, ?4)".into(),
        r#"["m1", "Quarterly Report", "revenue grew", "alice@corp"]"#.into(),
    )
    .unwrap();

    let rows = c
        .query(
            "mail".into(),
            "SELECT id, subject FROM messages WHERE id = ?1".into(),
            r#"["m1"]"#.into(),
        )
        .unwrap();
    assert!(rows.contains("Quarterly Report"));

    // FTS5 body search
    let hits = c
        .query(
            "mail".into(),
            "SELECT id FROM messages_fts WHERE messages_fts MATCH ?1".into(),
            r#"["revenue"]"#.into(),
        )
        .unwrap();
    assert!(
        hits.contains("m1"),
        "FTS body search should match 'revenue'"
    );
}

#[test]
fn test_store_opens_only_with_correct_key() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mail.db").to_string_lossy().to_string();
    {
        let c = core(&dir, "right-pass");
        c.open_store("mail".into(), path.clone(), "standard".into())
            .unwrap();
        apply_mail_schema_statements(&c);
        c.exec(
            "mail".into(),
            "INSERT INTO messages (id, subject) VALUES ('s', 'SECRET')".into(),
            "[]".into(),
        )
        .unwrap();
    }
    // A wrong vault passphrase derives a different per-store key -> open fails.
    std::fs::remove_file(dir.path().join("guard.db")).ok();
    let c2 = core(&dir, "WRONG-pass");
    let res = c2.open_store("mail".into(), path.clone(), "standard".into());
    assert!(res.is_err(), "wrong key must NOT open the SQLCipher store");

    // The file on disk is ciphertext — the plaintext 'SECRET' is absent.
    let raw = std::fs::read(&path).unwrap();
    assert!(
        !raw.windows(6).any(|w| w == b"SECRET"),
        "subject must be encrypted at rest"
    );
}

#[test]
fn test_exec_batch_rejects_pragma() {
    // Security regression: multi-statement execute_batch must not run PRAGMA
    // (e.g. PRAGMA rekey) even when the leading keyword passes check_stmt_allowed
    // at the bridge layer. exec() must reject the entire batch if PRAGMA appears
    // anywhere in the SQL string (case-insensitive).
    let dir = tempfile::tempdir().unwrap();
    let c = core(&dir, "p");
    let path = dir.path().join("mail.db").to_string_lossy().to_string();
    c.open_store("mail".into(), path, "standard".into())
        .unwrap();
    apply_mail_schema_statements(&c);

    // Attempt the bypass: leading keyword passes the bridge allowlist, trailing
    // PRAGMA rekey would re-encrypt under attacker-controlled key if allowed.
    // med-offcore-sqlguard-001 r2: ordinary exec refuses multi-statement
    // input outright — the payload never reaches the batch validator, so the
    // PRAGMA inside it can never execute. (Per-statement PRAGMA/ATTACH/DETACH/
    // VACUUM rejection inside a validated batch is pinned at the validator
    // level by store.rs's sql_guard_tests.)
    let attack_sql = "CREATE TABLE pwn(x); PRAGMA rekey=\"attacker\";".to_string();
    let result = c.exec("mail".into(), attack_sql, "[]".into());
    assert!(
        result.is_err(),
        "multi-statement exec with PRAGMA must be rejected"
    );
    let msg = format!("{:?}", result.unwrap_err());
    assert!(
        msg.contains("multi-statement"),
        "rejection must name the r2 single-statement contract: {msg}"
    );
    // Nothing from the refused payload ran.
    let rows = c
        .query(
            "mail".into(),
            "SELECT count(*) AS n FROM sqlite_master WHERE name = 'pwn'".into(),
            "[]".into(),
        )
        .unwrap();
    assert!(
        rows.contains("\"n\":0"),
        "refused batch must not run: {rows}"
    );
}

#[test]
fn test_exec_batch_rejects_attach() {
    // Security regression: a compromised renderer sending DDL + ATTACH in one
    // batch would bypass the bridge allowlist (which only inspects the first
    // statement keyword). med-offcore-sqlguard-001 r2: exec refuses the whole
    // multi-statement payload unconditionally, preventing plaintext-DB writes
    // to arbitrary on-disk paths.
    let dir = tempfile::tempdir().unwrap();
    let c = core(&dir, "p");
    let path = dir.path().join("mail.db").to_string_lossy().to_string();
    c.open_store("mail".into(), path, "standard".into())
        .unwrap();
    apply_mail_schema_statements(&c);

    // ATTACH variant.
    let attach_sql = "CREATE TABLE t(x); ATTACH DATABASE '/tmp/evil.db' AS e;".to_string();
    let result = c.exec("mail".into(), attach_sql, "[]".into());
    assert!(
        result.is_err(),
        "multi-statement exec with ATTACH must be rejected"
    );
    let msg = format!("{:?}", result.unwrap_err());
    assert!(
        msg.contains("multi-statement"),
        "rejection must name the r2 single-statement contract: {msg}"
    );

    // DETACH variant.
    let detach_sql = "CREATE TABLE t2(x); DETACH DATABASE e;".to_string();
    let result = c.exec("mail".into(), detach_sql, "[]".into());
    assert!(
        result.is_err(),
        "multi-statement exec with DETACH must be rejected"
    );
    // Neither refused payload produced its table.
    let rows = c
        .query(
            "mail".into(),
            "SELECT count(*) AS n FROM sqlite_master WHERE name IN ('t', 't2')".into(),
            "[]".into(),
        )
        .unwrap();
    assert!(
        rows.contains("\"n\":0"),
        "refused batches must not run: {rows}"
    );
}

#[test]
fn test_exec_batch_rejects_vacuum_into() {
    // Security regression (med-offcore-sqlguard-001): the batch path used to
    // name-blocklist only PRAGMA/ATTACH/DETACH, so
    // "CREATE TABLE pwn(x); VACUUM INTO '<path>';" passed validation and
    // execute_batch — copying the entire store-keyed database to any
    // process-writable path, in a file that also survived wipe(). r2: ordinary
    // exec refuses the multi-statement payload outright (single-statement
    // contract); the per-statement validator that rejects VACUUM INTO in ANY
    // position remains pinned behind the authorized one-shot init path
    // (store.rs sql_guard_tests + the real-schema tests below).
    let dir = tempfile::tempdir().unwrap();
    let c = core(&dir, "p");
    let path = dir.path().join("mail.db").to_string_lossy().to_string();
    c.open_store("mail".into(), path, "standard".into())
        .unwrap();
    apply_mail_schema_statements(&c);

    let exfil = dir.path().join("exfil.db").to_string_lossy().to_string();
    let attack_sql = format!("CREATE TABLE pwn(x); VACUUM INTO '{exfil}';");
    let result = c.exec("mail".into(), attack_sql, "[]".into());
    assert!(result.is_err(), "VACUUM INTO batch must be rejected");
    let msg = format!("{:?}", result.unwrap_err());
    assert!(
        msg.contains("multi-statement"),
        "rejection must name the r2 single-statement contract: {msg}"
    );
    // The rejected batch ran NOTHING: no partial DDL, no store copy on disk.
    let rows = c
        .query(
            "mail".into(),
            "SELECT count(*) AS n FROM sqlite_master WHERE name = 'pwn'".into(),
            "[]".into(),
        )
        .unwrap();
    assert!(
        rows.contains("\"n\":0"),
        "rejected batch must not apply any statement: {rows}"
    );
    assert!(
        !std::path::Path::new(&exfil).exists(),
        "VACUUM INTO must not produce a copy of the store"
    );

    // A lone VACUUM INTO is equally blocked (first-keyword gate).
    assert!(
        c.exec("mail".into(), format!("VACUUM INTO '{exfil}'"), "[]".into())
            .is_err(),
        "lone VACUUM INTO must be rejected"
    );
}

#[test]
fn test_wipe_removes_only_that_appkeys_file() {
    let dir = tempfile::tempdir().unwrap();
    let c = core(&dir, "p");
    let path = dir.path().join("mail.db").to_string_lossy().to_string();
    c.open_store("mail".into(), path.clone(), "standard".into())
        .unwrap();
    apply_mail_schema_statements(&c);
    c.exec(
        "mail".into(),
        "INSERT INTO messages (id) VALUES ('x')".into(),
        "[]".into(),
    )
    .unwrap();
    c.wipe("mail".into()).unwrap();
    assert!(
        !std::path::Path::new(&path).exists(),
        "wipe deletes the appKey's DB file"
    );
    assert!(!c.is_open("mail".into()));
}

// ── SM4 profile arms (gated — require sm4-page-cipher feature) ───────────────
//
// These tests verify the "smx" cipher-profile path once the SQLCipher
// SQLCIPHER_CRYPTO_CUSTOM hook is wired (a custom SQLCipher build; see A1
// concern). They compile only when `sm4-page-cipher` is enabled; normal builds
// skip them, keeping the AES default path green.

// ponytail: gate with the feature so the test compiles even when the
// SQLCipher custom-crypto hook can't be wired in the bundled build.
#[cfg(feature = "sm4-page-cipher")]
#[test]
fn store_smx_profile_round_trips() {
    let dir = tempfile::tempdir().unwrap();
    let c = core(&dir, "smx-pass");
    let path = dir.path().join("smx.db").to_string_lossy().to_string();
    c.open_store("mail".into(), path, "smx".into()).unwrap();
    c.exec("mail".into(), MC_MAIL_SCHEMA.into(), "[]".into())
        .unwrap();
    c.exec(
        "mail".into(),
        "INSERT INTO mc_messages(id, mailbox_id, json) VALUES (?1,?2,?3)".into(),
        r#"["m2", 1, "{}"]"#.into(),
    )
    .unwrap();
    let rows = c
        .query(
            "mail".into(),
            "SELECT id FROM mc_messages".into(),
            "[]".into(),
        )
        .unwrap();
    assert!(rows.contains("\"m2\""));
}

#[cfg(feature = "sm4-page-cipher")]
#[test]
fn store_profile_flip_recreates() {
    let dir = tempfile::tempdir().unwrap();
    let c = core(&dir, "flip-pass");
    let path = dir.path().join("flip.db").to_string_lossy().to_string();
    c.open_store("mail".into(), path.clone(), "smx".into())
        .unwrap();
    c.exec("mail".into(), MC_MAIL_SCHEMA.into(), "[]".into())
        .unwrap();
    c.exec(
        "mail".into(),
        "INSERT INTO mc_messages(id,mailbox_id,json) VALUES ('m5',1,'{}')".into(),
        "[]".into(),
    )
    .unwrap();
    // flip to standard → wipe+recreate under the new cipher, old (smx) data gone
    c.open_store("mail".into(), path, "standard".into())
        .unwrap();
    let rows = c
        .query(
            "mail".into(),
            "SELECT count(*) AS n FROM mc_messages".into(),
            "[]".into(),
        )
        .unwrap();
    assert!(
        rows.contains("\"n\":0") || rows.contains("\"n\": 0"),
        "profile flip recreates empty: {rows}"
    );
}

/// Regression (was a C-ABI-only test against the now-deleted c_api.rs; the
/// same first-keyword allowlist now lives in store.rs and is enforced for
/// every caller of the safe Rust API, not just the C ABI). PRAGMA / ATTACH
/// must be rejected via `OfflineCore::exec`/`query` regardless of which
/// platform calls in (mobile shell links Rust directly, HarmonyOS via NAPI).
#[test]
fn test_stmt_allowlist_rejects_pragma_and_attach() {
    let dir = tempfile::tempdir().unwrap();
    let c = core(&dir, "p");
    let path = dir.path().join("allw.db").to_string_lossy().to_string();
    c.open_store("mail".into(), path, "standard".into())
        .unwrap();

    // PRAGMA must be blocked at exec.
    assert!(
        c.exec("mail".into(), "PRAGMA integrity_check".into(), "[]".into())
            .is_err(),
        "PRAGMA must be rejected by OfflineCore::exec"
    );
    // PRAGMA must be blocked at query.
    assert!(
        c.query("mail".into(), "PRAGMA journal_mode".into(), "[]".into())
            .is_err(),
        "PRAGMA must be rejected by OfflineCore::query"
    );
    // r4: the U6 upgrade was restructured onto the authorized batch path, so
    // the QUERY gate stays PRAGMA-free — the old init probe payload must still
    // be refused (no gate widening was needed or made).
    assert!(
        c.query(
            "mail".into(),
            "PRAGMA table_info(recovery_artifacts)".into(),
            "[]".into()
        )
        .is_err(),
        "PRAGMA table_info must stay rejected by OfflineCore::query (r4)"
    );
    // ATTACH must be blocked at exec.
    assert!(
        c.exec(
            "mail".into(),
            "ATTACH DATABASE '/tmp/x' AS e".into(),
            "[]".into()
        )
        .is_err(),
        "ATTACH must be rejected by OfflineCore::exec"
    );
}

// ── Real-schema compatibility (med-offcore-sqlguard-001 r2 finding b, r3) ────
//
// The MAIL_SCHEMA fixture above is a MINIATURE, not the application schema.
// The REAL mail DDL lives in the webmail migration manifest —
// mailserver/webmail/src/lib/offline/migrations.ts, whose bundled
// MAIL_MIGRATION_MANIFEST owns the versioned statements (E4-I moved it out of
// store-native.ts's single MAIL_SCHEMA block; store-native.ts's init() applies
// the same statements through applyMailMigrations) — and it is read here
// READ-ONLY (include_str!): the test breaks loudly at compile time if the
// schema source moves or its constant is renamed, so the fixture and the real
// schema can never silently diverge.
// Coverage required by the review:
//   1. the authorized one-shot init path accepts the REAL statements
//      verbatim (structural split + per-statement batch allowlist + SQLite
//      parse), the created tables/indexes/FTS are usable, and a replay is
//      refused by the one-shot gate;
//   2. ordinary exec REJECTS the real multi-statement payload.
// r3: both tests drive the APPLICATION surface — `OfflineCore::open_store` →
// `OfflineCore::exec_schema_init`, the exact method the napi/uniffi bridge
// exports (`db_exec_schema_init`) delegates to — on a real keyed store, not
// the inner `store::exec_schema_init` on a bare connection. Application
// initialization therefore works verbatim against the real mail DDL on the
// path the shipped shells actually call.

const MIGRATIONS_TS: &str =
    include_str!("../../../../mailserver/webmail/src/lib/offline/migrations.ts");

/// Extract every schema statement of the bundled migration manifest from the
/// TS source, verbatim, in manifest order (v1 base, then v2 optional work).
/// Between the manifest declaration and the U6 replay constant, every backtick
/// template literal is exactly one schema statement (ids/appKey are
/// single-quoted, versions are numbers), so collecting them reconstructs the
/// manifest's statement lists without re-parsing TS.
fn real_schema_statements() -> Vec<String> {
    const START: &str = "export const MAIL_MIGRATION_MANIFEST";
    const END: &str = "export const MAIL_U6_ELIGIBILITY_REPLAY";
    let start = MIGRATIONS_TS
        .find(START)
        .expect("migrations.ts must declare `export const MAIL_MIGRATION_MANIFEST`")
        + START.len();
    let end = MIGRATIONS_TS[start..]
        .find(END)
        .expect("migrations.ts must declare `export const MAIL_U6_ELIGIBILITY_REPLAY` after the manifest")
        + start;
    let block = &MIGRATIONS_TS[start..end];
    let mut out = Vec::new();
    let mut rest = block;
    while let Some(open) = rest.find('`') {
        rest = &rest[open + 1..];
        let close = rest
            .find('`')
            .expect("manifest statement template literal must close with a backtick");
        out.push(rest[..close].to_string());
        rest = &rest[close + 1..];
    }
    assert!(
        !out.is_empty(),
        "MAIL_MIGRATION_MANIFEST must carry schema statements"
    );
    out
}

/// Extract the real application schema batch from the TS source, verbatim —
/// composed exactly as the TS one-shot legacy path composes it for a fresh
/// store (migrations.ts `legacySchemaInitSql`): every manifest statement,
/// each terminated with `;`, separated by newlines (trailing `;\n` so an
/// appended upgrade statement stays a separate statement).
fn real_mail_schema() -> String {
    let mut batch = String::new();
    for statement in real_schema_statements() {
        batch.push_str(&statement);
        batch.push_str(";\n");
    }
    batch
}

/// Extract the legacy eligibility-upgrade ALTER statement from the TS source,
/// verbatim (same compile-time coupling as `real_mail_schema`): the exact
/// statement the TS planner (`MAIL_U6_ELIGIBILITY_REPLAY`) appends to the
/// authorized batch for pre-versioning dev stores.
fn real_u6_eligibility_upgrade() -> String {
    const MARKER: &str = "export const MAIL_U6_ELIGIBILITY_REPLAY";
    let start = MIGRATIONS_TS
        .find(MARKER)
        .expect("migrations.ts must declare `export const MAIL_U6_ELIGIBILITY_REPLAY`")
        + MARKER.len();
    let rest = &MIGRATIONS_TS[start..];
    let open = rest
        .find('"')
        .expect("U6 replay constant must be a double-quoted string");
    let rest = &rest[open + 1..];
    let end = rest
        .find("\";")
        .expect("U6 replay constant must close with a quote-semicolon");
    rest[..end].to_string()
}

/// Extract the init detection's sqlite_master probe SQL from the TS source,
/// verbatim: the E4-I detection (migrations.ts `detectMailSchemaVersion`) is a
/// plain allowlisted SELECT over the store's own schema metadata — reading the
/// three tables whose presence and DDL determine the schema generation (it
/// replaced the PRAGMA table_info read that every shell gate rejected —
/// med-offcore-sqlguard-001 r4).
fn real_init_probe_sql() -> String {
    const MARKER: &str = "SELECT name, sql FROM sqlite_master";
    let mid = MIGRATIONS_TS
        .find(MARKER)
        .expect("migrations.ts detectMailSchemaVersion must probe sqlite_master");
    let open = MIGRATIONS_TS[..mid]
        .rfind('"')
        .expect("probe must be a double-quoted TS string literal");
    let rest = &MIGRATIONS_TS[open + 1..];
    let end = rest
        .find('"')
        .expect("probe string must close with a double quote");
    rest[..end].to_string()
}

/// Mirror of the TS init detection (migrations.ts `detectMailSchemaVersion`):
/// given the raw `query()` JSON result of the sqlite_master probe over
/// recovery_artifacts/optional_jobs/attachment_transfers, decide whether the
/// legacy eligibility replay must be appended to the authorized batch. `[]`
/// (fresh store) and recovery_artifacts DDL already naming `eligibility`
/// (current store) both mean "no upgrade" — only a recovery_artifacts row
/// whose stored DDL lacks the column is a pre-versioning dev store. The row
/// is matched by NAME, not position: the probe returns up to three rows.
fn needs_u6_upgrade(probe_json: &str) -> bool {
    let rows: Vec<serde_json::Value> =
        serde_json::from_str(probe_json).expect("probe result must be a JSON row array");
    let ddl = rows
        .iter()
        .filter(|r| r.get("name").and_then(|v| v.as_str()) == Some("recovery_artifacts"))
        .find_map(|r| r.get("sql"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    !ddl.is_empty() && !ddl.contains("eligibility")
}

#[test]
fn real_mail_schema_applies_verbatim_through_authorized_init_path() {
    let schema = real_mail_schema();
    assert!(
        schema.contains("CREATE TABLE IF NOT EXISTS messages")
            && schema.contains("CREATE TABLE IF NOT EXISTS recovery_uploads")
            && schema.contains("CREATE VIRTUAL TABLE IF NOT EXISTS messages_fts USING fts5"),
        "extraction must yield the real application DDL, not the miniature fixture"
    );

    // Application path: open a real keyed store, then init through the SAME
    // OfflineCore method the napi/uniffi bridge exports.
    let dir = tempfile::tempdir().unwrap();
    let c = core(&dir, "real-schema");
    let path = dir
        .path()
        .join("real-schema.db")
        .to_string_lossy()
        .to_string();
    c.open_store("mail".into(), path, "standard".into())
        .expect("open mail store");
    // Deterministic gate state: the one-shot gate is keyed by the connection's
    // address, and a prior (dropped) test connection could have consumed it
    // via allocator address reuse (fail-closed flakiness — see the helper's
    // docs). Test-only; production never resets the gate.
    c.__reset_schema_init_gate_for_tests("mail");
    c.exec_schema_init("mail".into(), schema.clone())
        .expect("REAL mail schema must apply verbatim through the authorized init path");

    // Every real table (incl. the fts5 virtual table and the E4-I v2
    // optional-work tables) and every named index — read back through the
    // ordinary query path the TS layer itself uses.
    let tables = c
        .query(
            "mail".into(),
            "SELECT count(*) AS n FROM sqlite_master WHERE type = 'table' AND name IN \
             ('messages','message_tags','bodies','mailboxes','sync_issues','meta_mail',\
             'action_queue','recovery_artifacts','recovery_artifact_items',\
             'recovery_uploads','messages_fts','optional_jobs','attachment_transfers')"
                .into(),
            "[]".into(),
        )
        .unwrap();
    assert!(
        tables.contains("\"n\":13"),
        "all real tables (+ fts virtual table, + v2 optional-work tables) created: {tables}"
    );
    let indexes = c
        .query(
            "mail".into(),
            "SELECT count(*) AS n FROM sqlite_master WHERE type = 'index' AND name LIKE 'idx_%'"
                .into(),
            "[]".into(),
        )
        .unwrap();
    assert!(
        indexes.contains("\"n\":9"),
        "all named real indexes created (received/thread, tag, queue status, recovery x2, optional-work x3): {indexes}"
    );

    // The created schema is actually usable: CRUD + FTS via ordinary
    // single-statement exec/query (the post-init application contract).
    c.exec(
        "mail".into(),
        "INSERT INTO messages (id, subject) VALUES ('m1', 'Quarterly Report')".into(),
        "[]".into(),
    )
    .unwrap();
    c.exec(
        "mail".into(),
        "INSERT INTO messages_fts (id, subject, body, addrs) VALUES \
         ('m1', 'Quarterly Report', 'revenue grew', 'alice@corp')"
            .into(),
        "[]".into(),
    )
    .unwrap();
    let hits = c
        .query(
            "mail".into(),
            "SELECT id FROM messages_fts WHERE messages_fts MATCH 'revenue'".into(),
            "[]".into(),
        )
        .unwrap();
    assert!(
        hits.contains("\"m1\""),
        "real fts5 table is functional: {hits}"
    );

    // One-shot gate: replaying the (idempotent) real schema on the SAME
    // store connection is refused — later batches never run through this seam.
    let err = c
        .exec_schema_init("mail".into(), schema)
        .expect_err("a second init batch must hit the one-shot gate");
    assert!(
        err.to_string().contains("one-shot"),
        "replay rejection must name the one-shot gate: {err}"
    );
}

/// r4: the FULL application initialization sequence — probe → authorized
/// batch — through the exported OfflineCore paths, on a fresh store, then
/// across a real reopen (new connection = fresh one-shot gate). No PRAGMA is
/// issued anywhere: the old `PRAGMA table_info` read was rejected by every
/// shell gate and made real init fail (med-offcore-sqlguard-001 r4).
#[test]
fn real_init_full_sequence_fresh_store_and_reopen() {
    let schema = real_mail_schema();
    let probe = real_init_probe_sql();

    let dir = tempfile::tempdir().unwrap();
    let path = dir
        .path()
        .join("real-init.db")
        .to_string_lossy()
        .to_string();

    // First launch: a fresh store. The probe sees NO recovery_artifacts row,
    // so the authorized batch is the plain schema (no U6 upgrade appended).
    {
        let c = core(&dir, "real-init");
        c.open_store("mail".into(), path.clone(), "standard".into())
            .expect("open mail store");
        c.__reset_schema_init_gate_for_tests("mail");

        let probe_rows = c
            .query("mail".into(), probe.clone(), "[]".into())
            .expect("sqlite_master probe runs through the ordinary query path");
        assert_eq!(
            probe_rows.trim(),
            "[]",
            "fresh store: no recovery_artifacts row yet: {probe_rows}"
        );
        assert!(!needs_u6_upgrade(&probe_rows), "fresh store: no upgrade");

        c.exec_schema_init("mail".into(), schema.clone())
            .expect("REAL mail schema applies through the authorized init path");

        // After init the probe reads the stored DDL — current shape, no upgrade.
        let probe_rows = c
            .query("mail".into(), probe.clone(), "[]".into())
            .expect("post-init probe");
        assert!(
            !needs_u6_upgrade(&probe_rows),
            "fresh-applied schema is current-shape: {probe_rows}"
        );
        assert!(
            probe_rows.contains("eligibility"),
            "stored DDL names eligibility: {probe_rows}"
        );

        // Seed one row so the reopen arm can prove persistence.
        c.exec(
            "mail".into(),
            "INSERT INTO messages (id, subject) VALUES ('m1', 'keep me')".into(),
            "[]".into(),
        )
        .unwrap();
    } // drop: the app "restarts" — native connection gone.

    // Reopen: a NEW OfflineCore re-derives the same store key from the same
    // vault/passphrase, opens the SAME file on a fresh native connection, so
    // the one-shot gate is fresh — exactly the real reopen sequence.
    let c = core(&dir, "real-init");
    c.open_store("mail".into(), path.clone(), "standard".into())
        .expect("reopen the same keyed store after restart");
    c.__reset_schema_init_gate_for_tests("mail");

    let probe_rows = c
        .query("mail".into(), probe, "[]".into())
        .expect("probe on reopen");
    assert!(
        !needs_u6_upgrade(&probe_rows),
        "current-shape store must not be upgraded: {probe_rows}"
    );
    c.exec_schema_init("mail".into(), schema)
        .expect("idempotent re-init through the authorized path on the fresh connection");
    let rows = c
        .query(
            "mail".into(),
            "SELECT count(*) AS n FROM messages".into(),
            "[]".into(),
        )
        .unwrap();
    assert!(
        rows.contains("\"n\":1"),
        "reopened store keeps its data across the real init sequence: {rows}"
    );
}

/// r4: the FULL initialization sequence on a PRE-U6 development store — the
/// first recovery_artifacts shape (no `eligibility` column, plus a pre-existing
/// row). The probe detects the old shape and the authorized batch applies the
/// schema + U6 ALTER upgrade IN PLACE: the old row survives with the column
/// default. The upgrade consumes the connection's one batch (one-shot gate).
#[test]
fn real_init_full_sequence_upgrades_pre_u6_store_in_place() {
    let schema = real_mail_schema();
    let upgrade = real_u6_eligibility_upgrade();
    let probe = real_init_probe_sql();
    assert!(
        upgrade.starts_with("ALTER TABLE recovery_artifacts ADD COLUMN eligibility"),
        "extraction must yield the real U6 upgrade statement: {upgrade}"
    );

    let dir = tempfile::tempdir().unwrap();
    let c = core(&dir, "pre-u6");
    let path = dir.path().join("pre-u6.db").to_string_lossy().to_string();
    c.open_store("mail".into(), path, "standard".into())
        .expect("open mail store");
    c.__reset_schema_init_gate_for_tests("mail");

    // Simulate the pre-release U6 store: the first recovery table shape was
    // created by an EARLIER app version's authorized init. Recreate it through
    // ordinary single-statement exec (allowlisted CREATE — the ordinary-caller
    // contract), which — like that earlier session — leaves the one-shot gate
    // unconsumed for THIS session's init.
    c.exec(
        "mail".into(),
        "CREATE TABLE IF NOT EXISTS recovery_artifacts (\
         artifact_identity TEXT PRIMARY KEY, message_id TEXT NOT NULL, \
         account_id TEXT NOT NULL, mailbox_id TEXT NOT NULL, \
         installation_id TEXT NOT NULL, raw_sha256 TEXT NOT NULL, \
         raw_size INTEGER NOT NULL, received_at INTEGER NOT NULL, \
         timeline_generation TEXT NOT NULL, boot_epoch TEXT NOT NULL, \
         state_watermark TEXT NOT NULL, receipt TEXT NOT NULL, \
         verified_at INTEGER NOT NULL, retained_until INTEGER, \
         status TEXT NOT NULL DEFAULT 'covered')"
            .into(),
        "[]".into(),
    )
    .expect("old-shape table via ordinary exec");
    c.exec(
        "mail".into(),
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_recovery_artifacts_message \
         ON recovery_artifacts(account_id, message_id, raw_sha256)"
            .into(),
        "[]".into(),
    )
    .expect("old-shape index via ordinary exec");
    c.exec(
        "mail".into(),
        "INSERT INTO recovery_artifacts (artifact_identity, message_id, account_id, \
         mailbox_id, installation_id, raw_sha256, raw_size, received_at, \
         timeline_generation, boot_epoch, state_watermark, receipt, verified_at) \
         VALUES ('a1', 'm1', 'acc', 'mb', 'inst', 'sha', 5, 100, 'tg', 'be', 'sw', 'rc', 200)"
            .into(),
        "[]".into(),
    )
    .expect("pre-upgrade row in the old-shape table");

    // FULL init sequence, exactly as the TS layer runs it: probe → detect →
    // authorized batch (schema + U6 upgrade appended).
    let probe_rows = c
        .query("mail".into(), probe, "[]".into())
        .expect("sqlite_master probe");
    assert!(
        needs_u6_upgrade(&probe_rows),
        "pre-U6 DDL must be detected: {probe_rows}"
    );
    c.exec_schema_init("mail".into(), format!("{schema}{upgrade}"))
        .expect("authorized batch must accept the real schema + U6 ALTER upgrade");

    // The upgrade applied in place: the pre-existing row survives and reads
    // back the column default.
    let rows = c
        .query(
            "mail".into(),
            "SELECT eligibility, message_id FROM recovery_artifacts \
             WHERE artifact_identity = 'a1'"
                .into(),
            "[]".into(),
        )
        .unwrap();
    assert!(
        rows.contains("\"m1\"") && rows.contains("received"),
        "pre-U6 row survives with the default eligibility: {rows}"
    );
    // The store now reads as current-shape (and the batch is consumed).
    let probe_rows = c
        .query(
            "mail".into(),
            "SELECT sql FROM sqlite_master WHERE type = 'table' \
             AND name = 'recovery_artifacts'"
                .into(),
            "[]".into(),
        )
        .unwrap();
    assert!(
        !needs_u6_upgrade(&probe_rows),
        "upgraded store reads as current-shape: {probe_rows}"
    );
    let err = c
        .exec_schema_init("mail".into(), schema)
        .expect_err("the upgrade consumed this connection's one authorized batch");
    assert!(
        err.to_string().contains("one-shot"),
        "re-init on the SAME connection must hit the one-shot gate: {err}"
    );
}

#[test]
fn real_mail_schema_is_rejected_by_ordinary_exec() {
    let schema = real_mail_schema();
    let dir = tempfile::tempdir().unwrap();
    let c = core(&dir, "real-schema-exec");
    let path = dir
        .path()
        .join("real-schema-exec.db")
        .to_string_lossy()
        .to_string();
    c.open_store("mail".into(), path, "standard".into())
        .expect("open mail store");
    let err = c
        .exec("mail".into(), schema, "[]".into())
        .expect_err("ordinary exec must refuse the real multi-statement schema");
    assert!(
        err.to_string().contains("multi-statement"),
        "exec rejection must name the r2 contract: {err}"
    );
    // None of the real application DDL was created by the refused payload
    // (open_store's generic oc_* tables + sqlite_sequence exist regardless).
    let tables = c
        .query(
            "mail".into(),
            "SELECT count(*) AS n FROM sqlite_master WHERE type = 'table' AND name IN \
             ('messages','message_tags','bodies','mailboxes','sync_issues','meta_mail',\
             'action_queue','recovery_artifacts','recovery_artifact_items',\
             'recovery_uploads','messages_fts')"
                .into(),
            "[]".into(),
        )
        .unwrap();
    assert!(
        tables.contains("\"n\":0"),
        "ordinary exec must not apply any real DDL: {tables}"
    );
}
