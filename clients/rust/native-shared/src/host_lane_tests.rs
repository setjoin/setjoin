//! Host-runnable boundary-delegation lane for the shared native shim
//! (D-CLIENTS-RUST-OHOS-NATIVE-002, `SEC-TEST-GATE-DISABLED /
//! SECURITY-TEST-LANE-DISABLED`).
//!
//! This module is compiled ONLY by the `native-shared` test crate (see
//! `lib.rs`), never by the napi twins — the `#[napi]` fns in the include!'d
//! implementation are plain Rust fns at test time: calling them needs no JS
//! runtime, only module REGISTRATION does. These tests execute the exact
//! source `ohos-native` compiles, on the build host, with no OHOS device and
//! no Electron build. Executing the TRUE `#[napi]`/ArkTS exports still needs a
//! real OHOS/ArkWeb process (ohos-native's `lib.test = false`; its
//! `tests/binding_confinement_test.rs` pins the offline-core floor level).
//!
//! Concurrency contract: SESSION is a process-global `OnceLock` with no
//! re-lock, so every session-touching scenario serializes through LANE_LOCK
//! and the locked-vs-unlocked phases run IN ORDER inside one #[test] — locked
//! fail-closed semantics are only observable before the first unlock.
//! DRIVE_CONFINEMENT (offline-core) is likewise process-global; the drive
//! phase installs and resets the policy under the same lock.

use super::*;
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard};

static LANE_LOCK: Mutex<()> = Mutex::new(());

fn lane_guard() -> MutexGuard<'static, ()> {
    match LANE_LOCK.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(), // a prior panic must not cascade
    }
}

/// std-only temp fixture (this crate deliberately carries no
/// dev-dependencies); the directory is removed on drop.
struct LaneDir(PathBuf);

impl LaneDir {
    fn new(tag: &str) -> Self {
        let p = std::env::temp_dir().join(format!(
            "ns-shared-lane-{}-{}-{}",
            tag,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        std::fs::create_dir_all(&p).expect("create temp dir");
        LaneDir(p)
    }
    fn path(&self) -> String {
        self.0.to_string_lossy().to_string()
    }
}

impl Drop for LaneDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn expect_reason<T>(result: napi::Result<T>, fragment: &str, what: &str) {
    match result {
        Ok(_) => panic!("{what}: expected an error containing {fragment:?}, got Ok"),
        Err(e) => assert!(
            e.reason.contains(fragment),
            "{what}: expected reason containing {fragment:?}, got {:?}",
            e.reason
        ),
    }
}

/// One ordered pass over the boundary contract the shared wrappers owe the
/// shells: locked fail-closed matrix → unlock semantics → per-plane
/// round-trips → drive AsyncTask denial delegation. See the phase fns.
#[test]
fn napi_boundary_delegation_contract() {
    let _lane = lane_guard();
    let dir = LaneDir::new("contract");

    locked_session_fails_closed();
    unlock_is_fail_closed_replacing(&format!("{}/guard.db", dir.path()));
    secure_store_round_trip();
    vault_surfaces_on_fresh_vault();
    mam_projection_and_wipe_latch();
    db_plane_allows_and_refuses(&format!("{}/cache.db", dir.path()));
    batch_and_migration_plane(&dir);
    recovery_blob_plane(&format!("{}/blob.db", dir.path()));
    drive_tasks_delegate_to_the_floor(&dir);
}

/// Before any unlock, every session-guarded export must throw "vault locked";
/// only the documented null-form projections answer (`secure_store_get` →
/// None, `mam_get_policy` → None, `mam_is_wiped` → false — SEC-STATE-FAILOPEN:
/// unknown state, never a compliance answer). The wrappers' own argument
/// validation (blob size/offset) runs BEFORE the session check, locked or not.
fn locked_session_fails_closed() {
    assert!(!vault_is_unlocked().unwrap());
    assert!(secure_store_get("k".into()).unwrap().is_none());
    assert!(mam_get_policy().unwrap().is_none());
    assert!(!mam_is_wiped().unwrap());

    expect_reason(vault_list_totp(), "vault locked", "locked list totp");
    expect_reason(
        vault_generate_totp("id".into()),
        "vault locked",
        "locked generate totp",
    );
    expect_reason(push_device_public_key(), "vault locked", "locked push key");
    expect_reason(
        secure_store_set("k".into(), "v".into()),
        "vault locked",
        "locked secure set",
    );
    expect_reason(
        secure_store_remove("k".into()),
        "vault locked",
        "locked secure remove",
    );
    expect_reason(
        mam_store_device_id("d".into()),
        "vault locked",
        "locked mam device id",
    );
    expect_reason(
        mam_store_policy("{}".into()),
        "vault locked",
        "locked mam store policy",
    );
    expect_reason(mam_mark_wiped(), "vault locked", "locked mark wiped");
    expect_reason(mam_clear_wiped(), "vault locked", "locked clear wiped");

    expect_reason(
        db_open("x.db".into(), "app".into(), "standard".into()),
        "vault locked",
        "locked db open",
    );
    expect_reason(
        db_is_open("app".into()),
        "vault locked",
        "locked db is open",
    );
    expect_reason(
        db_exec("app".into(), "SELECT 1".into(), "[]".into()),
        "vault locked",
        "locked db exec",
    );
    expect_reason(
        db_query("app".into(), "SELECT 1".into(), "[]".into()),
        "vault locked",
        "locked db query",
    );
    expect_reason(
        db_exec_schema_init("app".into(), "CREATE TABLE t(a)".into()),
        "vault locked",
        "locked schema init",
    );
    expect_reason(db_wipe("app".into()), "vault locked", "locked db wipe");
    expect_reason(
        db_transaction_batch("app".into(), r#"[{"sql":"SELECT 1"}]"#.into(), "{}".into()),
        "vault locked",
        "locked transaction batch",
    );
    expect_reason(
        db_migrate_store("app".into(), 2),
        "vault locked",
        "locked migrate store",
    );

    // Wrapper-level argument validation precedes the session check.
    expect_reason(
        recovery_blob_write_begin("app".into(), "a".repeat(64), 0),
        "blob size must be positive",
        "locked blob begin size=0",
    );
    expect_reason(
        recovery_blob_write_chunk("app".into(), "h".into(), -1, vec![1u8].into()),
        "blob offset must be non-negative",
        "locked blob chunk offset=-1",
    );
    expect_reason(
        recovery_blob_read_chunk("app".into(), "h".into(), -1, 1),
        "blob offset must be non-negative",
        "locked blob read offset=-1",
    );
    // With valid arguments it is the locked session that refuses.
    expect_reason(
        recovery_blob_write_begin("app".into(), "a".repeat(64), 8),
        "vault locked",
        "locked blob begin",
    );
}

/// `CapabilitySession::unlock` replaces the whole capability generation (its
/// doc: a failed attempt is fail-closed and cannot leave an older unlocked
/// core reachable). A wrong passphrase on an EXISTING vault returns `false` —
/// never an error — and leaves NOTHING unlocked; a first open on a fresh path
/// creates the vault under that passphrase.
fn unlock_is_fail_closed_replacing(vault_path: &str) {
    assert!(
        vault_unlock(vault_path.to_string(), "lane-passphrase".into()).unwrap(),
        "first open on a fresh path must create + unlock"
    );
    assert!(vault_is_unlocked().unwrap());

    assert!(
        !vault_unlock(vault_path.to_string(), "wrong-passphrase".into()).unwrap(),
        "wrong passphrase on an existing vault must return false"
    );
    assert!(
        !vault_is_unlocked().unwrap(),
        "a failed unlock must not leave the old core reachable"
    );

    assert!(vault_unlock(vault_path.to_string(), "lane-passphrase".into()).unwrap());
    assert!(vault_is_unlocked().unwrap());
}

/// Vault-backed key/value plane: set → get → remove → absent.
fn secure_store_round_trip() {
    secure_store_set("ss-lane-key".into(), "v1".into()).unwrap();
    assert_eq!(
        secure_store_get("ss-lane-key".into()).unwrap().as_deref(),
        Some("v1")
    );
    secure_store_remove("ss-lane-key".into()).unwrap();
    assert!(secure_store_get("ss-lane-key".into()).unwrap().is_none());
}

/// Fresh-vault guard surfaces reachable through the wrappers: empty TOTP
/// list, unknown-id generation fails closed, and the push registration key is
/// raw 65-byte uncompressed SEC1, hex-encoded.
fn vault_surfaces_on_fresh_vault() {
    assert!(vault_list_totp().unwrap().is_empty());
    assert!(
        vault_generate_totp("no-such-account".into()).is_err(),
        "unknown TOTP id must fail closed"
    );
    let key = push_device_public_key().unwrap();
    assert_eq!(key.len(), 130, "65-byte SEC1 as hex, got: {key}");
    assert!(key.bytes().all(|b| b.is_ascii_hexdigit()));
}

/// MAM value cache through the wrappers: DTO-shaped JSON round-trips,
/// malformed policy is refused at the boundary, and the durable wipe latch
/// cycles mark → is → clear.
fn mam_projection_and_wipe_latch() {
    mam_store_device_id("device-lane-1".into()).unwrap();
    mam_store_policy(
        r#"{"policy_version":42,"copy_paste":"block_external","screen_capture":"block","encryption":"required","watermark":true,"notification_profile":"silent","max_offline_days":7}"#
            .into(),
    )
    .unwrap();
    let policy = mam_get_policy().unwrap().expect("policy must be cached");
    assert!(
        policy.contains(r#""policy_version":42"#),
        "round-tripped policy: {policy}"
    );

    expect_reason(
        mam_store_policy("not-json".into()),
        "bad policy JSON",
        "malformed policy",
    );

    assert!(!mam_is_wiped().unwrap());
    mam_mark_wiped().unwrap();
    assert!(mam_is_wiped().unwrap());
    mam_clear_wiped().unwrap();
    assert!(!mam_is_wiped().unwrap());
}

/// The SQL plane's native floor as the wrappers surface it: single allowlisted
/// statements only for `db_exec`/`db_query`; multi-statement payloads refused
/// unconditionally; non-allowlisted keywords refused by the first-keyword
/// gate; the schema-init seam is the ONLY batch path, one-shot per connection,
/// where a REJECTED batch does not consume the gate and a SUCCESSFUL one
/// closes it.
fn db_plane_allows_and_refuses(db_path: &str) {
    let app = "lane-db".to_string();

    // An unopened key: `db_is_open` answers false, real statements refuse.
    assert!(!db_is_open(app.clone()).unwrap());
    expect_reason(
        db_exec(app.clone(), "SELECT 1".into(), "[]".into()),
        "store 'lane-db' not open",
        "exec on unopened store",
    );

    db_open(db_path.to_string(), app.clone(), "standard".into()).unwrap();
    assert!(db_is_open(app.clone()).unwrap());

    // DDL rows-changed counting is a SQLite detail — pin only that the single
    // allowlisted statement executes; the INSERT's count is the real contract.
    db_exec(
        app.clone(),
        "CREATE TABLE lane_t(v TEXT)".into(),
        "[]".into(),
    )
    .unwrap();
    assert_eq!(
        db_exec(
            app.clone(),
            "INSERT INTO lane_t(v) VALUES (?1)".into(),
            r#"["hello"]"#.into()
        )
        .unwrap(),
        1.0
    );
    assert_eq!(
        db_query(app.clone(), "SELECT v FROM lane_t".into(), "[]".into()).unwrap(),
        r#"[{"v":"hello"}]"#
    );

    expect_reason(
        db_exec(
            app.clone(),
            "INSERT INTO lane_t(v) VALUES ('a'); DROP TABLE lane_t".into(),
            "[]".into(),
        ),
        "multi-statement SQL is refused",
        "multi-statement exec",
    );
    expect_reason(
        db_exec(app.clone(), "PRAGMA user_version = 3".into(), "[]".into()),
        "statement not allowed",
        "PRAGMA via exec",
    );
    expect_reason(
        db_query(app.clone(), "PRAGMA user_version".into(), "[]".into()),
        "statement not allowed",
        "PRAGMA via query",
    );

    // A rejected batch consumes nothing — the valid batch after it still
    // initializes, and only THEN does the one-shot gate close.
    expect_reason(
        db_exec_schema_init(
            app.clone(),
            "CREATE TABLE s1(a); PRAGMA user_version = 3".into(),
        ),
        "batch rejected: statement 2 keyword 'PRAGMA'",
        "batch containing PRAGMA",
    );
    assert_eq!(
        db_exec_schema_init(
            app.clone(),
            "CREATE TABLE lane_s1(a TEXT); CREATE TABLE lane_s2(a TEXT)".into()
        )
        .unwrap(),
        0.0
    );
    expect_reason(
        db_exec_schema_init(app.clone(), "CREATE TABLE lane_s3(a TEXT)".into()),
        "one-shot init gate",
        "replayed schema init",
    );

    db_wipe(app).unwrap();
    assert!(!db_is_open("lane-db".into()).unwrap());
}

/// The E4-I atomic job batch + bundled migration entries as the wrappers
/// surface them (`db_transaction_batch` / `db_migrate_store` — the napi-level
/// source of `window.setjoinNative.db.transactionBatch`/`.migrateStore`):
/// paired refusals and success per the freeze oracles — reads/DML-only
/// batches committing atomically with a changed-row total, transaction
/// control/DDL/smuggling refused BEFORE mutation, one bad statement rolling
/// back the whole batch, migration via the BUNDLED manifest only (foreign
/// apps and unknown/ahead/downgrade versions refused) with reopen/version
/// assertions.
fn batch_and_migration_plane(dir: &LaneDir) {
    const BUDGET: &str = r#"{"maxStatements":64,"maxParamBytes":1048576}"#;
    // The appKey IS the manifest namespace — the bundled manifest covers
    // exactly 'mail' (real callers; 'lane-*' keys would be refused).
    let app = "mail".to_string();
    db_open(
        format!("{}/mail.db", dir.path()),
        app.clone(),
        "standard".into(),
    )
    .unwrap();

    // Migration through the bundled manifest: fresh → v2, JSON-version result.
    assert_eq!(
        db_migrate_store(app.clone(), 2).unwrap(),
        r#"{"version":2}"#
    );
    // A current store re-migrating is a clean no-op at the same version.
    assert_eq!(
        db_migrate_store(app.clone(), 2).unwrap(),
        r#"{"version":2}"#
    );

    // Batch happy path over the migrated schema: two inserts + one update.
    let changed = db_transaction_batch(
        app.clone(),
        r#"[
            {"sql": "INSERT INTO messages (id, thread_id) VALUES (?1, ?2)", "params": ["m1", "t1"]},
            {"sql": "INSERT INTO message_tags (message_id, tag_id) VALUES (?1, ?2)", "params": ["m1", "inbox"]},
            {"sql": "UPDATE messages SET thread_id = ?1 WHERE id = ?2", "params": ["t2", "m1"]}
        ]"#
        .into(),
        BUDGET.into(),
    )
    .unwrap();
    assert_eq!(changed, 3.0, "two inserts + one update");
    assert!(
        db_query(
            app.clone(),
            "SELECT id FROM messages WHERE id = ?1".into(),
            r#"["m1"]"#.into(),
        )
        .unwrap()
        .contains("m1")
    );
    // Reads are admitted (freeze read/DML contract) and add no changed rows.
    assert_eq!(
        db_transaction_batch(
            app.clone(),
            r#"[{"sql": "SELECT id FROM messages", "params": []}]"#.into(),
            BUDGET.into(),
        )
        .unwrap(),
        0.0
    );

    // Refused shapes — every denial precedes mutation.
    for (what, statements) in [
        (
            "batch empty",
            "[]" ,
        ),
        (
            "batch transaction control",
            r#"[{"sql": "BEGIN"}, {"sql": "INSERT INTO messages (id) VALUES ('x')}]"#,
        ),
        (
            "batch DDL",
            r#"[{"sql": "CREATE TABLE stolen (x)}]"#,
        ),
        (
            "batch smuggled multi-statement",
            r#"[{"sql": "INSERT INTO messages (id) VALUES ('a'); INSERT INTO messages (id) VALUES ('b')}]"#,
        ),
        (
            "batch budget overflow",
            r#"[{"sql": "INSERT INTO messages (id) VALUES (?1)", "params": ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]}]"#,
        ),
        (
            "batch bad statements JSON",
            "not json",
        ),
    ] {
        let budget = if what == "batch budget overflow" {
            r#"{"maxStatements":64,"maxParamBytes":16}"#.to_string()
        } else {
            BUDGET.to_string()
        };
        expect_reason(
            db_transaction_batch(app.clone(), statements.into(), budget),
            "batch rejected",
            what,
        );
    }
    // The refusals left nothing behind.
    assert_eq!(
        db_query(
            app.clone(),
            "SELECT count(*) AS n FROM messages".into(),
            "[]".into(),
        )
        .unwrap(),
        r#"[{"n":1}]"#,
        "only the happy-path row survives"
    );

    // Atomicity: statement 2 fails → statement 1 rolls back, statement 3
    // never runs, and the failure itself surfaces.
    expect_reason(
        db_transaction_batch(
            app.clone(),
            r#"[
                {"sql": "INSERT INTO messages (id) VALUES (?1)", "params": ["doomed"]},
                {"sql": "UPDATE messages SET no_such_column = 1"},
                {"sql": "INSERT INTO messages (id) VALUES (?1)", "params": ["never"]}
            ]"#
            .into(),
            BUDGET.into(),
        ),
        "no such column",
        "mid-batch SQL failure",
    );
    assert_eq!(
        db_query(
            app.clone(),
            "SELECT count(*) AS n FROM messages WHERE id IN ('doomed','never')".into(),
            "[]".into(),
        )
        .unwrap(),
        r#"[{"n":0}]"#,
        "the whole batch rolled back"
    );

    // Migration refusals: a foreign app (its own store is open) and
    // unknown/ahead/downgrade targets on the mail store.
    let drive = "drive".to_string();
    db_open(
        format!("{}/drive.db", dir.path()),
        drive.clone(),
        "standard".into(),
    )
    .unwrap();
    expect_reason(
        db_migrate_store(drive, 2),
        "foreign-app",
        "migrate foreign app",
    );
    for target in [0, 3, 1] {
        let what = format!("migrate target {target}");
        expect_reason(
            db_migrate_store(app.clone(), target),
            "migration refused",
            &what,
        );
    }

    db_wipe(app).unwrap();
    db_wipe("lane-drive".into()).unwrap();
}

/// The generic recovery blob plane through the wrappers: boundary argument
/// validation, an ordered write → commit → read → ref cycle with content
/// verification, overlap denial, and abort discarding a partial write.
fn recovery_blob_plane(db_path: &str) {
    let app = "lane-blob".to_string();
    db_open(db_path.to_string(), app.clone(), "standard".into()).unwrap();

    // Commit verifies the chunk bytes against the DECLARED content digest, so
    // declare the real one: sha256("hello").
    let sha = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824".to_string();
    let begin = recovery_blob_write_begin(app.clone(), sha.clone(), 5).unwrap();
    let v: serde_json::Value = serde_json::from_str(&begin).unwrap();
    let handle = v["handle"].as_str().expect("write handle").to_string();
    assert_eq!(v["nextOffset"].as_i64(), Some(0));

    assert_eq!(
        recovery_blob_write_chunk(app.clone(), handle.clone(), 0, b"hello".to_vec().into())
            .unwrap(),
        5.0
    );
    // Replaying a DIFFERENT payload at an accepted offset is corruption, not
    // idempotence.
    expect_reason(
        recovery_blob_write_chunk(app.clone(), handle.clone(), 0, b"XXXXX".to_vec().into()),
        "overlapping blob chunk",
        "overlapping chunk",
    );
    // Re-beginning the same digest/size is the resume cursor.
    let resume = recovery_blob_write_begin(app.clone(), sha.clone(), 5).unwrap();
    assert!(
        resume.contains(r#""nextOffset":5"#),
        "resume must acknowledge the accepted chunk: {resume}"
    );
    assert_eq!(
        recovery_blob_write_commit(app.clone(), handle).unwrap(),
        sha,
        "commit returns the verified digest"
    );

    let open = recovery_blob_read_open(app.clone(), sha.clone()).unwrap();
    let v: serde_json::Value = serde_json::from_str(&open).unwrap();
    let read_handle = v["handle"].as_str().expect("read handle").to_string();
    assert_eq!(v["size"].as_i64(), Some(5));
    assert_eq!(
        recovery_blob_read_chunk(app.clone(), read_handle.clone(), 0, 5)
            .unwrap()
            .to_vec(),
        b"hello".to_vec()
    );
    recovery_blob_read_close(app.clone(), read_handle).unwrap();

    assert_eq!(recovery_blob_ref(app.clone(), sha.clone()).unwrap(), 1.0);
    assert_eq!(recovery_blob_unref(app.clone(), sha).unwrap(), 0.0);

    // Abort discards the partial write; a fresh begin for the same digest
    // starts over at offset 0 (the aborted handle is gone).
    let sha2 = "cd".repeat(32);
    let b2 = recovery_blob_write_begin(app.clone(), sha2.clone(), 4).unwrap();
    let v: serde_json::Value = serde_json::from_str(&b2).unwrap();
    let h2 = v["handle"].as_str().expect("abort handle").to_string();
    recovery_blob_write_chunk(app.clone(), h2.clone(), 0, b"abcd".to_vec().into()).unwrap();
    recovery_blob_write_abort(app.clone(), h2).unwrap();
    let restarted = recovery_blob_write_begin(app.clone(), sha2, 4).unwrap();
    assert!(
        restarted.contains(r#""nextOffset":0"#),
        "aborted write must restart from zero: {restarted}"
    );
}

/// The drive AsyncTask bodies (`compute()` — the exact code the libuv/OHOS
/// worker thread runs) delegate to the same process-global fail-closed floor
/// the integration tests pin at the offline-core level: deny-by-default,
/// trusted-root containment for imports, approved-origin equality for chunk
/// URLs — with an approved loopback origin passing the gate pre-DNS and
/// failing cleanly at the connect. The policy is reset to the deny-by-default
/// state on exit.
fn drive_tasks_delegate_to_the_floor(dir: &LaneDir) {
    let app = "drive".to_string();
    db_open(
        format!("{}/drive.db", dir.path()),
        app.clone(),
        "standard".into(),
    )
    .unwrap();

    drive_set_confinement(vec![], vec![]); // the explicit process default
    let src = dir.0.join("outside.bin");
    std::fs::write(&src, b"importable").unwrap();
    expect_reason(
        DriveImportFileTask {
            app_key: app.clone(),
            src_path: src.to_string_lossy().to_string(),
        }
        .compute(),
        "no trusted import roots",
        "task import, empty policy",
    );
    expect_reason(
        DriveFetchChunkTask {
            app_key: app.clone(),
            url: "https://drive.example.org/v1/chunks/aa".into(),
            bearer: "b".into(),
            sha256: "aa".into(),
            size: 1,
        }
        .compute(),
        "no approved chunk origins",
        "task fetch, empty policy",
    );
    expect_reason(
        DrivePushChunkTask {
            app_key: app.clone(),
            url: "https://drive.example.org/v1/chunks/aa".into(),
            bearer: "b".into(),
            sha256: "aa".into(),
        }
        .compute(),
        "no approved chunk origins",
        "task push, empty policy",
    );

    // With a trusted root installed, a file under a sibling directory that no
    // composition approved is still refused by the task body.
    let root = dir.0.join("imports");
    std::fs::create_dir_all(&root).unwrap();
    drive_set_confinement(
        vec![root.to_string_lossy().to_string()],
        vec!["https://drive.example.org".into()],
    );
    expect_reason(
        DriveImportFileTask {
            app_key: app.clone(),
            src_path: src.to_string_lossy().to_string(),
        }
        .compute(),
        "resolves outside every trusted import root",
        "task import outside root",
    );

    // An APPROVED loopback origin passes the gate (pre-DNS) and fails at the
    // connect — the error is network-shaped, not a URL rejection.
    drive_set_confinement(vec![], vec!["http://127.0.0.1:9".into()]);
    let net_err = DriveFetchChunkTask {
        app_key: app.clone(),
        url: "http://127.0.0.1:9/v1/chunks/aa".into(),
        bearer: "b".into(),
        sha256: "aa".into(),
        size: 1,
    }
    .compute()
    .expect_err("nothing listens on the discard port");
    assert!(
        !net_err.reason.contains("url rejected"),
        "an approved origin must not be gate-rejected: {:?}",
        net_err.reason
    );

    // Loopback serve bookkeeping through the task + sync export; stop is
    // idempotent.
    let serve = DriveServeStartTask {
        app_key: app.clone(),
    }
    .compute()
    .unwrap();
    assert!(serve.contains("\"port\":"), "serve json: {serve}");
    drive_serve_stop(app.clone()).unwrap();
    drive_serve_stop(app.clone()).unwrap();

    // Leave the process in the deny-by-default state.
    drive_set_confinement(vec![], vec![]);
    assert!(!drive_has_chunk(app, "ab".repeat(32)).unwrap());
}
