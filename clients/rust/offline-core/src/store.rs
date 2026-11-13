/// Generic SQLCipher store — schema-agnostic.
///
/// The mail schema is NOT Rust: it is applied as TS migrations through the
/// bridge (Task 8). offline-core opens an empty keyed DB and executes what
/// the TS layer sends: `exec`/`query` run SINGLE allowlisted statements only;
/// a multi-statement DDL batch is accepted exclusively through
/// `exec_schema_init` — the authorized, one-shot-per-connection schema
/// initialization path (med-offcore-sqlguard-001 r2).
///
/// The SQLCipher key is NEVER returned to JS or over the bridge — it is
/// applied in-process here only.
use rusqlite::{params_from_iter, Connection};
use serde_json::Value;
use std::collections::HashSet;
use std::sync::{Mutex, OnceLock};
use thiserror::Error;
use zeroize::Zeroize;

#[derive(Debug, Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum OfflineError {
    #[error("database: {0}")]
    Database(String),
    #[error("crypto: {0}")]
    Crypto(String),
    #[error("guard: {0}")]
    Guard(String),
    /// Chunk hash/size verification failed — nothing was stored (Drive spec §3.6).
    #[error("integrity: {0}")]
    Integrity(String),
    /// Native TLS handshake failed — almost always a private CA missing from the
    /// OS trust store (rustls-platform-verifier trusts the OS store ONLY; grill G,
    /// ARCH-017). Callers (the SPA, via the napi bridge) map this to the
    /// drive.sync.tlsUntrusted hint. Never bypass verification; never pin here.
    #[error("tls: {0}")]
    Tls(String),
    /// Native HTTP transport/status failure (non-TLS).
    #[error("http: {0}")]
    Http(String),
}

/// Classify a ureq transport error message. TLS-trust failures become the typed
/// `Tls` variant so callers can render the install-the-org-CA hint instead of a
/// generic sync error (grill G — the private-CA footgun surfaces at vault sync
/// time, not login time).
/// ponytail: substring classification over ureq's flattened error text; upgrade
/// to matching ureq's error-kind variants directly if a future ureq exposes the
/// underlying rustls error natively.
pub fn classify_transport(msg: &str, _tls_capable: bool) -> OfflineError {
    let m = msg.to_ascii_lowercase();
    if m.contains("certificate")
        || m.contains("unknownissuer")
        || m.contains("tls")
        || m.contains("handshake")
    {
        OfflineError::Tls(format!(
            "server certificate not trusted by this device — install the organization CA \
             into the OS trust store (same CA the browser/WebView uses): {msg}"
        ))
    } else {
        OfflineError::Http(msg.to_string())
    }
}

impl From<rusqlite::Error> for OfflineError {
    fn from(e: rusqlite::Error) -> Self {
        OfflineError::Database(e.to_string())
    }
}

// ── Statement allowlist ───────────────────────────────────────────────────────
//
// First-keyword allowlist, enforced here (not only at the TS/ArkTS bridge
// layer) so every caller of the safe Rust API is covered too — not just
// platforms that route through a bridge check. PRAGMA / ATTACH / DETACH /
// VACUUM are deliberately absent: a lone PRAGMA/ATTACH/DETACH/VACUUM statement
// is rejected by this first-keyword check, and a statement smuggled into a
// multi-statement batch in ANY position is rejected by the structural
// per-statement validation in `exec_schema_batch` below — before a single
// statement executes. Multi-statement input never reaches that validator
// through `exec` at all: ordinary exec is single-statement by contract
// (med-offcore-sqlguard-001 r2).
const STMT_ALLOWED_KWS: &[&str] = &[
    "SELECT",
    "INSERT",
    "UPDATE",
    "DELETE",
    "CREATE",
    "DROP",
    "WITH",
    "BEGIN",
    "COMMIT",
    "ROLLBACK",
    "SAVEPOINT",
    "RELEASE",
];

/// Statement classes permitted INSIDE a validated schema-migration batch
/// (see `exec_schema_batch`). Transaction control (BEGIN/COMMIT/…), reads
/// (SELECT/WITH) and every side-effecting-outside-the-store class (PRAGMA,
/// ATTACH, DETACH, VACUUM) are never batch-valid: the TS layer drives
/// transactions and reads as single statements through `exec`/`query`.
/// Extending this list is an explicit contract change — the batch path is
/// reachable ONLY through `exec_schema_init`, the authorized one-shot
/// schema-initialization path (med-offcore-sqlguard-001 r2); any additional
/// future batch consumer must extend this allowlist deliberately.
const BATCH_STMT_ALLOWED_KWS: &[&str] = &["CREATE", "ALTER", "DROP", "INSERT", "UPDATE", "DELETE"];

/// Uppercased leading keyword of `sql` (first whitespace-delimited token).
/// Deliberately naive: a leading comment or parenthesis fails the allowlist
/// (fail-closed), matching the bridge-layer extraction.
fn first_keyword(sql: &str) -> String {
    sql.trim_start()
        .split_ascii_whitespace()
        .next()
        .unwrap_or("")
        .to_ascii_uppercase()
}

/// Authoritative first-keyword allowlist gate. Single source of truth for which
/// leading SQL keyword the offline store accepts. The per-shell bridges (e.g.
/// src-tauri `bridge.rs`) delegate to this instead of keeping their own copy, so
/// a shell can never widen the gate. The dependency points one way only
/// (shell → store); store.rs never imports a shell's list.
pub fn stmt_is_allowed(sql: &str) -> bool {
    STMT_ALLOWED_KWS.contains(&first_keyword(sql).as_str())
}

impl From<serde_json::Error> for OfflineError {
    fn from(e: serde_json::Error) -> Self {
        OfflineError::Database(format!("json: {e}"))
    }
}

/// Apply the SQLCipher PRAGMA key on a freshly-opened connection.
///
/// Call ONCE immediately after `Connection::open`, before any other SQL.
/// Uses the raw-key form (`PRAGMA key="x'...'"`) so SQLCipher uses the 32 bytes
/// directly with no extra KDF (guard-core already ran Argon2id + per-appKey derivation).
/// Verifies the key is correct by probing sqlite_master; a wrong key fails HERE.
///
/// Key-material hygiene (OFFSTORE-KEY-ZEROIZE-GAP): the PRAGMA/hex heap strings
/// built HERE are zeroized before return; the CALLER owns the key buffer and
/// passes it zeroize-on-drop (`open_store` wraps the provisioned subkey in
/// `Zeroizing`). By design, SQLCipher's codec context must retain the raw key
/// for the connection's lifetime and SQLite retains PRAGMA statement text —
/// that residual is the documented posture, not a Rust-side gap.
/// ponytail: raw-key form; swap to passphrase form if interop with external tooling requires it.
pub fn apply_pragma_key(conn: &Connection, key: &[u8; 32]) -> Result<(), OfflineError> {
    let mut hex_key = hex::encode(key);
    let mut pragma = format!("PRAGMA key = \"x'{hex_key}'\";");
    let result = conn
        .execute_batch(&pragma)
        .map_err(|e| OfflineError::Crypto(format!("PRAGMA key: {e}")));
    pragma.zeroize();
    hex_key.zeroize();
    result?;
    // Touch the DB so a wrong key fails HERE (cipher integrity check).
    conn.query_row("SELECT count(*) FROM sqlite_master", [], |r| {
        r.get::<_, i64>(0)
    })
    .map_err(|_| OfflineError::Crypto("wrong key".into()))?;
    Ok(())
}

/// Execute a SINGLE allowlisted SQL statement with JSON-array params.
///
/// `params_json` is a JSON array of scalars, e.g. `["val1", 42, null]`.
/// Returns the count of rows changed.
///
/// Security: SQL comes from trusted TS statements or the native allowlist
/// (ARCH-013 decision 4); params are bound, never interpolated.
///
/// Single statements take the bound-params path; the leading keyword must be
/// allowlisted (`stmt_is_allowed`).
///
/// med-offcore-sqlguard-001 r2: `exec` is SINGLE-STATEMENT by contract.
/// Whether a payload is multi-statement is decided structurally
/// (quote/comment-aware split), not by counting `;` characters — a `;` inside
/// a string literal or comment is not a boundary. Multi-statement input is
/// refused unconditionally (with or without params): batches execute ONLY
/// through `exec_schema_init`, the authorized one-shot schema-initialization
/// path, so an ordinary (renderer-reachable) caller can never replay
/// allowlisted-keyword batch payloads (CREATE/ALTER/DROP/INSERT/UPDATE/DELETE
/// …) against the store.
pub fn exec(conn: &Connection, sql: &str, params_json: &str) -> Result<u64, OfflineError> {
    if !stmt_is_allowed(sql) {
        return Err(OfflineError::Database(
            "statement not allowed: first keyword blocked".into(),
        ));
    }
    let params = parse_params(params_json)?;
    if split_statements(sql).len() > 1 {
        return Err(OfflineError::Database(
            "multi-statement SQL is refused by exec(): only single allowlisted statements \
             run here; schema initialization batches must go through the authorized one-shot \
             init path (exec_schema_init)"
                .into(),
        ));
    }
    let n = conn.execute(sql, params_from_iter(params.iter().map(value_to_sql)))?;
    Ok(n as u64)
}

// ── One-shot schema-initialization gate (med-offcore-sqlguard-001 r2) ────────
//
// The authorized batch path is one-shot PER CONNECTION: the DDL batch is
// applied exactly once per open (`open_store` creates a fresh connection per
// session, and the TS layer's idempotent re-init on reopen lands on a fresh
// gate). After the first SUCCESSFUL batch on a connection, every later batch
// attempt through the authorized path is refused — the gate cannot be
// re-armed by anything renderer-reachable because it lives in native process
// memory, keyed by the live connection's address (never in a SQL-readable
// table: renderer-writable single-statement INSERT/DELETE could otherwise
// erase or forge the marker).
//
// ponytail: keyed by `std::ptr::from_ref(conn)` — two LIVE connections never
// share an address, so concurrent stores cannot interfere. An address reused
// by a LATER connection after a prior one was dropped would fail CLOSED (its
// authorized init refused as already-consumed — an availability cost, never a
// security hole; connections are long-lived per open_store). Tests reset the
// marker for one connection via `__reset_schema_init_gate_for_tests` to stay
// deterministic across allocator reuse.
static SCHEMA_INIT_CONSUMED: OnceLock<Mutex<HashSet<usize>>> = OnceLock::new();

fn schema_init_slot() -> &'static Mutex<HashSet<usize>> {
    SCHEMA_INIT_CONSUMED.get_or_init(|| Mutex::new(HashSet::new()))
}

fn conn_gate_key(conn: &Connection) -> usize {
    std::ptr::from_ref(conn) as usize
}

/// The authorized schema-initialization path — the ONLY way a multi-statement
/// batch executes (med-offcore-sqlguard-001 r2).
///
/// One-shot per connection: the whole batch is structurally validated first
/// (`exec_schema_batch` — per-statement allowlist, nothing executes unless the
/// batch validates completely), executed, and only then is the connection's
/// gate consumed. A REJECTED batch does not consume the gate (the store stays
/// initializable); an already-consumed connection refuses every later batch —
/// replaying this seam can never run arbitrary allowlisted-keyword batches
/// against an initialized store.
pub fn exec_schema_init(conn: &Connection, sql: &str) -> Result<u64, OfflineError> {
    let key = conn_gate_key(conn);
    {
        let consumed = schema_init_slot()
            .lock()
            .expect("schema-init gate lock poisoned");
        if consumed.contains(&key) {
            return Err(OfflineError::Database(
                "schema initialization already performed on this store connection; later \
                 batches are refused (one-shot init gate)"
                    .into(),
            ));
        }
    }
    let result = exec_schema_batch(conn, sql);
    if result.is_ok() {
        schema_init_slot()
            .lock()
            .expect("schema-init gate lock poisoned")
            .insert(key);
    }
    result
}

/// TEST-ONLY (doc-hidden): drop the one-shot schema-init marker for ONE
/// connection. Integration tests open and drop many connections in a single
/// process; without this, allocator address reuse could make a fresh test
/// connection inherit a dead connection's consumed marker (fail-closed
/// flakiness). Production code never calls it, and its only effect is
/// permitting the FIRST authorized init of the exact connection passed in —
/// it cannot widen the batch validator or re-open any other connection's
/// gate.
#[doc(hidden)]
pub fn __reset_schema_init_gate_for_tests(conn: &Connection) {
    if let Ok(mut consumed) = schema_init_slot().lock() {
        consumed.remove(&conn_gate_key(conn));
    }
}

/// Validate and execute a schema-migration batch — the ONLY multi-statement
/// path, reachable ONLY through `exec_schema_init` (pub(crate): no caller
/// outside this crate can execute a batch, so the "authorized init path only"
/// contract is compiler-enforced for every bridge, shell and test crate).
///
/// The batch is structurally split into statements (`split_statements`), and
/// EVERY statement is independently allowlisted against
/// `BATCH_STMT_ALLOWED_KWS`. Nothing executes unless the whole batch validates:
/// a rejected batch has no partial effects. Side-effecting statements —
/// `PRAGMA` (e.g. `rekey`), `ATTACH`/`DETACH`, and `VACUUM INTO <path>` (which
/// copies the entire store-keyed database file to an arbitrary process-writable
/// path, a copy that would also survive `OfflineCore::wipe`) — are rejected in
/// any position, as are reads and transaction control.
pub(crate) fn exec_schema_batch(conn: &Connection, sql: &str) -> Result<u64, OfflineError> {
    let stmts = split_statements(sql);
    if stmts.is_empty() {
        return Err(OfflineError::Database(
            "batch rejected: no SQL statements found".into(),
        ));
    }
    for (idx, stmt) in stmts.iter().enumerate() {
        let kw = first_keyword(stmt);
        if !BATCH_STMT_ALLOWED_KWS.contains(&kw.as_str()) {
            let pos = idx + 1;
            return Err(OfflineError::Database(format!(
                "multi-statement batch rejected: statement {pos} keyword '{kw}' is not allowed \
                 (PRAGMA, ATTACH, DETACH, VACUUM and other side-effecting statements are never \
                 permitted in a batch)"
            )));
        }
    }
    // Every statement validated; execute in order. A SQL-level failure aborts
    // the remainder (same surface as execute_batch had).
    for stmt in &stmts {
        conn.execute_batch(stmt)?;
    }
    Ok(0)
}

// ── E4-I authorized atomic job batch (connectivity-native-transaction-freeze) ──
//
// The batch entry owns transaction control: ONE connection, ONE transaction,
// the whole bounded batch committed or nothing applied. Reachable ONLY through
// the napi bridge's `db_transaction_batch` (the shells' `db.transactionBatch`
// projection); ordinary `exec`/`query` stay single-statement. The TS layer
// (`$lib/offline/nativeBatch`) pre-admits with the same contract — this native
// validator is the authority, so the floor holds even when a caller skips the
// TS checks (the r2/r3 posture: no per-shell keyword copy is trusted).

/// Statement classes permitted INSIDE one authorized job batch. Parameterized
/// reads and DML only — exactly the vocabulary the TS admission contract
/// (`nativeBatch.ts` ALLOWED_LEADING_KEYWORDS) admits: schema DDL (CREATE/
/// ALTER/DROP), transaction control (BEGIN/COMMIT/ROLLBACK/SAVEPOINT/RELEASE
/// and aliases) and every side-effecting class (PRAGMA/ATTACH/DETACH/VACUUM)
/// are refused BEFORE the transaction opens. Extending this list is an
/// explicit contract change (N66: DDL never rides the job batch).
const JOB_BATCH_STMT_ALLOWED_KWS: &[&str] = &[
    "SELECT", "INSERT", "UPDATE", "DELETE", "REPLACE", "WITH", "VALUES",
];

/// One deserialized batch statement (`statements_json` element).
#[derive(serde::Deserialize)]
pub struct BatchStatementDto {
    pub sql: String,
    #[serde(default)]
    pub params: Option<Vec<Value>>,
}

/// Aggregate admission budget for one batch (`budget_json`). The wire keys
/// are the camelCase names the TS contract serializes
/// (`NativeBatchBudget.maxStatements`/`.maxParamBytes`).
#[derive(serde::Deserialize)]
pub struct BatchBudgetDto {
    #[serde(rename = "maxStatements", default)]
    pub max_statements: Option<u64>,
    #[serde(rename = "maxParamBytes", default)]
    pub max_param_bytes: Option<u64>,
}

/// Validate and execute ONE bounded atomic batch. Every statement and the
/// aggregate budget are validated BEFORE the transaction opens: an empty
/// batch, a count/byte-budget overflow, a multi-statement payload smuggled
/// into one entry, or a single non-allowlisted keyword refuses the WHOLE
/// batch with no database effects. On any SQL-level failure the transaction
/// rolls back and the error surfaces — partial application is impossible.
/// Returns the total changed-row count across the committed batch.
pub fn exec_transaction_batch(
    conn: &Connection,
    statements: &[BatchStatementDto],
    budget: &BatchBudgetDto,
) -> Result<u64, OfflineError> {
    let max_statements = budget.max_statements.unwrap_or(0);
    let max_param_bytes = budget.max_param_bytes.unwrap_or(0);
    if statements.is_empty() {
        return Err(OfflineError::Database(
            "batch rejected: empty batch".into(),
        ));
    }
    if max_statements == 0 || max_param_bytes == 0 {
        return Err(OfflineError::Database(
            "batch rejected: budget must set positive maxStatements and maxParamBytes".into(),
        ));
    }
    if statements.len() as u64 > max_statements {
        return Err(OfflineError::Database(format!(
            "batch rejected: too many statements ({}, budget {max_statements})",
            statements.len()
        )));
    }
    // Validation pass — all params parsed and the byte budget measured before
    // any transaction exists. UTF-8 byte length of the statement text plus the
    // serialized params array mirrors the TS admission accounting.
    let mut prepared: Vec<(String, Vec<Value>)> = Vec::with_capacity(statements.len());
    let mut total_bytes: u64 = 0;
    for (idx, stmt) in statements.iter().enumerate() {
        let params = stmt.params.clone().unwrap_or_default();
        let bytes = serde_json::to_string(&params)?.len() as u64;
        // Structural multi-statement refusal (quote/comment-aware) — a ';'
        // inside a literal is not a boundary; a real separator in one entry is
        // smuggling and refuses the batch.
        let split = split_statements(&stmt.sql);
        if split.len() > 1 {
            return Err(OfflineError::Database(format!(
                "batch rejected: statement {} is a multi-statement payload",
                idx + 1
            )));
        }
        let kw = first_keyword(&stmt.sql);
        if !JOB_BATCH_STMT_ALLOWED_KWS.contains(&kw.as_str()) {
            return Err(OfflineError::Database(format!(
                "batch rejected: statement {} keyword '{kw}' is not allowed (job batches are \
                 parameterized reads/DML only; transaction control, DDL and side-effecting \
                 statements are never batch-valid)",
                idx + 1
            )));
        }
        total_bytes += stmt.sql.len() as u64 + bytes;
        if total_bytes > max_param_bytes {
            return Err(OfflineError::Database(format!(
                "batch rejected: aggregate bytes {total_bytes} exceed budget {max_param_bytes} \
                 (statement {})",
                idx + 1
            )));
        }
        prepared.push((stmt.sql.clone(), params));
    }
    // Execution pass — ONE transaction, no interleaving (the caller holds the
    // per-store connection for the whole batch). A failure rolls back. Read
    // statements (SELECT/WITH) are admitted per the freeze contract but return
    // no rows to the caller — the entry resolves with the total CHANGED-row
    // count — so row-returning statements are drained, not `execute`d.
    conn.execute_batch("BEGIN IMMEDIATE")?;
    let mut total_changed: u64 = 0;
    for (sql, params) in &prepared {
        let result = (|| -> Result<u64, rusqlite::Error> {
            let mut stmt = conn.prepare(sql)?;
            if stmt.column_count() > 0 {
                let mut rows = stmt.query(params_from_iter(params.iter().map(value_to_sql)))?;
                while rows.next()?.is_some() {}
                Ok(0)
            } else {
                Ok(stmt.execute(params_from_iter(params.iter().map(value_to_sql)))? as u64)
            }
        })();
        match result {
            Ok(n) => total_changed += n,
            Err(e) => {
                let _ = conn.execute_batch("ROLLBACK");
                return Err(e.into());
            }
        }
    }
    // COMMIT is a statement-failure class too (E6 Astra P3): a deferred
    // foreign-key constraint, a disk-I/O or full-disk error all surface at
    // COMMIT, not at a statement. Propagating it bare used to leave the
    // transaction open on this shared connection — every later batch then
    // died on "cannot start a transaction within a transaction" and only a
    // full store reopen recovered. Mirror the statement path above: attempt
    // the ROLLBACK first, then propagate the ORIGINAL commit failure. When
    // SQLite already auto-rolled the transaction back (some commit failures
    // do), the ROLLBACK itself errors ("no transaction is active") and that
    // secondary error is intentionally dropped — the connection is usable
    // again either way; recovery without a reopen is the contract here.
    if let Err(commit_err) = conn.execute_batch("COMMIT") {
        let _ = conn.execute_batch("ROLLBACK");
        return Err(commit_err.into());
    }
    Ok(total_changed)
}

/// Structurally split a SQL batch into individual statements.
///
/// Splits on `;` only OUTSIDE SQL quoting and comments: single-quoted strings
/// (`''` escaped), double-quoted and backtick identifiers (`""`/`` `` ``
/// escaped), `[bracket]` identifiers, `--` line comments and `/* */` block
/// comments (comments are replaced by a single space so the token stream
/// SQLite re-parses is unchanged). Trigger bodies (`BEGIN … ; … END;`)
/// intentionally split into pieces and are then rejected by the batch
/// allowlist — schema batches stay trigger-free (fail-closed); supporting
/// them would be an explicit contract extension. Unterminated quotes/comments
/// consume to end of input; the resulting statement fails SQLite parsing or
/// the allowlist — also fail-closed.
fn split_statements(sql: &str) -> Vec<String> {
    fn push_stmt(cur: &mut String, stmts: &mut Vec<String>) {
        let trimmed = cur.trim();
        if !trimmed.is_empty() {
            stmts.push(trimmed.to_string());
        }
        cur.clear();
    }

    let mut stmts = Vec::new();
    let mut cur = String::with_capacity(sql.len());
    let mut chars = sql.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\'' | '"' | '`' => {
                cur.push(c);
                // Quoted string/identifier: consume to the closing quote; a
                // doubled quote is an escaped literal quote, keep consuming.
                while let Some(qc) = chars.next() {
                    cur.push(qc);
                    if qc == c {
                        if chars.peek() == Some(&c) {
                            cur.push(c);
                            chars.next();
                        } else {
                            break;
                        }
                    }
                }
            }
            '[' => {
                cur.push(c);
                // Bracket-quoted identifier: consume to the closing bracket.
                for bc in chars.by_ref() {
                    cur.push(bc);
                    if bc == ']' {
                        break;
                    }
                }
            }
            '-' => {
                if chars.peek() == Some(&'-') {
                    chars.next();
                    // Line comment: consume through end of line; a comment is
                    // whitespace to SQLite, so replace it with a single space.
                    for lc in chars.by_ref() {
                        if lc == '\n' {
                            break;
                        }
                    }
                    cur.push(' ');
                } else {
                    cur.push(c);
                }
            }
            '/' => {
                if chars.peek() == Some(&'*') {
                    chars.next();
                    // Block comment: consume through the closing `*/`.
                    while let Some(bc) = chars.next() {
                        if bc == '*' && chars.peek() == Some(&'/') {
                            chars.next();
                            break;
                        }
                    }
                    cur.push(' ');
                } else {
                    cur.push(c);
                }
            }
            ';' => push_stmt(&mut cur, &mut stmts),
            _ => cur.push(c),
        }
    }
    push_stmt(&mut cur, &mut stmts);
    stmts
}

/// Run a SELECT and return results as a JSON array-of-objects string.
///
/// Each row becomes one JSON object keyed by column name. Suitable for the
/// bridge to deserialise directly in TS.
pub fn query(conn: &Connection, sql: &str, params_json: &str) -> Result<String, OfflineError> {
    if !stmt_is_allowed(sql) {
        return Err(OfflineError::Database(
            "statement not allowed: first keyword blocked".into(),
        ));
    }
    let params = parse_params(params_json)?;
    let mut stmt = conn.prepare(sql)?;
    let col_names: Vec<String> = stmt.column_names().iter().map(|s| s.to_string()).collect();
    let rows = stmt.query_map(params_from_iter(params.iter().map(value_to_sql)), |row| {
        let mut obj = serde_json::Map::new();
        for (i, name) in col_names.iter().enumerate() {
            let v: rusqlite::types::Value = row.get(i)?;
            obj.insert(name.clone(), rusqlite_to_json(v));
        }
        Ok(obj)
    })?;

    let results: Vec<_> = rows
        .map(|r| r.map(Value::Object))
        .collect::<Result<_, _>>()?;
    Ok(serde_json::to_string(&results)?)
}

// ── helpers ──────────────────────────────────────────────────────────────────

fn parse_params(json: &str) -> Result<Vec<Value>, OfflineError> {
    let v: Value = serde_json::from_str(json)?;
    match v {
        Value::Array(arr) => Ok(arr),
        _ => Err(OfflineError::Database("params must be a JSON array".into())),
    }
}

/// Map a serde_json Value to a rusqlite ToSql value.
/// ponytail: allocates a String for text/null-strings; fine for bridge payloads.
fn value_to_sql(v: &Value) -> Box<dyn rusqlite::ToSql> {
    match v {
        Value::Null => Box::new(rusqlite::types::Null),
        Value::Bool(b) => Box::new(*b as i64),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Box::new(i)
            } else {
                Box::new(n.as_f64().unwrap_or(0.0))
            }
        }
        Value::String(s) => Box::new(s.clone()),
        other => Box::new(other.to_string()), // arrays/objects serialised
    }
}

fn rusqlite_to_json(v: rusqlite::types::Value) -> Value {
    match v {
        rusqlite::types::Value::Null => Value::Null,
        rusqlite::types::Value::Integer(i) => Value::Number(i.into()),
        rusqlite::types::Value::Real(f) => serde_json::Number::from_f64(f)
            .map(Value::Number)
            .unwrap_or(Value::Null),
        rusqlite::types::Value::Text(s) => Value::String(s),
        rusqlite::types::Value::Blob(b) => Value::String(base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            b,
        )),
    }
}

#[cfg(test)]
mod error_tests {
    use super::*;

    #[test]
    fn tls_failures_classify_as_tls_not_database() {
        // The three shapes rustls/ureq actually emit for an untrusted chain.
        for msg in [
            "invalid peer certificate: UnknownIssuer",
            "tls: handshake failure",
            "certificate verify failed",
        ] {
            assert!(
                matches!(classify_transport(msg, true), OfflineError::Tls(_)),
                "{msg} must classify as Tls"
            );
        }
    }

    #[test]
    fn non_tls_transport_stays_http() {
        assert!(matches!(
            classify_transport("connection refused", true),
            OfflineError::Http(_)
        ));
        assert!(matches!(
            classify_transport("timed out", true),
            OfflineError::Http(_)
        ));
    }

    #[test]
    fn tls_error_text_is_actionable() {
        let OfflineError::Tls(m) =
            classify_transport("invalid peer certificate: UnknownIssuer", true)
        else {
            panic!("not Tls")
        };
        assert!(
            m.contains("OS trust store"),
            "must tell the operator what to fix: {m}"
        );
    }
}

#[cfg(test)]
mod sql_guard_tests {
    use super::*;

    fn conn() -> Connection {
        let c = Connection::open_in_memory().expect("in-memory db");
        c.execute_batch("CREATE TABLE t0(x);").expect("seed table");
        c
    }

    fn count_tables(c: &Connection, name: &str) -> i64 {
        c.query_row(
            "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
            [name],
            |r| r.get(0),
        )
        .expect("count tables")
    }

    fn err_msg(res: Result<u64, OfflineError>) -> String {
        match res {
            Err(e) => e.to_string(),
            Ok(_) => panic!("expected rejection"),
        }
    }

    /// The exact med-offcore-sqlguard-001 bypass: `CREATE …; VACUUM INTO
    /// <path>;` used to pass the name-blocklist and execute_batch would copy
    /// the store-keyed database to an arbitrary process-writable path. It must
    /// be rejected in any position, before ANY statement of the batch runs.
    /// (r2: the validator is reached only through the authorized init path —
    /// ordinary exec refuses multi-statement input outright, see
    /// `exec_refuses_every_multi_statement_payload`.)
    #[test]
    fn vacuum_into_in_non_leading_position_is_rejected() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let target = dir.path().join("exfil.db");
        let c = conn();
        let sql = format!(
            "CREATE TABLE pwn(x); VACUUM INTO '{}';",
            target.to_string_lossy()
        );
        let msg = err_msg(exec_schema_batch(&c, &sql));
        assert!(msg.contains("VACUUM"), "error names VACUUM: {msg}");
        assert_eq!(count_tables(&c, "pwn"), 0, "no partial batch effects");
        assert!(!target.exists(), "no store-keyed copy may be written");
    }

    #[test]
    fn vacuum_into_leading_and_case_variants_are_rejected() {
        let c = conn();
        for sql in [
            "VACUUM INTO '/tmp/x.db'",
            "vacuum into '/tmp/x.db'",
            "VaCuUm InTo '/tmp/x.db'",
        ] {
            assert!(
                exec_schema_batch(&c, sql).is_err(),
                "{sql} must be rejected"
            );
        }
    }

    #[test]
    fn side_effecting_statements_in_any_batch_position_are_rejected() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let e = dir.path().join("e.db").to_string_lossy().to_string();
        let c = conn();
        let batches = [
            format!("CREATE TABLE t2(x); ATTACH DATABASE '{e}' AS evil;"),
            "CREATE TABLE t3(x); DETACH DATABASE evil;".to_string(),
            format!("DROP TABLE t0; ATTACH DATABASE '{e}' AS evil2;"),
            "CREATE TABLE t4(x); PRAGMA journal_mode=WAL;".to_string(),
            "INSERT INTO t0 VALUES (1); VACUUM;".to_string(),
        ];
        for sql in &batches {
            assert!(
                exec_schema_batch(&c, sql).is_err(),
                "{sql} must be rejected"
            );
        }
        // Rejection precedes execution: nothing from any rejected batch ran.
        assert_eq!(count_tables(&c, "t2"), 0);
        assert_eq!(count_tables(&c, "t3"), 0);
        assert_eq!(count_tables(&c, "t4"), 0);
        assert_eq!(count_tables(&c, "t0"), 1, "rejected batch left t0 intact");
    }

    /// MAIL_SCHEMA-shaped batch (the real init batch is CREATE TABLE / CREATE
    /// INDEX / CREATE VIRTUAL TABLE fts5, with quoted strings inside) must
    /// execute through the authorized one-shot init path unchanged; rows then
    /// take the normal single-statement path, incl. ';' inside a literal.
    #[test]
    fn mail_schema_shaped_batch_executes_through_authorized_init_path() {
        let c = conn();
        let schema = "CREATE TABLE IF NOT EXISTS msg (id TEXT PRIMARY KEY, body TEXT);\
            CREATE INDEX IF NOT EXISTS idx_msg_body ON msg(body);\
            CREATE VIRTUAL TABLE IF NOT EXISTS msg_fts USING fts5(id UNINDEXED, body, tokenize = 'unicode61');";
        exec_schema_init(&c, schema).expect("schema batch accepted through authorized path");
        exec(
            &c,
            "INSERT INTO msg (id, body) VALUES (?1, ?2)",
            r#"["m1","hi; there"]"#,
        )
        .expect("insert");
        exec(
            &c,
            "INSERT INTO msg_fts (id, body) VALUES (?1, ?2)",
            r#"["m1","revenue"]"#,
        )
        .expect("fts insert");
        let rows =
            query(&c, "SELECT id FROM msg WHERE body = ?1", r#"["hi; there"]"#).expect("query");
        assert!(rows.contains("m1"));
        let hits = query(
            &c,
            "SELECT id FROM msg_fts WHERE msg_fts MATCH ?1",
            r#"["revenue"]"#,
        )
        .expect("fts query");
        assert!(hits.contains("m1"));
    }

    /// med-offcore-sqlguard-001 r2 core contract: ordinary exec refuses
    /// multi-statement input UNCONDITIONALLY — even with entirely benign,
    /// batch-allowlisted keywords and no params. The batch validator is not
    /// reachable through exec at all.
    #[test]
    fn exec_refuses_every_multi_statement_payload() {
        let c = conn();
        let payloads = [
            "CREATE TABLE b1(x); CREATE TABLE b2(y);",
            "INSERT INTO t0 VALUES (1); INSERT INTO t0 VALUES (2);",
            "UPDATE t0 SET x = 1; DELETE FROM t0;",
            "SELECT 1; SELECT 2;",
            "CREATE TABLE p3(x); VACUUM INTO '/tmp/evil.db';",
        ];
        for sql in payloads {
            let msg = err_msg(exec(&c, sql, "[]"));
            assert!(
                msg.contains("multi-statement") && msg.contains("exec_schema_init"),
                "rejection must name the authorized init path: {msg}"
            );
        }
        // Nothing from any refused payload ran.
        assert_eq!(count_tables(&c, "b1"), 0);
        assert_eq!(count_tables(&c, "b2"), 0);
        assert_eq!(count_tables(&c, "p3"), 0);
        assert_eq!(
            c.query_row("SELECT count(*) FROM t0", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            0
        );
    }

    /// The authorized init path is ONE-SHOT per connection: the first
    /// successful batch consumes the connection's gate; every later batch —
    /// even a benign, already-validated one — is refused. Single-statement
    /// exec/query stay available afterwards.
    #[test]
    fn exec_schema_init_is_one_shot_per_connection() {
        let c = conn();
        exec_schema_init(&c, "CREATE TABLE g1(x);").expect("first init runs");
        let msg = err_msg(exec_schema_init(&c, "CREATE TABLE g2(y);"));
        assert!(
            msg.contains("one-shot"),
            "second batch must be refused by the gate: {msg}"
        );
        assert_eq!(count_tables(&c, "g2"), 0, "refused batch must not run");
        // Ordinary single-statement execution is unaffected by the gate.
        exec(&c, "INSERT INTO g1 VALUES (1)", "[]").expect("single statements still run");
    }

    /// A REJECTED batch must not consume the gate: the store stays
    /// initializable (a caller can fix its batch and init once).
    #[test]
    fn rejected_batch_does_not_consume_the_one_shot_gate() {
        let c = conn();
        assert!(exec_schema_init(&c, "CREATE TABLE bad(x); VACUUM;").is_err());
        assert_eq!(count_tables(&c, "bad"), 0, "rejected batch ran nothing");
        exec_schema_init(&c, "CREATE TABLE good(x);")
            .expect("gate still open after a rejected attempt");
    }

    #[test]
    fn parameterised_multi_statement_batch_is_rejected() {
        let c = conn();
        let msg = err_msg(exec(&c, "CREATE TABLE t5(x); CREATE TABLE t6(y);", "[1]"));
        assert!(
            msg.contains("multi-statement"),
            "multi-statement exec is refused regardless of params: {msg}"
        );
        assert_eq!(count_tables(&c, "t5"), 0, "reject before any execution");
        assert_eq!(count_tables(&c, "t6"), 0);
    }

    #[test]
    fn semicolon_inside_string_literal_is_not_a_batch_boundary() {
        let c = conn();
        exec(&c, "INSERT INTO t0 VALUES ('a;b')", "[]").expect("single statement");
        let rows = query(&c, "SELECT x FROM t0 WHERE x = 'a;b'", "[]").expect("query");
        assert!(rows.contains("a;b"));
    }

    /// Trigger bodies contain statement separators; the structural batch path
    /// deliberately rejects them (fail-closed) instead of parsing trigger
    /// grammar. Supporting triggers in batches is an explicit contract change
    /// (see BATCH_STMT_ALLOWED_KWS).
    #[test]
    fn trigger_body_batch_is_rejected_fail_closed() {
        let c = conn();
        let sql = "CREATE TABLE t7(x); CREATE TRIGGER tr AFTER INSERT ON t7 BEGIN \
                   INSERT INTO t0 VALUES (new.x); END;";
        assert!(exec_schema_batch(&c, sql).is_err());
        assert_eq!(count_tables(&c, "t7"), 0, "no partial batch effects");
    }

    #[test]
    fn splitter_respects_quoting_comments_and_escapes() {
        assert_eq!(
            split_statements("SELECT 1; SELECT 2;"),
            vec!["SELECT 1", "SELECT 2"]
        );
        assert_eq!(split_statements("SELECT ';'"), vec!["SELECT ';'"]);
        assert_eq!(
            split_statements("SELECT \"a;b\"; SELECT 2"),
            vec!["SELECT \"a;b\"", "SELECT 2"]
        );
        assert_eq!(
            split_statements("SELECT 'it''s;x';"),
            vec!["SELECT 'it''s;x'"]
        );
        assert_eq!(split_statements("SELECT [a;b];"), vec!["SELECT [a;b]"]);
        assert_eq!(
            split_statements("SELECT 1 -- note; here\n; SELECT 2"),
            vec!["SELECT 1", "SELECT 2"]
        );
        assert_eq!(split_statements("SELECT 1/* c;d */;"), vec!["SELECT 1"]);
        assert_eq!(split_statements("SELECT 'abc"), vec!["SELECT 'abc"]);
        assert!(
            split_statements("  ;  ; ").is_empty(),
            "empty pieces dropped"
        );
    }

    /// A comment before the keyword fails the first-keyword gate (fail-closed,
    /// same extraction as the bridge layer); pinned so it stays that way.
    #[test]
    fn comment_led_statement_fails_first_keyword_gate() {
        assert!(!stmt_is_allowed("/* hi */ SELECT 1"));
        assert_eq!(first_keyword("/* hi */ SELECT 1"), "/*");
    }
}
