//! Migration slice (#293): job reads and delete, global source profiles and the
//! M365 consent start. Go's `user.MigrationHandler` / `migration` package.
//!
//! The native job runner and provider I/O live in the gateway's migration_runner;
//! this module owns the administrator database commands and consent transactions. `migration_jobs` and `system_config` carry no
//! RLS and are installation-wide admin resources; the gateway admits only
//! organization-wide admins with the required grant, as Go's chain does.
use super::{deadline, envelope, invalid, s, scope, FAMILY};
use ring::{aead, hkdf, rand::SecureRandom};
use serde_json::Value;
use setjoin_authz::AuthContext;
use setjoin_pg::{CommandOutcome, ReceiptCommand, Row, ScopedExecutor, StatementFailure, Type};

pub const PIPELINE: [&str; 1] = ["mail.pipeline"];

fn command(name: &'static str) -> ReceiptCommand {
    ReceiptCommand {
        family: FAMILY,
        command: name,
    }
}

/// `system_config` key of a source type, as Go's `keyMap`.
pub fn config_key(source: &str) -> Option<&'static str> {
    match source {
        "imap" => Some("imap.defaults"),
        "ews" => Some("ews.global"),
        "m365" => Some("m365.app"),
        _ => None,
    }
}

const STAMP: &str = "'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'";

fn columns() -> String {
    format!(
        "id, user_id, source_type, status, conflict_strategy, progress::text, error_log::text, \
         to_char(started_at, {STAMP}), to_char(completed_at, {STAMP}), to_char(created_at, {STAMP})"
    )
}

/// encoding/json's `compact`: whitespace outside strings goes, nothing else changes.
pub fn compact(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let (mut quoted, mut escaped) = (false, false);
    for ch in text.chars() {
        if quoted {
            out.push(ch);
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                quoted = false;
            }
        } else if !matches!(ch, ' ' | '\t' | '\r' | '\n') {
            if ch == '"' {
                quoted = true;
            }
            out.push(ch);
        }
    }
    out
}

struct Job {
    id: i64,
    user: i64,
    source: String,
    status: String,
    strategy: String,
    progress: String,
    errors: String,
    started: Option<String>,
    completed: Option<String>,
    created: String,
}

fn job(row: &Row) -> Option<Job> {
    Some(Job {
        id: row.try_get(0).ok()?,
        user: row.try_get(1).ok()?,
        source: row.try_get(2).ok()?,
        status: row.try_get(3).ok()?,
        strategy: row.try_get(4).ok()?,
        progress: row.try_get(5).ok()?,
        errors: row.try_get(6).ok()?,
        started: row.try_get(7).ok()?,
        completed: row.try_get(8).ok()?,
        created: row.try_get(9).ok()?,
    })
}

fn opt(v: &Option<String>) -> String {
    v.as_deref().map_or("null".to_owned(), s)
}

/// `GET /admin/migration/jobs`: Go's struct order; rows it cannot scan are skipped.
pub async fn list(
    exec: &ScopedExecutor,
    status: &str,
    user: &str,
) -> Result<String, StatementFailure> {
    let mut sql = format!("SELECT {} FROM migration_jobs WHERE 1=1", columns());
    let mut params: Vec<setjoin_pg::Param<'_>> = Vec::new();
    if !status.is_empty() {
        params.push((&status, Type::TEXT));
        sql.push_str(&format!(" AND status = ${}", params.len()));
    }
    if !user.is_empty() {
        params.push((&user, Type::TEXT));
        // pgx sends the string as the text form of the bigint parameter.
        sql.push_str(&format!(" AND user_id = ${}::text::bigint", params.len()));
    }
    sql.push_str(" ORDER BY created_at DESC LIMIT 100");
    // pgx reports a text that is not a bigint while iterating the rows, which Go's
    // handler never checks: the answer is an empty list.
    let rows = match exec.read(&sql, &params).await {
        Ok(rows) => rows,
        Err(e) if matches!(e.sqlstate.as_deref(), Some("22P02" | "22003")) => Vec::new(),
        Err(e) => return Err(e),
    };
    let items: Vec<String> = rows
        .iter()
        .filter_map(job)
        .map(|j| {
            format!(
                "{{\"id\":{},\"user_id\":{},\"source_type\":{},\"status\":{},\"conflict_strategy\":{},\"progress\":{},\"error_log\":{},\"started_at\":{},\"completed_at\":{},\"created_at\":{}}}",
                j.id, j.user, s(&j.source), s(&j.status), s(&j.strategy), compact(&j.progress), compact(&j.errors),
                opt(&j.started), opt(&j.completed), s(&j.created)
            )
        })
        .collect();
    Ok(super::done(format!("[{}]", items.join(","))))
}

/// `GET /admin/migration/jobs/{id}`: a Go `map`, so keys are sorted. Any failure is "not found".
pub async fn get(exec: &ScopedExecutor, id: i64) -> Option<String> {
    let rows = exec
        .read(
            &format!("SELECT {} FROM migration_jobs WHERE id = $1", columns()),
            &[(&id, Type::INT8)],
        )
        .await
        .ok()?;
    let j = job(rows.first()?)?;
    Some(super::done(format!(
        "{{\"completed_at\":{},\"conflict_strategy\":{},\"created_at\":{},\"error_log\":{},\"id\":{},\"progress\":{},\"source_type\":{},\"started_at\":{},\"status\":{},\"user_id\":{}}}",
        opt(&j.completed), s(&j.strategy), s(&j.created), compact(&j.errors), j.id, compact(&j.progress),
        s(&j.source), opt(&j.started), s(&j.status), j.user
    )))
}

fn count(rows: &[Row]) -> Result<bool, StatementFailure> {
    match rows {
        [row] => row
            .try_get::<_, i64>(0)
            .map(|n| n > 0)
            .map_err(|_| invalid()),
        _ => Err(invalid()),
    }
}

/// `DELETE /admin/migration/jobs/{id}`; `false` when no row matched.
pub async fn delete(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    id: i64,
    operation: [u8; 16],
) -> CommandOutcome<bool, StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        exec,
        command("migration.job.delete"),
        &envelope(&auth, operation, &format!("job:{id}")),
        &auth,
        deadline(),
        "WITH d AS (DELETE FROM migration_jobs WHERE id = $4 \
         AND $1::bigint > 0 AND $2::bigint > 0 AND $3::text <> '' RETURNING 1) SELECT count(*)::bigint FROM d",
        &[(&id, Type::INT8)],
        count,
    )
    .await
}

/// `AdminAPI.hasGlobalSourceConfig`: whether a global profile row exists for the source.
pub async fn has_global(exec: &ScopedExecutor, source: &str) -> bool {
    let Some(key) = config_key(source) else {
        return false;
    };
    exec.read(
        "SELECT EXISTS(SELECT 1 FROM system_config WHERE key = $1)",
        &[(&key, Type::TEXT)],
    )
    .await
    .ok()
    .and_then(|rows| rows.first().and_then(|r| r.try_get::<_, bool>(0).ok()))
    .unwrap_or(false)
}

/// The first mailbox of the user with this e-mail address (Go's `LIMIT 1`, no order).
pub async fn mailbox_for_email(exec: &ScopedExecutor, email: &str) -> Option<i64> {
    let rows = exec
        .read(
            "SELECT m.id FROM mailboxes m JOIN users u ON m.user_id = u.id WHERE u.email = $1 LIMIT 1",
            &[(&email, Type::TEXT)],
        )
        .await
        .ok()?;
    rows.first()?.try_get::<_, i64>(0).ok()
}

/// One pending job owned by the verified actor (Go's `AdminAPI.Start` insert); the
/// owner is the auth context's user, never a request field. The per-user
/// one-active-job index may refuse it.
pub async fn insert_job(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    source: &str,
    config_enc: &[u8],
    mailbox: i64,
    operation: [u8; 16],
) -> CommandOutcome<i64, StatementFailure> {
    let auth = scope(actor);
    let owner = actor.user_id();
    let payload = format!("job:{source}:{mailbox}");
    let config: &[u8] = config_enc;
    setjoin_pg::run_receipted_command(
        exec,
        command("migration.job.start"),
        &envelope(&auth, operation, &payload),
        &auth,
        deadline(),
        "WITH i AS (INSERT INTO migration_jobs (user_id, source_type, source_config_enc, target_mailbox_id, conflict_strategy, status) \
         SELECT $4::bigint, $5::text, $6::bytea, $7::bigint, 'skip', 'pending' \
         WHERE $1::bigint > 0 AND $2::bigint > 0 AND $3::text <> '' RETURNING id) SELECT id FROM i",
        &[
            (&owner, Type::INT8),
            (&source, Type::TEXT),
            (&config, Type::BYTEA),
            (&mailbox, Type::INT8),
        ],
        |rows| match rows {
            [row] => row.try_get::<_, i64>(0).map_err(|_| invalid()),
            _ => Err(invalid()),
        },
    )
    .await
}

/// A `system_config` row: the jsonb text and the `encrypted` flag. `None` on a miss or any error.
pub async fn config(exec: &ScopedExecutor, key: &str) -> Option<(String, bool)> {
    let rows = exec
        .read(
            "SELECT value::text, encrypted FROM system_config WHERE key = $1",
            &[(&key, Type::TEXT)],
        )
        .await
        .ok()?;
    let row = rows.first()?;
    Some((row.try_get(0).ok()?, row.try_get(1).ok()?))
}

/// Upsert of a global source profile. IMAP stores plain jsonb and leaves `encrypted`
/// alone; EWS and M365 store the sealed wrapper and set it.
pub async fn put_config(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    key: &str,
    value: &str,
    sealed: bool,
    operation: [u8; 16],
) -> CommandOutcome<bool, StatementFailure> {
    let auth = scope(actor);
    let sql = if sealed {
        "WITH w AS (INSERT INTO system_config (key, value, encrypted) \
         SELECT $4::text, $5::text::jsonb, TRUE WHERE $1::bigint > 0 AND $2::bigint > 0 AND $3::text <> '' \
         ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, encrypted = TRUE, updated_at = now() RETURNING 1) \
         SELECT count(*)::bigint FROM w"
    } else {
        "WITH w AS (INSERT INTO system_config (key, value) \
         SELECT $4::text, $5::text::jsonb WHERE $1::bigint > 0 AND $2::bigint > 0 AND $3::text <> '' \
         ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now() RETURNING 1) \
         SELECT count(*)::bigint FROM w"
    };
    setjoin_pg::run_receipted_command(
        exec,
        command("migration.source.save"),
        &envelope(&auth, operation, &format!("source:{key}")),
        &auth,
        deadline(),
        sql,
        &[(&key, Type::TEXT), (&value, Type::TEXT)],
        count,
    )
    .await
}

/// `DELETE /admin/migration/source/{type}` (also succeeds when nothing is stored).
pub async fn delete_config(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    key: &str,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        exec,
        command("migration.source.delete"),
        &envelope(&auth, operation, &format!("source:{key}")),
        &auth,
        deadline(),
        "WITH d AS (DELETE FROM system_config WHERE key = $4 \
         AND $1::bigint > 0 AND $2::bigint > 0 AND $3::text <> '' RETURNING 1) SELECT count(*)::bigint FROM d",
        &[(&key, Type::TEXT)],
        |rows| count(rows).map(|_| ()),
    )
    .await
}

/// `m365_consent_state_mint` for the verified actor (Go's `RunUserScoped` call).
pub async fn mint_consent(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    token: &str,
    cloud: &str,
    ttl_seconds: i32,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let auth = scope(actor);
    let user = actor.user_id();
    setjoin_pg::run_receipted_command(
        exec,
        command("migration.m365.consent"),
        &envelope(&auth, operation, &format!("consent:{user}")),
        &auth,
        deadline(),
        "SELECT m365_consent_state_mint($4, $5, $6, $7)::text \
         WHERE $1::bigint > 0 AND $2::bigint > 0 AND $3::text <> ''",
        &[
            (&user, Type::INT8),
            (&token, Type::TEXT),
            (&cloud, Type::TEXT),
            (&ttl_seconds, Type::INT4),
        ],
        |rows| {
            if rows.len() == 1 {
                Ok(())
            } else {
                Err(invalid())
            }
        },
    )
    .await
}

// ---- sealed profiles: Go `migration.DeriveKey` / `EncryptConfigAny` ----

struct KeyLen;
impl hkdf::KeyType for KeyLen {
    fn len(&self) -> usize {
        32
    }
}

/// HKDF-SHA256 of the raw `DB_ENCRYPTION_KEY` (no salt, `purpose` as info); `None` when empty.
pub fn derive_key(root: &str, purpose: &str) -> Option<[u8; 32]> {
    if root.is_empty() {
        return None;
    }
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, &[]).extract(root.as_bytes());
    let mut key = [0u8; 32];
    prk.expand(&[purpose.as_bytes()], KeyLen)
        .ok()?
        .fill(&mut key)
        .ok()?;
    Some(key)
}

fn gcm(key: &[u8; 32]) -> Option<aead::LessSafeKey> {
    Some(aead::LessSafeKey::new(
        aead::UnboundKey::new(&aead::AES_256_GCM, key).ok()?,
    ))
}

/// Nonce, then AES-256-GCM ciphertext and tag.
pub fn seal(plaintext: &[u8], key: &[u8; 32]) -> Option<Vec<u8>> {
    let mut nonce = [0u8; 12];
    ring::rand::SystemRandom::new().fill(&mut nonce).ok()?;
    let mut buffer = plaintext.to_vec();
    gcm(key)?
        .seal_in_place_append_tag(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::empty(),
            &mut buffer,
        )
        .ok()?;
    let mut out = nonce.to_vec();
    out.extend_from_slice(&buffer);
    Some(out)
}

pub fn open(data: &[u8], key: &[u8; 32]) -> Option<Vec<u8>> {
    if data.len() < 12 {
        return None;
    }
    let (nonce, rest) = data.split_at(12);
    let mut buffer = rest.to_vec();
    let plain = gcm(key)?
        .open_in_place(
            aead::Nonce::try_assume_unique_for_key(nonce).ok()?,
            aead::Aad::empty(),
            &mut buffer,
        )
        .ok()?;
    Some(plain.to_vec())
}

/// `{"_enc":"<base64>"}`, the stored form of a sealed profile.
pub fn wrapper(sealed: &[u8]) -> String {
    use base64::Engine as _;
    format!(
        "{{\"_enc\":\"{}\"}}",
        base64::engine::general_purpose::STANDARD.encode(sealed)
    )
}

/// What reading a stored sealed profile can end in, with Go's handler outcomes.
pub enum Unsealed {
    /// Decrypted plaintext JSON.
    Plain(Value),
    /// `json.Unmarshal` of the wrapper failed.
    BadWrapper,
    /// The wrapper's base64 is invalid.
    BadBase64,
    /// Decryption failed (wrong key, truncated, tampered) or the key is unavailable.
    Undecryptable,
}

pub fn unseal(stored: &str, root: &str) -> Unsealed {
    use base64::Engine as _;
    let Ok(Value::Object(map)) = serde_json::from_str::<Value>(stored).map(|v| match v {
        Value::Null => Value::Object(Default::default()),
        other => other,
    }) else {
        return Unsealed::BadWrapper;
    };
    // Go matches `_enc` case-insensitively and rejects a non-string value.
    let mut enc = String::new();
    for (k, v) in &map {
        if k.eq_ignore_ascii_case("_enc") {
            match v {
                Value::String(x) => enc = x.clone(),
                Value::Null => {}
                _ => return Unsealed::BadWrapper,
            }
        }
    }
    let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(enc.as_bytes()) else {
        return Unsealed::BadBase64;
    };
    let Some(key) = derive_key(root, "system") else {
        return Unsealed::Undecryptable;
    };
    match open(&bytes, &key).and_then(|p| serde_json::from_slice::<Value>(&p).ok()) {
        Some(v) => Unsealed::Plain(v),
        None => Unsealed::Undecryptable,
    }
}

/// A stored value Go's `json.Unmarshal` would refuse (wrong type).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decode;

/// A string field by Go's case-insensitive match; absent or null is empty, any
/// other type is a decode error.
pub fn field(v: &Value, name: &str) -> Result<String, Decode> {
    let mut out = String::new();
    if let Value::Object(map) = v {
        for (k, x) in map {
            if crate_fold(k) == crate_fold(name) {
                match x {
                    Value::String(t) => out = t.clone(),
                    Value::Null => {}
                    _ => return Err(Decode),
                }
            }
        }
    } else {
        return Err(Decode);
    }
    Ok(out)
}
pub fn bool_field(v: &Value, name: &str) -> Result<bool, Decode> {
    let mut out = false;
    if let Value::Object(map) = v {
        for (k, x) in map {
            if crate_fold(k) == crate_fold(name) {
                match x {
                    Value::Bool(b) => out = *b,
                    Value::Null => {}
                    _ => return Err(Decode),
                }
            }
        }
    }
    Ok(out)
}
pub fn list_field(v: &Value, name: &str) -> Result<Vec<String>, Decode> {
    let mut out = Vec::new();
    if let Value::Object(map) = v {
        for (k, x) in map {
            if crate_fold(k) == crate_fold(name) {
                match x {
                    Value::Array(items) => {
                        out = items
                            .iter()
                            .map(|i| match i {
                                Value::String(t) => Ok(t.clone()),
                                Value::Null => Ok(String::new()),
                                _ => Err(Decode),
                            })
                            .collect::<Result<_, _>>()?
                    }
                    Value::Null => {}
                    _ => return Err(Decode),
                }
            }
        }
    }
    Ok(out)
}
fn crate_fold(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'ſ' => 's',
            'K' => 'k',
            _ => c.to_ascii_lowercase(),
        })
        .collect()
}

fn strings(items: &[String]) -> String {
    format!(
        "[{}]",
        items.iter().map(|i| s(i)).collect::<Vec<_>>().join(",")
    )
}

/// Go `json.Marshal` of `GlobalIMAPConfig` (HTML escaped, omitempty slices).
pub fn imap_json(host: &str, port: i64, tls: &str, hosts: &[String], cidrs: &[String]) -> String {
    let mut out = format!(
        "{{\"host\":{},\"port\":{port},\"tls_mode\":{}",
        s(host),
        s(tls)
    );
    if !hosts.is_empty() {
        out.push_str(&format!(",\"private_hosts\":{}", strings(hosts)));
    }
    if !cidrs.is_empty() {
        out.push_str(&format!(",\"private_cidrs\":{}", strings(cidrs)));
    }
    out.push('}');
    super::go_escape(&out)
}

pub struct Ews {
    pub url: String,
    pub username: String,
    pub password: String,
    pub auth_mode: String,
    pub insecure: bool,
    pub hosts: Vec<String>,
    pub cidrs: Vec<String>,
}
impl Ews {
    /// Go `json.Marshal` of `GlobalEWSConfig`.
    pub fn json(&self) -> String {
        let mut out = format!(
            "{{\"serverURL\":{},\"username\":{},\"password\":{},\"authMode\":{},\"insecureSkipVerify\":{}",
            s(&self.url), s(&self.username), s(&self.password), s(&self.auth_mode), self.insecure
        );
        if !self.hosts.is_empty() {
            out.push_str(&format!(",\"privateHosts\":{}", strings(&self.hosts)));
        }
        if !self.cidrs.is_empty() {
            out.push_str(&format!(",\"privateCIDRs\":{}", strings(&self.cidrs)));
        }
        out.push('}');
        super::go_escape(&out)
    }
    pub fn from_value(v: &Value) -> Result<Ews, Decode> {
        Ok(Ews {
            url: field(v, "serverURL")?,
            username: field(v, "username")?,
            password: field(v, "password")?,
            auth_mode: field(v, "authMode")?,
            insecure: bool_field(v, "insecureSkipVerify")?,
            hosts: list_field(v, "privateHosts")?,
            cidrs: list_field(v, "privateCIDRs")?,
        })
    }
}

#[derive(Clone)]
pub struct M365 {
    pub client_id: String,
    pub client_secret: String,
    pub tenant_id: String,
    pub cloud: String,
    pub source_email: String,
    pub source_user_id: String,
}
impl M365 {
    /// Go `json.Marshal` of `MigrationM365Config`.
    pub fn json(&self) -> String {
        let mut out = format!(
            "{{\"client_id\":{},\"client_secret\":{},\"tenant_id\":{},\"cloud\":{},\"source_email\":{}",
            s(&self.client_id), s(&self.client_secret), s(&self.tenant_id), s(&self.cloud), s(&self.source_email)
        );
        if !self.source_user_id.is_empty() {
            out.push_str(&format!(",\"source_user_id\":{}", s(&self.source_user_id)));
        }
        out.push('}');
        super::go_escape(&out)
    }
    pub fn from_value(v: &Value) -> Result<M365, Decode> {
        Ok(M365 {
            client_id: field(v, "client_id")?,
            client_secret: field(v, "client_secret")?,
            tenant_id: field(v, "tenant_id")?,
            cloud: field(v, "cloud")?,
            source_email: field(v, "source_email")?,
            source_user_id: field(v, "source_user_id")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_keeps_strings() {
        assert_eq!(
            compact("{\"a\": [1, 2], \"b c\": \"x  y\\\" z\"}"),
            "{\"a\":[1,2],\"b c\":\"x  y\\\" z\"}"
        );
    }

    #[test]
    fn seal_round_trips_and_binds_the_key() {
        let key = derive_key(&"22".repeat(32), "system").unwrap();
        let other = derive_key(&"23".repeat(32), "system").unwrap();
        let sealed = seal(b"{\"a\":1}", &key).unwrap();
        assert_eq!(open(&sealed, &key).unwrap(), b"{\"a\":1}");
        assert!(open(&sealed, &other).is_none());
        assert!(open(&sealed[..11], &key).is_none());
        assert!(derive_key("", "system").is_none());
    }

    #[test]
    fn hkdf_matches_go() {
        // Output of golang.org/x/crypto/hkdf.New(sha256.New, root, nil, "system"), 32 bytes (Go run).
        let key = derive_key("0123456789abcdef", "system").unwrap();
        let hex: String = key.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "11b3014d81170c03ec7b170d9a741b41ab4b87bfee7b36ac923c732d5db30a8b"
        );
        assert_ne!(key, derive_key("0123456789abcdef", "other").unwrap());
    }

    #[test]
    fn marshal_matches_go_field_order_and_escaping() {
        assert_eq!(
            imap_json("a&b", 993, "tls", &[], &["10.0.0.0/8".into()]),
            "{\"host\":\"a\\u0026b\",\"port\":993,\"tls_mode\":\"tls\",\"private_cidrs\":[\"10.0.0.0/8\"]}"
        );
        let e = Ews {
            url: "u".into(),
            username: "n".into(),
            password: "".into(),
            auth_mode: "per_user".into(),
            insecure: false,
            hosts: vec![],
            cidrs: vec![],
        };
        assert_eq!(e.json(), "{\"serverURL\":\"u\",\"username\":\"n\",\"password\":\"\",\"authMode\":\"per_user\",\"insecureSkipVerify\":false}");
    }
}

/// Spend one actor-bound consent authorization before any outbound verification.
pub async fn consume_consent(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    token: &str,
    operation: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let auth = scope(actor);
    let user = actor.user_id();
    setjoin_pg::run_receipted_command(
        exec,
        command("migration.m365.consume"),
        &envelope(&auth, operation, &format!("consent:{user}")),
        &auth,
        deadline(),
        "SELECT m365_consent_state_consume($2,$4)::text WHERE $1::bigint>0 AND $3::text<>''",
        &[(&token, Type::TEXT)],
        |rows| match rows {
            [row] => row.try_get::<_, String>(0).map_err(|_| invalid()),
            _ => Err(invalid()),
        },
    )
    .await
}
/// The verified tenant binding and its audit commit together, after verification.
pub async fn complete_consent(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    wrapped: &str,
    notes: &str,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(exec,command("migration.m365.complete"),&envelope(&auth,operation,"m365.app"),&auth,deadline(),
        "SELECT m365_consent_complete($2,$4,$5,'routine')::text WHERE $1::bigint>0 AND $3::text<>''",&[(&wrapped,Type::TEXT),(&notes,Type::TEXT)],
        |rows|if rows.len()==1{Ok(())}else{Err(invalid())}).await
}
