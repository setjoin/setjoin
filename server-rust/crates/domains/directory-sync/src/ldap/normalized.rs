//! Normalized, generation-fenced path: `directorysync.Engine` plus the
//! `identitysource.Store` inbox (`mailserver/internal/directorysync/engine.go`,
//! `identitysource/pipeline.go`). Reducers own matching, lifecycle and cursor
//! advancement; this module only stages bounded entries and drains them.
use super::client::{normalize_dn, LdapUser};
use super::engine::{build_sync_filter, Res, SyncResult, Worker};
use super::{canonical_address, go_duration, log_warn, new_uuid};
use serde_json::{json, Value};
use setjoin_pg::workers::WorkerConnection;
use setjoin_pg::workers::WorkerDatabase;
use setjoin_pg::Type;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

pub const MAX_ENTRIES: usize = 500;
pub const MAX_OBJECT_KEY: usize = 512;
pub const MAX_SUBJECT: usize = 2048;
pub const MAX_PAYLOAD_BYTES: usize = 64 << 10;
pub const MAX_CURSOR_BYTES: usize = 4096;
const LEASE_SECS: i32 = 45;
const QUARANTINE_MAX_RECORDS: usize = 500;

const PAYLOAD_KEYS: [&str; 12] = [
    "operation",
    "email",
    "displayName",
    "firstName",
    "lastName",
    "jobTitle",
    "phone",
    "department",
    "upn",
    "enabled",
    "cursorValue",
    "managerSubject",
];

pub struct Source {
    pub id: i64,
    pub generation: i64,
    pub cursor: String,
}

#[derive(Default, Clone)]
pub struct Finish {
    pub state: String,
    pub cursor_advanced: bool,
    pub pending: i64,
    pub applied: i64,
    pub quarantined: i64,
}

struct Entry {
    object_key: String,
    subject: String,
    payload: String,
}

struct Quarantine {
    object_key: String,
    digest: String,
    reason: &'static str,
}

fn sqlstate(error: &str) -> String {
    error
        .rsplit_once("(SQLSTATE ")
        .and_then(|(_, rest)| rest.strip_suffix(')'))
        .unwrap_or("INTERNAL")
        .to_owned()
}

fn has_control(s: &str) -> bool {
    s.chars().any(char::is_control)
}

/// Go `boundedText`: trimmed, non-empty, control-free, within `limit` bytes.
fn bounded_text(name: &str, value: &str, limit: usize) -> Res<()> {
    let trimmed = value.trim_matches(|c: char| c.is_whitespace());
    if trimmed != value || value.is_empty() || value.len() > limit {
        return Err(format!(
            "{name} must be trimmed and contain 1..{limit} bytes"
        ));
    }
    if has_control(value) {
        return Err(format!("{name} contains a control character"));
    }
    Ok(())
}

impl Entry {
    fn validate(&self) -> Res<()> {
        bounded_text("objectKey", &self.object_key, MAX_OBJECT_KEY)?;
        bounded_text("immutableSubject", &self.subject, MAX_SUBJECT)?;
        if self.payload.is_empty() || self.payload.len() > MAX_PAYLOAD_BYTES {
            return Err(format!(
                "payload must be valid JSON and at most {MAX_PAYLOAD_BYTES} bytes"
            ));
        }
        let Ok(Value::Object(map)) = serde_json::from_str::<Value>(&self.payload) else {
            return Err("payload must be a JSON object".into());
        };
        for key in map.keys() {
            if !PAYLOAD_KEYS.contains(&key.as_str()) {
                return Err(format!("payload contains unsupported field {key:?}"));
            }
        }
        Ok(())
    }
}

fn sha256_hex(b: &[u8]) -> String {
    Sha256::digest(b)
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect()
}

pub struct Object {
    pub subject: String,
    pub relation_key: String,
    pub manager_relation_key: String,
    pub manager_subject: String,
    pub email: String,
    pub display_name: String,
    pub first_name: String,
    pub last_name: String,
    pub job_title: String,
    pub phone: String,
    pub department: String,
    pub upn: String,
    pub disabled: bool,
    pub tombstone: bool,
    pub cursor_value: String,
}

fn object_from(user: &LdapUser) -> Object {
    Object {
        subject: user.immutable_subject.clone(),
        relation_key: normalize_dn(&user.dn),
        manager_relation_key: normalize_dn(&user.manager_dn),
        manager_subject: user.manager_subject.clone(),
        email: user.email.clone(),
        display_name: user.display_name.clone(),
        first_name: user.first_name.clone(),
        last_name: user.last_name.clone(),
        job_title: user.title.clone(),
        phone: user.phone.clone(),
        department: user.department.clone(),
        upn: user.upn.clone(),
        disabled: user.disabled,
        tombstone: false,
        cursor_value: user.modify_stamp.clone(),
    }
}

fn quarantine_key(o: &Object) -> String {
    let key = if o.subject.is_empty() {
        &o.relation_key
    } else {
        &o.subject
    };
    if key.is_empty() || key.len() > MAX_OBJECT_KEY || has_control(key) {
        format!("digest:{}", sha256_hex(key.as_bytes()))
    } else {
        key.clone()
    }
}

fn subject_within_bounds(subject: &str) -> bool {
    !subject.is_empty()
        && subject.trim_matches(|c: char| c.is_whitespace()) == subject
        && subject.len() <= MAX_OBJECT_KEY
        && !has_control(subject)
}

/// `directorysync.Engine.entries` with the LDAP connector's validation.
fn entries(
    objects: &[Object],
    result: &mut SyncResult,
    label: &str,
    forbid_duplicates: bool,
) -> Res<(Vec<Entry>, Vec<Quarantine>)> {
    let mut relation_subjects: HashMap<&str, &str> = HashMap::new();
    for o in objects {
        if !o.relation_key.is_empty() && !o.subject.is_empty() {
            relation_subjects.insert(&o.relation_key, &o.subject);
        }
    }
    let mut seen: HashSet<&str> = HashSet::new();
    let mut quarantined: HashSet<String> = HashSet::new();
    let mut records = vec![];
    let mut out = vec![];
    let mut quarantine = |reason: &'static str,
                          o: &Object,
                          records: &mut Vec<Quarantine>,
                          result: &mut SyncResult| {
        result.skipped += 1;
        log_warn(&format!(
            "{label} sync: directory object skipped and quarantined: {reason} subject={}",
            o.subject
        ));
        let key = quarantine_key(o);
        if quarantined.insert(format!("{reason}\0{key}")) {
            records.push(Quarantine {
                object_key: key,
                digest: sha256_hex(o.subject.as_bytes()),
                reason,
            });
        }
    };
    for o in objects {
        if o.subject.is_empty() {
            quarantine("MISSING_IMMUTABLE_SUBJECT", o, &mut records, result);
            continue;
        }
        if !subject_within_bounds(&o.subject) {
            quarantine("INVALID_IMMUTABLE_SUBJECT", o, &mut records, result);
            continue;
        }
        let duplicate = seen.contains(o.subject.as_str());
        if duplicate && forbid_duplicates {
            return Err(format!("{label} immutable subject is not unique in page"));
        }
        seen.insert(&o.subject);
        let email = canonical_address(&o.email);
        if (email.is_empty() || !email.contains('@')) && !o.tombstone && !o.disabled {
            quarantine("NO_USABLE_MAIL_ATTRIBUTE", o, &mut records, result);
            continue;
        }
        let manager = if o.manager_subject.is_empty() {
            relation_subjects
                .get(o.manager_relation_key.as_str())
                .copied()
                .unwrap_or("")
                .to_owned()
        } else {
            o.manager_subject.clone()
        };
        let operation = if o.disabled || o.tombstone {
            "disable"
        } else {
            "upsert"
        };
        let payload = json!({
            "operation": operation, "email": email, "displayName": o.display_name, "firstName": o.first_name,
            "lastName": o.last_name, "jobTitle": o.job_title, "phone": o.phone, "department": o.department,
            "upn": o.upn, "enabled": !(o.disabled || o.tombstone), "cursorValue": o.cursor_value,
            "managerSubject": manager,
        });
        out.push(Entry {
            object_key: o.subject.clone(),
            subject: o.subject.clone(),
            payload: serde_json::to_string(&payload).map_err(|e| e.to_string())?,
        });
    }
    Ok((out, records))
}

async fn lease_acquire(c: &WorkerConnection, s: &Source, instance: &str) -> Res<bool> {
    let rows = c
        .query(
            "SELECT identity_source_lease_acquire($1,$2,$3::text::uuid,$4)",
            &[
                (&s.id, Type::INT8),
                (&s.generation, Type::INT8),
                (&instance, Type::TEXT),
                (&LEASE_SECS, Type::INT4),
            ],
        )
        .await?;
    Ok(rows.first().map(|r| r.get::<_, bool>(0)).unwrap_or(false))
}

async fn lease_release(c: &WorkerConnection, s: &Source, instance: &str) -> Res<()> {
    c.query(
        "SELECT identity_source_lease_release($1,$2,$3::text::uuid)",
        &[
            (&s.id, Type::INT8),
            (&s.generation, Type::INT8),
            (&instance, Type::TEXT),
        ],
    )
    .await?;
    Ok(())
}

fn finish_from(raw: &str) -> Res<Finish> {
    let v: Value = serde_json::from_str(raw)
        .map_err(|e| format!("decode identity source finish result: {e}"))?;
    Ok(Finish {
        state: v["state"].as_str().unwrap_or("").to_owned(),
        cursor_advanced: v["cursorAdvanced"].as_bool().unwrap_or(false),
        pending: v["pending"].as_i64().unwrap_or(0),
        applied: v["applied"].as_i64().unwrap_or(0),
        quarantined: v["quarantined"].as_i64().unwrap_or(0),
    })
}

async fn drain(
    c: &WorkerConnection,
    s: &Source,
    batch: &str,
    keys: &[String],
    entry_count: usize,
    start: Instant,
    instance: &str,
) -> (Finish, Option<String>) {
    let mut errors: Vec<String> = vec![];
    let mut heartbeat = Instant::now();
    for key in keys {
        if heartbeat.elapsed() >= Duration::from_secs(LEASE_SECS as u64 / 3) {
            match lease_acquire(c, s, instance).await {
                Err(e) => {
                    errors.push(format!("renew identity source lease while applying: {e}"));
                    return (Finish::default(), Some(errors.join("; ")));
                }
                Ok(false) => {
                    errors.push("identity source lease was lost while applying".into());
                    return (Finish::default(), Some(errors.join("; ")));
                }
                Ok(true) => heartbeat = Instant::now(),
            }
        }
        match c
            .query(
                "SELECT identity_source_entry_apply($1,$2,$3::text::uuid,$4)::text",
                &[
                    (&s.id, Type::INT8),
                    (&s.generation, Type::INT8),
                    (&batch, Type::TEXT),
                    (key, Type::TEXT),
                ],
            )
            .await
        {
            Err(e) => {
                let code = sqlstate(&e);
                errors.push(e.clone());
                if let Err(record) = c
                    .query(
                        "SELECT identity_source_entry_fail($1,$2,$3::text::uuid,$4,$5)",
                        &[
                            (&s.id, Type::INT8),
                            (&s.generation, Type::INT8),
                            (&batch, Type::TEXT),
                            (key, Type::TEXT),
                            (&code, Type::TEXT),
                        ],
                    )
                    .await
                {
                    errors.push(format!("record connector failure: {record}"));
                    return (Finish::default(), Some(errors.join("; ")));
                }
            }
            Ok(rows) => {
                let raw: String = rows.first().map(|r| r.get(0)).unwrap_or_default();
                let state = serde_json::from_str::<Value>(&raw).ok().map(|v| {
                    (
                        v["state"].as_str().unwrap_or("").to_owned(),
                        v["code"].as_str().unwrap_or("").to_owned(),
                    )
                });
                match state {
                    None => errors.push("decode identity source apply result".into()),
                    Some((state, code)) if state == "blocked" => {
                        errors.push(format!("entry {key} blocked ({code})"))
                    }
                    Some(_) => {}
                }
            }
        }
    }
    match lease_acquire(c, s, instance).await {
        Err(e) => {
            errors.push(format!(
                "renew identity source lease before cursor commit: {e}"
            ));
            return (Finish::default(), Some(errors.join("; ")));
        }
        Ok(false) => {
            errors.push("identity source lease was lost before cursor commit".into());
            return (Finish::default(), Some(errors.join("; ")));
        }
        Ok(true) => {}
    }
    let seconds = (start.elapsed().as_secs_f64().round() as i32).max(0);
    let rows = c
        .query(
            "SELECT identity_source_batch_finish($1,$2,$3::text::uuid,$4,$5::text::uuid)::text",
            &[
                (&s.id, Type::INT8),
                (&s.generation, Type::INT8),
                (&batch, Type::TEXT),
                (&seconds, Type::INT4),
                (&instance, Type::TEXT),
            ],
        )
        .await;
    let finish = match rows {
        Err(e) => {
            errors.push(e);
            return (Finish::default(), Some(errors.join("; ")));
        }
        Ok(rows) => match finish_from(
            &rows
                .first()
                .map(|r| r.get::<_, String>(0))
                .unwrap_or_default(),
        ) {
            Ok(f) => f,
            Err(e) => {
                errors.push(e);
                return (Finish::default(), Some(errors.join("; ")));
            }
        },
    };
    if !finish.cursor_advanced {
        errors.push(format!(
            "identity source batch {batch} remains blocked with {} pending entries",
            finish.pending
        ));
    }
    if finish.state == "completed" && (finish.applied + finish.quarantined) as usize != entry_count
    {
        errors.push(format!(
            "identity source batch {batch} completed with {} terminal entries, expected {entry_count}",
            finish.applied + finish.quarantined
        ));
    }
    (
        finish.clone(),
        (!errors.is_empty()).then(|| errors.join("; ")),
    )
}

async fn apply_page(
    c: &WorkerConnection,
    s: &Source,
    cursor: &str,
    page: &[Entry],
    instance: &str,
) -> Result<Finish, String> {
    let batch = new_uuid();
    if cursor.is_empty() || cursor.len() > MAX_CURSOR_BYTES {
        return Err(format!("cursor must contain 1..{MAX_CURSOR_BYTES} bytes"));
    }
    match serde_json::from_str::<Value>(cursor) {
        Ok(Value::Null) | Err(_) => return Err("cursor must be non-null JSON".into()),
        Ok(_) => {}
    }
    if page.len() > MAX_ENTRIES {
        return Err(format!(
            "page has {} entries; maximum is {MAX_ENTRIES}",
            page.len()
        ));
    }
    for (i, e) in page.iter().enumerate() {
        e.validate().map_err(|e| format!("entry {i}: {e}"))?;
    }
    let start = Instant::now();
    if !lease_acquire(c, s, instance)
        .await
        .map_err(|e| format!("renew identity source lease: {e}"))?
    {
        return Err("identity source lease was lost before staging".into());
    }
    let list: Vec<Value> = page
        .iter()
        .map(|e| {
            json!({"objectKey": e.object_key, "immutableSubject": e.subject,
                   "payload": serde_json::from_str::<Value>(&e.payload).unwrap_or(Value::Null)})
        })
        .collect();
    let entries_json = serde_json::to_string(&list).map_err(|e| e.to_string())?;
    c.query(
        "SELECT identity_source_batch_begin($1,$2,$3::text::uuid,$4::text::jsonb,$5::text::jsonb,$6::text::uuid)",
        &[
            (&s.id, Type::INT8),
            (&s.generation, Type::INT8),
            (&batch, Type::TEXT),
            (&cursor, Type::TEXT),
            (&entries_json, Type::TEXT),
            (&instance, Type::TEXT),
        ],
    )
    .await?;
    let keys: Vec<String> = page.iter().map(|e| e.object_key.clone()).collect();
    let (finish, error) = drain(c, s, &batch, &keys, page.len(), start, instance).await;
    match error {
        Some(e) => Err(e),
        None => Ok(finish),
    }
}

fn stamp_cursor(stamp: &str) -> String {
    json!({"modifyTimestamp": stamp}).to_string()
}

/// `directorysync.Connector`: what differs between directory families. The
/// cursor is carried as an opaque text state, encoded to JSON for the inbox.
pub trait Connector {
    fn label(&self) -> &'static str;
    fn preflight(&self) -> Res<()> {
        Ok(())
    }
    /// `ValidateObject(_, duplicate)`: LDAP rejects a repeated subject in a page.
    fn forbid_duplicates(&self) -> bool;
    /// Committed cursor JSON (possibly empty) to the opaque state.
    fn decode_cursor(&self, committed: &str) -> Res<String>;
    fn encode_cursor(&self, state: &str) -> String;
    /// One directory read from `before`; returns the objects and the cursor after.
    fn fetch(
        &self,
        before: &str,
    ) -> impl std::future::Future<Output = Res<(Vec<Object>, String)>> + Send;
}

/// The LDAP connector (`ldapsync.normalizedConnector`).
pub struct LdapConnector<'a>(pub &'a Worker);

impl Connector for LdapConnector<'_> {
    fn label(&self) -> &'static str {
        "LDAP"
    }
    fn preflight(&self) -> Res<()> {
        if self.0.client.subject_attribute().is_empty() {
            return Err(
                "LDAP normalized sync requires a uniqueness-proven immutable subject attribute"
                    .into(),
            );
        }
        Ok(())
    }
    fn forbid_duplicates(&self) -> bool {
        true
    }
    fn decode_cursor(&self, committed: &str) -> Res<String> {
        if committed.is_empty() {
            return Ok(String::new());
        }
        match serde_json::from_str::<Value>(committed) {
            Ok(v) => Ok(v["modifyTimestamp"].as_str().unwrap_or("").to_owned()),
            Err(e) => Err(format!("decode LDAP committed cursor: {e}")),
        }
    }
    fn encode_cursor(&self, state: &str) -> String {
        stamp_cursor(state)
    }
    async fn fetch(&self, before: &str) -> Res<(Vec<Object>, String)> {
        let worker = self.0;
        let mut ldap = worker.client.connect().await.map_err(|e| e.to_string())?;
        worker
            .client
            .bind(&mut ldap)
            .await
            .map_err(|e| e.to_string())?;
        let users = worker
            .client
            .search_users(&mut ldap, &build_sync_filter(&worker.filter, before), 500)
            .await
            .map_err(|e| e.to_string())?;
        let _ = ldap.unbind().await;
        let mut after = before.to_owned();
        for u in &users {
            if u.modify_stamp > after {
                after = u.modify_stamp.clone();
            }
        }
        Ok((users.iter().map(object_from).collect(), after))
    }
}

/// `Engine.Sync` for the LDAP connector.
pub async fn sync(worker: &Worker, source_key: &str) -> Res<SyncResult> {
    sync_with(
        &LdapConnector(worker),
        &worker.db,
        &worker.instance,
        source_key,
    )
    .await
}

/// Go `Engine.releaseLease` runs on `context.WithoutCancel`, so a worker stopped mid-cycle still
/// frees its lease. A Rust cycle that is dropped never reaches `lease_release`; the stopping loop
/// calls this instead, or the replacement worker (a new instance) skips its immediate cycle
/// against the abandoned lease and waits a whole interval (#472).
pub async fn release_abandoned(db: &WorkerDatabase, instance: &str) -> Res<()> {
    let c = db.connect().await.map_err(|e| e.to_string())?;
    let held = c
        .query(
            "SELECT source_id,source_generation FROM identity_source_leases WHERE process_instance_id=$1::text::uuid",
            &[(&instance, Type::TEXT)],
        )
        .await
        .map_err(|e| e.to_string())?;
    for row in held {
        let source = Source {
            id: row.get(0),
            generation: row.get(1),
            cursor: String::new(),
        };
        lease_release(&c, &source, instance).await?;
    }
    Ok(())
}

/// `directorysync.Engine.Sync` for any connector.
pub async fn sync_with<C: Connector>(
    connector: &C,
    db: &WorkerDatabase,
    instance: &str,
    source_key: &str,
) -> Res<SyncResult> {
    let started = Instant::now();
    let mut result = SyncResult::default();
    connector.preflight()?;
    let label = connector.label();
    let c = db.connect().await.map_err(|e| e.to_string())?;
    let rows = c
        .query(
            "SELECT id,generation,committed_cursor::text FROM identity_sources WHERE source_key=$1",
            &[(&source_key, Type::TEXT)],
        )
        .await
        .map_err(|e| format!("load {label} identity source: {e}"))?;
    let Some(row) = rows.first() else {
        return Err(format!(
            "load {label} identity source: no rows in result set"
        ));
    };
    let source = Source {
        id: row.get(0),
        generation: row.get(1),
        cursor: row.get::<_, Option<String>>(2).unwrap_or_default(),
    };
    let acquired = lease_acquire(&c, &source, instance)
        .await
        .map_err(|e| format!("acquire {label} identity source lease: {e}"))?;
    if !acquired {
        result.skipped = 1;
        return Ok(result);
    }
    let outcome = run(connector, &c, &source, instance, started, &mut result).await;
    if let Err(e) = lease_release(&c, &source, instance).await {
        log_warn(&format!("{label} sync: release identity source lease: {e}"));
    }
    outcome.map(|_| result)
}

async fn run<C: Connector>(
    connector: &C,
    c: &WorkerConnection,
    source: &Source,
    instance: &str,
    started: Instant,
    result: &mut SyncResult,
) -> Res<()> {
    let label = connector.label();
    // Drain the one durable open batch before contacting the directory.
    let resumed = c
        .query(
            "SELECT identity_source_batch_resume($1,$2,$3::text::uuid)::text",
            &[
                (&source.id, Type::INT8),
                (&source.generation, Type::INT8),
                (&instance, Type::TEXT),
            ],
        )
        .await
        .map_err(|e| {
            result.errors = 1;
            format!(
                "resume {label} identity source batch: load unfinished identity source batch: {e}"
            )
        })?;
    let raw: String = resumed.first().map(|r| r.get(0)).unwrap_or_default();
    let found: Value = serde_json::from_str(&raw)
        .map_err(|e| format!("decode unfinished identity source batch: {e}"))?;
    if found["found"].as_bool() == Some(true) {
        let batch = found["batchId"].as_str().unwrap_or("").to_owned();
        if batch.is_empty()
            || found["generation"].as_str().unwrap_or("").is_empty()
                && !found["generation"].is_number()
        {
            result.errors = 1;
            return Err("unfinished identity source batch response is incomplete".into());
        }
        let keys: Vec<String> = found["objectKeys"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        let count = found["entryCount"].as_u64().unwrap_or(0) as usize;
        let (finish, error) =
            drain(c, source, &batch, &keys, count, Instant::now(), instance).await;
        if let Some(e) = error {
            result.errors = 1;
            return Err(format!("resume {label} identity source batch: {e}"));
        }
        result.checked = count as i64;
        result.updated = finish.applied;
        result.skipped = finish.quarantined;
        result.duration = go_duration(started.elapsed());
        return Ok(());
    }

    let before = connector.decode_cursor(&source.cursor)?;
    let (objects, after) = connector.fetch(&before).await?;
    result.checked = objects.len() as i64;
    let (staged, quarantines) = entries(&objects, result, label, connector.forbid_duplicates())?;
    record_quarantines(c, source, instance, &quarantines, label)
        .await
        .inspect_err(|_| result.errors = 1)?;
    let (before_json, after_json) = (
        connector.encode_cursor(&before),
        connector.encode_cursor(&after),
    );
    let chunks = staged.len().div_ceil(MAX_ENTRIES).max(1);
    let passes = if chunks > 1 { 2 } else { 1 };
    let mut finishes: Vec<(Finish, usize, usize)> = vec![];
    for pass in 0..passes {
        for chunk in 0..chunks {
            let start = chunk * MAX_ENTRIES;
            let end = (start + MAX_ENTRIES).min(staged.len());
            let cursor = if pass == passes - 1 && chunk == chunks - 1 {
                &after_json
            } else {
                &before_json
            };
            let page = &staged[start.min(staged.len())..end];
            let finish = apply_page(c, source, cursor, page, instance)
                .await
                .inspect_err(|_| result.errors = 1)?;
            if pass == passes - 1 {
                let disables = page
                    .iter()
                    .filter(|e| e.payload.contains("\"operation\":\"disable\""))
                    .count();
                finishes.push((finish, page.len(), disables));
            }
        }
    }
    for (finish, count, disables) in finishes {
        result.updated += finish.applied;
        result.skipped += finish.quarantined;
        if finish.quarantined == 0 && finish.applied as usize == count {
            result.disabled += disables as i64;
        }
    }
    result.duration = go_duration(started.elapsed());
    Ok(())
}

async fn record_quarantines(
    c: &WorkerConnection,
    s: &Source,
    instance: &str,
    records: &[Quarantine],
    label: &str,
) -> Res<()> {
    if records.is_empty() {
        return Ok(());
    }
    if records.len() > QUARANTINE_MAX_RECORDS {
        return Err(format!(
            "{label} sync produced {} quarantine records; maximum is {QUARANTINE_MAX_RECORDS}",
            records.len()
        ));
    }
    let payload: Vec<Value> = records
        .iter()
        .map(|r| json!({"objectKey": r.object_key, "subjectDigest": r.digest, "reasonCode": r.reason}))
        .collect();
    let text = serde_json::to_string(&payload).map_err(|e| e.to_string())?;
    let rows = c
        .query(
            "SELECT identity_source_quarantine_record($1,$2,$3::text::uuid,$4::text::jsonb)",
            &[
                (&s.id, Type::INT8),
                (&s.generation, Type::INT8),
                (&instance, Type::TEXT),
                (&text, Type::TEXT),
            ],
        )
        .await
        .map_err(|e| format!("record {label} quarantine accounting: {e}"))?;
    let recorded: i32 = rows.first().map(|r| r.get(0)).unwrap_or(0);
    if recorded as usize != records.len() {
        return Err(format!(
            "record {label} quarantine accounting: quarantine ledger recorded {recorded} of {} records",
            records.len()
        ));
    }
    Ok(())
}
