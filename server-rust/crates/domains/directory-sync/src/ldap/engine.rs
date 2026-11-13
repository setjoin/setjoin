//! LDAP sync engine mirroring `mailserver/internal/ldapsync/sync.go` (legacy
//! email/anchor path) plus the read-only dry run and preview.
//!
//! Every database effect is one fixed statement or one reducer call on the
//! worker connection, exactly the statements frozen Go issues. Errors follow
//! Go: an unreadable protection or authority state fails the entry (counted in
//! `errors`), never degrades to "no protection".
use super::client::{normalize_dn, ClientError, ConnClass, ConnError, LdapClient, LdapUser};
use super::{canonical_address, go_duration, go_quote, log_warn};
use serde_json::Value;
use setjoin_pg::workers::{WorkerConnection, WorkerDatabase};
use setjoin_pg::Type;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::time::Instant;

pub type Res<T> = Result<T, String>;

pub const DEFAULT_ABSENCE_SWEEP_HOURS: i64 = 24;
const ALWAYS_LOCAL_ONLY: &str = "krb5_principal";
/// Go `syncWriterAttrsKeys` in the order Rust applies them (Go ranges a map).
const ATTR_ORDER: [&str; 7] = [
    "display_name",
    "email",
    "first_name",
    "job_title",
    "krb5_principal",
    "last_name",
    "phone",
];

/// Go `ldaputil.SyncResult`, with Go's JSON field order and tags.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SyncResult {
    pub checked: i64,
    pub created: i64,
    pub updated: i64,
    pub disabled: i64,
    pub skipped: i64,
    pub errors: i64,
    pub duration: String,
}
impl SyncResult {
    pub fn json(&self) -> String {
        format!(
            "{{\"checked\":{},\"created\":{},\"updated\":{},\"disabled\":{},\"skipped\":{},\"errors\":{},\"duration\":{}}}\n",
            self.checked,
            self.created,
            self.updated,
            self.disabled,
            self.skipped,
            self.errors,
            serde_json::to_string(&self.duration).expect("string")
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreviewRow {
    pub email: String,
    pub display_name: String,
    pub action: &'static str,
    pub reason: String,
}

/// The built worker: one configured directory (Go `SyncWorker`).
#[derive(Clone)]
pub struct Worker {
    pub client: LdapClient,
    pub db: WorkerDatabase,
    pub interval_min: i64,
    pub filter: String,
    /// `Some("legacy:ldap")` when the normalized, generation-fenced path is on.
    pub source_key: Option<String>,
    /// Lease owner for the normalized path; stable for the worker's life.
    pub instance: String,
    /// Go `SetEnabledResolver`: mutating cycles skip while disabled.
    pub enabled: bool,
}

/// `ldap.CompileFilter` admission used by Go's `SetFilter`.
pub fn admit_filter(filter: &str) -> Res<()> {
    if filter.is_empty() || super::filter::compile(filter).is_some() {
        Ok(())
    } else {
        Err("invalid LDAP user filter".into())
    }
}

/// Go `buildSyncFilter`.
pub fn build_sync_filter(base: &str, cursor: &str) -> String {
    let base = if base.is_empty() {
        "(objectClass=person)"
    } else {
        base
    };
    if cursor.is_empty() {
        base.to_owned()
    } else {
        format!("(&{base}(modifyTimestamp>={cursor}))")
    }
}

fn printable_ascii(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| (0x20..=0x7e).contains(&b))
}

fn reserved(email: &str) -> bool {
    let at = match email.rfind('@') {
        Some(at) => at,
        None => return false,
    };
    let local = email[..at].to_lowercase();
    let local = local
        .strip_prefix('"')
        .and_then(|l| l.strip_suffix('"'))
        .unwrap_or(&local);
    [
        "postmaster",
        "abuse",
        "webmaster",
        "hostmaster",
        "mailer-daemon",
        "nobody",
    ]
    .contains(&local)
}

async fn text_config(c: &WorkerConnection, key: &str) -> Option<String> {
    let rows = c
        .query(
            "SELECT value #>> '{}' FROM system_config WHERE key = $1",
            &[(&key, Type::TEXT)],
        )
        .await
        .ok()?;
    rows.first()?.get::<_, Option<String>>(0)
}

/// Go `strconv.Atoi(strings.TrimSpace(raw))`.
fn atoi(raw: &str) -> Option<i64> {
    let t = raw.trim_matches(|c: char| c.is_whitespace());
    let digits = t.strip_prefix(['+', '-']).unwrap_or(t);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    t.parse::<i64>()
        .ok()
        .or_else(|| t.strip_prefix('+')?.parse().ok())
}

impl Worker {
    pub async fn connect_db(&self) -> Res<WorkerConnection> {
        self.db.connect().await.map_err(|e| e.to_string())
    }

    /// Go `searchOnly`: bind and search without touching the database.
    async fn search_only(&self, limit: u32) -> Result<Vec<LdapUser>, ConnError> {
        let network = |e: ClientError| ConnError {
            class: ConnClass::Network,
            message: e.to_string(),
        };
        let mut ldap = self.client.connect().await.map_err(network)?;
        if let Err(e) = self.client.bind(&mut ldap).await {
            let class = match e {
                ClientError::Bind {
                    invalid_credentials: true,
                    ..
                } => ConnClass::BindAuth,
                _ => ConnClass::Network,
            };
            return Err(ConnError {
                class,
                message: e.to_string(),
            });
        }
        let page = if limit > 0 && limit < 500 { limit } else { 500 };
        let users = self
            .client
            .search_users(&mut ldap, &self.filter, page)
            .await
            .map_err(network);
        let _ = ldap.unbind().await;
        users
    }

    pub async fn dry_run(&self, limit: i64) -> Result<i64, ConnError> {
        let limit = if limit <= 0 { 5 } else { limit };
        Ok(self.search_only(limit as u32).await?.len() as i64)
    }

    /// Total directory count and a bounded, mapped sample (zero writes).
    pub async fn preview(&self, limit: i64) -> Result<(usize, Vec<PreviewRow>), ConnError> {
        let limit = if limit <= 0 { 25 } else { limit } as usize;
        let users = self.search_only(0).await?;
        let total = users.len();
        let mut rows = vec![];
        if let Ok(conn) = self.connect_db().await {
            for user in users.iter().take(limit) {
                rows.push(self.preview_row(&conn, user).await);
            }
        } else {
            for user in users.iter().take(limit) {
                rows.push(PreviewRow {
                    email: user.email.clone(),
                    display_name: user.display_name.clone(),
                    action: if user.email.is_empty() {
                        "skip"
                    } else {
                        "create"
                    },
                    reason: if user.email.is_empty() {
                        "no email attribute".into()
                    } else {
                        String::new()
                    },
                });
            }
        }
        Ok((total, rows))
    }

    async fn preview_row(&self, c: &WorkerConnection, u: &LdapUser) -> PreviewRow {
        let mut row = PreviewRow {
            email: u.email.clone(),
            display_name: u.display_name.clone(),
            action: "",
            reason: String::new(),
        };
        if u.email.is_empty() {
            row.action = "skip";
            row.reason = "no email attribute".into();
            return row;
        }
        let canon = canonical_address(&u.email);
        let existing = c
            .query(
                "SELECT id FROM users WHERE email = $1",
                &[(&canon, Type::TEXT)],
            )
            .await
            .ok()
            .and_then(|r| r.first().map(|r| r.get::<_, i64>(0)));
        if existing.is_none() {
            row.action = "create";
            return row;
        }
        if u.disabled {
            row.action = "disable";
            return row;
        }
        match c
            .query(
                "SELECT fp.field FROM field_policy fp JOIN users u ON u.id = fp.user_id \
                 WHERE u.email = $1 AND fp.policy = 'local_only'",
                &[(&canon, Type::TEXT)],
            )
            .await
        {
            Err(_) => {
                row.action = "skip";
                row.reason = "local-only field policy read failed".into();
            }
            Ok(rows) => {
                let fields: HashSet<String> = rows.iter().map(|r| r.get::<_, String>(0)).collect();
                let fields = enforce_always_local_only(fields);
                row.action = "update";
                if !fields.is_empty() {
                    row.reason = format!(
                        "{} locked local-only field(s) will be skipped",
                        fields.len()
                    );
                }
            }
        }
        row
    }

    /// Go `sync`: one cycle. `Err` mirrors Go's returned error (no result body).
    pub async fn sync(&self) -> Res<SyncResult> {
        if !self.enabled {
            return Ok(SyncResult {
                skipped: 1,
                ..Default::default()
            });
        }
        if let Some(key) = &self.source_key {
            return super::normalized::sync(self, key).await;
        }
        let start = Instant::now();
        let mut result = SyncResult::default();
        let mut ldap = self.client.connect().await.map_err(|e| {
            log_warn(&format!("LDAP sync: connect failed: {e}"));
            e.to_string()
        })?;
        self.client.bind(&mut ldap).await.map_err(|e| {
            log_warn(&format!("LDAP sync: bind failed: {e}"));
            e.to_string()
        })?;
        let conn = self.connect_db().await?;
        let cursor = text_config(&conn, "ldap_sync_last_cursor")
            .await
            .unwrap_or_default();

        let sweep_hours = self.absence_sweep_interval(&conn).await;
        let mut full = cursor.is_empty();
        let mut sweep_due = full && sweep_hours > 0;
        if !full && sweep_hours > 0 {
            let last = self.last_absence_sweep(&conn).await;
            let due = match last {
                None => true,
                Some(at) => {
                    let age = std::time::SystemTime::now()
                        .duration_since(at)
                        .unwrap_or_default();
                    age >= std::time::Duration::from_secs(sweep_hours as u64 * 3600)
                }
            };
            if due {
                full = true;
                sweep_due = true;
            }
        }
        let cursor_for_search = if full { "" } else { cursor.as_str() };
        let filter = build_sync_filter(&self.filter, cursor_for_search);
        let users = self
            .client
            .search_users(&mut ldap, &filter, 500)
            .await
            .map_err(|e| {
                log_warn(&format!("LDAP sync: search failed: {e}"));
                e.to_string()
            })?;
        let _ = ldap.unbind().await;
        result.checked = users.len() as i64;
        let auto_depts = text_config(&conn, "ldap_sync_auto_create_depts")
            .await
            .as_deref()
            == Some("true");
        for user in &users {
            if user.email.is_empty() {
                continue;
            }
            if let Err(e) = self.upsert_user(&conn, user, auto_depts, &mut result).await {
                result.errors += 1;
                log_warn(&format!(
                    "LDAP sync: upsert failed user={} error={e}",
                    user.email
                ));
            }
        }
        self.resolve_manager_ids(&conn, &users).await;
        if sweep_due {
            if let Err(e) = self.disable_absent_users(&conn, &users, &mut result).await {
                result.errors += 1;
                log_warn(&format!("LDAP sync: absence sweep failed; absent accounts stay enabled and the sweep retries next cycle: {e}"));
            } else if let Err(e) = self.record_absence_sweep(&conn).await {
                result.errors += 1;
                log_warn(&format!("LDAP sync: failed to record absence sweep timestamp; the sweep retries next cycle: {e}"));
            }
        }
        let max_stamp = users
            .iter()
            .map(|u| u.modify_stamp.as_str())
            .max()
            .unwrap_or("")
            .to_owned();
        if !max_stamp.is_empty() && result.errors == 0 {
            let quoted = go_quote(&max_stamp);
            conn.query(
                "INSERT INTO system_config (key, value, description) VALUES ('ldap_sync_last_cursor', $1::text::jsonb, 'LDAP modifyTimestamp cursor') \
                 ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()",
                &[(&quoted, Type::TEXT)],
            )
            .await
            .map_err(|e| format!("LDAP sync: update cursor: {e}"))?;
        }
        let details = if full {
            format!(
                "{{\"cursor_after\":{},\"full_enumeration\":true}}",
                go_quote(&max_stamp)
            )
        } else {
            format!("{{\"cursor_after\":{}}}", go_quote(&max_stamp))
        };
        let summary = if result.errors == 0 {
            String::new()
        } else {
            format!("{} directory entries failed", result.errors)
        };
        let ms = start.elapsed().as_millis() as i32;
        let (checked, created, updated, disabled, skipped) = (
            result.checked as i32,
            result.created as i32,
            result.updated as i32,
            result.disabled as i32,
            result.skipped as i32,
        );
        if let Err(e) = conn
            .query(
                "INSERT INTO identity_sync_log (source, users_checked, users_created, users_updated, users_disabled, \
                 fields_skipped, duration_ms, error, details) VALUES ($1, $2, $3, $4, $5, $6, $7, NULLIF($8, ''), $9::text::jsonb)",
                &[
                    (&"ldap", Type::TEXT),
                    (&checked, Type::INT4),
                    (&created, Type::INT4),
                    (&updated, Type::INT4),
                    (&disabled, Type::INT4),
                    (&skipped, Type::INT4),
                    (&ms, Type::INT4),
                    (&summary, Type::TEXT),
                    (&details, Type::TEXT),
                ],
            )
            .await
        {
            log_warn(&format!("LDAP sync: failed to insert sync log: {e}"));
        }
        result.duration = go_duration(start.elapsed());
        Ok(result)
    }

    async fn absence_sweep_interval(&self, c: &WorkerConnection) -> i64 {
        let raw = text_config(c, "ldap_sync_absence_sweep_hours")
            .await
            .unwrap_or_default();
        match atoi(&raw) {
            Some(h) if h >= 0 => h,
            _ => DEFAULT_ABSENCE_SWEEP_HOURS,
        }
    }

    async fn last_absence_sweep(&self, c: &WorkerConnection) -> Option<std::time::SystemTime> {
        let raw = text_config(c, "ldap_sync_last_absence_sweep")
            .await
            .unwrap_or_default();
        let at = chrono_free_rfc3339(raw.trim())?;
        Some(at)
    }

    async fn record_absence_sweep(&self, c: &WorkerConnection) -> Res<()> {
        let now = go_quote(&super::rfc3339_now());
        c.query(
            "INSERT INTO system_config (key, value, description) VALUES ('ldap_sync_last_absence_sweep', $1::text::jsonb, \
             'LDAP absent-entry deprovisioning sweep timestamp (RFC3339)') \
             ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()",
            &[(&now, Type::TEXT)],
        )
        .await
        .map_err(|e| format!("LDAP sync: record absence sweep: {e}"))?;
        Ok(())
    }

    async fn resolve_anchor(&self, c: &WorkerConnection, subject: &str) -> Res<Anchor> {
        let rows = c
            .query(
                "SELECT ldap_sync_anchor_resolve($1::text, NULL::bigint)::text",
                &[(&subject, Type::TEXT)],
            )
            .await?;
        let raw: String = rows
            .first()
            .ok_or("anchor resolution returned no row")?
            .get(0);
        let v: Value =
            serde_json::from_str(&raw).map_err(|e| format!("decode anchor resolution: {e}"))?;
        let text = |k: &str| v.get(k).and_then(Value::as_str).unwrap_or("").to_owned();
        let num = |k: &str| v.get(k).and_then(Value::as_i64).unwrap_or(0);
        Ok(Anchor {
            resolution: text("resolution"),
            user_id: num("userId"),
            generation: num("generation"),
            reason: text("reason"),
        })
    }

    async fn upsert_user(
        &self,
        c: &WorkerConnection,
        u: &LdapUser,
        auto_depts: bool,
        result: &mut SyncResult,
    ) -> Res<()> {
        if u.email.is_empty() {
            return Ok(());
        }
        let canon = canonical_address(&u.email);
        let mut dept: Option<i64> = None;
        if auto_depts && !u.department.is_empty() {
            if let Ok(rows) = c
                .query(
                    "INSERT INTO departments (name,path,ldap_ou) VALUES ($1,$1,$1) ON CONFLICT (path) DO UPDATE SET \
                     name = EXCLUDED.name, ldap_ou = EXCLUDED.ldap_ou RETURNING id",
                    &[(&u.department, Type::TEXT)],
                )
                .await
            {
                dept = rows.first().map(|r| r.get::<_, i64>(0));
            }
        }
        let mut existing: i64 = 0;
        let mut anchored = false;
        let mut generation = 0i64;
        if !u.immutable_subject.is_empty() {
            let res = self
                .resolve_anchor(c, &u.immutable_subject)
                .await
                .map_err(|e| format!("resolve anchor for {:?}: {e}", u.immutable_subject))?;
            generation = res.generation;
            match res.resolution.as_str() {
                "anchored" => {
                    existing = res.user_id;
                    anchored = true;
                }
                "missing" | "no_source" => {}
                "stale" => {
                    return Err(format!(
                        "anchor {:?} is stale: source generation moved past {} (outcome retried next cycle)",
                        u.immutable_subject, res.generation
                    ))
                }
                _ => {
                    result.skipped += 1;
                    log_warn(&format!(
                        "LDAP sync: anchor denied lifecycle authority; entry skipped without email fallback email={canon} reason={}",
                        res.reason
                    ));
                    if res.user_id != 0 {
                        c.query(
                            "INSERT INTO sync_conflicts (user_id, field, local_value, remote_value, source) VALUES ($1, 'email', $2, $3, 'ldap')",
                            &[(&res.user_id, Type::INT8), (&canon, Type::TEXT), (&u.immutable_subject, Type::TEXT)],
                        )
                        .await
                        .map_err(|e| format!("record denied-anchor conflict for user {}: {e}", res.user_id))?;
                    }
                    return Ok(());
                }
            }
        }
        if !anchored {
            let rows = c
                .query(
                    "SELECT id, sync_source FROM users WHERE lower(email) = $1",
                    &[(&canon, Type::TEXT)],
                )
                .await;
            // Go treats any scan error (including no row) as "create".
            let found = rows.ok().and_then(|r| {
                r.first()
                    .map(|r| (r.get::<_, i64>(0), r.get::<_, String>(1)))
            });
            let Some((id, sync_source)) = found else {
                if !printable_ascii(&u.email) || (!u.upn.is_empty() && !printable_ascii(&u.upn)) {
                    result.skipped += 1;
                    log_warn(&format!(
                        "LDAP sync: directory entry carries control characters in its address; refusing to provision email={canon}"
                    ));
                    return Ok(());
                }
                if reserved(&canon) {
                    return Err("provision_account: email local-part is reserved (RFC 2142)".into());
                }
                let enabled = !u.disabled;
                let upn = canonical_address(&u.upn);
                let rows = c
                    .query(
                        "SELECT provision_account(p_email => $1, p_display_name => $2, p_enabled => $3, p_sync_source => 'ldap', \
                         p_first_name => $4, p_last_name => $5, p_job_title => $6, p_phone => $7, p_department_id => $8, \
                         p_ad_upn => $9, p_krb5_principal => $10)::text",
                        &[
                            (&canon, Type::TEXT),
                            (&none_if_empty(&u.display_name), Type::TEXT),
                            (&enabled, Type::BOOL),
                            (&none_if_empty(&u.first_name), Type::TEXT),
                            (&none_if_empty(&u.last_name), Type::TEXT),
                            (&none_if_empty(&u.title), Type::TEXT),
                            (&none_if_empty(&u.phone), Type::TEXT),
                            (&dept, Type::INT8),
                            (&none_if_empty(&upn), Type::TEXT),
                            (&none_if_empty(&u.upn), Type::TEXT),
                        ],
                    )
                    .await?;
                if !u.immutable_subject.is_empty() {
                    let raw: String = rows.first().map(|r| r.get(0)).unwrap_or_default();
                    let user_id = serde_json::from_str::<Value>(&raw)
                        .ok()
                        .and_then(|v| v.get("user_id").and_then(Value::as_i64))
                        .unwrap_or(0);
                    if user_id != 0 {
                        self.link_provisioned_user(c, user_id, &u.immutable_subject, generation)
                            .await;
                    }
                }
                result.created += 1;
                return Ok(());
            };
            existing = id;
            if sync_source != "ldap" {
                result.skipped += 1;
                let remote = if u.immutable_subject.is_empty() {
                    canon.clone()
                } else {
                    u.immutable_subject.clone()
                };
                log_warn(&format!(
                    "LDAP sync: directory entry does not anchor the matched account; skipping email={canon} account_sync_source={sync_source}"
                ));
                c.query(
                    "INSERT INTO sync_conflicts (user_id, field, local_value, remote_value, source) VALUES ($1, 'email', $2, $3, 'ldap')",
                    &[(&existing, Type::INT8), (&canon, Type::TEXT), (&remote, Type::TEXT)],
                )
                .await
                .map_err(|e| format!("record unanchored directory match for user {existing}: {e}"))?;
                return Ok(());
            }
        }
        if u.disabled {
            self.disable_sync_user(c, existing, "directory disabled entry", generation)
                .await?;
            result.disabled += 1;
            return Ok(());
        }
        let overrides = c
            .query(
                "SELECT local_overrides::TEXT FROM users WHERE id = $1",
                &[(&existing, Type::INT8)],
            )
            .await
            .map_err(|e| format!("load local_overrides for user {existing}: {e}"))?;
        let mut local_overrides: BTreeMap<String, Value> = BTreeMap::new();
        if let Some(raw) = overrides
            .first()
            .and_then(|r| r.get::<_, Option<String>>(0))
        {
            if raw.len() > 2 {
                match serde_json::from_str::<Value>(&raw) {
                    Ok(Value::Object(map)) => local_overrides = map.into_iter().collect(),
                    Ok(Value::Null) => {}
                    _ => {
                        return Err(format!(
                            "decode local_overrides for user {existing}: not an object"
                        ))
                    }
                }
            }
        }
        let rows = c
            .query(
                "SELECT fp.field FROM field_policy fp WHERE fp.user_id = $1 AND fp.policy = 'local_only'",
                &[(&existing, Type::INT8)],
            )
            .await
            .map_err(|e| format!("load local-only field policy for user {existing}: {e}"))?;
        let local_only: HashSet<String> = rows.iter().map(|r| r.get::<_, String>(0)).collect();
        let attrs = sync_attrs(u);
        apply_user_update(
            c,
            existing,
            &attrs,
            &local_only,
            &local_overrides,
            dept,
            "ldap",
            result,
        )
        .await
    }

    async fn disable_sync_user(
        &self,
        c: &WorkerConnection,
        user: i64,
        reason: &str,
        generation: i64,
    ) -> Res<()> {
        let pinned: Option<i64> = (generation > 0).then_some(generation);
        c.query(
            "SELECT ldap_sync_disable_user($1::bigint, $2::text, $3::bigint)::text",
            &[
                (&user, Type::INT8),
                (&reason, Type::TEXT),
                (&pinned, Type::INT8),
            ],
        )
        .await
        .map_err(|e| format!("disable user {user}: {e}"))?;
        Ok(())
    }

    async fn link_provisioned_user(
        &self,
        c: &WorkerConnection,
        user: i64,
        subject: &str,
        generation: i64,
    ) {
        let pinned: Option<i64> = (generation > 0).then_some(generation);
        match c
            .query(
                "SELECT ldap_sync_anchor_link($1::bigint, $2::text, $3::bigint)::text",
                &[(&user, Type::INT8), (&subject, Type::TEXT), (&pinned, Type::INT8)],
            )
            .await
        {
            Err(e) => log_warn(&format!(
                "LDAP sync: could not anchor provisioned account to immutable subject user_id={user}: {e}"
            )),
            Ok(rows) => {
                let raw: String = rows.first().map(|r| r.get(0)).unwrap_or_default();
                match serde_json::from_str::<Value>(&raw) {
                    Err(_) => log_warn("LDAP sync: undecodable anchor-link outcome"),
                    Ok(v) if v.get("linked").and_then(Value::as_bool) != Some(true) => log_warn(&format!(
                        "LDAP sync: immutable subject was not anchored to the provisioned account; link left unchanged user_id={user}"
                    )),
                    Ok(_) => {}
                }
            }
        }
    }

    async fn disable_absent_users(
        &self,
        c: &WorkerConnection,
        users: &[LdapUser],
        result: &mut SyncResult,
    ) -> Res<()> {
        let present_emails: Vec<String> = users
            .iter()
            .filter(|u| !u.email.is_empty())
            .map(|u| canonical_address(&u.email))
            .collect();
        let present_subjects: Vec<String> = users
            .iter()
            .filter(|u| !u.immutable_subject.is_empty())
            .map(|u| u.immutable_subject.clone())
            .collect();
        let rows = c
            .query(
                "SELECT id, email FROM users WHERE sync_source = 'ldap' AND enabled AND NOT is_guest_account(id) \
                 AND lower(email) <> ALL($1::text[]) \
                 AND NOT EXISTS (SELECT 1 FROM user_identity_links l JOIN identity_sources s ON s.id = l.source_id \
                   WHERE s.source_key = 'legacy:ldap' AND l.state = 'active' AND l.user_id = users.id \
                   AND l.external_subject = ANY($2::text[])) \
                 AND NOT EXISTS (SELECT 1 FROM user_lifecycle_authorities a JOIN user_identity_links l2 ON l2.id = a.link_id \
                   JOIN identity_sources s2 ON s2.id = l2.source_id WHERE a.user_id = users.id \
                   AND a.authority_kind = 'source' AND s2.source_key <> 'legacy:ldap')",
                &[(&present_emails, Type::TEXT_ARRAY), (&present_subjects, Type::TEXT_ARRAY)],
            )
            .await
            .map_err(|e| format!("absence sweep query: {e}"))?;
        let absentees: Vec<(i64, String)> = rows.iter().map(|r| (r.get(0), r.get(1))).collect();
        for (id, email) in absentees {
            self.disable_sync_user(c, id, "absent from full directory enumeration", 0)
                .await
                .map_err(|e| format!("absence sweep disable {email:?}: {e}"))?;
            result.disabled += 1;
        }
        Ok(())
    }

    async fn resolve_manager_ids(&self, c: &WorkerConnection, users: &[LdapUser]) {
        let emails: Vec<String> = users
            .iter()
            .filter(|u| !u.email.is_empty())
            .map(|u| canonical_address(&u.email))
            .collect();
        let subjects: Vec<String> = users
            .iter()
            .filter(|u| !u.immutable_subject.is_empty())
            .map(|u| u.immutable_subject.clone())
            .collect();
        if emails.is_empty() && subjects.is_empty() {
            return;
        }
        let (authorized, subject_to_id) =
            match self.authorized_manager_targets(c, &emails, &subjects).await {
                Ok(v) => v,
                Err(e) => {
                    log_warn(&format!(
                        "LDAP sync: manager pass: failed to resolve authorized targets: {e}"
                    ));
                    return;
                }
            };
        if !authorized.is_empty() {
            let mut ids: Vec<i64> = authorized.iter().copied().collect();
            ids.sort_unstable();
            if let Err(e) = c
                .query(
                    "UPDATE users SET manager_id = NULL WHERE id = ANY($1::bigint[])",
                    &[(&ids, Type::INT8_ARRAY)],
                )
                .await
            {
                log_warn(&format!(
                    "LDAP sync: manager pass: failed to clear stale manager_ids: {e}"
                ));
                return;
            }
        }
        let rows = match c
            .query(
                "SELECT email, id FROM users WHERE email = ANY($1) AND sync_source = 'ldap' AND NOT is_guest_account(id) \
                 AND NOT EXISTS (SELECT 1 FROM user_lifecycle_authorities a JOIN user_identity_links l2 ON l2.id = a.link_id \
                   JOIN identity_sources s2 ON s2.id = l2.source_id WHERE a.user_id = users.id \
                   AND a.authority_kind = 'source' AND s2.source_key <> 'legacy:ldap')",
                &[(&emails, Type::TEXT_ARRAY)],
            )
            .await
        {
            Ok(rows) => rows,
            Err(e) => {
                log_warn(&format!("LDAP sync: manager pass: failed to fetch user ids: {e}"));
                return;
            }
        };
        let email_to_id: HashMap<String, i64> = rows
            .iter()
            .map(|r| (r.get::<_, String>(0), r.get::<_, i64>(1)))
            .collect();
        let resolve_self = |u: &LdapUser| -> Option<i64> {
            if !u.immutable_subject.is_empty() {
                if let Some(id) = subject_to_id.get(&u.immutable_subject) {
                    if authorized.contains(id) {
                        return Some(*id);
                    }
                }
            }
            if u.email.is_empty() {
                return None;
            }
            let id = *email_to_id.get(&canonical_address(&u.email))?;
            authorized.contains(&id).then_some(id)
        };
        let mut dn_to_id: HashMap<String, i64> = HashMap::new();
        for u in users {
            if u.dn.is_empty() {
                continue;
            }
            if let Some(id) = resolve_self(u) {
                dn_to_id.insert(normalize_dn(&u.dn), id);
            }
        }
        for u in users {
            if u.manager_dn.is_empty() || u.email.is_empty() {
                continue;
            }
            let Some(self_id) = resolve_self(u) else {
                continue;
            };
            let Some(manager_id) = dn_to_id.get(&normalize_dn(&u.manager_dn)).copied() else {
                continue;
            };
            if let Err(e) = c
                .query(
                    "UPDATE users SET manager_id = $1 WHERE id = $2",
                    &[(&manager_id, Type::INT8), (&self_id, Type::INT8)],
                )
                .await
            {
                log_warn(&format!("LDAP sync: failed to update manager_id user_id={self_id} manager_id={manager_id}: {e}"));
            }
        }
    }

    async fn authorized_manager_targets(
        &self,
        c: &WorkerConnection,
        emails: &[String],
        subjects: &[String],
    ) -> Res<(HashSet<i64>, HashMap<String, i64>)> {
        let rows = c
            .query(
                "SELECT u.id FROM users u WHERE NOT is_guest_account(u.id) AND ( lower(u.email) = ANY($1::text[]) OR EXISTS ( \
                 SELECT 1 FROM user_identity_links la JOIN identity_sources sa ON sa.id = la.source_id \
                 WHERE la.user_id = u.id AND sa.source_key = 'legacy:ldap' AND la.state = 'active' \
                 AND la.external_subject = ANY($2::text[]) ) ) AND ( ( u.sync_source = 'ldap' AND NOT EXISTS ( \
                 SELECT 1 FROM user_lifecycle_authorities a JOIN user_identity_links l2 ON l2.id = a.link_id \
                 JOIN identity_sources s2 ON s2.id = l2.source_id WHERE a.user_id = u.id AND a.authority_kind = 'source' \
                 AND s2.source_key <> 'legacy:ldap' ) ) OR EXISTS ( SELECT 1 FROM user_identity_links l \
                 JOIN identity_sources s ON s.id = l.source_id WHERE l.user_id = u.id AND s.source_key = 'legacy:ldap' \
                 AND s.state = 'active' AND l.state = 'active' AND 'provision' = ANY (l.purposes) ) )",
                &[(&emails, Type::TEXT_ARRAY), (&subjects, Type::TEXT_ARRAY)],
            )
            .await?;
        let authorized: HashSet<i64> = rows.iter().map(|r| r.get::<_, i64>(0)).collect();
        let mut subject_to_id = HashMap::new();
        if !subjects.is_empty() {
            let rows = c
                .query(
                    "SELECT l.external_subject, l.user_id FROM user_identity_links l JOIN identity_sources s ON s.id = l.source_id \
                     JOIN users u ON u.id = l.user_id WHERE s.source_key = 'legacy:ldap' AND s.state = 'active' \
                     AND l.state = 'active' AND 'provision' = ANY (l.purposes) AND NOT is_guest_account(u.id) \
                     AND l.external_subject = ANY($1::text[])",
                    &[(&subjects, Type::TEXT_ARRAY)],
                )
                .await?;
            for row in rows {
                subject_to_id.insert(row.get::<_, String>(0), row.get::<_, i64>(1));
            }
        }
        Ok((authorized, subject_to_id))
    }
}

struct Anchor {
    resolution: String,
    user_id: i64,
    generation: i64,
    reason: String,
}

fn none_if_empty(s: &str) -> Option<String> {
    (!s.is_empty()).then(|| s.to_owned())
}

pub fn enforce_always_local_only(mut fields: HashSet<String>) -> HashSet<String> {
    fields.insert(ALWAYS_LOCAL_ONLY.into());
    fields
}

/// Go `buildLDAPSyncAttrs` (`ldaputil.SyncAttrs`): users column -> directory value.
pub fn sync_attrs(u: &LdapUser) -> BTreeMap<&'static str, String> {
    BTreeMap::from([
        ("email", canonical_address(&u.email)),
        ("display_name", u.display_name.clone()),
        ("first_name", u.first_name.clone()),
        ("last_name", u.last_name.clone()),
        ("job_title", u.title.clone()),
        ("phone", u.phone.clone()),
        ("krb5_principal", u.upn.clone()),
    ])
}

/// Go `ldaputil.ApplyUserUpdate` for the LDAP engine (no extra sets).
#[allow(clippy::too_many_arguments)]
pub async fn apply_user_update(
    c: &WorkerConnection,
    existing: i64,
    attrs: &BTreeMap<&'static str, String>,
    local_only: &HashSet<String>,
    local_overrides: &BTreeMap<String, Value>,
    dept: Option<i64>,
    source: &str,
    result: &mut SyncResult,
) -> Res<()> {
    let local_only = enforce_always_local_only(local_only.clone());
    let mut sets: Vec<String> = vec![];
    let mut values: Vec<String> = vec![];
    for col in ATTR_ORDER {
        let Some(val) = attrs.get(col) else { continue };
        if val.is_empty() {
            continue;
        }
        if local_only.contains(col) {
            if col == ALWAYS_LOCAL_ONLY {
                audit_suppressed_principal_write(c, existing, val, source).await?;
            }
            result.skipped += 1;
            continue;
        }
        if local_overrides.get(col).is_some_and(|v| !v.is_null()) {
            let remote = super::go_json_string(val);
            let local = super::go_json(&local_overrides[col]);
            c.query(
                "INSERT INTO sync_conflicts (user_id, field, local_value, remote_value, source) VALUES ($1, $2, $3, $4, $5)",
                &[(&existing, Type::INT8), (&col, Type::TEXT), (&local, Type::TEXT), (&remote, Type::TEXT), (&source, Type::TEXT)],
            )
            .await
            .map_err(|e| format!("record sync conflict for {col}: {e}"))?;
            result.skipped += 1;
            continue;
        }
        sets.push(format!("{col} = ${}", sets.len() + 1));
        values.push(val.clone());
    }
    let mut dept_arg: Option<i64> = None;
    if let Some(d) = dept {
        if !local_overrides
            .get("department_id")
            .is_some_and(|v| !v.is_null())
        {
            sets.push(format!("department_id = ${}", sets.len() + 1));
            dept_arg = Some(d);
        }
    }
    if sets.is_empty() {
        return Ok(());
    }
    let id_index = sets.len() + 1;
    let sql = format!(
        "UPDATE users SET {} WHERE id = ${id_index}",
        sets.join(", ")
    );
    let mut params: Vec<setjoin_pg::Param<'_>> = vec![];
    for v in &values {
        params.push((v, Type::TEXT));
    }
    if let Some(d) = dept_arg.as_ref() {
        params.push((d, Type::INT8));
    }
    params.push((&existing, Type::INT8));
    c.query(&sql, &params).await?;
    result.updated += 1;
    Ok(())
}

async fn audit_suppressed_principal_write(
    c: &WorkerConnection,
    user: i64,
    directory: &str,
    source: &str,
) -> Res<()> {
    let rows = c
        .query(
            "SELECT krb5_principal FROM users WHERE id = $1",
            &[(&user, Type::INT8)],
        )
        .await
        .map_err(|e| format!("read stored krb5_principal for user {user}: {e}"))?;
    let stored: Option<String> = rows.first().and_then(|r| r.get::<_, Option<String>>(0));
    if stored.as_deref() != Some(directory) {
        log_warn(&format!(
            "directory sync suppressed krb5_principal overwrite user_id={user} source={source}"
        ));
        c.query(
            "INSERT INTO sync_conflicts (user_id, field, local_value, remote_value, source, resolution) VALUES ($1, $2, $3, $4, $5, 'kept_local')",
            &[(&user, Type::INT8), (&ALWAYS_LOCAL_ONLY, Type::TEXT), (&stored, Type::TEXT), (&directory, Type::TEXT), (&source, Type::TEXT)],
        )
        .await
        .map_err(|e| format!("record suppressed krb5_principal overwrite for user {user}: {e}"))?;
    }
    Ok(())
}

/// RFC 3339 parse for the absence-sweep stamp (`time.Parse(time.RFC3339, ...)`).
fn chrono_free_rfc3339(raw: &str) -> Option<std::time::SystemTime> {
    super::parse_rfc3339(raw)
}
