//! Disposable-Postgres verifier for Setjoin's zero-proc-macro typed SQL
//! contract catalog (`verify-sql-contracts`, #541).
//!
//! Verifies every registered [`SqlContract`] against live PostgreSQL 17:
//! - Preflight: non-empty catalog, globally unique IDs, `setjoin_pg::statement::admit`,
//!   zero custom non-builtin OIDs (`>= 16384`), fail-closed role verification
//!   (`setjoin_app` with `rolsuper = false AND rolbypassrls = false` and PG >= 170000;
//!   worker/owner with `rolbypassrls = true OR rolsuper = true`).
//! - Per contract: `prepare_typed` checking exact parameter count/types, exact
//!   column count/types/names, zero custom result OIDs (`< 16384`), plus scoped
//!   `EXPLAIN (COSTS OFF, FORMAT JSON)` verifying `GRANT`s, `BEGIN READ ONLY`,
//!   and `FORCE RLS` expansion.
//! - For `RlsCheck::PrepareExplainAndRlsDenyProbe`: active `SAVEPOINT` probe
//!   against a seeded divergent-ID fixture (cleaned up unconditionally) asserting
//!   `FORCE RLS` denies (`42501` or 0 visible rows) under unset and foreign GUCs.
//! - Supports `--mutant-json <path>` for deterministic negative mutant testing
//!   without recompiling Rust.
#![forbid(unsafe_code)]

use serde::Deserialize;
use setjoin_sql_catalog::{RlsCheck, SqlAuditPosture, SqlContract, SqlScope, Type};
use std::{
    collections::{BTreeMap, HashSet},
    env, fs,
    process::ExitCode,
    sync::Arc,
};
use tokio_postgres::{
    types::{Kind, ToSql},
    Client, NoTls,
};

const ALL_CONTRACTS: &[&[SqlContract]] = &[
    setjoin_blobs::SQL_CONTRACTS,
    setjoin_rules::SQL_CONTRACTS,
    setjoin_user_settings::SQL_CONTRACTS,
    setjoin_approvals::SQL_CONTRACTS,
    setjoin_calendar::SQL_CONTRACTS,
    setjoin_guests::SQL_CONTRACTS,
    setjoin_office::SQL_CONTRACTS,
    setjoin_static::SQL_CONTRACTS,
    setjoin_devices::SQL_CONTRACTS,
];

const FIRST_CUSTOM_OID: u32 = 16384;

#[derive(Clone, Debug)]
struct OwnedColumn {
    name: Option<String>,
    ty: Type,
}

#[derive(Clone, Debug)]
struct OwnedContract {
    id: String,
    domain: String,
    sql: String,
    params: Vec<Type>,
    columns: Vec<OwnedColumn>,
    scope: SqlScope,
    rls_check: RlsCheck,
    audit: SqlAuditPosture,
}

impl From<&SqlContract> for OwnedContract {
    fn from(c: &SqlContract) -> Self {
        Self {
            id: c.id.to_owned(),
            domain: c.domain.to_owned(),
            sql: c.sql.to_owned(),
            params: c.params.to_vec(),
            columns: c
                .columns
                .iter()
                .map(|col| OwnedColumn {
                    name: col.name.map(str::to_owned),
                    ty: col.ty.clone(),
                })
                .collect(),
            scope: c.scope,
            rls_check: c.rls_check,
            audit: c.audit,
        }
    }
}

#[derive(Deserialize)]
struct MutantColumnJson {
    name: Option<String>,
    ty: String,
}

#[derive(Deserialize)]
struct MutantContractJson {
    id: String,
    domain: String,
    sql: String,
    params: Vec<String>,
    columns: Vec<MutantColumnJson>,
    scope: String,
    rls_check: String,
    #[serde(default)]
    audit: Option<String>,
}

fn parse_scope(raw: &str) -> Result<SqlScope, String> {
    match raw {
        "MailboxReadOnly" => Ok(SqlScope::MailboxReadOnly),
        "MailboxReadWrite" => Ok(SqlScope::MailboxReadWrite),
        "UserScoped" => Ok(SqlScope::UserScoped),
        "AdminRead" => Ok(SqlScope::AdminRead),
        "AdminWrite" => Ok(SqlScope::AdminWrite),
        "AuthPreScope" => Ok(SqlScope::AuthPreScope),
        "WorkerBypass" => Ok(SqlScope::WorkerBypass),
        other => Err(format!("unknown SqlScope '{other}'")),
    }
}

fn parse_rls_check(raw: &str) -> Result<RlsCheck, String> {
    match raw {
        "PrepareAndExplain" => Ok(RlsCheck::PrepareAndExplain),
        "PrepareExplainAndRlsDenyProbe" => Ok(RlsCheck::PrepareExplainAndRlsDenyProbe),
        other => Err(format!("unknown RlsCheck '{other}'")),
    }
}

fn parse_audit_posture(raw: Option<&str>) -> Result<SqlAuditPosture, String> {
    match raw {
        None | Some("Standard") => Ok(SqlAuditPosture::Standard),
        Some("ReducerWritesCoreAudit") => Ok(SqlAuditPosture::ReducerWritesCoreAudit),
        Some(other) => Err(format!("unknown SqlAuditPosture '{other}'")),
    }
}

fn parse_pg_type(raw: &str) -> Result<Type, String> {
    if let Some(oid_str) = raw.strip_prefix("oid:") {
        let oid: u32 = oid_str
            .parse()
            .map_err(|_| format!("invalid custom oid '{raw}'"))?;
        return Ok(Type::new(
            format!("custom_oid_{oid}"),
            oid,
            Kind::Simple,
            "public".to_owned(),
        ));
    }
    match raw.to_ascii_lowercase().as_str() {
        "bool" | "boolean" => Ok(Type::BOOL),
        "int2" | "smallint" => Ok(Type::INT2),
        "int4" | "int" | "integer" => Ok(Type::INT4),
        "int8" | "bigint" => Ok(Type::INT8),
        "float4" | "real" => Ok(Type::FLOAT4),
        "float8" => Ok(Type::FLOAT8),
        "text" => Ok(Type::TEXT),
        "varchar" => Ok(Type::VARCHAR),
        "bytea" => Ok(Type::BYTEA),
        "uuid" => Ok(Type::UUID),
        "jsonb" => Ok(Type::JSONB),
        "json" => Ok(Type::JSON),
        "timestamptz" => Ok(Type::TIMESTAMPTZ),
        "timestamp" => Ok(Type::TIMESTAMP),
        "date" => Ok(Type::DATE),
        "time" => Ok(Type::TIME),
        "inet" => Ok(Type::INET),
        "void" => Ok(Type::VOID),
        "int4_array" | "int4[]" => Ok(Type::INT4_ARRAY),
        "int8_array" | "int8[]" | "bigint[]" => Ok(Type::INT8_ARRAY),
        "text_array" | "text[]" => Ok(Type::TEXT_ARRAY),
        other => Err(format!("unsupported PG type name '{other}'")),
    }
}

fn load_mutant_contracts(path: &str) -> Result<Vec<OwnedContract>, String> {
    let raw = fs::read_to_string(path).map_err(|e| format!("read mutant JSON {path}: {e}"))?;
    let parsed: Vec<MutantContractJson> =
        serde_json::from_str(&raw).map_err(|e| format!("parse mutant JSON {path}: {e}"))?;
    let mut out = Vec::with_capacity(parsed.len());
    for item in parsed {
        let params = item
            .params
            .iter()
            .map(|p| parse_pg_type(p))
            .collect::<Result<Vec<_>, _>>()?;
        let columns = item
            .columns
            .into_iter()
            .map(|c| {
                Ok(OwnedColumn {
                    name: c.name,
                    ty: parse_pg_type(&c.ty)?,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        out.push(OwnedContract {
            id: item.id,
            domain: item.domain,
            sql: item.sql,
            params,
            columns,
            scope: parse_scope(&item.scope)?,
            rls_check: parse_rls_check(&item.rls_check)?,
            audit: parse_audit_posture(item.audit.as_deref())?,
        });
    }
    Ok(out)
}

fn swap_dsn_user(dsn: &str, new_user: &str) -> Result<String, String> {
    if let Some(rest) = dsn
        .strip_prefix("postgres://")
        .or_else(|| dsn.strip_prefix("postgresql://"))
    {
        let scheme = if dsn.starts_with("postgresql://") {
            "postgresql://"
        } else {
            "postgres://"
        };
        if let Some((auth, tail)) = rest.split_once('@') {
            let new_auth = match auth.split_once(':') {
                Some((_, pass)) => format!("{new_user}:{pass}"),
                None => new_user.to_owned(),
            };
            return Ok(format!("{scheme}{new_auth}@{tail}"));
        }
        return Ok(format!("{scheme}{new_user}@{rest}"));
    }
    // Key/value libpq DSN format fallback.
    let mut replaced = false;
    let mut parts = Vec::new();
    for token in dsn.split_whitespace() {
        if token.starts_with("user=") {
            parts.push(format!("user={new_user}"));
            replaced = true;
        } else {
            parts.push(token.to_owned());
        }
    }
    if !replaced {
        parts.push(format!("user={new_user}"));
    }
    Ok(parts.join(" "))
}

fn resolve_dsns() -> Result<(String, String), String> {
    let base = env::var("TEST_DB_DSN")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .or_else(|| env::var("DB_DSN").ok().filter(|v| !v.trim().is_empty()));

    let app_dsn = env::var("DB_APP_DSN")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .map(Ok)
        .unwrap_or_else(|| {
            let base = base
                .as_deref()
                .ok_or_else(|| "DB_APP_DSN, TEST_DB_DSN, or DB_DSN is required".to_owned())?;
            swap_dsn_user(base, "setjoin_app")
        })?;

    let worker_dsn = env::var("DB_WORKER_DSN")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .or(base)
        .ok_or_else(|| "DB_WORKER_DSN, TEST_DB_DSN, or DB_DSN is required".to_owned())?;

    Ok((app_dsn, worker_dsn))
}

async fn connect_pg(dsn: &str, label: &str) -> Result<Client, String> {
    let (client, connection) = tokio_postgres::connect(dsn, NoTls)
        .await
        .map_err(|e| format!("connect {label} failed: {e}"))?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    Ok(client)
}

async fn verify_roles(app: &Client, worker: &Client) -> Result<(String, i32, String), String> {
    let app_row = app
        .query_one(
            "SELECT current_user::text, r.rolsuper, r.rolbypassrls, \
                    current_setting('server_version_num')::int4 \
             FROM pg_roles r WHERE r.rolname = current_user",
            &[],
        )
        .await
        .map_err(|e| format!("app role preflight query failed: {e}"))?;
    let app_user: String = app_row.get(0);
    let app_super: bool = app_row.get(1);
    let app_bypass: bool = app_row.get(2);
    let pg_ver: i32 = app_row.get(3);

    if app_super || app_bypass {
        return Err(format!(
            "PREFLIGHT_ROLE_FORBIDDEN: app role '{app_user}' must have rolsuper=false AND rolbypassrls=false \
             (got rolsuper={app_super}, rolbypassrls={app_bypass})"
        ));
    }
    if pg_ver < 170_000 {
        return Err(format!(
            "PREFLIGHT_PG_VERSION_UNSUPPORTED: require PostgreSQL >= 170000, got {pg_ver}"
        ));
    }

    let worker_row = worker
        .query_one(
            "SELECT current_user::text, r.rolsuper, r.rolbypassrls \
             FROM pg_roles r WHERE r.rolname = current_user",
            &[],
        )
        .await
        .map_err(|e| format!("worker role preflight query failed: {e}"))?;
    let worker_user: String = worker_row.get(0);
    let worker_super: bool = worker_row.get(1);
    let worker_bypass: bool = worker_row.get(2);
    if !worker_super && !worker_bypass {
        return Err(format!(
            "PREFLIGHT_WORKER_ROLE_FORBIDDEN: worker role '{worker_user}' must have rolbypassrls=true OR rolsuper=true"
        ));
    }
    Ok((app_user, pg_ver, worker_user))
}

fn preflight_static(contracts: &[OwnedContract]) -> Result<(), Vec<String>> {
    let mut errs = Vec::new();
    if contracts.is_empty() {
        errs.push("PREFLIGHT_EMPTY_CATALOG: ALL_CONTRACTS must not be empty".to_owned());
        return Err(errs);
    }
    let mut seen_ids = HashSet::new();
    for c in contracts {
        if c.domain.trim().is_empty() {
            errs.push(format!(
                "PREFLIGHT_EMPTY_DOMAIN [{}]: domain must not be empty",
                c.id
            ));
        }
        if c.id.trim().is_empty() {
            errs.push("PREFLIGHT_EMPTY_ID: contract id must not be empty".to_owned());
        } else if !seen_ids.insert(c.id.as_str()) {
            errs.push(format!(
                "PREFLIGHT_DUPLICATE_ID: duplicate contract id '{}'",
                c.id
            ));
        }
        if let Err(reason) = setjoin_pg::statement::admit(&c.sql) {
            errs.push(format!(
                "PREFLIGHT_ADMIT_FAILED [{}]: statement rejected by setjoin_pg::statement::admit: {reason}",
                c.id
            ));
        }
        if c.audit == SqlAuditPosture::ReducerWritesCoreAudit {
            if c.scope != SqlScope::AdminWrite {
                errs.push(format!(
                    "AUDIT_POSTURE_SCOPE_INVALID [{}]: ReducerWritesCoreAudit requires SqlScope::AdminWrite (got {})",
                    c.id,
                    c.scope.as_str()
                ));
            }
            if c.params.first() != Some(&Type::INT8) {
                errs.push(format!(
                    "AUDIT_POSTURE_ACTOR_INVALID [{}]: ReducerWritesCoreAudit requires $1 to be INT8 p_actor",
                    c.id
                ));
            }
        }
        for (idx, ty) in c.params.iter().enumerate() {
            if ty.oid() >= FIRST_CUSTOM_OID {
                errs.push(format!(
                    "CUSTOM_OID_FORBIDDEN [{}]: declared param ${} uses custom OID {} ({})",
                    c.id,
                    idx + 1,
                    ty.oid(),
                    ty.name()
                ));
            }
        }
        for (idx, col) in c.columns.iter().enumerate() {
            if col.ty.oid() >= FIRST_CUSTOM_OID {
                errs.push(format!(
                    "CUSTOM_OID_FORBIDDEN [{}]: declared column #{} uses custom OID {} ({})",
                    c.id,
                    idx,
                    col.ty.oid(),
                    col.ty.name()
                ));
            }
        }
    }
    if errs.is_empty() {
        Ok(())
    } else {
        Err(errs)
    }
}

/// Seeded divergent-ID fixture (`victim_user_id != victim_mailbox_id`,
/// `foreign_user_id != foreign_mailbox_id`) used for active `FORCE RLS` deny
/// probes. Cleaned up unconditionally after verification.
struct RlsFixture {
    tag: String,
    victim_user_id: i64,
    victim_mailbox_id: i64,
    victim_calendar_id: i64,
    victim_session_uuid: String,
    victim_request_id: i64,
    foreign_user_id: i64,
    foreign_mailbox_id: i64,
}

fn fixture_uuid(salt: u8, pid: u32, nanos: u128) -> String {
    let hi = (u64::from(salt) << 56) ^ (u64::from(pid) << 24) ^ ((nanos >> 64) as u64);
    let lo = (nanos as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ u64::from(salt);
    let p1 = (hi >> 32) as u32;
    let p2 = ((hi >> 16) & 0xffff) as u16;
    let p3 = (0x4000 | (hi & 0x0fff)) as u16;
    let p4 = (0x8000 | ((lo >> 48) & 0x3fff)) as u16;
    let p5 = lo & 0xffff_ffff_ffff;
    format!("{p1:08x}-{p2:04x}-{p3:04x}-{p4:04x}-{p5:012x}")
}

impl RlsFixture {
    async fn seed(worker: &Client) -> Result<Self, String> {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| format!("clock error: {e}"))?
            .as_nanos();
        let pid = std::process::id();
        let tag = format!("sqlc-{pid}-{nanos}");
        let domain_name = format!("{tag}.invalid");

        worker
            .batch_execute("BEGIN")
            .await
            .map_err(|e| format!("fixture BEGIN failed: {e}"))?;
        let seeded = Self::seed_inner(worker, tag, domain_name, pid, nanos).await;
        match seeded {
            Ok(fixture) => {
                worker
                    .batch_execute("COMMIT")
                    .await
                    .map_err(|e| format!("fixture COMMIT failed: {e}"))?;
                Ok(fixture)
            }
            Err(e) => {
                let _ = worker.batch_execute("ROLLBACK").await;
                Err(e)
            }
        }
    }

    async fn seed_inner(
        worker: &Client,
        tag: String,
        domain_name: String,
        pid: u32,
        nanos: u128,
    ) -> Result<Self, String> {
        let domain_id: i64 = worker
            .query_one(
                "INSERT INTO domains (name, is_primary) VALUES ($1, FALSE) RETURNING id",
                &[&domain_name],
            )
            .await
            .map_err(|e| format!("seed domain failed: {e}"))?
            .get(0);

        // Insert a spacer user first so victim_user_id != victim_mailbox_id even on a clean DB.
        let spacer_user = format!("spacer-{tag}");
        let spacer_email = format!("{spacer_user}@{domain_name}");
        let _spacer_user_id: i64 = worker
            .query_one(
                "INSERT INTO users (username, domain_id, email, display_name) \
                 VALUES ($1, $2, $3, 'Spacer') RETURNING id",
                &[&spacer_user, &domain_id, &spacer_email],
            )
            .await
            .map_err(|e| format!("seed spacer user failed: {:?}", e.as_db_error()))?
            .get(0);

        let victim_user = format!("victim-{tag}");
        let victim_email = format!("{victim_user}@{domain_name}");
        let victim_user_id: i64 = worker
            .query_one(
                "INSERT INTO users (username, domain_id, email, display_name) \
                 VALUES ($1, $2, $3, 'Victim') RETURNING id",
                &[&victim_user, &domain_id, &victim_email],
            )
            .await
            .map_err(|e| format!("seed victim user failed: {:?}", e.as_db_error()))?
            .get(0);

        let foreign_user = format!("foreign-{tag}");
        let foreign_email = format!("{foreign_user}@{domain_name}");
        let foreign_user_id: i64 = worker
            .query_one(
                "INSERT INTO users (username, domain_id, email, display_name) \
                 VALUES ($1, $2, $3, 'Foreign') RETURNING id",
                &[&foreign_user, &domain_id, &foreign_email],
            )
            .await
            .map_err(|e| format!("seed foreign user failed: {:?}", e.as_db_error()))?
            .get(0);

        // Ensure victim_mailbox_id diverges from victim_user_id (if equal, create a spare first).
        let mut victim_mailbox_id: i64 = worker
            .query_one(
                "INSERT INTO mailboxes (domain_id, user_id, email, display_name, is_primary) \
                 VALUES ($1, $2, $3, 'Victim', TRUE) RETURNING id",
                &[&domain_id, &victim_user_id, &victim_email],
            )
            .await
            .map_err(|e| format!("seed victim mailbox failed: {:?}", e.as_db_error()))?
            .get(0);
        if victim_mailbox_id == victim_user_id {
            let alt_email = format!("victim-alt-{tag}@{domain_name}");
            worker
                .execute(
                    "UPDATE mailboxes SET is_primary = FALSE WHERE id = $1",
                    &[&victim_mailbox_id],
                )
                .await
                .map_err(|e| format!("adjust victim mailbox failed: {:?}", e.as_db_error()))?;
            victim_mailbox_id = worker
                .query_one(
                    "INSERT INTO mailboxes (domain_id, user_id, email, display_name, is_primary) \
                     VALUES ($1, $2, $3, 'Victim Alt', TRUE) RETURNING id",
                    &[&domain_id, &victim_user_id, &alt_email],
                )
                .await
                .map_err(|e| {
                    format!(
                        "seed divergent victim mailbox failed: {:?}",
                        e.as_db_error()
                    )
                })?
                .get(0);
        }

        let foreign_mailbox_id: i64 = worker
            .query_one(
                "INSERT INTO mailboxes (domain_id, user_id, email, display_name, is_primary) \
                 VALUES ($1, $2, $3, 'Foreign', TRUE) RETURNING id",
                &[&domain_id, &foreign_user_id, &foreign_email],
            )
            .await
            .map_err(|e| format!("seed foreign mailbox failed: {:?}", e.as_db_error()))?
            .get(0);

        // Seed rows into FORCE RLS tables probed by migrated domain contracts.
        let victim_calendar_id: i64 = worker
            .query_one(
                "INSERT INTO calendars (mailbox_id, name, timezone) VALUES ($1, $2, 'UTC') RETURNING id",
                &[&victim_mailbox_id, &tag],
            )
            .await
            .map_err(|e| format!("seed calendar failed: {:?}", e.as_db_error()))?
            .get(0);

        let sub_url = format!("https://{domain_name}/cal.ics");
        worker
            .execute(
                "INSERT INTO calendar_subscriptions (user_id, calendar_id, url) VALUES ($1, $2, $3)",
                &[&victim_user_id, &victim_calendar_id, &sub_url],
            )
            .await
            .map_err(|e| format!("seed calendar_subscriptions failed: {:?}", e.as_db_error()))?;

        let victim_request_id: i64 = worker
            .query_one(
                "INSERT INTO approval_requests \
                 (consumer_type, requester_user_id, subject, payload, status, approver_kind, approver_ref, domain_id, expires_at) \
                 VALUES ('hr.leave', $1, $2, '{}'::jsonb, 'pending', 'user', $1, $3, now() + interval '1 day') RETURNING id",
                &[&victim_user_id, &tag, &domain_id],
            )
            .await
            .map_err(|e| format!("seed approval_requests failed: {:?}", e.as_db_error()))?
            .get(0);

        worker
            .execute(
                "INSERT INTO login_events (user_id, success, source_ip, location) \
                 VALUES ($1, false, '127.0.0.1'::inet, $2)",
                &[&victim_user_id, &tag],
            )
            .await
            .map_err(|e| format!("seed login_events failed: {:?}", e.as_db_error()))?;

        worker
            .execute(
                "INSERT INTO device_registry (user_id, device_hash) \
                 VALUES ($1, $2)",
                &[&victim_user_id, &tag],
            )
            .await
            .map_err(|e| format!("seed device_registry failed: {:?}", e.as_db_error()))?;

        let fp_bytes = tag.as_bytes();
        worker
            .execute(
                "INSERT INTO user_devices (user_id, fingerprint_hash, platform, device_name) \
                 VALUES ($1, sha256($2::bytea), 'desktop', $3)",
                &[&victim_user_id, &fp_bytes, &tag],
            )
            .await
            .map_err(|e| format!("seed user_devices failed: {:?}", e.as_db_error()))?;

        let victim_session_uuid = fixture_uuid(1, pid, nanos);
        let incident_uuid = fixture_uuid(2, pid, nanos);
        let device_uuid = fixture_uuid(3, pid, nanos);
        let artifact_id = format!("art-{tag}");
        // Best-effort seed of recovery upload session isolated in a SAVEPOINT so
        // a schema/constraint mismatch never aborts the outer seed transaction (25P02).
        worker
            .batch_execute("SAVEPOINT sp_upload_session")
            .await
            .map_err(|e| format!("savepoint sp_upload_session failed: {e}"))?;
        let upload_res = worker
            .execute(
                "INSERT INTO mail_recovery_upload_sessions \
                 (id, incident_id, mailbox_id, uploading_user_id, device_id, artifact_identity, eligibility, status, expires_at) \
                 VALUES ($1::text::uuid, $2::text::uuid, $3, $4, $5::text::uuid, $6, 'full', 'uploading', now() + interval '1 hour') \
                 ON CONFLICT DO NOTHING",
                &[
                    &victim_session_uuid,
                    &incident_uuid,
                    &victim_mailbox_id,
                    &victim_user_id,
                    &device_uuid,
                    &artifact_id,
                ],
            )
            .await;
        if upload_res.is_err() {
            let _ = worker
                .batch_execute("ROLLBACK TO SAVEPOINT sp_upload_session")
                .await;
        }
        worker
            .batch_execute("RELEASE SAVEPOINT sp_upload_session")
            .await
            .map_err(|e| format!("release sp_upload_session failed: {e}"))?;

        Ok(Self {
            tag,
            victim_user_id,
            victim_mailbox_id,
            victim_calendar_id,
            victim_session_uuid,
            victim_request_id,
            foreign_user_id,
            foreign_mailbox_id,
        })
    }

    async fn cleanup(&self, worker: &Client) {
        let domain_name = format!("{}.invalid", self.tag);
        if let Err(e) = worker.batch_execute("BEGIN").await {
            eprintln!("WARN: fixture cleanup BEGIN failed: {e}");
            return;
        }
        let steps: [(&str, &str, &[&(dyn ToSql + Sync)]); 11] = [
            (
                "mail_recovery_upload_sessions",
                "DELETE FROM mail_recovery_upload_sessions WHERE id = $1::text::uuid",
                &[&self.victim_session_uuid],
            ),
            (
                "approval_requests",
                "DELETE FROM approval_requests WHERE id = $1",
                &[&self.victim_request_id],
            ),
            (
                "user_devices",
                "DELETE FROM user_devices WHERE user_id IN ($1, $2)",
                &[&self.victim_user_id, &self.foreign_user_id],
            ),
            (
                "device_registry",
                "DELETE FROM device_registry WHERE user_id IN ($1, $2)",
                &[&self.victim_user_id, &self.foreign_user_id],
            ),
            (
                "login_events",
                "DELETE FROM login_events WHERE user_id IN ($1, $2)",
                &[&self.victim_user_id, &self.foreign_user_id],
            ),
            (
                "calendar_subscriptions",
                "DELETE FROM calendar_subscriptions WHERE user_id IN ($1, $2)",
                &[&self.victim_user_id, &self.foreign_user_id],
            ),
            (
                "calendars",
                "DELETE FROM calendars WHERE id = $1",
                &[&self.victim_calendar_id],
            ),
            (
                "mailboxes_unlink",
                "UPDATE mailboxes SET user_id = NULL, is_primary = FALSE \
                 WHERE domain_id = (SELECT id FROM domains WHERE name = $1)",
                &[&domain_name],
            ),
            (
                "mailboxes_delete",
                "DELETE FROM mailboxes WHERE domain_id = (SELECT id FROM domains WHERE name = $1)",
                &[&domain_name],
            ),
            (
                "users",
                "DELETE FROM users WHERE domain_id = (SELECT id FROM domains WHERE name = $1)",
                &[&domain_name],
            ),
            (
                "domains",
                "DELETE FROM domains WHERE name = $1",
                &[&domain_name],
            ),
        ];
        for (label, sql, params) in steps {
            if let Err(e) = worker.batch_execute("SAVEPOINT sp_clean").await {
                eprintln!("WARN: fixture cleanup savepoint ({label}) failed: {e}");
                break;
            }
            if let Err(e) = worker.execute(sql, params).await {
                eprintln!(
                    "WARN: fixture cleanup step '{label}' failed: {:?}",
                    e.as_db_error()
                );
                let _ = worker.batch_execute("ROLLBACK TO SAVEPOINT sp_clean").await;
            }
            let _ = worker.batch_execute("RELEASE SAVEPOINT sp_clean").await;
        }
        if let Err(e) = worker.batch_execute("COMMIT").await {
            eprintln!("WARN: fixture cleanup COMMIT failed: {e}");
            let _ = worker.batch_execute("ROLLBACK").await;
        }
    }
}

struct JsonText(String);

impl<'a> tokio_postgres::types::FromSql<'a> for JsonText {
    fn from_sql(
        ty: &Type,
        raw: &'a [u8],
    ) -> Result<Self, Box<dyn std::error::Error + Sync + Send>> {
        let bytes = if *ty == Type::JSONB && raw.first() == Some(&1) {
            &raw[1..]
        } else {
            raw
        };
        Ok(Self(std::str::from_utf8(bytes)?.to_owned()))
    }

    fn accepts(ty: &Type) -> bool {
        matches!(*ty, Type::JSON | Type::JSONB | Type::TEXT)
    }
}

/// Typed `NULL` parameter holder for `EXPLAIN` (always cast-safe for `::uuid`,
/// `::jsonb`, `::timestamptz`, `::inet`, `::date`, arrays, etc.).
struct NullParam;

impl std::fmt::Debug for NullParam {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NULL")
    }
}

impl ToSql for NullParam {
    fn to_sql(
        &self,
        _ty: &Type,
        _out: &mut tokio_postgres::types::private::BytesMut,
    ) -> Result<tokio_postgres::types::IsNull, Box<dyn std::error::Error + Sync + Send>> {
        Ok(tokio_postgres::types::IsNull::Yes)
    }

    fn accepts(_ty: &Type) -> bool {
        true
    }

    tokio_postgres::types::to_sql_checked!();
}

enum ProbeVal {
    Int8(i64),
    Int4(i32),
    Bool(bool),
    Text(String),
    Bytea(Vec<u8>),
    Null,
}

impl ProbeVal {
    fn as_tosql(&self) -> &(dyn ToSql + Sync) {
        match self {
            Self::Int8(v) => v,
            Self::Int4(v) => v,
            Self::Bool(v) => v,
            Self::Text(v) => v,
            Self::Bytea(v) => v,
            Self::Null => &NullParam,
        }
    }
}

fn build_rls_probe_values(contract: &OwnedContract, fixture: &RlsFixture) -> Vec<ProbeVal> {
    let sql_lower = contract.sql.to_ascii_lowercase();
    let is_insert_cal_sub = sql_lower.contains("insert into calendar_subscriptions");
    let is_approval_by_id = sql_lower.contains("approval_requests")
        && (sql_lower.contains("r.id=$1") || sql_lower.contains("where id=$1"));
    let is_mailbox_scope = matches!(
        contract.scope,
        SqlScope::MailboxReadOnly | SqlScope::MailboxReadWrite
    );
    let mut vals = Vec::with_capacity(contract.params.len());
    for (idx, ty) in contract.params.iter().enumerate() {
        let v = match *ty {
            Type::INT8 => {
                if is_insert_cal_sub && idx == 1 {
                    ProbeVal::Int8(fixture.victim_calendar_id)
                } else if is_approval_by_id && idx == 0 {
                    ProbeVal::Int8(fixture.victim_request_id)
                } else if idx == 0 {
                    if is_mailbox_scope {
                        ProbeVal::Int8(fixture.victim_mailbox_id)
                    } else {
                        ProbeVal::Int8(fixture.victim_user_id)
                    }
                } else if (idx == 1 && sql_lower.contains("limit $2"))
                    || (idx == 2 && sql_lower.contains("limit $3"))
                {
                    ProbeVal::Int8(10)
                } else if (idx == 2 && sql_lower.contains("offset $3"))
                    || (idx == 1 && sql_lower.contains("domain_id=$2"))
                    || (idx == 3 && sql_lower.contains("offset $4"))
                {
                    ProbeVal::Int8(0)
                } else {
                    ProbeVal::Int8(fixture.victim_user_id)
                }
            }
            Type::INT4 => ProbeVal::Int4(10),
            Type::BOOL => ProbeVal::Bool(false),
            Type::TEXT => {
                if sql_lower.contains("::uuid") && idx == 0 {
                    ProbeVal::Text(fixture.victim_session_uuid.clone())
                } else if is_insert_cal_sub {
                    ProbeVal::Text("https://mutant.invalid/feed.ics".to_owned())
                } else {
                    ProbeVal::Text(String::new())
                }
            }
            Type::BYTEA => ProbeVal::Bytea(fixture.tag.as_bytes().to_vec()),
            _ => ProbeVal::Null,
        };
        vals.push(v);
    }
    vals
}

fn plan_has_modify_table(val: &serde_json::Value) -> bool {
    match val {
        serde_json::Value::Array(items) => items.iter().any(plan_has_modify_table),
        serde_json::Value::Object(map) => {
            if map.get("Node Type").and_then(|v| v.as_str()) == Some("ModifyTable") {
                return true;
            }
            map.values().any(plan_has_modify_table)
        }
        _ => false,
    }
}

fn format_pg_err(prefix: &str, id: &str, err: &tokio_postgres::Error) -> String {
    if let Some(db) = err.as_db_error() {
        let code = db.code().code();
        let tag = match code {
            "42804" | "42883" => "BIND_TYPE_MISMATCH",
            "42501" => "RLS_VIOLATION/PERMISSION_DENIED",
            "25006" => "READ_ONLY_VIOLATION",
            _ => "PG_ERROR",
        };
        format!("{prefix} [{id}]: {tag} SQLSTATE={code}: {}", db.message())
    } else {
        format!("{prefix} [{id}]: {err}")
    }
}

async fn apply_scope_gucs(
    client: &Client,
    scope: SqlScope,
    mailbox_id: Option<i64>,
    user_id: Option<i64>,
) -> Result<(), String> {
    let mb = mailbox_id.map(|v| v.to_string()).unwrap_or_default();
    let uid = user_id.map(|v| v.to_string()).unwrap_or_default();
    let (mb_val, uid_val) = match scope {
        SqlScope::MailboxReadOnly | SqlScope::MailboxReadWrite => (mb, uid),
        SqlScope::UserScoped | SqlScope::AdminRead | SqlScope::AdminWrite => (String::new(), uid),
        SqlScope::AuthPreScope | SqlScope::WorkerBypass => (String::new(), String::new()),
    };
    client
        .query_typed(
            "SELECT set_config('app.current_mailbox_id', $1, true), \
                    set_config('app.current_user_id', $2, true)",
            &[(&mb_val, Type::TEXT), (&uid_val, Type::TEXT)],
        )
        .await
        .map_err(|e| format!("set_config failed: {e}"))?;
    Ok(())
}

fn rows_indicate_rls_leak(contract: &OwnedContract, rows: &[tokio_postgres::Row]) -> bool {
    if rows.is_empty() {
        return false;
    }
    // Pure aggregate COUNT(*) queries always produce 1 row; 0 means RLS hid all rows.
    let sql_upper = contract.sql.trim_start().to_ascii_uppercase();
    let is_count_agg =
        sql_upper.starts_with("SELECT COUNT(") || sql_upper.starts_with("SELECT COUNT (*)");
    if is_count_agg && rows.len() == 1 {
        if let Ok(cnt) = rows[0].try_get::<_, i64>(0) {
            return cnt > 0;
        }
    }
    true
}

async fn verify_one_contract(
    contract: &OwnedContract,
    app: &Client,
    worker: &Client,
    fixture: &RlsFixture,
) -> Result<(), String> {
    let client = if contract.scope.is_worker_bypass() {
        worker
    } else {
        app
    };

    // 1. Live `prepare_typed` verification inside a rolled-back transaction.
    let begin_sql = if contract.scope.is_read_only() {
        "BEGIN READ ONLY"
    } else {
        "BEGIN READ WRITE"
    };
    client
        .batch_execute(begin_sql)
        .await
        .map_err(|e| format_pg_err("BEGIN_FAILED", &contract.id, &e))?;

    let result = verify_inside_tx(contract, client, fixture).await;

    let _ = client.batch_execute("ROLLBACK").await;
    let _ = client.batch_execute("DEALLOCATE ALL").await;

    result
}

async fn verify_inside_tx(
    contract: &OwnedContract,
    client: &Client,
    fixture: &RlsFixture,
) -> Result<(), String> {
    // Prepare with exact declared parameter types.
    let stmt = client
        .prepare_typed(&contract.sql, &contract.params)
        .await
        .map_err(|e| format_pg_err("PREPARE_TYPED_FAILED", &contract.id, &e))?;

    // Check parameter count & resolved OIDs.
    let actual_params = stmt.params();
    if actual_params.len() != contract.params.len() {
        return Err(format!(
            "BIND_TYPE_MISMATCH [{}]: declared {} params, PostgreSQL resolved {}",
            contract.id,
            contract.params.len(),
            actual_params.len()
        ));
    }
    for (idx, (expected, actual)) in contract.params.iter().zip(actual_params.iter()).enumerate() {
        if actual.oid() >= FIRST_CUSTOM_OID {
            return Err(format!(
                "CUSTOM_OID_FORBIDDEN [{}]: param ${} resolved to custom OID {} ({})",
                contract.id,
                idx + 1,
                actual.oid(),
                actual.name()
            ));
        }
        if actual.oid() != expected.oid() {
            return Err(format!(
                "BIND_TYPE_MISMATCH [{}]: param ${} declared {} (oid {}) != PG {} (oid {})",
                contract.id,
                idx + 1,
                expected.name(),
                expected.oid(),
                actual.name(),
                actual.oid()
            ));
        }
    }

    // Check result column count, built-in OID < 16384, exact type, and optional name.
    let actual_cols = stmt.columns();
    if actual_cols.len() != contract.columns.len() {
        return Err(format!(
            "COLUMN_COUNT_MISMATCH [{}]: declared {} columns, PostgreSQL returned {}",
            contract.id,
            contract.columns.len(),
            actual_cols.len()
        ));
    }
    for (idx, (expected, actual)) in contract.columns.iter().zip(actual_cols.iter()).enumerate() {
        if actual.type_().oid() >= FIRST_CUSTOM_OID {
            return Err(format!(
                "CUSTOM_OID_FORBIDDEN [{}]: column #{} ('{}') returned custom OID {} ({}) — cast to built-in type (e.g. ::text) to avoid TYPEINFO_QUERY",
                contract.id,
                idx,
                actual.name(),
                actual.type_().oid(),
                actual.type_().name()
            ));
        }
        if actual.type_().oid() != expected.ty.oid() {
            return Err(format!(
                "COLUMN_TYPE_MISMATCH [{}]: column #{} ('{}') declared {} (oid {}) != PG {} (oid {})",
                contract.id,
                idx,
                actual.name(),
                expected.ty.name(),
                expected.ty.oid(),
                actual.type_().name(),
                actual.type_().oid()
            ));
        }
        if let Some(expected_name) = expected.name.as_deref() {
            if actual.name() != expected_name {
                return Err(format!(
                    "COLUMN_NAME_MISMATCH [{}]: column #{} declared name '{}' != PG '{}'",
                    contract.id,
                    idx,
                    expected_name,
                    actual.name()
                ));
            }
        }
    }

    // 2. Scope & FORCE RLS compatibility probe: set scope GUCs and run
    //    `EXPLAIN (COSTS OFF, FORMAT JSON)` with typed dummy bindings.
    apply_scope_gucs(
        client,
        contract.scope,
        Some(fixture.victim_mailbox_id),
        Some(fixture.victim_user_id),
    )
    .await?;

    let explain_sql = format!("EXPLAIN (COSTS OFF, FORMAT JSON) {}", contract.sql);
    let null_params: Vec<(&'static (dyn ToSql + Sync), Type)> = contract
        .params
        .iter()
        .map(|ty| (&NullParam as &'static (dyn ToSql + Sync), ty.clone()))
        .collect();
    let explain_rows = client
        .query_typed(&explain_sql, &null_params)
        .await
        .map_err(|e| format_pg_err("EXPLAIN_FAILED", &contract.id, &e))?;

    let plan_json: serde_json::Value = explain_rows
        .first()
        .and_then(|r| r.try_get::<_, JsonText>(0).ok())
        .and_then(|j| serde_json::from_str(&j.0).ok())
        .ok_or_else(|| format!("EXPLAIN_EMPTY [{}]: no JSON plan returned", contract.id))?;

    let is_write_plan = plan_has_modify_table(&plan_json);
    if contract.scope.is_read_only() && is_write_plan {
        // Trigger real PG 25006 inside a savepoint so diagnostics report SQLSTATE=25006.
        let _ = client.batch_execute("SAVEPOINT ro_check").await;
        let exec_res = client.query_typed(&contract.sql, &null_params).await;
        let _ = client.batch_execute("ROLLBACK TO SAVEPOINT ro_check").await;
        return match exec_res {
            Err(e) => Err(format_pg_err("READ_ONLY_WRITE_FORBIDDEN", &contract.id, &e)),
            Ok(_) => Err(format!(
                "READ_ONLY_WRITE_FORBIDDEN [{}]: SQLSTATE=25006 write plan in read-only scope {}",
                contract.id,
                contract.scope.as_str()
            )),
        };
    }

    // 3. Active FORCE RLS deny probe (inside SAVEPOINT ... ROLLBACK TO SAVEPOINT).
    if contract.rls_check == RlsCheck::PrepareExplainAndRlsDenyProbe
        && !contract.scope.is_worker_bypass()
    {
        let probe_vals = build_rls_probe_values(contract, fixture);
        let probe_params: Vec<(&(dyn ToSql + Sync), Type)> = probe_vals
            .iter()
            .zip(contract.params.iter())
            .map(|(v, ty)| (v.as_tosql(), ty.clone()))
            .collect();

        if is_write_plan {
            // For a write contract probing FORCE RLS under its own declared scope:
            // if the declared scope leaves RLS unsatisfied (e.g. AuthPreScope or foreign
            // tenant), PG raises SQLSTATE 42501 (`new row violates row-level security policy`).
            client
                .batch_execute("SAVEPOINT rls_write_probe")
                .await
                .map_err(|e| format_pg_err("SAVEPOINT_FAILED", &contract.id, &e))?;
            let res = client.query_typed(&contract.sql, &probe_params).await;
            let _ = client
                .batch_execute("ROLLBACK TO SAVEPOINT rls_write_probe")
                .await;
            if let Err(e) = res {
                return Err(format_pg_err("RLS_VIOLATION", &contract.id, &e));
            }
        } else {
            // For SELECT contracts: execute with BOTH unset GUCs and foreign GUCs
            // while passing the seeded victim's IDs; FORCE RLS must deny (42501 or 0 rows).
            for (probe_label, mb_guc, user_guc) in [
                ("unset_guc", None, None),
                (
                    "foreign_guc",
                    Some(fixture.foreign_mailbox_id),
                    Some(fixture.foreign_user_id),
                ),
            ] {
                client
                    .batch_execute("SAVEPOINT rls_deny_probe")
                    .await
                    .map_err(|e| format_pg_err("SAVEPOINT_FAILED", &contract.id, &e))?;
                apply_scope_gucs(client, contract.scope, mb_guc, user_guc).await?;
                let res = client.query_typed(&contract.sql, &probe_params).await;
                let _ = client
                    .batch_execute("ROLLBACK TO SAVEPOINT rls_deny_probe")
                    .await;
                match res {
                    Ok(rows) => {
                        if rows_indicate_rls_leak(contract, &rows) {
                            return Err(format!(
                                "RLS_VIOLATION [{}]: probe '{probe_label}' leaked {} row(s) across tenant boundary under setjoin_app (expected 0 rows or SQLSTATE 42501)",
                                contract.id,
                                rows.len()
                            ));
                        }
                    }
                    Err(e) => {
                        let code = e.as_db_error().map(|db| db.code().code());
                        if code != Some("42501") {
                            return Err(format_pg_err("RLS_PROBE_ERROR", &contract.id, &e));
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let mut mutant_path: Option<String> = None;
    let mut idx = 0;
    while idx < args.len() {
        match args[idx].as_str() {
            "--mutant-json" => {
                idx += 1;
                if idx >= args.len() {
                    eprintln!("usage: verify-sql-contracts [--mutant-json <path>]");
                    return ExitCode::from(2);
                }
                mutant_path = Some(args[idx].clone());
            }
            "-h" | "--help" => {
                println!("usage: verify-sql-contracts [--mutant-json <path>]");
                return ExitCode::SUCCESS;
            }
            other => {
                eprintln!("unknown argument: {other}");
                return ExitCode::from(2);
            }
        }
        idx += 1;
    }

    let contracts: Vec<OwnedContract> = if let Some(path) = mutant_path.as_deref() {
        match load_mutant_contracts(path) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("ERROR: {e}");
                return ExitCode::from(1);
            }
        }
    } else {
        ALL_CONTRACTS
            .iter()
            .flat_map(|slice| slice.iter().map(OwnedContract::from))
            .collect()
    };

    if let Err(errs) = preflight_static(&contracts) {
        for err in &errs {
            eprintln!("FAIL: {err}");
        }
        return ExitCode::from(1);
    }

    let (app_dsn, worker_dsn) = match resolve_dsns() {
        Ok(pair) => pair,
        Err(e) => {
            eprintln!("FAIL: PREFLIGHT_DSN_MISSING: {e}");
            return ExitCode::from(1);
        }
    };

    let app = Arc::new(match connect_pg(&app_dsn, "setjoin_app").await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("FAIL: {e}");
            return ExitCode::from(1);
        }
    });
    let worker = Arc::new(match connect_pg(&worker_dsn, "worker").await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("FAIL: {e}");
            return ExitCode::from(1);
        }
    });

    let (app_user, pg_ver, worker_user) = match verify_roles(&app, &worker).await {
        Ok(info) => info,
        Err(e) => {
            eprintln!("FAIL: {e}");
            return ExitCode::from(1);
        }
    };

    let fixture = Arc::new(match RlsFixture::seed(&worker).await {
        Ok(f) => f,
        Err(e) => {
            eprintln!("FAIL: FIXTURE_SEED_FAILED: {e}");
            return ExitCode::from(1);
        }
    });

    // Run contract verification in a spawned task so a panic in any check
    // still runs `fixture.cleanup(&worker)` unconditionally.
    let total_contracts = contracts.len();
    let app_task = Arc::clone(&app);
    let worker_task = Arc::clone(&worker);
    let fixture_task = Arc::clone(&fixture);
    let run_result = tokio::spawn(async move {
        let mut failures = Vec::new();
        let mut by_scope: BTreeMap<&'static str, usize> = BTreeMap::new();
        let mut rls_probes = 0usize;

        for contract in &contracts {
            *by_scope.entry(contract.scope.as_str()).or_insert(0) += 1;
            if contract.rls_check == RlsCheck::PrepareExplainAndRlsDenyProbe {
                rls_probes += 1;
            }
            if let Err(err) =
                verify_one_contract(contract, &app_task, &worker_task, &fixture_task).await
            {
                failures.push(err);
            }
        }
        (failures, by_scope, rls_probes)
    })
    .await;

    fixture.cleanup(&worker).await;

    let (failures, by_scope, rls_probes) = match run_result {
        Ok(res) => res,
        Err(join_err) => {
            eprintln!("FAIL: VERIFIER_PANICKED: {join_err}");
            return ExitCode::from(1);
        }
    };

    if !failures.is_empty() {
        for err in &failures {
            eprintln!("FAIL: {err}");
        }
        eprintln!(
            "verify-sql-contracts: FAILED ({} / {} contracts failed; app_role={app_user}, worker_role={worker_user}, pg={pg_ver})",
            failures.len(),
            total_contracts
        );
        return ExitCode::from(1);
    }

    let scope_summary: Vec<String> = by_scope
        .iter()
        .map(|(scope, count)| format!("{scope}={count}"))
        .collect();
    println!(
        "verify-sql-contracts: PASS ({} contracts verified, {} active RLS deny probes; app_role={app_user}, worker_role={worker_user}, pg={pg_ver}; scopes: {})",
        total_contracts,
        rls_probes,
        scope_summary.join(", ")
    );
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_passes_static_preflight_and_covers_all_scopes() {
        let contracts: Vec<OwnedContract> = ALL_CONTRACTS
            .iter()
            .flat_map(|slice| slice.iter().map(OwnedContract::from))
            .collect();
        preflight_static(&contracts).expect("static preflight");
        let scopes: HashSet<SqlScope> = contracts.iter().map(|c| c.scope).collect();
        for required in [
            SqlScope::MailboxReadOnly,
            SqlScope::MailboxReadWrite,
            SqlScope::UserScoped,
            SqlScope::AdminRead,
            SqlScope::AdminWrite,
            SqlScope::AuthPreScope,
            SqlScope::WorkerBypass,
        ] {
            assert!(
                scopes.contains(&required),
                "catalog must cover scope {required:?}"
            );
        }
        assert!(
            contracts
                .iter()
                .any(|c| c.rls_check == RlsCheck::PrepareExplainAndRlsDenyProbe),
            "catalog must include active FORCE RLS deny probes"
        );
    }

    #[test]
    fn swap_dsn_user_preserves_password_and_host() {
        assert_eq!(
            swap_dsn_user(
                "postgres://mail@127.0.0.1:15432/mailserver_test?sslmode=disable",
                "setjoin_app"
            )
            .unwrap(),
            "postgres://setjoin_app@127.0.0.1:15432/mailserver_test?sslmode=disable"
        );
        assert_eq!(
            swap_dsn_user("postgresql://owner:secret@db:5432/app", "setjoin_app").unwrap(),
            "postgresql://setjoin_app:secret@db:5432/app"
        );
    }

    #[test]
    fn static_preflight_rejects_custom_oid_and_duplicate_id() {
        let custom = Type::new("my_enum".into(), 20000, Kind::Simple, "public".into());
        let bad = OwnedContract {
            id: "dup.id".into(),
            domain: "test".into(),
            sql: "SELECT $1".into(),
            params: vec![custom],
            columns: vec![OwnedColumn {
                name: None,
                ty: Type::INT8,
            }],
            scope: SqlScope::UserScoped,
            rls_check: RlsCheck::PrepareAndExplain,
            audit: SqlAuditPosture::Standard,
        };
        let errs = preflight_static(&[bad.clone(), bad]).unwrap_err();
        assert!(errs.iter().any(|e| e.contains("CUSTOM_OID_FORBIDDEN")));
        assert!(errs.iter().any(|e| e.contains("PREFLIGHT_DUPLICATE_ID")));
    }
}
