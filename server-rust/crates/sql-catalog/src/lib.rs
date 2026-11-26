//! Zero-proc-macro typed SQL contract catalog for Setjoin (#541).
//!
//! This leaf crate depends **only** on `tokio-postgres` (for `types::Type`)
//! and introduces zero procedural macros, zero `syn`/`quote`, and zero `sqlx`.
//! Every domain crate declares static [`SqlContract`] entries referencing the
//! exact SQL text, parameter [`Type`]s, result [`ColumnSpec`]s, [`SqlScope`],
//! and [`RlsCheck`] policy verified against disposable PostgreSQL 17 in CI.
#![forbid(unsafe_code)]

pub use tokio_postgres::types::Type;

/// Execution scope and credential/transaction contract for a [`SqlContract`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SqlScope {
    /// Mailbox-scoped `BEGIN READ ONLY` transaction under `setjoin_app`
    /// (`app.current_mailbox_id` + `app.current_user_id` set).
    MailboxReadOnly,
    /// Mailbox-scoped `BEGIN READ WRITE` transaction under `setjoin_app`
    /// (`app.current_mailbox_id` + `app.current_user_id` set).
    MailboxReadWrite,
    /// User-scoped transaction under `setjoin_app`
    /// (`app.current_user_id` set; `app.current_mailbox_id` empty or set).
    UserScoped,
    /// Admin `BEGIN READ ONLY` transaction under `setjoin_app`
    /// (`app.current_user_id` set).
    AdminRead,
    /// Admin `BEGIN READ WRITE` transaction under `setjoin_app`
    /// (`app.current_user_id` set).
    AdminWrite,
    /// Pre-scope authentication / public lookup under `setjoin_app` with no
    /// tenant GUCs set (`BEGIN READ ONLY`).
    AuthPreScope,
    /// Cross-tenant worker query running on `DB_WORKER_DSN` (`setjoin_worker`,
    /// `BYPASSRLS`).
    WorkerBypass,
}

impl SqlScope {
    /// Whether this scope runs in a PostgreSQL `BEGIN READ ONLY` transaction.
    pub const fn is_read_only(self) -> bool {
        matches!(
            self,
            Self::MailboxReadOnly | Self::AdminRead | Self::AuthPreScope
        )
    }

    /// Whether this scope requires the privileged `BYPASSRLS` worker role.
    pub const fn is_worker_bypass(self) -> bool {
        matches!(self, Self::WorkerBypass)
    }

    /// Stable machine-readable scope label for diagnostics and JSON reports.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MailboxReadOnly => "MailboxReadOnly",
            Self::MailboxReadWrite => "MailboxReadWrite",
            Self::UserScoped => "UserScoped",
            Self::AdminRead => "AdminRead",
            Self::AdminWrite => "AdminWrite",
            Self::AuthPreScope => "AuthPreScope",
            Self::WorkerBypass => "WorkerBypass",
        }
    }
}

/// Expected result column metadata verified against live PostgreSQL `Describe`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ColumnSpec {
    /// Optional column name (`None` skips exact alias checking for expressions
    /// such as `to_char(...)` or `COALESCE(...)`).
    pub name: Option<&'static str>,
    /// Expected built-in PostgreSQL result column [`Type`] (OID `< 16384`).
    pub ty: Type,
}

impl ColumnSpec {
    /// Unnamed result column specification (checks exact PostgreSQL [`Type`]).
    pub const fn unnamed(ty: Type) -> Self {
        Self { name: None, ty }
    }

    /// Named result column specification (checks exact column name and [`Type`]).
    pub const fn named(name: &'static str, ty: Type) -> Self {
        Self {
            name: Some(name),
            ty,
        }
    }
}

/// PostgreSQL RLS verification mode for a [`SqlContract`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RlsCheck {
    /// Run `prepare_typed` + scoped `EXPLAIN (COSTS OFF, FORMAT JSON)` as the
    /// contract's role (`setjoin_app` or `setjoin_worker`).
    PrepareAndExplain,
    /// Run `prepare_typed` + scoped `EXPLAIN`, plus an active `FORCE RLS` deny
    /// probe with unset/foreign scope GUCs against a seeded divergent-ID
    /// fixture inside a rolled-back `SAVEPOINT`.
    PrepareExplainAndRlsDenyProbe,
}

/// Core-audit posture for a [`SqlContract`] (#546a).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum SqlAuditPosture {
    /// Standard contract: read-only, tenant-scoped, or admin write audited
    /// explicitly via `AdminWriteTx::record_audit` / `AuditEvent`.
    #[default]
    Standard,
    /// Admin write reducer whose PL/pgSQL body atomically invokes
    /// `audit_write(p_actor, ..., 'core')` (setting PostgreSQL's
    /// transaction-local `app.core_audit_written = '1'` proof).
    ///
    /// Statically verified by `scripts/check-rust-sql-contracts.py` to appear
    /// ONLY inside `crates/domains/*/src/sql.rs`, to execute a single
    /// top-level `SELECT [public.]<fn>(...)`, and to target a reducer whose
    /// `'core'` `audit_write` is never wrapped inside `EXCEPTION WHEN OTHERS`.
    ReducerWritesCoreAudit,
}

/// Static compile-time SQL contract verified against disposable PostgreSQL 17.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SqlContract {
    /// Globally unique contract identifier (e.g. `"rules.personal_list"`).
    pub id: &'static str,
    /// Owning domain or subsystem name (e.g. `"rules"`).
    pub domain: &'static str,
    /// Exact static SQL text sent on the wire via unnamed `query_typed`.
    pub sql: &'static str,
    /// Declared parameter [`Type`]s matching `$1..$N` in exact order.
    pub params: &'static [Type],
    /// Declared result [`ColumnSpec`]s matching the `RowDescription` in order.
    pub columns: &'static [ColumnSpec],
    /// Required capability/credential scope.
    pub scope: SqlScope,
    /// Required PostgreSQL verification level.
    pub rls_check: RlsCheck,
    /// Declared core-audit posture (defaults to [`SqlAuditPosture::Standard`]).
    pub audit: SqlAuditPosture,
}

/// Zero-proc-macro compile-time helper expanding to the canonical UTC RFC 3339
/// PostgreSQL timestamp expression (matching Go's `time.Time` JSON encoding
/// with trimmed fractional seconds).
///
/// Expands via `concat!` to a `&'static str`, eliminating runtime `format!`
/// SQL interpolation helpers across domain crates.
#[macro_export]
macro_rules! pg_rfc3339 {
    ($col:literal) => {
        concat!(
            "to_char(",
            $col,
            " AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS') || CASE WHEN date_part('microseconds', ",
            $col,
            " AT TIME ZONE 'UTC')::bigint % 1000000 = 0 THEN '' ELSE regexp_replace(to_char(",
            $col,
            " AT TIME ZONE 'UTC','.US'),'0+$','') END || 'Z'"
        )
    };
}

/// Zero-proc-macro compile-time helper expanding to Go's `fmt.Sprintf("%v", time.Time)`
/// UTC representation (`2006-01-02 15:04:05.999999999 +0000 UTC`).
#[macro_export]
macro_rules! pg_go_utc_time {
    ($col:literal) => {
        concat!(
            "to_char(",
            $col,
            " AT TIME ZONE 'UTC','YYYY-MM-DD HH24:MI:SS') || CASE WHEN date_part('microseconds', ",
            $col,
            " AT TIME ZONE 'UTC')::bigint % 1000000 = 0 THEN '' ELSE regexp_replace(to_char(",
            $col,
            " AT TIME ZONE 'UTC','.US'),'0+$','') END || ' +0000 UTC'"
        )
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pg_rfc3339_matches_canonical_utc_expression() {
        const EXPR: &str = pg_rfc3339!("created_at");
        assert_eq!(
            EXPR,
            "to_char(created_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS') || \
             CASE WHEN date_part('microseconds', created_at AT TIME ZONE 'UTC')::bigint % 1000000 = 0 \
             THEN '' ELSE regexp_replace(to_char(created_at AT TIME ZONE 'UTC','.US'),'0+$','') END || 'Z'"
        );
        const FULL: &str = concat!("SELECT ", pg_rfc3339!("updated_at"), " FROM rules");
        assert!(FULL.starts_with("SELECT to_char(updated_at AT TIME ZONE 'UTC'"));
        assert!(FULL.ends_with("FROM rules"));
    }

    #[test]
    fn pg_go_utc_time_matches_go_format() {
        const EXPR: &str = pg_go_utc_time!("dr.last_seen");
        assert!(
            EXPR.starts_with("to_char(dr.last_seen AT TIME ZONE 'UTC','YYYY-MM-DD HH24:MI:SS')")
        );
        assert!(EXPR.ends_with("|| ' +0000 UTC'"));
    }

    #[test]
    fn scope_predicates_and_contract_const_construction() {
        const C: SqlContract = SqlContract {
            id: "test.sample",
            domain: "test",
            sql: "SELECT $1::bigint AS id",
            params: &[Type::INT8],
            columns: &[ColumnSpec::named("id", Type::INT8)],
            scope: SqlScope::MailboxReadOnly,
            rls_check: RlsCheck::PrepareAndExplain,
            audit: SqlAuditPosture::Standard,
        };
        assert_eq!(C.id, "test.sample");
        assert_eq!(C.audit, SqlAuditPosture::Standard);
        assert_eq!(SqlAuditPosture::default(), SqlAuditPosture::Standard);
        assert!(C.scope.is_read_only());
        assert!(!C.scope.is_worker_bypass());
        assert!(!SqlScope::MailboxReadWrite.is_read_only());
        assert!(SqlScope::AdminRead.is_read_only());
        assert!(SqlScope::AuthPreScope.is_read_only());
        assert!(SqlScope::WorkerBypass.is_worker_bypass());
    }
}
