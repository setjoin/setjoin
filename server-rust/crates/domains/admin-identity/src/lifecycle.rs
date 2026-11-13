//! Admin identity (F01) slice `user-lifecycle`: create, update, delete, password
//! reset, CSV import rows, secure-account, sign-in history and app-password
//! revocation. See the crate DOX for the contract.
//!
//! Go's validation (password policy, display name) is pure and runs at the edge in
//! Go's order. Writes that were multi-statement Go transactions call one reducer
//! each (`rust_admin_user_*`, `rust_admin_app_password_revoke`); the existing
//! `admin_reset_password` and `provision_account` reducers are called as Go calls
//! them. Reducers answer `{status,...}`; every status other than the success one
//! rolls the command back, so a refusal leaves neither data nor a receipt.
use super::{deadline, envelope, invalid, scope};
use setjoin_authz::AuthContext;
use setjoin_pg::{
    CommandOutcome, ReceiptCommand, Rejection, Row, ScopedExecutor, StatementFailure, Type,
};
use sha2::{Digest, Sha256};
use unicode_properties::{GeneralCategory, UnicodeGeneralCategory};

pub const USERS_SUSPEND: [&str; 1] = ["users.suspend"];
pub const USERS_DELETE: [&str; 1] = ["users.delete"];
pub const USERS_PASSWORD_RESET: [&str; 1] = ["users.password_reset"];

fn command(name: &'static str) -> ReceiptCommand {
    ReceiptCommand {
        family: "F01",
        command: name,
    }
}

/// A refusal decided by a reducer, carried through the executor as a rolled-back body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Problem {
    pub status: u16,
    pub detail: String,
}

pub fn problem_of(error: &Rejection<StatementFailure>) -> Option<Problem> {
    let (Rejection::Statement(e) | Rejection::Body(e)) = error else {
        return None;
    };
    if e.sqlstate.is_some() {
        return None;
    }
    let v: serde_json::Value = serde_json::from_str(&e.message).ok()?;
    Some(Problem {
        status: v["status"].as_u64()? as u16,
        detail: v["detail"].as_str()?.to_owned(),
    })
}

/// The reducer verdict of a committed command: the success status commits and
/// yields the reducer document, any other status rolls the command back.
fn verdict(rows: &[Row], success: u64) -> Result<serde_json::Value, StatementFailure> {
    let text: String = rows
        .first()
        .and_then(|r| r.try_get(0).ok())
        .ok_or_else(invalid)?;
    let v: serde_json::Value = serde_json::from_str(&text).map_err(|_| invalid())?;
    match v["status"].as_u64() {
        Some(status) if status == success => Ok(v),
        Some(_) if v["detail"].is_string() => Err(StatementFailure {
            sqlstate: None,
            hint: None,
            message: text,
        }),
        _ => Err(invalid()),
    }
}

// ---- Go's pure validation ----------------------------------------------------------

/// Go's `validate.PasswordPolicy` as loaded by `pwhash.LoadPasswordPolicy`.
#[derive(Clone, Debug)]
pub struct PasswordPolicy {
    pub min_length: i32,
    pub uppercase: bool,
    pub lowercase: bool,
    pub digit: bool,
    pub special: bool,
}

impl Default for PasswordPolicy {
    /// The policy Go falls back to when the configuration read fails.
    fn default() -> Self {
        Self {
            min_length: 8,
            uppercase: true,
            lowercase: true,
            digit: true,
            special: true,
        }
    }
}

/// `pwhash.LoadPasswordPolicy`; a failed read is Go's default policy.
pub async fn load_policy(exec: &ScopedExecutor) -> PasswordPolicy {
    let sql = "SELECT \
        COALESCE((SELECT (value->>0)::INT FROM system_config WHERE key = 'password_min_length'), 8), \
        COALESCE((SELECT (value->>0)::BOOL FROM system_config WHERE key = 'password_require_uppercase'), true), \
        COALESCE((SELECT (value->>0)::BOOL FROM system_config WHERE key = 'password_require_lowercase'), true), \
        COALESCE((SELECT (value->>0)::BOOL FROM system_config WHERE key = 'password_require_digit'), true), \
        COALESCE((SELECT (value->>0)::BOOL FROM system_config WHERE key = 'password_require_special'), true)";
    let Ok(rows) = exec.read(sql, &[]).await else {
        return PasswordPolicy::default();
    };
    let Some(row) = rows.first() else {
        return PasswordPolicy::default();
    };
    match (
        row.try_get::<_, i32>(0),
        row.try_get::<_, bool>(1),
        row.try_get::<_, bool>(2),
        row.try_get::<_, bool>(3),
        row.try_get::<_, bool>(4),
    ) {
        (Ok(min_length), Ok(uppercase), Ok(lowercase), Ok(digit), Ok(special)) => PasswordPolicy {
            min_length,
            uppercase,
            lowercase,
            digit,
            special,
        },
        _ => PasswordPolicy::default(),
    }
}

/// Go's `strings.ToLower` applies the simple case mapping rune by rune.
fn go_lower(text: &str) -> String {
    text.chars()
        .map(|c| {
            let mut lower = c.to_lowercase();
            match (lower.next(), lower.next()) {
                (Some(one), None) => one,
                _ => 'i', // U+0130 is the only rune whose full mapping is two runes; Go maps it to 'i'.
            }
        })
        .collect()
}

/// `pwhash.CheckCommonPassword`; a failed lookup is "not common", as in Go.
pub async fn is_common_password(exec: &ScopedExecutor, password: &str) -> bool {
    let digest: Vec<u8> = Sha256::digest(go_lower(password.trim()).as_bytes()).to_vec();
    let Ok(rows) = exec
        .read(
            "SELECT EXISTS(SELECT 1 FROM common_passwords WHERE password_hash = $1)",
            &[(&digest, Type::BYTEA)],
        )
        .await
    else {
        return false;
    };
    rows.first()
        .and_then(|r| r.try_get::<_, bool>(0).ok())
        .unwrap_or(false)
}

pub const COMMON_PASSWORD: &str =
    "This password is too common and easily guessed. Please choose a stronger password.";

/// `validate.ValidatePassword`; the error is Go's `ToFieldError().Message`.
pub fn validate_password(
    password: &str,
    policy: &PasswordPolicy,
    disallow_email: &str,
) -> Result<(), &'static str> {
    if password.is_empty() {
        return Err("password must not be empty");
    }
    if password.len() > 72 {
        return Err("password exceeds 72 UTF-8 bytes");
    }
    let min = if policy.min_length < 1 {
        8
    } else {
        policy.min_length
    } as usize;
    if password.chars().count() < min {
        return Err("password too short");
    }
    let (mut upper, mut lower, mut digit, mut special) = (false, false, false, false);
    for c in password.chars() {
        match c.general_category() {
            GeneralCategory::UppercaseLetter => upper = true,
            GeneralCategory::LowercaseLetter => lower = true,
            GeneralCategory::DecimalNumber => digit = true,
            GeneralCategory::ConnectorPunctuation
            | GeneralCategory::DashPunctuation
            | GeneralCategory::OpenPunctuation
            | GeneralCategory::ClosePunctuation
            | GeneralCategory::InitialPunctuation
            | GeneralCategory::FinalPunctuation
            | GeneralCategory::OtherPunctuation
            | GeneralCategory::MathSymbol
            | GeneralCategory::CurrencySymbol
            | GeneralCategory::ModifierSymbol
            | GeneralCategory::OtherSymbol => special = true,
            _ => {}
        }
    }
    if policy.uppercase && !upper {
        return Err("password must contain an uppercase letter");
    }
    if policy.lowercase && !lower {
        return Err("password must contain a lowercase letter");
    }
    if policy.digit && !digit {
        return Err("password must contain a digit");
    }
    if policy.special && !special {
        return Err("password must contain a special character");
    }
    if !disallow_email.is_empty() && contains_email(password, disallow_email) {
        return Err("password must not contain your email address");
    }
    Ok(())
}

/// `passwordContainsEmail`: case-insensitive containment of the address's
/// local part (quoted-string unwrapped) or domain, split on the last '@'.
fn contains_email(password: &str, email: &str) -> bool {
    let password = password.to_lowercase();
    let mut address = email.trim().to_lowercase();
    if let Ok(list) = mailparse::addrparse(&address) {
        if list.len() == 1 {
            if let mailparse::MailAddr::Single(a) = &list[0] {
                if !a.addr.is_empty() {
                    address = a.addr.to_lowercase();
                }
            }
        }
    }
    let Some(at) = address.rfind('@') else {
        return false;
    };
    let local = &address[..at];
    let local = if local.len() >= 2 && local.starts_with('"') && local.ends_with('"') {
        &local[1..local.len() - 1]
    } else {
        local
    };
    let domain = &address[at + 1..];
    (!local.is_empty() && password.contains(local))
        || (!domain.is_empty() && password.contains(domain))
}

/// `validate.ValidateDisplayName`.
pub fn validate_display_name(name: &str) -> Result<(), &'static str> {
    let name = name.trim();
    if name.is_empty() {
        return Err("display name must not be empty");
    }
    if name.len() > 128 {
        return Err("display name exceeds 128 characters");
    }
    if name.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err("display name contains control character");
    }
    Ok(())
}

// ---- reads under the verified actor --------------------------------------------------

fn flag(rows: &[Row]) -> Result<bool, StatementFailure> {
    rows.first()
        .and_then(|r| r.try_get::<_, bool>(0).ok())
        .ok_or_else(invalid)
}

/// `admin_can_manage(actor, target)`: current domain and OU reach.
pub async fn can_manage(
    exec: &ScopedExecutor,
    actor: i64,
    target: i64,
) -> Result<bool, StatementFailure> {
    flag(
        &exec
            .read(
                "SELECT admin_can_manage($1, $2)",
                &[(&actor, Type::INT8), (&target, Type::INT8)],
            )
            .await?,
    )
}

/// `is_guest_account(target)`: Go fails closed on a lookup error.
pub async fn is_guest(exec: &ScopedExecutor, target: i64) -> Result<bool, StatementFailure> {
    flag(
        &exec
            .read("SELECT is_guest_account($1)", &[(&target, Type::INT8)])
            .await?,
    )
}

/// Go's `domainGate` existence-in-scope test (domain scope 0 is global).
pub async fn in_scope(
    exec: &ScopedExecutor,
    domain_scope: i64,
    target: i64,
) -> Result<bool, StatementFailure> {
    flag(
        &exec
            .read(
                "SELECT EXISTS(SELECT 1 FROM users WHERE id = $1 AND ($2::bigint <= 0 OR domain_id = $2))",
                &[(&target, Type::INT8), (&domain_scope, Type::INT8)],
            )
            .await?,
    )
}

/// The target's email for the password-policy containment check; `None` is Go's 404.
pub async fn reset_email(
    exec: &ScopedExecutor,
    domain_scope: i64,
    target: i64,
) -> Result<Option<String>, StatementFailure> {
    let rows = if domain_scope > 0 {
        exec.read(
            "SELECT email FROM users WHERE id = $1 AND COALESCE(guest_account_host_domain(id), domain_id) = $2",
            &[(&target, Type::INT8), (&domain_scope, Type::INT8)],
        )
        .await?
    } else {
        exec.read(
            "SELECT email FROM users WHERE id = $1",
            &[(&target, Type::INT8)],
        )
        .await?
    };
    match rows.first() {
        None => Ok(None),
        Some(row) => Ok(Some(row.try_get::<_, String>(0).map_err(|_| invalid())?)),
    }
}

/// `mailbox_lifecycle_enabled()`: when on, the compatibility DELETE is refused.
pub async fn lifecycle_enabled(worker: &ScopedExecutor) -> Result<bool, StatementFailure> {
    flag(
        &worker
            .read("SELECT mailbox_lifecycle_enabled()", &[])
            .await?,
    )
}

/// `GET /admin/users/{id}/sign-ins`: up to 200 attributed events, newest first.
/// Rows render in Go's struct field order; `occurred_at` is `Format(time.RFC3339)`.
pub async fn sign_ins(
    exec: &ScopedExecutor,
    target: i64,
    domain_scope: i64,
) -> Result<String, StatementFailure> {
    let rows = exec
        .read(
            "SELECT id, to_char(occurred_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'), source_ip, location, \
             device_name, platform, client, protocol, auth_method, success, fail_reason \
             FROM rust_admin_user_sign_ins($1, $2)",
            &[(&target, Type::INT8), (&domain_scope, Type::INT8)],
        )
        .await?;
    let bad = |_| invalid();
    let mut items = Vec::new();
    for row in &rows {
        let text = |i: usize| -> Result<String, StatementFailure> {
            Ok(super::s(&row.try_get::<_, String>(i).map_err(bad)?))
        };
        let fail = row.try_get::<_, String>(10).map_err(bad)?;
        items.push(format!(
            "{{\"id\":{},\"occurred_at\":{},\"source_ip\":{},\"location\":{},\"device_name\":{},\"platform\":{},\"client\":{},\"protocol\":{},\"auth_method\":{},\"success\":{}{}}}",
            row.try_get::<_, i64>(0).map_err(bad)?,
            text(1)?,
            text(2)?,
            text(3)?,
            text(4)?,
            text(5)?,
            text(6)?,
            text(7)?,
            text(8)?,
            row.try_get::<_, bool>(9).map_err(bad)?,
            if fail.is_empty() {
                String::new()
            } else {
                format!(",\"fail_reason\":{}", super::s(&fail))
            },
        ));
    }
    Ok(super::done(format!("{{\"items\":[{}]}}", items.join(","))))
}

// ---- commands --------------------------------------------------------------------------

/// `POST /admin/users` after the edge validation: the new id and whether the
/// outbox already holds the publication (Go dispatches directly otherwise).
#[allow(clippy::too_many_arguments)]
pub async fn create(
    worker: &ScopedExecutor,
    actor: &AuthContext,
    raw_email: &str,
    email: &str,
    display_name: &str,
    hash: &str,
    is_local_admin: bool,
    domain_scope: i64,
    operation: [u8; 16],
) -> CommandOutcome<(i64, bool), StatementFailure> {
    let auth = scope(actor);
    let payload = format!("{raw_email}\u{0}{email}\u{0}{display_name}\u{0}{is_local_admin}");
    setjoin_pg::run_receipted_command(
        worker,
        command("user_create"),
        &envelope(&auth, operation, &payload),
        &auth,
        deadline(),
        "SELECT rust_admin_user_create($2,$4,$5,$6,$7,$8,$9)::text WHERE $1::bigint > 0 AND $3::text <> ''",
        &[
            (&raw_email, Type::TEXT),
            (&email, Type::TEXT),
            (&display_name, Type::TEXT),
            (&hash, Type::TEXT),
            (&is_local_admin, Type::BOOL),
            (&domain_scope, Type::INT8),
        ],
        |rows| {
            let v = verdict(rows, 201)?;
            Ok((
                v["id"].as_i64().ok_or_else(invalid)?,
                v["queued"].as_bool().ok_or_else(invalid)?,
            ))
        },
    )
    .await
}

/// `PUT /admin/users/{id}` after reach: the publication flag.
#[allow(clippy::too_many_arguments)]
pub async fn update(
    worker: &ScopedExecutor,
    actor: &AuthContext,
    id: i64,
    domain_scope: i64,
    display_name: Option<&str>,
    enabled: Option<bool>,
    is_local_admin: Option<bool>,
    operation: [u8; 16],
) -> CommandOutcome<bool, StatementFailure> {
    let auth = scope(actor);
    let payload = format!("{id}:{domain_scope}:{display_name:?}:{enabled:?}:{is_local_admin:?}");
    let display_name = display_name.map(str::to_owned);
    setjoin_pg::run_receipted_command(
        worker,
        command("user_update"),
        &envelope(&auth, operation, &payload),
        &auth,
        deadline(),
        "SELECT rust_admin_user_update($2,$4,$5,$6,$7,$8)::text WHERE $1::bigint > 0 AND $3::text <> ''",
        &[
            (&id, Type::INT8),
            (&domain_scope, Type::INT8),
            (&display_name, Type::TEXT),
            (&enabled, Type::BOOL),
            (&is_local_admin, Type::BOOL),
        ],
        |rows| {
            let v = verdict(rows, 204)?;
            v["queued"].as_bool().ok_or_else(invalid)
        },
    )
    .await
}

/// `DELETE /admin/users/{id}`: the publication flag.
pub async fn delete(
    worker: &ScopedExecutor,
    actor: &AuthContext,
    id: i64,
    domain_scope: i64,
    operation: [u8; 16],
) -> CommandOutcome<bool, StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        worker,
        command("user_delete"),
        &envelope(&auth, operation, &format!("{id}:{domain_scope}")),
        &auth,
        deadline(),
        "SELECT rust_admin_user_delete($2,$4,$5)::text WHERE $1::bigint > 0 AND $3::text <> ''",
        &[(&id, Type::INT8), (&domain_scope, Type::INT8)],
        |rows| {
            let v = verdict(rows, 204)?;
            v["queued"].as_bool().ok_or_else(invalid)
        },
    )
    .await
}

/// `PUT /admin/users/{id}/password`: Go's `admin_reset_password` reducer, unchanged.
pub async fn reset_password(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    id: i64,
    domain_scope: i64,
    hash: &str,
    must_change: bool,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        exec,
        command("user_password_reset"),
        &envelope(
            &auth,
            operation,
            &format!("{id}:{domain_scope}:{must_change}"),
        ),
        &auth,
        deadline(),
        "SELECT admin_reset_password($2,$4,$5,$6,$7) WHERE $1::bigint > 0 AND $3::text <> ''",
        &[
            (&id, Type::INT8),
            (&domain_scope, Type::INT8),
            (&hash, Type::TEXT),
            (&must_change, Type::BOOL),
        ],
        |rows| {
            rows.first()
                .and_then(|r| r.try_get::<_, i64>(0).ok())
                .map(|_| ())
                .ok_or_else(invalid)
        },
    )
    .await
}

/// `POST /admin/users/{id}/secure-account`.
pub async fn secure(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    id: i64,
    domain_scope: i64,
    ip: &str,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let auth = scope(actor);
    setjoin_pg::run_receipted_command(
        exec,
        command("user_secure"),
        &envelope(&auth, operation, &format!("{id}:{domain_scope}")),
        &auth,
        deadline(),
        "SELECT count(*)::bigint FROM (SELECT rust_admin_user_secure($2,$4,$6,$5) WHERE $1::bigint > 0 AND $3::text <> '') w",
        &[(&id, Type::INT8), (&domain_scope, Type::INT8), (&ip, Type::TEXT)],
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

/// `DELETE /admin/users/{userId}/app-passwords/{apId}`: `false` is Go's 404.
#[allow(clippy::too_many_arguments)]
pub async fn revoke_app_password(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    user: i64,
    app_password: i64,
    domain_scope: i64,
    ip: &str,
    operation: [u8; 16],
) -> CommandOutcome<bool, StatementFailure> {
    let auth = scope(actor);
    let email = actor.email().to_owned();
    setjoin_pg::run_receipted_command(
        exec,
        command("app_password_revoke"),
        &envelope(
            &auth,
            operation,
            &format!("{user}:{app_password}:{domain_scope}"),
        ),
        &auth,
        deadline(),
        "SELECT rust_admin_app_password_revoke($2,$4,$5,$6,$7,$8) WHERE $1::bigint > 0 AND $3::text <> ''",
        &[
            (&user, Type::INT8),
            (&app_password, Type::INT8),
            (&domain_scope, Type::INT8),
            (&ip, Type::TEXT),
            (&email, Type::TEXT),
        ],
        |rows| {
            let found = flag(rows)?;
            if found {
                Ok(true)
            } else {
                // A miss changes nothing: roll back so no receipt is kept for it.
                Err(StatementFailure {
                    sqlstate: None,
                    hint: None,
                    message: "{\"status\":404,\"detail\":\"not found\"}".into(),
                })
            }
        },
    )
    .await
}

/// A CSV row: `provision_account` exactly as Go's `identity.ProvisionAccount` binds it.
#[allow(clippy::too_many_arguments)]
pub async fn import_row(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    email: &str,
    display_name: &str,
    hash: &str,
    is_local_admin: bool,
    department: Option<i64>,
    quota_bytes: Option<i64>,
    operation: [u8; 16],
) -> CommandOutcome<bool, StatementFailure> {
    let auth = scope(actor);
    let payload =
        format!("{email}\u{0}{display_name}\u{0}{is_local_admin}:{department:?}:{quota_bytes:?}");
    let actor_id = actor.user_id();
    setjoin_pg::run_receipted_command(
        exec,
        command("user_import_row"),
        &envelope(&auth, operation, &payload),
        &auth,
        deadline(),
        "SELECT provision_account(p_email => $4, p_display_name => $5, p_password_hash => $6, p_is_local_admin => $7, \
         p_enabled => TRUE, p_sync_source => 'local', p_department_id => $8, p_quota_bytes => $9, p_create_only => TRUE, \
         p_actor => $10)::text WHERE $1::bigint > 0 AND $2::bigint > 0 AND $3::text <> ''",
        &[
            (&email, Type::TEXT),
            (&display_name, Type::TEXT),
            (&hash, Type::TEXT),
            (&is_local_admin, Type::BOOL),
            (&department, Type::INT8),
            (&quota_bytes, Type::INT8),
            (&actor_id, Type::INT8),
        ],
        |rows| {
            let text: String = rows
                .first()
                .and_then(|r| r.try_get(0).ok())
                .ok_or_else(invalid)?;
            let v: serde_json::Value = serde_json::from_str(&text).map_err(|_| invalid())?;
            Ok(v["created"].as_bool().unwrap_or(false))
        },
    )
    .await
}

/// `admin_scope_within(actor, 'ou', department, grant_domain)` for a CSV row.
pub async fn department_in_scope(
    exec: &ScopedExecutor,
    actor: i64,
    department: i64,
    grant_domain: Option<i64>,
) -> Result<bool, StatementFailure> {
    flag(
        &exec
            .read(
                "SELECT admin_scope_within($1, 'ou', $2, $3)",
                &[
                    (&actor, Type::INT8),
                    (&department, Type::INT8),
                    (&grant_domain, Type::INT8),
                ],
            )
            .await?,
    )
}

/// `resolveLocalDomain`: the id of the local domain named by the raw address's last
/// '@' suffix, or `None` (any failure is the same 400 in Go).
pub async fn local_domain(exec: &ScopedExecutor, raw_email: &str) -> Option<i64> {
    let at = raw_email.rfind('@')?;
    if at == raw_email.len() - 1 {
        return None;
    }
    let domain = raw_email[at + 1..].to_lowercase();
    let rows = exec
        .read(
            "SELECT id FROM domains WHERE lower(name) = $1 AND is_local = TRUE LIMIT 1",
            &[(&domain, Type::TEXT)],
        )
        .await
        .ok()?;
    rows.first().and_then(|r| r.try_get::<_, i64>(0).ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> PasswordPolicy {
        PasswordPolicy::default()
    }

    #[test]
    fn password_policy_messages_follow_go_order() {
        let p = policy();
        assert_eq!(
            validate_password("", &p, ""),
            Err("password must not be empty")
        );
        assert_eq!(
            validate_password(&"a".repeat(73), &p, ""),
            Err("password exceeds 72 UTF-8 bytes")
        );
        assert_eq!(validate_password("Ab1!", &p, ""), Err("password too short"));
        assert_eq!(
            validate_password("alllower1!", &p, ""),
            Err("password must contain an uppercase letter")
        );
        assert_eq!(
            validate_password("ALLUPPER1!", &p, ""),
            Err("password must contain a lowercase letter")
        );
        assert_eq!(
            validate_password("NoDigits!!", &p, ""),
            Err("password must contain a digit")
        );
        assert_eq!(
            validate_password("NoSpecial12", &p, ""),
            Err("password must contain a special character")
        );
        assert_eq!(validate_password("Str0ng!Passw0rd", &p, ""), Ok(()));
    }

    #[test]
    fn length_counts_runes_for_the_minimum_and_bytes_for_the_maximum() {
        let p = PasswordPolicy {
            min_length: 8,
            uppercase: false,
            lowercase: false,
            digit: false,
            special: false,
        };
        // Eight CJK runes are 24 bytes: long enough; 25 of them are 75 bytes: too long.
        assert_eq!(validate_password(&"密".repeat(8), &p, ""), Ok(()));
        assert_eq!(
            validate_password(&"密".repeat(25), &p, ""),
            Err("password exceeds 72 UTF-8 bytes")
        );
        assert_eq!(
            validate_password(&"密".repeat(7), &p, ""),
            Err("password too short")
        );
    }

    #[test]
    fn character_classes_are_unicode_general_categories() {
        let p = PasswordPolicy {
            min_length: 1,
            uppercase: true,
            lowercase: true,
            digit: true,
            special: true,
        };
        // Greek capital, lowercase, Arabic-Indic digit (Nd) and a currency symbol (Sc).
        assert_eq!(validate_password("Δa٣€", &p, ""), Ok(()));
        // A titlecase letter (Lt) is neither upper nor lower in Go.
        assert_eq!(
            validate_password("ǅ1!x", &p, ""),
            Err("password must contain an uppercase letter")
        );
    }

    #[test]
    fn address_containment_uses_local_part_and_domain_case_insensitively() {
        let p = policy();
        assert_eq!(
            validate_password("My-Bob-Pw!9x", &p, "Bob@corp.example"),
            Err("password must not contain your email address")
        );
        assert_eq!(
            validate_password("Pw-CORP.example!9", &p, "bob@corp.example"),
            Err("password must not contain your email address")
        );
        assert_eq!(
            validate_password("Str0ng!Passw0rd", &p, "\"Bob\" <bob@corp.example>"),
            Ok(())
        );
        assert_eq!(
            validate_password("Xbob!Passw0rd9", &p, "\"bob\"@corp.example"),
            Err("password must not contain your email address")
        );
    }

    #[test]
    fn display_name_rules() {
        assert_eq!(
            validate_display_name("   "),
            Err("display name must not be empty")
        );
        assert_eq!(
            validate_display_name(&"n".repeat(129)),
            Err("display name exceeds 128 characters")
        );
        assert_eq!(
            validate_display_name("a\u{7}b"),
            Err("display name contains control character")
        );
        assert_eq!(validate_display_name("  名前 😀  "), Ok(()));
    }

    #[test]
    fn lowercasing_is_rune_wise_like_go() {
        assert_eq!(go_lower("ABC Δ"), "abc δ");
        assert_eq!(go_lower("İ"), "i");
    }
}
