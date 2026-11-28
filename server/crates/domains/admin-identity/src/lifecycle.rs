//! Admin identity (F01) slice `user-lifecycle`: create, update, delete, password
//! reset, CSV import rows, secure-account, sign-in history and app-password
//! revocation. See the crate DOX for the contract.
use super::{deadline, envelope, invalid, sql, FAMILY};
use setjoin_authz::principals::{AdminPermissionProof, TxFactory};
use setjoin_pg::{CommandOutcome, ReceiptCommand, Rejection, Row, StatementFailure};
use sha2::{Digest, Sha256};
use unicode_properties::{GeneralCategory, UnicodeGeneralCategory};

pub const USERS_SUSPEND: [&str; 1] = ["users.suspend"];
pub const USERS_DELETE: [&str; 1] = ["users.delete"];
pub const USERS_PASSWORD_RESET: [&str; 1] = ["users.password_reset"];

fn command(name: &'static str) -> ReceiptCommand {
    ReceiptCommand {
        family: FAMILY,
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

/// Public projection for worker-bypass `USER_UPDATE` / `USER_DELETE` (204 verdict).
pub fn parse_mut_verdict(rows: &[Row]) -> Result<bool, StatementFailure> {
    let v = verdict(rows, 204)?;
    v["queued"].as_bool().ok_or_else(invalid)
}

/// Public projection for worker-bypass `USER_IMPORT_ROW` (`provision_account`).
pub fn parse_import_row(rows: &[Row]) -> Result<bool, StatementFailure> {
    let text: String = rows
        .first()
        .and_then(|r| r.try_get(0).ok())
        .ok_or_else(invalid)?;
    let v: serde_json::Value = serde_json::from_str(&text).map_err(|_| invalid())?;
    Ok(v["created"].as_bool().unwrap_or(false))
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
pub async fn load_policy(factory: &TxFactory, admin: &AdminPermissionProof) -> PasswordPolicy {
    let Ok(rows) = factory
        .run_admin_read_contract(admin, &sql::PASSWORD_POLICY_LOAD, &[])
        .await
    else {
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
pub async fn is_common_password(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    password: &str,
) -> bool {
    let digest: Vec<u8> = Sha256::digest(go_lower(password.trim()).as_bytes()).to_vec();
    let Ok(rows) = factory
        .run_admin_read_contract(admin, &sql::COMMON_PASSWORD_EXISTS, &[&digest])
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

// ---- reads under the verified admin proof --------------------------------------------------

fn flag(rows: &[Row]) -> Result<bool, StatementFailure> {
    rows.first()
        .and_then(|r| r.try_get::<_, bool>(0).ok())
        .ok_or_else(invalid)
}

/// `admin_can_manage(actor, target)`: current domain and OU reach.
pub async fn can_manage(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    actor: i64,
    target: i64,
) -> Result<bool, StatementFailure> {
    flag(
        &factory
            .run_admin_read_contract(admin, &sql::ADMIN_CAN_MANAGE, &[&actor, &target])
            .await?,
    )
}

/// `is_guest_account(target)`: Go fails closed on a lookup error.
pub async fn is_guest(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    target: i64,
) -> Result<bool, StatementFailure> {
    flag(
        &factory
            .run_admin_read_contract(admin, &sql::IS_GUEST_ACCOUNT, &[&target])
            .await?,
    )
}

/// Go's `domainGate` existence-in-scope test (domain scope 0 is global).
pub async fn in_scope(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    domain_scope: i64,
    target: i64,
) -> Result<bool, StatementFailure> {
    flag(
        &factory
            .run_admin_read_contract(admin, &sql::USER_IN_SCOPE, &[&target, &domain_scope])
            .await?,
    )
}

/// The target's email for the password-policy containment check; `None` is Go's 404.
pub async fn reset_email(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    domain_scope: i64,
    target: i64,
) -> Result<Option<String>, StatementFailure> {
    let rows = if domain_scope > 0 {
        factory
            .run_admin_read_contract(admin, &sql::RESET_EMAIL_SCOPED, &[&target, &domain_scope])
            .await?
    } else {
        factory
            .run_admin_read_contract(admin, &sql::RESET_EMAIL_GLOBAL, &[&target])
            .await?
    };
    match rows.first() {
        None => Ok(None),
        Some(row) => Ok(Some(row.try_get::<_, String>(0).map_err(|_| invalid())?)),
    }
}

/// `mailbox_lifecycle_enabled()`: when on, the compatibility DELETE is refused.
pub async fn lifecycle_enabled(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
) -> Result<bool, StatementFailure> {
    flag(
        &factory
            .run_admin_read_contract(admin, &sql::LIFECYCLE_ENABLED, &[])
            .await?,
    )
}

/// `GET /admin/users/{id}/sign-ins`: up to 200 attributed events, newest first.
pub async fn sign_ins(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    target: i64,
    domain_scope: i64,
) -> Result<String, StatementFailure> {
    let rows = factory
        .run_admin_read_contract(admin, &sql::USER_SIGN_INS, &[&target, &domain_scope])
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

// ---- audited commands --------------------------------------------------------------------------

/// `POST /admin/users` after the edge validation: the new id and whether the
/// outbox already holds the publication (Go dispatches directly otherwise).
#[allow(clippy::too_many_arguments)]
pub async fn create(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    raw_email: &str,
    email: &str,
    display_name: &str,
    hash: &str,
    is_local_admin: bool,
    domain_scope: i64,
    operation: [u8; 16],
) -> CommandOutcome<(i64, bool), StatementFailure> {
    let payload = format!("{raw_email}\u{0}{email}\u{0}{display_name}\u{0}{is_local_admin}");
    let env = envelope(admin.actor(), admin.generation(), operation, &payload);
    factory
        .run_admin_audited_reducer_contract(
            admin,
            &env,
            deadline(),
            &sql::USER_CREATE,
            &[
                &raw_email,
                &email,
                &display_name,
                &hash,
                &is_local_admin,
                &domain_scope,
            ],
            Some(command("user_create")),
            |rows, _audited| {
                let v = verdict(&rows, 201)?;
                Ok((
                    v["id"].as_i64().ok_or_else(invalid)?,
                    v["queued"].as_bool().ok_or_else(invalid)?,
                ))
            },
        )
        .await
}

/// `PUT /admin/users/{id}/password`: Go's `admin_reset_password` reducer, unchanged.
pub async fn reset_password(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    id: i64,
    domain_scope: i64,
    hash: &str,
    must_change: bool,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let env = envelope(
        admin.actor(),
        admin.generation(),
        operation,
        &format!("{id}:{domain_scope}:{must_change}"),
    );
    factory
        .run_admin_audited_reducer_contract(
            admin,
            &env,
            deadline(),
            &sql::USER_PASSWORD_RESET,
            &[&id, &domain_scope, &hash, &must_change],
            Some(command("user_password_reset")),
            |rows, _audited| {
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
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    id: i64,
    domain_scope: i64,
    ip: &str,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let env = envelope(
        admin.actor(),
        admin.generation(),
        operation,
        &format!("{id}:{domain_scope}"),
    );
    factory
        .run_admin_audited_reducer_contract(
            admin,
            &env,
            deadline(),
            &sql::USER_SECURE,
            &[&id, &ip, &domain_scope],
            Some(command("user_secure")),
            |rows, _audited| {
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
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    actor_email: &str,
    user: i64,
    app_password: i64,
    domain_scope: i64,
    ip: &str,
    operation: [u8; 16],
) -> CommandOutcome<bool, StatementFailure> {
    let env = envelope(
        admin.actor(),
        admin.generation(),
        operation,
        &format!("{user}:{app_password}:{domain_scope}"),
    );
    let email = actor_email.to_owned();
    factory
        .run_admin_audited_reducer_contract(
            admin,
            &env,
            deadline(),
            &sql::APP_PASSWORD_REVOKE,
            &[&user, &app_password, &domain_scope, &ip, &email],
            Some(command("app_password_revoke")),
            |rows, _audited| {
                let found = flag(&rows)?;
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

/// `admin_scope_within(actor, 'ou', department, grant_domain)` for a CSV row.
pub async fn department_in_scope(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    actor: i64,
    department: i64,
    grant_domain: Option<i64>,
) -> Result<bool, StatementFailure> {
    flag(
        &factory
            .run_admin_read_contract(
                admin,
                &sql::DEPARTMENT_IN_SCOPE,
                &[&actor, &department, &grant_domain],
            )
            .await?,
    )
}

/// `resolveLocalDomain`: the id of the local domain named by the raw address's last
/// '@' suffix, or `None` (any failure is the same 400 in Go).
pub async fn local_domain(
    factory: &TxFactory,
    admin: &AdminPermissionProof,
    raw_email: &str,
) -> Option<i64> {
    let at = raw_email.rfind('@')?;
    if at == raw_email.len() - 1 {
        return None;
    }
    let domain = raw_email[at + 1..].to_lowercase();
    let rows = factory
        .run_admin_read_contract(admin, &sql::LOCAL_DOMAIN, &[&domain])
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
        assert_eq!(validate_password("Δa٣€", &p, ""), Ok(()));
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
            validate_display_name(&"a".repeat(129)),
            Err("display name exceeds 128 characters")
        );
        assert_eq!(
            validate_display_name("a\nb"),
            Err("display name contains control character")
        );
        assert_eq!(validate_display_name("Alice"), Ok(()));
    }
}
