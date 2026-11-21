//! F21 login/session/token service; family boundaries are in DOX.md.
#![forbid(unsafe_code)]
use serde_json::{json, Value};
use setjoin_pg::{ScopedExecutor, StatementFailure};

/// Public org policy (no user data); frozen Go's pwhash.LoadPasswordPolicy query.
pub async fn password_policy(exec: &ScopedExecutor) -> Result<Value, StatementFailure> {
    let rows=exec.read("SELECT COALESCE((SELECT (value->>0)::INT FROM system_config WHERE key='password_min_length'),8), COALESCE((SELECT (value->>0)::BOOL FROM system_config WHERE key='password_require_uppercase'),true), COALESCE((SELECT (value->>0)::BOOL FROM system_config WHERE key='password_require_lowercase'),true), COALESCE((SELECT (value->>0)::BOOL FROM system_config WHERE key='password_require_digit'),true), COALESCE((SELECT (value->>0)::BOOL FROM system_config WHERE key='password_require_special'),true)",&[]).await?;
    let bad = || StatementFailure {
        sqlstate: None,
        hint: None,
        message: "invalid password policy row".into(),
    };
    let r = rows.first().ok_or_else(bad)?;
    let min_length: i32 = r.try_get(0).map_err(|_| bad())?;
    let require_uppercase: bool = r.try_get(1).map_err(|_| bad())?;
    let require_lowercase: bool = r.try_get(2).map_err(|_| bad())?;
    let require_digit: bool = r.try_get(3).map_err(|_| bad())?;
    let require_special: bool = r.try_get(4).map_err(|_| bad())?;
    Ok(
        json!({"minLength":min_length,"maxBytes":72,"requireUppercase":require_uppercase,"requireLowercase":require_lowercase,"requireDigit":require_digit,"requireSpecial":require_special}),
    )
}
pub mod login;

pub mod issuance;
pub mod impersonation;
pub mod bootstrap;

pub mod drive_token;
pub mod session;

pub mod password;

pub mod totp;
pub mod push;

pub mod push_delivery;

pub mod recovery;

pub mod webauthn;

pub mod possession;
pub mod oidc;
pub mod mutants;

pub mod rp;

pub mod saml;
pub mod saml_acs;
mod sso_cache;

pub mod identity_links;

pub mod self_service;

pub mod guest_invite;
