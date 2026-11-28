//! F21 login/session/token service; family boundaries are in DOX.md.
#![forbid(unsafe_code)]
use serde_json::{json, Value};
use setjoin_pg::{AuthDb, StatementFailure};

/// Public org policy (no user data); frozen Go's pwhash.LoadPasswordPolicy query.
pub async fn password_policy(exec: &AuthDb) -> Result<Value, StatementFailure> {
    let rows = exec.read_contract(&crate::sql::LIB_L8, &[]).await?;
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
pub mod sql;

/// Static typed SQL contract catalog for `setjoin-identity` (#546d).
pub const SQL_CONTRACTS: &[setjoin_sql_catalog::SqlContract] = sql::CONTRACTS;

pub mod login;

pub mod bootstrap;
pub mod device_trust;
pub mod impersonation;
pub mod issuance;

pub mod drive_token;
pub mod session;

pub mod password;

pub mod push;
pub mod totp;

pub mod push_delivery;

pub mod recovery;

pub mod webauthn;

pub mod mutants;
pub mod oidc;
pub mod possession;

pub mod rp;

pub mod saml;
pub mod saml_acs;
mod sso_cache;

pub mod identity_links;

pub mod self_service;

pub mod guest_invite;
