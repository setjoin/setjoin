//! F21 login/session/token service; family boundaries are in DOX.md.
#![forbid(unsafe_code)]
use serde_json::{json, Value};
use setjoin_pg::{ScopedExecutor, StatementFailure};

/// Public org policy (no user data); frozen Go's pwhash.LoadPasswordPolicy query.
pub async fn password_policy(exec: &ScopedExecutor) -> Result<Value, StatementFailure> {
    let rows=exec.read("SELECT COALESCE((SELECT (value->>0)::INT FROM system_config WHERE key='password_min_length'),8), COALESCE((SELECT (value->>0)::BOOL FROM system_config WHERE key='password_require_uppercase'),true), COALESCE((SELECT (value->>0)::BOOL FROM system_config WHERE key='password_require_lowercase'),true), COALESCE((SELECT (value->>0)::BOOL FROM system_config WHERE key='password_require_digit'),true), COALESCE((SELECT (value->>0)::BOOL FROM system_config WHERE key='password_require_special'),true)",&[]).await?;
    let r = &rows[0];
    Ok(
        json!({"minLength":r.get::<_,i32>(0),"maxBytes":72,"requireUppercase":r.get::<_,bool>(1),"requireLowercase":r.get::<_,bool>(2),"requireDigit":r.get::<_,bool>(3),"requireSpecial":r.get::<_,bool>(4)}),
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

pub mod identity_links;

pub mod self_service;

pub mod guest_invite;
