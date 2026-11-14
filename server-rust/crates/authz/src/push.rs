//! Go's cookie/out-of-band push-token acceptance seam. Unlike HTTP command
//! admission it does not impose CSRF, a feature toggle or mailbox lifecycle.
use crate::token::{self, KeySource};
use serde_json::{Map, Value};
use setjoin_pg::{ScopedExecutor, Type};

#[derive(Clone)]
pub struct PushIdentity {
    claims: Map<String, Value>,
    guest: bool,
}

impl PushIdentity {
    /// Signed metadata retained by the narrow Drive mirror issuer (#333).
    pub fn email(&self)->&str{self.text("email")}
    pub fn has_device_binding(&self)->bool{self.claims.get("device").is_some_and(|v|!v.is_null())}
    /// Signed impersonation provenance (the acting admin's uid), if any.
    pub fn act(&self)->Option<i64>{self.claims.get("act").and_then(Value::as_i64)}
    /// Whether the token carries a non-null `act` of any type (Go: present and non-null).
    pub fn has_act(&self)->bool{self.claims.get("act").is_some_and(|v|!v.is_null())}
    /// Whether the signed token carries `iat` (drive-scoped push admission does not require it).
    pub fn has_issued_at(&self)->bool{self.claims.get("iat").is_some_and(|v|v.as_i64().is_some())}
    pub fn account_type(&self)->&str{if self.guest{"guest"}else{self.text("acct")}}
    pub fn user_id(&self) -> i64 {
        self.claims.get("uid").and_then(Value::as_i64).unwrap_or(0)
    }
    pub fn issued_at(&self) -> i64 {
        self.claims.get("iat").and_then(Value::as_i64).unwrap_or(0)
    }
    pub fn expires_at(&self) -> i64 {
        self.claims["exp"].as_i64().expect("verified exp")
    }
    pub fn token_id(&self) -> &str {
        self.text("jti")
    }
    pub fn token_family(&self) -> &str {
        self.text("fam")
    }
    pub fn is_guest(&self) -> bool {
        self.guest
    }
    pub fn device_id(&self) -> &str {
        self.claims
            .get("device")
            .and_then(|v| v.get("id"))
            .and_then(Value::as_str)
            .unwrap_or("")
    }
    fn text(&self, name: &str) -> &str {
        self.claims.get(name).and_then(Value::as_str).unwrap_or("")
    }
}

async fn verified_claims(
    _exec: &ScopedExecutor,
    keys: &impl KeySource,
    issuer: &str,
    token: &str,
    drive_scope:bool,
) -> Option<Map<String, Value>> {
    let claims = token::signed_claims(token, keys).await?;
    token::claims_shape_ok(&claims)?;
    let text = |key: &str| claims.get(key).and_then(Value::as_str).unwrap_or("");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs() as i64;
    if text("iss") != issuer
        || text("typ") != "access"
        || (!text("scp").is_empty() && !(drive_scope && text("scp")=="drive"))
        || (!drive_scope && claims.get("iat")?.as_i64().is_none())
        || now >= claims.get("exp")?.as_i64()?
        || claims
            .get("nbf")
            .filter(|v| !v.is_null())
            .is_some_and(|v| v.as_i64().is_none_or(|n| now < n))
    {
        return None;
    }
    let audience = claims.get("aud")?;
    if audience.as_str() != Some(token::AUDIENCE)
        && !audience
            .as_array()
            .is_some_and(|a| a.iter().any(|v| v.as_str() == Some(token::AUDIENCE)))
    {
        return None;
    }
    Some(claims)
}

#[derive(Clone, Copy, Debug)]
pub enum PushAuthError {
    Invalid,
    GuestInactive,
    GuestUnavailable,
}

pub async fn authenticate(
    exec: &ScopedExecutor,
    keys: &impl KeySource,
    issuer: &str,
    token: &str,
) -> Option<PushIdentity> {
    authenticate_detailed(exec, keys, issuer, token).await.ok()
}

pub async fn authenticate_detailed(
    exec: &ScopedExecutor,
    keys: &impl KeySource,
    issuer: &str,
    token: &str,
) -> Result<PushIdentity, PushAuthError> {
    authenticate_for_scope(exec,keys,issuer,token,false).await
}
/// Gateway Drive issuer admission: empty or drive scope; no mailbox is invented.
pub async fn authenticate_drive(exec:&ScopedExecutor,keys:&impl KeySource,issuer:&str,token:&str)->Result<PushIdentity,PushAuthError>{authenticate_for_scope(exec,keys,issuer,token,true).await}
async fn authenticate_for_scope(exec:&ScopedExecutor,keys:&impl KeySource,issuer:&str,token:&str,drive_scope:bool)->Result<PushIdentity,PushAuthError>{
    let claims = verified_claims(exec, keys, issuer, token, drive_scope)
        .await
        .ok_or(PushAuthError::Invalid)?;
    let user = claims.get("uid").and_then(Value::as_i64).unwrap_or(0);
    let claimed_guest = claims.get("acct").and_then(Value::as_str) == Some("guest");
    let rows=exec.read("SELECT status, expires_at IS NOT NULL AND expires_at < now() FROM guest_account_status($1)",&[(&user,Type::INT8)]).await.map_err(|_|PushAuthError::GuestUnavailable)?;
    let guest = if let Some(row) = rows.first() {
        if row.get::<_, String>(0) != "active" || row.get::<_, bool>(1) {
            return Err(PushAuthError::GuestInactive);
        }
        true
    } else {
        if claimed_guest {
            return Err(PushAuthError::GuestInactive);
        }
        false
    };
    Ok(PushIdentity { claims, guest })
}

/// HTTP security shapes still owned by the shared interceptor (#420).
pub async fn http_admission_allowed(exec: &ScopedExecutor) -> bool {
    crate::gates::admission_allowed(exec, None).await
}

/// Durable twin of Go's process-local denylist; read failure kept distinct (#354).
pub async fn revocation(exec: &ScopedExecutor, identity: &PushIdentity) -> Result<bool, setjoin_pg::StatementFailure> {
    let (user, iat, jti, family) = (identity.user_id(), identity.issued_at() as f64, identity.token_id(), identity.token_family());
    let rows = exec.read("SELECT EXISTS(SELECT 1 FROM session_revocations WHERE user_id=$1 AND expires_at>now() AND ((scope='all' AND not_before>=to_timestamp($2::float8)) OR (scope='jti' AND $3<>'' AND jti=$3) OR (scope='family' AND $4<>'' AND family_id=$4)))",
        &[(&user,Type::INT8),(&iat,Type::FLOAT8),(&jti,Type::TEXT),(&family,Type::TEXT)]).await?;
    Ok(rows[0].get::<_, bool>(0))
}
/// Durable twin of Go's process-local denylist; also closes the subscribe race.
pub async fn revoked(exec: &ScopedExecutor, identity: &PushIdentity) -> bool {
    revocation(exec, identity).await.unwrap_or(true)
}

impl PushIdentity {
    /// The push batch's own primary mailbox and pre-dispatch state. No client
    /// account ID or HTTP-only admission gate enters this authorization.
    pub async fn command_authorization(&self, exec: &ScopedExecutor) -> Option<crate::Authorized> {
        let user = self.user_id();
        let rows=exec.read("SELECT m.id,m.jmap_email_state::int8,m.jmap_mailbox_state::int8,m.jmap_thread_state::int8,m.jmap_tag_state::int8,coalesce((SELECT max(jmap_state) FROM calendars WHERE mailbox_id=m.id),0)::int8,coalesce((SELECT max(jmap_state) FROM addressbooks WHERE mailbox_id=m.id),0)::int8,coalesce((SELECT max(jmap_state) FROM tasks WHERE mailbox_id=m.id),0)::int8,floor(extract(epoch FROM u.updated_at))::int8 FROM mailboxes m JOIN users u ON u.id=m.user_id WHERE m.user_id=$1 AND m.is_primary",&[(&user,Type::INT8)]).await.ok()?;
        let row = rows.first()?;
        let admin = self
            .claims
            .get("admin")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let roles = if admin {
            crate::gates::roles(exec, user).await?
        } else {
            Vec::new()
        };
        let strings = |key: &str| {
            self.claims
                .get(key)
                .and_then(Value::as_array)
                .map(|v| {
                    v.iter()
                        .filter_map(Value::as_str)
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default()
        };
        Some(crate::Authorized {
            context: crate::AuthContext {
                guest: self.guest,
                user_id: user,
                email: self.text("email").into(),
                mailbox_id: row.get(0),
                domain_scope: self.claims.get("domain").and_then(Value::as_i64),
                admin,
                permissions: strings("perms"),
                roles,
                auth_time: self.claims.get("auth_time").and_then(Value::as_i64),
            },
            state: crate::gates::SessionState {
                email: row.get(1),
                mailbox: row.get(2),
                thread: row.get(3),
                tag: row.get(4),
                calendar: row.get(5),
                contact: row.get(6),
                task: row.get(7),
                identity: row.get(8),
            },
            issued_at: self.issued_at(),
            token_id: self.token_id().into(),
            token_family: self.token_family().into(),
            acr: self.text("acr").into(),
            amr: strings("amr"),
            device_id: self.device_id().into(),
        })
    }
}

impl PushIdentity {
    /// Sealed user-only HTTP authority. Zero denotes an absent mailbox and is
    /// never converted into a MailboxId or used for mailstore operations.
    pub(crate) fn user_authorization(&self) -> Option<crate::Authorized> {
        if !self.guest || self.user_id() <= 0 { return None; }
        let strings=|key:&str|self.claims.get(key).and_then(Value::as_array)
            .map(|a|a.iter().filter_map(Value::as_str).map(str::to_owned).collect()).unwrap_or_default();
        Some(crate::Authorized {
            context:crate::AuthContext {
                guest: true,
                user_id:self.user_id(),email:self.text("email").into(),mailbox_id:0,
                domain_scope:self.claims.get("domain").and_then(Value::as_i64),
                admin:self.claims.get("admin").and_then(Value::as_bool).unwrap_or(false),
                permissions:strings("perms"),roles:Vec::new(),
                auth_time:self.claims.get("auth_time").and_then(Value::as_i64),
            },
            state:crate::gates::SessionState {email:0,mailbox:0,thread:0,tag:0,calendar:0,contact:0,task:0,identity:0},
            issued_at:self.issued_at(),token_id:self.token_id().into(),token_family:self.token_family().into(),
            acr:self.text("acr").into(),amr:strings("amr"),device_id:self.device_id().into(),
        })
    }
}

#[cfg(test)]
mod accessor_tests {
    use super::*;
    use serde_json::json;

    fn identity(claims: Value) -> PushIdentity {
        PushIdentity { claims: claims.as_object().cloned().unwrap_or_default(), guest: true }
    }

    #[test]
    fn has_act_is_true_for_any_non_null_type() {
        for act in [json!(1), json!("admin"), json!(1.5), json!({}), json!([]), json!(true)] {
            assert!(identity(json!({"act": act.clone()})).has_act(), "act {act}");
        }
        assert!(!identity(json!({"act": null})).has_act());
        assert!(!identity(json!({})).has_act());
    }

    #[test]
    fn has_issued_at_requires_an_integer() {
        assert!(identity(json!({"iat": 12345})).has_issued_at());
        for iat in [json!("12345"), json!(1.5), json!(null), json!({})] {
            assert!(!identity(json!({"iat": iat.clone()})).has_issued_at(), "iat {iat}");
        }
        assert!(!identity(json!({})).has_issued_at());
    }
}
