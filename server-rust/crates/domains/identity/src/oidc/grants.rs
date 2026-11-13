//! Code grants and token publication. Only a consumed credential supplies a user.
use super::*;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use serde_json::{json, Value};
use setjoin_contracts::ids::{ActorId, OperationId};
use setjoin_pg::{CommandOutcome, Param, Rejection, StatementFailure};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub struct OAuthError {
    pub kind: &'static str,
    pub description: String,
    pub operation: Option<OperationId>,
}
impl OAuthError {
    pub fn new(kind: &'static str, description: impl Into<String>) -> Self {
        Self {
            kind,
            description: description.into(),
            operation: None,
        }
    }
    pub fn status(&self) -> u16 {
        match self.kind {
            "invalid_client" => 401,
            "server_error" => 500,
            _ => 400,
        }
    }
    pub fn wire(&self) -> String {
        let mut fields = vec![("error", json!(self.kind))];
        if !self.description.is_empty() {
            fields.push(("error_description", json!(self.description)));
        }
        crate::issuance::object(&fields) + "\n"
    }
}
/// Hard absolute lifetime of a refresh-token family (#523): rotation may slide
/// each token's 30-day window but never past this cap from the original grant.
const REFRESH_FAMILY_SECS: u64 = 90 * 24 * 3600;
fn invalid_code() -> OAuthError {
    OAuthError::new("invalid_grant", "invalid code")
}
fn db_error(prefix: &str, error: &StatementFailure) -> OAuthError {
    if error.message == "refresh token no longer active: invalid_refresh_token" {
        return OAuthError::new("server_error", &error.message);
    }
    let phase = error
        .hint
        .as_ref()
        .and_then(|s| serde_json::from_str::<Value>(s).ok())
        .and_then(|v| v["oidc_phase"].as_str().map(str::to_owned));
    let prefix = phase.as_deref().unwrap_or(prefix);
    let detail = error.sqlstate.as_ref().map_or_else(
        || error.message.clone(),
        |s| format!("ERROR: {} (SQLSTATE {s})", error.message),
    );
    OAuthError::new("server_error", format!("{prefix}: {detail}"))
}
pub(super) async fn write<T, D>(
    exec: &ScopedExecutor,
    user: i64,
    command: &'static str,
    sql: &'static str,
    params: &[Param<'_>],
    decode: D,
    prefix: &str,
) -> Result<T, OAuthError>
where
    D: FnOnce(&[setjoin_pg::Row]) -> Result<T, StatementFailure>,
{
    let actor =
        ActorId::new(user).map_err(|_| OAuthError::new("server_error", "invalid OIDC subject"))?;
    let operation = OperationId(*uuid::Uuid::new_v4().as_bytes());
    match exec
        .clone()
        .with_user_receipt(setjoin_pg::ReceiptCommand {
            family: "F21",
            command,
        })
        .run_user_command(actor, operation, sql, params, decode)
        .await
    {
        CommandOutcome::Committed(v) => Ok(v),
        CommandOutcome::Unknown { operation } => Err(OAuthError {
            kind: "server_error",
            description: format!("{prefix}: unexpected EOF"),
            operation: Some(operation),
        }),
        CommandOutcome::RolledBack(Rejection::Statement(e) | Rejection::Body(e)) => {
            Err(db_error(prefix, &e))
        }
        _ => Err(OAuthError::new(
            "server_error",
            format!("{prefix}: database unavailable"),
        )),
    }
}
pub(super) fn random_hex(n: usize) -> Result<String, OAuthError> {
    use ring::rand::SecureRandom;
    let mut bytes = vec![0; n];
    ring::rand::SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| OAuthError::new("server_error", "random identifier failed"))?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}
fn unix(time: SystemTime) -> i64 {
    time.duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}
pub struct TokenReply {
    pub access: String,
    pub id: String,
    pub refresh: String,
    pub validity: u64,
    pub scopes: Vec<String>,
}
impl TokenReply {
    pub fn wire(&self) -> String {
        let mut f = vec![
            ("access_token", json!(self.access)),
            ("token_type", json!("Bearer")),
        ];
        if !self.refresh.is_empty() {
            f.push(("refresh_token", json!(self.refresh)));
        }
        if self.validity > 0 {
            f.push(("expires_in", json!(self.validity)));
        }
        if !self.id.is_empty() {
            f.push(("id_token", json!(self.id)));
        }
        if !self.scopes.is_empty() {
            f.push(("scope", json!(self.scopes.join(" "))));
        }
        crate::issuance::object(&f) + "\n"
    }
}
async fn consume(exec: &ScopedExecutor, code: &str, client_id: &str) -> Result<Authorization, OAuthError> {
    let hash = Sha256::digest(code.as_bytes()).to_vec();
    // Credential lookup, like password/address lookup: no request-owned uid.
    let rows=exec.read("SELECT user_id,client_id FROM oidc_auth_requests WHERE code_hash=$1 AND expires_at>now() AND done=true",&[(&hash,Type::BYTEA)]).await.map_err(|_|invalid_code())?;
    let user = rows
        .first()
        .and_then(|r| r.try_get::<_, Option<i64>>(0).ok().flatten())
        .filter(|u| *u > 0)
        .ok_or_else(invalid_code)?;
    // The reducer consumes only a code issued to the presenting client, so
    // client A can never burn client B's code (#523).
    let owner: String = rows[0].get(1);
    let client_id = if crate::mutants::on("oidc-consume-any-client") { owner.as_str() } else { client_id };
    write(
        exec,
        user,
        "oidc-consume",
        "SELECT * FROM rust_identity_oidc_consume($1,$2,$3)",
        &[(&user, Type::INT8), (&hash, Type::BYTEA), (&client_id, Type::TEXT)],
        |rows| {
            rows.first().map(Authorization::decode).unwrap_or_else(|| {
                Err(StatementFailure {
                    sqlstate: None,
                    hint: None,
                    message: "auth request not found".into(),
                })
            })
        },
        "auth request consumption",
    )
    .await
    .map_err(|error| OAuthError {
        operation: error.operation,
        ..invalid_code()
    })
}
pub(super) async fn secret(exec: &ScopedExecutor, id: &str, presented: &str) -> bool {
    let Ok(rows) = exec
        .read(
            "SELECT secret FROM oidc_clients WHERE id=$1 AND enabled=true",
            &[(&id, Type::TEXT)],
        )
        .await
    else {
        return false;
    };
    let Some(hash) = rows.first().and_then(|r| r.try_get::<_, String>(0).ok()) else {
        return false;
    };
    let presented = presented.to_owned();
    tokio::task::spawn_blocking(move || bcrypt::verify(presented, &hash).unwrap_or(false))
        .await
        .unwrap_or(false)
}
pub async fn code_exchange(
    exec: &ScopedExecutor,
    key: &SigningKey,
    issuer: &str,
    fields: &BTreeMap<String, String>,
) -> Result<TokenReply, OAuthError> {
    let get = |k: &str| fields.get(k).map(String::as_str).unwrap_or("");
    if get("code").is_empty() {
        return Err(OAuthError::new("invalid_request", "code missing"));
    }
    if get("client_assertion_type") == "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
        return Err(OAuthError::new(
            "invalid_client",
            "auth_method private_key_jwt not supported",
        ));
    }
    // Owner-approved security fix 2026-11-05 (#523): authenticate the client
    // BEFORE the single-use code is consumed, so a code holder who cannot
    // authenticate cannot burn it (frozen Go consumes first).
    let early = !crate::mutants::on("oidc-consume-before-client-auth");
    let mut client_early = None;
    if early {
        let client = client(exec, get("client_id"))
            .await
            .map_err(|_| OAuthError::new("invalid_client", ""))?;
        if !client.public && !secret(exec, &client.id, get("client_secret")).await {
            return Err(OAuthError::new(
                "invalid_client",
                "invalid client_id / client_secret",
            ));
        }
        if !client.grants.iter().any(|s| s == "authorization_code") {
            return Err(OAuthError::new(
                "unauthorized_client",
                "client missing grant type authorization_code",
            ));
        }
        client_early = Some(client);
    }
    let request = consume(exec, get("code"), client_early.as_ref().map_or(get("client_id"), |c| c.id.as_str())).await?;
    if request.challenge.is_empty() {
        if !get("code_verifier").is_empty() {
            return Err(OAuthError::new(
                "invalid_request",
                "code_verifier unexpectedly provided",
            ));
        }
    } else {
        if get("code_verifier").is_empty() {
            return Err(OAuthError::new("invalid_request", "code_verifier required"));
        }
        use subtle::ConstantTimeEq;
        let expected = B64.encode(Sha256::digest(get("code_verifier").as_bytes()));
        if !bool::from(expected.as_bytes().ct_eq(request.challenge.as_bytes())) {
            return Err(OAuthError::new("invalid_grant", "invalid code_verifier"));
        }
    }
    let client = match client_early {
        Some(c) => c,
        None => client(exec, get("client_id"))
            .await
            .map_err(|_| OAuthError::new("invalid_client", ""))?,
    };
    // OAuth 2.1: PKCE for every client, confidential ones included (#523).
    if request.challenge.is_empty() && (client.public || !crate::mutants::on("oidc-confidential-no-pkce")) {
        return Err(OAuthError::new("invalid_request", "PKCE required"));
    }
    if !client.public && !early && !secret(exec, &client.id, get("client_secret")).await {
        return Err(OAuthError::new(
            "invalid_client",
            "invalid client_id / client_secret",
        ));
    }
    if client.id != request.client {
        return Err(OAuthError::new("invalid_grant", ""));
    }
    if !client.grants.iter().any(|s| s == "authorization_code") {
        return Err(OAuthError::new(
            "unauthorized_client",
            "client missing grant type authorization_code",
        ));
    }
    if get("redirect_uri") != request.redirect {
        return Err(OAuthError::new(
            "invalid_grant",
            "redirect_uri does not correspond",
        ));
    }
    mint_fresh(exec, key, issuer, &request, &client, get("code")).await
}
async fn mint_fresh(
    exec: &ScopedExecutor,
    key: &SigningKey,
    issuer: &str,
    request: &Authorization,
    client: &Client,
    code: &str,
) -> Result<TokenReply, OAuthError> {
    let user = request
        .user
        .filter(|u| *u > 0)
        .ok_or_else(|| OAuthError::new("server_error", "invalid OIDC subject"))?;
    let subject = user.to_string();
    let id = random_hex(16)?;
    let expiry = SystemTime::now() + Duration::from_secs(300);
    write(exec,user,"oidc-access","INSERT INTO oidc_tokens(id,client_id,user_id,subject,scopes,expires_at) VALUES($1,$2,$3,$4,$5,$6) RETURNING id",
        &[(&id,Type::TEXT),(&request.client,Type::TEXT),(&user,Type::INT8),(&subject,Type::TEXT),(&request.scopes,Type::TEXT_ARRAY),(&expiry,Type::TIMESTAMPTZ)],|_|Ok(()),"create access token").await?;
    let mut refresh = String::new();
    if request.scopes.iter().any(|s| s == "offline_access")
        && client.grants.iter().any(|g| g == "refresh_token")
    {
        refresh = random_hex(32)?;
        let hash = format!("{:x}", Sha256::digest(refresh.as_bytes()));
        let expires = SystemTime::now() + Duration::from_secs(2592000);
        let family_expires = SystemTime::now() + Duration::from_secs(REFRESH_FAMILY_SECS);
        // Independent autocommit in frozen Go. A failed attachment leaves the
        // access row committed; do not combine these fresh-grant statements.
        // The grant's first row names the refresh family and its hard lifetime (#523).
        write(exec,user,"oidc-refresh-attach","UPDATE oidc_tokens SET refresh_token_hash=$3,refresh_expires_at=$4,refresh_family=$1,refresh_family_expires_at=$5 WHERE id=$1 AND user_id=$2",
            &[(&id,Type::TEXT),(&user,Type::INT8),(&hash,Type::TEXT),(&expires,Type::TIMESTAMPTZ),(&family_expires,Type::TIMESTAMPTZ)],|_|Ok(()),"set refresh hash").await?;
    }
    let validity = expiry
        .duration_since(SystemTime::now())
        .unwrap_or_default()
        .as_secs();
    finish(
        exec, key, issuer, request, client, code, &id, expiry, refresh, validity,
    )
    .await
}
async fn finish(
    exec: &ScopedExecutor,
    key: &SigningKey,
    issuer: &str,
    request: &Authorization,
    client: &Client,
    code: &str,
    id: &str,
    expiry: SystemTime,
    refresh: String,
    validity: u64,
) -> Result<TokenReply, OAuthError> {
    let user = request
        .user
        .filter(|u| *u > 0)
        .ok_or_else(|| OAuthError::new("server_error", "invalid OIDC subject"))?;
    let subject = user.to_string();
    let now = unix(SystemTime::now());
    let access=key.sign(&json!({"iss":issuer,"sub":subject,"aud":[client.id],"exp":unix(expiry),"iat":now,"nbf":now,"client_id":client.id,"jti":id})).map_err(|e|OAuthError::new("server_error",e))?;
    let now = unix(SystemTime::now());
    let mut claims = json!({"iss":issuer,"sub":subject,"aud":[client.id],"exp":now+300,"iat":now,"azp":client.id,"client_id":client.id,"acr":if request.acr.is_empty(){"aal1"}else{&request.acr},"amr":if request.amr.is_empty(){vec!["pwd".to_owned()]}else{request.amr.clone()},"at_hash":B64.encode(&Sha256::digest(access.as_bytes())[..16])});
    if !request.nonce.is_empty() {
        claims["nonce"] = json!(request.nonce);
    }
    let auth = unix(request.auth_time);
    if auth != 0 {
        claims["auth_time"] = json!(auth);
    }
    if !code.is_empty() {
        claims["c_hash"] = json!(B64.encode(&Sha256::digest(code.as_bytes())[..16]));
    }
    if !request.scopes.is_empty() && !request.scopes.iter().any(|s| s == "openid") {
        claims.as_object_mut().unwrap().remove("sub");
    }
    let email = request.scopes.iter().any(|s| s == "email");
    let profile = request.scopes.iter().any(|s| s == "profile");
    if email || profile {
        let actor = ActorId::new(user).expect("proved positive subject");
        let rows = exec
            .read_user_scoped(
                actor,
                "SELECT email,COALESCE(NULLIF(display_name,''),email) FROM users WHERE id=$1",
                &[(&user, Type::INT8)],
            )
            .await
            .map_err(|e| db_error("read OIDC subject claims", &e))?;
        let row = rows.first().ok_or_else(|| {
            OAuthError::new(
                "server_error",
                "read OIDC subject claims: no rows in result set",
            )
        })?;
        if email {
            claims["email"] = json!(row.get::<_, String>(0));
            claims["email_verified"] = json!(true);
        }
        if profile {
            claims["name"] = json!(row.get::<_, String>(1));
        }
    }
    let id_token = key
        .sign(&claims)
        .map_err(|e| OAuthError::new("server_error", e))?;
    Ok(TokenReply {
        access,
        id: id_token,
        refresh,
        validity,
        scopes: request.scopes.clone(),
    })
}

pub async fn refresh_exchange(
    exec: &ScopedExecutor,
    key: &SigningKey,
    issuer: &str,
    fields: &BTreeMap<String, String>,
) -> Result<TokenReply, OAuthError> {
    let get = |k: &str| fields.get(k).map(String::as_str).unwrap_or("");
    if get("refresh_token").is_empty() {
        return Err(OAuthError::new("invalid_request", "refresh_token missing"));
    }
    if get("client_assertion_type") == "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
        return Err(OAuthError::new(
            "server_error",
            "auth_method private_key_jwt not supported",
        ));
    }
    let client = client(exec, get("client_id"))
        .await
        .map_err(|e| OAuthError::new("server_error", e))?;
    if !client.grants.iter().any(|s| s == "refresh_token") {
        return Err(OAuthError::new("unauthorized_client", ""));
    }
    if !client.public && !secret(exec, &client.id, get("client_secret")).await {
        return Err(OAuthError::new(
            "invalid_client",
            "invalid client_id / client_secret",
        ));
    }
    let old_hash = format!("{:x}", Sha256::digest(get("refresh_token").as_bytes()));
    // #525: the credential-keyed read goes through the worker-owned reducer that
    // derives the user from the hash (oidc_tokens is FORCE-RLS on the user GUC).
    let anchor_sql = if crate::mutants::on("oidc-direct-refresh-anchor") {
        "SELECT id,client_id,user_id,scopes,revoked_at IS NOT NULL,refresh_expires_at>now() AND COALESCE(refresh_family_expires_at,created_at+interval '90 days')>now() FROM oidc_tokens WHERE refresh_token_hash=$1 LIMIT 1"
    } else {
        "SELECT id,client_id,user_id,scopes,spent,live FROM rust_identity_oidc_refresh_anchor($1)"
    };
    let rows=exec.read(anchor_sql,&[(&old_hash,Type::TEXT)]).await.map_err(|_|OAuthError::new("invalid_grant",""))?;
    let r = rows
        .first()
        .ok_or_else(|| OAuthError::new("invalid_grant", ""))?;
    let id: String = r.get(0);
    let owner_client: String = r.get(1);
    let user: i64 = r.get(2);
    let mut scopes: Vec<String> = r.get(3);
    let (spent, live): (bool, bool) = (r.get(4), r.get(5));
    if owner_client != client.id {
        return Err(OAuthError::new("invalid_grant", ""));
    }
    if spent {
        // A rotated (or revoked) refresh token presented again means it leaked:
        // revoke the whole family (owner-approved security fix 2026-11-05, #523).
        if !crate::mutants::on("oidc-refresh-reuse-ignored") {
            write(
                exec,
                user,
                "oidc-refresh-reuse",
                "SELECT revoked FROM rust_identity_oidc_reuse($1,$2,$3)",
                &[(&user, Type::INT8), (&client.id, Type::TEXT), (&old_hash, Type::TEXT)],
                |_| Ok(()),
                "refresh reuse revocation",
            )
            .await?;
        }
        return Err(OAuthError::new("invalid_grant", ""));
    }
    if !live {
        return Err(OAuthError::new("invalid_grant", ""));
    }
    if fields.contains_key("scope") {
        let requested: Vec<String> = get("scope").split(' ').map(str::to_owned).collect();
        if requested.iter().any(|s| !scopes.contains(s)) {
            return Err(OAuthError::new("invalid_scope", ""));
        }
        scopes = requested;
    }
    // Go stores no authentication context on the refresh anchor. Preserve its
    // aal1/pwd fallback and absent auth_time/nonce rather than inventing one.
    let request = Authorization {
        id,
        client: owner_client,
        redirect: String::new(),
        state: String::new(),
        nonce: String::new(),
        challenge: String::new(),
        scopes,
        user: Some(user),
        done: false,
        auth_time: UNIX_EPOCH,
        acr: String::new(),
        amr: Vec::new(),
    };
    // #523: every refresh redemption spends the presented token, narrowed scope
    // included; its access row joins the family. (Go minted without rotating.)
    if crate::mutants::on("oidc-narrow-no-rotate") && !request.scopes.iter().any(|s| s == "offline_access") {
        return mint_fresh(exec, key, issuer, &request, &client, "").await;
    }
    let id = random_hex(16)?;
    let refresh = random_hex(32)?;
    let hash = format!("{:x}", Sha256::digest(refresh.as_bytes()));
    let expiry = write(
        exec,
        user,
        "oidc-rotate",
        "SELECT expires_at FROM rust_identity_oidc_rotate($1,$2,$3,$4,$5,$6)",
        &[
            (&user, Type::INT8),
            (&client.id, Type::TEXT),
            (&old_hash, Type::TEXT),
            (&id, Type::TEXT),
            (&request.scopes, Type::TEXT_ARRAY),
            (&hash, Type::TEXT),
        ],
        |rows| {
            rows.first()
                .map(|r| r.get::<_, SystemTime>(0))
                .ok_or_else(|| StatementFailure {
                    sqlstate: None,
                    hint: None,
                    message: "refresh token no longer active: invalid_refresh_token".into(),
                })
        },
        "refresh rotation",
    )
    .await?;
    let validity = expiry
        .duration_since(SystemTime::now())
        .unwrap_or_default()
        .as_secs();
    finish(
        exec, key, issuer, &request, &client, "", &id, expiry, refresh, validity,
    )
    .await
}
