//! OP token consumers. Cryptographic credentials establish the subject before
//! user-scoped reads/writes; client authentication never grants user authority.
use super::grants::{secret, write};
use super::*;
use setjoin_contracts::ids::ActorId;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub struct Access {
    id: String,
    subject: String,
}
pub fn access(key: &SigningKey, cipher: &CodeCipher, issuer: &str, token: &str) -> Option<Access> {
    if let Some(plain) = cipher.decrypt(token) {
        let mut parts = plain.split(':');
        let (id, subject) = (parts.next()?, parts.next()?);
        if parts.next().is_some() {
            return None;
        }
        return Some(Access {
            id: id.into(),
            subject: subject.into(),
        });
    }
    let claims = key.verify(token)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs() as i64;
    if claims["iss"] != issuer || claims["exp"].as_i64()? <= now {
        return None;
    }
    let subject = claims["sub"].as_str().unwrap_or("").to_owned();
    Some(Access {
        id: claims["jti"].as_str().unwrap_or("").into(),
        subject,
    })
}
struct Live {
    scopes: Vec<String>,
    client: String,
}
/// The stored row is the authority (owner-approved security fix 2026-11-05,
/// #523): the credential's subject must be the row's user, and the row must be
/// unrevoked and unexpired, whatever the token's own claims say.
async fn live(exec: &ScopedExecutor, access: &Access) -> Option<Live> {
    // #525: the owner comes from the worker-owned credential reducer (RLS).
    let owner_sql = if crate::mutants::on("oidc-direct-token-owner") {
        "SELECT user_id FROM oidc_tokens WHERE id=$1"
    } else {
        "SELECT user_id FROM rust_identity_oidc_token_owner($1)"
    };
    let found = exec
        .read(owner_sql, &[(&access.id, Type::TEXT)])
        .await
        .ok()?;
    let user = found.first()?.get::<_, i64>(0);
    let bound = !crate::mutants::on("oidc-token-unbound");
    if bound && access.subject != user.to_string() {
        return None;
    }
    let actor = ActorId::new(user).ok()?;
    let sql = if bound {
        "SELECT scopes,client_id FROM oidc_tokens WHERE id=$1 AND user_id=$2 AND revoked_at IS NULL AND expires_at>now()"
    } else {
        "SELECT scopes,client_id FROM oidc_tokens WHERE id=$1 AND user_id=$2 AND revoked_at IS NULL"
    };
    let rows = exec
        .read_user_scoped(
            actor,
            sql,
            &[(&access.id, Type::TEXT), (&user, Type::INT8)],
        )
        .await
        .ok()?;
    rows.first().map(|r| Live {
        scopes: r.get(0),
        client: r.get(1),
    })
}
async fn scopes(exec: &ScopedExecutor, access: &Access) -> Option<Vec<String>> {
    live(exec, access).await.map(|l| l.scopes)
}
pub async fn userinfo(exec: &ScopedExecutor, access: &Access) -> Option<String> {
    let scopes = scopes(exec, access).await?;
    let mut f = vec![("sub", json!(access.subject))];
    let email = scopes.iter().any(|s| s == "email");
    let profile = scopes.iter().any(|s| s == "profile");
    if email || profile {
        let user = access.subject.parse::<i64>().ok().filter(|u| *u > 0)?;
        let actor = ActorId::new(user).ok()?;
        let rows = exec
            .read_user_scoped(
                actor,
                "SELECT email,COALESCE(NULLIF(display_name,''),email) FROM users WHERE id=$1",
                &[(&user, Type::INT8)],
            )
            .await
            .ok()?;
        let row = rows.first()?;
        if profile {
            f.push(("name", json!(row.get::<_, String>(1))));
        }
        if email {
            f.push(("email", json!(row.get::<_, String>(0))));
            f.push(("email_verified", json!(true)));
        }
    }
    Some(crate::issuance::object(&f) + "\n")
}
pub async fn introspect(exec: &ScopedExecutor, access: Option<&Access>, caller: &str) -> String {
    let Some(a) = access else {
        return "{\"active\":false}\n".into();
    };
    let Some(live) = live(exec, a).await else {
        return "{\"active\":false}\n".into();
    };
    // RFC 7662 §2.2: only the client the token was issued to may learn about it
    // (owner-approved security fix 2026-11-05, #523); report the token's own client.
    let any = crate::mutants::on("oidc-introspect-any-client");
    if live.client != caller && !any {
        return "{\"active\":false}\n".into();
    }
    crate::issuance::object(&[
        ("active", json!(true)),
        ("scope", json!(live.scopes.join(" "))),
        ("client_id", json!(if any { caller } else { live.client.as_str() })),
        ("sub", json!(a.subject)),
    ]) + "\n"
}
pub async fn authenticate(exec: &ScopedExecutor, id: &str, password: &str) -> bool {
    secret(exec, id, password).await
}
pub async fn revoke(
    exec: &ScopedExecutor,
    key: &SigningKey,
    cipher: &CodeCipher,
    issuer: &str,
    fields: &BTreeMap<String, String>,
    basic: Option<(&str, &str)>,
) -> Result<(), OAuthError> {
    let get = |k: &str| fields.get(k).map(String::as_str).unwrap_or("");
    if get("client_assertion_type") == "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
        return Err(OAuthError::new(
            "invalid_client",
            "auth_method private_key_jwt not supported",
        ));
    }
    let id = basic.map_or(get("client_id"), |b| b.0);
    let password = basic.map_or(get("client_secret"), |b| b.1);
    if id.is_empty() {
        return Err(OAuthError::new("invalid_client", "invalid authorization"));
    }
    let client = client(exec, id)
        .await
        .map_err(|_| OAuthError::new("invalid_client", ""))?;
    if basic.is_some() || !password.is_empty() {
        if !secret(exec, id, password).await {
            return Err(OAuthError::new(
                "invalid_client",
                "invalid client_id / client_secret",
            ));
        }
    } else if !client.public {
        return Err(OAuthError::new("invalid_client", "invalid authorization"));
    }
    let token = get("token");
    // #525: the frozen pre-lookup of an active refresh token by hash only resolved the same
    // anchor row the revoke statement below matches by that hash again, so it is gone
    // (credential-keyed reads now go through rust_identity_oidc_revoke_target alone).
    let token_id = access(key, cipher, issuer, token)
        .map(|a| a.id)
        .unwrap_or_else(|| token.to_owned());
    let hash = format!("{:x}", Sha256::digest(token_id.as_bytes()));
    let target_sql = if crate::mutants::on("oidc-direct-revoke-target") {
        "SELECT user_id FROM oidc_tokens WHERE (refresh_token_hash=$1 OR id=$2) AND client_id=$3 AND revoked_at IS NULL"
    } else {
        "SELECT user_id FROM rust_identity_oidc_revoke_target($1,$2,$3)"
    };
    let rows=exec.read(target_sql,&[(&hash,Type::TEXT),(&token_id,Type::TEXT),(&id,Type::TEXT)]).await.map_err(|_|OAuthError::new("server_error","token revocation failed"))?;
    let result = if let Some(row) = rows.first() {
        let user: i64 = row.get(0);
        write(exec,user,"oidc-revoke","UPDATE oidc_tokens SET revoked_at=now() WHERE (refresh_token_hash=$1 OR id=$2) AND client_id=$3 AND user_id=$4 AND revoked_at IS NULL",&[(&hash,Type::TEXT),(&token_id,Type::TEXT),(&id,Type::TEXT),(&user,Type::INT8)],|_|Ok(()),"token revocation failed").await
    } else {
        let operation = setjoin_contracts::ids::OperationId(*uuid::Uuid::new_v4().as_bytes());
        match exec
            .run_protocol_command(
                &format!("oidc-client:{id}"),
                operation,
                setjoin_pg::ReceiptCommand {
                    family: "F21",
                    command: "oidc-revoke-empty",
                },
                "UPDATE oidc_tokens SET revoked_at=now() WHERE false",
                &[],
                |_| Ok(()),
            )
            .await
        {
            setjoin_pg::CommandOutcome::Committed(()) => Ok(()),
            setjoin_pg::CommandOutcome::Unknown { operation } => Err(OAuthError {
                kind: "server_error",
                description: String::new(),
                operation: Some(operation),
            }),
            _ => Err(OAuthError::new("server_error", "")),
        }
    };
    result.map_err(|e| OAuthError {
        description: "token revocation failed".into(),
        ..e
    })
}
pub async fn end_session(
    exec: &ScopedExecutor,
    key: &SigningKey,
    issuer: &str,
    fields: &BTreeMap<String, String>,
) -> Result<String, OAuthError> {
    let get = |k: &str| fields.get(k).map(String::as_str).unwrap_or("");
    let mut user = None;
    let mut id = get("client_id").to_owned();
    if !get("id_token_hint").is_empty() {
        let claims = key
            .verify(get("id_token_hint"))
            .filter(|c| c["iss"] == issuer)
            .ok_or_else(|| OAuthError::new("invalid_request", "id_token_hint invalid"))?;
        let azp = claims["azp"].as_str().unwrap_or("");
        if !id.is_empty() && id != azp {
            return Err(OAuthError::new(
                "invalid_request",
                "client_id does not match azp of id_token_hint",
            ));
        }
        id = azp.into();
        user = claims["sub"]
            .as_str()
            .and_then(|s| s.parse::<i64>().ok())
            .filter(|u| *u > 0);
    }
    if !id.is_empty() {
        client(exec, &id)
            .await
            .map_err(|e| OAuthError::new("server_error", e))?;
        if !get("post_logout_redirect_uri").is_empty() {
            return Err(OAuthError::new(
                "invalid_request",
                "post_logout_redirect_uri invalid",
            ));
        }
    }
    let Some(user) = user else {
        return Err(OAuthError::new("server_error", "error terminating session"));
    };
    write(exec,user,"oidc-end-session","UPDATE oidc_tokens SET revoked_at=now() WHERE user_id=$1 AND client_id=$2 AND revoked_at IS NULL",&[(&user,Type::INT8),(&id,Type::TEXT)],|_|Ok(()),"error terminating session").await.map_err(|e|OAuthError{description:"error terminating session".into(),..e})?;
    Ok(if get("state").is_empty() {
        "/".into()
    } else {
        query_response("/", &[("state", get("state"))], false)
    })
}
