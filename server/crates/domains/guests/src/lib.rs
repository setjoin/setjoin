//! Guests (F11): verified actors and canonical reducer authority.
#![forbid(unsafe_code)]

pub mod sql;
pub use sql::SQL_CONTRACTS;

use setjoin_authz::principals::{AdminPermissionProof, TxFactory, UserPrincipal};
use setjoin_contracts::{
    authority::{AuthorityKey, ResourceScope},
    command::CommandEnvelope,
    ids::{ActorId, Digest, Generation, OperationId},
};
use setjoin_pg::{CommandOutcome, ReceiptCommand, Rejection, StatementFailure};
use sha2::{Digest as _, Sha256};

fn invalid() -> StatementFailure {
    StatementFailure {
        sqlstate: None,
        hint: None,
        message: "invalid guest result".into(),
    }
}

fn deadline() -> std::time::Instant {
    std::time::Instant::now() + std::time::Duration::from_secs(30)
}

fn envelope(
    actor: ActorId,
    generation: Generation,
    operation: [u8; 16],
    payload: &[u8],
) -> CommandEnvelope<()> {
    CommandEnvelope {
        operation: OperationId(operation),
        authority: AuthorityKey {
            actor,
            scope: ResourceScope::User(actor),
            generation,
        },
        binding: setjoin_db::lifecycle::accepted_contract(),
        payload_digest: Digest(Sha256::digest(payload).into()),
        command: (),
    }
}

pub async fn enabled(factory: &TxFactory) -> Result<bool, StatementFailure> {
    let rows = factory.run_public_read_contract(&sql::ENABLED, &[]).await?;
    Ok(rows.first().is_some_and(|r| r.get(0)))
}

pub async fn approval_enabled(factory: &TxFactory) -> Result<bool, StatementFailure> {
    let rows = factory
        .run_public_read_contract(&sql::APPROVAL_ENABLED, &[])
        .await?;
    Ok(rows.first().is_some_and(|r| r.get(0)))
}

pub async fn profiles(
    factory: &TxFactory,
    proof: &AdminPermissionProof,
) -> Result<String, StatementFailure> {
    let user = proof.actor().get();
    let rows = factory
        .run_admin_read_contract(proof, &sql::PROFILES_LIST, &[&user])
        .await?;
    rows.first()
        .and_then(|r| r.try_get(0).ok())
        .ok_or_else(invalid)
}

pub async fn profile(
    factory: &TxFactory,
    proof: &AdminPermissionProof,
    id: i64,
) -> Result<String, StatementFailure> {
    let user = proof.actor().get();
    let rows = factory
        .run_admin_read_contract(proof, &sql::PROFILE_GET, &[&user, &id])
        .await?;
    rows.first()
        .and_then(|r| r.try_get(0).ok())
        .ok_or_else(invalid)
}

pub async fn profile_domains(
    factory: &TxFactory,
    proof: &AdminPermissionProof,
) -> Result<String, StatementFailure> {
    let user = proof.actor().get();
    let rows = factory
        .run_admin_read_contract(proof, &sql::PROFILE_DOMAINS, &[&user])
        .await?;
    rows.first()
        .and_then(|r| r.try_get(0).ok())
        .ok_or_else(invalid)
}

/// One receipted reducer call mirrors Go's entire save/read transaction.
pub async fn save_profile(
    factory: &TxFactory,
    proof: &AdminPermissionProof,
    id: Option<i64>,
    body: &str,
    operation: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let env = envelope(
        proof.actor(),
        proof.generation(),
        operation,
        body.as_bytes(),
    );
    factory
        .run_admin_audited_reducer_contract(
            proof,
            &env,
            deadline(),
            &sql::PROFILE_SAVE,
            &[&id, &body],
            Some(ReceiptCommand {
                family: "F11",
                command: "guest_profile_save",
            }),
            |rows, _| {
                rows.first()
                    .and_then(|r| r.try_get(0).ok())
                    .ok_or_else(invalid)
            },
        )
        .await
}

pub async fn delete_profile(
    factory: &TxFactory,
    proof: &AdminPermissionProof,
    id: i64,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let env = envelope(
        proof.actor(),
        proof.generation(),
        operation,
        &id.to_be_bytes(),
    );
    factory
        .run_admin_audited_reducer_contract(
            proof,
            &env,
            deadline(),
            &sql::PROFILE_DELETE,
            &[&id],
            Some(ReceiptCommand {
                family: "F11",
                command: "guest_profile_delete",
            }),
            |rows, _| {
                if rows.len() == 1 {
                    Ok(())
                } else {
                    Err(invalid())
                }
            },
        )
        .await
}

/// BYPASSRLS read retains the canonical same-assignment live permission + host reach.
pub async fn list(
    factory: &TxFactory,
    proof: &AdminPermissionProof,
) -> Result<String, StatementFailure> {
    let user = proof.actor().get();
    let rows = factory
        .run_admin_read_contract(proof, &sql::GUEST_LIST, &[&user])
        .await?;
    rows.first()
        .and_then(|r| r.try_get(0).ok())
        .ok_or_else(invalid)
}

pub async fn get(
    factory: &TxFactory,
    proof: &AdminPermissionProof,
    id: i64,
) -> Result<Option<String>, StatementFailure> {
    let user = proof.actor().get();
    let rows = factory
        .run_admin_read_contract(proof, &sql::GUEST_GET, &[&user, &id])
        .await?;
    rows.first()
        .map(|r| r.try_get(0).map_err(|_| invalid()))
        .transpose()
}

pub async fn sponsors(
    factory: &TxFactory,
    proof: &AdminPermissionProof,
    id: i64,
    query: &str,
) -> Result<String, StatementFailure> {
    let user = proof.actor().get();
    let rows = factory
        .run_admin_read_contract(proof, &sql::SPONSORS_LIST, &[&user, &id, &query])
        .await?;
    rows.first()
        .and_then(|r| r.try_get(0).ok())
        .ok_or_else(invalid)
}

/// Go's scoped prelock is not a separate mutation authority; the reducer repeats reach.
pub async fn set_status(
    factory: &TxFactory,
    proof: &AdminPermissionProof,
    id: i64,
    action: &str,
    expires: Option<&str>,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let payload = format!("{id}:{action}:{expires:?}");
    let env = envelope(
        proof.actor(),
        proof.generation(),
        operation,
        payload.as_bytes(),
    );
    factory
        .run_admin_audited_reducer_contract(
            proof,
            &env,
            deadline(),
            &sql::SET_STATUS,
            &[&id, &action, &expires],
            Some(ReceiptCommand {
                family: "F11",
                command: "guest_status",
            }),
            |rows, _| match rows.first().and_then(|r| r.try_get::<_, bool>(0).ok()) {
                Some(true) => Ok(()),
                Some(false) => Err(StatementFailure {
                    sqlstate: None,
                    hint: None,
                    message: "guest target not found".into(),
                }),
                None => Err(invalid()),
            },
        )
        .await
}

pub async fn assign_profile(
    factory: &TxFactory,
    user: &UserPrincipal,
    id: i64,
    profile: Option<i64>,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let actor = user.user().get();
    let payload = format!("{id}:{profile:?}");
    let env = envelope(
        user.user(),
        user.generation(),
        operation,
        payload.as_bytes(),
    );
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::ASSIGN_PROFILE,
            &[&actor, &id, &profile],
            Some(ReceiptCommand {
                family: "F11",
                command: "guest_profile_apply",
            }),
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

pub async fn transfer(
    factory: &TxFactory,
    proof: &AdminPermissionProof,
    id: i64,
    sponsor: i64,
    operation: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let payload = format!("{id}:{sponsor}");
    let env = envelope(
        proof.actor(),
        proof.generation(),
        operation,
        payload.as_bytes(),
    );
    factory
        .run_admin_audited_reducer_contract(
            proof,
            &env,
            deadline(),
            &sql::TRANSFER,
            &[&id, &sponsor],
            Some(ReceiptCommand {
                family: "F11",
                command: "guest_transfer",
            }),
            |rows, _| {
                rows.first()
                    .and_then(|r| r.try_get(0).ok())
                    .ok_or_else(invalid)
            },
        )
        .await
}

/// Global allowlist metadata is taken from the authenticated actor's row,
/// matching Go's separate read before the canonical one-statement mutation.
pub async fn set_domain(
    factory: &TxFactory,
    proof: &AdminPermissionProof,
    user: &UserPrincipal,
    domain: &str,
    remove: bool,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let actor = user.user().get();
    let (host, email) = if remove {
        (0, String::new())
    } else {
        let rows = match factory
            .run_admin_read_contract(proof, &sql::ACTOR_DOMAIN_EMAIL, &[&actor])
            .await
        {
            Ok(rows) => rows,
            Err(e) => return CommandOutcome::RolledBack(Rejection::Statement(e)),
        };
        let Some(row) = rows.first() else {
            return CommandOutcome::RolledBack(Rejection::Body(invalid()));
        };
        (row.get::<_, i64>(0), row.get::<_, String>(1))
    };
    let payload = format!("{domain}:{remove}");
    let env = envelope(
        user.user(),
        user.generation(),
        operation,
        payload.as_bytes(),
    );
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::SET_DOMAIN,
            &[&actor, &domain, &host, &email, &remove],
            Some(ReceiptCommand {
                family: "F11",
                command: "guest_invite_domain_set",
            }),
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

pub async fn console_denied(
    factory: &TxFactory,
    user: &UserPrincipal,
    path: &str,
    permission: &str,
    operation: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let before = serde_json::json!({
        "actor": user.audit_meta().email,
        "target": path,
        "missingPermission": permission
    })
    .to_string();
    let env = envelope(user.user(), user.generation(), operation, before.as_bytes());
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::CONSOLE_DENIED,
            &[&before, &path],
            Some(ReceiptCommand {
                family: "F11",
                command: "console.denied",
            }),
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

/// Go's preflight and canonical revoke share one wrapper transaction.
pub async fn revoke(
    factory: &TxFactory,
    proof: &AdminPermissionProof,
    id: i64,
    invite: i64,
    operation: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let payload = format!("{id}:{invite}");
    let env = envelope(
        proof.actor(),
        proof.generation(),
        operation,
        payload.as_bytes(),
    );
    factory
        .run_admin_audited_reducer_contract(
            proof,
            &env,
            deadline(),
            &sql::REVOKE_INVITE,
            &[&id, &invite],
            Some(ReceiptCommand {
                family: "F11",
                command: "guest_invite_revoke",
            }),
            |rows, _| {
                let result: String = rows
                    .first()
                    .and_then(|r| r.try_get(0).ok())
                    .ok_or_else(invalid)?;
                if result == "forbidden" {
                    return Err(StatementFailure {
                        sqlstate: None,
                        hint: None,
                        message: result,
                    });
                }
                Ok(result)
            },
        )
        .await
}

pub async fn submit(
    factory: &TxFactory,
    user: &UserPrincipal,
    email: &str,
    message: Option<&str>,
    operation: [u8; 16],
) -> CommandOutcome<Option<i64>, StatementFailure> {
    let actor = user.user().get();
    let payload = format!("{email}:{message:?}");
    let env = envelope(
        user.user(),
        user.generation(),
        operation,
        payload.as_bytes(),
    );
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::SUBMIT_INVITE_REQUEST,
            &[&actor, &email, &message],
            Some(ReceiptCommand {
                family: "F11",
                command: "guest_invite_request_create",
            }),
            |rows| {
                rows.first()
                    .and_then(|r| r.try_get(0).ok())
                    .ok_or_else(invalid)
            },
        )
        .await
}

/// Public metadata only. The raw credential is never a SQL value or receipt.
pub struct Prepared {
    pub guest: i64,
    pub invite: i64,
    pub expires: String,
    pub from: String,
    pub org: String,
    pub base: String,
    pub ttl: i64,
    pub email: String,
    pub status: Option<String>,
}

impl Prepared {
    pub fn decode(value: String) -> Result<Self, StatementFailure> {
        let v: serde_json::Value = serde_json::from_str(&value).map_err(|_| invalid())?;
        if v["blocked"] == true {
            return Err(StatementFailure {
                sqlstate: None,
                hint: None,
                message: "allowlist denied".into(),
            });
        }
        let status = v["status"].as_str().map(str::to_owned);
        if status.as_deref().is_some_and(|s| s != "applied") {
            return Ok(Self {
                guest: 0,
                invite: 0,
                expires: String::new(),
                from: String::new(),
                org: String::new(),
                base: String::new(),
                ttl: 0,
                email: String::new(),
                status,
            });
        }
        let text = |key| v[key].as_str().map(str::to_owned).ok_or_else(invalid);
        let result = Self {
            guest: v["guest"].as_i64().ok_or_else(invalid)?,
            invite: v["invite"].as_i64().ok_or_else(invalid)?,
            expires: text("expires")?,
            from: text("from")?,
            org: text("org")?,
            base: text("base")?,
            ttl: v["ttl"].as_i64().ok_or_else(invalid)?,
            email: text("email")?,
            status,
        };
        // Go validates both values inside Prepare, before the enclosing commit.
        let sender = mailparse::addrparse(&result.from).map_err(|_| invalid())?;
        if sender.len() != 1
            || !matches!(&sender[0], mailparse::MailAddr::Single(a) if a.addr == result.from && a.display_name.is_none())
            || result.from.bytes().any(|b| b < 32 || b == 127)
        {
            return Err(invalid());
        }
        let url = url::Url::parse(&result.base).map_err(|_| invalid())?;
        if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
            return Err(invalid());
        }
        Ok(result)
    }
}

pub enum Invitation<'a> {
    Create {
        email: &'a str,
        name: &'a str,
        expires: Option<&'a str>,
        profile: Option<i64>,
    },
    Reinvite {
        guest: i64,
        expires: Option<&'a str>,
    },
}

pub async fn invite(
    factory: &TxFactory,
    proof: &AdminPermissionProof,
    input: Invitation<'_>,
    hash: &str,
    operation: [u8; 16],
) -> CommandOutcome<Prepared, StatementFailure> {
    let env = envelope(
        proof.actor(),
        proof.generation(),
        operation,
        hash.as_bytes(),
    );
    match input {
        Invitation::Create {
            email,
            name,
            expires,
            profile,
        } => {
            factory
                .run_admin_audited_reducer_contract(
                    proof,
                    &env,
                    deadline(),
                    &sql::INVITE_CREATE,
                    &[&email, &name, &expires, &profile, &hash],
                    Some(ReceiptCommand {
                        family: "F11",
                        command: "guest_invite",
                    }),
                    |rows, _| {
                        Prepared::decode(
                            rows.first()
                                .and_then(|r| r.try_get(0).ok())
                                .ok_or_else(invalid)?,
                        )
                    },
                )
                .await
        }
        Invitation::Reinvite { guest, expires } => {
            factory
                .run_admin_audited_reducer_contract(
                    proof,
                    &env,
                    deadline(),
                    &sql::INVITE_REINVITE,
                    &[&guest, &expires, &hash],
                    Some(ReceiptCommand {
                        family: "F11",
                        command: "guest_reinvite",
                    }),
                    |rows, _| {
                        Prepared::decode(
                            rows.first()
                                .and_then(|r| r.try_get(0).ok())
                                .ok_or_else(invalid)?,
                        )
                    },
                )
                .await
        }
    }
}
