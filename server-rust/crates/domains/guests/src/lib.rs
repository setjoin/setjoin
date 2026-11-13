//! Guests (F11): verified actors and canonical reducer authority.
#![forbid(unsafe_code)]
use setjoin_authz::AuthContext;
use setjoin_contracts::ids::{ActorId, Generation, MailboxId};
use setjoin_pg::{MailboxAuthContext, ScopedExecutor, StatementFailure, Type};

pub fn scope(actor: &AuthContext) -> MailboxAuthContext {
    MailboxAuthContext::from_authenticated_session(
        ActorId::new(actor.user_id()).expect("verified user"),
        MailboxId::new(actor.mailbox_id()).expect("verified mailbox"),
        Generation(1),
    )
}
fn invalid() -> StatementFailure {
    StatementFailure {
        sqlstate: None,
        hint: None,
        message: "invalid guest result".into(),
    }
}
pub async fn enabled(exec: &ScopedExecutor) -> Result<bool, StatementFailure> {
    let rows = exec
        .read(
            "SELECT enabled FROM feature_toggles WHERE key='feature.guest_accounts'",
            &[],
        )
        .await?;
    Ok(rows.first().is_some_and(|r| r.get(0)))
}
pub async fn allowed(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    write: bool,
) -> Result<bool, StatementFailure> {
    if !actor.signed_admin() {
        return Ok(actor
            .signed_permissions()
            .iter()
            .any(|p| p == "guests.manage" || (!write && p == "guests.view")));
    }
    let user = actor.user_id();
    let rows=exec.read("SELECT guest_admin_has_live_permission($1,'guests.manage') OR (NOT $2 AND guest_admin_has_live_permission($1,'guests.view'))",&[(&user,Type::INT8),(&write,Type::BOOL)]).await?;
    Ok(rows.first().is_some_and(|r| r.get(0)))
}
pub async fn profiles(
    exec: &ScopedExecutor,
    actor: &AuthContext,
) -> Result<String, StatementFailure> {
    let user = actor.user_id();
    let rows = exec
        .read_scoped(
            &scope(actor),
            "SELECT guest_profile_list($1)::text",
            &[(&user, Type::INT8)],
        )
        .await?;
    rows.first()
        .and_then(|r| r.try_get(0).ok())
        .ok_or_else(invalid)
}
pub async fn profile(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    id: i64,
) -> Result<String, StatementFailure> {
    let user = actor.user_id();
    let rows = exec
        .read_scoped(
            &scope(actor),
            "SELECT guest_profile_get($1,$2)::text",
            &[(&user, Type::INT8), (&id, Type::INT8)],
        )
        .await?;
    rows.first()
        .and_then(|r| r.try_get(0).ok())
        .ok_or_else(invalid)
}
pub async fn profile_domains(
    exec: &ScopedExecutor,
    actor: &AuthContext,
) -> Result<String, StatementFailure> {
    let user = actor.user_id();
    let rows = exec
        .read_scoped(
            &scope(actor),
            "SELECT guest_profile_domain_list($1)::text",
            &[(&user, Type::INT8)],
        )
        .await?;
    rows.first()
        .and_then(|r| r.try_get(0).ok())
        .ok_or_else(invalid)
}

/// One receipted reducer call mirrors Go's entire save/read transaction.
pub async fn save_profile(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    id: Option<i64>,
    body: &str,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<String, StatementFailure> {
    use setjoin_contracts::{
        command::CommandEnvelope,
        ids::{Digest, OperationId},
    };
    use sha2::{Digest as _, Sha256};
    let auth = scope(actor);
    let envelope = CommandEnvelope {
        operation: OperationId(operation),
        authority: auth.authority(),
        binding: setjoin_db::lifecycle::accepted_contract(),
        payload_digest: Digest(Sha256::digest(body.as_bytes()).into()),
        command: (),
    };
    setjoin_pg::run_receipted_command(exec,setjoin_pg::ReceiptCommand{family:"F11",command:"guest_profile_save"},&envelope,&auth,std::time::Instant::now()+std::time::Duration::from_secs(30),"SELECT rust_guest_profile_save($2,$4,$5::text::jsonb)::text WHERE $1::bigint>0 AND $3::text<>''",&[(&id,Type::INT8),(&body,Type::TEXT)],|rows|rows.first().and_then(|r|r.try_get(0).ok()).ok_or_else(invalid)).await
}

pub async fn delete_profile(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    id: i64,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<(), StatementFailure> {
    use setjoin_contracts::{
        command::CommandEnvelope,
        ids::{Digest, OperationId},
    };
    use sha2::{Digest as _, Sha256};
    let auth = scope(actor);
    let envelope = CommandEnvelope {
        operation: OperationId(operation),
        authority: auth.authority(),
        binding: setjoin_db::lifecycle::accepted_contract(),
        payload_digest: Digest(Sha256::digest(id.to_be_bytes()).into()),
        command: (),
    };
    setjoin_pg::run_receipted_command(
        exec,
        setjoin_pg::ReceiptCommand {
            family: "F11",
            command: "guest_profile_delete",
        },
        &envelope,
        &auth,
        std::time::Instant::now() + std::time::Duration::from_secs(30),
        "SELECT guest_profile_delete($2,$4) WHERE $1::bigint>0 AND $3::text<>''",
        &[(&id, Type::INT8)],
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

/// BYPASSRLS read retains the canonical same-assignment live permission + host reach.
pub async fn list(exec: &ScopedExecutor, actor: &AuthContext) -> Result<String, StatementFailure> {
    let user = actor.user_id();
    let rows = exec
        .read_scoped(
            &scope(actor),
            include_str!("guest_list.sql"),
            &[(&user, Type::INT8)],
        )
        .await?;
    rows.first()
        .and_then(|r| r.try_get(0).ok())
        .ok_or_else(invalid)
}

pub async fn get(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    id: i64,
) -> Result<Option<String>, StatementFailure> {
    let user = actor.user_id();
    let rows = exec
        .read_scoped(
            &scope(actor),
            include_str!("guest_get.sql"),
            &[(&user, Type::INT8), (&id, Type::INT8)],
        )
        .await?;
    rows.first()
        .map(|r| r.try_get(0).map_err(|_| invalid()))
        .transpose()
}

pub async fn sponsors(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    id: i64,
    query: &str,
) -> Result<String, StatementFailure> {
    let user = actor.user_id();
    let rows = exec
        .read_scoped(
            &scope(actor),
            include_str!("sponsors.sql"),
            &[(&user, Type::INT8), (&id, Type::INT8), (&query, Type::TEXT)],
        )
        .await?;
    rows.first()
        .and_then(|r| r.try_get(0).ok())
        .ok_or_else(invalid)
}

/// Go's scoped prelock is not a separate mutation authority; the reducer repeats reach.
pub async fn set_status(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    id: i64,
    action: &str,
    expires: Option<&str>,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<(), StatementFailure> {
    use setjoin_contracts::{
        command::CommandEnvelope,
        ids::{Digest, OperationId},
    };
    use sha2::{Digest as _, Sha256};
    let auth = scope(actor);
    let envelope = CommandEnvelope {
        operation: OperationId(operation),
        authority: auth.authority(),
        binding: setjoin_db::lifecycle::accepted_contract(),
        payload_digest: Digest(Sha256::digest(format!("{id}:{action}:{expires:?}")).into()),
        command: (),
    };
    setjoin_pg::run_receipted_command(exec,setjoin_pg::ReceiptCommand{family:"F11",command:"guest_status"},&envelope,&auth,std::time::Instant::now()+std::time::Duration::from_secs(30),"SELECT rust_guest_status($2,$4,$5,$6::text::timestamptz) WHERE $1::bigint>0 AND $3::text<>''",&[(&id,Type::INT8),(&action,Type::TEXT),(&expires,Type::TEXT)],|rows|match rows.first().and_then(|r|r.try_get::<_,bool>(0).ok()){Some(true)=>Ok(()),Some(false)=>Err(StatementFailure{sqlstate:None,hint:None,message:"guest target not found".into()}),None=>Err(invalid())}).await
}

pub async fn assign_profile(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    id: i64,
    profile: Option<i64>,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<(), StatementFailure> {
    use setjoin_contracts::{
        command::CommandEnvelope,
        ids::{Digest, OperationId},
    };
    use sha2::{Digest as _, Sha256};
    let auth = scope(actor);
    let envelope = CommandEnvelope {
        operation: OperationId(operation),
        authority: auth.authority(),
        binding: setjoin_db::lifecycle::accepted_contract(),
        payload_digest: Digest(Sha256::digest(format!("{id}:{profile:?}")).into()),
        command: (),
    };
    setjoin_pg::run_receipted_command(
        exec,
        setjoin_pg::ReceiptCommand {
            family: "F11",
            command: "guest_profile_apply",
        },
        &envelope,
        &auth,
        std::time::Instant::now() + std::time::Duration::from_secs(30),
        "SELECT guest_profile_apply($2,$4,$5) WHERE $1::bigint>0 AND $3::text<>''",
        &[(&id, Type::INT8), (&profile, Type::INT8)],
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
    exec: &ScopedExecutor,
    actor: &AuthContext,
    id: i64,
    sponsor: i64,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<String, StatementFailure> {
    use setjoin_contracts::{
        command::CommandEnvelope,
        ids::{Digest, OperationId},
    };
    use sha2::{Digest as _, Sha256};
    let auth = scope(actor);
    let envelope = CommandEnvelope {
        operation: OperationId(operation),
        authority: auth.authority(),
        binding: setjoin_db::lifecycle::accepted_contract(),
        payload_digest: Digest(Sha256::digest(format!("{id}:{sponsor}")).into()),
        command: (),
    };
    setjoin_pg::run_receipted_command(
        exec,
        setjoin_pg::ReceiptCommand {
            family: "F11",
            command: "guest_transfer",
        },
        &envelope,
        &auth,
        std::time::Instant::now() + std::time::Duration::from_secs(30),
        "SELECT guest_transfer($2,$4,$5)::text WHERE $1::bigint>0 AND $3::text<>''",
        &[(&id, Type::INT8), (&sponsor, Type::INT8)],
        |rows| {
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
    exec: &ScopedExecutor,
    actor: &AuthContext,
    domain: &str,
    remove: bool,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<(), StatementFailure> {
    use setjoin_contracts::{
        command::CommandEnvelope,
        ids::{Digest, OperationId},
    };
    use sha2::{Digest as _, Sha256};
    let auth = scope(actor);
    let user = actor.user_id();
    let (host, email) = if remove {
        (0, String::new())
    } else {
        let rows = match exec
            .read_scoped(
                &auth,
                "SELECT domain_id,email FROM users WHERE id=$1",
                &[(&user, Type::INT8)],
            )
            .await
        {
            Ok(rows) => rows,
            Err(e) => {
                return setjoin_pg::CommandOutcome::RolledBack(setjoin_pg::Rejection::Statement(e))
            }
        };
        let Some(row) = rows.first() else {
            return setjoin_pg::CommandOutcome::RolledBack(setjoin_pg::Rejection::Body(invalid()));
        };
        (row.get::<_, i64>(0), row.get::<_, String>(1))
    };
    let envelope = CommandEnvelope {
        operation: OperationId(operation),
        authority: auth.authority(),
        binding: setjoin_db::lifecycle::accepted_contract(),
        payload_digest: Digest(Sha256::digest(format!("{domain}:{remove}")).into()),
        command: (),
    };
    setjoin_pg::run_receipted_command(
        exec,
        setjoin_pg::ReceiptCommand {
            family: "F11",
            command: "guest_invite_domain_set",
        },
        &envelope,
        &auth,
        std::time::Instant::now() + std::time::Duration::from_secs(30),
        "SELECT guest_invite_domain_set($2,$4,$5,$6,$7) WHERE $1::bigint>0 AND $3::text<>''",
        &[
            (&domain, Type::TEXT),
            (&host, Type::INT8),
            (&email, Type::TEXT),
            (&remove, Type::BOOL),
        ],
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
    exec: &ScopedExecutor,
    actor: &AuthContext,
    path: &str,
    permission: &str,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<(), StatementFailure> {
    use setjoin_contracts::{
        command::CommandEnvelope,
        ids::{Digest, OperationId},
    };
    use sha2::{Digest as _, Sha256};
    let before =
        serde_json::json!({"actor":actor.email(),"target":path,"missingPermission":permission})
            .to_string();
    let auth = scope(actor);
    let envelope = CommandEnvelope {
        operation: OperationId(operation),
        authority: auth.authority(),
        binding: setjoin_db::lifecycle::accepted_contract(),
        payload_digest: Digest(Sha256::digest(before.as_bytes()).into()),
        command: (),
    };
    setjoin_pg::run_receipted_command(exec,setjoin_pg::ReceiptCommand{family:"F11",command:"console.denied"},&envelope,&auth,std::time::Instant::now()+std::time::Duration::from_secs(30),
 "SELECT audit_write(NULL,'console.denied','console',NULL,$4::text::jsonb,NULL,NULL,$5,'core') WHERE $1::bigint>0 AND $2::bigint>0 AND $3::text<>''",&[(&before,Type::TEXT),(&path,Type::TEXT)],|rows|if rows.len()==1{Ok(())}else{Err(invalid())}).await
}

/// Go's preflight and canonical revoke share one wrapper transaction.
pub async fn revoke(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    id: i64,
    invite: i64,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<String, StatementFailure> {
    use setjoin_contracts::{
        command::CommandEnvelope,
        ids::{Digest, OperationId},
    };
    use sha2::{Digest as _, Sha256};
    let auth = scope(actor);
    let envelope = CommandEnvelope {
        operation: OperationId(operation),
        authority: auth.authority(),
        binding: setjoin_db::lifecycle::accepted_contract(),
        payload_digest: Digest(Sha256::digest(format!("{id}:{invite}")).into()),
        command: (),
    };
    setjoin_pg::run_receipted_command(
        exec,
        setjoin_pg::ReceiptCommand {
            family: "F11",
            command: "guest_invite_revoke",
        },
        &envelope,
        &auth,
        std::time::Instant::now() + std::time::Duration::from_secs(30),
        "SELECT rust_guest_invite_revoke($2,$4,$5) WHERE $1::bigint>0 AND $3::text<>''",
        &[(&id, Type::INT8), (&invite, Type::INT8)],
        |rows| {
            let result: String = rows
                .first()
                .and_then(|r| r.try_get(0).ok())
                .ok_or_else(invalid)?;
            if result == "forbidden" {
                Err(StatementFailure {
                    sqlstate: None,
                    hint: None,
                    message: result,
                })
            } else {
                Ok(result)
            }
        },
    )
    .await
}

pub async fn approval_enabled(exec: &ScopedExecutor) -> Result<bool, StatementFailure> {
    Ok(exec
        .read(
            "SELECT enabled FROM feature_toggles WHERE key='approval.guest_invite'",
            &[],
        )
        .await?
        .first()
        .is_some_and(|r| r.get(0)))
}
pub async fn submit(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    email: &str,
    message: Option<&str>,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<Option<i64>, StatementFailure> {
    use setjoin_contracts::{
        command::CommandEnvelope,
        ids::{Digest, OperationId},
    };
    use sha2::{Digest as _, Sha256};
    let auth = scope(actor);
    let envelope = CommandEnvelope {
        operation: OperationId(operation),
        authority: auth.authority(),
        binding: setjoin_db::lifecycle::accepted_contract(),
        payload_digest: Digest(Sha256::digest(format!("{email}:{message:?}")).into()),
        command: (),
    };
    setjoin_pg::run_receipted_command(
        exec,
        setjoin_pg::ReceiptCommand {
            family: "F11",
            command: "guest_invite_request_create",
        },
        &envelope,
        &auth,
        std::time::Instant::now() + std::time::Duration::from_secs(30),
        "SELECT guest_invite_request_create($2,$4,$5) WHERE $1::bigint>0 AND $3::text<>''",
        &[(&email, Type::TEXT), (&message, Type::TEXT)],
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
    fn decode(value: String) -> Result<Self, StatementFailure> {
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
            || !matches!(&sender[0],mailparse::MailAddr::Single(a)if a.addr==result.from&&a.display_name.is_none())
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
    Approval {
        request: i64,
        decision: &'a str,
        comment: Option<&'a str>,
    },
}
pub async fn invite(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    input: Invitation<'_>,
    hash: &str,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<Prepared, StatementFailure> {
    use setjoin_contracts::{
        command::CommandEnvelope,
        ids::{Digest, OperationId},
    };
    use sha2::{Digest as _, Sha256};
    let auth = scope(actor);
    let envelope = CommandEnvelope {
        operation: OperationId(operation),
        authority: auth.authority(),
        binding: setjoin_db::lifecycle::accepted_contract(),
        payload_digest: Digest(Sha256::digest(hash.as_bytes()).into()),
        command: (),
    };
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let decode = |rows: &[setjoin_pg::Row]| {
        Prepared::decode(
            rows.first()
                .and_then(|r| r.try_get(0).ok())
                .ok_or_else(invalid)?,
        )
    };
    match input{
  Invitation::Create{email,name,expires,profile}=>setjoin_pg::run_receipted_command(exec,setjoin_pg::ReceiptCommand{family:"F11",command:"guest_invite"},&envelope,&auth,deadline,"SELECT rust_guest_invite($2,$4,$5,$6::text::timestamptz,$7,$8)::text WHERE $1::bigint>0 AND $3::text<>''",&[(&email,Type::TEXT),(&name,Type::TEXT),(&expires,Type::TEXT),(&profile,Type::INT8),(&hash,Type::TEXT)],decode).await,
  Invitation::Reinvite{guest,expires}=>setjoin_pg::run_receipted_command(exec,setjoin_pg::ReceiptCommand{family:"F11",command:"guest_reinvite"},&envelope,&auth,deadline,"SELECT rust_guest_reinvite($2,$4,$5::text::timestamptz,$6)::text WHERE $1::bigint>0 AND $3::text<>''",&[(&guest,Type::INT8),(&expires,Type::TEXT),(&hash,Type::TEXT)],decode).await,
  Invitation::Approval{request,decision,comment}=>setjoin_pg::run_receipted_command(exec,setjoin_pg::ReceiptCommand{family:"F10",command:"guest_invite_approval"},&envelope,&auth,deadline,"SELECT rust_guest_approval_decide($4,$2,$5,$6,$7)::text WHERE $1::bigint>0 AND $3::text<>''",&[(&request,Type::INT8),(&decision,Type::TEXT),(&comment,Type::TEXT),(&hash,Type::TEXT)],decode).await,
 }
}

/// Go's separately committed outbound queue insert, following successful storage.
pub async fn enqueue(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    message: &str,
    from: &str,
    to: &str,
    key: &str,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<(), StatementFailure> {
    use setjoin_contracts::{
        command::CommandEnvelope,
        ids::{Digest, OperationId},
    };
    use sha2::{Digest as _, Sha256};
    let auth = scope(actor);
    let envelope = CommandEnvelope {
        operation: OperationId(operation),
        authority: auth.authority(),
        binding: setjoin_db::lifecycle::accepted_contract(),
        payload_digest: Digest(Sha256::digest(key.as_bytes()).into()),
        command: (),
    };
    setjoin_pg::run_receipted_command(exec,setjoin_pg::ReceiptCommand{family:"F11",command:"guest_invite_enqueue"},&envelope,&auth,std::time::Instant::now()+std::time::Duration::from_secs(30),"INSERT INTO outbound_queue(message_id,from_addr,rcpt_addrs,raw_ref,status) SELECT $4,$5,ARRAY[$6],$7,'pending' WHERE $1::bigint>0 AND $2::bigint>0 AND $3::text<>'' RETURNING id",&[(&message,Type::TEXT),(&from,Type::TEXT),(&to,Type::TEXT),(&key,Type::TEXT)],|rows|if rows.len()==1{Ok(())}else{Err(invalid())}).await
}
