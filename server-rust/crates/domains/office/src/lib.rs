//! Token-authenticated Office reducer boundary. No family dependencies.
#![forbid(unsafe_code)]
use serde_json::Value;
use setjoin_pg::{ScopedExecutor, StatementFailure, Type};
use sha2::{Digest, Sha256};
pub fn token_hash(token: &str) -> String {
    format!("{:x}", Sha256::digest(token))
}
/// The opaque launch bearer is the reducer's credential; a URL supplies only
/// the target file. The reducer repeats live membership, launch and fence checks.
pub async fn projection(
    exec: &ScopedExecutor,
    file: i64,
    token: &str,
) -> Result<Launch, StatementFailure> {
    let hash = token_hash(token);
    let rows = exec
        .read(
            "SELECT office_wopi_file_query($1,$2)::text",
            &[(&file, Type::INT8), (&hash, Type::TEXT)],
        )
        .await?;
    let raw: String = rows[0].get(0);
    serde_json::from_str(&raw)
        .map(Launch)
        .map_err(|_| StatementFailure {
            sqlstate: None,
            hint: None,
            message: "invalid Office projection".into(),
        })
}

pub fn token_hash_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// Immutable result of the credential-checking reducer. Only this module can
/// mint a launch authority; request JSON can never construct one.
pub struct Launch(Value);
impl std::ops::Deref for Launch {
    type Target = Value;
    fn deref(&self) -> &Value {
        &self.0
    }
}
fn invalid() -> StatementFailure {
    StatementFailure {
        sqlstate: None,
        hint: None,
        message: "invalid Office authority".into(),
    }
}
async fn launch_auth(
    exec: &ScopedExecutor,
    p: &Launch,
) -> Result<setjoin_pg::MailboxAuthContext, StatementFailure> {
    let actor = p["actorUserId"].as_i64().ok_or_else(invalid)?;
    let rows = exec
        .read(
            "SELECT id FROM mailboxes WHERE user_id=$1 AND is_primary",
            &[(&actor, Type::INT8)],
        )
        .await?;
    let mailbox: i64 = rows.first().ok_or_else(invalid)?.get(0);
    Ok(setjoin_pg::MailboxAuthContext::from_authenticated_session(
        setjoin_contracts::ids::ActorId::new(actor).map_err(|_| invalid())?,
        setjoin_contracts::ids::MailboxId::new(mailbox).map_err(|_| invalid())?,
        setjoin_contracts::ids::Generation(1),
    ))
}
fn envelope(
    auth: &setjoin_pg::MailboxAuthContext,
    operation: [u8; 16],
) -> setjoin_contracts::command::CommandEnvelope<()> {
    setjoin_contracts::command::CommandEnvelope {
        operation: setjoin_contracts::ids::OperationId(operation),
        authority: auth.authority(),
        binding: setjoin_db::lifecycle::accepted_contract(),
        payload_digest: setjoin_contracts::ids::Digest([0; 32]),
        command: (),
    }
}
fn decode(rows: &[setjoin_pg::Row]) -> Result<Value, StatementFailure> {
    let raw: String = rows.first().ok_or_else(invalid)?.get(0);
    serde_json::from_str(&raw).map_err(|_| invalid())
}
pub async fn lock(
    exec: &ScopedExecutor,
    p: &Launch,
    token: &str,
    operation: &str,
    value: &str,
    old: Option<&str>,
    id: [u8; 16],
) -> setjoin_pg::CommandOutcome<Value, StatementFailure> {
    let auth = match launch_auth(exec, p).await {
        Ok(a) => a,
        Err(e) => return setjoin_pg::CommandOutcome::RolledBack(setjoin_pg::Rejection::Body(e)),
    };
    let launch = p["launchId"].as_str().unwrap_or("");
    let hash = token_hash(token);
    setjoin_pg::run_receipted_command(exec,setjoin_pg::ReceiptCommand{family:"F15",command:"office_wopi_lock_apply"},&envelope(&auth,id),&auth,std::time::Instant::now()+std::time::Duration::from_secs(30),
 "SELECT office_wopi_lock_apply($4::text::uuid,$5,$6,$7,$8,1800)::text WHERE $1::bigint>0 AND $2::bigint>0 AND $3::text IS NOT NULL",
 &[(&launch,Type::TEXT),(&hash,Type::TEXT),(&operation,Type::TEXT),(&value,Type::TEXT),(&old,Type::TEXT)],decode).await
}

/// Match Go's chunk transaction: authorize and lock, promote, register through
/// the existing reducer, then commit. No canonical compensation after Unknown.
pub async fn commit_chunk<F, Fut>(
    exec: &ScopedExecutor,
    p: &Launch,
    sha: &str,
    size: i32,
    id: [u8; 16],
    promote: F,
) -> setjoin_pg::CommandOutcome<(), StatementFailure>
where
    F: FnOnce(String) -> Fut + Send,
    Fut: std::future::Future<Output = Result<(), StatementFailure>> + Send,
{
    let auth = match launch_auth(exec, p).await {
        Ok(a) => a,
        Err(e) => return setjoin_pg::CommandOutcome::RolledBack(setjoin_pg::Rejection::Body(e)),
    };
    let actor = auth.actor().get();
    let space = p["spaceId"].as_i64().unwrap_or(0);
    let node = p["fileNodeId"].as_i64().unwrap_or(0);
    let epoch = p["aclEpoch"].as_i64().unwrap_or(0);
    let acl = p["aclMode"] == "acl";
    setjoin_pg::command::run_receipted_effect(exec,setjoin_pg::ReceiptCommand{family:"F15",command:"drive_chunk_register"},&envelope(&auth,id),&auth,std::time::Instant::now()+std::time::Duration::from_secs(30),async move|tx:&mut setjoin_pg::ScopedTx|{
 let scope:String=if acl {
 let rows=tx.query("SELECT CASE WHEN s.classification='regular' THEN 'g' ELSE 's'||s.id END FROM drive_nodes n JOIN drive_spaces s ON s.id=n.space_id JOIN drive_acl_generations g ON g.space_id=s.id WHERE n.id=$3 AND n.space_id=$2 AND s.acl_mode='acl' AND g.epoch=$4 AND drive_runtime_has_node_capability($1,n.id,CASE WHEN n.kind='folder' THEN 'create_child' ELSE 'modify_content' END)",&[(&actor,Type::INT8),(&space,Type::INT8),(&node,Type::INT8),(&epoch,Type::INT8)]).await?;rows.first().ok_or_else(invalid)?.get(0)
 }else{tx.query("SELECT drive_chunk_upload_require($1,$2)",&[(&actor,Type::INT8),(&space,Type::INT8)]).await?[0].get(0)};
 tx.query("SELECT pg_advisory_xact_lock(hashtextextended('drive-chunk:'||$1||':'||$2,0))",&[(&scope,Type::TEXT),(&sha,Type::TEXT)]).await?;
 promote(format!("drive/{scope}/{sha}")).await?;
 if acl{tx.query("SELECT drive_chunk_register_bound($1,$2,$3,$4,$5,$6)",&[(&actor,Type::INT8),(&space,Type::INT8),(&node,Type::INT8),(&epoch,Type::INT8),(&sha,Type::TEXT),(&size,Type::INT4)]).await?;}else{tx.query("SELECT drive_chunk_register($1,$2,$3,$4)",&[(&actor,Type::INT8),(&space,Type::INT8),(&sha,Type::TEXT),(&size,Type::INT4)]).await?;}
 Ok(())
 }).await
}

pub async fn callback_allowed(
    exec: &ScopedExecutor,
    p: &Launch,
    token: &str,
) -> Result<bool, StatementFailure> {
    let launch = p["launchId"].as_str().unwrap_or("");
    let hash = token_hash(token);
    Ok(exec
        .read(
            "SELECT office_wopi_callback_allowed($1::text::uuid,$2,'modify_content')",
            &[(&launch, Type::TEXT), (&hash, Type::TEXT)],
        )
        .await?[0]
        .get(0))
}
pub struct Save<'a> {
    pub token: &'a str,
    pub key: &'a str,
    pub sha: &'a str,
    pub size: i64,
    pub manifest: &'a str,
    pub lock: Option<String>,
}
pub async fn save(
    exec: &ScopedExecutor,
    p: &Launch,
    s: Save<'_>,
    id: [u8; 16],
) -> setjoin_pg::CommandOutcome<Value, StatementFailure> {
    let auth = match launch_auth(exec, p).await {
        Ok(a) => a,
        Err(e) => return setjoin_pg::CommandOutcome::RolledBack(setjoin_pg::Rejection::Body(e)),
    };
    let launch = p["launchId"].as_str().unwrap_or("");
    let hash = token_hash(s.token);
    let base = p["versionId"].as_i64().unwrap_or(0);
    let content_type = p["contentType"].as_str();
    setjoin_pg::run_receipted_command(exec,setjoin_pg::ReceiptCommand{family:"F15",command:"office_save_accept"},&envelope(&auth,id),&auth,std::time::Instant::now()+std::time::Duration::from_secs(30),
 "SELECT office_save_accept($4::text::uuid,$5,$6,$7,$8,$9,$10,$11::text::jsonb,$12)::text WHERE $1::bigint>0 AND $2::bigint>0 AND $3::text IS NOT NULL",
 &[(&launch,Type::TEXT),(&hash,Type::TEXT),(&s.key,Type::TEXT),(&base,Type::INT8),(&s.sha,Type::TEXT),(&s.size,Type::INT8),(&content_type,Type::TEXT),(&s.manifest,Type::TEXT),(&s.lock,Type::TEXT)],decode).await
}

fn actor_auth(actor: &setjoin_authz::AuthContext) -> setjoin_pg::MailboxAuthContext {
    setjoin_pg::MailboxAuthContext::from_authenticated_session(
        setjoin_contracts::ids::ActorId::new(actor.user_id()).expect("verified actor"),
        setjoin_contracts::ids::MailboxId::new(actor.mailbox_id()).expect("verified mailbox"),
        setjoin_contracts::ids::Generation(1),
    )
}
pub struct Configure<'a> {
    pub provider: &'a str,
    pub generation: i64,
    pub profile: &'a str,
    pub entitlement: &'a str,
    pub build: Option<&'a str>,
    pub config: &'a str,
    pub reason: &'a str,
}
pub async fn configure(
    exec: &ScopedExecutor,
    actor: &setjoin_authz::AuthContext,
    p: Configure<'_>,
    id: [u8; 16],
) -> setjoin_pg::CommandOutcome<Value, StatementFailure> {
    let auth = actor_auth(actor);
    setjoin_pg::run_receipted_command(exec,setjoin_pg::ReceiptCommand{family:"F15",command:"office_provider_configure"},&envelope(&auth,id),&auth,std::time::Instant::now()+std::time::Duration::from_secs(30),
 "SELECT office_provider_configure($2,$4,$5,$6,$7,$8,$9::text::jsonb,$10)::text WHERE $1::bigint>0 AND $3::text IS NOT NULL",
 &[(&p.provider,Type::TEXT),(&p.generation,Type::INT8),(&p.profile,Type::TEXT),(&p.entitlement,Type::TEXT),(&p.build,Type::TEXT),(&p.config,Type::TEXT),(&p.reason,Type::TEXT)],decode).await
}

pub async fn activate(
    exec: &ScopedExecutor,
    actor: &setjoin_authz::AuthContext,
    provider: &str,
    generation: i64,
    qualification: &str,
    scope: &str,
    reason: &str,
    id: [u8; 16],
) -> setjoin_pg::CommandOutcome<Value, StatementFailure> {
    let auth = actor_auth(actor);
    setjoin_pg::run_receipted_command(exec,setjoin_pg::ReceiptCommand{family:"F15",command:"office_provider_activate"},&envelope(&auth,id),&auth,std::time::Instant::now()+std::time::Duration::from_secs(30),
 "SELECT office_provider_activate($2,$4,$5,$6::text::uuid,$7::text::jsonb,$8)::text WHERE $1::bigint>0 AND $3::text IS NOT NULL",
 &[(&provider,Type::TEXT),(&generation,Type::INT8),(&qualification,Type::TEXT),(&scope,Type::TEXT),(&reason,Type::TEXT)],decode).await
}
/// Google UUID Parse forms, including the zero UUID accepted by Go's admin edge.
pub fn uuid(raw: &str) -> Option<String> {
    if !raw.is_ascii() {
        return None;
    }
    let raw = if raw.len() == 45 && raw[..9].eq_ignore_ascii_case("urn:uuid:") {
        &raw[9..]
    } else if raw.len() == 38 {
        &raw[1..37]
    } else {
        raw
    };
    let hex = if raw.len() == 36 {
        if [8, 13, 18, 23].iter().any(|&i| raw.as_bytes()[i] != b'-') {
            return None;
        }
        raw.replace('-', "")
    } else if raw.len() == 32 {
        raw.to_owned()
    } else {
        return None;
    };
    if !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let h = hex.to_ascii_lowercase();
    Some(format!(
        "{}-{}-{}-{}-{}",
        &h[..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..]
    ))
}

pub async fn remove(
    exec: &ScopedExecutor,
    actor: &setjoin_authz::AuthContext,
    provider: &str,
    reason: &str,
    id: [u8; 16],
) -> setjoin_pg::CommandOutcome<Value, StatementFailure> {
    let auth = actor_auth(actor);
    setjoin_pg::run_receipted_command(
        exec,
        setjoin_pg::ReceiptCommand {
            family: "F15",
            command: "office_provider_remove",
        },
        &envelope(&auth, id),
        &auth,
        std::time::Instant::now() + std::time::Duration::from_secs(30),
        "SELECT office_provider_remove($2,$4,$5)::text WHERE $1::bigint>0 AND $3::text IS NOT NULL",
        &[(&provider, Type::TEXT), (&reason, Type::TEXT)],
        decode,
    )
    .await
}

/// The middleware's best-effort system audit is a separate committed write,
/// exactly as in Go. The caller has already verified the access token.
pub async fn console_denied(
    exec: &ScopedExecutor,
    actor: &setjoin_authz::AuthContext,
    before: &str,
    path: &str,
    id: [u8; 16],
) -> setjoin_pg::CommandOutcome<(), StatementFailure> {
    let auth = actor_auth(actor);
    setjoin_pg::run_receipted_command(exec,setjoin_pg::ReceiptCommand{family:"F15",command:"console.denied"},&envelope(&auth,id),&auth,std::time::Instant::now()+std::time::Duration::from_secs(30),
 "SELECT audit_write(NULL,'console.denied','console',NULL,$4::text::jsonb,NULL,NULL,$5,'core') WHERE $1::bigint>0 AND $2::bigint>0 AND $3::text IS NOT NULL",&[(&before,Type::TEXT),(&path,Type::TEXT)],|_|Ok(())).await
}

pub async fn qualification_target(
    exec: &ScopedExecutor,
    actor: &setjoin_authz::AuthContext,
    provider: &str,
    generation: i64,
) -> Result<Value, StatementFailure> {
    let user = actor.user_id();
    let rows = exec
        .read(
            "SELECT office_provider_qualification_target($1,$2,$3)::text",
            &[
                (&user, Type::INT8),
                (&provider, Type::TEXT),
                (&generation, Type::INT8),
            ],
        )
        .await?;
    decode(&rows)
}
pub struct Qualification<'a> {
    pub provider: &'a str,
    pub generation: i64,
    pub profile: &'a str,
    pub config_sha: &'a str,
    pub checks: &'a str,
    pub fingerprint: &'a str,
    pub build: Option<&'a str>,
    pub route_revision: i64,
    pub receipt: i64,
    pub reason: &'a str,
}
pub async fn qualify(
    exec: &ScopedExecutor,
    actor: &setjoin_authz::AuthContext,
    p: Qualification<'_>,
    id: [u8; 16],
) -> setjoin_pg::CommandOutcome<Value, StatementFailure> {
    let auth = actor_auth(actor);
    setjoin_pg::run_receipted_command(exec,setjoin_pg::ReceiptCommand{family:"F15",command:"office_provider_qualify"},&envelope(&auth,id),&auth,std::time::Instant::now()+std::time::Duration::from_secs(30),
 "SELECT office_provider_qualify($2,$4,$5,$6,$7,$8::text::jsonb,$9,$10,$11,$12,$13)::text WHERE $1::bigint>0 AND $3::text IS NOT NULL",
 &[(&p.provider,Type::TEXT),(&p.generation,Type::INT8),(&p.profile,Type::TEXT),(&p.config_sha,Type::TEXT),(&p.checks,Type::TEXT),(&p.fingerprint,Type::TEXT),(&p.build,Type::TEXT),(&p.route_revision,Type::INT8),(&p.receipt,Type::INT8),(&p.reason,Type::TEXT)],decode).await
}

pub async fn reason_missing(
    exec: &ScopedExecutor,
    actor: &setjoin_authz::AuthContext,
    ip: &str,
    id: [u8; 16],
) -> setjoin_pg::CommandOutcome<(), StatementFailure> {
    let auth = actor_auth(actor);
    setjoin_pg::run_receipted_command(exec,setjoin_pg::ReceiptCommand{family:"F15",command:"sensitive_action.reason_missing"},&envelope(&auth,id),&auth,std::time::Instant::now()+std::time::Duration::from_secs(30),
 "SELECT audit_write($2,'sensitive_action.reason_missing','',NULL,NULL,NULL,$4::text::inet,'office.manage','core') WHERE $1::bigint>0 AND $3::text IS NOT NULL",&[(&ip,Type::TEXT)],|_|Ok(())).await
}
