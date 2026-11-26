//! Token-authenticated Office reducer boundary. No family dependencies.
#![forbid(unsafe_code)]

pub mod sql;
pub use sql::SQL_CONTRACTS;

use serde_json::Value;
use setjoin_authz::principals::{AdminPermissionProof, TxFactory, UserPrincipal};
use setjoin_contracts::{
    authority::{AuthorityKey, ResourceScope},
    command::CommandEnvelope,
    ids::{ActorId, Digest, Generation, OperationId},
};
use setjoin_pg::{CommandOutcome, ReceiptCommand, Row, StatementFailure};
use sha2::{Digest as _, Sha256};

pub fn token_hash(token: &str) -> String {
    format!("{:x}", Sha256::digest(token))
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
impl Launch {
    pub fn actor_user_id(&self) -> Option<ActorId> {
        self.0["actorUserId"]
            .as_i64()
            .and_then(|id| ActorId::new(id).ok())
    }
}

fn invalid() -> StatementFailure {
    StatementFailure {
        sqlstate: None,
        hint: None,
        message: "invalid Office authority".into(),
    }
}

fn deadline() -> std::time::Instant {
    std::time::Instant::now() + std::time::Duration::from_secs(30)
}

fn user_envelope(
    actor: ActorId,
    generation: Generation,
    operation: [u8; 16],
) -> CommandEnvelope<()> {
    CommandEnvelope {
        operation: OperationId(operation),
        authority: AuthorityKey {
            actor,
            scope: ResourceScope::User(actor),
            generation,
        },
        binding: setjoin_db::lifecycle::accepted_contract(),
        payload_digest: Digest([0; 32]),
        command: (),
    }
}

fn decode(rows: &[Row]) -> Result<Value, StatementFailure> {
    let raw: String = rows.first().ok_or_else(invalid)?.get(0);
    serde_json::from_str(&raw).map_err(|_| invalid())
}

pub async fn wopi_enabled(factory: &TxFactory) -> Result<bool, StatementFailure> {
    let rows = factory
        .run_public_read_contract(&sql::WOPI_ENABLED, &[])
        .await?;
    Ok(rows.first().is_some_and(|r| r.get(0)))
}

/// The opaque launch bearer is the reducer's credential; a URL supplies only
/// the target file. The reducer repeats live membership, launch and fence checks.
pub async fn projection(
    factory: &TxFactory,
    file: i64,
    token: &str,
) -> Result<Launch, StatementFailure> {
    let hash = token_hash(token);
    let rows = factory
        .run_public_read_contract(&sql::WOPI_FILE_QUERY, &[&file, &hash])
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

pub async fn callback_allowed(
    factory: &TxFactory,
    p: &Launch,
    token: &str,
) -> Result<bool, StatementFailure> {
    let launch = p["launchId"].as_str().unwrap_or("");
    let hash = token_hash(token);
    Ok(factory
        .run_public_read_contract(&sql::WOPI_CALLBACK_ALLOWED, &[&launch, &hash])
        .await?[0]
        .get(0))
}

#[allow(clippy::too_many_arguments)]
pub async fn lock(
    factory: &TxFactory,
    user: &UserPrincipal,
    p: &Launch,
    token: &str,
    operation: &str,
    value: &str,
    old: Option<&str>,
    id: [u8; 16],
) -> CommandOutcome<Value, StatementFailure> {
    let launch = p["launchId"].as_str().unwrap_or("");
    let hash = token_hash(token);
    let env = user_envelope(user.user(), user.generation(), id);
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::WOPI_LOCK_APPLY,
            &[&launch, &hash, &operation, &value, &old],
            Some(ReceiptCommand {
                family: "F15",
                command: "office_wopi_lock_apply",
            }),
            |rows| decode(&rows),
        )
        .await
}

/// Match Go's chunk transaction: authorize and lock, promote, register through
/// the existing reducer, then commit. No canonical compensation after Unknown.
pub async fn commit_chunk<F, Fut>(
    factory: &TxFactory,
    user: &UserPrincipal,
    p: &Launch,
    sha: &str,
    size: i32,
    id: [u8; 16],
    promote: F,
) -> CommandOutcome<(), StatementFailure>
where
    F: FnOnce(String) -> Fut + Send,
    Fut: std::future::Future<Output = Result<(), StatementFailure>> + Send,
{
    let actor = user.user().get();
    let space = p["spaceId"].as_i64().unwrap_or(0);
    let node = p["fileNodeId"].as_i64().unwrap_or(0);
    let epoch = p["aclEpoch"].as_i64().unwrap_or(0);
    let acl = p["aclMode"] == "acl";
    let env = user_envelope(user.user(), user.generation(), id);
    factory
        .run_user_effect_write(
            user,
            ReceiptCommand {
                family: "F15",
                command: "drive_chunk_register",
            },
            &env,
            deadline(),
            async move |tx| {
                let scope: String = if acl {
                    let rows = tx
                        .query_contract(&sql::CHUNK_SCOPE_ACL, &[&actor, &space, &node, &epoch])
                        .await?;
                    rows.first().ok_or_else(invalid)?.get(0)
                } else {
                    tx.query_contract(&sql::CHUNK_UPLOAD_REQUIRE, &[&actor, &space])
                        .await?[0]
                        .get(0)
                };
                tx.query_contract(&sql::CHUNK_ADVISORY_LOCK, &[&scope, &sha])
                    .await?;
                promote(format!("drive/{scope}/{sha}")).await?;
                if acl {
                    tx.query_contract(
                        &sql::CHUNK_REGISTER_BOUND,
                        &[&actor, &space, &node, &epoch, &sha, &size],
                    )
                    .await?;
                } else {
                    tx.query_contract(&sql::CHUNK_REGISTER, &[&actor, &space, &sha, &size])
                        .await?;
                }
                Ok(())
            },
        )
        .await
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
    factory: &TxFactory,
    user: &UserPrincipal,
    p: &Launch,
    s: Save<'_>,
    id: [u8; 16],
) -> CommandOutcome<Value, StatementFailure> {
    let launch = p["launchId"].as_str().unwrap_or("");
    let hash = token_hash(s.token);
    let base = p["versionId"].as_i64().unwrap_or(0);
    let content_type = p["contentType"].as_str();
    let env = user_envelope(user.user(), user.generation(), id);
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::WOPI_SAVE_ACCEPT,
            &[
                &launch,
                &hash,
                &s.key,
                &base,
                &s.sha,
                &s.size,
                &content_type,
                &s.manifest,
                &s.lock,
            ],
            Some(ReceiptCommand {
                family: "F15",
                command: "office_save_accept",
            }),
            |rows| decode(&rows),
        )
        .await
}

pub async fn reason_required(
    factory: &TxFactory,
    proof: &AdminPermissionProof,
) -> Result<bool, StatementFailure> {
    let rows = factory
        .run_admin_read_contract(proof, &sql::ADMIN_REASON_REQUIRED, &[])
        .await?;
    Ok(rows.first().is_some_and(|r| r.get(0)))
}

pub async fn admin_list(
    factory: &TxFactory,
    proof: &AdminPermissionProof,
) -> Result<String, StatementFailure> {
    let user = proof.actor().get();
    let rows = factory
        .run_admin_read_contract(proof, &sql::ADMIN_LIST, &[&user])
        .await?;
    Ok(rows.first().ok_or_else(invalid)?.get(0))
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
    factory: &TxFactory,
    proof: &AdminPermissionProof,
    p: Configure<'_>,
    id: [u8; 16],
) -> CommandOutcome<Value, StatementFailure> {
    let env = user_envelope(proof.actor(), proof.generation(), id);
    factory
        .run_admin_audited_reducer_contract(
            proof,
            &env,
            deadline(),
            &sql::ADMIN_CONFIGURE,
            &[
                &p.provider,
                &p.generation,
                &p.profile,
                &p.entitlement,
                &p.build,
                &p.config,
                &p.reason,
            ],
            Some(ReceiptCommand {
                family: "F15",
                command: "office_provider_configure",
            }),
            |rows, _| decode(&rows),
        )
        .await
}

#[allow(clippy::too_many_arguments)]
pub async fn activate(
    factory: &TxFactory,
    proof: &AdminPermissionProof,
    provider: &str,
    generation: i64,
    qualification: &str,
    scope: &str,
    reason: &str,
    id: [u8; 16],
) -> CommandOutcome<Value, StatementFailure> {
    let env = user_envelope(proof.actor(), proof.generation(), id);
    factory
        .run_admin_audited_reducer_contract(
            proof,
            &env,
            deadline(),
            &sql::ADMIN_ACTIVATE,
            &[&provider, &generation, &qualification, &scope, &reason],
            Some(ReceiptCommand {
                family: "F15",
                command: "office_provider_activate",
            }),
            |rows, _| decode(&rows),
        )
        .await
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
    factory: &TxFactory,
    proof: &AdminPermissionProof,
    provider: &str,
    reason: &str,
    id: [u8; 16],
) -> CommandOutcome<Value, StatementFailure> {
    let env = user_envelope(proof.actor(), proof.generation(), id);
    factory
        .run_admin_audited_reducer_contract(
            proof,
            &env,
            deadline(),
            &sql::ADMIN_REMOVE,
            &[&provider, &reason],
            Some(ReceiptCommand {
                family: "F15",
                command: "office_provider_remove",
            }),
            |rows, _| decode(&rows),
        )
        .await
}

/// The middleware's best-effort system audit is a separate committed write,
/// exactly as in Go. The caller has already verified the access token.
pub async fn console_denied(
    factory: &TxFactory,
    user: &UserPrincipal,
    before: &str,
    path: &str,
    id: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let env = user_envelope(user.user(), user.generation(), id);
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::CONSOLE_DENIED,
            &[&before, &path],
            Some(ReceiptCommand {
                family: "F15",
                command: "console.denied",
            }),
            |_| Ok(()),
        )
        .await
}

pub async fn qualification_target(
    factory: &TxFactory,
    proof: &AdminPermissionProof,
    provider: &str,
    generation: i64,
) -> Result<Value, StatementFailure> {
    let user = proof.actor().get();
    let rows = factory
        .run_admin_read_contract(
            proof,
            &sql::ADMIN_QUALIFICATION_TARGET,
            &[&user, &provider, &generation],
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
    factory: &TxFactory,
    proof: &AdminPermissionProof,
    p: Qualification<'_>,
    id: [u8; 16],
) -> CommandOutcome<Value, StatementFailure> {
    let env = user_envelope(proof.actor(), proof.generation(), id);
    factory
        .run_admin_audited_reducer_contract(
            proof,
            &env,
            deadline(),
            &sql::ADMIN_QUALIFY,
            &[
                &p.provider,
                &p.generation,
                &p.profile,
                &p.config_sha,
                &p.checks,
                &p.fingerprint,
                &p.build,
                &p.route_revision,
                &p.receipt,
                &p.reason,
            ],
            Some(ReceiptCommand {
                family: "F15",
                command: "office_provider_qualify",
            }),
            |rows, _| decode(&rows),
        )
        .await
}

pub async fn reason_missing(
    factory: &TxFactory,
    user: &UserPrincipal,
    ip: &str,
    id: [u8; 16],
) -> CommandOutcome<(), StatementFailure> {
    let actor = user.user().get();
    let env = user_envelope(user.user(), user.generation(), id);
    factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::REASON_MISSING,
            &[&actor, &ip],
            Some(ReceiptCommand {
                family: "F15",
                command: "sensitive_action.reason_missing",
            }),
            |_| Ok(()),
        )
        .await
}
