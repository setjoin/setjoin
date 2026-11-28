//! Exchange assessment control plane (#294). Capability-gated admin reads and
//! audited reducer calls; HTTP authentication and live grants precede these
//! adapters.
use super::{command, deadline, envelope, invalid, sql};
use setjoin_authz::principals::{AdminPermissionProof, TxFactory, UserPrincipal};
use setjoin_pg::{CommandOutcome, StatementFailure};

pub async fn registry(
    factory: &TxFactory,
    proof: &AdminPermissionProof,
) -> Result<String, StatementFailure> {
    let rows = factory
        .run_admin_read_contract(proof, &sql::EXCHANGE_REGISTRY, &[])
        .await?;
    rows.first()
        .and_then(|r| r.try_get::<_, String>(0).ok())
        .ok_or_else(invalid)
}

/// Go's ListProjects: live domain scope, 500 rows, map keys sorted by encoding/json.
pub async fn projects(
    factory: &TxFactory,
    proof: &AdminPermissionProof,
    domain: i64,
) -> Result<String, StatementFailure> {
    let rows = factory
        .run_admin_read_contract(proof, &sql::EXCHANGE_PROJECTS, &[&domain])
        .await?;
    let values: Result<Vec<serde_json::Value>, _> = rows
        .iter()
        .map(|r| serde_json::from_str(&r.get::<_, String>(0)))
        .collect();
    serde_json::to_string(&values.map_err(|_| invalid())?).map_err(|_| invalid())
}

pub async fn runs(
    factory: &TxFactory,
    proof: &AdminPermissionProof,
    project: i64,
    domain: i64,
) -> Result<String, StatementFailure> {
    let rows = factory
        .run_admin_read_contract(proof, &sql::EXCHANGE_RUNS, &[&project, &domain])
        .await?;
    let values: Result<Vec<serde_json::Value>, _> = rows
        .iter()
        .map(|r| serde_json::from_str(&r.get::<_, String>(0)))
        .collect();
    serde_json::to_string(&values.map_err(|_| invalid())?).map_err(|_| invalid())
}

/// Existing Go reducer, same transaction plus the shared operation receipt.
#[allow(clippy::too_many_arguments)]
pub async fn create_project(
    factory: &TxFactory,
    proof: &AdminPermissionProof,
    key: &str,
    digest: &str,
    domain: i64,
    name: &str,
    retention: Option<&str>,
    operation: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let env = envelope(proof.actor(), proof.generation(), operation, digest);
    factory
        .run_admin_audited_reducer_contract(
            proof,
            &env,
            deadline(),
            &sql::EXCHANGE_CREATE_PROJECT,
            &[&key, &digest, &domain, &name, &retention],
            Some(command("exchange.project.create")),
            |rows, _| {
                rows.first()
                    .and_then(|r| r.try_get::<_, String>(0).ok())
                    .ok_or_else(invalid)
            },
        )
        .await
}

pub struct CreateRun<'a> {
    pub project: i64,
    pub key: &'a str,
    pub digest: &'a str,
    pub cell: &'a str,
    pub cell_digest: &'a str,
    pub registry: i64,
    pub registry_digest: &'a str,
    pub catalog: i64,
    pub collector: &'a str,
}

pub async fn create_run(
    factory: &TxFactory,
    proof: &AdminPermissionProof,
    r: &CreateRun<'_>,
    operation: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let env = envelope(proof.actor(), proof.generation(), operation, r.digest);
    factory
        .run_admin_audited_reducer_contract(
            proof,
            &env,
            deadline(),
            &sql::EXCHANGE_CREATE_RUN,
            &[
                &r.key,
                &r.digest,
                &r.project,
                &r.cell,
                &r.cell_digest,
                &r.registry,
                &r.registry_digest,
                &r.catalog,
                &r.collector,
            ],
            Some(command("exchange.run.create")),
            |rows, _| {
                rows.first()
                    .and_then(|r| r.try_get::<_, String>(0).ok())
                    .ok_or_else(invalid)
            },
        )
        .await
}

pub async fn transition(
    factory: &TxFactory,
    proof: &AdminPermissionProof,
    run: i64,
    generation: i64,
    state: &str,
    error: Option<&str>,
    operation: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let env = envelope(
        proof.actor(),
        proof.generation(),
        operation,
        &format!("{run}:{generation}:{state}:{error:?}"),
    );
    factory
        .run_admin_audited_reducer_contract(
            proof,
            &env,
            deadline(),
            &sql::EXCHANGE_TRANSITION,
            &[&run, &generation, &state, &error],
            Some(command("exchange.run.transition")),
            |rows, _| {
                rows.first()
                    .and_then(|r| r.try_get::<_, String>(0).ok())
                    .ok_or_else(invalid)
            },
        )
        .await
}

pub async fn attest(
    factory: &TxFactory,
    proof: &AdminPermissionProof,
    run: i64,
    kind: &str,
    digest: &str,
    statement: Option<&str>,
    operation: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let env = envelope(
        proof.actor(),
        proof.generation(),
        operation,
        &format!("{run}:{kind}:{digest}:{statement:?}"),
    );
    factory
        .run_admin_audited_reducer_contract(
            proof,
            &env,
            deadline(),
            &sql::EXCHANGE_ATTEST,
            &[&run, &kind, &digest, &statement],
            Some(command("exchange.attestation.create")),
            |rows, _| {
                rows.first()
                    .and_then(|r| r.try_get::<_, String>(0).ok())
                    .ok_or_else(invalid)
            },
        )
        .await
}

pub struct Decision<'a> {
    pub run: i64,
    pub generation: i64,
    pub capability: &'a str,
    pub mapping: &'a str,
    pub decision: &'a str,
    pub reason: &'a str,
    pub expires: Option<&'a str>,
}

pub async fn decide(
    factory: &TxFactory,
    proof: &AdminPermissionProof,
    d: &Decision<'_>,
    operation: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let env = envelope(
        proof.actor(),
        proof.generation(),
        operation,
        &format!(
            "{}:{}:{}:{}:{}:{}:{:?}",
            d.run, d.generation, d.capability, d.mapping, d.decision, d.reason, d.expires
        ),
    );
    factory
        .run_admin_audited_reducer_contract(
            proof,
            &env,
            deadline(),
            &sql::EXCHANGE_DECIDE,
            &[
                &d.run,
                &d.generation,
                &d.capability,
                &d.mapping,
                &d.decision,
                &d.reason,
                &d.expires,
            ],
            Some(command("exchange.decision.set")),
            |rows, _| {
                rows.first()
                    .and_then(|r| r.try_get::<_, String>(0).ok())
                    .ok_or_else(invalid)
            },
        )
        .await
}

pub async fn resolve(
    factory: &TxFactory,
    proof: &AdminPermissionProof,
    run: i64,
    generation: i64,
    operation: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let env = envelope(
        proof.actor(),
        proof.generation(),
        operation,
        &format!("{run}:{generation}"),
    );
    factory
        .run_admin_audited_reducer_contract(
            proof,
            &env,
            deadline(),
            &sql::EXCHANGE_RESOLVE,
            &[&run, &generation],
            Some(command("exchange.claim.resolve")),
            |rows, _| {
                rows.first()
                    .and_then(|r| r.try_get::<_, String>(0).ok())
                    .ok_or_else(invalid)
            },
        )
        .await
}

pub struct Deletion<'a> {
    pub project: i64,
    pub scope: &'a str,
    pub run: Option<i64>,
    pub artifact: Option<i64>,
    pub reason: &'a str,
}

pub async fn request_deletion(
    factory: &TxFactory,
    proof: &AdminPermissionProof,
    d: &Deletion<'_>,
    operation: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let env = envelope(
        proof.actor(),
        proof.generation(),
        operation,
        &format!(
            "{}:{}:{:?}:{:?}:{}",
            d.project, d.scope, d.run, d.artifact, d.reason
        ),
    );
    factory
        .run_admin_audited_reducer_contract(
            proof,
            &env,
            deadline(),
            &sql::EXCHANGE_REQUEST_DELETION,
            &[&d.project, &d.scope, &d.run, &d.artifact, &d.reason],
            Some(command("exchange.delete.request")),
            |rows, _| {
                rows.first()
                    .and_then(|r| r.try_get::<_, String>(0).ok())
                    .ok_or_else(invalid)
            },
        )
        .await
}

pub async fn audit(
    factory: &TxFactory,
    proof: &AdminPermissionProof,
    run: i64,
    domain: i64,
) -> Result<String, StatementFailure> {
    let rows = factory
        .run_admin_read_contract(proof, &sql::EXCHANGE_AUDIT, &[&run, &domain])
        .await?;
    rows.first()
        .and_then(|r| r.try_get::<_, String>(0).ok())
        .ok_or_else(invalid)
}

/// Go's per-request RequireReason policy lookup fails open on a database error.
pub async fn reason_required(factory: &TxFactory) -> bool {
    factory
        .run_public_read_contract(&sql::EXCHANGE_REASON_REQUIRED, &[])
        .await
        .ok()
        .and_then(|rows| {
            rows.first()
                .and_then(|r| r.try_get::<_, Vec<String>>(0).ok())
        })
        .is_some_and(|areas| areas.iter().any(|a| a == "exchange"))
}

pub async fn missing_reason(
    factory: &TxFactory,
    user: &UserPrincipal,
    ip: &str,
    permission: &str,
    operation: [u8; 16],
) {
    let actor = user.user().get();
    let env = envelope(
        user.user(),
        user.generation(),
        operation,
        &format!("{ip}:{permission}"),
    );
    let _ = factory
        .run_user_write_contract_pipelined(
            user,
            &env,
            deadline(),
            &sql::EXCHANGE_MISSING_REASON,
            &[&actor, &ip, &permission],
            Some(command("exchange.reason_missing")),
            |rows| {
                if rows.len() == 1 {
                    Ok(())
                } else {
                    Err(invalid())
                }
            },
        )
        .await;
}

pub struct UploadContext {
    pub project: i64,
    pub domain: i64,
    pub retention: Option<String>,
    pub generation: i64,
    pub installation: String,
}

pub async fn upload_context(
    factory: &TxFactory,
    proof: &AdminPermissionProof,
    run: i64,
) -> Result<Option<UploadContext>, StatementFailure> {
    let actor = proof.actor().get();
    let rows = factory
        .run_admin_read_contract(proof, &sql::EXCHANGE_UPLOAD_CONTEXT, &[&run, &actor])
        .await?;
    Ok(rows.first().map(|r| UploadContext {
        project: r.get(0),
        domain: r.get(1),
        retention: r.get(2),
        generation: r.get(3),
        installation: r.get(4),
    }))
}

pub async fn bundle_replay(
    factory: &TxFactory,
    proof: &AdminPermissionProof,
    run: i64,
    sha: &str,
    generation: i64,
) -> Result<Option<String>, StatementFailure> {
    let rows = factory
        .run_admin_read_contract(
            proof,
            &sql::EXCHANGE_BUNDLE_REPLAY,
            &[&run, &sha, &generation],
        )
        .await?;
    Ok(rows.first().map(|r| r.get(0)))
}

pub struct BundleCommit<'a> {
    pub run: i64,
    pub generation: i64,
    pub sha: &'a str,
    pub key: &'a str,
    pub profile: &'a str,
    pub sealed: &'a super::exchange_artifact::Sealed,
    pub retention: Option<&'a str>,
}

pub async fn commit_bundle(
    factory: &TxFactory,
    proof: &AdminPermissionProof,
    b: &BundleCommit<'_>,
    operation: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let key_id = "db-encryption-key:v1";
    let env = envelope(
        proof.actor(),
        proof.generation(),
        operation,
        &format!("{}:{}:{}:{}", b.run, b.generation, b.sha, b.key),
    );
    factory
        .run_admin_audited_reducer_contract(
            proof,
            &env,
            deadline(),
            &sql::EXCHANGE_COMMIT_BUNDLE,
            &[
                &b.run,
                &b.generation,
                &b.sha,
                &b.key,
                &b.profile,
                &key_id,
                &b.sealed.ciphertext_size,
                &b.sealed.nonce,
                &b.sealed.wrapped_dek,
                &b.sealed.aad_sha256,
                &b.retention,
            ],
            Some(command("exchange.artifact.commit")),
            |rows, _| {
                rows.first()
                    .and_then(|r| r.try_get::<_, String>(0).ok())
                    .ok_or_else(invalid)
            },
        )
        .await
}

pub async fn publication_context(
    factory: &TxFactory,
    proof: &AdminPermissionProof,
    run: i64,
) -> Result<Option<UploadContext>, StatementFailure> {
    let actor = proof.actor().get();
    let rows = factory
        .run_admin_read_contract(proof, &sql::EXCHANGE_PUBLICATION_CONTEXT, &[&run, &actor])
        .await?;
    Ok(rows.first().map(|r| UploadContext {
        project: r.get(0),
        domain: r.get(1),
        retention: r.get(2),
        generation: r.get(3),
        installation: r.get(4),
    }))
}

pub async fn publication_replay(
    factory: &TxFactory,
    proof: &AdminPermissionProof,
    run: i64,
    digest: &str,
) -> Result<Option<String>, StatementFailure> {
    let rows = factory
        .run_admin_read_contract(proof, &sql::EXCHANGE_PUBLICATION_REPLAY, &[&run, &digest])
        .await?;
    Ok(rows.first().map(|r| r.get(0)))
}

pub async fn publish(
    factory: &TxFactory,
    proof: &AdminPermissionProof,
    b: &BundleCommit<'_>,
    digest: &str,
    receipt: &super::exchange_artifact::SignedReceipt,
    operation: [u8; 16],
) -> CommandOutcome<String, StatementFailure> {
    let key_id = "db-encryption-key:v1";
    let algorithm = "ed25519";
    let env = envelope(
        proof.actor(),
        proof.generation(),
        operation,
        &format!("{}:{digest}:{}", b.run, b.key),
    );
    factory
        .run_admin_audited_reducer_contract(
            proof,
            &env,
            deadline(),
            &sql::EXCHANGE_PUBLISH,
            &[
                &b.run,
                &digest,
                &b.sha,
                &b.key,
                &b.profile,
                &key_id,
                &b.sealed.ciphertext_size,
                &b.sealed.nonce,
                &b.sealed.wrapped_dek,
                &b.sealed.aad_sha256,
                &receipt.bytes,
                &algorithm,
                &receipt.key_id,
                &receipt.signature,
            ],
            Some(command("exchange.publication.create")),
            |rows, _| {
                rows.first()
                    .and_then(|r| r.try_get::<_, String>(0).ok())
                    .ok_or_else(invalid)
            },
        )
        .await
}
