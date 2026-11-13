//! Exchange assessment control plane (#294). Worker-credential reads and
//! reducer calls; HTTP authentication and live grants precede these adapters.
use super::invalid;
use setjoin_pg::{ScopedExecutor, StatementFailure};

pub async fn registry(worker: &ScopedExecutor) -> Result<String, StatementFailure> {
    let rows = worker.read("SELECT projection::text FROM exchange_registry_snapshots ORDER BY registry_version DESC LIMIT 1", &[]).await?;
    rows.first()
        .and_then(|r| r.try_get::<_, String>(0).ok())
        .ok_or_else(invalid)
}

/// Go's ListProjects: live domain scope, 500 rows, map keys sorted by encoding/json.
pub async fn projects(worker: &ScopedExecutor, domain: i64) -> Result<String, StatementFailure> {
    let created = super::nano("created_at");
    let updated = super::nano("updated_at");
    let retention = super::nano("retention_until");
    let sql=format!("SELECT jsonb_build_object('id',id,'domainId',domain_id,'name',name,'state',state,'retentionUntil',{retention},'createdBy',created_by,'createdAt',{created},'updatedAt',{updated})::text FROM exchange_assessment_projects WHERE ($1::bigint=0 OR domain_id=$1) AND state<>'deleted' ORDER BY updated_at DESC,id DESC LIMIT 500");
    let rows = worker
        .read(&sql, &[(&domain, setjoin_pg::Type::INT8)])
        .await?;
    let values: Result<Vec<serde_json::Value>, _> = rows
        .iter()
        .map(|r| serde_json::from_str(&r.get::<_, String>(0)))
        .collect();
    serde_json::to_string(&values.map_err(|_| invalid())?).map_err(|_| invalid())
}

pub async fn runs(
    worker: &ScopedExecutor,
    project: i64,
    domain: i64,
) -> Result<String, StatementFailure> {
    let created = super::nano("r.created_at");
    let updated = super::nano("r.updated_at");
    let completed = super::nano("r.completed_at");
    let sql=format!("SELECT jsonb_build_object('id',r.id,'projectId',r.project_id,'generation',r.generation,'state',r.state,'supportCellId',r.support_cell_id,'supportCellDigest',r.support_cell_digest,'registryVersion',r.registry_version,'registryDigest',r.registry_digest,'catalogVersion',r.catalog_version,'collectorVersion',r.collector_version,'errorCode',r.error_code,'createdAt',{created},'updatedAt',{updated},'completedAt',{completed})::text FROM exchange_assessment_runs r JOIN exchange_assessment_projects p ON p.id=r.project_id WHERE r.project_id=$1 AND ($2::bigint=0 OR p.domain_id=$2) ORDER BY r.id DESC LIMIT 500");
    let rows = worker
        .read(
            &sql,
            &[
                (&project, setjoin_pg::Type::INT8),
                (&domain, setjoin_pg::Type::INT8),
            ],
        )
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
    worker: &ScopedExecutor,
    actor: &setjoin_authz::AuthContext,
    key: &str,
    digest: &str,
    domain: i64,
    name: &str,
    retention: Option<&str>,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<String, StatementFailure> {
    let auth = super::scope(actor);
    setjoin_pg::run_receipted_command(worker,setjoin_pg::ReceiptCommand{family:super::FAMILY,command:"exchange.project.create"},&super::envelope(&auth,operation,digest),&auth,super::deadline(),
     "SELECT exchange_assessment_project_create_idempotent($2,$4::text::uuid,$5,$6,$7,$8::text::timestamptz)::text WHERE $1::bigint>0 AND $3::text<>''",
     &[(&key,setjoin_pg::Type::TEXT),(&digest,setjoin_pg::Type::TEXT),(&domain,setjoin_pg::Type::INT8),(&name,setjoin_pg::Type::TEXT),(&retention,setjoin_pg::Type::TEXT)],
     |rows|rows.first().and_then(|r|r.try_get::<_,String>(0).ok()).ok_or_else(invalid)).await
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
    worker: &ScopedExecutor,
    actor: &setjoin_authz::AuthContext,
    r: &CreateRun<'_>,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<String, StatementFailure> {
    let auth = super::scope(actor);
    setjoin_pg::run_receipted_command(worker,setjoin_pg::ReceiptCommand{family:super::FAMILY,command:"exchange.run.create"},&super::envelope(&auth,operation,r.digest),&auth,super::deadline(),
 "SELECT exchange_assessment_run_create_idempotent($2,$5::text::uuid,$6,$4,$7,$8,$9::bigint::integer,$10,$11::bigint::integer,$12)::text WHERE $1::bigint>0 AND $3::text<>''",
 &[(&r.project,setjoin_pg::Type::INT8),(&r.key,setjoin_pg::Type::TEXT),(&r.digest,setjoin_pg::Type::TEXT),(&r.cell,setjoin_pg::Type::TEXT),(&r.cell_digest,setjoin_pg::Type::TEXT),(&r.registry,setjoin_pg::Type::INT8),(&r.registry_digest,setjoin_pg::Type::TEXT),(&r.catalog,setjoin_pg::Type::INT8),(&r.collector,setjoin_pg::Type::TEXT)],
 |rows|rows.first().and_then(|r|r.try_get::<_,String>(0).ok()).ok_or_else(invalid)).await
}

pub async fn transition(
    worker: &ScopedExecutor,
    actor: &setjoin_authz::AuthContext,
    run: i64,
    generation: i64,
    state: &str,
    error: Option<&str>,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<String, StatementFailure> {
    let auth = super::scope(actor);
    setjoin_pg::run_receipted_command(worker,setjoin_pg::ReceiptCommand{family:super::FAMILY,command:"exchange.run.transition"},&super::envelope(&auth,operation,&format!("{run}:{generation}:{state}:{error:?}")),&auth,super::deadline(),
 "SELECT exchange_assessment_run_transition($2,$4,$5,$6,$7)::text WHERE $1::bigint>0 AND $3::text<>''",
 &[(&run,setjoin_pg::Type::INT8),(&generation,setjoin_pg::Type::INT8),(&state,setjoin_pg::Type::TEXT),(&error,setjoin_pg::Type::TEXT)],
 |rows|rows.first().and_then(|r|r.try_get::<_,String>(0).ok()).ok_or_else(invalid)).await
}

pub async fn attest(
    worker: &ScopedExecutor,
    actor: &setjoin_authz::AuthContext,
    run: i64,
    kind: &str,
    digest: &str,
    statement: Option<&str>,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<String, StatementFailure> {
    let auth = super::scope(actor);
    setjoin_pg::run_receipted_command(worker,setjoin_pg::ReceiptCommand{family:super::FAMILY,command:"exchange.attestation.create"},&super::envelope(&auth,operation,&format!("{run}:{kind}:{digest}:{statement:?}")),&auth,super::deadline(),
 "SELECT exchange_assessment_attestation_create($2,$4,$5,$6,$7::text::jsonb)::text WHERE $1::bigint>0 AND $3::text<>''",
 &[(&run,setjoin_pg::Type::INT8),(&kind,setjoin_pg::Type::TEXT),(&digest,setjoin_pg::Type::TEXT),(&statement,setjoin_pg::Type::TEXT)],
 |rows|rows.first().and_then(|r|r.try_get::<_,String>(0).ok()).ok_or_else(invalid)).await
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
    worker: &ScopedExecutor,
    actor: &setjoin_authz::AuthContext,
    d: &Decision<'_>,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<String, StatementFailure> {
    let auth = super::scope(actor);
    setjoin_pg::run_receipted_command(worker,setjoin_pg::ReceiptCommand{family:super::FAMILY,command:"exchange.decision.set"},&super::envelope(&auth,operation,&format!("{}:{}:{}:{}:{}:{}:{:?}",d.run,d.generation,d.capability,d.mapping,d.decision,d.reason,d.expires)),&auth,super::deadline(),
 "SELECT exchange_assessment_decision_set($2,$4,$5,$6,$7,$8,$9,$10::text::timestamptz)::text WHERE $1::bigint>0 AND $3::text<>''",
 &[(&d.run,setjoin_pg::Type::INT8),(&d.generation,setjoin_pg::Type::INT8),(&d.capability,setjoin_pg::Type::TEXT),(&d.mapping,setjoin_pg::Type::TEXT),(&d.decision,setjoin_pg::Type::TEXT),(&d.reason,setjoin_pg::Type::TEXT),(&d.expires,setjoin_pg::Type::TEXT)],
 |rows|rows.first().and_then(|r|r.try_get::<_,String>(0).ok()).ok_or_else(invalid)).await
}

pub async fn resolve(
    worker: &ScopedExecutor,
    actor: &setjoin_authz::AuthContext,
    run: i64,
    generation: i64,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<String, StatementFailure> {
    let auth = super::scope(actor);
    setjoin_pg::run_receipted_command(worker,setjoin_pg::ReceiptCommand{family:super::FAMILY,command:"exchange.claim.resolve"},&super::envelope(&auth,operation,&format!("{run}:{generation}")),&auth,super::deadline(),
 "SELECT exchange_assessment_claim_resolve($2,$4,$5)::text WHERE $1::bigint>0 AND $3::text<>''",
 &[(&run,setjoin_pg::Type::INT8),(&generation,setjoin_pg::Type::INT8)],
 |rows|rows.first().and_then(|r|r.try_get::<_,String>(0).ok()).ok_or_else(invalid)).await
}

pub struct Deletion<'a> {
    pub project: i64,
    pub scope: &'a str,
    pub run: Option<i64>,
    pub artifact: Option<i64>,
    pub reason: &'a str,
}
pub async fn request_deletion(
    worker: &ScopedExecutor,
    actor: &setjoin_authz::AuthContext,
    d: &Deletion<'_>,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<String, StatementFailure> {
    let auth = super::scope(actor);
    setjoin_pg::run_receipted_command(worker,setjoin_pg::ReceiptCommand{family:super::FAMILY,command:"exchange.delete.request"},&super::envelope(&auth,operation,&format!("{}:{}:{:?}:{:?}:{}",d.project,d.scope,d.run,d.artifact,d.reason)),&auth,super::deadline(),
 "SELECT exchange_assessment_delete_request($2,$4,$5,$6,$7,$8)::text WHERE $1::bigint>0 AND $3::text<>''",
 &[(&d.project,setjoin_pg::Type::INT8),(&d.scope,setjoin_pg::Type::TEXT),(&d.run,setjoin_pg::Type::INT8),(&d.artifact,setjoin_pg::Type::INT8),(&d.reason,setjoin_pg::Type::TEXT)],
 |rows|rows.first().and_then(|r|r.try_get::<_,String>(0).ok()).ok_or_else(invalid)).await
}

pub async fn audit(
    worker: &ScopedExecutor,
    run: i64,
    domain: i64,
) -> Result<String, StatementFailure> {
    let rows=worker.read("SELECT jsonb_build_object(\
 'claims',COALESCE((SELECT jsonb_agg(to_jsonb(s) ORDER BY s.id DESC) FROM exchange_assessment_claim_snapshots s WHERE s.run_id=r.id),'[]'::jsonb),\
 'attestations',COALESCE((SELECT jsonb_agg(to_jsonb(a) ORDER BY a.id DESC) FROM exchange_assessment_attestations a WHERE a.run_id=r.id),'[]'::jsonb),\
 'evidence',COALESCE((SELECT jsonb_agg(to_jsonb(e) ORDER BY e.id DESC) FROM exchange_assessment_evidence e WHERE e.run_id=r.id),'[]'::jsonb),\
 'publications',COALESCE((SELECT jsonb_agg(to_jsonb(x) ORDER BY x.id DESC) FROM exchange_assessment_publications x WHERE x.run_id=r.id),'[]'::jsonb))::text \
 FROM exchange_assessment_runs r JOIN exchange_assessment_projects p ON p.id=r.project_id WHERE r.id=$1 AND ($2::bigint=0 OR p.domain_id=$2)", &[(&run,setjoin_pg::Type::INT8),(&domain,setjoin_pg::Type::INT8)]).await?;
    rows.first()
        .and_then(|r| r.try_get::<_, String>(0).ok())
        .ok_or_else(invalid)
}

/// Go's per-request RequireReason policy lookup fails open on a database error.
pub async fn reason_required(exec: &ScopedExecutor) -> bool {
    exec.read(
        "SELECT reason_required_areas FROM audit_policy WHERE id=1",
        &[],
    )
    .await
    .ok()
    .and_then(|rows| {
        rows.first()
            .and_then(|r| r.try_get::<_, Vec<String>>(0).ok())
    })
    .is_some_and(|areas| areas.iter().any(|a| a == "exchange"))
}
pub async fn missing_reason(
    exec: &ScopedExecutor,
    actor: &setjoin_authz::AuthContext,
    ip: &str,
    permission: &str,
    operation: [u8; 16],
) {
    let auth = super::scope(actor);
    let _=setjoin_pg::run_receipted_command(exec,setjoin_pg::ReceiptCommand{family:super::FAMILY,command:"exchange.reason_missing"},&super::envelope(&auth,operation,&format!("{ip}:{permission}")),&auth,super::deadline(),
 "SELECT audit_write($2,'sensitive_action.reason_missing','',NULL,NULL,NULL,NULLIF($4::text,'')::inet,$5,'core') WHERE $1::bigint>0 AND $3::text<>''",
 &[(&ip,setjoin_pg::Type::TEXT),(&permission,setjoin_pg::Type::TEXT)],|rows|if rows.len()==1{Ok(())}else{Err(invalid())}).await;
}

pub struct UploadContext {
    pub project: i64,
    pub domain: i64,
    pub retention: Option<String>,
    pub generation: i64,
    pub installation: String,
}
pub async fn upload_context(
    worker: &ScopedExecutor,
    actor: i64,
    run: i64,
) -> Result<Option<UploadContext>, StatementFailure> {
    let rows=worker.read("SELECT r.project_id,p.domain_id,p.retention_until::text,r.generation,u.installation_id::text FROM exchange_assessment_runs r JOIN exchange_assessment_projects p ON p.id=r.project_id JOIN upgrade_control_state u ON u.singleton WHERE r.id=$1 AND exchange_assessment_domain_authorized($2,p.domain_id,'exchange.assessment.run')",&[(&run,setjoin_pg::Type::INT8),(&actor,setjoin_pg::Type::INT8)]).await?;
    Ok(rows.first().map(|r| UploadContext {
        project: r.get(0),
        domain: r.get(1),
        retention: r.get(2),
        generation: r.get(3),
        installation: r.get(4),
    }))
}
pub async fn bundle_replay(
    worker: &ScopedExecutor,
    run: i64,
    sha: &str,
    generation: i64,
) -> Result<Option<String>, StatementFailure> {
    let rows=worker.read("SELECT (to_jsonb(a)||jsonb_build_object('replayed',true,'runGeneration',$3::bigint))::text FROM exchange_assessment_artifacts a WHERE a.run_id=$1 AND a.kind='bundle' AND a.sha256=$2",&[(&run,setjoin_pg::Type::INT8),(&sha,setjoin_pg::Type::TEXT),(&generation,setjoin_pg::Type::INT8)]).await?;
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
    worker: &ScopedExecutor,
    actor: &setjoin_authz::AuthContext,
    b: &BundleCommit<'_>,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<String, StatementFailure> {
    let auth = super::scope(actor);
    let key_id = "db-encryption-key:v1";
    setjoin_pg::run_receipted_command(worker,setjoin_pg::ReceiptCommand{family:super::FAMILY,command:"exchange.artifact.commit"},&super::envelope(&auth,operation,&format!("{}:{}:{}:{}",b.run,b.generation,b.sha,b.key)),&auth,super::deadline(),
 "SELECT exchange_assessment_artifact_commit($2,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14::text::timestamptz)::text WHERE $1::bigint>0 AND $3::text<>''",
 &[(&b.run,setjoin_pg::Type::INT8),(&b.generation,setjoin_pg::Type::INT8),(&b.sha,setjoin_pg::Type::TEXT),(&b.key,setjoin_pg::Type::TEXT),(&b.profile,setjoin_pg::Type::TEXT),(&key_id,setjoin_pg::Type::TEXT),(&b.sealed.ciphertext_size,setjoin_pg::Type::INT8),(&b.sealed.nonce,setjoin_pg::Type::BYTEA),(&b.sealed.wrapped_dek,setjoin_pg::Type::BYTEA),(&b.sealed.aad_sha256,setjoin_pg::Type::TEXT),(&b.retention,setjoin_pg::Type::TEXT)],
 |rows|rows.first().and_then(|r|r.try_get::<_,String>(0).ok()).ok_or_else(invalid)).await
}

pub async fn publication_context(
    worker: &ScopedExecutor,
    actor: i64,
    run: i64,
) -> Result<Option<UploadContext>, StatementFailure> {
    let rows=worker.read("SELECT r.project_id,p.domain_id,p.retention_until::text,r.generation,u.installation_id::text FROM exchange_assessment_runs r JOIN exchange_assessment_projects p ON p.id=r.project_id JOIN upgrade_control_state u ON u.singleton WHERE r.id=$1 AND exchange_assessment_domain_authorized($2,p.domain_id,'exchange.assessment.publish')",&[(&run,setjoin_pg::Type::INT8),(&actor,setjoin_pg::Type::INT8)]).await?;
    Ok(rows.first().map(|r| UploadContext {
        project: r.get(0),
        domain: r.get(1),
        retention: r.get(2),
        generation: r.get(3),
        installation: r.get(4),
    }))
}
pub async fn publication_replay(
    worker: &ScopedExecutor,
    run: i64,
    digest: &str,
) -> Result<Option<String>, StatementFailure> {
    let rows=worker.read("SELECT (to_jsonb(p)||'{\"replayed\":true}'::jsonb)::text FROM exchange_assessment_publications p WHERE p.run_id=$1 AND p.projection_digest=$2 AND p.revoked_at IS NULL",&[(&run,setjoin_pg::Type::INT8),(&digest,setjoin_pg::Type::TEXT)]).await?;
    Ok(rows.first().map(|r| r.get(0)))
}
pub async fn publish(
    worker: &ScopedExecutor,
    actor: &setjoin_authz::AuthContext,
    b: &BundleCommit<'_>,
    digest: &str,
    receipt: &super::exchange_artifact::SignedReceipt,
    operation: [u8; 16],
) -> setjoin_pg::CommandOutcome<String, StatementFailure> {
    let auth = super::scope(actor);
    let key_id = "db-encryption-key:v1";
    let algorithm = "ed25519";
    setjoin_pg::run_receipted_command(worker,setjoin_pg::ReceiptCommand{family:super::FAMILY,command:"exchange.publication.create"},&super::envelope(&auth,operation,&format!("{}:{digest}:{}",b.run,b.key)),&auth,super::deadline(),
 "SELECT exchange_assessment_publish_signed($2,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14::text::jsonb,$15,$16,$17)::text WHERE $1::bigint>0 AND $3::text<>''",
 &[(&b.run,setjoin_pg::Type::INT8),(&digest,setjoin_pg::Type::TEXT),(&b.sha,setjoin_pg::Type::TEXT),(&b.key,setjoin_pg::Type::TEXT),(&b.profile,setjoin_pg::Type::TEXT),(&key_id,setjoin_pg::Type::TEXT),(&b.sealed.ciphertext_size,setjoin_pg::Type::INT8),(&b.sealed.nonce,setjoin_pg::Type::BYTEA),(&b.sealed.wrapped_dek,setjoin_pg::Type::BYTEA),(&b.sealed.aad_sha256,setjoin_pg::Type::TEXT),(&receipt.bytes,setjoin_pg::Type::TEXT),(&algorithm,setjoin_pg::Type::TEXT),(&receipt.key_id,setjoin_pg::Type::TEXT),(&receipt.signature,setjoin_pg::Type::BYTEA)],
 |rows|rows.first().and_then(|r|r.try_get::<_,String>(0).ok()).ok_or_else(invalid)).await
}
