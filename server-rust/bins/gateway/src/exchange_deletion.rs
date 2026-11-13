//! Exchange active-store deletion: frozen Go's immediate then one-minute drain.
//! Already-authorized work is global and runs even with the feature toggle off.
use crate::recovery_worker::{ObjectStore, S3Store};
use serde::{Deserialize, Serialize};
use setjoin_mailboxes::exchange_artifact::{ReceiptSigner, ReceiptSubject};
use setjoin_pg::{workers::WorkerDatabase, Type};
use sha2::{Digest, Sha256};
use std::{future::Future, sync::Arc, time::Duration};
pub const NAME: &str = "exchange-assessment-deletion";
pub const INTERVAL: Duration = Duration::from_secs(60);
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct Artifact {
    id: i64,
    run_id: i64,
    object_key: String,
    sha256: String,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Subject<'a> {
    request_id: i64,
    project_id: i64,
    scope: &'a str,
    artifacts: &'a [Artifact],
}
pub struct DeletionWorker<S = S3Store> {
    db: WorkerDatabase,
    store: Arc<S>,
    signer: Arc<ReceiptSigner>,
}
impl<S: ObjectStore> DeletionWorker<S> {
    pub fn new(db: WorkerDatabase, store: Arc<S>, signer: Arc<ReceiptSigner>) -> Self {
        Self { db, store, signer }
    }
    pub async fn run_until(self, stop: impl Future<Output = ()> + Send) {
        let mut ticks = tokio::time::interval(INTERVAL);
        ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        tokio::pin!(stop);
        loop {
            tokio::select! {biased;_= &mut stop=>return,_=ticks.tick()=>{}}
            tokio::select! {biased;_= &mut stop=>return,_=self.tick()=>{}}
        }
    }
    /// One externally observable sweep. Failed items remain requested for retry.
    pub async fn tick(&self) {
        let conn = match self.db.connect_session().await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("exchange deletion: worker connection failed: {e}");
                return;
            }
        };
        let rows=match conn.query("SELECT d.id,d.project_id,p.domain_id,d.run_id,d.scope,u.installation_id::text, COALESCE(jsonb_agg(jsonb_build_object('id',a.id,'runId',a.run_id,'objectKey',a.object_key,'sha256',a.sha256) ORDER BY a.id) FILTER (WHERE a.id IS NOT NULL),'[]'::jsonb)::text FROM exchange_assessment_deletion_requests d JOIN exchange_assessment_projects p ON p.id=d.project_id JOIN upgrade_control_state u ON u.singleton LEFT JOIN exchange_assessment_runs r ON r.project_id=d.project_id LEFT JOIN exchange_assessment_artifacts a ON a.run_id=r.id AND ((d.scope='artifact' AND a.id=d.artifact_id) OR (d.scope='run' AND a.run_id=d.run_id) OR d.scope='project') WHERE d.state='requested' GROUP BY d.id,d.project_id,p.domain_id,d.run_id,d.scope,u.installation_id ORDER BY d.id LIMIT 20",&[]).await{Ok(r)=>r,Err(e)=>{eprintln!("exchange deletion: list failed: {e}");return;}};
        for row in rows {
            let decoded = (|| {
                Some((
                    row.try_get::<_, i64>(0).ok()?,
                    row.try_get::<_, i64>(1).ok()?,
                    row.try_get::<_, i64>(2).ok()?,
                    row.try_get::<_, String>(4).ok()?,
                    row.try_get::<_, String>(5).ok()?,
                    serde_json::from_str::<Vec<Artifact>>(&row.try_get::<_, String>(6).ok()?)
                        .ok()?,
                ))
            })();
            let Some((request, project, domain, scope, installation, artifacts)) = decoded else {
                eprintln!("exchange deletion: invalid work row");
                continue;
            };
            let mut failed = false;
            for artifact in &artifacts {
                if self.store.remove(&artifact.object_key).await.is_err() {
                    eprintln!(
                        "exchange deletion: object removal failed request={request} artifact={}",
                        artifact.id
                    );
                    failed = true;
                    break;
                }
            }
            if failed {
                continue;
            }
            let subject = Subject {
                request_id: request,
                project_id: project,
                scope: &scope,
                artifacts: &artifacts,
            };
            let Ok(raw) = serde_json::to_string(&subject) else {
                continue;
            };
            let raw = setjoin_mailboxes::go_escape(&raw);
            let sha = format!("{:x}", Sha256::digest(raw.as_bytes()));
            let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
            let Ok(receipt) = self.signer.sign(
                ReceiptSubject {
                    kind: "deletion",
                    sha256: &sha,
                    installation: &installation,
                    tenant: domain,
                    project,
                    disposition: "backup_expiry_pending",
                },
                &now,
            ) else {
                eprintln!("exchange deletion: receipt signing failed request={request}");
                continue;
            };
            let algorithm = "ed25519";
            if let Err(e) = conn
                .query(
                    "SELECT exchange_assessment_delete_finalize($1,$2,$3::text::jsonb,$4,$5,$6)",
                    &[
                        (&request, Type::INT8),
                        (&sha, Type::TEXT),
                        (&receipt.bytes, Type::TEXT),
                        (&algorithm, Type::TEXT),
                        (&receipt.key_id, Type::TEXT),
                        (&receipt.signature, Type::BYTEA),
                    ],
                )
                .await
            {
                eprintln!("exchange deletion: finalize failed request={request}: {e}");
            }
        }
    }
}
