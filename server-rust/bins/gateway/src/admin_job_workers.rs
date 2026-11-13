//! Admin identity job workers (#412): `bulk-role-jobs`, `email-address-policy-jobs`,
//! `identity-operations` and `identity-transitions`, ported from Go's
//! `bulkroles`, `eapjobs`, `identityops` and `identitytransition` packages.
//!
//! Every worker runs on the worker credential (`DB_WORKER_DSN`, BYPASSRLS after the
//! native-RLS flip) with the deployment audit keys set per session, as Go's
//! `workerPool`; every state change is a reducer or one of Go's own statements.
//! `tick` is the unit the oracle drives (one Go `Run` iteration); `run_until` adds
//! Go's timing. Go's copy must be off first (`GO_WORKERS_OFF=<name>`, #259).
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use setjoin_pg::workers::{WorkerConnection, WorkerDatabase};
use setjoin_pg::Type;
use std::collections::HashMap;
use std::future::Future;
use std::sync::Mutex;
use std::time::{Duration, Instant};

type Error = String;

/// A random version-4 UUID, as `uuid.New()`.
pub fn new_uuid() -> String {
    let mut b = [0u8; 16];
    getrandom::getrandom(&mut b).expect("os randomness");
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h: String = b.iter().map(|x| format!("{x:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

async fn begin(c: &WorkerConnection) -> Result<(), Error> {
    c.query("BEGIN", &[]).await.map(|_| ())
}
async fn commit(c: &WorkerConnection) -> Result<(), Error> {
    c.query("COMMIT", &[]).await.map(|_| ())
}
async fn rollback(c: &WorkerConnection) {
    let _ = c.query("ROLLBACK", &[]).await;
}

/// Go's ticker loop: wait `interval`, run `body`, until `stop` resolves. A tick
/// in flight is dropped (Go cancels its context) when `stop` wins.
async fn every<F, Fut>(
    interval: Duration,
    immediate: bool,
    stop: impl Future<Output = ()>,
    mut body: F,
) where
    F: FnMut() -> Fut,
    Fut: Future<Output = ()>,
{
    tokio::pin!(stop);
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ticker.tick().await;
    if immediate {
        tokio::select! { _ = &mut stop => return, _ = body() => {} }
    }
    loop {
        tokio::select! {
            _ = &mut stop => return,
            _ = ticker.tick() => {
                tokio::select! { _ = &mut stop => return, _ = body() => {} }
            }
        }
    }
}

// ---------------------------------------------------------------- bulk-role-jobs

/// `bulk-role-jobs` (Go `bulkroles.Worker`): claim, apply and settle in ONE
/// transaction so the row stays locked for the whole run.
pub struct BulkRoleJobs {
    pub db: WorkerDatabase,
}

impl BulkRoleJobs {
    pub const INTERVAL: Duration = Duration::from_secs(3);

    /// Startup reclaim of rows a crashed server left `running`.
    pub async fn reclaim(&self) -> Result<(), Error> {
        let c = self.db.connect_session().await.map_err(|e| e.to_string())?;
        c.query(
            "UPDATE bulk_role_jobs SET status='queued', updated_at=now() WHERE status='running'",
            &[],
        )
        .await
        .map(|_| ())
    }

    /// One Go ticker iteration: drain every queued job.
    pub async fn tick(&self) -> Result<(), Error> {
        let c = self.db.connect_session().await.map_err(|e| e.to_string())?;
        loop {
            match self.process_once(&c).await {
                Ok(true) => {}
                Ok(false) => return Ok(()),
                Err(error) => {
                    eprintln!("bulkroles: processOnce error: {error}");
                    return Err(error);
                }
            }
        }
    }

    async fn process_once(&self, c: &WorkerConnection) -> Result<bool, Error> {
        begin(c).await?;
        let claimed = self.claim_and_apply(c).await;
        let (id, applied) = match claimed {
            Ok(None) => {
                rollback(c).await;
                return Ok(false);
            }
            Ok(Some(found)) => found,
            Err(error) => {
                rollback(c).await;
                return Err(error);
            }
        };
        match applied {
            Ok(()) => {
                // The reducer may have set status='error'; only promote running to done.
                let finish = c
                    .query(
                        "UPDATE bulk_role_jobs SET status='done',updated_at=now() WHERE id=$1 AND status='running'",
                        &[(&id, Type::INT8)],
                    )
                    .await;
                if let Err(error) = finish {
                    rollback(c).await;
                    return Err(error);
                }
                commit(c).await?;
                Ok(true)
            }
            Err(error) => {
                // The failed statement left the transaction aborted: roll back (the
                // job returns to queued) and mark the failure terminal outside it.
                rollback(c).await;
                let text = format!("bulk_role_job_apply: {error}");
                if let Err(mark) = c
                    .query(
                        "UPDATE bulk_role_jobs SET status='error', updated_at=now(), error=$2 WHERE id=$1",
                        &[(&id, Type::INT8), (&text, Type::TEXT)],
                    )
                    .await
                {
                    eprintln!("bulkroles: failed to mark job error id={id}: {mark} (original {error})");
                }
                Err(text)
            }
        }
    }

    /// `Ok(None)` when the queue is empty; otherwise the job id and the reducer's outcome.
    async fn claim_and_apply(
        &self,
        c: &WorkerConnection,
    ) -> Result<Option<(i64, Result<(), Error>)>, Error> {
        let rows = c
            .query(
                "SELECT id FROM bulk_role_jobs WHERE status='queued' ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT 1",
                &[],
            )
            .await?;
        let Some(row) = rows.first() else {
            return Ok(None);
        };
        let id: i64 = row.get(0);
        c.query(
            "UPDATE bulk_role_jobs SET status='running',updated_at=now() WHERE id=$1",
            &[(&id, Type::INT8)],
        )
        .await?;
        let applied = c
            .query("SELECT bulk_role_job_apply($1)", &[(&id, Type::INT8)])
            .await
            .map(|_| ());
        Ok(Some((id, applied)))
    }

    pub async fn run_until(self: std::sync::Arc<Self>, stop: impl Future<Output = ()>) {
        eprintln!("bulkroles worker started interval={:?}", Self::INTERVAL);
        if let Err(error) = self.reclaim().await {
            eprintln!("bulkroles: failed to reclaim running jobs on startup: {error}");
        }
        every(Self::INTERVAL, false, stop, || async {
            let _ = self.tick().await;
        })
        .await;
    }
}

// ------------------------------------------------------- email-address-policy-jobs

const MAX_PERSIST_FAILURES: u32 = 5;
const BASE_RETRY_BACKOFF: Duration = Duration::from_secs(6);
const MAX_RETRY_BACKOFF: Duration = Duration::from_secs(300);

#[derive(Default)]
struct RetryState {
    attempts: u32,
    next_retry: Option<Instant>,
    dead: bool,
}

/// `email-address-policy-jobs` (Go `eapjobs.Worker`), including the in-memory
/// backoff and dead-letter budget for jobs whose error cannot be persisted.
pub struct EapJobs {
    pub db: WorkerDatabase,
    failures: Mutex<HashMap<i64, RetryState>>,
}

impl EapJobs {
    pub const INTERVAL: Duration = Duration::from_secs(3);

    pub fn new(db: WorkerDatabase) -> Self {
        Self {
            db,
            failures: Mutex::new(HashMap::new()),
        }
    }

    fn excluded(&self, now: Instant) -> Vec<i64> {
        let failures = self.failures.lock().unwrap_or_else(|e| e.into_inner());
        failures
            .iter()
            .filter(|(_, s)| s.dead || s.next_retry.is_some_and(|t| now < t))
            .map(|(id, _)| *id)
            .collect()
    }

    fn note_failure(&self, now: Instant, job: i64) {
        let mut failures = self.failures.lock().unwrap_or_else(|e| e.into_inner());
        let state = failures.entry(job).or_default();
        state.attempts += 1;
        let shift = (state.attempts - 1).min(20);
        let backoff = BASE_RETRY_BACKOFF
            .checked_mul(1u32 << shift)
            .filter(|b| *b <= MAX_RETRY_BACKOFF)
            .unwrap_or(MAX_RETRY_BACKOFF);
        state.next_retry = Some(now + backoff);
        if state.attempts >= MAX_PERSIST_FAILURES {
            state.dead = true;
            eprintln!("eapjobs: job {job} dead-lettered after repeated error-persist failures; it will not be re-claimed until restart");
        }
    }

    fn clear_failure(&self, job: i64) {
        self.failures
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&job);
    }

    /// Startup reclaim, as Go's `Run` prologue.
    pub async fn reclaim(&self) -> Result<(), Error> {
        let c = self.db.connect_session().await.map_err(|e| e.to_string())?;
        c.query(
            "UPDATE eap_apply_jobs SET status='queued', updated_at=now() WHERE status='running'",
            &[],
        )
        .await
        .map(|_| ())
    }

    /// One Go ticker iteration: drain queued jobs, stopping on the first error.
    pub async fn tick(&self) -> Result<(), Error> {
        let c = self.db.connect_session().await.map_err(|e| e.to_string())?;
        loop {
            if !self.process_one(&c).await? {
                return Ok(());
            }
        }
    }

    async fn process_one(&self, c: &WorkerConnection) -> Result<bool, Error> {
        begin(c).await.map_err(|e| format!("eapjobs: begin tx: {e}"))?;
        let excluded = self.excluded(Instant::now());
        let claim = c
            .query(
                "UPDATE eap_apply_jobs SET status = 'running', updated_at = now() WHERE id = ( SELECT id FROM eap_apply_jobs WHERE status = 'queued' AND NOT (id = ANY($1)) ORDER BY id FOR UPDATE SKIP LOCKED LIMIT 1 ) RETURNING id, policy_id",
                &[(&excluded, Type::INT8_ARRAY)],
            )
            .await;
        let rows = match claim {
            Ok(rows) => rows,
            Err(error) => {
                rollback(c).await;
                return Err(format!("eapjobs: claim job: {error}"));
            }
        };
        let Some(row) = rows.first() else {
            rollback(c).await;
            return Ok(false);
        };
        let job: i64 = row.get(0);
        let policy: Option<i64> = row.get(1);

        // Total up front: the bulk apply sweeps every policy-enabled primary mailbox.
        match c
            .query(
                "SELECT email_address_policy_match_count(NULL,NULL,NULL,NULL)",
                &[],
            )
            .await
        {
            Ok(rows) => {
                let total: i32 = rows[0].get(0);
                if let Err(error) = c
                    .query(
                        "UPDATE eap_apply_jobs SET total=$2 WHERE id=$1",
                        &[(&job, Type::INT8), (&total, Type::INT4)],
                    )
                    .await
                {
                    eprintln!("eapjobs: failed to set initial total job={job}: {error}");
                }
            }
            Err(error) => {
                eprintln!("eapjobs: failed to count total candidates job={job}: {error}")
            }
        }

        let applied = c
            .query(
                "SELECT email_address_policy_apply_bulk($1)",
                &[(&policy, Type::INT8)],
            )
            .await;
        let applied: i32 = match applied {
            Ok(rows) => rows[0].get(0),
            Err(error) => {
                // The transaction is aborted: record the failure on a clean statement.
                rollback(c).await;
                match c
                    .query(
                        "UPDATE eap_apply_jobs SET status = 'error', error = $2, updated_at = now() WHERE id = $1",
                        &[(&job, Type::INT8), (&error, Type::TEXT)],
                    )
                    .await
                {
                    Ok(_) => self.clear_failure(job),
                    Err(update) => {
                        eprintln!("eapjobs: failed to mark job as error job={job}: {update} (reducer {error})");
                        self.note_failure(Instant::now(), job);
                    }
                }
                eprintln!("eapjobs: reducer failed job={job} policy={policy:?}: {error}");
                return Err(error);
            }
        };
        if let Err(error) = c
            .query(
                "UPDATE eap_apply_jobs SET status = 'done', applied = $2, total = $2, updated_at = now() WHERE id = $1",
                &[(&job, Type::INT8), (&applied, Type::INT4)],
            )
            .await
        {
            rollback(c).await;
            return Err(format!("eapjobs: mark done: {error}"));
        }
        commit(c)
            .await
            .map_err(|e| format!("eapjobs: commit: {e}"))?;
        self.clear_failure(job);
        eprintln!("eapjobs: job completed job={job} policy={policy:?} applied={applied}");
        Ok(true)
    }

    pub async fn run_until(self: std::sync::Arc<Self>, stop: impl Future<Output = ()>) {
        eprintln!("eap apply worker started interval={:?}", Self::INTERVAL);
        if let Err(error) = self.reclaim().await {
            eprintln!("eapjobs: failed to reclaim running jobs on startup: {error}");
        }
        every(Self::INTERVAL, false, stop, || async {
            let _ = self.tick().await;
        })
        .await;
    }
}

// ------------------------------------------------------------ identity-operations

const MAX_ARTIFACT_BYTES: usize = 25 << 20;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ClaimedJob {
    job_id: String,
    kind: String,
    source_id: Option<String>,
    transition_id: Option<String>,
    request: Option<Box<RawValue>>,
    progress: Option<Box<RawValue>>,
    #[serde(default)]
    failure_count: i64,
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct Cursor {
    processed: i64,
    links_observed: i64,
    conflicts_recorded: i64,
    next_after_user_id: String,
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct Batch {
    processed: i64,
    links_observed: i64,
    conflicts_recorded: i64,
    next_after_user_id: String,
    complete: bool,
    items: Option<Vec<BatchItem>>,
}

#[derive(Deserialize, Serialize)]
struct BatchItem {
    #[serde(rename = "userId", default)]
    user_id: String,
    #[serde(default)]
    state: String,
    #[serde(default)]
    result: Option<Box<RawValue>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BatchProgress<'a> {
    processed: i64,
    links_observed: i64,
    conflicts_recorded: i64,
    next_after_user_id: &'a str,
    complete: bool,
    items: Option<()>,
}

/// `identity-operations` (Go `identityops.Worker`): leases one job per tick from
/// `identity_job_claim` and settles every batch through a reducer.
pub struct IdentityOperations {
    pub db: WorkerDatabase,
    worker_id: String,
}

impl IdentityOperations {
    pub const INTERVAL: Duration = Duration::from_secs(2);

    pub fn new(db: WorkerDatabase) -> Self {
        Self {
            db,
            worker_id: new_uuid(),
        }
    }

    /// One Go `tick`: claim at most one job and run it.
    pub async fn tick(&self) -> Result<(), Error> {
        let c = self.db.connect_session().await.map_err(|e| e.to_string())?;
        let rows = c
            .query(
                "SELECT identity_job_claim($1::uuid)::text",
                &[(&self.worker_id, Type::TEXT)],
            )
            .await?;
        let raw: Option<String> = rows.first().and_then(|r| r.get::<_, Option<String>>(0));
        let Some(raw) = raw.filter(|r| r != "null") else {
            return Ok(());
        };
        let job: ClaimedJob =
            serde_json::from_str(&raw).map_err(|e| format!("decode identity job claim: {e}"))?;
        if job.job_id.is_empty() || job.job_id == "00000000-0000-0000-0000-000000000000" {
            return Err("decode identity job claim: %!w(<nil>)".into());
        }
        let outcome = match job.kind.as_str() {
            "upgrade_backfill" => self.run_backfill(&c, &job).await,
            "diagnostics" => self.run_diagnostics(&c, &job).await,
            other => Err(format!("unsupported identity job kind {other:?}")),
        };
        let Err(failure) = outcome else {
            return Ok(());
        };
        let retryable = job.failure_count < 20;
        if let Err(settle) = c
            .query(
                "SELECT identity_job_fail($1::uuid,$2::uuid,$3,$4)",
                &[
                    (&job.job_id, Type::TEXT),
                    (&self.worker_id, Type::TEXT),
                    (&"IDENTITY_JOB_EXECUTION", Type::TEXT),
                    (&retryable, Type::BOOL),
                ],
            )
            .await
        {
            return Err(format!(
                "identity job failed ({failure}), settle failed: {settle}"
            ));
        }
        eprintln!(
            "identity operator job attempt failed job={} kind={} retryable={retryable}: {failure}",
            job.job_id, job.kind
        );
        Ok(())
    }

    async fn run_backfill(&self, c: &WorkerConnection, job: &ClaimedJob) -> Result<(), Error> {
        let current: Cursor = job
            .progress
            .as_ref()
            .and_then(|p| serde_json::from_str(p.get()).ok())
            .unwrap_or_default();
        let after: i64 = if current.next_after_user_id.is_empty() {
            0
        } else {
            match current.next_after_user_id.parse::<i64>() {
                Ok(n) if n >= 0 => n,
                _ => return Err("invalid persisted backfill cursor".into()),
            }
        };
        let rows = c
            .query(
                "SELECT identity_legacy_backfill($1::bigint,$2::integer)::text",
                &[(&after, Type::INT8), (&500i32, Type::INT4)],
            )
            .await?;
        let raw: Option<String> = rows[0].get(0);
        let batch: Batch = serde_json::from_str(raw.as_deref().unwrap_or("null"))
            .map_err(|e| format!("decode identity backfill result: {e}"))?;
        let items = batch.items.as_deref().unwrap_or(&[]);
        if items.len() > 500 {
            return Err("identity backfill result exceeds the 500-person batch bound".into());
        }
        let items_json = match &batch.items {
            Some(items) => serde_json::to_string(items),
            None => Ok("null".to_owned()),
        }
        .map_err(|e| format!("encode identity backfill results: {e}"))?;
        let progress = serde_json::to_string(&BatchProgress {
            processed: batch.processed + current.processed,
            links_observed: batch.links_observed + current.links_observed,
            conflicts_recorded: batch.conflicts_recorded + current.conflicts_recorded,
            next_after_user_id: &batch.next_after_user_id,
            complete: batch.complete,
            items: None,
        })
        .map_err(|e| e.to_string())?;
        let conflicts = batch.conflicts_recorded + current.conflicts_recorded > 0;
        c.query(
            "SELECT identity_job_batch_settle($1::uuid,$2::uuid,$3::jsonb,$4::jsonb,$5,$6)",
            &[
                (&job.job_id, Type::TEXT),
                (&self.worker_id, Type::TEXT),
                (&items_json, Type::TEXT),
                (&progress, Type::TEXT),
                (&batch.complete, Type::BOOL),
                (&conflicts, Type::BOOL),
            ],
        )
        .await
        .map(|_| ())
    }

    async fn run_diagnostics(&self, c: &WorkerConnection, job: &ClaimedJob) -> Result<(), Error> {
        #[derive(Deserialize)]
        struct Scope {
            #[serde(rename = "sinceSeconds", default)]
            since_seconds: i64,
        }
        let scope: Option<Scope> = job
            .request
            .as_ref()
            .and_then(|r| serde_json::from_str(r.get()).ok());
        let Some(since) = scope
            .map(|s| s.since_seconds)
            .filter(|s| (1..=86400).contains(s))
        else {
            return Err("invalid diagnostic request scope".into());
        };
        let evidence = self.diagnostic_evidence(c, job, since).await?;
        let created = go_rfc3339_nano(chrono::Utc::now());
        let manifest = manifest_json(job, &created, since);
        let artifact = build_diagnostic_zip(&manifest, &evidence)?;
        if artifact.len() > MAX_ARTIFACT_BYTES {
            return Err("diagnostic artifact exceeds 25 MiB".into());
        }
        let redactions = r#"{"credentials":1,"emails":1,"externalSubjects":1,"personalProfiles":1,"rawAssertions":1}"#;
        let progress = format!(
            "{{\"bytes\":{},\"failed\":0,\"processed\":{}}}",
            artifact.len(),
            evidence.len()
        );
        c.query(
            "SELECT identity_job_complete($1::uuid,$2::uuid,'completed',$3::jsonb,$4,$5::jsonb,$6::jsonb)",
            &[
                (&job.job_id, Type::TEXT),
                (&self.worker_id, Type::TEXT),
                (&progress, Type::TEXT),
                (&artifact, Type::BYTEA),
                (&manifest, Type::TEXT),
                (&redactions, Type::TEXT),
            ],
        )
        .await
        .map(|_| ())
    }

    async fn diagnostic_evidence(
        &self,
        c: &WorkerConnection,
        job: &ClaimedJob,
        since: i64,
    ) -> Result<Vec<String>, Error> {
        let mut rows = Vec::new();
        if let Some(source) = &job.source_id {
            let id = match source.parse::<i64>() {
                Ok(n) if n > 0 => n,
                _ => return Err("invalid claimed source id".into()),
            };
            let found = c
                .query(
                    "SELECT jsonb_build_object( 'type','source', 'sourceId',s.id::text, 'sourceKey',s.source_key, 'kind',s.kind, 'state',s.state, 'generation',s.generation::text, 'mappingVersion',s.mapping_version::text, 'readMode',s.read_mode, 'lastSuccessAt',s.last_success_at, 'lastFailureAt',s.last_failure_at, 'lastErrorCode',s.last_error_code, 'inbox',jsonb_build_object( 'pending',(SELECT count(*) FROM identity_source_inbox i WHERE i.source_id=s.id AND i.state='pending'), 'quarantined',(SELECT count(*) FROM identity_source_inbox i WHERE i.source_id=s.id AND i.state='quarantined') ), 'divergences',jsonb_build_object( 'critical',(SELECT count(*) FROM identity_shadow_divergences d WHERE d.source_id=s.id AND d.state='open' AND d.divergence_class IN ( 'person_mismatch','authority_mismatch','access_mismatch')), 'expectedAmbiguity',(SELECT count(*) FROM identity_shadow_divergences d WHERE d.source_id=s.id AND d.state='open' AND d.divergence_class='expected_legacy_ambiguity') ) )::text FROM identity_sources s WHERE s.id=$1",
                    &[(&id, Type::INT8)],
                )
                .await?;
            let row = found.first().ok_or("no rows in result set")?;
            rows.push(row.get::<_, String>(0));
        }
        if let Some(transition) = &job.transition_id {
            let found = c
                .query(
                    "SELECT jsonb_build_object( 'type','transition', 'transitionId',t.id, 'state',t.state, 'generation',t.transition_generation::text, 'transitionType',t.kind, 'createdAt',t.created_at, 'updatedAt',t.updated_at, 'effects',COALESCE(( SELECT jsonb_agg(jsonb_build_object( 'effectId',e.effect_id,'kind',e.effect_kind, 'state',e.state,'attemptCount',e.attempt_count, 'lastErrorCode',e.last_error_code ) ORDER BY e.effect_kind) FROM identity_transition_effects e WHERE e.transition_id=t.id ),'[]'::jsonb) )::text FROM identity_transitions t WHERE t.id=$1::uuid",
                    &[(transition, Type::TEXT)],
                )
                .await?;
            let row = found.first().ok_or("no rows in result set")?;
            rows.push(row.get::<_, String>(0));
        }
        let since = i32::try_from(since).map_err(|e| e.to_string())?;
        let metrics = c
            .query(
                "SELECT jsonb_build_object( 'type','boundedMetrics', 'sinceSeconds',$1::integer, 'jobs',jsonb_build_object( 'queued',(SELECT count(*) FROM identity_jobs WHERE state='queued'), 'running',(SELECT count(*) FROM identity_jobs WHERE state='running') ), 'transitions',jsonb_build_object( 'pendingEffects',(SELECT count(*) FROM identity_transition_effects WHERE state<>'completed'), 'failedEffects',(SELECT count(*) FROM identity_transition_effects WHERE state='failed') ), 'candidates',jsonb_build_object( 'pending',(SELECT count(*) FROM identity_match_candidates WHERE status='pending'), 'deferred',(SELECT count(*) FROM identity_match_candidates WHERE status='deferred') ) )::text",
                &[(&since, Type::INT4)],
            )
            .await?;
        rows.push(metrics[0].get::<_, String>(0));
        Ok(rows)
    }

    pub async fn run_until(self: std::sync::Arc<Self>, stop: impl Future<Output = ()>) {
        every(Self::INTERVAL, true, stop, || async {
            if let Err(error) = self.tick().await {
                eprintln!("identity operator job tick failed: {error}");
            }
        })
        .await;
    }
}

/// `time.RFC3339Nano` of a UTC instant: fractional seconds with trailing zeros trimmed.
pub fn go_rfc3339_nano(at: chrono::DateTime<chrono::Utc>) -> String {
    let base = at.format("%Y-%m-%dT%H:%M:%S").to_string();
    let nanos = format!("{:09}", at.timestamp_subsec_nanos());
    let fraction = nanos.trim_end_matches('0');
    if fraction.is_empty() {
        format!("{base}Z")
    } else {
        format!("{base}.{fraction}Z")
    }
}

/// Go's `json.Marshal` of the manifest map: keys sorted.
fn manifest_json(job: &ClaimedJob, created: &str, since: i64) -> String {
    let text = |v: &str| serde_json::to_string(v).expect("string");
    let optional = |v: &Option<String>| v.as_deref().map_or("null".to_owned(), text);
    format!(
        "{{\"createdAt\":{},\"files\":[\"evidence.jsonl\"],\"jobId\":{},\"manifestVersion\":\"1\",\"redactionPolicy\":\"identity-diagnostics-v1\",\"scope\":{{\"sinceSeconds\":{since},\"sourceId\":{},\"transitionId\":{}}}}}",
        text(created),
        text(&job.job_id),
        optional(&job.source_id),
        optional(&job.transition_id),
    )
}

/// Go's `buildDiagnosticZIP`: `manifest.json` then `evidence.jsonl`, deflated, with
/// `archive/zip`'s layout (data descriptors, extended timestamp, Unix mode 0600).
/// The deflate stream itself is `flate2`'s, not `compress/flate`'s (same content,
/// different bytes).
pub fn build_diagnostic_zip(manifest: &str, evidence: &[String]) -> Result<Vec<u8>, Error> {
    use std::io::Write;
    let mut manifest_bytes = manifest.as_bytes().to_vec();
    manifest_bytes.push(b'\n');
    let mut lines = Vec::new();
    for row in evidence {
        if serde_json::from_str::<serde::de::IgnoredAny>(row).is_err() {
            return Err("invalid diagnostic evidence JSON".into());
        }
        lines.extend_from_slice(row.as_bytes());
        lines.push(b'\n');
    }
    struct Entry {
        name: &'static str,
        crc: u32,
        compressed: usize,
        size: usize,
        offset: usize,
    }
    let mut out: Vec<u8> = Vec::new();
    let mut entries = Vec::new();
    // MS-DOS date of 1970-01-01 as archive/zip computes it (the year wraps).
    const DOS_DATE: u16 = 0xEC21;
    const EXTRA: [u8; 9] = [0x55, 0x54, 5, 0, 1, 0, 0, 0, 0];
    for (name, payload) in [
        ("manifest.json", manifest_bytes.as_slice()),
        ("evidence.jsonl", lines.as_slice()),
    ] {
        let offset = out.len();
        out.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&8u16.to_le_bytes());
        out.extend_from_slice(&8u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&DOS_DATE.to_le_bytes());
        out.extend_from_slice(&[0; 12]);
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&(EXTRA.len() as u16).to_le_bytes());
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(&EXTRA);
        let mut encoder =
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(payload).map_err(|e| e.to_string())?;
        let compressed = encoder.finish().map_err(|e| e.to_string())?;
        let mut crc = flate2::Crc::new();
        crc.update(payload);
        out.extend_from_slice(&compressed);
        out.extend_from_slice(&0x0807_4b50u32.to_le_bytes());
        out.extend_from_slice(&crc.sum().to_le_bytes());
        out.extend_from_slice(&(compressed.len() as u32).to_le_bytes());
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        entries.push(Entry {
            name,
            crc: crc.sum(),
            compressed: compressed.len(),
            size: payload.len(),
            offset,
        });
    }
    let directory = out.len();
    for e in &entries {
        out.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        out.extend_from_slice(&0x0314u16.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&8u16.to_le_bytes());
        out.extend_from_slice(&8u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&DOS_DATE.to_le_bytes());
        out.extend_from_slice(&e.crc.to_le_bytes());
        out.extend_from_slice(&(e.compressed as u32).to_le_bytes());
        out.extend_from_slice(&(e.size as u32).to_le_bytes());
        out.extend_from_slice(&(e.name.len() as u16).to_le_bytes());
        out.extend_from_slice(&(EXTRA.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&[0; 4]);
        out.extend_from_slice(&(0o100600u32 << 16).to_le_bytes());
        out.extend_from_slice(&(e.offset as u32).to_le_bytes());
        out.extend_from_slice(e.name.as_bytes());
        out.extend_from_slice(&EXTRA);
    }
    let size = out.len() - directory;
    out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    out.extend_from_slice(&[0; 4]);
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&(size as u32).to_le_bytes());
    out.extend_from_slice(&(directory as u32).to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    Ok(out)
}

// ------------------------------------------------------------ identity-transitions

/// The LiveKit credentials of Go's `meetRooms` (absent when LiveKit is not configured).
#[derive(Clone)]
pub struct Rooms {
    pub endpoint: String,
    pub key: String,
    pub secret: String,
}

impl Rooms {
    async fn remove(&self, room: &str, identity: &str) -> Result<(), String> {
        crate::guest_worker::remove_participant(
            &self.endpoint,
            &self.key,
            &self.secret,
            room,
            identity,
        )
        .await
    }

    /// Go's `mediaevict.EvictParticipantThrough`: kick until the horizon
    /// (microseconds since the epoch) has passed; a not-found answer is success
    /// for that attempt but does not stop the loop.
    async fn evict_through(
        &self,
        room: &str,
        identity: &str,
        until_micros: Option<i64>,
    ) -> Result<(), String> {
        loop {
            self.remove(room, identity).await?;
            let now = now_micros();
            let Some(until) = until_micros.filter(|u| now < *u) else {
                return Ok(());
            };
            let wait = ((until - now) as u64).min(5_000_000);
            tokio::time::sleep(Duration::from_micros(wait)).await;
        }
    }
}

fn now_micros() -> i64 {
    chrono::Utc::now().timestamp_micros()
}

const TRANSITION_BATCH: usize = 100;
const MAX_SESSION_EVICTION_ATTEMPTS: i32 = 60;

struct Effect {
    transition_id: String,
    effect_id: String,
    kind: String,
}

/// `identity-transitions` (Go `identitytransition.Worker`): durable post-commit
/// identity effects (notice, LiveKit eviction, auth sessions) and session
/// eviction intents, both settled through reducers or Go's own statements.
pub struct IdentityTransitions {
    pub db: WorkerDatabase,
    pub rooms: Option<Rooms>,
    worker_id: String,
}

impl IdentityTransitions {
    pub const INTERVAL: Duration = Duration::from_secs(5);

    pub fn new(db: WorkerDatabase, rooms: Option<Rooms>) -> Self {
        Self {
            db,
            rooms,
            worker_id: format!("identity-transition-{}", new_uuid()),
        }
    }

    /// One Go iteration: `drain` then `drainSessionEvictions`.
    pub async fn tick(&self) {
        let c = match self.db.connect_session().await {
            Ok(c) => c,
            Err(error) => {
                eprintln!("identity transition effect claim failed: {error}");
                return;
            }
        };
        self.drain(&c).await;
        self.drain_session_evictions(&c).await;
    }

    async fn drain(&self, c: &WorkerConnection) {
        for _ in 0..TRANSITION_BATCH {
            match self.claim(c).await {
                Err(error) => {
                    eprintln!("identity transition effect claim failed: {error}");
                    return;
                }
                Ok(None) => return,
                Ok(Some(effect)) => match self.process(c, &effect).await {
                    Err(error) => self.fail(c, &effect, &error).await,
                    Ok(()) => self.complete(c, &effect).await,
                },
            }
        }
    }

    async fn claim(&self, c: &WorkerConnection) -> Result<Option<Effect>, Error> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Claimed {
            #[serde(default)]
            transition_id: String,
            #[serde(default)]
            effect_id: String,
            #[serde(default)]
            kind: String,
            #[serde(default)]
            attempt_count: i64,
        }
        let rows = c
            .query(
                "SELECT identity_transition_effect_claim($1,$2)::text",
                &[(&self.worker_id, Type::TEXT), (&120i32, Type::INT4)],
            )
            .await?;
        let raw: Option<String> = rows
            .first()
            .and_then(|r| r.get::<_, Option<String>>(0))
            .filter(|r| !r.is_empty());
        let Some(raw) = raw else {
            return Ok(None);
        };
        let claimed: Claimed = serde_json::from_str(&raw)
            .map_err(|e| format!("decode claimed identity transition effect: {e}"))?;
        if !is_uuid(&claimed.transition_id) {
            return Err("claimed identity transition has invalid transition id".into());
        }
        if !is_uuid(&claimed.effect_id) {
            return Err("claimed identity transition has invalid effect id".into());
        }
        if claimed.kind.is_empty() || !(1..=20).contains(&claimed.attempt_count) {
            return Err("claimed identity transition effect is invalid".into());
        }
        Ok(Some(Effect {
            transition_id: claimed.transition_id,
            effect_id: claimed.effect_id,
            kind: claimed.kind,
        }))
    }

    async fn process(&self, c: &WorkerConnection, e: &Effect) -> Result<(), Error> {
        let (base, rollback) = match e.kind.strip_prefix("rollback_") {
            Some(base) => (base, true),
            None => (e.kind.as_str(), false),
        };
        match base {
            "auth_sessions" => Ok(()),
            "subscriber_notice" => {
                let state = if rollback {
                    "rollback_committed"
                } else {
                    "committed"
                };
                c.query(
                    "SELECT app_notify( 'identity_transition', jsonb_build_object( 'transitionId',$1::text,'state',$2::text )::text )",
                    &[(&e.transition_id, Type::TEXT), (&state, Type::TEXT)],
                )
                .await
                .map(|_| ())
            }
            "livekit_sessions" => {
                let targets = c
                    .query(
                        "SELECT target_key,(extract(epoch FROM evict_until)*1000000)::bigint FROM identity_transition_effect_targets WHERE transition_id=$1::uuid AND effect_kind=$2 AND completed_at IS NULL ORDER BY target_key",
                        &[(&e.transition_id, Type::TEXT), (&e.kind, Type::TEXT)],
                    )
                    .await?;
                if targets.is_empty() {
                    return Ok(());
                }
                let Some(rooms) = &self.rooms else {
                    return Err("LiveKit is not configured".into());
                };
                for target in &targets {
                    let key: String = target.get(0);
                    let until: Option<i64> = target.get(1);
                    let Some((room, identity)) = key.split_once('|') else {
                        return Err("invalid LiveKit target".into());
                    };
                    rooms.evict_through(room, identity, until).await?;
                    c.query(
                        "UPDATE identity_transition_effect_targets SET completed_at=statement_timestamp(),last_error=NULL WHERE transition_id=$1::uuid AND effect_kind=$2 AND target_key=$3",
                        &[
                            (&e.transition_id, Type::TEXT),
                            (&e.kind, Type::TEXT),
                            (&key, Type::TEXT),
                        ],
                    )
                    .await?;
                }
                Ok(())
            }
            _ => Err(format!("unknown effect kind {:?}", e.kind)),
        }
    }

    async fn complete(&self, c: &WorkerConnection, e: &Effect) {
        if let Err(error) = c
            .query(
                "SELECT identity_transition_effect_complete($1,$2::uuid,$3::uuid,NULL)",
                &[
                    (&self.worker_id, Type::TEXT),
                    (&e.transition_id, Type::TEXT),
                    (&e.effect_id, Type::TEXT),
                ],
            )
            .await
        {
            eprintln!("identity transition effect completion failed: {error}");
        }
    }

    async fn fail(&self, c: &WorkerConnection, e: &Effect, effect_error: &str) {
        if let Err(error) = c
            .query(
                "SELECT identity_transition_effect_fail($1,$2::uuid,$3::uuid,$4,NULL)",
                &[
                    (&self.worker_id, Type::TEXT),
                    (&e.transition_id, Type::TEXT),
                    (&e.effect_id, Type::TEXT),
                    (&"effect_failed", Type::TEXT),
                ],
            )
            .await
        {
            eprintln!("identity transition effect failure recording failed: {error}");
        }
        eprintln!(
            "identity transition effect failed transition_id={} kind={}: {effect_error}",
            e.transition_id, e.kind
        );
    }

    async fn drain_session_evictions(&self, c: &WorkerConnection) {
        for _ in 0..TRANSITION_BATCH {
            let rows = match c
                .query(
                    "UPDATE identity_session_eviction_intents SET attempt_count=attempt_count+1, last_attempt_at=statement_timestamp(), next_attempt_at=statement_timestamp()+interval '2 minutes' WHERE id=( SELECT id FROM identity_session_eviction_intents WHERE completed_at IS NULL AND next_attempt_at<=statement_timestamp() ORDER BY next_attempt_at,id FOR UPDATE SKIP LOCKED LIMIT 1 ) RETURNING id,room_name,identity,(extract(epoch FROM retry_until)*1000000)::bigint,attempt_count",
                    &[],
                )
                .await
            {
                Ok(rows) => rows,
                Err(error) => {
                    eprintln!("identity session eviction claim failed: {error}");
                    return;
                }
            };
            let Some(row) = rows.first() else {
                return;
            };
            let id: i64 = row.get(0);
            let room: String = row.get(1);
            let identity: String = row.get(2);
            let retry_until: i64 = row.get(3);
            let attempts: i32 = row.get(4);
            self.process_session_eviction(c, id, &room, &identity, retry_until, attempts)
                .await;
        }
    }

    async fn process_session_eviction(
        &self,
        c: &WorkerConnection,
        id: i64,
        room: &str,
        identity: &str,
        retry_until: i64,
        attempts: i32,
    ) {
        let removed = match &self.rooms {
            Some(rooms) => rooms.remove(room, identity).await,
            None => Err("LiveKit is not configured".to_owned()),
        };
        let succeeded = removed.is_ok();
        if succeeded && now_micros() >= retry_until {
            if let Err(error) = c
                .query(
                    "UPDATE identity_session_eviction_intents SET completed_at=statement_timestamp(), next_attempt_at=statement_timestamp(),last_error=NULL WHERE id=$1",
                    &[(&id, Type::INT8)],
                )
                .await
            {
                eprintln!("identity session eviction completion failed intent_id={id}: {error}");
            }
            return;
        }
        let mut delay: i32 = 5;
        let mut last_error = String::new();
        if let Err(error) = &removed {
            delay = (attempts.max(1) * 5).min(60);
            last_error = error.clone();
            // Bounded retry: past the cap the intent is parked beyond every claim window.
            if attempts >= MAX_SESSION_EVICTION_ATTEMPTS {
                match c
                    .query(
                        "UPDATE identity_session_eviction_intents SET next_attempt_at='infinity', last_error=NULLIF($2,'') WHERE id=$1",
                        &[(&id, Type::INT8), (&last_error, Type::TEXT)],
                    )
                    .await
                {
                    Ok(_) => {
                        eprintln!("identity session eviction intent exhausted, dead-lettered intent_id={id} room={room} identity={identity} attempts={attempts} last_error={last_error}");
                        return;
                    }
                    Err(error) => {
                        eprintln!("identity session eviction dead-letter failed intent_id={id}: {error}")
                    }
                }
            }
        }
        if let Err(error) = c
            .query(
                "UPDATE identity_session_eviction_intents SET next_attempt_at=statement_timestamp()+make_interval(secs=>$2), last_error=NULLIF($3,'') WHERE id=$1",
                &[
                    (&id, Type::INT8),
                    (&delay, Type::INT4),
                    (&last_error, Type::TEXT),
                ],
            )
            .await
        {
            eprintln!("identity session eviction reschedule failed intent_id={id}: {error}");
        }
        if let Err(error) = removed {
            eprintln!("identity session eviction failed intent_id={id} room={room} identity={identity} attempt={attempts} retry_in={delay}s: {error}");
        }
    }

    pub async fn run_until(self: std::sync::Arc<Self>, stop: impl Future<Output = ()>) {
        every(Self::INTERVAL, true, stop, || async {
            self.tick().await;
        })
        .await;
    }
}

/// `uuid.Parse` over the canonical hyphenated form the database emits.
fn is_uuid(text: &str) -> bool {
    let b = text.as_bytes();
    b.len() == 36
        && b.iter().enumerate().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => *c == b'-',
            _ => c.is_ascii_hexdigit(),
        })
}
