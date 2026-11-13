//! The catalog identity-source runtime (#400): Go's `identitysource.Supervisor`
//! and `cmd/mailserverd` `identitySourceRuntimeManager` as one manager.
//!
//! It reads the active catalog `ad`/`ldap` sources, starts one sync loop per
//! source generation (an immediate cycle, then one per interval) and replaces or
//! stops loops when a generation moves, a source leaves the catalog or the master
//! gate (`feature.identity_model_v2`) closes. A notification wakes it at once; a
//! 30 s poll closes the lost-notification window. Every cycle is the shared
//! normalized pipeline (`ldap::normalized::sync_with`): reducers own matching,
//! lifecycle and cursor advancement, and the database lease picks the one
//! discovery process across gateways.
use crate::ad::runtime::AdWorker;
use crate::ad::{AdClient, ClientConfig};
use crate::ldap::engine::{admit_filter, Res, Worker};
use crate::ldap::runtime::load_env_codec;
use crate::ldap::{new_uuid, LdapClient};
use setjoin_config_secret::ConfigSecretCodec;
use setjoin_pg::workers::WorkerDatabase;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{oneshot, Mutex, Notify};
use tokio::task::JoinHandle;

/// Go `identitySourceRuntimePollInterval`.
pub const POLL: Duration = Duration::from_secs(30);

/// `admin.IdentitySourceRuntimeConfig`: the decrypted runtime projection of one
/// active AD or LDAP source. The bind password never reaches `Debug` output.
#[derive(Clone, Default)]
pub struct SourceConfig {
    pub source_key: String,
    pub kind: String,
    pub host: String,
    pub port: i64,
    pub transport: String,
    pub base_dn: String,
    pub bind_dn: String,
    pub subject_attribute: String,
    pub user_filter: String,
    pub group_filter: String,
    pub password: String,
}

impl std::fmt::Debug for SourceConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SourceConfig")
            .field("source_key", &self.source_key)
            .field("kind", &self.kind)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("transport", &self.transport)
            .field("password", &"<redacted>")
            .finish_non_exhaustive()
    }
}

/// Go `DecodeIdentitySourceRuntime`, supplied by the identity-admin family
/// (it owns the source document validator): `(codec, source key, row kind,
/// config envelope)`. A family crate may not depend on another, so the gateway
/// passes the decoder in.
pub type Decode = fn(Option<&ConfigSecretCodec>, &str, &str, &[u8]) -> Result<SourceConfig, String>;

#[derive(Clone, Debug)]
pub struct Entry {
    pub source_id: i64,
    pub generation: i64,
    pub key: String,
    pub config: SourceConfig,
}

/// Go `identitySourceRuntimeSnapshot`.
#[derive(Debug, Default)]
pub struct Snapshot {
    pub entries: Vec<Entry>,
    /// Active sources whose configuration cannot run (isolated and logged).
    pub invalid: Vec<String>,
    pub authoritative: bool,
    pub master_enabled: bool,
}

pub(crate) fn log(message: &str) {
    eprintln!("setjoin-gateway: identity-source-runtime: {message}");
}

/// A built source worker.
enum Built {
    Ldap(Box<Worker>),
    Ad(Box<AdWorker>),
}

impl Built {
    fn label(&self) -> &'static str {
        match self {
            Built::Ldap(_) => "LDAP",
            Built::Ad(_) => "AD",
        }
    }

    fn interval(&self) -> Duration {
        let minutes = match self {
            Built::Ldap(w) => w.interval_min,
            Built::Ad(w) => w.interval_min,
        };
        Duration::from_secs(minutes.max(1) as u64 * 60)
    }

    async fn cycle(&self) {
        let outcome = match self {
            Built::Ldap(w) => w.sync().await.map(|_| ()),
            Built::Ad(w) => w.sync().await.map(|_| ()),
        };
        if let Err(error) = outcome {
            log(&format!("{} sync cycle failed: {error}", self.label()));
        }
    }

    /// `SyncWorker.Run`: an immediate cycle, then one per interval, until stopped.
    async fn run(self, mut stop: oneshot::Receiver<()>) {
        let mut ticker = tokio::time::interval(self.interval());
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = &mut stop => return,
                _ = ticker.tick() => {}
            }
            tokio::select! {
                _ = &mut stop => {
                    // The dropped cycle may hold the source lease (Go releases it on a context
                    // that survives the cancel); free it before the replacement worker starts.
                    self.release_abandoned().await;
                    return;
                }
                _ = self.cycle() => {}
            }
        }
    }

    async fn release_abandoned(&self) {
        let (db, instance) = match self {
            Built::Ldap(w) => (&w.db, w.instance.as_str()),
            Built::Ad(w) => (&w.db, w.instance.as_str()),
        };
        let released = tokio::time::timeout(
            STOP_DEADLINE,
            crate::ldap::normalized::release_abandoned(db, instance),
        )
        .await;
        match released {
            Ok(Ok(())) => {}
            Ok(Err(error)) => log(&format!(
                "{} sync: release identity source lease: {error}",
                self.label()
            )),
            Err(_) => log(&format!(
                "{} sync: release identity source lease: timed out",
                self.label()
            )),
        }
    }
}

/// How long stopping workers may take in total, and how long one abandoned-cycle lease
/// release may take.
const STOP_DEADLINE: Duration = Duration::from_secs(5);
/// Slack past `STOP_DEADLINE` so a release that times out on its own is not aborted mid-log.
const STOP_GRACE: Duration = Duration::from_millis(500);

/// Signal every worker first, then join them against ONE shared deadline: N stalled workers
/// take about `STOP_DEADLINE` in total, not `STOP_DEADLINE` x N. A worker still running at
/// the deadline is aborted (its lease expires on its own).
async fn stop_all(running: Vec<Running>) {
    let mut tasks = Vec::with_capacity(running.len());
    for r in running {
        let _ = r.stop.send(());
        tasks.push(r.task);
    }
    let deadline = tokio::time::Instant::now() + STOP_DEADLINE + STOP_GRACE;
    for mut task in tasks {
        if tokio::time::timeout_at(deadline, &mut task).await.is_err() {
            task.abort();
            log("worker did not stop before the shared deadline; aborted");
        }
    }
}

struct Running {
    generation: i64,
    stop: oneshot::Sender<()>,
    task: JoinHandle<()>,
}

pub struct IdentitySourceRuntime {
    db: WorkerDatabase,
    codec: tokio::sync::OnceCell<Option<Arc<ConfigSecretCodec>>>,
    from_env: bool,
    decode: Decode,
    ad_interval_min: i64,
    ldap_interval_min: i64,
    poll: Duration,
    /// Coalesced reconcile request (a toggle observer, a test).
    pub trigger: Arc<Notify>,
    workers: Mutex<HashMap<i64, Running>>,
    /// Completed reconciliations; tests poll it.
    pub reconciles: AtomicU64,
}

impl IdentitySourceRuntime {
    /// Secrets keyed from the process environment, sync intervals from
    /// `AD_SYNC_INTERVAL_MIN` / `LDAP_SYNC_INTERVAL_MIN` (Go's `ad.sync_interval_min`
    /// and `ldap.sync_interval_min`, default 15).
    pub fn from_env(db: WorkerDatabase, decode: Decode) -> Self {
        let minutes = |name: &str| {
            std::env::var(name)
                .ok()
                .and_then(|v| v.trim().parse::<i64>().ok())
                .filter(|n| *n > 0)
                .unwrap_or(15)
        };
        let mut runtime = Self::new(
            db,
            decode,
            minutes("AD_SYNC_INTERVAL_MIN"),
            minutes("LDAP_SYNC_INTERVAL_MIN"),
        );
        runtime.from_env = true;
        runtime
    }

    pub fn with_parts(
        db: WorkerDatabase,
        codec: Option<Arc<ConfigSecretCodec>>,
        decode: Decode,
        ad_interval_min: i64,
        ldap_interval_min: i64,
    ) -> Self {
        let runtime = Self::new(db, decode, ad_interval_min, ldap_interval_min);
        let _ = runtime.codec.set(codec);
        runtime
    }

    fn new(
        db: WorkerDatabase,
        decode: Decode,
        ad_interval_min: i64,
        ldap_interval_min: i64,
    ) -> Self {
        Self {
            db,
            codec: tokio::sync::OnceCell::new(),
            from_env: false,
            decode,
            ad_interval_min,
            ldap_interval_min,
            poll: POLL,
            trigger: Arc::new(Notify::new()),
            workers: Mutex::new(HashMap::new()),
            reconciles: AtomicU64::new(0),
        }
    }

    pub fn with_poll(mut self, poll: Duration) -> Self {
        self.poll = poll;
        self
    }

    async fn codec(&self) -> Option<Arc<ConfigSecretCodec>> {
        self.codec
            .get_or_init(|| async {
                if !self.from_env {
                    return None;
                }
                load_env_codec(&self.db).await
            })
            .await
            .clone()
    }

    /// Go `databaseIdentitySourceRuntimeCatalog.LoadActive`. A snapshot that is
    /// not authoritative (the read failed) stops every worker.
    pub async fn load_active(&self) -> (Snapshot, Option<String>) {
        let rows = match self.query_active().await {
            Ok(rows) => rows,
            Err(error) => return (Snapshot::default(), Some(error)),
        };
        let codec = self.codec().await;
        let mut snapshot = Snapshot {
            authoritative: true,
            ..Default::default()
        };
        for row in &rows {
            let (enabled, id, key, kind, generation, envelope): (
                bool,
                Option<i64>,
                Option<String>,
                Option<String>,
                Option<i64>,
                Option<Vec<u8>>,
            ) = (
                row.get(0),
                row.get(1),
                row.get(2),
                row.get(3),
                row.get(4),
                row.get(5),
            );
            snapshot.master_enabled = enabled;
            let (Some(id), Some(key), Some(kind), Some(generation)) = (id, key, kind, generation)
            else {
                continue;
            };
            match (self.decode)(codec.as_deref(), &key, &kind, &envelope.unwrap_or_default()) {
                Ok(config) => snapshot.entries.push(Entry {
                    source_id: id,
                    generation,
                    key,
                    config,
                }),
                Err(error) => snapshot.invalid.push(format!(
                    "active identity source {key:?} is not runnable: {error}"
                )),
            }
        }
        (snapshot, None)
    }

    async fn query_active(&self) -> Result<Vec<setjoin_pg::Row>, String> {
        let conn = self
            .db
            .connect()
            .await
            .map_err(|e| format!("query active identity sources: {e}"))?;
        conn.query(
            "WITH gate AS (
                SELECT COALESCE((SELECT enabled FROM feature_toggles
                                  WHERE key='feature.identity_model_v2'),FALSE) AS enabled
             )
             SELECT gate.enabled,s.id,s.source_key,s.kind,s.generation,s.config_envelope
               FROM gate
               LEFT JOIN identity_sources s
                 ON gate.enabled
                AND s.state='active'
                AND s.kind IN ('ad','ldap')
              ORDER BY s.id",
            &[],
        )
        .await
        .map_err(|e| format!("query active identity sources: {e}"))
    }

    /// Go `identityMain`'s `Start`: the first reconciliation must succeed.
    pub async fn start(&self) -> Res<()> {
        self.reconcile()
            .await
            .map_err(|e| format!("initial identity source reconciliation: {e}"))
    }

    /// Go `reconcile`.
    pub async fn reconcile(&self) -> Res<()> {
        let (snapshot, load_error) = self.load_active().await;
        let outcome = self.apply(snapshot, load_error).await;
        self.reconciles.fetch_add(1, Ordering::SeqCst);
        outcome
    }

    async fn apply(&self, snapshot: Snapshot, load_error: Option<String>) -> Res<()> {
        let mut errors: Vec<String> = load_error.into_iter().collect();
        if !snapshot.authoritative || !snapshot.master_enabled {
            self.supervise(Vec::new()).await;
            return join(errors);
        }
        for invalid in &snapshot.invalid {
            log(&format!("source isolated: {invalid}"));
        }
        errors.extend(self.supervise(snapshot.entries).await);
        join(errors)
    }

    /// Go `Supervisor.Reconcile`: build what is new or moved, stop what left or
    /// moved (a failed build still stops the old generation), start what built.
    async fn supervise(&self, mut entries: Vec<Entry>) -> Vec<String> {
        let mut workers = self.workers.lock().await;
        entries.sort_by_key(|e| e.source_id);
        let mut errors = Vec::new();
        let mut built: HashMap<i64, Built> = HashMap::new();
        for entry in &entries {
            if workers
                .get(&entry.source_id)
                .is_some_and(|w| w.generation == entry.generation)
            {
                continue;
            }
            match self.build(entry) {
                Ok(worker) => {
                    built.insert(entry.source_id, worker);
                }
                Err(error) => {
                    errors.push(format!("build source worker {}: {error}", entry.source_id))
                }
            }
        }
        let wanted: HashMap<i64, i64> = entries
            .iter()
            .map(|e| (e.source_id, e.generation))
            .collect();
        let stale: Vec<i64> = workers
            .iter()
            .filter(|(id, w)| wanted.get(id) != Some(&w.generation))
            .map(|(id, _)| *id)
            .collect();
        let stopping: Vec<Running> = stale.iter().filter_map(|id| workers.remove(id)).collect();
        stop_all(stopping).await;
        for entry in &entries {
            if workers.contains_key(&entry.source_id) {
                continue;
            }
            let Some(worker) = built.remove(&entry.source_id) else {
                continue;
            };
            let (stop, stopped) = oneshot::channel();
            let task = tokio::spawn(worker.run(stopped));
            workers.insert(
                entry.source_id,
                Running {
                    generation: entry.generation,
                    stop,
                    task,
                },
            );
        }
        errors
    }

    /// Go `identitySourceWorkerBuilder.Build`.
    fn build(&self, entry: &Entry) -> Res<Built> {
        let cfg = &entry.config;
        match cfg.kind.as_str() {
            "ad" => {
                let client = AdClient::configured(&ClientConfig {
                    host: cfg.host.clone(),
                    port: cfg.port,
                    transport: cfg.transport.clone(),
                    base_dn: cfg.base_dn.clone(),
                    bind_dn: cfg.bind_dn.clone(),
                    password: cfg.password.clone(),
                    subject_attribute: cfg.subject_attribute.clone(),
                    user_filter: cfg.user_filter.clone(),
                })?;
                Ok(Built::Ad(Box::new(AdWorker {
                    client,
                    db: self.db.clone(),
                    interval_min: self.ad_interval_min,
                    instance: new_uuid(),
                    source_key: entry.key.clone(),
                })))
            }
            "ldap" => {
                if cfg.host.is_empty() || !(1..=65535).contains(&cfg.port) {
                    return Err("LDAP endpoint is invalid".into());
                }
                if cfg.base_dn.is_empty() {
                    return Err("LDAP base DN is required".into());
                }
                if cfg.transport != "ldaps" && cfg.transport != "starttls" {
                    return Err("LDAP transport must be ldaps or starttls".into());
                }
                let mut client = LdapClient::new(
                    &cfg.host,
                    cfg.port,
                    cfg.transport == "ldaps",
                    &cfg.bind_dn,
                    &cfg.password,
                    &cfg.base_dn,
                );
                client.set_subject_attribute(&cfg.subject_attribute)?;
                admit_filter(&cfg.user_filter)?;
                Ok(Built::Ldap(Box::new(Worker {
                    client,
                    db: self.db.clone(),
                    interval_min: self.ldap_interval_min,
                    filter: cfg.user_filter.clone(),
                    source_key: Some(entry.key.clone()),
                    instance: new_uuid(),
                    enabled: true,
                })))
            }
            other => Err(format!("unsupported identity source kind {other:?}")),
        }
    }

    /// The manager loop: reconcile on a trigger or every poll interval until
    /// `shutdown` resolves, then stop every worker.
    pub async fn run_until(&self, shutdown: impl std::future::Future<Output = ()>) {
        tokio::pin!(shutdown);
        let mut ticker = tokio::time::interval(self.poll);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        ticker.tick().await;
        loop {
            tokio::select! {
                _ = &mut shutdown => break,
                _ = self.trigger.notified() => {}
                _ = ticker.tick() => {}
            }
            if let Err(error) = self.reconcile().await {
                log(&format!("reconciliation failed: {error}"));
            }
        }
        self.stop().await;
    }

    /// Stop and join every worker.
    pub async fn stop(&self) {
        self.supervise(Vec::new()).await;
    }

    /// `(source id, generation)` of the running workers, by id.
    pub async fn running(&self) -> Vec<(i64, i64)> {
        let mut out: Vec<_> = self
            .workers
            .lock()
            .await
            .iter()
            .map(|(id, w)| (*id, w.generation))
            .collect();
        out.sort_unstable();
        out
    }
}

fn join(errors: Vec<String>) -> Res<()> {
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("\n"))
    }
}

/// Why a directory probe failed (`identitySourceProbeBlocker`): a rejected bind
/// password is reported apart from every other failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProbeFailure {
    pub credential_rejected: bool,
}

/// Go `probeIdentitySourceRuntime`: connect, bind and read the user set of one
/// catalog source without a single database write (AD reads everything, LDAP
/// at most five entries per page). `db` only satisfies the worker type; the dry
/// run never opens it.
pub async fn probe(db: &WorkerDatabase, cfg: &SourceConfig) -> Result<(), ProbeFailure> {
    use crate::ldap::client::ClientError;
    let other = |_: String| ProbeFailure {
        credential_rejected: false,
    };
    let entry = Entry {
        source_id: 0,
        generation: 0,
        key: cfg.source_key.clone(),
        config: cfg.clone(),
    };
    let probe = IdentitySourceRuntime::new(db.clone(), |_, _, _, _| Err(String::new()), 15, 15);
    match probe.build(&entry).map_err(other)? {
        Built::Ldap(worker) => worker
            .dry_run(5)
            .await
            .map(|_| ())
            .map_err(|e| ProbeFailure {
                credential_rejected: e.class == crate::ldap::client::ConnClass::BindAuth,
            }),
        Built::Ad(worker) => {
            let (mut ldap, endpoint) = worker
                .client
                .connect()
                .await
                .map_err(|e| other(e.to_string()))?;
            if let Err(e) = endpoint.bind(&mut ldap).await {
                return Err(ProbeFailure {
                    credential_rejected: matches!(
                        e,
                        ClientError::Bind {
                            invalid_credentials: true,
                            ..
                        }
                    ),
                });
            }
            let found = worker.client.search_users(&mut ldap, 0).await;
            let _ = ldap.unbind().await;
            found.map(|_| ()).map_err(|e| other(e.to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Counts a worker's future being dropped (it ended or was aborted).
    struct Gone(Arc<std::sync::atomic::AtomicUsize>);
    impl Drop for Gone {
        fn drop(&mut self) {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    fn stalled(release_after: Option<Duration>) -> Running {
        stalled_counted(release_after, Arc::default())
    }

    fn stalled_counted(
        release_after: Option<Duration>,
        gone: Arc<std::sync::atomic::AtomicUsize>,
    ) -> Running {
        let (stop, stopped) = oneshot::channel::<()>();
        let task = tokio::spawn(async move {
            let _gone = Gone(gone);
            let _ = stopped.await;
            match release_after {
                Some(d) => tokio::time::sleep(d).await,
                None => std::future::pending::<()>().await,
            }
        });
        Running {
            generation: 1,
            stop,
            task,
        }
    }

    /// Eight workers that each need the full release window to stop must finish in about
    /// one window together (serial stopping would take 8 x 5 s = 40 s).
    #[tokio::test(start_paused = true)]
    async fn stalled_workers_stop_in_one_shared_window() {
        let started = tokio::time::Instant::now();
        stop_all((0..8).map(|_| stalled(Some(STOP_DEADLINE))).collect()).await;
        let took = started.elapsed();
        assert!(took >= STOP_DEADLINE, "stopped too early: {took:?}");
        assert!(
            took < STOP_DEADLINE + Duration::from_secs(2),
            "8 stalled workers took {took:?}, not about {STOP_DEADLINE:?}"
        );
    }

    /// A worker that never stops cannot extend the deadline, however many there are.
    #[tokio::test(start_paused = true)]
    async fn hung_workers_are_aborted_at_the_shared_deadline() {
        let gone = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let started = tokio::time::Instant::now();
        stop_all((0..8).map(|_| stalled_counted(None, gone.clone())).collect()).await;
        let took = started.elapsed();
        assert!(
            took < STOP_DEADLINE + STOP_GRACE + Duration::from_secs(2),
            "8 hung workers took {took:?}"
        );
        // Aborting must actually destroy the workers, not just stop waiting for them.
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(gone.load(std::sync::atomic::Ordering::SeqCst), 8, "hung workers were left running");
    }
}
