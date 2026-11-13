//! Go's in-process migration job runner (`migration.Orchestrator`, #431): the
//! job state machine behind `POST /admin/migration/{start,jobs/{id}/...}`, the
//! IMAP connector (`imap.rs`), `importMailItem` and the source factories. Every
//! write to `migration_jobs` is one `migration_orchestrate` reducer call; the
//! runner uses the worker credential (`DB_WORKER_DSN`). See the crate DOX.
use crate::recovery_worker::ObjectStore;
use serde_json::{json, Value};
use setjoin_mailboxes::migration as codec;
use setjoin_pg::workers::{WorkerConnection, WorkerDatabase};
use setjoin_pg::{Param, Row, Type};
use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use tokio::sync::{mpsc, watch};

mod auxiliary;
pub mod ews;
mod folder_i18n;
pub mod imap;
pub mod m365;

pub use imap::{ImapConfig, ImapConnector};

type BoxFut<T> = Pin<Box<dyn Future<Output = T> + Send>>;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ItemKind {
    Mail,
    Calendar,
    Contact,
}
impl ItemKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ItemKind::Mail => "mail",
            ItemKind::Calendar => "calendar",
            ItemKind::Contact => "contact",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Change {
    Upsert,
    Move,
    Delete,
}
impl Change {
    pub fn as_str(self) -> &'static str {
        match self {
            Change::Upsert => "upsert",
            Change::Move => "move",
            Change::Delete => "delete",
        }
    }
}

/// Go's `SourceObject`.
#[derive(Clone, Debug)]
pub struct SourceItem {
    pub kind: ItemKind,
    pub change: Change,
    pub object_id: String,
    pub version: String,
    pub folder_id: String,
    pub raw: Vec<u8>,
    pub ics: String,
    pub vcf: String,
    pub folder_path: Vec<String>,
    pub tags: Vec<String>,
    pub uid: u32,
    pub uid_validity: u32,
}

/// The cursor a closed page proposes (Go's `SourceCheckpointSnapshot`).
#[derive(Clone, Debug)]
pub enum Checkpoint {
    Imap {
        folder: String,
        uid: u32,
        uid_validity: u32,
    },
    /// `(scope, legacy scope, kind, value)` and the legacy `delta` patch.
    Delta {
        scope: String,
        legacy_scope: String,
        kind: &'static str,
        value: Value,
        legacy: Value,
    },
}

impl Checkpoint {
    /// `(scope, legacy_scope, kind, value)`.
    fn candidate(&self) -> (String, String, String, Value) {
        match self {
            Checkpoint::Imap {
                folder,
                uid,
                uid_validity,
            } => (
                folder.clone(),
                folder.clone(),
                "imap_uid".into(),
                json!({"uid": uid, "uidValidity": uid_validity}),
            ),
            Checkpoint::Delta {
                scope,
                legacy_scope,
                kind,
                value,
                ..
            } => (
                scope.clone(),
                legacy_scope.clone(),
                (*kind).into(),
                value.clone(),
            ),
        }
    }
    fn legacy_patch(&self) -> Option<Value> {
        match self {
            Checkpoint::Imap { folder, uid, .. } => {
                Some(json!({"cursor_uids": {folder.clone(): uid}}))
            }
            Checkpoint::Delta { legacy, .. } => Some(legacy.clone()),
        }
    }
}

pub struct Batch {
    pub items: Vec<SourceItem>,
    pub checkpoint: Checkpoint,
}

/// `dedupeSourceBatch`.
/// Owner-approved security fix 2026-11-05 (#547): after defaults are merged, a job that is not
/// administrator-created never runs in clear. This covers an omitted mode that inherited the
/// administrator's `none` and jobs created before the self-service routes refused it.
fn refuse_plaintext(cfg: &ImapConfig, admin_job: bool) -> Result<(), String> {
    if !admin_job
        && cfg.tls_mode == "none"
        && !setjoin_contracts::mutants::on("self-service-runs-plaintext-imap")
    {
        return Err("plaintext IMAP (tls_mode none) is not allowed for a self-service job".into());
    }
    Ok(())
}

fn dedupe(items: Vec<SourceItem>) -> Vec<SourceItem> {
    let mut seen = std::collections::HashSet::new();
    let mut uids: HashMap<String, std::collections::HashSet<u32>> = HashMap::new();
    let mut out = vec![];
    for item in items {
        let key = format!(
            "{}\0{}\0{}\0{}\0{}",
            item.kind.as_str(),
            item.object_id,
            item.version,
            item.change.as_str(),
            item.folder_id
        );
        if !seen.insert(key) {
            continue;
        }
        if item.uid != 0
            && !uids
                .entry(item.folder_id.clone())
                .or_default()
                .insert(item.uid)
        {
            continue;
        }
        out.push(item);
    }
    out
}

/// How a connector reaches a host: resolution and the connection are separate so the
/// SSRF policy judges exactly the addresses that are dialed. Tests replace both.
type Resolve = Arc<dyn Fn(String) -> BoxFut<Result<Vec<IpAddr>, String>> + Send + Sync>;
type Connect = Arc<dyn Fn(SocketAddr) -> BoxFut<Result<Box<dyn imap::Io>, String>> + Send + Sync>;

#[derive(Clone)]
pub struct Dialer {
    resolve: Resolve,
    connect: Connect,
}

pub const UNSAFE: &str = "URL is not allowed (must be http/https to a public host)";

impl Dialer {
    pub fn system() -> Self {
        Dialer {
            resolve: Arc::new(|host| {
                Box::pin(async move {
                    if let Ok(ip) = host.parse::<IpAddr>() {
                        return Ok(vec![ip]);
                    }
                    tokio::net::lookup_host((host.as_str(), 0))
                        .await
                        .map(|a| a.map(|s| s.ip()).collect())
                        .map_err(|e| e.to_string())
                })
            }),
            connect: Arc::new(|address| {
                Box::pin(async move {
                    let stream = tokio::time::timeout(
                        std::time::Duration::from_secs(10),
                        tokio::net::TcpStream::connect(address),
                    )
                    .await
                    .map_err(|_| format!("dial tcp {address}: i/o timeout"))?
                    .map_err(|e| format!("dial tcp {address}: {}", imap::dial_error(&e)))?;
                    Ok(Box::new(stream) as Box<dyn imap::Io>)
                })
            }),
        }
    }

    /// A seam for tests: names resolve through `resolve`, connections go to `connect`.
    pub fn custom(
        resolve: impl Fn(String) -> BoxFut<Result<Vec<IpAddr>, String>> + Send + Sync + 'static,
        connect: impl Fn(SocketAddr) -> BoxFut<Result<Box<dyn imap::Io>, String>>
            + Send
            + Sync
            + 'static,
    ) -> Self {
        Dialer {
            resolve: Arc::new(resolve),
            connect: Arc::new(connect),
        }
    }

    /// Go's `ssrf.DialContextWithPrivatePolicy`: every answer must pass the policy.
    pub async fn dial(
        &self,
        host: &str,
        port: u16,
        private_hosts: &[String],
        private_cidrs: &[String],
    ) -> Result<Box<dyn imap::Io>, String> {
        setjoin_mailboxes::private_policy::compile_private_policy(private_hosts, private_cidrs)
            .map_err(|e| format!("invalid IMAP source policy: {e}"))?;
        let ips = (self.resolve)(host.to_owned()).await.unwrap_or_default();
        if ips.is_empty() {
            return Err(UNSAFE.into());
        }
        for ip in &ips {
            if !setjoin_mailboxes::private_policy::dial_allowed(
                private_hosts,
                private_cidrs,
                host,
                *ip,
            ) {
                return Err(UNSAFE.into());
            }
        }
        let mut last = UNSAFE.to_owned();
        for ip in ips {
            match (self.connect)(SocketAddr::new(ip, port)).await {
                Ok(stream) => return Ok(stream),
                Err(e) => last = e,
            }
        }
        Err(last)
    }
}

/// The per-job control block (`jobState`): cancel, a one-slot pause token and a
/// one-slot resume token.
#[allow(dead_code)] // `resume_rx`: Go's resume token is only read inside the pause branch it never leaves
struct JobState {
    cancel: watch::Sender<bool>,
    pause_tx: mpsc::Sender<()>,
    pause_rx: tokio::sync::Mutex<mpsc::Receiver<()>>,
    resume_tx: mpsc::Sender<()>,
    resume_rx: tokio::sync::Mutex<mpsc::Receiver<()>>,
}

impl JobState {
    fn cancelled(&self) -> bool {
        *self.cancel.borrow()
    }
    async fn wait_cancel(&self) {
        let mut rx = self.cancel.subscribe();
        while !*rx.borrow() {
            if rx.changed().await.is_err() {
                std::future::pending::<()>().await;
            }
        }
    }
}

pub struct Config {
    pub db: WorkerDatabase,
    pub store: Arc<dyn ObjectStore>,
    /// Raw `DB_ENCRYPTION_KEY`.
    pub root: String,
    pub dialer: Dialer,
    /// Go's `terminalEventDispatcher`: terminal `migration.*` events go through it.
    /// `None` is Go's nil dispatcher (events are not delivered).
    pub dispatcher: Option<crate::webhook::Dispatcher>,
}

#[allow(dead_code)] // `root`/`system_key`: the sealed EWS/M365 profiles (next milestones)
pub struct Inner {
    db: WorkerDatabase,
    store: Arc<dyn ObjectStore>,
    root: String,
    key: Option<[u8; 32]>,
    system_key: Option<[u8; 32]>,
    dialer: Dialer,
    provider_client: Option<reqwest::Client>,
    dispatcher: Option<crate::webhook::Dispatcher>,
    active: Mutex<HashMap<i64, Arc<JobState>>>,
    stopping: std::sync::atomic::AtomicBool,
}

#[derive(Clone)]
pub struct Orchestrator(pub Arc<Inner>);

/// A lazily opened worker connection that reconnects once after an error.
struct Db {
    db: WorkerDatabase,
    conn: tokio::sync::Mutex<Option<WorkerConnection>>,
}

impl Db {
    async fn query(&self, sql: &str, params: &[Param<'_>]) -> Result<Vec<Row>, String> {
        let mut guard = self.conn.lock().await;
        for attempt in 0..2 {
            if guard.is_none() {
                *guard = Some(self.db.connect_session().await.map_err(|e| e.to_string())?);
            }
            match guard.as_ref().expect("connection").query(sql, params).await {
                Ok(rows) => return Ok(rows),
                Err(error) => {
                    // A database error (SQLSTATE present) is final; a lost
                    // connection is retried on a fresh one.
                    if attempt == 1 || error.contains("SQLSTATE") {
                        return Err(error);
                    }
                    *guard = None;
                }
            }
        }
        unreachable!()
    }
}

struct JobRow {
    user_id: i64,
    source_type: String,
    config_enc: Option<Vec<u8>>,
    status: String,
    conflict_strategy: String,
}

fn hash_color(name: &str) -> String {
    use sha2::{Digest, Sha256};
    format!("#{}", imap::hex(&Sha256::digest(name.as_bytes())[..3]))
}

/// `migrationOperationID`: a version-5 UUID over the object identity.
fn operation_id(job: i64, item: &SourceItem) -> String {
    use sha2::{Digest, Sha256};
    // uuid.NewSHA1(NameSpaceOID, key) is SHA-1; ring provides it.
    let _ = Sha256::new();
    let key = format!(
        "{job}\0{}\0{}\0{}\0{}",
        item.kind.as_str(),
        item.object_id,
        item.version,
        item.change.as_str()
    );
    let mut context = ring::digest::Context::new(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY);
    // NameSpaceOID
    context.update(&[
        0x6b, 0xa7, 0xb8, 0x12, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30,
        0xc8,
    ]);
    context.update(key.as_bytes());
    let digest = context.finish();
    let mut b = [0u8; 16];
    b.copy_from_slice(&digest.as_ref()[..16]);
    b[6] = (b[6] & 0x0f) | 0x50;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h = imap::hex(&b);
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

/// Progress counters of one connector phase (`phaseProgress`).
#[derive(Default)]
struct Progress {
    items_done: i64,
    items_failed: i64,
    imported: i64,
    updated: i64,
    moved: i64,
    deleted: i64,
    unchanged: i64,
    replayed: i64,
    current_folder: Option<String>,
    /// Go's `currentFolder` (starts empty, so an empty path never reports).
    tracked_folder: String,
}
impl Progress {
    fn json(&self) -> Value {
        let mut m = serde_json::Map::new();
        m.insert("items_done".into(), self.items_done.into());
        m.insert("items_failed".into(), self.items_failed.into());
        m.insert("imported".into(), self.imported.into());
        m.insert("updated".into(), self.updated.into());
        m.insert("moved".into(), self.moved.into());
        m.insert("deleted".into(), self.deleted.into());
        m.insert("unchanged".into(), self.unchanged.into());
        m.insert("replayed".into(), self.replayed.into());
        if let Some(folder) = &self.current_folder {
            m.insert("current_folder".into(), folder.clone().into());
        }
        Value::Object(m)
    }
    fn count(&mut self, outcome: &str) {
        match outcome {
            "imported" => self.imported += 1,
            "updated" => self.updated += 1,
            "moved" => self.moved += 1,
            "deleted" => self.deleted += 1,
            "unchanged" => self.unchanged += 1,
            "replayed" => self.replayed += 1,
            _ => {}
        }
    }
}

enum Source {
    Imap(ImapConnector),
    Ews(ews::EwsConnector),
    M365(m365::M365Connector),
}

impl Source {
    async fn identity(&mut self) -> Result<(String, String, String), String> {
        match self {
            Source::Imap(c) => c.identity().map(|(k, d)| ("imap".to_owned(), k, d)),
            Source::Ews(c) => c.identity().map(|(k, d)| ("ews".into(), k, d)),
            Source::M365(c) => c.identity().await.map(|(k, d)| ("m365".into(), k, d)),
        }
    }
    async fn next_batch(&mut self) -> Result<Option<Batch>, String> {
        match self {
            Source::Imap(c) => c.next_batch().await,
            Source::Ews(c) => c.next_batch().await,
            Source::M365(c) => c.next_batch().await,
        }
    }
}

/// Why a connector phase ended without finishing.
enum Stop {
    /// Go's `ctx.Err() != nil`: the job context was cancelled.
    Context,
    Failed(String),
}

impl Orchestrator {
    pub fn new(config: Config) -> Self {
        Self::with_provider_client(config, None)
    }
    /// Supply a trusted HTTPS transport to the provider oracle, keeping endpoint selection in the connector.
    pub fn with_provider_client(config: Config, provider_client: Option<reqwest::Client>) -> Self {
        Orchestrator(Arc::new(Inner {
            key: codec::derive_key(&config.root, "migration"),
            system_key: codec::derive_key(&config.root, "system"),
            db: config.db,
            store: config.store,
            root: config.root,
            dialer: config.dialer,
            provider_client,
            dispatcher: config.dispatcher,
            active: Mutex::new(HashMap::new()),
            stopping: Default::default(),
        }))
    }

    /// `StartJob`: begin a job on a background task.
    pub fn start_job(&self, id: i64) -> Result<(), String> {
        let mut active = self.0.active.lock().expect("active jobs");
        if active.contains_key(&id) {
            return Err(format!("job {id} is already running"));
        }
        let (cancel, _) = watch::channel(false);
        let (pause_tx, pause_rx) = mpsc::channel(1);
        let (resume_tx, resume_rx) = mpsc::channel(1);
        let js = Arc::new(JobState {
            cancel,
            pause_tx,
            pause_rx: tokio::sync::Mutex::new(pause_rx),
            resume_tx,
            resume_rx: tokio::sync::Mutex::new(resume_rx),
        });
        active.insert(id, js.clone());
        drop(active);
        let inner = self.0.clone();
        tokio::spawn(async move {
            inner.clone().run_job(id, js).await;
            inner.active.lock().expect("active jobs").remove(&id);
        });
        Ok(())
    }

    fn state(&self, id: i64) -> Option<Arc<JobState>> {
        self.0.active.lock().expect("active jobs").get(&id).cloned()
    }

    pub fn cancel_job(&self, id: i64) -> Result<(), String> {
        let js = self
            .state(id)
            .ok_or_else(|| format!("job {id} is not running"))?;
        let _ = js.cancel.send(true);
        Ok(())
    }

    pub fn pause_job(&self, id: i64) -> Result<(), String> {
        let js = self
            .state(id)
            .ok_or_else(|| format!("job {id} is not running"))?;
        let _ = js.pause_tx.try_send(());
        Ok(())
    }

    /// `ResumeJob`: a running (or parked) job gets a resume token; a job whose
    /// goroutine already returned is started again.
    pub fn resume_job(&self, id: i64) -> Result<(), String> {
        match self.state(id) {
            Some(js) => {
                let _ = js.resume_tx.try_send(());
                Ok(())
            }
            None => self.start_job(id),
        }
    }

    pub fn is_running(&self, id: i64) -> bool {
        self.state(id).is_some()
    }

    /// `Shutdown`: ask every running job to pause (it parks at its next item).
    pub fn shutdown(&self) {
        self.0
            .stopping
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let jobs: Vec<_> = self
            .0
            .active
            .lock()
            .expect("active jobs")
            .values()
            .cloned()
            .collect();
        for js in jobs {
            let _ = js.pause_tx.try_send(());
        }
    }

    /// Store raw migration inputs; the HTTP caller first proves job ownership.
    pub async fn store_upload(&self,id:i64,ics:Option<&[u8]>,vcf:Option<&[u8]>)->Result<(),String> {
        for (suffix,data) in [("ics",ics),("vcf",vcf)] {
            if let Some(data)=data.filter(|bytes|!bytes.is_empty()) {
                self.0.store.put(&format!("migration/upload/{id}/{suffix}"),data,"application/octet-stream").await
                    .map_err(|error|format!("store {suffix} upload: {error}"))?;
            }
        }
        Ok(())
    }

    pub fn encryption_key(&self) -> Option<[u8; 32]> {
        self.0.key
    }

    pub fn dialer(&self) -> Dialer {
        self.0.dialer.clone()
    }

    pub fn ews(&self, cfg: ews::EwsConfig) -> Result<ews::EwsConnector, String> {
        match &self.0.provider_client {
            Some(c) => ews::EwsConnector::with_client(cfg, c.clone()),
            None => ews::EwsConnector::new(cfg),
        }
    }
    pub fn m365(&self, cfg: m365::M365Config) -> Result<m365::M365Connector, String> {
        match &self.0.provider_client {
            Some(c) => Ok(m365::M365Connector::with_client(cfg, c.clone())),
            None => m365::M365Connector::new(cfg),
        }
    }

    /// Test seam (#536): the legacy-arm calendar/contact projection of one source object for
    /// the job's target mailbox (the `mail_migration_source_identity` OFF path).
    #[doc(hidden)]
    pub async fn project_legacy_aux(
        &self,
        id: i64,
        mailbox: i64,
        item: &SourceItem,
    ) -> Result<String, String> {
        let db = self.0.db();
        self.0.import_aux_item(&db, id, mailbox, item, false).await
    }

    pub fn worker(&self) -> &WorkerDatabase {
        &self.0.db
    }

    /// Go's `orchestrate`, the one seam every job mutation (and its terminal webhook
    /// event) flows through; the runner's phases and the oracle both enter here.
    pub async fn orchestrate(
        &self,
        id: i64,
        phase: &str,
        patch: Option<Value>,
    ) -> Result<String, String> {
        let db = self.0.db();
        self.0.orchestrate(&db, id, phase, patch).await
    }

    /// `RecoverStuckJobs` at startup.
    pub async fn recover_stuck(&self) -> Result<usize, String> {
        let c = self
            .0
            .db
            .connect_session()
            .await
            .map_err(|e| e.to_string())?;
        let rows = c
            .query("SELECT migration_recover_stuck()::text", &[])
            .await?;
        let text: String = rows[0].get(0);
        let v: Value = serde_json::from_str(&text).map_err(|e| e.to_string())?;
        let count = v["ids"].as_array().map_or(0, Vec::len);
        if count > 0 {
            for event in v["terminal_events"].as_array().into_iter().flatten() {
                let job = event["job_id"].as_i64().unwrap_or_default();
                self.0.dispatch_terminal_event(job, event).await;
            }
        }
        Ok(count)
    }
}

impl Inner {
    fn db(&self) -> Db {
        Db {
            db: self.db.clone(),
            conn: tokio::sync::Mutex::new(None),
        }
    }

    /// `orchestrate`: the single seam for every `migration_jobs` mutation. The
    /// reducer's own error is returned; Go callers ignore it.
    async fn orchestrate(
        &self,
        db: &Db,
        id: i64,
        phase: &str,
        patch: Option<Value>,
    ) -> Result<String, String> {
        let patch = patch.map_or_else(|| "null".to_owned(), |v| v.to_string());
        let rows = db
            .query(
                "SELECT migration_orchestrate($1, $2, $3::text::jsonb)::text",
                &[
                    (&id, Type::INT8),
                    (&phase, Type::TEXT),
                    (&patch, Type::TEXT),
                ],
            )
            .await
            .inspect_err(|e| {
                eprintln!("migration: orchestrate failed job_id={id} phase={phase} error={e}")
            })?;
        let text: String = rows[0].get(0);
        let v: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
        self.dispatch_terminal_event(id, &v).await;
        Ok(v["status"].as_str().unwrap_or_default().to_owned())
    }

    /// `dispatchTerminalEvent`: the reducer names the terminal event; one it already
    /// enrolled in the publication outbox is not dispatched again. A mailbox-scoped job
    /// fans out to the mailbox's subscribers, any other to the subject user's.
    async fn dispatch_terminal_event(&self, job_id: i64, event: &Value) {
        let kind = event["event_type"].as_str().unwrap_or_default();
        let user = event["subject_user_id"].as_i64().unwrap_or_default();
        let Some(dispatcher) = &self.dispatcher else {
            return;
        };
        if event["publication_enrolled"].as_bool().unwrap_or(false) || kind.is_empty() || user == 0
        {
            return;
        }
        let cloud = crate::webhook::CloudEvent::new(
            "mailserver/gateway",
            kind,
            json!({ "job_id": job_id }),
        );
        match event["subject_mailbox_id"].as_i64() {
            Some(mailbox) => dispatcher.dispatch_for_mailbox(user, mailbox, &cloud).await,
            None => dispatcher.dispatch_for_user(user, &cloud).await,
        }
    }

    async fn update_progress(&self, db: &Db, id: i64, phase: &str, data: Value) {
        let _ = self
            .orchestrate(db, id, "progress", Some(json!({"progress": {phase: data}})))
            .await;
    }

    async fn load_job(&self, db: &Db, id: i64) -> Option<JobRow> {
        let rows = db
            .query(
                "SELECT user_id, source_type, source_config_enc, status, conflict_strategy \
                 FROM migration_jobs WHERE id = $1",
                &[(&id, Type::INT8)],
            )
            .await
            .ok()?;
        let r = rows.first()?;
        Some(JobRow {
            user_id: r.get(0),
            source_type: r.get(1),
            config_enc: r.get(2),
            status: r.get(3),
            conflict_strategy: r.get(4),
        })
    }

    /// `loadLegacySourceResume`: `{"uids": {...}, "delta": {...}}` or a flat folder map.
    async fn load_resume(&self, db: &Db, id: i64) -> BTreeMap<String, i64> {
        let raw: String = db
            .query(
                "SELECT COALESCE(resume_cursor, '{}') FROM migration_jobs WHERE id = $1",
                &[(&id, Type::INT8)],
            )
            .await
            .ok()
            .and_then(|r| r.first().map(|r| r.get(0)))
            .unwrap_or_default();
        let v: Value = serde_json::from_str(&raw).unwrap_or(Value::Null);
        let ints = |m: &Value| -> Option<BTreeMap<String, i64>> {
            m.as_object()?
                .iter()
                .map(|(k, v)| Some((k.clone(), v.as_i64()?)))
                .collect()
        };
        if let Some(uids) = v.get("uids").and_then(ints) {
            let delta = v
                .get("delta")
                .and_then(Value::as_object)
                .map_or(0, |m| m.len());
            if !uids.is_empty() || delta > 0 {
                return uids;
            }
        } else if v
            .get("delta")
            .and_then(Value::as_object)
            .is_some_and(|m| !m.is_empty())
        {
            return BTreeMap::new();
        }
        ints(&v).unwrap_or_default()
    }

    async fn run_job(self: Arc<Self>, id: i64, js: Arc<JobState>) {
        let db = self.db();
        let Some(job) = self.load_job(&db, id).await else {
            eprintln!("migration: load job failed job_id={id}");
            return;
        };
        let resume = self.load_resume(&db, id).await;
        if job.status == "paused" {
            let _ = self.orchestrate(&db, id, "resume", None).await;
        } else {
            let _ = self.orchestrate(&db, id, "start", None).await;
        }
        let single = matches!(job.source_type.as_str(), "imap" | "ews" | "m365")
            || job
                .source_type
                .split('|')
                .map(str::trim)
                .any(|s| s == "imap");
        if single {
            let source = self
                .create_source(
                    &db,
                    if job.source_type.contains('|') {
                        "imap"
                    } else {
                        &job.source_type
                    },
                    job.config_enc.as_deref(),
                )
                .await;
            let mut source = match source {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("migration: create connector failed job_id={id} error={e}");
                    let _ = self
                        .orchestrate(
                            &db,
                            id,
                            "fail",
                            Some(json!({"errors": [format!("connector: {e}")]})),
                        )
                        .await;
                    return;
                }
            };
            match self
                .connector_phase(&db, id, &mut source, resume.clone(), &js)
                .await
            {
                Err(Stop::Context) => {
                    self.finalize(&db, id).await;
                    return;
                }
                Err(Stop::Failed(e)) => {
                    if js.cancelled() {
                        self.finalize(&db, id).await;
                        return;
                    }
                    let _ = self
                        .orchestrate(&db, id, "fail", Some(json!({"errors": [e]})))
                        .await;
                    return;
                }
                Ok(()) => {}
            }
            if js.cancelled() {
                self.finalize(&db, id).await;
                return;
            }
        }
        for phase in ["ics", "vcf"] {
            if job
                .source_type
                .split('|')
                .map(str::trim)
                .any(|s| s == phase)
            {
                // Go's upload phase carries the job context into object/DB I/O.
                // Keep cancellation subscribed while that I/O is pending too.
                tokio::select! {
                    biased;
                    _ = js.wait_cancel() => {
                        self.finalize(&db, id).await;
                        return;
                    }
                    _ = self.upload_phase(&db, id, &job, phase) => {}
                }
                if js.cancelled() {
                    self.finalize(&db, id).await;
                    return;
                }
            }
        }
        let _ = self.orchestrate(&db, id, "complete", None).await;
    }

    /// `finalizePauseOrCancel` (`shouldPause` is never set, so this is always a cancel).
    async fn finalize(&self, db: &Db, id: i64) {
        let _ = self.orchestrate(db, id, "cancel", None).await;
    }

    async fn create_source(
        &self,
        db: &Db,
        source_type: &str,
        config_enc: Option<&[u8]>,
    ) -> Result<Source, String> {
        let config = self.decrypt_job_config(config_enc)?;
        let use_global = config
            .get("use_global_auth")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        match source_type {
            "imap" => {
                let cfg = self.imap_config(db, &config, use_global).await?;
                Ok(Source::Imap(ImapConnector::new(cfg, self.dialer.clone())))
            }
            "ews" => {
                let cfg = self.ews_config(db, &config, use_global).await?;
                let connector = match &self.provider_client {
                    Some(c) => ews::EwsConnector::with_client(cfg, c.clone()),
                    None => ews::EwsConnector::new(cfg),
                }?;
                Ok(Source::Ews(connector))
            }
            "m365" => {
                let cfg = self.m365_config(db, &config, use_global).await?;
                let connector = match &self.provider_client {
                    Some(c) => m365::M365Connector::with_client(cfg, c.clone()),
                    None => m365::M365Connector::new(cfg)?,
                };
                Ok(Source::M365(connector))
            }
            _ => {
                let cfg = self.imap_config(db, &config, use_global).await?;
                Ok(Source::Imap(ImapConnector::new(cfg, self.dialer.clone())))
            }
        }
    }

    /// `DecryptConfigAny` into the job wrapper.
    fn decrypt_job_config(&self, enc: Option<&[u8]>) -> Result<Value, String> {
        let data = enc.unwrap_or_default();
        let err = |e: &str| format!("decrypt job config: {e}");
        let key = self.key.ok_or_else(|| err("cipher: invalid key size"))?;
        if data.len() < 12 {
            return Err(err("migration: ciphertext too short"));
        }
        let plain =
            codec::open(data, &key).ok_or_else(|| err("cipher: message authentication failed"))?;
        serde_json::from_slice(&plain).map_err(|e| err(&e.to_string()))
    }

    async fn imap_config(
        &self,
        db: &Db,
        job: &Value,
        use_global: bool,
    ) -> Result<ImapConfig, String> {
        let s = |v: &Value, k: &str| v.get(k).and_then(Value::as_str).unwrap_or("").to_owned();
        let list = |v: &Value, k: &str| -> Vec<String> {
            v.get(k)
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .map(|x| x.as_str().unwrap_or("").to_owned())
                        .collect()
                })
                .unwrap_or_default()
        };
        let imap = job.get("imap").filter(|v| !v.is_null());
        let cred = |v: &Value| v.get("credentials").cloned().unwrap_or(Value::Null);
        let cfg = if use_global {
            let rows = db
                .query(
                    "SELECT value::text FROM system_config WHERE key = 'imap.defaults'",
                    &[],
                )
                .await
                .map_err(|e| {
                    format!("merge global config: no global IMAP config in system_config: {e}")
                })?;
            let Some(row) = rows.first() else {
                return Err("merge global config: no global IMAP config in system_config: no rows in result set".into());
            };
            let text: String = row.get(0);
            let global: Value = serde_json::from_str(&text)
                .map_err(|e| format!("merge global config: parse global IMAP config: {e}"))?;
            let mut cfg = ImapConfig {
                host: s(&global, "host"),
                port: global.get("port").and_then(Value::as_i64).unwrap_or(0),
                tls_mode: s(&global, "tls_mode"),
                private_hosts: list(&global, "private_hosts"),
                private_cidrs: list(&global, "private_cidrs"),
                ..Default::default()
            };
            if let Some(imap) = imap {
                if !s(imap, "host").is_empty() {
                    cfg.host = s(imap, "host");
                }
                let port = imap.get("port").and_then(Value::as_i64).unwrap_or(0);
                if port != 0 {
                    cfg.port = port;
                }
                if !s(imap, "tls_mode").is_empty() {
                    cfg.tls_mode = s(imap, "tls_mode");
                }
                let c = cred(imap);
                if !s(&c, "username").is_empty() {
                    cfg.username = s(&c, "username");
                    cfg.password = s(&c, "password");
                }
            }
            if cfg.host.is_empty() {
                return Err("merge global config: IMAP host is required".into());
            }
            // Owner-approved security fix 2026-11-05 (#547): the host above may be the caller's
            // own (a self-service job overrides it), so the administrator's private-network
            // allowlist must never ride along; only an administrator-created job
            // (`self_service: false`) inherits it. A job without the marker is treated as the
            // caller's. Frozen Go inherited it for every job, letting a user reach any internal
            // host the admin had allowlisted.
            let admin_job = job.get("self_service").and_then(Value::as_bool) == Some(false);
            if !admin_job && !setjoin_contracts::mutants::on("self-service-inherits-private-allowlist") {
                cfg.private_hosts.clear();
                cfg.private_cidrs.clear();
            }
            refuse_plaintext(&cfg, admin_job)?;
            cfg
        } else {
            // A legacy bare-config blob has no wrapper fields.
            let inner = imap.unwrap_or(job);
            let c = cred(inner);
            let cfg = ImapConfig {
                host: s(inner, "host"),
                port: inner.get("port").and_then(Value::as_i64).unwrap_or(0),
                tls_mode: s(inner, "tls_mode"),
                private_hosts: list(inner, "private_hosts"),
                private_cidrs: list(inner, "private_cidrs"),
                username: s(&c, "username"),
                password: s(&c, "password"),
            };
            if !cfg.private_hosts.is_empty() || !cfg.private_cidrs.is_empty() {
                return Err("migration private-network policy is administrator-owned; per-job privateHosts/privateCIDRs are not accepted".into());
            }
            refuse_plaintext(&cfg, job.get("self_service").and_then(Value::as_bool) == Some(false))?;
            cfg
        };
        Ok(cfg)
    }

    async fn feature_enabled(&self, db: &Db, key: &str) -> bool {
        db.query(
            "SELECT enabled FROM feature_toggles WHERE key=$1",
            &[(&key, Type::TEXT)],
        )
        .await
        .ok()
        .and_then(|r| r.first().map(|r| r.get::<_, bool>(0)))
        .unwrap_or(false)
    }

    /// `runConnectorPhase` for the mail-bearing sources.
    async fn connector_phase(
        &self,
        db: &Db,
        id: i64,
        source: &mut Source,
        resume: BTreeMap<String, i64>,
        js: &JobState,
    ) -> Result<(), Stop> {
        let mailbox: i64 = db
            .query(
                "SELECT target_mailbox_id FROM migration_jobs WHERE id = $1",
                &[(&id, Type::INT8)],
            )
            .await
            .ok()
            .and_then(|r| {
                r.first()
                    .and_then(|r| r.try_get::<_, Option<i64>>(0).ok().flatten())
            })
            .unwrap_or(0);
        if mailbox == 0 {
            return Err(Stop::Failed("migration target mailbox is missing".into()));
        }
        let (source_type, mailbox_key, digest) = source
            .identity()
            .await
            .map_err(|e| Stop::Failed(format!("resolve source mailbox: {e}")))?;
        let use_identity = self
            .feature_enabled(db, "feature.mail_migration_source_identity")
            .await;
        let mut generation = 1i64;
        let mut durable: Vec<(String, String, Value)> = vec![];
        if use_identity {
            generation = self
                .bind_source(db, id, &source_type, &mailbox_key, &digest)
                .await
                .map_err(Stop::Failed)?;
            let (_, k2, d2) = source
                .identity()
                .await
                .map_err(|e| Stop::Failed(format!("revalidate source mailbox: {e}")))?;
            if k2 != mailbox_key || d2 != digest {
                return Err(Stop::Failed(
                    "source mailbox changed between preflight and enumeration".into(),
                ));
            }
            durable = self.load_checkpoints(db, id, generation).await;
        }
        let delta = self.load_delta(db, id).await;
        match source {
            Source::Imap(c) => c.restore(&resume, &durable).map_err(Stop::Failed)?,
            Source::Ews(c) => c.restore(&delta, &durable).map_err(Stop::Failed)?,
            Source::M365(c) => c.restore(&delta, &durable).map_err(Stop::Failed)?,
        }
        let mut progress = Progress::default();
        let mut last_save = std::time::Instant::now();
        loop {
            let batch = tokio::select! {
                biased;
                _ = js.wait_cancel() => Err(Stop::Context),
                b = source.next_batch() => b.map_err(Stop::Failed),
            };
            let batch = match batch {
                Ok(Some(batch)) => batch,
                Ok(None) => break,
                Err(stop) => {
                    // Progress is saved before the failure is reported.
                    self.update_progress(db, id, "connector", progress.json())
                        .await;
                    return Err(stop);
                }
            };
            let result = self
                .handle_batch(
                    db,
                    id,
                    mailbox,
                    js,
                    batch,
                    &mut progress,
                    use_identity,
                    generation,
                )
                .await;
            if let Err(stop) = result {
                self.update_progress(db, id, "connector", progress.json())
                    .await;
                return Err(stop);
            }
            if last_save.elapsed() > std::time::Duration::from_secs(10) {
                self.update_progress(db, id, "connector", progress.json())
                    .await;
                last_save = std::time::Instant::now();
            }
        }
        self.update_progress(db, id, "connector", progress.json())
            .await;
        if use_identity {
            self.thread_reconcile(db, id).await.map_err(Stop::Failed)?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn handle_batch(
        &self,
        db: &Db,
        id: i64,
        mailbox: i64,
        js: &JobState,
        batch: Batch,
        progress: &mut Progress,
        use_identity: bool,
        generation: i64,
    ) -> Result<(), Stop> {
        for mut item in dedupe(batch.items) {
            if js.cancelled() {
                return Err(Stop::Context);
            }
            if js.pause_rx.lock().await.try_recv().is_ok() {
                // Go sends on `pauseAck`, which nothing ever receives: the job
                // goroutine blocks here for good (see the crate DOX, BUGS).
                std::future::pending::<()>().await;
            }
            if item.object_id.is_empty() {
                return Err(Stop::Failed(format!(
                    "connector returned {} object without immutable source id",
                    item.kind.as_str()
                )));
            }
            if item.change == Change::Delete && !use_identity {
                continue;
            }
            let folder_key = item.folder_path.join("/");
            if folder_key != progress.tracked_folder {
                progress.tracked_folder = folder_key.clone();
                progress.current_folder = Some(folder_key);
            }
            match item.kind {
                ItemKind::Mail => {
                    match self
                        .import_mail_item(db, id, mailbox, &mut item, use_identity)
                        .await
                    {
                        Ok(outcome) => progress.count(&outcome),
                        Err(e) => {
                            progress.items_failed += 1;
                            return Err(Stop::Failed(format!(
                                "import source object {}: {e}",
                                imap::go_quote(&item.object_id)
                            )));
                        }
                    }
                }
                ItemKind::Calendar | ItemKind::Contact => {
                    match self
                        .import_aux_item(db, id, mailbox, &item, use_identity)
                        .await
                    {
                        Ok(outcome) => progress.count(&outcome),
                        Err(error) => {
                            progress.items_failed += 1;
                            let kind = if item.kind == ItemKind::Calendar {
                                "event"
                            } else {
                                "contact"
                            };
                            return Err(Stop::Failed(format!(
                                "import source {kind} {}: {error}",
                                imap::go_quote(&item.object_id)
                            )));
                        }
                    }
                }
            }
            progress.items_done += 1;
        }
        self.commit_checkpoint(
            db,
            id,
            &batch.checkpoint,
            generation,
            progress.items_done,
            use_identity,
        )
        .await
        .map_err(Stop::Failed)
    }

    async fn commit_checkpoint(
        &self,
        db: &Db,
        id: i64,
        checkpoint: &Checkpoint,
        generation: i64,
        committed: i64,
        use_identity: bool,
    ) -> Result<(), String> {
        if use_identity {
            let (scope, legacy, kind, value) = checkpoint.candidate();
            if scope.is_empty() || legacy.is_empty() || kind.is_empty() {
                return Err("source session returned an incomplete checkpoint candidate".into());
            }
            let value = value.to_string();
            db.query(
                "SELECT migration_checkpoint_commit_v2($1,$2,$3,$4,$5::text::jsonb,$6,$7)::text",
                &[
                    (&id, Type::INT8),
                    (&scope, Type::TEXT),
                    (&legacy, Type::TEXT),
                    (&kind, Type::TEXT),
                    (&value, Type::TEXT),
                    (&generation, Type::INT8),
                    (&committed, Type::INT8),
                ],
            )
            .await
            .map_err(|e| format!("commit {kind} checkpoint {}: {e}", imap::go_quote(&scope)))?;
            return Ok(());
        }
        if let Some(patch) = checkpoint.legacy_patch() {
            let _ = self.orchestrate(db, id, "progress", Some(patch)).await;
        }
        Ok(())
    }

    async fn bind_source(
        &self,
        db: &Db,
        id: i64,
        source_type: &str,
        key: &str,
        digest: &str,
    ) -> Result<i64, String> {
        let rows = db
            .query(
                "SELECT migration_source_bind($1,$2,$3,$4)::text",
                &[
                    (&id, Type::INT8),
                    (&source_type, Type::TEXT),
                    (&key, Type::TEXT),
                    (&digest, Type::TEXT),
                ],
            )
            .await
            .map_err(|e| format!("bind source mailbox: {e}"))?;
        let instance: String = rows[0].get(0);
        let rows = db
            .query(
                "SELECT generation FROM migration_source_instances WHERE id=$1::text::uuid",
                &[(&instance, Type::TEXT)],
            )
            .await
            .map_err(|e| format!("read source generation: {e}"))?;
        Ok(rows[0].get(0))
    }

    async fn load_checkpoints(
        &self,
        db: &Db,
        id: i64,
        generation: i64,
    ) -> Vec<(String, String, Value)> {
        let Ok(rows) = db
            .query(
                "SELECT scope_key, cursor_kind, cursor_value::text FROM migration_checkpoints \
                 WHERE job_id=$1 AND source_generation=$2 ORDER BY scope_key, cursor_kind",
                &[(&id, Type::INT8), (&generation, Type::INT8)],
            )
            .await
        else {
            return vec![];
        };
        rows.iter()
            .filter_map(|r| {
                let value: String = r.get(2);
                Some((r.get(0), r.get(1), serde_json::from_str(&value).ok()?))
            })
            .collect()
    }

    async fn thread_reconcile(&self, db: &Db, id: i64) -> Result<(), String> {
        db.query(
            "SELECT migration_thread_reconcile_start($1)::text",
            &[(&id, Type::INT8)],
        )
        .await
        .map_err(|e| format!("start thread reconciliation: {e}"))?;
        loop {
            let rows = db
                .query(
                    "SELECT migration_thread_reconcile_batch($1,1000)::text",
                    &[(&id, Type::INT8)],
                )
                .await
                .map_err(|e| format!("reconcile imported threads: {e}"))?;
            let text: String = rows[0].get(0);
            let v: Value = serde_json::from_str(&text)
                .map_err(|e| format!("decode thread reconciliation receipt: {e}"))?;
            let (processed, remaining) = (
                v["processed"].as_i64().unwrap_or(0),
                v["remaining"].as_i64().unwrap_or(0),
            );
            self.update_progress(
                db,
                id,
                "thread_reconcile",
                json!({"processed": processed, "remaining": remaining}),
            )
            .await;
            if remaining == 0 {
                return Ok(());
            }
            if processed == 0 {
                return Err(format!(
                    "thread reconciliation made no progress with {remaining} remaining"
                ));
            }
        }
    }

    /// Go's `importMailItem`.
    async fn import_mail_item(
        &self,
        db: &Db,
        id: i64,
        mailbox: i64,
        item: &mut SourceItem,
        use_identity: bool,
    ) -> Result<String, String> {
        use setjoin_mailboxes::import_export::Strings;
        use setjoin_mailboxes::mimeutil::ImportFields;
        let operation = operation_id(id, item);
        if item.change == Change::Delete {
            return self
                .apply_mail_object(db, id, &operation, item, None, None, None, "")
                .await;
        }
        let fields = ImportFields::parse(&item.raw);
        let message_id = if fields.message_id.is_empty() {
            let mut b = [0u8; 16];
            ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut b)
                .map_err(|_| "random".to_owned())?;
            format!("<imported-{}@migration>", imap::hex(&b)).into_bytes()
        } else {
            fields.message_id.clone()
        };
        use sha2::{Digest, Sha256};
        let reference = imap::hex(&Sha256::digest(&item.raw));
        self.store
            .put(&reference, &item.raw, "message/rfc822")
            .await
            .map_err(|e| format!("minio upload: {e}"))?;
        let mut tag: Option<i64> = None;
        if let Some(name) = item.tags.first() {
            let found = db
                .query(
                    "SELECT id FROM tags WHERE mailbox_id = $1 AND name = $2 LIMIT 1",
                    &[(&mailbox, Type::INT8), (name, Type::TEXT)],
                )
                .await;
            match found {
                Ok(rows) if !rows.is_empty() => tag = Some(rows[0].get(0)),
                _ if !item.folder_path.is_empty() => {
                    match self.ensure_tag_path(db, mailbox, &item.folder_path).await {
                        Ok(t) => tag = Some(t),
                        Err(e) => eprintln!(
                            "migration: failed to create tag path path={:?} error={e}",
                            item.folder_path
                        ),
                    }
                }
                _ => {}
            }
        }
        let strings = Strings::of(&fields, &message_id)
            .ok_or_else(|| "invalid byte sequence for encoding \"UTF8\"".to_owned())?;
        let size = item.raw.len() as i64;
        if use_identity {
            return self
                .apply_mail_object(
                    db,
                    id,
                    &operation,
                    item,
                    Some((&strings, &fields)),
                    tag,
                    Some(&reference),
                    &reference,
                )
                .await;
        }
        db.query(
            "SELECT import_message($1,$2,$3,$4,$5,$6,$7::text::jsonb,$8::text::jsonb,$9::text::jsonb,$10,$11,$12,$13,$14,$15,$16,$17,NULL, \
             p_actor_id => NULL, p_domain_scope => NULL)::text",
            &[
                (&mailbox, Type::INT8),
                (&tag, Type::INT8),
                (&strings.message_id, Type::TEXT),
                (&strings.subject, Type::TEXT),
                (&strings.from_addr, Type::TEXT),
                (&strings.from_name, Type::TEXT),
                (&fields.to_json, Type::TEXT),
                (&fields.cc_json, Type::TEXT),
                (&fields.bcc_json, Type::TEXT),
                (&strings.in_reply_to, Type::TEXT),
                (&strings.references, Type::TEXT),
                (&strings.body_text, Type::TEXT),
                (&strings.body_html, Type::TEXT),
                (&size, Type::INT8),
                (&false, Type::BOOL),
                (&false, Type::BOOL),
                (&reference, Type::TEXT),
            ],
        )
        .await?;
        Ok("imported".into())
    }

    #[allow(clippy::too_many_arguments)]
    async fn apply_mail_object(
        &self,
        db: &Db,
        id: i64,
        operation: &str,
        item: &SourceItem,
        parsed: Option<(
            &setjoin_mailboxes::import_export::Strings,
            &setjoin_mailboxes::mimeutil::ImportFields,
        )>,
        tag: Option<i64>,
        raw_ref: Option<&str>,
        _hash: &str,
    ) -> Result<String, String> {
        let change = item.change.as_str();
        let (strings, fields) = match parsed {
            Some((s, f)) => (Some(s), Some(f)),
            None => (None, None),
        };
        let arr = "[]".to_owned();
        let size = item.raw.len() as i64;
        let (to, cc, bcc) = match fields {
            Some(f) => (f.to_json.as_str(), f.cc_json.as_str(), f.bcc_json.as_str()),
            None => (arr.as_str(), arr.as_str(), arr.as_str()),
        };
        // Go passes the empty arrays for a tombstone and the parsed lists otherwise.
        let size = if fields.is_some() { size } else { 0 };
        let rows = db
            .query(
                "SELECT migration_apply_mail_object($1,$2::text::uuid,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12, \
                 $13::text::jsonb,$14::text::jsonb,$15::text::jsonb,$16,$17,$18,$19,$20,false,false,$21,NULL)::text",
                &[
                    (&id, Type::INT8),
                    (&operation, Type::TEXT),
                    (&item.object_id, Type::TEXT),
                    (&item.version, Type::TEXT),
                    (&item.folder_id, Type::TEXT),
                    (&change, Type::TEXT),
                    (&raw_ref, Type::TEXT),
                    (&tag, Type::INT8),
                    (&strings.map(|s| s.message_id.as_str()), Type::TEXT),
                    (&strings.map(|s| s.subject.as_str()), Type::TEXT),
                    (&strings.map(|s| s.from_addr.as_str()), Type::TEXT),
                    (&strings.map(|s| s.from_name.as_str()), Type::TEXT),
                    (&to, Type::TEXT),
                    (&cc, Type::TEXT),
                    (&bcc, Type::TEXT),
                    (&strings.map(|s| s.in_reply_to.as_str()), Type::TEXT),
                    (&strings.map(|s| s.references.as_str()), Type::TEXT),
                    (&strings.map(|s| s.body_text.as_str()), Type::TEXT),
                    (&strings.map(|s| s.body_html.as_str()), Type::TEXT),
                    (&size, Type::INT8),
                    (&raw_ref, Type::TEXT),
                ],
            )
            .await?;
        let text: String = rows[0].get(0);
        let v: Value = serde_json::from_str(&text).map_err(|e| e.to_string())?;
        match v["outcome"].as_str() {
            Some(o) if !o.is_empty() => Ok(o.to_owned()),
            _ => Err("migration reducer omitted outcome".into()),
        }
    }

    /// `ensureTagPath`.
    async fn ensure_tag_path(&self, db: &Db, mailbox: i64, path: &[String]) -> Result<i64, String> {
        if path.is_empty() {
            return Err("empty tag path".into());
        }
        let mut parent: Option<i64> = None;
        let mut leaf = 0i64;
        for segment in path {
            if segment.is_empty() {
                continue;
            }
            let rows = db
                .query(
                    "SELECT id FROM tags WHERE mailbox_id = $1 AND name = $2 LIMIT 1",
                    &[(&mailbox, Type::INT8), (segment, Type::TEXT)],
                )
                .await;
            if let Ok(rows) = rows {
                if let Some(r) = rows.first() {
                    leaf = r.get(0);
                    parent = Some(leaf);
                    continue;
                }
            }
            let color = hash_color(segment);
            let order = (path.len() * 10) as i32;
            let rows = db
                .query(
                    "INSERT INTO tags (mailbox_id, name, tag_type, parent_id, color, sort_order) \
                     VALUES ($1, $2, 'user', $3, $4, $5) \
                     ON CONFLICT (mailbox_id, name) DO UPDATE \
                     SET parent_id = COALESCE(tags.parent_id, EXCLUDED.parent_id) \
                     RETURNING id",
                    &[
                        (&mailbox, Type::INT8),
                        (segment, Type::TEXT),
                        (&parent, Type::INT8),
                        (&color, Type::TEXT),
                        (&order, Type::INT4),
                    ],
                )
                .await
                .map_err(|e| format!("ensure tag {}: {e}", imap::go_quote(segment)))?;
            leaf = rows[0].get(0);
            parent = Some(leaf);
        }
        Ok(leaf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(uid: u32, version: &str) -> SourceItem {
        SourceItem {
            kind: ItemKind::Mail,
            change: Change::Upsert,
            object_id: format!("imap:INBOX:100:{uid}"),
            version: version.into(),
            folder_id: "INBOX".into(),
            raw: vec![],
            ics: String::new(),
            vcf: String::new(),
            folder_path: vec![],
            tags: vec![],
            uid,
            uid_validity: 100,
        }
    }

    #[test]
    fn operation_id_is_go_uuid_v5_over_the_object_identity() {
        // uuid.NewSHA1(uuid.NameSpaceOID, "7\x00mail\x00imap:INBOX:100:1\x00abc\x00upsert")
        assert_eq!(
            operation_id(7, &item(1, "abc")),
            "3bea9c0a-8765-5172-b964-e99d25fd1869"
        );
    }

    #[test]
    fn dedupe_drops_repeats_within_one_page() {
        let mut same_uid = item(2, "other");
        same_uid.object_id = "imap:INBOX:100:2-again".into();
        let out = dedupe(vec![item(1, "a"), item(1, "a"), item(2, "b"), same_uid]);
        assert_eq!(out.iter().map(|i| i.uid).collect::<Vec<_>>(), [1, 2]);
    }

    #[test]
    fn tag_color_is_the_first_three_hash_bytes() {
        assert_eq!(hash_color("Work"), "#104ab9");
    }
}
