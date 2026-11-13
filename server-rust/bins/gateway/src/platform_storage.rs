//! Process storage adapters for F08 (#459). Database contracts live in setjoin-platform.
use crate::recovery_worker::S3Store;
use serde_json::{json, Value};
use std::{sync::Arc, time::Duration};

pub struct Runtime {
    store: Arc<S3Store>,
    master: String,
    http: reqwest::Client,
    db: Option<setjoin_pg::workers::WorkerDatabase>,
    migration: MigrationConfig,
    state: std::sync::Mutex<State>,
    changed: tokio::sync::Notify,
    stopping: tokio_util::sync::CancellationToken,
}

impl Runtime {
    pub fn new(store: Arc<S3Store>, master: String) -> Result<Self, String> {
        let migration = MigrationConfig {
            bucket: store.bucket_name(),
            ..MigrationConfig::default()
        };
        Ok(Self {
            store,
            migration,
            master,
            db: None,
            state: std::sync::Mutex::new(State::default()),
            changed: tokio::sync::Notify::new(),
            stopping: tokio_util::sync::CancellationToken::new(),
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .map_err(|e| e.to_string())?,
        })
    }

    /// The master URL uses the shared S3 scheme and host, replacing an explicit port.
    pub fn from_env() -> Result<Self, String> {
        let store = Arc::new(S3Store::from_env()?);
        let mut master = reqwest::Url::parse(store.endpoint()).map_err(|e| e.to_string())?;
        // URL normalizes explicit :80/:443 away; Go still replaces those ports.
        if store
            .endpoint()
            .parse::<hyper::Uri>()
            .ok()
            .and_then(|uri| uri.port_u16())
            .is_some()
        {
            master
                .set_port(Some(9333))
                .map_err(|_| "invalid storage master port")?;
        }
        let bucket = store.bucket_name();
        Ok(
            Self::new(store, master.to_string().trim_end_matches('/').into())?
                .with_migration_config(MigrationConfig {
                    provider: std::env::var("STORAGE_PROVIDER").unwrap_or_default(),
                    endpoint: std::env::var("STORAGE_ENDPOINT").unwrap_or_default(),
                    access: std::env::var("STORAGE_ACCESS_KEY").unwrap_or_default(),
                    secret: std::env::var("STORAGE_SECRET_KEY").unwrap_or_default(),
                    bucket,
                }),
        )
    }

    async fn seaweed(&self, path: &str) -> Result<Value, String> {
        // Go intentionally ignores the HTTP status if the response is valid JSON.
        let response = self
            .http
            .get(format!("{}{path}", self.master))
            .send()
            .await
            .map_err(|e| e.to_string())?;
        let value: Value = response.json().await.map_err(|e| e.to_string())?;
        if !value.is_object() && !value.is_null() {
            return Err("invalid storage master document".into());
        }
        Ok(value)
    }

    pub async fn status(&self) -> Result<String, String> {
        let cluster = self.seaweed("/cluster/status").await?;
        let directory = self.seaweed("/dir/status").await.unwrap_or(Value::Null);
        let mut topology = Vec::new();
        let mut volumes = Vec::new();
        if let Some(centers) = directory["Topology"].as_object() {
            for (name, center) in centers {
                if center["DataCenters"].is_array() {
                    continue;
                }
                let mut racks = Vec::new();
                if let Some(rack_map) = center.as_object() {
                    for (rack_name, rack) in rack_map {
                        let Some(nodes) = rack["DataNodes"].as_array() else {
                            continue;
                        };
                        racks.push(json!({"name":rack_name,"nodes":nodes.len()}));
                        for node in nodes.iter().filter(|n| n.is_object()) {
                            volumes.push(json!({"url":node["Url"],"volumes":node["Volumes"].as_array().map_or(0, Vec::len),"free":node["Free"],"max":node["Max"]}));
                        }
                    }
                }
                topology.push(json!({"name":name,"racks":racks}));
            }
        }
        let buckets = match self.store.bucket().await {
            Ok(bucket) => match bucket.credentials().await {
                Ok(credentials) => s3::Bucket::list_buckets(bucket.region(), credentials)
                    .await
                    .map(|b| b.buckets.bucket.len())
                    .unwrap_or(0),
                Err(_) => 0,
            },
            Err(_) => 0,
        };
        let response = json!({
            "mode":"distributed", "version":directory["Version"].as_str().unwrap_or(""),
            "isLeader":cluster["IsLeader"].as_bool().unwrap_or(false),
            "leader":cluster["Leader"].as_str().unwrap_or(""),
            "buckets":{"count":buckets},
            "topology": if topology.is_empty() {Value::Null} else {json!(topology)},
            "volumes": if volumes.is_empty() {Value::Null} else {json!(volumes)},
        });
        Ok(format!("{}\n", setjoin_platform::config::go_any(&response)))
    }
}

pub enum Failure {
    Problem(u16, String),
    Unknown(setjoin_contracts::ids::OperationId),
}

impl Runtime {
    pub async fn reconcile(
        &self,
        exec: &setjoin_pg::ScopedExecutor,
        actor: &setjoin_authz::AuthContext,
        id: i64,
        operation: [u8; 16],
    ) -> Result<String, Failure> {
        use setjoin_pg::CommandOutcome;
        use setjoin_platform::storage;
        let Some((status, raw)) = storage::reconcile_details(exec, id)
            .await
            .map_err(|_| Failure::Problem(500, "database error".into()))?
        else {
            return Err(Failure::Problem(404, "scan not found".into()));
        };
        if status != "completed" {
            return Err(Failure::Problem(
                409,
                "scan must be completed before reconcile".into(),
            ));
        }
        let details = raw
            .and_then(|s| serde_json::from_str::<Value>(&s).ok())
            .filter(|v| {
                v.is_null()
                    || v.as_array()
                        .is_some_and(|xs| xs.iter().all(|x| x.is_object() || x.is_null()))
            })
            .ok_or_else(|| Failure::Problem(500, "invalid scan details".into()))?;
        let mut reimported = 0;
        for detail in details.as_array().into_iter().flatten() {
            if detail["issue"].as_str() != Some("orphaned") {
                continue;
            }
            let Some(sha) = detail["sha256"].as_str().filter(|s| !s.is_empty()) else {
                continue;
            };
            let Ok(bucket) = self.store.bucket().await else {
                continue;
            };
            let Ok((head, code)) = bucket.head_object(sha).await else {
                continue;
            };
            if code != 200 {
                continue;
            }
            let content_type = head
                .content_type
                .as_deref()
                .filter(|s| !s.is_empty())
                .unwrap_or("application/octet-stream");
            let Some(blob_operation) = crate::jmap::random() else {
                return Err(Failure::Problem(503, "service unavailable".into()));
            };
            match storage::reimport_blob(
                exec,
                actor,
                blob_operation,
                sha,
                &format!("{}/{sha}", bucket.name()),
                head.content_length.unwrap_or(0),
                content_type,
            )
            .await
            {
                CommandOutcome::Committed(()) => reimported += 1,
                CommandOutcome::RolledBack(_) => {} // Go logs and continues, including constraint errors.
                CommandOutcome::Unknown { operation } => return Err(Failure::Unknown(operation)),
            }
        }
        if let CommandOutcome::Unknown { operation } =
            storage::reconcile_count(exec, actor, operation, id, reimported).await
        {
            return Err(Failure::Unknown(operation));
        }
        Ok(format!("{{\"reimported\":{reimported}}}\n"))
    }
}

#[derive(Default)]
struct State {
    closing: bool,
    pending: usize,
    runs: std::collections::HashMap<(&'static str, i64), Run>,
}
#[derive(Clone)]
struct Run {
    stop: tokio_util::sync::CancellationToken,
    cancel_requested: Arc<std::sync::atomic::AtomicBool>,
    done: tokio::sync::watch::Receiver<Option<&'static str>>,
}
struct Admission(Arc<Runtime>);
impl Drop for Admission {
    fn drop(&mut self) {
        self.0.state.lock().expect("storage registry").pending -= 1;
        self.0.changed.notify_waiters();
    }
}
struct Completion {
    runtime: Arc<Runtime>,
    key: (&'static str, i64),
    outcome: &'static str,
    done: tokio::sync::watch::Sender<Option<&'static str>>,
}
impl Drop for Completion {
    fn drop(&mut self) {
        self.runtime
            .state
            .lock()
            .expect("storage registry")
            .runs
            .remove(&self.key);
        self.done.send_replace(Some(self.outcome));
        self.runtime.changed.notify_waiters();
    }
}
impl Runtime {
    pub fn with_database(mut self, db: setjoin_pg::workers::WorkerDatabase) -> Self {
        self.db = Some(db);
        self
    }
    fn admit(self: &Arc<Self>) -> Result<Admission, Failure> {
        let mut state = self.state.lock().expect("storage registry");
        if state.closing {
            return Err(Failure::Problem(
                503,
                "migration admission is closed — service shutdown in progress".into(),
            ));
        }
        state.pending += 1;
        Ok(Admission(self.clone()))
    }
    fn register(
        self: &Arc<Self>,
        kind: &'static str,
        id: i64,
    ) -> (
        tokio_util::sync::CancellationToken,
        Arc<std::sync::atomic::AtomicBool>,
        Completion,
    ) {
        let stop = self.stopping.child_token();
        let (done, rx) = tokio::sync::watch::channel(None);
        let cancel_requested = Arc::new(std::sync::atomic::AtomicBool::new(false));
        self.state.lock().expect("storage registry").runs.insert(
            (kind, id),
            Run {
                stop: stop.clone(),
                cancel_requested: cancel_requested.clone(),
                done: rx,
            },
        );
        (
            stop,
            cancel_requested,
            Completion {
                runtime: self.clone(),
                key: (kind, id),
                outcome: "failed",
                done,
            },
        )
    }
    /// Closing is visible before pending admissions are joined. Dependencies remain live
    /// after a drain timeout: only observed task exits release execution ownership.
    pub async fn shutdown(&self) {
        self.state.lock().expect("storage registry").closing = true;
        self.stopping.cancel();
        if tokio::time::timeout(Duration::from_secs(20), self.drained())
            .await
            .is_err()
        {
            eprintln!("storage migration drain expired; execution ownership retained; waiting for live tasks");
            self.drained().await;
        }
    }
    async fn drained(&self) {
        loop {
            let changed = self.changed.notified();
            {
                let state = self.state.lock().expect("storage registry");
                if state.pending == 0 && state.runs.is_empty() {
                    return;
                }
            }
            changed.await;
        }
    }
    pub async fn start_scan(
        self: &Arc<Self>,
        exec: &setjoin_pg::ScopedExecutor,
        actor: &setjoin_authz::AuthContext,
        operation: [u8; 16],
    ) -> Result<String, Failure> {
        let _admission = self.admit()?;
        let db = self
            .db
            .clone()
            .ok_or_else(|| Failure::Problem(500, "database error".into()))?;
        let id = match setjoin_platform::storage::begin_scan(exec, actor, operation).await {
            setjoin_pg::CommandOutcome::Committed(id) => id,
            setjoin_pg::CommandOutcome::RolledBack(_) => {
                return Err(Failure::Problem(500, "database error".into()))
            }
            setjoin_pg::CommandOutcome::Unknown { operation } => {
                return Err(Failure::Unknown(operation))
            }
        };
        let (stop, _cancel_requested, mut completion) = self.register("scan", id);
        let runtime = self.clone();
        tokio::spawn(async move {
            tokio::select! {
                biased;
                _=stop.cancelled()=>{},
                result=tokio::time::timeout(Duration::from_secs(2*60*60),runtime.scan(&db,id))=>{
                    if result.is_ok() { completion.outcome="completed"; }
                }
            }
            drop(completion);
        });
        Ok(format!("{{\"id\":{id}}}\n"))
    }
    async fn scan(&self, db: &setjoin_pg::workers::WorkerDatabase, id: i64) {
        use setjoin_platform::storage;
        let Ok(db) = db.connect().await else { return };
        let Ok(mut keys) = storage::scan_keys(&db).await else {
            storage::scan_failed(&db, id).await;
            return;
        };
        let mut counts = [0i64; 4];
        let mut details = vec![];
        if let Ok(bucket) = self.store.bucket().await {
            let mut token = None;
            loop {
                let Ok((page, code)) = bucket
                    .list_page(String::new(), None, token, None, Some(1000))
                    .await
                else {
                    break;
                };
                if code != 200 {
                    break;
                }
                for object in page.contents {
                    counts[0] += 1;
                    if !keys.remove(&object.key) {
                        counts[1] += 1;
                        details.push(
                            json!({"sha256":object.key,"issue":"orphaned","size":object.size}),
                        );
                    }
                    if counts[0] % 1000 == 0 {
                        storage::scan_progress(&db, id, counts, &details, false).await;
                        details.clear();
                    }
                }
                token = page.next_continuation_token.filter(|_| page.is_truncated);
                if token.is_none() {
                    break;
                }
            }
        }
        for sha in keys {
            counts[2] += 1;
            details.push(json!({"sha256":sha,"issue":"missing"}));
        }
        if let Ok(rows) = storage::scan_drift(&db).await {
            for (sha, expected, actual) in rows {
                counts[3] += 1;
                details.push(json!({"sha256":sha,"issue":"refcount_drift","refCountExpected":expected,"refCountActual":actual}));
            }
        }
        storage::scan_progress(&db, id, counts, &details, true).await;
    }
}

#[derive(Clone, Default)]
pub struct MigrationConfig {
    pub provider: String,
    pub endpoint: String,
    pub access: String,
    pub secret: String,
    pub bucket: String,
}
impl Runtime {
    pub fn with_migration_config(mut self, config: MigrationConfig) -> Self {
        self.migration = config;
        self
    }
    /// Go has no production exclusivity attestation. Recovery therefore observes
    /// orphan rows and cannot authorize reclaiming another process's live job.
    pub async fn recover(&self) {
        let Some(db) = &self.db else { return };
        let observed = async {
            let db = db.connect().await.map_err(|e| e.to_string())?;
            setjoin_platform::storage::migration_orphans(&db).await
        }
        .await;
        match observed {
            Ok(rows) => {
                for (id, status) in rows {
                    eprintln!("storage migration {id} remains {status}; exclusive execution ownership not proven; reclaim deferred");
                }
            }
            Err(error) => eprintln!("storage migration startup recovery failed: {error}"),
        }
    }
    pub async fn start_migration(
        self: &Arc<Self>,
        exec: &setjoin_pg::ScopedExecutor,
        actor: &setjoin_authz::AuthContext,
        operation: [u8; 16],
        requested: &str,
    ) -> Result<String, Failure> {
        let target = if requested.is_empty() {
            &self.migration.provider
        } else {
            requested
        };
        if target.is_empty() || target == "s3" {
            return Err(Failure::Problem(
                400,
                "target provider required and must differ from current".into(),
            ));
        }
        if !matches!(target, "posix" | "backup_s3" | "oss") {
            return Err(Failure::Problem(
                500,
                format!(
                    "failed to create target driver: storage: unknown provider {}",
                    setjoin_contracts::go_quote::quote(target.as_bytes())
                ),
            ));
        }
        let config = &self.migration;
        let target_store = setjoin_backup::store::Store::driver(
            target,
            &config.endpoint,
            "us-east-1",
            &config.bucket,
            &config.access,
            &config.secret,
        )
        .map_err(|e| Failure::Problem(500, format!("failed to create target driver: {e}")))?;
        let target_store = if target == "backup_s3" {
            target_store.with_aws_operation_query()
        } else if target == "oss" {
            target_store.with_signing_region(String::new())
        } else {
            target_store
        };
        let source = Arc::new(
            S3Store::new(
                self.store.endpoint(),
                &self.store.bucket_name(),
                &config.access,
                &config.secret,
            )
            .map_err(|e| Failure::Problem(500, format!("failed to create source driver: {e}")))?,
        );
        let _admission = self.admit()?;
        let db = self
            .db
            .clone()
            .ok_or_else(|| Failure::Problem(500, "database error".into()))?;
        let local = target == "posix";
        let aws_plaintext_upload = target == "backup_s3"
            && !config.endpoint.trim().is_empty()
            && !config.endpoint.trim().starts_with("https://");
        let provider = if target == "backup_s3" { "s3" } else { target };
        let id = match setjoin_platform::storage::begin_migration(exec, actor, operation, provider)
            .await
        {
            setjoin_pg::CommandOutcome::Committed(id) => id,
            setjoin_pg::CommandOutcome::RolledBack(_) => {
                return Err(Failure::Problem(
                    500,
                    "failed to start migration: migration: record start: database error".into(),
                ))
            }
            setjoin_pg::CommandOutcome::Unknown { operation } => {
                return Err(Failure::Unknown(operation))
            }
        };
        let (stop, cancel_requested, mut completion) = self.register("migration", id);
        let runtime = self.clone();
        tokio::spawn(async move {
            completion.outcome = runtime
                .migrate(
                    &db,
                    id,
                    source,
                    target_store,
                    stop,
                    cancel_requested,
                    local,
                    aws_plaintext_upload,
                )
                .await;
            drop(completion);
        });
        Ok(format!("{{\"id\":{id},\"status\":\"started\"}}\n"))
    }
    async fn migrate(
        &self,
        db: &setjoin_pg::workers::WorkerDatabase,
        id: i64,
        source: Arc<S3Store>,
        target: setjoin_backup::store::Store,
        stop: tokio_util::sync::CancellationToken,
        cancel_requested: Arc<std::sync::atomic::AtomicBool>,
        local: bool,
        aws_plaintext_upload: bool,
    ) -> &'static str {
        let writer = match db.connect().await {
            Ok(db) => db,
            Err(error) => {
                eprintln!("storage migration {id} connection failed: {error}");
                return "failed";
            }
        };
        Self::set_migration_status(&writer, id, "backfill").await;
        // A dropped filesystem future can leave Tokio blocking work copying after
        // the run "exited". Join it; only cooperative network I/O may be interrupted.
        let result = self
            .backfill(
                db,
                &writer,
                id,
                &source,
                &target,
                &stop,
                local,
                aws_plaintext_upload,
            )
            .await;
        let status = if stop.is_cancelled() {
            if cancel_requested.load(std::sync::atomic::Ordering::SeqCst) {
                "cancelled"
            } else {
                "failed"
            }
        } else if result.is_ok_and(|failed| failed == 0) {
            "cutover"
        } else {
            "failed"
        };
        Self::set_migration_status(&writer, id, status).await;
        status
    }
    async fn set_migration_status(
        db: &setjoin_pg::workers::WorkerConnection,
        id: i64,
        status: &str,
    ) {
        let result = tokio::time::timeout(
            Duration::from_secs(10),
            setjoin_platform::storage::migration_status_write(db, id, status),
        )
        .await;
        match result { Ok(Ok(()))=>{},result=>eprintln!("storage migration {id} intended {status}; persistence failed {result:?}; reconcile row manually"), }
    }
    async fn backfill(
        &self,
        db: &setjoin_pg::workers::WorkerDatabase,
        writer: &setjoin_pg::workers::WorkerConnection,
        id: i64,
        source: &S3Store,
        target: &setjoin_backup::store::Store,
        stop: &tokio_util::sync::CancellationToken,
        local: bool,
        aws_plaintext_upload: bool,
    ) -> Result<usize, String> {
        let reader = db.connect().await.map_err(|e| e.to_string())?;
        let mut rows = setjoin_platform::storage::migration_rows(&reader).await?;
        let (mut migrated, mut failed) = (0i64, 0usize);
        loop {
            let next = tokio::select! {biased;_=stop.cancelled()=>return Err("migration stopped".into()),next=rows.next()=>next?};
            let Some(row) = next else { break };
            let (Ok(sha), Ok(size)) = (row.try_get::<_, String>(0), row.try_get::<_, i64>(1))
            else {
                continue;
            };
            // Go verifies a target by GET/read-back, never by existence alone.
            if Self::verify_cooperatively(target, &sha, size, stop, local).await? {
                migrated += 1;
                continue;
            }
            // Go's AWS SDK rejects the non-seekable tee reader over HTTP before
            // consuming the lazy source or sending a PUT (trailing checksum).
            if aws_plaintext_upload {
                failed += 1;
                eprintln!("storage migration {id} unreconciled object {sha}: unseekable stream is not supported without TLS and trailing checksum");
                continue;
            }
            if stop.is_cancelled() {
                return Err("migration stopped".into());
            }
            match Self::copy_blob(source, target, &sha, size, stop, local).await {
                Ok(()) => {
                    migrated += 1;
                    if migrated % 1000 == 0 && !stop.is_cancelled() {
                        setjoin_platform::storage::migration_progress(
                            writer,
                            id,
                            migrated,
                            Some(&sha),
                        )
                        .await;
                    }
                }
                Err(error) => {
                    if stop.is_cancelled() {
                        return Err(error);
                    }
                    failed += 1;
                    eprintln!("storage migration {id} unreconciled object {sha}: {error}");
                }
            }
        }
        if stop.is_cancelled() {
            return Err("migration stopped".into());
        }
        setjoin_platform::storage::migration_progress(writer, id, migrated, None).await;
        Ok(failed)
    }
    async fn verified(target: &setjoin_backup::store::Store, key: &str, size: i64) -> bool {
        target.body_digest(key).await.is_ok_and(|(hash, count)| {
            count as i128 == size as i128 && hash.eq_ignore_ascii_case(key)
        })
    }
    async fn verify_cooperatively(
        target: &setjoin_backup::store::Store,
        key: &str,
        size: i64,
        stop: &tokio_util::sync::CancellationToken,
        local: bool,
    ) -> Result<bool, String> {
        if local {
            return Ok(Self::verified(target, key, size).await);
        }
        tokio::select! {biased;_=stop.cancelled()=>Err("migration stopped".into()),verified=Self::verified(target,key,size)=>Ok(verified)}
    }
    async fn copy_blob(
        source: &S3Store,
        target: &setjoin_backup::store::Store,
        key: &str,
        size: i64,
        stop: &tokio_util::sync::CancellationToken,
        local: bool,
    ) -> Result<(), String> {
        use s3::request::Request as _;
        use sha2::{Digest, Sha256};
        use tokio::io::AsyncWriteExt;
        let prefix =
            std::env::var("GOFREE_RESOURCE_PREFIX").unwrap_or_else(|_| "setjoin-storage".into());
        let temp = setjoin_backup::TempFile::new(&format!("{prefix}-migration-"), ".blob")?;
        let bucket = tokio::select! {biased;_=stop.cancelled()=>return Err("migration stopped".into()),bucket=source.bucket()=>bucket?};
        let request = s3::request::tokio_backend::ReqwestRequest::new(
            &bucket,
            key,
            s3::command::Command::GetObject,
        )
        .await
        .map_err(|e| e.to_string())?;
        let mut response = tokio::select! {biased;_=stop.cancelled()=>return Err("migration stopped".into()),response=request.response()=>response.map_err(|e|e.to_string())?};
        if response.status().as_u16() != 200 {
            return Err(format!("source HTTP {}", response.status()));
        }
        let modified = response
            .headers()
            .get("last-modified")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if ![
            "%a, %-d %b %Y %H:%M:%S GMT",
            "%a, %e %b %Y %H:%M:%S GMT",
            "%a, %e %b %y %H:%M:%S GMT",
        ]
        .iter()
        .any(|f| chrono::NaiveDateTime::parse_from_str(modified, f).is_ok())
        {
            return Err("invalid source Last-Modified".into());
        }
        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&temp.path)
            .await
            .map_err(|e| e.to_string())?;
        let (mut hash, mut count) = (Sha256::new(), 0u64);
        loop {
            let next = tokio::select! {biased;_=stop.cancelled()=>return Err("migration stopped".into()),next=response.chunk()=>next.map_err(|e|e.to_string())?};
            let Some(bytes) = next else { break };
            hash.update(&bytes);
            count += bytes.len() as u64;
            file.write_all(&bytes).await.map_err(|e| e.to_string())?;
        }
        file.sync_all().await.map_err(|e| e.to_string())?;
        drop(file);
        if stop.is_cancelled() {
            return Err("migration stopped".into());
        }
        if local {
            target.put_file(key, &temp.path).await?;
        } else {
            tokio::select! {biased;_=stop.cancelled()=>return Err("migration stopped".into()),result=target.put_file(key,&temp.path)=>result?};
        }
        let source_valid = count as i128 == size as i128
            && format!("{:x}", hash.finalize()).eq_ignore_ascii_case(key);
        let target_valid = if source_valid {
            Self::verify_cooperatively(target, key, size, stop, local).await?
        } else {
            false
        };
        if !source_valid || !target_valid {
            let deleted = if local {
                target.delete(key).await
            } else {
                tokio::select! {biased;_=stop.cancelled()=>return Err("migration stopped".into()),result=target.delete(key)=>result}
            };
            if let Err(error) = deleted {
                eprintln!("migration partial delete failed {key}: {error}");
            }
            return Err("copied object failed integrity verification".into());
        }
        Ok(())
    }
}

impl Runtime {
    pub async fn cancel_migration(
        &self,
        exec: &setjoin_pg::ScopedExecutor,
        id: i64,
    ) -> Result<String, Failure> {
        let status = setjoin_platform::storage::migration_row_status(exec, id)
            .await
            .ok_or_else(|| Failure::Problem(404, "migration not found".into()))?;
        let quote = |s: &str| setjoin_contracts::go_quote::quote(s.as_bytes());
        if !matches!(status.as_str(), "dual_write" | "backfill") {
            return Err(Failure::Problem(
                409,
                format!(
                    "migration: not in a cancellable state: migration {id} is {}",
                    quote(&status)
                ),
            ));
        }
        let run = {
            self.state
                .lock()
                .expect("storage registry")
                .runs
                .get(&("migration", id))
                .cloned()
        };
        let Some(mut run) = run else {
            return Err(Failure::Problem(409,format!("migration: no live run for this migration in this process: migration {id} (row status {})",quote(&status))));
        };
        run.cancel_requested
            .store(true, std::sync::atomic::Ordering::SeqCst);
        run.stop.cancel();
        let outcome = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if let Some(outcome) = *run.done.borrow() {
                    return outcome;
                }
                if run.done.changed().await.is_err() {
                    return "failed";
                }
            }
        })
        .await
        .map_err(|_| {
            Failure::Problem(
                503,
                "migration: cancel drain deadline expired — run goroutine still live".into(),
            )
        })?;
        match outcome {
            "cancelled"=>Ok("{\"status\":\"cancelled\"}\n".into()),
            "cutover"=>Err(Failure::Problem(409,format!("migration: not in a cancellable state: migration {id} rests at \"cutover\" — the run completed its backfill before the handshake could stop it"))),
            other=>Err(Failure::Problem(409,format!("migration: not in a cancellable state: migration {id} stopped at {} — not the cancelled outcome",quote(other)))),
        }
    }
}
