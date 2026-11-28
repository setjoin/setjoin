//! Drive's two process workers (#409), mirroring frozen Go's
//! `drive.Worker` (`drive-maintenance`, 5 min) and `drive.PreviewWorker`
//! (`drive-preview`, 15 s) statement for statement.
//!
//! Both run on the worker credential: the sweep, the zero-ref chunk queue and
//! the render queue are cross-tenant by design. Both have shared effects (row
//! deletes, S3 deletes and puts), so Go's copy must be off first. The chunk GC
//! and the canonical-orphan reaper keep Go's two-transaction shape with the
//! per-key advisory lock held across the storage delete (ARCH-028 exception:
//! the unit spans an S3 call, so no reducer can own it).
use crate::recovery_worker::{ListedObject, ObjectStore, S3Store};
use setjoin_pg::{
    workers::{WorkerConnection, WorkerDatabase},
    Type,
};
use sha2::{Digest, Sha256};
use std::{future::Future, sync::Arc, time::Duration};

pub const MAINTENANCE: &str = "drive-maintenance";
pub const PREVIEW: &str = "drive-preview";
/// Go's `workerInterval`.
pub const MAINTENANCE_INTERVAL: Duration = Duration::from_secs(300);
/// Go's `previewWorkerInterval`.
pub const PREVIEW_INTERVAL: Duration = Duration::from_secs(15);

const GC_BATCH: i64 = 200;
const WORM_RETRY_BATCH: i64 = 200;
const CANONICAL_BATCH: usize = 200;
const PREVIEW_BATCH: i64 = 5;
/// Go's `tmpReapWindow` and `canonicalOrphanReapWindow`.
const REAP_WINDOW_SECS: i64 = 24 * 3600;
/// Go's `driveChunkSize`.
const CHUNK_SIZE: usize = 4 * 1024 * 1024;
const PREVIEW_CMD_TIMEOUT: Duration = Duration::from_secs(120);

fn stale(
    modified: Option<chrono::DateTime<chrono::Utc>>,
    now: chrono::DateTime<chrono::Utc>,
) -> bool {
    modified.is_some_and(|m| now - m > chrono::Duration::seconds(REAP_WINDOW_SECS))
}

/// Keys the Drive chunk writer itself can produce (`drive/g/<sha>` or
/// `drive/s<space>/<sha>`); anything else is never a deletion candidate.
pub fn parse_canonical_chunk_key(key: &str) -> Option<(&str, &str)> {
    let mut parts = key.split('/');
    let (Some("drive"), Some(scope), Some(sha), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return None;
    };
    if sha.len() != 64 || !sha.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    if scope == "g" {
        return Some((scope, sha));
    }
    let bytes = scope.as_bytes();
    if bytes.len() < 2 || bytes[0] != b's' || bytes[1] == b'0' {
        return None;
    }
    // Go's strconv.ParseInt also accepts a leading sign; non-positive is refused.
    match scope[1..].parse::<i64>() {
        Ok(space) if space > 0 => Some((scope, sha)),
        _ => None,
    }
}

async fn rollback(conn: &WorkerConnection) {
    let _ = conn.batch("ROLLBACK").await;
}

async fn lock_chunk(conn: &WorkerConnection, scope: &str, sha: &str) -> Result<(), String> {
    conn.query(
        "SELECT pg_advisory_xact_lock(hashtextextended('drive-chunk:' || $1::text || ':' || $2::text, 0))",
        &[(&scope, Type::TEXT), (&sha, Type::TEXT)],
    )
    .await
    .map(|_| ())
}

pub struct DriveMaintenance {
    db: WorkerDatabase,
    store: Arc<S3Store>,
    /// Go's nil-safe `SetRetention` handle: `false` leaves WORM chunks pending.
    retention: bool,
    scan_after: tokio::sync::Mutex<String>,
}

struct GcRow {
    scope: String,
    sha: String,
    ref_count: i64,
    retained: bool,
    storage_ref: String,
}

impl DriveMaintenance {
    pub fn new(db: WorkerDatabase, store: Arc<S3Store>, retention: bool) -> Self {
        Self {
            db,
            store,
            retention,
            scan_after: tokio::sync::Mutex::new(String::new()),
        }
    }

    pub async fn run_until(self, stop: impl Future<Output = ()> + Send) {
        let mut ticks = tokio::time::interval_at(
            tokio::time::Instant::now() + MAINTENANCE_INTERVAL,
            MAINTENANCE_INTERVAL,
        );
        ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        tokio::pin!(stop);
        loop {
            tokio::select! {biased; _ = &mut stop => return, _ = ticks.tick() => {}}
            tokio::select! {biased; _ = &mut stop => return, _ = self.tick() => {}}
        }
    }

    /// Each step is error-isolated, as in Go: a failure logs and does not block
    /// the others. Version prune is deliberately not called (Go does not).
    pub async fn tick(&self) {
        let conn = match self.db.connect().await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("drive worker: sweep failed: {e}");
                return;
            }
        };
        if let Err(e) = self.sweep(&conn).await {
            eprintln!("drive worker: sweep failed: {e}");
        }
        if let Err(e) = self.gc_chunks(&conn).await {
            eprintln!("drive worker: chunk GC failed: {e}");
        }
        self.reap_canonical_orphans(&conn).await;
        self.reap_tmp().await;
        self.retry_pending_worm_locks(&conn).await;
    }

    async fn sweep(&self, conn: &WorkerConnection) -> Result<(), String> {
        let rows = conn
            .query("SELECT drive_maintenance_sweep()::text", &[])
            .await?;
        let result: String = rows.first().map(|r| r.get(0)).unwrap_or_default();
        eprintln!("drive maintenance sweep: {result}");
        Ok(())
    }

    async fn gc_chunks(&self, conn: &WorkerConnection) -> Result<(), String> {
        let rows = conn
            .query(
                "SELECT q.scope_key, q.sha256, c.ref_count, (c.retain_until IS NOT NULL AND c.retain_until > now()), c.storage_ref
		  FROM drive_chunk_gc_queue q JOIN drive_chunks c USING (scope_key, sha256)
		 LIMIT $1",
                &[(&GC_BATCH, Type::INT8)],
            )
            .await?;
        let batch: Vec<GcRow> = rows
            .iter()
            .map(|r| GcRow {
                scope: r.get(0),
                sha: r.get(1),
                ref_count: r.get(2),
                retained: r.get(3),
                storage_ref: r.get(4),
            })
            .collect();
        for r in batch {
            if r.ref_count > 0 {
                // Re-referenced since queueing: drop the queue row only.
                if let Err(e) = conn
                    .execute(
                        "DELETE FROM drive_chunk_gc_queue WHERE scope_key=$1 AND sha256=$2",
                        &[(&r.scope, Type::TEXT), (&r.sha, Type::TEXT)],
                    )
                    .await
                {
                    eprintln!("drive worker: gc dequeue failed: {e}");
                }
            } else if r.retained {
                // WORM-retained: stays queued for a later tick.
            } else {
                self.gc_delete_one(conn, &r).await;
            }
        }
        Ok(())
    }

    /// The row goes first (re-checking `ref_count=0` and the queue verdict in
    /// the DELETE), the storage object second, under the per-key advisory lock
    /// that every producer takes (see Go's `gcDeleteOne`).
    async fn gc_delete_one(&self, conn: &WorkerConnection, r: &GcRow) {
        let (scope, sha) = (&r.scope, &r.sha);
        let params = || -> [setjoin_pg::Param<'_>; 2] { [(scope, Type::TEXT), (sha, Type::TEXT)] };
        if let Err(e) = conn.batch("BEGIN").await {
            eprintln!("drive worker: gc begin failed: {e}");
            return;
        }
        if let Err(e) = lock_chunk(conn, scope, sha).await {
            eprintln!("drive worker: gc chunk lock failed: {e}");
            return rollback(conn).await;
        }
        let deleted = match conn
            .execute(
                "DELETE FROM drive_chunks c
		 WHERE c.scope_key=$1 AND c.sha256=$2 AND c.ref_count=0
		   AND EXISTS (SELECT 1 FROM drive_chunk_gc_queue q
		                WHERE q.scope_key=c.scope_key AND q.sha256=c.sha256)",
                &params(),
            )
            .await
        {
            Ok(n) => n,
            Err(e) => {
                eprintln!("drive worker: gc chunk delete failed: {e}");
                return rollback(conn).await;
            }
        };
        if let Err(e) = conn
            .execute(
                "DELETE FROM drive_chunk_gc_queue WHERE scope_key=$1 AND sha256=$2",
                &params(),
            )
            .await
        {
            eprintln!("drive worker: gc dequeue failed: {e}");
            return rollback(conn).await;
        }
        if let Err(e) = conn.batch("COMMIT").await {
            eprintln!("drive worker: gc commit failed: {e}");
            return rollback(conn).await;
        }
        if deleted == 0 {
            return; // re-referenced since the batch read; the object stays live
        }
        if let Err(e) = conn.batch("BEGIN").await {
            eprintln!("drive worker: gc remove begin failed: {e}");
            return;
        }
        if let Err(e) = lock_chunk(conn, scope, sha).await {
            eprintln!("drive worker: gc remove lock failed: {e}");
            return rollback(conn).await;
        }
        let registered = match conn
            .query(
                "SELECT EXISTS (SELECT 1 FROM drive_chunks WHERE scope_key=$1 AND sha256=$2)",
                &params(),
            )
            .await
        {
            Ok(rows) => rows.first().is_some_and(|r| r.get::<_, bool>(0)),
            Err(e) => {
                eprintln!("drive worker: gc re-reference recheck failed, leaving storage object alone: {e}");
                return rollback(conn).await;
            }
        };
        if registered {
            eprintln!("drive worker: gc skip, chunk re-registered since commit (race averted)");
            return rollback(conn).await;
        }
        if let Err(e) = self.store.remove(&r.storage_ref).await {
            eprintln!("drive worker: gc storage remove failed (DB row already gone, orphaned object): {e}");
            return rollback(conn).await;
        }
        if let Err(e) = conn.batch("COMMIT").await {
            eprintln!("drive worker: gc remove transaction close failed: {e}");
            rollback(conn).await;
        }
    }

    /// Inventories `drive/` for objects whose promote succeeded but whose
    /// registration failed. Exact key grammar, age, an authoritative absence
    /// check and the advisory lock are all required before a delete.
    async fn reap_canonical_orphans(&self, conn: &WorkerConnection) {
        let mut cursor = self.scan_after.lock().await;
        let now = chrono::Utc::now();
        let mut listed = 0usize;
        let mut completed = true;
        let mut last_key = cursor.clone();
        let mut token: Option<String> = None;
        let mut first = true;
        'pages: loop {
            let start = if first { Some(cursor.as_str()) } else { None };
            first = false;
            let (objects, next) = match self
                .store
                .list_page("drive/", start, token.take(), Some(CANONICAL_BATCH))
                .await
            {
                Ok(page) => page,
                Err(e) => {
                    // minio emits one error item and closes the channel.
                    listed += 1;
                    eprintln!("drive worker: canonical inventory list error: {e}");
                    break 'pages;
                }
            };
            for ListedObject { key, modified } in objects {
                if listed >= CANONICAL_BATCH {
                    completed = false;
                    break 'pages;
                }
                listed += 1;
                last_key = key.clone();
                let Some((scope, sha)) = parse_canonical_chunk_key(&key) else {
                    continue;
                };
                if !stale(modified, now) {
                    continue;
                }
                self.reap_canonical_orphan(conn, scope, sha, &key).await;
            }
            match next {
                Some(t) => token = Some(t),
                None => break,
            }
        }
        let _ = listed;
        if completed {
            cursor.clear();
        } else if !last_key.is_empty() {
            *cursor = last_key;
        }
    }

    async fn reap_canonical_orphan(
        &self,
        conn: &WorkerConnection,
        scope: &str,
        sha: &str,
        key: &str,
    ) {
        if let Err(e) = conn.batch("BEGIN").await {
            eprintln!("drive worker: canonical orphan begin failed: {e}");
            return;
        }
        if let Err(e) = lock_chunk(conn, scope, sha).await {
            eprintln!("drive worker: canonical orphan lock failed: {e}");
            return rollback(conn).await;
        }
        let registered = match conn
            .query(
                "SELECT EXISTS (SELECT 1 FROM drive_chunks WHERE scope_key=$1 AND sha256=$2)",
                &[(&scope, Type::TEXT), (&sha, Type::TEXT)],
            )
            .await
        {
            Ok(rows) => rows.first().is_some_and(|r| r.get::<_, bool>(0)),
            Err(e) => {
                eprintln!("drive worker: canonical orphan DB check failed, leaving storage object alone: {e}");
                return rollback(conn).await;
            }
        };
        if registered {
            return rollback(conn).await;
        }
        if let Err(e) = self.store.remove(key).await {
            eprintln!("drive worker: canonical orphan remove failed, will retry: {e}");
            return rollback(conn).await;
        }
        if let Err(e) = conn.batch("COMMIT").await {
            eprintln!("drive worker: canonical orphan transaction close failed: {e}");
            rollback(conn).await;
        }
    }

    /// Orphaned `tmp/upload/` objects older than 24 h.
    async fn reap_tmp(&self) {
        let now = chrono::Utc::now();
        let mut token: Option<String> = None;
        loop {
            let (objects, next) = match self
                .store
                .list_page("tmp/upload/", None, token.take(), None)
                .await
            {
                Ok(page) => page,
                Err(e) => {
                    eprintln!("drive worker: tmp list error: {e}");
                    return;
                }
            };
            for ListedObject { key, modified } in objects {
                if !stale(modified, now) {
                    continue;
                }
                if let Err(e) = self.store.remove(&key).await {
                    eprintln!("drive worker: tmp reap failed: {e}");
                }
            }
            match next {
                Some(t) => token = Some(t),
                None => return,
            }
        }
    }

    /// Re-applies Object-Lock for chunks whose apply failed (`worm_pending` is
    /// a stored generated column, so nothing is queued and nothing is lost on
    /// a crash). Without a retention handle every GXP chunk stays pending.
    async fn retry_pending_worm_locks(&self, conn: &WorkerConnection) {
        if !self.retention {
            return;
        }
        let rows = match conn
            .query(
                "SELECT c.scope_key, c.sha256,
		        to_char(c.retain_until AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US'), s.worm_mode
		  FROM drive_chunks c
		  JOIN drive_spaces s ON s.id = substring(c.scope_key from 2)::bigint
		 WHERE c.scope_key LIKE 's%' AND c.worm_pending
		 LIMIT $1",
                &[(&WORM_RETRY_BATCH, Type::INT8)],
            )
            .await
        {
            Ok(rows) => rows,
            Err(e) => {
                eprintln!("drive worker: worm-pending query failed: {e}");
                return;
            }
        };
        for row in &rows {
            let scope: String = row.get(0);
            let sha: String = row.get(1);
            let until: String = row.get(2);
            let mode: Option<String> = row.get(3);
            // RFC 3339 with trimmed fractional zeros, as Go's time formatting.
            let until = format!("{}Z", until.trim_end_matches('0').trim_end_matches('.'));
            let mode = mode
                .filter(|m| !m.is_empty())
                .unwrap_or_else(|| "governance".into());
            let key = format!("drive/{scope}/{sha}");
            if let Err(e) = self.store.retain(&key, &mode, &until).await {
                eprintln!("drive worker: worm retry apply failed, will retry next tick: {e}");
                continue;
            }
            if let Err(e) = conn
                .execute(
                    "UPDATE drive_chunks
			   SET worm_applied_until = GREATEST(coalesce(worm_applied_until, '-infinity'), $3::text::timestamptz)
			 WHERE scope_key = $1 AND sha256 = $2",
                    &[(&scope, Type::TEXT), (&sha, Type::TEXT), (&until, Type::TEXT)],
                )
                .await
            {
                eprintln!("drive worker: worm mark-applied failed: {e}");
            }
        }
    }
}

/// Go's `maxPreviewSourceBytes` / `maxPreviewOutputBytes` (64 MiB each).
#[derive(Clone, Copy)]
pub struct PreviewBounds {
    pub source: u64,
    pub output: u64,
}

impl Default for PreviewBounds {
    fn default() -> Self {
        Self {
            source: 64 << 20,
            output: 64 << 20,
        }
    }
}

pub struct DrivePreview {
    db: WorkerDatabase,
    store: Arc<S3Store>,
    /// `DRIVE_PREVIEW_CMD`; empty means inert (metadata-card fallback).
    cmd: String,
    bounds: PreviewBounds,
}

impl DrivePreview {
    pub fn new(db: WorkerDatabase, store: Arc<S3Store>, cmd: String) -> Self {
        Self {
            db,
            store,
            cmd,
            bounds: PreviewBounds::default(),
        }
    }

    pub fn with_bounds(mut self, bounds: PreviewBounds) -> Self {
        self.bounds = bounds;
        self
    }

    /// Unset command: return at once, never ticking or claiming (Go logs at
    /// debug level only).
    pub async fn run_until(self, stop: impl Future<Output = ()> + Send) {
        if self.cmd.is_empty() {
            return;
        }
        let mut ticks = tokio::time::interval_at(
            tokio::time::Instant::now() + PREVIEW_INTERVAL,
            PREVIEW_INTERVAL,
        );
        ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        tokio::pin!(stop);
        loop {
            tokio::select! {biased; _ = &mut stop => return, _ = ticks.tick() => {}}
            tokio::select! {biased; _ = &mut stop => return, _ = self.tick() => {}}
        }
    }

    /// Claims up to five pending versions (a benign duplicate-render race with
    /// a second replica, as in Go: `drive_preview_attach` is last-attach-wins).
    pub async fn tick(&self) {
        let conn = match self.db.connect().await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("drive preview worker: claim query failed: {e}");
                return;
            }
        };
        let rows = match conn
            .query(
                "SELECT v.id, CASE WHEN s.classification = 'regular' THEN 'g' ELSE 's' || s.id END
		  FROM drive_file_versions v JOIN drive_spaces s ON s.id = v.space_id
		 WHERE v.preview_status = 'pending'
		 ORDER BY v.id
		 LIMIT $1",
                &[(&PREVIEW_BATCH, Type::INT8)],
            )
            .await
        {
            Ok(rows) => rows,
            Err(e) => {
                eprintln!("drive preview worker: claim query failed: {e}");
                return;
            }
        };
        let batch: Vec<(i64, String)> = rows.iter().map(|r| (r.get(0), r.get(1))).collect();
        for (id, scope) in batch {
            if let Err(e) = self.render(&conn, id, &scope).await {
                eprintln!("drive preview worker: render failed for version {id}: {e}");
                if let Err(e) = conn
                    .execute(
                        "SELECT drive_preview_attach($1::bigint, NULL, NULL, 'failed')",
                        &[(&id, Type::INT8)],
                    )
                    .await
                {
                    eprintln!("drive preview worker: mark-failed attach failed: {e}");
                }
            }
        }
    }

    async fn render(&self, conn: &WorkerConnection, id: i64, scope: &str) -> Result<(), String> {
        let rows = conn
            .query(
                "SELECT c.storage_ref, c.size_bytes
		  FROM drive_version_chunks vc
		  JOIN drive_chunks c ON c.scope_key = vc.scope_key AND c.sha256 = vc.chunk_sha256
		 WHERE vc.version_id = $1 AND vc.stream = 'content'
		 ORDER BY vc.ordinal",
                &[(&id, Type::INT8)],
            )
            .await
            .map_err(|e| format!("read content manifest: {e}"))?;
        let manifest: Vec<(String, i32)> = rows.iter().map(|r| (r.get(0), r.get(1))).collect();
        if manifest.is_empty() {
            return Err("empty content manifest".into());
        }
        let declared: i64 = manifest.iter().map(|(_, size)| i64::from(*size)).sum();
        if declared as u64 > self.bounds.source {
            return Err(format!(
                "version declares {declared} source bytes, over the {} byte input admission bound",
                self.bounds.source
            ));
        }
        let work = TempWork::create()?;
        let mut source = Vec::new();
        for (key, _) in &manifest {
            let room = (self.bounds.source as usize).saturating_sub(source.len());
            let bytes = self
                .store
                .read(key, room)
                .await
                .map_err(|e| format!("fetch content chunk {key}: {e}"))?;
            source.extend_from_slice(&bytes);
        }
        std::fs::write(&work.source, &source).map_err(|e| format!("write temp source: {e}"))?;
        drop(source);
        run_preview_cmd(&self.cmd, &work.source, &work.out)
            .await
            .map_err(|e| format!("sidecar: {e}"))?;
        let pdf = find_produced_pdf(&work.out)?;
        let size = std::fs::metadata(&pdf)
            .map_err(|e| format!("stat produced PDF: {e}"))?
            .len();
        if size > self.bounds.output {
            return Err(format!(
                "produced PDF exceeds the {} byte output admission bound",
                self.bounds.output
            ));
        }
        let bytes = std::fs::read(&pdf).map_err(|e| format!("read produced PDF: {e}"))?;
        if bytes.is_empty() {
            return Err("sidecar produced an empty PDF".into());
        }
        let whole = hex(&Sha256::digest(&bytes));
        let mut out = Vec::new();
        for chunk in bytes.chunks(CHUNK_SIZE) {
            let sha = hex(&Sha256::digest(chunk));
            self.store
                .put(&format!("drive/{scope}/{sha}"), chunk, "application/pdf")
                .await
                .map_err(|e| format!("store preview chunk: {e}"))?;
            out.push(serde_json::json!({"sha256": sha, "size": chunk.len()}));
        }
        let manifest = serde_json::to_string(&out).map_err(|e| e.to_string())?;
        conn.execute(
            "SELECT drive_preview_attach($1::bigint, $2::text, $3::text::jsonb, 'ready')",
            &[
                (&id, Type::INT8),
                (&whole, Type::TEXT),
                (&manifest, Type::TEXT),
            ],
        )
        .await
        .map_err(|e| format!("attach: {e}"))?;
        Ok(())
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A private source file and output directory (mode 0600/0700, random names),
/// removed on drop as Go's deferred `os.Remove`/`os.RemoveAll` do.
struct TempWork {
    source: std::path::PathBuf,
    out: std::path::PathBuf,
}

impl TempWork {
    fn create() -> Result<Self, String> {
        use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
        let name = |prefix: &str| -> Result<std::path::PathBuf, String> {
            let mut random = [0u8; 8];
            getrandom::getrandom(&mut random).map_err(|e| e.to_string())?;
            Ok(std::env::temp_dir().join(format!("{prefix}{}", hex(&random))))
        };
        let source = name("drive-preview-src-")?;
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&source)
            .map_err(|e| format!("create temp source: {e}"))?;
        let out = name("drive-preview-out-")?;
        if let Err(e) = std::fs::DirBuilder::new().mode(0o700).create(&out) {
            let _ = std::fs::remove_file(&source);
            return Err(format!("create temp outdir: {e}"));
        }
        Ok(Self { source, out })
    }
}

impl Drop for TempWork {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.source);
        let _ = std::fs::remove_dir_all(&self.out);
    }
}

/// Substitutes `{in}`/`{outdir}` into the admin-set template and runs it through
/// the shell (neither value is request input), capped at two minutes.
async fn run_preview_cmd(
    template: &str,
    source: &std::path::Path,
    out: &std::path::Path,
) -> Result<(), String> {
    let line = template
        .replace("{in}", &source.display().to_string())
        .replace("{outdir}", &out.display().to_string());
    let child = tokio::process::Command::new("sh")
        .arg("-c")
        .arg(line)
        .stdin(std::process::Stdio::null())
        .kill_on_drop(true)
        .output();
    match tokio::time::timeout(PREVIEW_CMD_TIMEOUT, child).await {
        Err(_) => Err("signal: killed (timeout)".into()),
        Ok(Err(e)) => Err(e.to_string()),
        Ok(Ok(output)) if output.status.success() => Ok(()),
        Ok(Ok(output)) => {
            let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
            text.push_str(&String::from_utf8_lossy(&output.stderr));
            Err(format!("{} (output: {})", output.status, text.trim()))
        }
    }
}

/// The first `*.pdf` (case-insensitive) in name order, like `os.ReadDir`.
fn find_produced_pdf(out: &std::path::Path) -> Result<std::path::PathBuf, String> {
    let mut names: Vec<_> = std::fs::read_dir(out)
        .map_err(|e| format!("read outdir: {e}"))?
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_ok_and(|t| !t.is_dir()))
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
        .into_iter()
        .find(|n| n.to_lowercase().ends_with(".pdf"))
        .map(|n| out.join(n))
        .ok_or_else(|| "sidecar produced no .pdf in outdir".into())
}
