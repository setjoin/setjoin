//! `meet-reconcile` (#410): the Meet reconcile sweep, mirroring frozen Go's
//! `meet.Worker` (`mailserver/internal/meet/worker*.go`) leg for leg on the
//! worker credential. Every tick runs, in Go's order:
//!
//! 1. the unconditional drain legs (never gated on a feature flag): recording
//!    reconcile (DB-only legs, then the ListEgress legs when Egress is
//!    enabled), recording ingest and staging reaper (object store), semantic
//!    package sweep, semantic export queue, Drive-History emitter and the
//!    local-capture lease expirer;
//! 2. only when `feature.meet` is ON and LiveKit is configured: lobby expiry,
//!    `ListRooms` (a failure ends the tick), ended-room and closed-breakout
//!    `DeleteRoom` retries, breakout presence healing, the lost-webhook GC and
//!    the captions healer.
//!
//! Writes are the same single statements or reducer calls Go issues; the one
//! multi-statement transaction (recording ingest) is Go's own. The semantic
//! export composer is nil in production Go, so a claimed export always
//! completes failed with Go's fixed reason. The grace map of breakout absences
//! is process-local, as in Go. Start it with `RUST_WORKERS_ON=meet-reconcile`
//! only together with `GO_WORKERS_OFF=meet-reconcile`.
use crate::{meet_livekit::LiveKit, recovery_worker::S3Store};
use setjoin_pg::{
    workers::{WorkerConnection, WorkerDatabase},
    Type,
};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    future::Future,
    sync::Mutex,
    time::Duration,
};

pub const NAME: &str = "meet-reconcile";
/// Go's `workerInterval`.
pub const INTERVAL: Duration = Duration::from_secs(60);
const REQUESTED_GRACE: i64 = 120;
const MAX_INGEST_ATTEMPTS: i32 = 5;
const STAGING_KEEP_FAILED: i64 = 7 * 24 * 3600;
const STALE_WINDOW_SECS: i64 = 600;
const CAPTIONS_GRACE: f64 = 60.0;
const BATCH: i64 = 16;
const CHUNK: u64 = 4 * 1024 * 1024;

pub struct MeetReconcile {
    pub db: WorkerDatabase,
    pub livekit: LiveKit,
    pub store: Option<S3Store>,
    absent: Mutex<HashMap<String, (i64, String)>>,
}

fn warn(what: &str, error: impl std::fmt::Display) {
    eprintln!("meet worker: {what}: {error}");
}

impl MeetReconcile {
    pub fn new(db: WorkerDatabase, livekit: LiveKit, store: Option<S3Store>) -> Self {
        Self {
            db,
            livekit,
            store,
            absent: Mutex::new(HashMap::new()),
        }
    }

    pub async fn run_until(self, stop: impl Future<Output = ()> + Send) {
        let mut ticks = tokio::time::interval_at(tokio::time::Instant::now() + INTERVAL, INTERVAL);
        ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        tokio::pin!(stop);
        loop {
            tokio::select! {biased; _ = &mut stop => return, _ = ticks.tick() => {}}
            tokio::select! {biased; _ = &mut stop => return, _ = self.tick() => {}}
        }
    }

    /// One sweep. Public: the oracle drives exactly one tick.
    pub async fn tick(&self) {
        let c = match self.db.connect_session().await {
            Ok(c) => c,
            Err(e) => return warn("connect failed", e),
        };
        self.reconcile_recordings(&c).await;
        if self.store.is_some() {
            self.ingest_recordings(&c).await;
            self.reap_staging(&c).await;
        }
        self.sweep_semantic_packages(&c).await;
        self.drain_semantic_exports(&c).await;
        self.emit_drive_history(&c).await;
        match c
            .query("SELECT meeting_local_capture_lease_expire(50)", &[])
            .await
        {
            Ok(_) => {}
            Err(e) => warn("local-capture lease expiry failed", e),
        }
        let enabled = match c
            .query(
                "SELECT coalesce((SELECT enabled FROM feature_toggles WHERE key='feature.meet'),false)",
                &[],
            )
            .await
        {
            Ok(rows) => rows.first().is_some_and(|r| r.get::<_, bool>(0)),
            Err(_) => false,
        };
        if !enabled || !self.livekit.configured() {
            return;
        }
        if let Err(e) = c.query("SELECT meeting_requests_expire()", &[]).await {
            warn("lobby expiry failed", e);
        }
        let live: HashSet<String> = match self.livekit.list_rooms().await {
            Ok(rooms) => rooms.into_iter().collect(),
            Err(()) => return warn("ListRooms failed", "twirp"),
        };
        self.retry_delete(
            &c,
            &live,
            "ended-room",
            "SELECT room_name::text FROM meetings WHERE state = 'ended' AND ended_at > now() - interval '24 hours'",
        )
        .await;
        self.retry_delete(
            &c,
            &live,
            "breakout child-room",
            "SELECT b.room_name::text FROM meeting_breakouts b JOIN meetings m ON m.id = b.meeting_id \
             WHERE (b.state = 'closed' AND b.closed_at > now() - interval '24 hours') \
                OR (m.state = 'ended' AND m.ended_at > now() - interval '24 hours')",
        )
        .await;
        self.reconcile_breakout_presence(&c).await;
        self.gc_lost_webhooks(&c, &live).await;
        self.reconcile_captions(&c).await;
    }

    async fn retry_delete(
        &self,
        c: &WorkerConnection,
        live: &HashSet<String>,
        what: &str,
        sql: &str,
    ) {
        let rows = match c.query(sql, &[]).await {
            Ok(r) => r,
            Err(e) => return warn(&format!("{what} query failed"), e),
        };
        for row in rows {
            let room: String = row.get(0);
            if !live.contains(&room) {
                continue;
            }
            if self.livekit.delete_room(&room).await.is_err() {
                warn(&format!("{what} DeleteRoom retry failed"), &room);
            }
        }
    }

    // ---- recordings -----------------------------------------------------

    async fn reconcile_recordings(&self, c: &WorkerConnection) {
        if let Err(e) = c
            .query(
                "UPDATE meeting_recordings r SET state = 'stopping' FROM meetings m \
                 WHERE m.id = r.meeting_id AND m.state = 'ended' \
                   AND (r.state = 'active' OR (r.state = 'requested' AND r.egress_id IS NOT NULL))",
                &[],
            )
            .await
        {
            warn("ended-residue flip failed", e);
        }
        if let Err(e) = c
            .query(
                "UPDATE meeting_recordings SET state = 'failed', stopped_at = COALESCE(stopped_at, now()), \
                        error = COALESCE(error, 'stopping with no egress binding (wedge-4 sweep)') \
                 WHERE state = 'stopping' AND egress_id IS NULL",
                &[],
            )
            .await
        {
            warn("wedge-4 sweep failed", e);
        }
        match c
            .query(
                "SELECT id FROM meeting_recordings WHERE state = 'requested' AND egress_id IS NULL \
                 AND started_at < now() - make_interval(secs => $1::int)",
                &[(&(REQUESTED_GRACE as i32), Type::INT4)],
            )
            .await
        {
            Err(e) => return warn("stale-requested query failed", e),
            Ok(rows) => {
                for row in rows {
                    let id: i64 = row.get(0);
                    if let Err(e) = c
                        .query(
                            "SELECT meeting_recording_bind_egress($1, NULL, NULL, false, \
                             'egress start never bound (gateway crash before StartRoomComposite)')",
                            &[(&id, Type::INT8)],
                        )
                        .await
                    {
                        warn("stale-requested fail-mark failed", e);
                    }
                }
            }
        }
        if self.livekit.egress() {
            self.reconcile_egress(c).await;
        }
    }

    async fn reconcile_egress(&self, c: &WorkerConnection) {
        let live = match self.livekit.list_egress().await {
            Ok(l) => l,
            Err(()) => return warn("ListEgress failed", "twirp"),
        };
        let active: HashSet<&str> = live.iter().filter(|e| e.1).map(|e| e.0.as_str()).collect();
        let rows = match c
            .query(
                "SELECT r.id, r.state, r.egress_id, r.staging_key, m.room_name::text \
                 FROM meeting_recordings r JOIN meetings m ON m.id = r.meeting_id \
                 WHERE r.state IN ('active', 'stopping') AND r.egress_id IS NOT NULL \
                   AND r.started_at < now() - make_interval(secs => $1::int)",
                &[(&(REQUESTED_GRACE as i32), Type::INT4)],
            )
            .await
        {
            Ok(r) => r,
            Err(e) => return warn("reconcile query failed", e),
        };
        let mut known = HashSet::new();
        for row in &rows {
            let (id, state, egress): (i64, String, String) = (row.get(0), row.get(1), row.get(2));
            let staging: Option<String> = row.get(3);
            let room: String = row.get(4);
            known.insert(egress.clone());
            if state == "stopping" && active.contains(egress.as_str()) {
                if self.livekit.stop_egress(&egress).await.is_err() {
                    warn("retry StopEgress failed", &egress);
                }
            } else if !active.contains(egress.as_str()) {
                let Some(key) = staging else { continue };
                let size = match &self.store {
                    Some(s) => s.stat_size(&key).await.ok().flatten(),
                    None => None,
                };
                let info = match size {
                    Some(n) => format!(
                        r#"{{"status":"EGRESS_COMPLETE","fileResults":[{{"size":"{n}"}}]}}"#
                    ),
                    None => r#"{"status":"EGRESS_FAILED","error":"egress vanished from ListEgress; no staging object found"}"#.to_owned(),
                };
                if let Err(e) = c
                    .query(
                        "SELECT meeting_recording_event($1::text::uuid, $2, 'egress_ended', $3::jsonb)",
                        &[(&room, Type::TEXT), (&egress, Type::TEXT), (&info, Type::TEXT)],
                    )
                    .await
                {
                    warn(&format!("synthetic egress_ended failed for recording {id}"), e);
                }
            }
        }
        let now_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos() as i64);
        for (id, is_active, started) in &live {
            if !is_active || known.contains(id) {
                continue;
            }
            if *started != 0 && now_ns - started < REQUESTED_GRACE * 1_000_000_000 {
                continue;
            }
            if self.livekit.stop_egress(id).await.is_err() {
                warn("belt StopEgress failed", id);
            }
        }
    }

    async fn ingest_recordings(&self, c: &WorkerConnection) {
        let rows = match c
            .query(
                "SELECT r.id, r.meeting_id, m.owner_user_id, r.staging_key, r.ingest_attempts, m.title, \
                        (extract(epoch FROM r.started_at) * 1000000)::int8 \
                 FROM meeting_recordings r JOIN meetings m ON m.id = r.meeting_id \
                 WHERE r.state = 'pending_ingest' AND r.staging_key IS NOT NULL",
                &[],
            )
            .await
        {
            Ok(r) => r,
            Err(e) => return warn("ingest-candidate query failed", e),
        };
        for row in rows {
            let id: i64 = row.get(0);
            let (meeting, owner): (i64, i64) = (row.get(1), row.get(2));
            let key: String = row.get(3);
            let attempts: i32 = row.get(4);
            let title: String = row.get(5);
            let started: i64 = row.get(6);
            if attempts >= MAX_INGEST_ATTEMPTS {
                if let Err(e) = c
                    .query(
                        "UPDATE meeting_recordings SET state='failed', \
                         error = 'ingest failed after '||ingest_attempts||' attempts: '||COALESCE(error,'') \
                         WHERE id = $1 AND state = 'pending_ingest'",
                        &[(&id, Type::INT8)],
                    )
                    .await
                {
                    warn("ingest exhaustion mark-failed failed", e);
                }
                continue;
            }
            if let Err(e) = c
                .query(
                    "UPDATE meeting_recordings SET ingest_attempts = ingest_attempts + 1 WHERE id = $1",
                    &[(&id, Type::INT8)],
                )
                .await
            {
                warn("ingest attempt-count bump failed", e);
                continue;
            }
            if let Err(error) = self
                .ingest_one(c, id, meeting, owner, &key, &title, started)
                .await
            {
                warn("ingest failed", &error);
                if let Err(e) = c
                    .query(
                        "UPDATE meeting_recordings SET error = $2 WHERE id = $1",
                        &[(&id, Type::INT8), (&error, Type::TEXT)],
                    )
                    .await
                {
                    warn("ingest error-record failed", e);
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn ingest_one(
        &self,
        c: &WorkerConnection,
        id: i64,
        meeting: i64,
        owner: i64,
        key: &str,
        title: &str,
        started_micros: i64,
    ) -> Result<(), String> {
        let store = self.store.as_ref().ok_or("no object store")?;
        let space: i64 = c
            .query("SELECT meeting_space_ensure($1)", &[(&meeting, Type::INT8)])
            .await?
            .first()
            .ok_or("no space")?
            .get(0);
        let size = store
            .stat_size(key)
            .await?
            .ok_or_else(|| "The specified key does not exist.".to_owned())?;
        let mut whole = Sha256::new();
        let mut manifest: Vec<(String, u64)> = Vec::new();
        let mut total = 0u64;
        let mut at = 0u64;
        while at < size {
            let len = CHUNK.min(size - at);
            let block = store.read_range(key, at, len).await?;
            at += len;
            whole.update(&block);
            let sha = hex(&Sha256::digest(&block));
            let mut random = [0u8; 16];
            random.copy_from_slice(&crate::jmap::random().ok_or("random unavailable")?);
            let temp = format!("tmp/upload/{}", hex(&random));
            store.put_temp(&temp, &block).await?;
            let committed = self
                .commit_chunk(c, store, owner, space, &temp, &sha, block.len() as i32)
                .await;
            {
                use crate::recovery_worker::ObjectStore as _;
                let _ = store.remove(&temp).await;
            }
            committed?;
            total += block.len() as u64;
            manifest.push((sha, block.len() as u64));
        }
        let manifest_json = if manifest.is_empty() {
            "null".to_owned()
        } else {
            let items: Vec<String> = manifest
                .iter()
                .map(|(s, n)| format!(r#"{{"sha256":"{s}","size":{n}}}"#))
                .collect();
            format!("[{}]", items.join(","))
        };
        let started = chrono::DateTime::from_timestamp_micros(started_micros)
            .ok_or("bad start time")?
            .with_timezone(&chrono::Local);
        let name = format!(
            "Recording \u{2014} {title} \u{2014} {} (#{id}).mp4",
            started.format("%Y-%m-%d %H:%M")
        );
        c.batch("BEGIN").await?;
        let outcome = async {
            let node: i64 = c
                .query(
                    "SELECT drive_node_create($1, $2, NULL, 'file', $3, 'video/mp4')",
                    &[
                        (&owner, Type::INT8),
                        (&space, Type::INT8),
                        (&name, Type::TEXT),
                    ],
                )
                .await?
                .first()
                .ok_or("no node")?
                .get(0);
            let whole_hex = hex(&whole.clone().finalize());
            let total = total as i64;
            let put: String = c
                .query(
                    "SELECT drive_file_put_version($1, $2, $3, $4, 'video/mp4', NULL, $5::jsonb, \
                     'meeting recording ingest', 'meet-egress')::text",
                    &[
                        (&owner, Type::INT8),
                        (&node, Type::INT8),
                        (&whole_hex, Type::TEXT),
                        (&total, Type::INT8),
                        (&manifest_json, Type::TEXT),
                    ],
                )
                .await?
                .first()
                .ok_or("no version")?
                .get(0);
            let version = serde_json::from_str::<serde_json::Value>(&put)
                .map_err(|e| e.to_string())?["versionId"]
                .as_i64()
                .unwrap_or(0);
            c.query(
                "SELECT meeting_recording_ingested($1, $2, $3)",
                &[
                    (&id, Type::INT8),
                    (&node, Type::INT8),
                    (&version, Type::INT8),
                ],
            )
            .await?;
            Ok::<(), String>(())
        }
        .await;
        match outcome {
            Ok(()) => c.batch("COMMIT").await?,
            Err(e) => {
                let _ = c.batch("ROLLBACK").await;
                return Err(e);
            }
        }
        use crate::recovery_worker::ObjectStore as _;
        if store.remove(key).await.is_err() {
            warn("staging delete failed (reaper will retry)", key);
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn commit_chunk(
        &self,
        c: &WorkerConnection,
        store: &S3Store,
        owner: i64,
        space: i64,
        temp: &str,
        sha: &str,
        size: i32,
    ) -> Result<(), String> {
        c.batch("BEGIN").await?;
        let outcome = async {
            let scope: String = c
                .query(
                    "SELECT drive_chunk_upload_require($1, $2)",
                    &[(&owner, Type::INT8), (&space, Type::INT8)],
                )
                .await?
                .first()
                .ok_or("no scope")?
                .get(0);
            c.query(
                "SELECT pg_advisory_xact_lock(hashtextextended('drive-chunk:' || $1::text || ':' || $2::text, 0))",
                &[(&scope, Type::TEXT), (&sha.to_owned(), Type::TEXT)],
            )
            .await?;
            store.promote(temp, &format!("drive/{scope}/{sha}")).await?;
            c.query(
                "SELECT drive_chunk_register($1, $2, $3, $4)",
                &[(&owner, Type::INT8), (&space, Type::INT8), (&sha.to_owned(), Type::TEXT), (&size, Type::INT4)],
            )
            .await?;
            Ok::<(), String>(())
        }
        .await;
        match outcome {
            Ok(()) => c.batch("COMMIT").await,
            Err(e) => {
                let _ = c.batch("ROLLBACK").await;
                Err(e)
            }
        }
    }

    async fn reap_staging(&self, c: &WorkerConnection) {
        let Some(store) = &self.store else { return };
        let objects = match store.list_with_modified("meet-egress/").await {
            Ok(o) => o,
            Err(e) => return warn("staging list failed", e),
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs() as i64);
        use crate::recovery_worker::ObjectStore as _;
        for (key, modified) in objects {
            let rows = match c
                .query(
                    "SELECT state FROM meeting_recordings WHERE staging_key = $1",
                    &[(&key, Type::TEXT)],
                )
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    warn("staging lookup failed", e);
                    continue;
                }
            };
            let old = now - modified > STAGING_KEEP_FAILED;
            let remove = match rows.first().map(|r| r.get::<_, String>(0)) {
                None => old,
                Some(s) if s == "ready" => true,
                Some(s) if s == "failed" => old,
                Some(_) => false,
            };
            if remove && store.remove(&key).await.is_err() {
                warn("staging reap failed", &key);
            }
        }
    }

    // ---- semantic recordings -------------------------------------------

    async fn sweep_semantic_packages(&self, c: &WorkerConnection) {
        let rows = match c
            .query(
                "SELECT id, deletion_generation FROM meeting_semantic_recordings \
                 WHERE package_state = 'DELETE_PENDING' ORDER BY id LIMIT $1",
                &[(&BATCH, Type::INT8)],
            )
            .await
        {
            Ok(r) => r,
            Err(e) => return warn("semantic delete-pending query failed", e),
        };
        for row in rows {
            let (id, generation): (i64, i64) = (row.get(0), row.get(1));
            self.sweep_one_package(c, id, generation).await;
        }
    }

    async fn sweep_one_package(&self, c: &WorkerConnection, id: i64, generation: i64) {
        let children = match c
            .query(
                "SELECT child FROM meeting_semantic_children WHERE recording_id = $1 AND NOT released ORDER BY child",
                &[(&id, Type::INT8)],
            )
            .await
        {
            Ok(r) => r,
            Err(e) => return warn("semantic children query failed", e),
        };
        for row in children {
            let child: String = row.get(0);
            let out = c
                .query(
                    "WITH receipt AS (SELECT meeting_semantic_child_release($1, $2, $3) AS r) \
                     SELECT (receipt.r->>'heldBeforeRelease')::boolean, (receipt.r->>'alreadyReleased')::boolean FROM receipt",
                    &[(&id, Type::INT8), (&child, Type::TEXT), (&generation, Type::INT8)],
                )
                .await;
            match out {
                Err(e) => return warn("child release failed", e),
                Ok(rows) => {
                    let held: Option<bool> = rows.first().and_then(|r| r.get(0));
                    if held == Some(true) {
                        return;
                    }
                }
            }
        }
        if let Err(e) = c
            .query(
                "SELECT meeting_semantic_package_finalize($1, $2)",
                &[(&id, Type::INT8), (&generation, Type::INT8)],
            )
            .await
        {
            warn("package finalize failed", e);
        }
    }

    async fn drain_semantic_exports(&self, c: &WorkerConnection) {
        let rows = match c
            .query(
                "SELECT e.recording_id, e.generation FROM meeting_semantic_exports e \
                 WHERE e.state IN ('pending', 'composing') \
                   AND (e.state = 'pending' OR e.claimed_at IS NULL OR e.claimed_at < now() - interval '10 minutes') \
                 ORDER BY e.recording_id, e.generation LIMIT $1",
                &[(&BATCH, Type::INT8)],
            )
            .await
        {
            Ok(r) => r,
            Err(e) => return warn("semantic export query failed", e),
        };
        for row in rows {
            let (id, generation): (i64, i64) = (row.get(0), row.get(1));
            let claim = match c
                .query(
                    "WITH claim AS (SELECT meeting_semantic_export_claim($1, $2) AS r) \
                     SELECT (claim.r->>'claimable')::boolean, COALESCE((claim.r->>'exhausted')::boolean, false) FROM claim",
                    &[(&id, Type::INT8), (&generation, Type::INT8)],
                )
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    warn("export claim failed", e);
                    continue;
                }
            };
            let claimable: bool = claim.first().and_then(|r| r.get(0)).unwrap_or(false);
            let exhausted: bool = claim.first().map(|r| r.get(1)).unwrap_or(false);
            let reason = if !claimable {
                if !exhausted {
                    continue;
                }
                "exportCompositionFailed: export composition attempts exhausted"
            } else {
                "exportCompositionFailed: no qualified composition provider (server audio is evidence-pending)"
            };
            let zero = 0i64;
            if let Err(e) = c
                .query(
                    "SELECT meeting_semantic_export_complete($1, $2, $3, $4, $5, NULLIF($6, ''))",
                    &[
                        (&id, Type::INT8),
                        (&generation, Type::INT8),
                        (&false, Type::BOOL),
                        (&zero, Type::INT8),
                        (&zero, Type::INT8),
                        (&reason.to_owned(), Type::TEXT),
                    ],
                )
                .await
            {
                warn("export completion failed", e);
            }
        }
    }

    async fn emit_drive_history(&self, c: &WorkerConnection) {
        for (kind, sql) in [
            (
                "recording.stopped",
                "SELECT r.id FROM meeting_semantic_recordings r WHERE r.rec_state = 'stopped' \
                 AND NOT EXISTS (SELECT 1 FROM drive_meet_history_events h WHERE h.source_kind = 'recording.stopped' AND h.source_id = r.id) \
                 ORDER BY r.id LIMIT $1",
            ),
            (
                "annotation.committed",
                "SELECT a.id FROM meeting_presentation_annotations a \
                 WHERE NOT EXISTS (SELECT 1 FROM drive_meet_history_events h WHERE h.source_kind = 'annotation.committed' AND h.source_id = a.id) \
                 ORDER BY a.id LIMIT $1",
            ),
            (
                "presentation.pinned",
                "SELECT p.id FROM meeting_presentations p \
                 WHERE NOT EXISTS (SELECT 1 FROM drive_meet_history_events h WHERE h.source_kind = 'presentation.pinned' AND h.source_id = p.id) \
                 ORDER BY p.id LIMIT $1",
            ),
        ] {
            let rows = match c.query(sql, &[(&BATCH, Type::INT8)]).await {
                Ok(r) => r,
                Err(e) => {
                    warn("drive-history candidate query failed", e);
                    continue;
                }
            };
            for row in rows {
                let id: i64 = row.get(0);
                if let Err(e) = c
                    .query(
                        "SELECT drive_meet_history_emit($1, $2)",
                        &[(&kind.to_owned(), Type::TEXT), (&id, Type::INT8)],
                    )
                    .await
                {
                    warn("drive-history emit refused", e);
                }
            }
        }
    }

    // ---- live legs -------------------------------------------------------

    async fn reconcile_breakout_presence(&self, c: &WorkerConnection) {
        let children = match c
            .query(
                "SELECT b.id, b.meeting_id, b.room_name::text, m.room_name::text FROM meeting_breakouts b \
                 JOIN meetings m ON m.id = b.meeting_id WHERE b.state = 'open' AND m.state = 'live'",
                &[],
            )
            .await
        {
            Ok(r) => r,
            Err(e) => return warn("breakout open-rooms query failed", e),
        };
        let candidates: HashSet<i64> = children.iter().map(|r| r.get::<_, i64>(1)).collect();
        self.sweep_stale_absent(c, &candidates).await;
        if children.is_empty() {
            return;
        }
        let assignments = match c
            .query(
                "SELECT meeting_id, identity, breakout_id FROM meeting_participants \
                 WHERE role = 'member' AND left_at IS NULL AND banned_at IS NULL \
                   AND meeting_id IN (SELECT DISTINCT meeting_id FROM meeting_breakouts WHERE state = 'open')",
                &[],
            )
            .await
        {
            Ok(r) => r,
            Err(e) => return warn("breakout assignments query failed", e),
        };
        let mut main_room: HashMap<i64, String> = HashMap::new();
        let mut kids: HashMap<i64, Vec<String>> = HashMap::new();
        let mut room_by_id: HashMap<i64, String> = HashMap::new();
        for r in &children {
            let (id, meeting): (i64, i64) = (r.get(0), r.get(1));
            let (room, main): (String, String) = (r.get(2), r.get(3));
            main_room.insert(meeting, main);
            kids.entry(meeting).or_default().push(room.clone());
            room_by_id.insert(id, room);
        }
        let mut presence: HashMap<i64, HashMap<String, Vec<String>>> = HashMap::new();
        // Go ranges a map here; the order only matters for which room's
        // ListParticipants call comes first, never for the effects.
        let mut meetings: Vec<_> = main_room.iter().collect();
        meetings.sort();
        for (meeting, main) in meetings {
            let mut p: HashMap<String, Vec<String>> = HashMap::new();
            let mut rooms = vec![main.clone()];
            rooms.extend(kids.get(meeting).cloned().unwrap_or_default());
            for room in rooms {
                match self.livekit.list_participants(&room).await {
                    Ok(ids) => {
                        for id in ids {
                            p.entry(id).or_default().push(room.clone());
                        }
                    }
                    Err(()) => warn("breakout ListParticipants failed", &room),
                }
            }
            presence.insert(*meeting, p);
        }
        for a in assignments {
            let (meeting, identity): (i64, String) = (a.get(0), a.get(1));
            let breakout: Option<i64> = a.get(2);
            let assigned = match breakout {
                None => main_room.get(&meeting).cloned().unwrap_or_default(),
                Some(b) => match room_by_id.get(&b) {
                    Some(r) => r.clone(),
                    None => continue,
                },
            };
            let key = format!("{meeting}/{identity}");
            let rooms = presence
                .get(&meeting)
                .and_then(|p| p.get(&identity))
                .cloned()
                .unwrap_or_default();
            if rooms.is_empty() {
                self.mark_absent_or_stamp(c, key, meeting, identity).await;
                continue;
            }
            self.absent
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&key);
            for room in rooms {
                if room != assigned
                    && self
                        .livekit
                        .remove_participant(&room, &identity)
                        .await
                        .is_err()
                {
                    warn("breakout presence-heal RemoveParticipant failed", &room);
                }
            }
        }
    }

    async fn mark_absent_or_stamp(
        &self,
        c: &WorkerConnection,
        key: String,
        meeting: i64,
        identity: String,
    ) {
        let seen = self
            .absent
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains_key(&key);
        if !seen {
            self.absent
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(key, (meeting, identity));
            return;
        }
        match c
            .query(
                "UPDATE meeting_participants SET left_at = now() WHERE meeting_id = $1 AND identity = $2 AND left_at IS NULL",
                &[(&meeting, Type::INT8), (&identity, Type::TEXT)],
            )
            .await
        {
            Ok(_) => {
                self.absent.lock().unwrap_or_else(|e| e.into_inner()).remove(&key);
            }
            Err(e) => warn("breakout absence left_at stamp failed", e),
        }
    }

    async fn sweep_stale_absent(&self, c: &WorkerConnection, candidates: &HashSet<i64>) {
        let stale: Vec<(String, (i64, String))> = self
            .absent
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter(|(_, (meeting, _))| !candidates.contains(meeting))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        for (key, (meeting, identity)) in stale {
            let rows = match c
                .query(
                    "SELECT room_name::text FROM meetings WHERE id = $1",
                    &[(&meeting, Type::INT8)],
                )
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    warn(
                        "absent-sweep meetings query failed, retaining entry for retry",
                        e,
                    );
                    continue;
                }
            };
            let Some(row) = rows.first() else {
                self.absent
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .remove(&key);
                continue;
            };
            let main: String = row.get(0);
            let present = match self.livekit.list_participants(&main).await {
                Ok(p) => p,
                Err(()) => {
                    warn(
                        "absent-sweep ListParticipants failed, retaining entry for retry",
                        &main,
                    );
                    continue;
                }
            };
            if !present.contains(&identity) {
                if let Err(e) = c
                    .query(
                        "UPDATE meeting_participants SET left_at = now() WHERE meeting_id = $1 AND identity = $2 AND left_at IS NULL",
                        &[(&meeting, Type::INT8), (&identity, Type::TEXT)],
                    )
                    .await
                {
                    warn("absent-sweep left_at stamp failed, retaining entry for retry", e);
                    continue;
                }
            }
            self.absent
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&key);
        }
    }

    async fn gc_lost_webhooks(&self, c: &WorkerConnection, live: &HashSet<String>) {
        let rows = match c
            .query(
                "SELECT m.id, m.room_name::text FROM meetings m WHERE m.state = 'live' \
                 AND NOT EXISTS (SELECT 1 FROM meeting_participants p WHERE p.meeting_id = m.id AND p.left_at IS NULL) \
                 AND GREATEST(m.created_at, \
                      COALESCE((SELECT max(joined_at) FROM meeting_participants WHERE meeting_id = m.id), '-infinity'), \
                      COALESCE((SELECT max(left_at) FROM meeting_participants WHERE meeting_id = m.id), '-infinity') \
                    ) < now() - make_interval(secs => $1::int)",
                &[(&(STALE_WINDOW_SECS as i32), Type::INT4)],
            )
            .await
        {
            Ok(r) => r,
            Err(e) => return warn("lost-webhook query failed", e),
        };
        for row in rows {
            let room: String = row.get(1);
            if live.contains(&room) {
                continue;
            }
            if let Err(e) = c
                .query(
                    "SELECT meeting_participant_event($1::text::uuid, 'room_finished')",
                    &[(&room, Type::TEXT)],
                )
                .await
            {
                warn("room_finished ingest failed", e);
            }
        }
    }

    async fn reconcile_captions(&self, c: &WorkerConnection) {
        let sessions = if self.livekit.captions_configured() {
            match self.livekit.captions_status().await {
                Ok(s) => s,
                Err(()) => return warn("captions Status failed", "asrbot"),
            }
        } else {
            Vec::new()
        };
        let live: HashSet<&String> = sessions.iter().collect();
        // Leg a: a captionsOn row the bot no longer lists, past the grace.
        let rows = match c
            .query(
                "SELECT id, room_name::text, extract(epoch FROM (settings->>'captionsSince')::timestamptz)::float8 \
                 FROM meetings WHERE COALESCE((settings->>'captionsOn')::boolean, false) = true",
                &[],
            )
            .await
        {
            Ok(r) => r,
            Err(e) => return warn("captions crashed-session query failed", e),
        };
        let now = now_secs();
        let mut stale = Vec::new();
        for row in &rows {
            let (id, room): (i64, String) = (row.get(0), row.get(1));
            let Some(since): Option<f64> = row.get(2) else {
                // Go scans NULL into a time.Time: the whole leg fails.
                return warn("captions crashed-session scan failed", "NULL captionsSince");
            };
            if !live.contains(&room) && now - since > CAPTIONS_GRACE {
                stale.push(id);
            }
        }
        for id in stale {
            if let Err(e) = c
                .query(
                    "UPDATE meetings SET settings = jsonb_set(settings, '{captionsOn}', 'false') \
                     WHERE id = $1 AND COALESCE((settings->>'captionsOn')::boolean, false) = true",
                    &[(&id, Type::INT8)],
                )
                .await
            {
                warn("captions crashed-session flag-off failed", e);
                continue;
            }
            let bot = format!("cc:{id}");
            if let Err(e) = c
                .query(
                    "SELECT notify_meet_state($1, 'captions_state', jsonb_build_object('on', false, 'botIdentity', $2::text))",
                    &[(&id, Type::INT8), (&bot, Type::TEXT)],
                )
                .await
            {
                warn("captions crashed-session push failed", e);
            }
        }
        // Leg b: sessions of meetings no longer captioning, or ended.
        if sessions.is_empty() {
            return;
        }
        let rows = match c
            .query(
                "SELECT id, room_name::text, state, extract(epoch FROM (settings->>'captionsSince')::timestamptz)::float8 \
                 FROM meetings WHERE room_name::text = ANY($1::text[]) \
                 AND (COALESCE((settings->>'captionsOn')::boolean, false) = false OR state = 'ended')",
                &[(&sessions, Type::TEXT_ARRAY)],
            )
            .await
        {
            Ok(r) => r,
            Err(e) => return warn("captions orphaned-session query failed", e),
        };
        let mut orphans = Vec::new();
        for row in &rows {
            let (room, state): (String, String) = (row.get(1), row.get(2));
            let Some(since): Option<f64> = row.get(3) else {
                return warn(
                    "captions orphaned-session scan failed",
                    "NULL captionsSince",
                );
            };
            orphans.push((room, state, since));
        }
        for (room, state, since) in orphans {
            if self.livekit.captions_stop(&room).await.is_err() {
                warn("captions retry-Stop failed", &room);
            }
            if state == "ended"
                && now_secs() - since > CAPTIONS_GRACE
                && self.livekit.delete_room(&room).await.is_err()
            {
                warn("captions ended-meeting DeleteRoom backstop failed", &room);
            }
        }
    }
}

fn now_secs() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0.0, |d| d.as_secs_f64())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
