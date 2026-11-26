//! Wave 2.3 (#550): Live-DB integration, concurrency race, WORM/403, shadow
//! zero-deletion, legacy `blob_cleanup` fencing, and function-security tests for
//! Mark-and-Sweep S3 Blob GC.
mod common;

use common::BoxError;
use setjoin_conformance::{fixture, harness::Db};
use setjoin_gateway::{
    blob_cleanup::BlobCleanup,
    blob_gc::{BlobGcWorker, GcMode, PurgeOutcome, METRICS},
    blob_retention,
    recovery_worker::ObjectStore,
};
use setjoin_pg::{workers::WorkerDatabase, CommandOutcome, ScopedExecutor, Type};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashMap},
    future::Future,
    pin::Pin,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use tokio::sync::{oneshot, Notify};

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn sha(label: &str) -> String {
    format!("{:x}", Sha256::digest(label.as_bytes()))
}

fn op_id(label: &str) -> [u8; 16] {
    let digest = Sha256::digest(label.as_bytes());
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

#[derive(Clone, Debug)]
enum DeleteBehavior {
    Ok,
    Err(String),
    Delay(Duration),
}

struct PauseHook {
    entered: Mutex<Option<oneshot::Sender<()>>>,
    release: Arc<Notify>,
}

struct ControlledStore {
    objects: Mutex<BTreeMap<String, Vec<u8>>>,
    deletes: Mutex<Vec<String>>,
    delete_count: AtomicUsize,
    behaviors: Mutex<HashMap<String, DeleteBehavior>>,
    pause_hooks: Mutex<HashMap<String, Arc<PauseHook>>>,
}

impl ControlledStore {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            objects: Mutex::new(BTreeMap::new()),
            deletes: Mutex::new(Vec::new()),
            delete_count: AtomicUsize::new(0),
            behaviors: Mutex::new(HashMap::new()),
            pause_hooks: Mutex::new(HashMap::new()),
        })
    }

    fn seed(&self, key: &str, bytes: &[u8]) {
        self.objects
            .lock()
            .unwrap()
            .insert(key.to_owned(), bytes.to_vec());
    }

    fn contains(&self, key: &str) -> bool {
        self.objects.lock().unwrap().contains_key(key)
    }

    fn delete_calls(&self) -> Vec<String> {
        self.deletes.lock().unwrap().clone()
    }

    fn set_behavior(&self, key: &str, behavior: DeleteBehavior) {
        self.behaviors
            .lock()
            .unwrap()
            .insert(key.to_owned(), behavior);
    }

    fn clear_behavior(&self, key: &str) {
        self.behaviors.lock().unwrap().remove(key);
    }

    fn install_pause(&self, key: &str) -> (oneshot::Receiver<()>, Arc<Notify>) {
        let (tx, rx) = oneshot::channel();
        let release = Arc::new(Notify::new());
        let hook = Arc::new(PauseHook {
            entered: Mutex::new(Some(tx)),
            release: release.clone(),
        });
        self.pause_hooks
            .lock()
            .unwrap()
            .insert(key.to_owned(), hook);
        (rx, release)
    }
}

impl ObjectStore for ControlledStore {
    fn put<'a>(
        &'a self,
        key: &'a str,
        bytes: &'a [u8],
        _content_type: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            self.objects
                .lock()
                .unwrap()
                .insert(key.to_owned(), bytes.to_vec());
            Ok(())
        })
    }

    fn put_file<'a>(
        &'a self,
        key: &'a str,
        path: &'a std::path::Path,
        _size: u64,
        _content_type: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            let bytes = tokio::fs::read(path).await.map_err(|e| e.to_string())?;
            self.objects.lock().unwrap().insert(key.to_owned(), bytes);
            Ok(())
        })
    }

    fn remove<'a>(
        &'a self,
        key: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            self.delete_count.fetch_add(1, Ordering::SeqCst);
            self.deletes.lock().unwrap().push(key.to_owned());

            let hook = self.pause_hooks.lock().unwrap().remove(key);
            if let Some(hook) = hook {
                if let Some(tx) = hook.entered.lock().unwrap().take() {
                    let _ = tx.send(());
                }
                hook.release.notified().await;
            }

            let behavior = self
                .behaviors
                .lock()
                .unwrap()
                .get(key)
                .cloned()
                .unwrap_or(DeleteBehavior::Ok);

            match behavior {
                DeleteBehavior::Ok => {
                    self.objects.lock().unwrap().remove(key);
                    Ok(())
                }
                DeleteBehavior::Err(msg) => Err(msg),
                DeleteBehavior::Delay(d) => {
                    tokio::time::sleep(d).await;
                    self.objects.lock().unwrap().remove(key);
                    Ok(())
                }
            }
        })
    }
}

async fn seed_purging_blob(owner: &tokio_postgres::Client, digest: &str) -> Result<(), BoxError> {
    owner
        .execute(
            "INSERT INTO public.blobs (sha256, minio_ref, size_bytes, content_type, ref_count, created_at) \
             VALUES ($1, $2, 12, 'application/octet-stream', 0, now() - interval '72 hours') \
             ON CONFLICT (sha256) DO UPDATE SET created_at = EXCLUDED.created_at, ref_count = 0",
            &[&digest, &format!("mailblobs/{digest}")],
        )
        .await?;
    owner
        .execute(
            "INSERT INTO public.blob_gc_state \
                 (blob_sha256, gc_state, reclaim_eligible_at, purging_at, last_touched_at) \
             VALUES ($1, 'purging', now() - interval '48 hours', now() - interval '1 minute', now() - interval '72 hours') \
             ON CONFLICT (blob_sha256) DO UPDATE \
                SET gc_state = 'purging', \
                    reclaim_eligible_at = EXCLUDED.reclaim_eligible_at, \
                    purging_at = EXCLUDED.purging_at, \
                    last_touched_at = EXCLUDED.last_touched_at, \
                    retain_until = NULL, \
                    worm_locked_until = NULL",
            &[&digest],
        )
        .await?;
    Ok(())
}

async fn cleanup_blob(owner: &tokio_postgres::Client, digest: &str) {
    let _ = owner
        .execute("DELETE FROM public.blobs WHERE sha256 = $1", &[&digest])
        .await;
}

async fn auth_context(
    exec: &ScopedExecutor,
    user_id: i64,
) -> Result<setjoin_authz::AuthContext, BoxError> {
    let mut headers = hyper::HeaderMap::new();
    headers.insert("host", "mail.test".parse()?);
    headers.insert("origin", "http://mail.test".parse()?);
    headers.insert(
        "authorization",
        format!("Bearer {}", common::recovery_token(user_id)).parse()?,
    );
    let auth = setjoin_authz::authorize_request(
        exec,
        &common::recovery_keys(),
        "mailserver",
        &headers,
        "http",
    )
    .await
    .ok_or("failed to build verified AuthContext")?;
    Ok(auth.context().clone())
}

/// Scenario A: Tx 2B pauses inside fake-S3 DELETE while holding the per-sha256
/// advisory lock. Concurrent uploaders (`blobs.rs` `account_upload`, `chat_unfurl`
/// `unfurl_blob`, `recovery` `blob_gc_reactivate`, `storage::reimport_blob`) MUST
/// block on the advisory lock until Tx 2B finishes, then succeed cleanly after
/// Tx 2B commits.
#[tokio::test]
async fn scenario_a_uploaders_block_on_advisory_lock_during_tx2b_s3_delete() -> Result<(), BoxError>
{
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("blob-gc-race-a") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let account = fixture::account(&owner, "blob-gc-race-a").await?;
    let app_exec = ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn), 4)
        .map_err(|e| e.0)?
        .with_audit_keys("22".repeat(32), String::new());
    let worker_exec = ScopedExecutor::from_dsn(&db.dsn, 4)
        .map_err(|e| e.0)?
        .with_audit_keys("22".repeat(32), String::new());
    let actor = auth_context(&app_exec, account.user).await?;

    for uploader in [
        "blobs_put",
        "chat_unfurl",
        "recovery_verify",
        "reimport_blob",
    ] {
        let digest = sha(&format!("scenario-a-{uploader}-{}", account.user));
        seed_purging_blob(&owner, &digest).await?;
        let store = ControlledStore::new();
        store.seed(&digest, b"old-bytes-12");
        let (entered_rx, release) = store.install_pause(&digest);

        let gc = BlobGcWorker::new(WorkerDatabase::new(&db.dsn)?, store.clone());
        let sha_for_gc = digest.clone();
        let gc_task = tokio::spawn(async move { gc.purge_one(&sha_for_gc, 0).await });

        // Wait until Tx 2B holds the advisory lock and is paused inside S3 DELETE.
        tokio::time::timeout(Duration::from_secs(5), entered_rx)
            .await
            .map_err(|_| format!("{uploader}: Tx 2B never entered paused S3 DELETE"))?
            .map_err(|_| "pause channel closed")?;

        let app_c = app_exec.clone();
        let worker_c = worker_exec.clone();
        let actor_c = actor.clone();
        let sha_u = digest.clone();
        let uploader_task = tokio::spawn(async move {
            let op = op_id(&format!("op-a-{uploader}-{sha_u}"));
            match uploader {
                "blobs_put" => {
                    let out = setjoin_blobs::account_upload(
                        &app_c,
                        &actor_c,
                        &sha_u,
                        &format!("mailblobs/{sha_u}"),
                        12,
                        "text/plain",
                        op,
                    )
                    .await;
                    assert!(
                        matches!(out, CommandOutcome::Committed(_)),
                        "{uploader}: {out:?}"
                    );
                }
                "chat_unfurl" => {
                    let out = setjoin_chat::members::unfurl_blob(
                        &app_c,
                        &actor_c,
                        &sha_u,
                        &format!("mailblobs/{sha_u}"),
                        12,
                        "image/png",
                        op,
                    )
                    .await;
                    assert!(
                        matches!(out, CommandOutcome::Committed(_)),
                        "{uploader}: {out:?}"
                    );
                }
                "recovery_verify" => {
                    worker_c
                        .protocol_statement(
                            "SELECT public.blob_gc_reactivate($1)",
                            &[(&sha_u, Type::TEXT)],
                        )
                        .await
                        .expect("recovery pre-put reactivate must succeed after Tx 2B commits");
                }
                "reimport_blob" => {
                    let out = setjoin_platform::storage::reimport_blob(
                        &worker_c,
                        &actor_c,
                        op,
                        &sha_u,
                        &format!("mailblobs/{sha_u}"),
                        12,
                        "application/octet-stream",
                    )
                    .await;
                    assert!(
                        matches!(out, CommandOutcome::Committed(())),
                        "{uploader}: {out:?}"
                    );
                }
                _ => unreachable!(),
            }
        });

        // Prove the uploader is blocked on pg_advisory_xact_lock while Tx 2B is paused.
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(
            !uploader_task.is_finished(),
            "{uploader} must remain blocked on advisory lock while Tx 2B holds S3 DELETE"
        );

        // Release Tx 2B S3 DELETE -> commits delete -> uploader immediately unblocks and succeeds.
        release.notify_one();
        let gc_res = tokio::time::timeout(Duration::from_secs(5), gc_task).await??;
        assert_eq!(
            gc_res?,
            PurgeOutcome::Purged,
            "{uploader}: Tx 2B should purge cleanly"
        );
        tokio::time::timeout(Duration::from_secs(5), uploader_task).await??;

        if uploader != "recovery_verify" {
            let exists: bool = owner
                .query_one(
                    "SELECT EXISTS (SELECT 1 FROM public.blobs WHERE sha256 = $1)",
                    &[&digest],
                )
                .await?
                .get(0);
            assert!(
                exists,
                "{uploader}: fresh blobs row must exist after unblock"
            );
        }
        cleanup_blob(&owner, &digest).await;
    }

    common::remove_blob_account(&owner, &account).await?;
    Ok(())
}

/// Scenario B: Uploader interleaves BETWEEN Tx 2A (`claim_purging` -> `purging`)
/// and Tx 2B (`purge_one`). Every uploader (`blobs.rs` `account_upload`,
/// `chat_unfurl` `unfurl_blob`, `recovery` `verify_item`, `storage::reimport_blob`)
/// flips `blob_gc_state.gc_state` back to `active`, causing Tx 2B to abort with
/// `AbortedReactivated` and perform **0 S3 deletes**.
#[tokio::test]
async fn scenario_b_uploader_between_tx2a_and_tx2b_aborts_s3_delete() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("blob-gc-race-b") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let account = fixture::account(&owner, "blob-gc-race-b").await?;
    let app_exec = ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn), 4)
        .map_err(|e| e.0)?
        .with_audit_keys("22".repeat(32), String::new());
    let worker_exec = ScopedExecutor::from_dsn(&db.dsn, 4)
        .map_err(|e| e.0)?
        .with_audit_keys("22".repeat(32), String::new());
    let actor = auth_context(&app_exec, account.user).await?;

    let wdb = WorkerDatabase::new(&db.dsn)?;
    let wconn = wdb.connect().await?;

    for uploader in [
        "blobs_put",
        "chat_unfurl",
        "recovery_verify",
        "reimport_blob",
    ] {
        let digest = sha(&format!("scenario-b-{uploader}-{}", account.user));
        // Seed old unreferenced blob + mark eligible + run real Tx 2A claim_purging.
        owner
            .execute(
                "INSERT INTO public.blobs (sha256, minio_ref, size_bytes, content_type, ref_count, created_at) \
                 VALUES ($1, $2, 12, 'application/octet-stream', 0, now() - interval '72 hours') \
                 ON CONFLICT (sha256) DO UPDATE SET created_at = EXCLUDED.created_at, ref_count = 0",
                &[&digest, &format!("mailblobs/{digest}")],
            )
            .await?;
        owner
            .execute(
                "INSERT INTO public.blob_gc_state (blob_sha256, gc_state, reclaim_eligible_at, purging_at, last_touched_at) \
                 VALUES ($1, 'reclaim_eligible', now() - interval '48 hours', NULL, now() - interval '72 hours') \
                 ON CONFLICT (blob_sha256) DO UPDATE \
                    SET gc_state = 'reclaim_eligible', \
                        reclaim_eligible_at = EXCLUDED.reclaim_eligible_at, \
                        purging_at = NULL, \
                        last_touched_at = EXCLUDED.last_touched_at",
                &[&digest],
            )
            .await?;

        let store = ControlledStore::new();
        store.seed(&digest, b"live-payload");
        let gc = BlobGcWorker::new(wdb.clone(), store.clone());

        // Tx 2A transitions reclaim_eligible -> purging.
        let claimed = gc.claim_purging(&wconn, &digest, 1440, 1440, 0).await?;
        assert_eq!(claimed, "purging", "{uploader}: Tx 2A must claim purging");

        // Interleave uploader between Tx 2A and Tx 2B!
        let op = op_id(&format!("op-b-{uploader}-{digest}"));
        let mut recovery_incident: Option<String> = None;
        match uploader {
            "blobs_put" => {
                let out = setjoin_blobs::account_upload(
                    &app_exec,
                    &actor,
                    &digest,
                    &format!("mailblobs/{digest}"),
                    12,
                    "text/plain",
                    op,
                )
                .await;
                assert!(matches!(out, CommandOutcome::Committed(_)), "{out:?}");
            }
            "chat_unfurl" => {
                let out = setjoin_chat::members::unfurl_blob(
                    &app_exec,
                    &actor,
                    &digest,
                    &format!("mailblobs/{digest}"),
                    12,
                    "image/png",
                    op,
                )
                .await;
                assert!(matches!(out, CommandOutcome::Committed(_)), "{out:?}");
            }
            "recovery_verify" => {
                let ids = owner
                    .query_one(
                        "SELECT gen_random_uuid()::text, gen_random_uuid()::text",
                        &[],
                    )
                    .await?;
                let incident: String = ids.get(0);
                let session: String = ids.get(1);
                recovery_incident = Some(incident.clone());
                owner.execute(
                    "INSERT INTO mail_recovery_incidents(id,installation_id,minimum_timeline,maximum_timeline,reason,opened_by,step_up_binding,expires_at,idempotency_key) \
                     VALUES($1::text::uuid,gen_random_uuid(),1,1,'blob gc race test',$2,decode(repeat('aa',32),'hex'),now()+interval '1 day',gen_random_uuid())",
                    &[&incident, &account.user],
                ).await?;
                owner.execute(
                    "INSERT INTO mail_recovery_upload_sessions(id,incident_id,mailbox_id,uploading_user_id,device_id,artifact_identity,lineage_sha256,raw_mime_sha256,eligibility,declared_size,total_declared_size,next_offset,receipt,consented_at,expires_at,idempotency_key) \
                     VALUES($1::text::uuid,$2::text::uuid,$3,$4,gen_random_uuid(),decode(repeat('aa',32),'hex'),decode(repeat('bb',32),'hex'),decode($5,'hex'),'received',12,12,12,'{}',now(),now()+interval '1 day',gen_random_uuid())",
                    &[&session, &incident, &account.mailbox, &account.user, &digest],
                ).await?;
                owner.execute(
                    "INSERT INTO mail_recovery_upload_items(session_id,item_id,role,sha256,declared_size,next_offset) \
                     VALUES($1::text::uuid,'raw','raw',decode($2,'hex'),12,12)",
                    &[&session, &digest],
                ).await?;
                let out =
                    setjoin_blobs::verify_item(&worker_exec, &actor, &session, "raw", &digest, op)
                        .await;
                assert!(matches!(out, CommandOutcome::Committed(_)), "{out:?}");
            }
            "reimport_blob" => {
                let out = setjoin_platform::storage::reimport_blob(
                    &worker_exec,
                    &actor,
                    op,
                    &digest,
                    &format!("mailblobs/{digest}"),
                    12,
                    "application/octet-stream",
                )
                .await;
                assert!(matches!(out, CommandOutcome::Committed(())), "{out:?}");
            }
            _ => unreachable!(),
        }

        // Now run Tx 2B: MUST see gc_state='active', abort, and perform ZERO S3 deletes!
        let outcome = gc.purge_one(&digest, 0).await?;
        assert_eq!(
            outcome,
            PurgeOutcome::AbortedReactivated,
            "{uploader}: Tx 2B must abort when uploader reactivated blob"
        );
        assert!(
            store.delete_calls().is_empty(),
            "{uploader}: Tx 2B must perform 0 S3 deletes, got {:?}",
            store.delete_calls()
        );
        assert!(
            store.contains(&digest),
            "{uploader}: S3 bytes must stay intact"
        );

        let state: String = owner
            .query_one(
                "SELECT gc_state FROM public.blob_gc_state WHERE blob_sha256 = $1",
                &[&digest],
            )
            .await?
            .get(0);
        assert_eq!(
            state, "active",
            "{uploader}: companion state must be active"
        );

        if let Some(inc) = recovery_incident {
            let _ = owner
                .execute(
                    "DELETE FROM mail_recovery_incidents WHERE id = $1::text::uuid",
                    &[&inc],
                )
                .await;
        }
        cleanup_blob(&owner, &digest).await;
    }

    common::remove_blob_account(&owner, &account).await?;
    Ok(())
}

/// Scenario C: S3 500 error and Tx 2B timeout leave a durable `purging` row and
/// retry cleanly on the next live tick; consecutive S3 errors trip the circuit breaker.
/// Scenario D: S3 403 Object Lock reverts to `active` with `worm_locked_until` +
/// audit warning, and does not infinite-loop on subsequent ticks.
#[tokio::test]
async fn scenarios_c_and_d_s3_500_timeout_circuit_breaker_and_403_worm_lock() -> Result<(), BoxError>
{
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("blob-gc-cd") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let wdb = WorkerDatabase::new(&db.dsn)?;

    // Scenario C1: S3 500 -> durable purging row -> clean retry next tick
    let sha_500 = sha("scenario-c-500");
    seed_purging_blob(&owner, &sha_500).await?;
    let store = ControlledStore::new();
    store.seed(&sha_500, b"payload-500");
    store.set_behavior(
        &sha_500,
        DeleteBehavior::Err("S3 delete returned HTTP 500 InternalError".into()),
    );

    let gc = BlobGcWorker::new(wdb.clone(), store.clone())
        .with_mode(GcMode::Live)
        .with_worm_config(blob_retention::Config::Off)
        .with_s3_delete_timeout(Duration::from_millis(120))
        .with_max_consecutive_errors(2);

    let err = gc.purge_one(&sha_500, 0).await.unwrap_err();
    assert!(err.contains("500"), "unexpected error: {err}");
    let state: String = owner
        .query_one(
            "SELECT gc_state FROM public.blob_gc_state WHERE blob_sha256 = $1",
            &[&sha_500],
        )
        .await?
        .get(0);
    assert_eq!(state, "purging", "S3 500 must leave durable purging row");

    // Scenario C2: S3 timeout -> durable purging row -> clean retry next tick
    store.set_behavior(&sha_500, DeleteBehavior::Delay(Duration::from_millis(400)));
    let err = gc.purge_one(&sha_500, 0).await.unwrap_err();
    assert!(
        err.contains("timed out"),
        "expected timeout error, got: {err}"
    );
    let state: String = owner
        .query_one(
            "SELECT gc_state FROM public.blob_gc_state WHERE blob_sha256 = $1",
            &[&sha_500],
        )
        .await?
        .get(0);
    assert_eq!(
        state, "purging",
        "S3 timeout must leave durable purging row"
    );

    // Clear fault -> live tick resumes durable purging row and deletes cleanly!
    store.clear_behavior(&sha_500);
    let summary = gc.tick().await?;
    assert!(
        summary.purged >= 1,
        "expected retry to purge sha_500: {summary:?}"
    );
    assert!(
        !store.contains(&sha_500),
        "S3 object must be deleted after retry"
    );
    let gone: bool = owner
        .query_one(
            "SELECT NOT EXISTS (SELECT 1 FROM public.blobs WHERE sha256 = $1)",
            &[&sha_500],
        )
        .await?
        .get(0);
    assert!(gone, "blobs row must be deleted after retry");

    // Scenario C3: Circuit breaker halts after max_consecutive_errors (2) on 3 failing blobs
    let cb_shas = [sha("cb-1"), sha("cb-2"), sha("cb-3")];
    for s in &cb_shas {
        seed_purging_blob(&owner, s).await?;
        store.seed(s, b"cb");
        store.set_behavior(s, DeleteBehavior::Err("S3 delete returned HTTP 503".into()));
    }
    let cb_summary = gc.tick().await?;
    assert!(
        cb_summary.circuit_breaker_tripped,
        "circuit breaker must trip on consecutive 5xx errors: {cb_summary:?}"
    );
    assert_eq!(cb_summary.s3_errors, 2, "must halt right at threshold=2");
    for s in &cb_shas {
        cleanup_blob(&owner, s).await;
    }

    // Scenario D: S3 403 Object Lock under Audit V3 cutover -> records worm_locked_until,
    // reverts active, writes valid V3 HMAC audit warning, and does not infinite-loop.
    let v3_hmac_key = "55".repeat(32);
    let had_v3: bool = owner
        .query_one(
            "SELECT EXISTS (SELECT 1 FROM public.audit_chain_cutover)",
            &[],
        )
        .await?
        .get(0);
    if !had_v3 {
        owner
            .query_one(
                "SELECT set_config('app.audit_hmac_key', $1, false)",
                &[&v3_hmac_key],
            )
            .await?;
        owner
            .query_one("SELECT public.audit_chain_activate_v3()", &[])
            .await?;
    }

    let sha_403 = sha("scenario-d-403-worm");
    let d_res: Result<(), BoxError> = async {
        seed_purging_blob(&owner, &sha_403).await?;
        let store_d = ControlledStore::new();
        store_d.seed(&sha_403, b"worm-locked");
        store_d.set_behavior(
            &sha_403,
            DeleteBehavior::Err("S3 delete returned HTTP 403 AccessDenied: Object Lock".into()),
        );
        let wdb_v3 = WorkerDatabase::new(&db.dsn)?
            .with_audit_keys(String::new(), v3_hmac_key.clone());
        let gc_d = BlobGcWorker::new(wdb_v3, store_d.clone())
            .with_mode(GcMode::Live)
            .with_worm_config(blob_retention::Config::Off);

        let outcome = gc_d.purge_one(&sha_403, 0).await?;
        assert_eq!(outcome, PurgeOutcome::WormLocked403);
        let row = owner
            .query_one(
                "SELECT gc_state, worm_locked_until > now() FROM public.blob_gc_state WHERE blob_sha256 = $1",
                &[&sha_403],
            )
            .await?;
        assert_eq!(row.get::<_, String>(0), "active");
        assert!(
            row.get::<_, bool>(1),
            "worm_locked_until must be in the future"
        );

        let audit_count: i64 = owner
            .query_one(
                "SELECT count(*) FROM public.admin_audit_log \
                  WHERE action = 'blob_gc_worm_lock_detected' AND after_state->>'sha256' = $1",
                &[&sha_403],
            )
            .await?
            .get(0);
        assert!(
            audit_count >= 1,
            "must write core Audit V3 warning for S3 403 Object Lock"
        );

        // Next live tick must NOT re-mark or re-attempt S3 DELETE (zero infinite loop!).
        let calls_before = store_d.delete_calls().len();
        let next_tick = gc_d.tick().await?;
        assert_eq!(
            store_d.delete_calls().len(),
            calls_before,
            "403 Object Lock blob must not infinite-loop in purging: {next_tick:?}"
        );
        Ok(())
    }
    .await;
    cleanup_blob(&owner, &sha_403).await;
    if !had_v3 {
        let _ = owner
            .execute("DELETE FROM public.audit_chain_cutover", &[])
            .await;
    }
    d_res?;
    Ok(())
}

/// Fail-closed on `WORM_MODE=invalid`, Shadow zero-deletion proof + Prometheus counters,
/// legacy `blob_cleanup.rs` mutual exclusion when `blob_gc_config.mode='live'`, and
/// `rls_preflight` `SECURITY DEFINER` / `SECURITY INVOKER` posture checks.
#[tokio::test]
async fn worm_invalid_shadow_zero_delete_legacy_fencing_and_rls_posture() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("blob-gc-safety") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let account = fixture::account(&owner, "blob-gc-safety").await?;
    let wdb = WorkerDatabase::new(&db.dsn)?;

    // 1. WORM_MODE=invalid fail-closed refusal
    let sha_worm_inv = sha("worm-invalid-candidate");
    owner
        .execute(
            "INSERT INTO public.blobs (sha256, minio_ref, size_bytes, content_type, ref_count, created_at) \
             VALUES ($1, $2, 10, 'text/plain', 0, now() - interval '72 hours') \
             ON CONFLICT (sha256) DO NOTHING",
            &[&sha_worm_inv, &format!("mailblobs/{sha_worm_inv}")],
        )
        .await?;
    let store_inv = ControlledStore::new();
    store_inv.seed(&sha_worm_inv, b"keep-me");
    let gc_inv = BlobGcWorker::new(wdb.clone(), store_inv.clone())
        .with_mode(GcMode::Live)
        .with_worm_config(blob_retention::Config::Invalid);
    let err = gc_inv.tick().await.unwrap_err();
    assert!(
        err.contains("WORM_MODE"),
        "expected fail-closed WORM_MODE error, got: {err}"
    );
    assert!(
        store_inv.delete_calls().is_empty(),
        "0 S3 deletes on invalid WORM"
    );
    assert!(store_inv.contains(&sha_worm_inv));

    // 2. Shadow zero-deletion proof under Audit V3 cutover
    // (detects users.avatar_sha256 ref_count=0 & drifted ref_count>0)
    let v3_hmac_key = "66".repeat(32);
    let had_v3: bool = owner
        .query_one(
            "SELECT EXISTS (SELECT 1 FROM public.audit_chain_cutover)",
            &[],
        )
        .await?
        .get(0);
    if !had_v3 {
        owner
            .query_one(
                "SELECT set_config('app.audit_hmac_key', $1, false)",
                &[&v3_hmac_key],
            )
            .await?;
        owner
            .query_one("SELECT public.audit_chain_activate_v3()", &[])
            .await?;
    }

    let sha_avatar = sha("shadow-avatar-zero-ref");
    let sha_drifted = sha("shadow-drifted-refcount");
    let shadow_block: Result<(), BoxError> = async {
        owner
            .execute(
                "INSERT INTO public.blobs (sha256, minio_ref, size_bytes, content_type, ref_count, created_at) \
                 VALUES ($1, $2, 10, 'image/png', 0, now() - interval '72 hours'), \
                        ($3, $4, 10, 'text/plain', 3, now() - interval '72 hours') \
                 ON CONFLICT (sha256) DO NOTHING",
                &[
                    &sha_avatar,
                    &format!("mailblobs/{sha_avatar}"),
                    &sha_drifted,
                    &format!("mailblobs/{sha_drifted}"),
                ],
            )
            .await?;
        owner
            .execute(
                "UPDATE public.users SET avatar_sha256 = $1 WHERE id = $2",
                &[&sha_avatar, &account.user],
            )
            .await?;

        let store_shadow = ControlledStore::new();
        store_shadow.seed(&sha_worm_inv, b"keep-me");
        store_shadow.seed(&sha_avatar, b"avatar");
        store_shadow.seed(&sha_drifted, b"drifted");
        let wdb_v3 = WorkerDatabase::new(&db.dsn)?
            .with_audit_keys(String::new(), v3_hmac_key.clone());
        let gc_shadow = BlobGcWorker::new(wdb_v3, store_shadow.clone())
            .with_mode(GcMode::Shadow)
            .with_worm_config(blob_retention::Config::Off);

        let shadow_res = gc_shadow.tick().await?;
        assert_eq!(shadow_res.mode, Some(GcMode::Shadow));
        assert_eq!(shadow_res.purged, 0, "shadow mode must purge 0 blobs");
        assert!(
            store_shadow.delete_calls().is_empty(),
            "shadow mode must perform 0 S3 deletes"
        );
        assert!(
            shadow_res.only_in_refcount_zero >= 1,
            "shadow must detect users.avatar_sha256 at ref_count=0: {shadow_res:?}"
        );
        assert!(
            shadow_res.only_in_mark_and_sweep >= 1,
            "shadow must detect drifted ref_count=3 with 0 live roots: {shadow_res:?}"
        );
        let prom = METRICS.render_prometheus();
        assert!(prom.contains("setjoin_blob_gc_shadow_runs_total"));
        assert!(prom.contains("setjoin_blob_gc_shadow_only_in_refcount_zero_total"));
        assert!(prom.contains("setjoin_blob_gc_shadow_only_in_mark_and_sweep_total"));
        Ok(())
    }
    .await;

    // Clean shadow fixtures & restore audit_chain_cutover before testing legacy fencing
    let _ = owner
        .execute(
            "UPDATE public.users SET avatar_sha256 = NULL WHERE id = $1",
            &[&account.user],
        )
        .await;
    cleanup_blob(&owner, &sha_worm_inv).await;
    cleanup_blob(&owner, &sha_avatar).await;
    cleanup_blob(&owner, &sha_drifted).await;
    if !had_v3 {
        let _ = owner
            .execute("DELETE FROM public.audit_chain_cutover", &[])
            .await;
    }
    shadow_block?;

    // 3. Legacy blob_cleanup.rs mutual exclusion when blob_gc_config.mode='live'
    let sha_young_queue = sha("legacy-queue-young-1h");
    let sha_bare_orphan = sha("legacy-orphan-bare-64hex");
    let key_prefixed_live = format!("inbound/{}", sha("legacy-prefixed-in-outbound"));
    let key_prefixed_dead = format!("inbound/{}", sha("legacy-prefixed-truly-dead"));

    owner
        .execute(
            "INSERT INTO public.blobs (sha256, minio_ref, size_bytes, content_type, ref_count, created_at) \
             VALUES ($1, $2, 5, 'text/plain', 0, now() - interval '1 hour') \
             ON CONFLICT (sha256) DO NOTHING",
            &[&sha_young_queue, &format!("mailblobs/{sha_young_queue}")],
        )
        .await?;
    owner
        .execute(
            "INSERT INTO public.blob_cleanup_queue (blob_sha256, scheduled_at, delay_minutes) \
             VALUES ($1, now() - interval '30 minutes', 5) \
             ON CONFLICT (blob_sha256) DO UPDATE SET scheduled_at = EXCLUDED.scheduled_at, delay_minutes = 5",
            &[&sha_young_queue],
        )
        .await?;
    owner
        .execute(
            "INSERT INTO public.outbound_queue (message_id, from_addr, rcpt_addrs, raw_ref) \
             VALUES ('<gc-fence-test@test>', 'a@test', ARRAY['b@test'], $1)",
            &[&key_prefixed_live],
        )
        .await?;
    for k in [&sha_bare_orphan, &key_prefixed_live, &key_prefixed_dead] {
        owner
            .execute(
                "INSERT INTO public.orphaned_message_blobs (raw_ref) VALUES ($1) ON CONFLICT DO NOTHING",
                &[k],
            )
            .await?;
    }

    let store_live = ControlledStore::new();
    store_live.seed(&sha_young_queue, b"young");
    store_live.seed(&sha_bare_orphan, b"bare");
    store_live.seed(&key_prefixed_live, b"live-outbound");
    store_live.seed(&key_prefixed_dead, b"dead-inbound");

    owner
        .execute(
            "UPDATE public.blob_gc_config SET mode = 'live' WHERE id = 1",
            &[],
        )
        .await?;
    let cleanup = BlobCleanup::new(wdb.clone(), store_live.clone());
    cleanup.tick().await;
    // Always restore mode = 'off' immediately!
    owner
        .execute(
            "UPDATE public.blob_gc_config SET mode = 'off' WHERE id = 1",
            &[],
        )
        .await?;

    assert!(
        store_live.contains(&sha_young_queue),
        "BLOB_GC_MODE=live must disable legacy process_cleanup_queue"
    );
    assert!(
        store_live.contains(&sha_bare_orphan),
        "BLOB_GC_MODE=live must fence bare 64-hex keys in process_orphaned_blobs"
    );
    assert!(
        store_live.contains(&key_prefixed_live),
        "BLOB_GC_MODE=live must protect prefixed keys referenced in outbound_queue"
    );
    assert!(
        !store_live.contains(&key_prefixed_dead),
        "BLOB_GC_MODE=live must still reap truly orphaned prefixed inbound/* keys"
    );

    owner
        .execute(
            "DELETE FROM public.outbound_queue WHERE raw_ref = $1",
            &[&key_prefixed_live],
        )
        .await?;
    owner
        .execute(
            "DELETE FROM public.orphaned_message_blobs WHERE raw_ref = ANY($1)",
            &[&vec![
                sha_bare_orphan.clone(),
                key_prefixed_live.clone(),
                key_prefixed_dead.clone(),
            ]],
        )
        .await?;
    cleanup_blob(&owner, &sha_young_queue).await;

    // 4. Function security / rls_preflight posture check (other_secdef_drifted invariant)
    let worker_only_fns = [
        "public.blob_has_live_reference(text)",
        "public.blob_gc_live_sources(text)",
        "public.blob_is_held_or_retained(text,integer)",
        "public.blob_gc_mark(integer,integer,integer)",
        "public.blob_gc_claim_purging(text,integer,integer,integer)",
        "public.blob_gc_record_worm_lock(text,timestamptz,text)",
        "public.blob_gc_shadow_reconcile(integer,integer,integer)",
    ];
    for sig in worker_only_fns {
        let row = owner
            .query_one(
                "SELECT p.prosecdef, \
                        has_function_privilege('public', p.oid, 'EXECUTE'), \
                        has_function_privilege('setjoin_app', p.oid, 'EXECUTE'), \
                        has_function_privilege('setjoin_worker', p.oid, 'EXECUTE') \
                   FROM pg_proc p WHERE p.oid = to_regprocedure($1)",
                &[&sig],
            )
            .await?;
        assert!(!row.get::<_, bool>(0), "{sig} must be SECURITY INVOKER");
        assert!(!row.get::<_, bool>(1), "{sig} must revoke PUBLIC");
        assert!(!row.get::<_, bool>(2), "{sig} must revoke setjoin_app");
        assert!(row.get::<_, bool>(3), "{sig} must grant setjoin_worker");
    }

    let reactivate = owner
        .query_one(
            "SELECT p.prosecdef, \
                    pg_get_userbyid(p.proowner), \
                    has_function_privilege('public', p.oid, 'EXECUTE'), \
                    has_function_privilege('setjoin_app', p.oid, 'EXECUTE'), \
                    has_function_privilege('setjoin_worker', p.oid, 'EXECUTE'), \
                    has_schema_privilege('setjoin_worker', 'public', 'CREATE') \
               FROM pg_proc p WHERE p.oid = to_regprocedure('public.blob_gc_reactivate(text)')",
            &[],
        )
        .await?;
    assert!(
        reactivate.get::<_, bool>(0),
        "blob_gc_reactivate must be SECURITY DEFINER"
    );
    assert_eq!(reactivate.get::<_, String>(1), "setjoin_worker");
    assert!(
        !reactivate.get::<_, bool>(2),
        "blob_gc_reactivate must revoke PUBLIC"
    );
    assert!(
        reactivate.get::<_, bool>(3),
        "blob_gc_reactivate must grant setjoin_app"
    );
    assert!(
        reactivate.get::<_, bool>(4),
        "blob_gc_reactivate must grant setjoin_worker"
    );
    assert!(
        !reactivate.get::<_, bool>(5),
        "setjoin_worker must NOT retain CREATE on schema public"
    );

    // Aggregate rls_preflight `other_secdef_drifted = 0` check across ALL non-extension
    // SECURITY DEFINER functions in schema `public`:
    //   - No 2-arg blob_gc_reactivate(text,timestamptz) exists
    //   - Every worker-owned SECURITY DEFINER function revokes PUBLIC EXECUTE
    //   - No non-extension SECURITY DEFINER function in `public` is owned by setjoin_app
    //     or has drifted away from setjoin_worker when named `blob_gc%`
    let old_sig_exists: bool = owner
        .query_one(
            "SELECT to_regprocedure('public.blob_gc_reactivate(text,timestamptz)') IS NOT NULL",
            &[],
        )
        .await?
        .get(0);
    assert!(
        !old_sig_exists,
        "2-arg blob_gc_reactivate(text,timestamptz) must not exist"
    );
    let other_secdef_drifted: i64 = owner
        .query_one(
            "SELECT count(*) \
               FROM pg_proc p \
               JOIN pg_namespace n ON n.oid = p.pronamespace \
               JOIN pg_roles r ON r.oid = p.proowner \
              WHERE n.nspname = 'public' \
                AND p.prosecdef \
                AND NOT EXISTS ( \
                    SELECT 1 FROM pg_depend d \
                     WHERE d.classid = 'pg_proc'::regclass \
                       AND d.objid = p.oid \
                       AND d.deptype = 'e' \
                ) \
                AND ( \
                    r.rolname = 'setjoin_app' \
                    OR (p.proname LIKE 'blob\\_gc%' AND (r.rolname <> 'setjoin_worker' OR has_function_privilege('public', p.oid, 'EXECUTE'))) \
                    OR (r.rolname = 'setjoin_worker' AND has_function_privilege('public', p.oid, 'EXECUTE')) \
                )",
            &[],
        )
        .await?
        .get(0);
    assert_eq!(
        other_secdef_drifted, 0,
        "other_secdef_drifted must be 0 across all non-extension public SECURITY DEFINER functions"
    );

    common::remove_blob_account(&owner, &account).await?;
    Ok(())
}
