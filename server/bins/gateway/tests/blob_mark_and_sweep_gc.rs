//! Wave 2.3 (#550): Live-DB integration, concurrency race, WORM/403, shadow
//! zero-deletion, legacy `blob_cleanup` fencing, and function-security tests for
//! Mark-and-Sweep S3 Blob GC.
use crate::common;

use common::BoxError;
use setjoin_conformance::{fixture, harness::Db};
use setjoin_gateway::{
    blob_cleanup::BlobCleanup,
    blob_gc::{BlobGcWorker, GcMode, PurgeOutcome, METRICS},
    blob_retention,
    recovery_worker::{BlobDeleteOutcome, ObjectStore, S3Store},
    supervisor::worm::{BlobPromoteConsumer, BlobReapRetryConsumer, WormArmConsumer},
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

    fn promote_object<'a>(
        &'a self,
        src: &'a str,
        dst: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            let mut objs = self.objects.lock().unwrap();
            let bytes = objs
                .get(src)
                .cloned()
                .ok_or_else(|| format!("missing staging object {src}"))?;
            objs.insert(dst.to_owned(), bytes);
            Ok(())
        })
    }

    fn object_exists<'a>(
        &'a self,
        key: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<bool, String>> + Send + 'a>> {
        Box::pin(async move { Ok(self.objects.lock().unwrap().contains_key(key)) })
    }

    fn retain_object<'a>(
        &'a self,
        key: &'a str,
        _mode: &'a str,
        _until: &'a str,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<(), setjoin_gateway::recovery_worker::RetentionError>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            if self.objects.lock().unwrap().contains_key(key) {
                Ok(())
            } else {
                Err(setjoin_gateway::recovery_worker::RetentionError::NotFound)
            }
        })
    }
}

async fn seed_purging_blob(owner: &tokio_postgres::Client, digest: &str) -> Result<(), BoxError> {
    owner
        .execute(
            "INSERT INTO public.blobs (sha256, minio_ref, size_bytes, content_type, created_at) \
             VALUES ($1, $2, 12, 'application/octet-stream', now() - interval '72 hours') \
             ON CONFLICT (sha256) DO UPDATE SET created_at = EXCLUDED.created_at",
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

async fn authorize_user(
    exec: &ScopedExecutor,
    user_id: i64,
) -> Result<setjoin_authz::Authorized, BoxError> {
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
    .ok_or("failed to build verified Authorized")?;
    Ok(auth)
}

fn tx_factory(
    app: &ScopedExecutor,
    worker: Option<&ScopedExecutor>,
) -> Result<setjoin_authz::principals::TxFactory, BoxError> {
    setjoin_gateway::policy_composition::tx_factory_from_executors(app, worker)
        .ok_or_else(|| BoxError::from("tx_factory unavailable"))
}

async fn mint_user(
    factory: &setjoin_authz::principals::TxFactory,
    exec: &ScopedExecutor,
    user_id: i64,
) -> Result<setjoin_authz::principals::UserPrincipal, BoxError> {
    let auth = authorize_user(exec, user_id).await?;
    factory
        .mint_user_from_authorized(&auth, "127.0.0.1")
        .await
        .map_err(|e| BoxError::from(e.to_string()))
}

async fn mint_storage_admin(
    owner: &tokio_postgres::Client,
    factory: &setjoin_authz::principals::TxFactory,
    exec: &ScopedExecutor,
    user_id: i64,
    label: &str,
) -> Result<(setjoin_authz::principals::AdminPermissionProof, i64), BoxError> {
    let role_name = format!("blob-gc-{label}-{user_id}");
    let role_id: i64 = owner
        .query_one(
            "INSERT INTO admin_role_groups(name, permissions) VALUES($1, ARRAY['system.storage']) \
             ON CONFLICT (name) DO UPDATE SET permissions = EXCLUDED.permissions RETURNING id",
            &[&role_name],
        )
        .await?
        .get(0);
    owner
        .execute(
            "INSERT INTO admin_role_assignments(user_id, role_group_id) VALUES($1, $2) \
             ON CONFLICT DO NOTHING",
            &[&user_id, &role_id],
        )
        .await?;
    let auth = authorize_user(exec, user_id).await?;
    let admin = factory
        .mint_admin_from_authorized(&auth, "127.0.0.1")
        .await
        .map_err(|e| BoxError::from(e.to_string()))?;
    let proof = admin
        .require_permission("system.storage")
        .map_err(|e| BoxError::from(e.to_string()))?;
    Ok((proof, role_id))
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
    let app_factory = tx_factory(&app_exec, Some(&worker_exec))?;
    let worker_factory = tx_factory(&worker_exec, Some(&worker_exec))?;
    let actor = mint_user(&app_factory, &app_exec, account.user).await?;
    let (admin_proof, admin_role_id) =
        mint_storage_admin(&owner, &app_factory, &app_exec, account.user, "race-a").await?;

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

        let app_f = app_factory.clone();
        let worker_f = worker_factory.clone();
        let worker_c = worker_exec.clone();
        let actor_c = actor.clone();
        let admin_c = admin_proof.clone();
        let sha_u = digest.clone();
        let uploader_task = tokio::spawn(async move {
            let op = op_id(&format!("op-a-{uploader}-{sha_u}"));
            match uploader {
                "blobs_put" => {
                    let out = setjoin_blobs::account_upload(
                        &app_f,
                        &actor_c,
                        &sha_u,
                        &format!("mailblobs/{sha_u}"),
                        12,
                        "text/plain",
                        None,
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
                        &app_f,
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
                        &worker_f,
                        &actor_c,
                        &admin_c,
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

    let _ = owner
        .execute(
            "DELETE FROM admin_role_assignments WHERE role_group_id = $1",
            &[&admin_role_id],
        )
        .await;
    let _ = owner
        .execute(
            "DELETE FROM admin_role_groups WHERE id = $1",
            &[&admin_role_id],
        )
        .await;
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
    let app_factory = tx_factory(&app_exec, Some(&worker_exec))?;
    let worker_factory = tx_factory(&worker_exec, Some(&worker_exec))?;
    let actor = mint_user(&app_factory, &app_exec, account.user).await?;
    let (admin_proof, admin_role_id) =
        mint_storage_admin(&owner, &app_factory, &app_exec, account.user, "race-b").await?;

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
                "INSERT INTO public.blobs (sha256, minio_ref, size_bytes, content_type, created_at) \
                 VALUES ($1, $2, 12, 'application/octet-stream', now() - interval '72 hours') \
                 ON CONFLICT (sha256) DO UPDATE SET created_at = EXCLUDED.created_at",
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
                    &app_factory,
                    &actor,
                    &digest,
                    &format!("mailblobs/{digest}"),
                    12,
                    "text/plain",
                    None,
                    op,
                )
                .await;
                assert!(matches!(out, CommandOutcome::Committed(_)), "{out:?}");
            }
            "chat_unfurl" => {
                let out = setjoin_chat::members::unfurl_blob(
                    &app_factory,
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
                let out = setjoin_blobs::verify_item(
                    &worker_factory,
                    &actor,
                    &session,
                    "raw",
                    &digest,
                    None,
                    op,
                )
                .await;
                assert!(matches!(out, CommandOutcome::Committed(_)), "{out:?}");
            }
            "reimport_blob" => {
                let out = setjoin_platform::storage::reimport_blob(
                    &worker_factory,
                    &actor,
                    &admin_proof,
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

    let _ = owner
        .execute(
            "DELETE FROM admin_role_assignments WHERE role_group_id = $1",
            &[&admin_role_id],
        )
        .await;
    let _ = owner
        .execute(
            "DELETE FROM admin_role_groups WHERE id = $1",
            &[&admin_role_id],
        )
        .await;
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
    cleanup_blob(&owner, &sha_worm_inv).await;
    owner
        .execute(
            "INSERT INTO public.blobs (sha256, minio_ref, size_bytes, content_type, created_at) \
             VALUES ($1, $2, 10, 'text/plain', now() - interval '72 hours') \
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

    // 2. Shadow mode zero-deletion proof (mark-only, 0 deletes) + Prometheus metrics
    let sha_avatar = sha("shadow-avatar-zero-ref");
    let sha_orphan_shadow = sha("shadow-orphan-unreferenced");
    cleanup_blob(&owner, &sha_avatar).await;
    cleanup_blob(&owner, &sha_orphan_shadow).await;
    owner
        .execute(
            "INSERT INTO public.blobs (sha256, minio_ref, size_bytes, content_type, created_at) \
             VALUES ($1, $2, 10, 'image/png', now() - interval '72 hours'), \
                    ($3, $4, 10, 'text/plain', now() - interval '72 hours') \
             ON CONFLICT (sha256) DO NOTHING",
            &[
                &sha_avatar,
                &format!("mailblobs/{sha_avatar}"),
                &sha_orphan_shadow,
                &format!("mailblobs/{sha_orphan_shadow}"),
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
    store_shadow.seed(&sha_orphan_shadow, b"orphan");
    let gc_shadow = BlobGcWorker::new(wdb.clone(), store_shadow.clone())
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
        shadow_res.marked_eligible >= 1,
        "shadow mode must still mark unreferenced blobs eligible: {shadow_res:?}"
    );
    let prom = METRICS.render_prometheus();
    assert!(prom.contains("setjoin_blob_gc_shadow_runs_total"));
    assert!(prom.contains("setjoin_blob_gc_sweep_purged_total"));

    // Verify blob_live_catalog() callable by non-superuser setjoin_owner
    owner
        .batch_execute("BEGIN; SET LOCAL ROLE setjoin_owner;")
        .await?;
    let owner_live_count: i64 = owner
        .query_one(
            "SELECT count(*) FROM public.blob_live_catalog() WHERE sha256 = $1",
            &[&sha_avatar],
        )
        .await?
        .get(0);
    let owner_dead_count: i64 = owner
        .query_one(
            "SELECT count(*) FROM public.blob_live_catalog() WHERE sha256 = $1",
            &[&sha_orphan_shadow],
        )
        .await?
        .get(0);
    owner.batch_execute("ROLLBACK;").await?;
    assert_eq!(
        owner_live_count, 1,
        "setjoin_owner must see live avatar blob in blob_live_catalog()"
    );
    assert_eq!(
        owner_dead_count, 0,
        "blob_live_catalog() must exclude unreferenced blob"
    );

    let _ = owner
        .execute(
            "UPDATE public.users SET avatar_sha256 = NULL WHERE id = $1",
            &[&account.user],
        )
        .await;
    cleanup_blob(&owner, &sha_worm_inv).await;
    cleanup_blob(&owner, &sha_avatar).await;
    cleanup_blob(&owner, &sha_orphan_shadow).await;

    // 3. Wave 2.4 BlobCleanup::tick() live-mode fencing (grace + orphan raw_ref protection)
    let sha_young = sha("live-young-1h");
    let sha_bare_in_blobs = sha("live-orphan-bare-in-blobs");
    let key_prefixed_live = format!("inbound/{}", sha("live-prefixed-in-outbound"));
    let key_prefixed_dead = format!("inbound/{}", sha("live-prefixed-truly-dead"));

    owner
        .execute(
            "INSERT INTO public.blobs (sha256, minio_ref, size_bytes, content_type, created_at) \
             VALUES ($1, $2, 5, 'text/plain', now() - interval '1 hour'), \
                    ($3, $4, 5, 'text/plain', now() - interval '1 hour') \
             ON CONFLICT (sha256) DO NOTHING",
            &[
                &sha_young,
                &format!("mailblobs/{sha_young}"),
                &sha_bare_in_blobs,
                &format!("mailblobs/{sha_bare_in_blobs}"),
            ],
        )
        .await?;
    owner
        .execute(
            "INSERT INTO public.outbound_queue (message_id, from_addr, rcpt_addrs, raw_ref) \
             VALUES ('<gc-fence-test@test>', 'a@test', ARRAY['b@test'], $1)",
            &[&key_prefixed_live],
        )
        .await?;
    for k in [&sha_bare_in_blobs, &key_prefixed_live, &key_prefixed_dead] {
        owner
            .execute(
                "INSERT INTO public.orphaned_message_blobs (raw_ref) VALUES ($1) ON CONFLICT DO NOTHING",
                &[k],
            )
            .await?;
    }

    let store_live = ControlledStore::new();
    store_live.seed(&sha_young, b"young");
    store_live.seed(&sha_bare_in_blobs, b"bare");
    store_live.seed(&key_prefixed_live, b"live-outbound");
    store_live.seed(&key_prefixed_dead, b"dead-inbound");

    let cleanup = BlobCleanup::new(wdb.clone(), store_live.clone());
    cleanup.tick().await;

    assert!(
        store_live.contains(&sha_young),
        "live Mark-and-Sweep must protect young blobs within 24h grace"
    );
    assert!(
        store_live.contains(&sha_bare_in_blobs),
        "bare 64-hex key present in public.blobs must stay owned by Mark-and-Sweep"
    );
    assert!(
        store_live.contains(&key_prefixed_live),
        "sweep_orphaned_message_blobs must protect prefixed keys referenced in outbound_queue"
    );
    assert!(
        !store_live.contains(&key_prefixed_dead),
        "sweep_orphaned_message_blobs must reap truly orphaned prefixed inbound/* keys"
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
                sha_bare_in_blobs.clone(),
                key_prefixed_live.clone(),
                key_prefixed_dead.clone(),
            ]],
        )
        .await?;
    cleanup_blob(&owner, &sha_young).await;
    cleanup_blob(&owner, &sha_bare_in_blobs).await;

    // 4. Function security / rls_preflight posture check (other_secdef_drifted invariant)
    let worker_only_fns = [
        "public.blob_has_live_reference(text)",
        "public.blob_gc_live_sources(text)",
        "public.blob_is_held_or_retained(text,integer)",
        "public.blob_gc_mark(integer,integer,integer)",
        "public.blob_gc_claim_purging(text,integer,integer,integer)",
        "public.blob_gc_record_worm_lock(text,timestamptz,text)",
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

    for sig in [
        "public.blob_gc_reactivate(text)",
        "public.blob_gc_reactivate_v2(text,text)",
        "public.blob_promote_recover_enqueue(text,text,double precision)",
        "public.blob_promote_recover_complete(bigint,text,text)",
    ] {
        let row = owner
            .query_one(
                "SELECT p.prosecdef, \
                        pg_get_userbyid(p.proowner), \
                        has_function_privilege('public', p.oid, 'EXECUTE'), \
                        has_function_privilege('setjoin_app', p.oid, 'EXECUTE'), \
                        has_function_privilege('setjoin_worker', p.oid, 'EXECUTE'), \
                        has_schema_privilege('setjoin_worker', 'public', 'CREATE') \
                   FROM pg_proc p WHERE p.oid = to_regprocedure($1)",
                &[&sig],
            )
            .await?;
        assert!(row.get::<_, bool>(0), "{sig} must be SECURITY DEFINER");
        assert_eq!(row.get::<_, String>(1), "setjoin_worker", "{sig} owner");
        assert!(!row.get::<_, bool>(2), "{sig} must revoke PUBLIC");
        assert!(row.get::<_, bool>(3), "{sig} must grant setjoin_app");
        assert!(row.get::<_, bool>(4), "{sig} must grant setjoin_worker");
        assert!(
            !row.get::<_, bool>(5),
            "setjoin_worker must NOT retain CREATE on schema public"
        );
    }

    let live_cat = owner
        .query_one(
            "SELECT p.prosecdef, \
                    pg_get_userbyid(p.proowner), \
                    has_function_privilege('public', p.oid, 'EXECUTE'), \
                    has_function_privilege('setjoin_app', p.oid, 'EXECUTE'), \
                    has_function_privilege('setjoin_worker', p.oid, 'EXECUTE'), \
                    has_function_privilege('setjoin_owner', p.oid, 'EXECUTE') \
               FROM pg_proc p WHERE p.oid = to_regprocedure('public.blob_live_catalog()')",
            &[],
        )
        .await?;
    assert!(
        live_cat.get::<_, bool>(0),
        "blob_live_catalog must be SECURITY DEFINER"
    );
    assert_eq!(live_cat.get::<_, String>(1), "setjoin_worker");
    assert!(
        !live_cat.get::<_, bool>(2),
        "blob_live_catalog must revoke PUBLIC"
    );
    assert!(
        !live_cat.get::<_, bool>(3),
        "blob_live_catalog must revoke setjoin_app"
    );
    assert!(
        live_cat.get::<_, bool>(4),
        "blob_live_catalog must grant setjoin_worker"
    );
    assert!(
        live_cat.get::<_, bool>(5),
        "blob_live_catalog must grant setjoin_owner"
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

/// Wave 2.4 Stress A: 16 concurrent dedup uploads racing with `BlobGcWorker`
/// Phase 2 `purging` -> 0 premature S3 deletions, 0 missing S3 objects.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stress_a_16_concurrent_dedup_uploads_racing_purging() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("blob-gc-stress-a") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let account = fixture::account(&owner, "blob-gc-stress-a").await?;
    let app_exec = ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn), 16)
        .map_err(|e| e.0)?
        .with_audit_keys("22".repeat(32), String::new());
    let app_factory = tx_factory(&app_exec, None)?;
    let actor = mint_user(&app_factory, &app_exec, account.user).await?;
    let wdb = WorkerDatabase::new(&db.dsn)?;
    let store = ControlledStore::new();

    let mut shas = Vec::with_capacity(16);
    for i in 0..16usize {
        let digest = sha(&format!("stress-a-{i}-{}", account.user));
        seed_purging_blob(&owner, &digest).await?;
        store.seed(&digest, format!("payload-{i}").as_bytes());
        shas.push(digest);
    }

    let mut handles = Vec::new();
    // Spawn 16 concurrent uploaders (stage -> account_upload -> promote -> complete/cleanup)
    for (i, digest) in shas.iter().cloned().enumerate() {
        let app_f = app_factory.clone();
        let actor_c = actor.clone();
        let store_c = store.clone();
        handles.push(tokio::spawn(async move {
            let staging = format!("tmp/blob-upload/{:032x}", i + 1);
            store_c.seed(&staging, format!("payload-{i}").as_bytes());
            let op = op_id(&format!("stress-a-up-{i}-{digest}"));
            let out = setjoin_blobs::account_upload(
                &app_f,
                &actor_c,
                &digest,
                &format!("mailblobs/{digest}"),
                10,
                "application/octet-stream",
                Some(&staging),
                op,
            )
            .await;
            let raw = match out {
                CommandOutcome::Committed(a) => a,
                other => return Err(format!("uploader {i} failed: {other:?}")),
            };
            let acct: serde_json::Value =
                serde_json::from_str(&raw).map_err(|e| format!("parse acct: {e}"))?;
            store_c.promote_object(&staging, &digest).await?;
            if let Some(wid) = acct["promoteWorkItemId"].as_i64() {
                let complete_op = op_id(&format!("stress-a-complete-{i}-{digest}"));
                let _ = setjoin_blobs::complete_promote_recover(
                    &app_f,
                    &actor_c,
                    wid,
                    &digest,
                    &staging,
                    complete_op,
                )
                .await;
            }
            if acct["verifyWorkItemId"].is_null() {
                let _ = store_c.remove(&staging).await;
            }
            Ok::<_, String>(())
        }));
    }

    // Race GC Phase 2 purges concurrently against all 16 shas!
    let gc_store = store.clone();
    let gc_shas = shas.clone();
    let gc_task = tokio::spawn(async move {
        let gc = BlobGcWorker::new(wdb, gc_store);
        for digest in gc_shas {
            let _ = gc.purge_one(&digest, 0).await;
        }
    });

    for h in handles {
        h.await.map_err(|e| e.to_string())??;
    }
    gc_task.await.map_err(|e| e.to_string())?;

    // Drain any blob.promote_verify items enqueued when dedup raced purging.
    let wpool = setjoin_pg::WorkerPool::from_dsn(&db.dsn, 4).map_err(|e| e.0)?;
    let wq = setjoin_workqueue::WorkQueue::new(wpool);
    owner
        .execute(
            "UPDATE public.work_items SET run_at = now() - interval '1 second' \
              WHERE kind IN ('blob.promote_recover', 'blob.promote_verify') AND status = 'pending'",
            &[],
        )
        .await?;
    let promote_consumer = BlobPromoteConsumer::new(store.clone());
    let _ = promote_consumer
        .drain_once(&wq, "stress-a-verify", None)
        .await?;

    // Every single one of the 16 uploaded blobs MUST exist in DB AND S3!
    for digest in &shas {
        let db_exists: bool = owner
            .query_one(
                "SELECT EXISTS(SELECT 1 FROM public.blobs WHERE sha256 = $1)",
                &[digest],
            )
            .await?
            .get(0);
        assert!(db_exists, "stress A: DB blobs row missing for {digest}");
        assert!(
            store.contains(digest),
            "stress A: S3 canonical object missing for {digest}"
        );
        cleanup_blob(&owner, digest).await;
    }
    owner
        .execute(
            "DELETE FROM public.work_items WHERE kind IN ('blob.promote_recover','blob.promote_verify')",
            &[],
        )
        .await?;
    common::remove_blob_account(&owner, &account).await?;
    Ok(())
}

/// Wave 2.4 Stress B: 32 concurrent attachment inserts referencing the same
/// shared `sha256` produce `pg_stat_user_tables.n_tup_upd` delta == 0 on
/// `public.blobs` (zero hot-row lock contention after V293 retired triggers).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stress_b_32_concurrent_attachments_zero_blobs_updates() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("blob-gc-stress-b") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let account = fixture::account(&owner, "blob-gc-stress-b").await?;
    let digest = sha(&format!("stress-b-shared-{}", account.user));

    owner
        .execute(
            "INSERT INTO public.blobs (sha256, minio_ref, size_bytes, content_type) \
             VALUES ($1, $2, 64, 'application/pdf') ON CONFLICT (sha256) DO NOTHING",
            &[&digest, &format!("mailblobs/{digest}")],
        )
        .await?;
    let msg_row = owner
        .query_one(
            "SELECT id, received_at::text FROM public.messages WHERE id = $1 AND mailbox_id = $2",
            &[&account.inbox_only, &account.mailbox],
        )
        .await?;
    let msg_id: i64 = msg_row.get(0);
    let recv_at: String = msg_row.get(1);

    let _ = owner.execute("SELECT pg_stat_clear_snapshot()", &[]).await;
    let upd_before: i64 = owner
        .query_one(
            "SELECT COALESCE(n_tup_upd, 0) FROM pg_stat_user_tables WHERE schemaname = 'public' AND relname = 'blobs'",
            &[],
        )
        .await?
        .get(0);

    let mut handles = Vec::with_capacity(32);
    for i in 0..32usize {
        let dsn = db.dsn.clone();
        let sha_c = digest.clone();
        let recv_c = recv_at.clone();
        handles.push(tokio::spawn(async move {
            let (client, conn) = tokio_postgres::connect(&dsn, tokio_postgres::NoTls)
                .await
                .map_err(|e| e.to_string())?;
            tokio::spawn(async move {
                let _ = conn.await;
            });
            client
                .execute(
                    "INSERT INTO public.message_attachments \
                         (message_id, received_at, blob_sha256, filename, content_type, size_bytes) \
                     VALUES ($1, $2::text::timestamptz, $3, $4, 'application/pdf', 64)",
                    &[&msg_id, &recv_c, &sha_c, &format!("shared-{i}.pdf")],
                )
                .await
                .map_err(|e| e.to_string())?;
            Ok::<_, String>(())
        }));
    }
    for h in handles {
        h.await.map_err(|e| e.to_string())??;
    }

    // Flush pgstats and confirm ZERO updates on public.blobs!
    let _ = owner
        .execute("SELECT pg_stat_force_next_flush()", &[])
        .await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    let _ = owner.execute("SELECT pg_stat_clear_snapshot()", &[]).await;
    let upd_after: i64 = owner
        .query_one(
            "SELECT COALESCE(n_tup_upd, 0) FROM pg_stat_user_tables WHERE schemaname = 'public' AND relname = 'blobs'",
            &[],
        )
        .await?
        .get(0);
    assert_eq!(
        upd_after - upd_before,
        0,
        "32 concurrent attachment inserts must perform 0 UPDATEs on public.blobs (before={upd_before}, after={upd_after})"
    );

    let att_count: i64 = owner
        .query_one(
            "SELECT count(*) FROM public.message_attachments WHERE blob_sha256 = $1",
            &[&digest],
        )
        .await?
        .get(0);
    assert_eq!(att_count, 32, "all 32 attachments must commit");

    owner
        .execute(
            "DELETE FROM public.message_attachments WHERE blob_sha256 = $1",
            &[&digest],
        )
        .await?;
    cleanup_blob(&owner, &digest).await;
    common::remove_blob_account(&owner, &account).await?;
    Ok(())
}

/// Wave 2.4 Stress C (Codex #5 regression): an attachment commits in another
/// session WHILE Tx 2B (`purge_one`) is blocked waiting on `FOR UPDATE OF s, b`.
/// Tx 2B's separate second statement (`blob_has_live_reference`) MUST evaluate
/// under a fresh `READ COMMITTED` snapshot, see the committed attachment, abort
/// with `AbortedReactivated`, and perform **0 S3 deletes**.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stress_c_codex5_attachment_commits_while_tx2b_blocked_on_for_update(
) -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("blob-gc-stress-c") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let account = fixture::account(&owner, "blob-gc-stress-c").await?;
    let digest = sha(&format!("stress-c-codex5-{}", account.user));
    seed_purging_blob(&owner, &digest).await?;

    let store = ControlledStore::new();
    store.seed(&digest, b"must-not-delete");

    // Hold ONLY the row lock on blob_gc_state (NOT the advisory lock) so Tx 2B
    // passes Statement 1a (advisory lock) and blocks specifically on Statement 1b
    // (`FOR UPDATE OF s, b`).
    let holder = db.connect().await?;
    holder.batch_execute("BEGIN").await?;
    holder
        .query_one(
            "SELECT 1 FROM public.blob_gc_state WHERE blob_sha256 = $1 FOR UPDATE",
            &[&digest],
        )
        .await?;

    let wdb = WorkerDatabase::new(&db.dsn)?;
    let gc = BlobGcWorker::new(wdb, store.clone());
    let sha_gc = digest.clone();
    let gc_task = tokio::spawn(async move { gc.purge_one(&sha_gc, 0).await });

    // Poll pg_stat_activity to PROVE Tx 2B is genuinely waiting on the row lock
    // (`wait_event_type = 'Lock'` on `FOR UPDATE OF s, b`) before holder commits.
    let wait_deadline = tokio::time::Instant::now() + Duration::from_millis(2500);
    let mut observed_lock_wait = false;
    while tokio::time::Instant::now() < wait_deadline {
        let waiting: bool = owner
            .query_one(
                "SELECT EXISTS ( \
                    SELECT 1 FROM pg_catalog.pg_stat_activity \
                     WHERE datname = current_database() \
                       AND pid <> pg_backend_pid() \
                       AND wait_event_type = 'Lock' \
                       AND query ILIKE '%FOR UPDATE OF s, b%' \
                )",
                &[],
            )
            .await?
            .get(0);
        if waiting {
            observed_lock_wait = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        observed_lock_wait,
        "pg_stat_activity must prove Tx 2B is waiting on FOR UPDATE OF s, b Lock before commit"
    );
    assert!(
        !gc_task.is_finished(),
        "Tx 2B must still be blocked waiting on FOR UPDATE OF s, b"
    );

    // Commit a new message_attachments reference from holder while Tx 2B waits!
    holder
        .execute(
            "INSERT INTO public.message_attachments \
                 (message_id, received_at, blob_sha256, filename, content_type, size_bytes) \
             SELECT id, received_at, $1, 'codex5.txt', 'text/plain', 15 \
               FROM public.messages WHERE id = $2 AND mailbox_id = $3",
            &[&digest, &account.inbox_only, &account.mailbox],
        )
        .await?;
    holder.batch_execute("COMMIT").await?;

    // Tx 2B unblocks -> fresh Statement 2 snapshot sees live attachment -> AbortedReactivated!
    let outcome = tokio::time::timeout(Duration::from_secs(5), gc_task)
        .await??
        .map_err(|e| format!("purge_one error: {e}"))?;
    assert_eq!(
        outcome,
        PurgeOutcome::AbortedReactivated,
        "Tx 2B must abort when attachment committed during FOR UPDATE wait"
    );
    assert!(
        store.delete_calls().is_empty(),
        "Tx 2B must issue 0 S3 deletes: {:?}",
        store.delete_calls()
    );
    assert!(store.contains(&digest), "S3 bytes must stay intact");

    owner
        .execute(
            "DELETE FROM public.message_attachments WHERE blob_sha256 = $1",
            &[&digest],
        )
        .await?;
    cleanup_blob(&owner, &digest).await;
    common::remove_blob_account(&owner, &account).await?;
    Ok(())
}

/// Wave 2.4 Stress D: Versioned fake S3 with a DeleteMarker hiding a
/// WORM-retained version across paginated `ListObjectVersions` (`IsTruncated=true`).
/// `S3Store::delete_blob_checked` must follow pagination, detect WORM 403 via
/// XML `<Code>` + `GetObjectRetention`, and `BlobGcWorker::purge_one` must
/// return `WormLocked403`, revert `gc_state = 'active'`, and preserve `public.blobs`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stress_d_versioned_s3_delete_marker_hides_worm_and_multipage_versions(
) -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("blob-gc-stress-d") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let digest = sha("stress-d-versioned-worm-multipage");
    seed_purging_blob(&owner, &digest).await?;

    let list_pages = Arc::new(AtomicUsize::new(0));
    let deleted_versions = Arc::new(Mutex::new(Vec::<String>::new()));
    let lp_c = list_pages.clone();
    let dv_c = deleted_versions.clone();
    let sha_srv = digest.clone();

    let endpoint = common::fake_upstream(move |request| {
        let lp = lp_c.clone();
        let dv = dv_c.clone();
        let key_target = sha_srv.clone();
        async move {
            let query = request.uri().query().unwrap_or("");
            let path = request.uri().path();
            if request.method() == hyper::Method::GET && query == "location=" {
                return hyper::Response::new(common::full(
                    "<LocationConstraint>us-east-1</LocationConstraint>",
                ));
            }
            if request.method() == hyper::Method::GET && query.contains("versions") {
                let page = lp.fetch_add(1, Ordering::SeqCst);
                if !query.contains("version-id-marker=v1") {
                    // Page 1: DeleteMarker + non-WORM version v1, truncated!
                    let body = format!(
                        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
                         <ListVersionsResult>\
                           <IsTruncated>true</IsTruncated>\
                           <NextKeyMarker>{key_target}</NextKeyMarker>\
                           <NextVersionIdMarker>v1</NextVersionIdMarker>\
                           <DeleteMarker><Key>{key_target}</Key><VersionId>dm-top</VersionId></DeleteMarker>\
                           <Version><Key>{key_target}</Key><VersionId>v1</VersionId></Version>\
                         </ListVersionsResult>"
                    );
                    let _ = page;
                    return hyper::Response::builder()
                        .header("content-type", "application/xml")
                        .body(common::full(body))
                        .unwrap();
                } else {
                    // Page 2: hidden WORM-retained version v2!
                    let body = format!(
                        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
                         <ListVersionsResult>\
                           <IsTruncated>false</IsTruncated>\
                           <Version><Key>{key_target}</Key><VersionId>v2-worm</VersionId></Version>\
                         </ListVersionsResult>"
                    );
                    return hyper::Response::builder()
                        .header("content-type", "application/xml")
                        .body(common::full(body))
                        .unwrap();
                }
            }
            if request.method() == hyper::Method::GET && query.contains("retention") {
                return hyper::Response::builder()
                    .status(200)
                    .header("content-type", "application/xml")
                    .body(common::full(
                        "<Retention><Mode>GOVERNANCE</Mode><RetainUntilDate>2035-01-01T00:00:00Z</RetainUntilDate></Retention>",
                    ))
                    .unwrap();
            }
            if request.method() == hyper::Method::DELETE && path.ends_with(&key_target) {
                let vid = query
                    .split('&')
                    .find_map(|p| p.strip_prefix("versionId="))
                    .unwrap_or("")
                    .to_owned();
                dv.lock().unwrap().push(vid.clone());
                if vid == "v2-worm" {
                    return hyper::Response::builder()
                        .status(403)
                        .header("content-type", "application/xml")
                        .body(common::full(
                            "<Error><Code>AccessDenied</Code><Message>Object is locked</Message></Error>",
                        ))
                        .unwrap();
                }
                return hyper::Response::builder()
                    .status(204)
                    .body(common::full(""))
                    .unwrap();
            }
            hyper::Response::builder()
                .status(404)
                .body(common::full(""))
                .unwrap()
        }
    })
    .await;

    let s3_store = Arc::new(S3Store::new(
        &format!("http://{endpoint}"),
        "mailblobs",
        "test-access",
        "test-secret",
    )?);

    // Direct check on delete_blob_checked first
    let direct_outcome = s3_store
        .delete_blob_checked(&digest, Duration::from_secs(5))
        .await?;
    match &direct_outcome {
        BlobDeleteOutcome::WormLocked403 { retain_until, .. } => {
            assert_eq!(
                retain_until.as_deref(),
                Some("2035-01-01T00:00:00Z"),
                "must propagate observed unexpired RetainUntilDate from GetObjectRetention"
            );
        }
        other => panic!("expected WormLocked403 on hidden WORM version, got: {other:?}"),
    }
    assert!(
        list_pages.load(Ordering::SeqCst) >= 2,
        "must follow multi-page ListObjectVersions pagination"
    );
    assert!(
        deleted_versions
            .lock()
            .unwrap()
            .iter()
            .any(|v| v == "v2-worm"),
        "must attempt versioned DELETE on hidden WORM version v2-worm"
    );

    // Now end-to-end through BlobGcWorker::purge_one
    let gc = BlobGcWorker::new(WorkerDatabase::new(&db.dsn)?, s3_store);
    let outcome = gc.purge_one(&digest, 0).await?;
    assert_eq!(outcome, PurgeOutcome::WormLocked403);
    let row = owner
        .query_one(
            "SELECT gc_state, worm_locked_until = '2035-01-01T00:00:00Z'::timestamptz \
               FROM public.blob_gc_state WHERE blob_sha256 = $1",
            &[&digest],
        )
        .await?;
    assert_eq!(row.get::<_, String>(0), "active");
    assert!(
        row.get::<_, bool>(1),
        "blob_gc_state.worm_locked_until must record exact observed GetObjectRetention horizon"
    );
    assert!(row.get::<_, bool>(1));
    let blob_kept: bool = owner
        .query_one(
            "SELECT EXISTS(SELECT 1 FROM public.blobs WHERE sha256 = $1)",
            &[&digest],
        )
        .await?
        .get(0);
    assert!(blob_kept, "public.blobs row must stay intact on WORM 403");

    cleanup_blob(&owner, &digest).await;
    Ok(())
}

/// Wave 2.4 Stress E: Unversioned S3 timeout/500 during Tx 2B racing with dedup
/// reactivation -> `was_purging = true` enqueues delayed `blob.promote_verify`,
/// which detects the late-deleted canonical key and re-promotes from `tmp/blob-upload/*`.
#[tokio::test]
async fn stress_e_unversioned_timeout_reactivation_promote_verify_restores_canonical(
) -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("blob-gc-stress-e") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let account = fixture::account(&owner, "blob-gc-stress-e").await?;
    let app_exec = ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn), 4)
        .map_err(|e| e.0)?
        .with_audit_keys("22".repeat(32), String::new());
    let app_factory = tx_factory(&app_exec, None)?;
    let actor = mint_user(&app_factory, &app_exec, account.user).await?;
    let digest = sha(&format!("stress-e-verify-{}", account.user));
    let staging = "tmp/blob-upload/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";

    seed_purging_blob(&owner, &digest).await?;
    let store = ControlledStore::new();
    store.seed(&digest, b"canonical-bytes");
    store.seed(staging, b"canonical-bytes");

    let out = setjoin_blobs::account_upload(
        &app_factory,
        &actor,
        &digest,
        &format!("mailblobs/{digest}"),
        15,
        "text/plain",
        Some(staging),
        op_id(&format!("stress-e-{digest}")),
    )
    .await;
    let raw = match out {
        CommandOutcome::Committed(a) => a,
        other => return Err(format!("account_upload failed: {other:?}").into()),
    };
    let acct: serde_json::Value = serde_json::from_str(&raw)?;
    assert_eq!(
        acct["wasPurging"].as_bool(),
        Some(true),
        "dedup against purging must set wasPurging=true: {acct}"
    );
    let verify_id = acct["verifyWorkItemId"]
        .as_i64()
        .ok_or("dedup against purging with staging_key must enqueue blob.promote_verify")?;
    // If a sibling blob.promote_recover item was also created, cancel it after initial promote
    // just as blobs.rs does, leaving ONLY blob.promote_verify pending for the 60s window.
    if let Some(prom_id) = acct["promoteWorkItemId"].as_i64() {
        let _ = setjoin_blobs::complete_promote_recover(
            &app_factory,
            &actor,
            prom_id,
            &digest,
            staging,
            op_id(&format!("stress-e-complete-{digest}")),
        )
        .await;
    }

    // Simulate a timed-out unversioned S3 DELETE landing late after dedup committed!
    store.objects.lock().unwrap().remove(&digest);
    assert!(!store.contains(&digest));
    assert!(
        store.contains(staging),
        "staging object must remain until promote_verify completes"
    );

    // Fast-forward run_at and run BlobPromoteConsumer
    owner
        .execute(
            "UPDATE public.work_items SET run_at = now() - interval '1 second' WHERE id = $1",
            &[&verify_id],
        )
        .await?;
    let wpool = setjoin_pg::WorkerPool::from_dsn(&db.dsn, 4).map_err(|e| e.0)?;
    let wq = setjoin_workqueue::WorkQueue::new(wpool);
    let consumer = BlobPromoteConsumer::new(store.clone());
    let claimed = consumer.drain_once(&wq, "stress-e-worker", None).await?;
    assert!(claimed >= 1);

    assert!(
        store.contains(&digest),
        "blob.promote_verify must restore missing canonical object from staging"
    );
    assert!(
        !store.contains(staging),
        "blob.promote_verify must delete staging object after restoring canonical"
    );

    owner
        .execute("DELETE FROM public.work_items WHERE id = $1", &[&verify_id])
        .await?;
    cleanup_blob(&owner, &digest).await;
    common::remove_blob_account(&owner, &account).await?;
    Ok(())
}

/// Wave 2.4 Stress F: Crash between `blob_upload_account` commit and `store.promote`
/// -> `blob.promote_recover` protects sha256 from GC, promotes `tmp/blob-upload/*`
/// to canonical `<sha256>`, and cleans up staging.
#[tokio::test]
async fn stress_f_post_commit_crash_promote_recover_restores_canonical() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("blob-gc-stress-f") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let account = fixture::account(&owner, "blob-gc-stress-f").await?;
    let app_exec = ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn), 4)
        .map_err(|e| e.0)?
        .with_audit_keys("22".repeat(32), String::new());
    let app_factory = tx_factory(&app_exec, None)?;
    let actor = mint_user(&app_factory, &app_exec, account.user).await?;
    let digest = sha(&format!("stress-f-recover-{}", account.user));
    let staging = "tmp/blob-upload/ffffffffffffffffffffffffffffffff";

    let store = ControlledStore::new();
    store.seed(staging, b"fresh-upload-bytes");

    let out = setjoin_blobs::account_upload(
        &app_factory,
        &actor,
        &digest,
        &format!("mailblobs/{digest}"),
        18,
        "text/plain",
        Some(staging),
        op_id(&format!("stress-f-{digest}")),
    )
    .await;
    let raw = match out {
        CommandOutcome::Committed(a) => a,
        other => return Err(format!("account_upload failed: {other:?}").into()),
    };
    let acct: serde_json::Value = serde_json::from_str(&raw)?;
    let recover_id = acct["promoteWorkItemId"]
        .as_i64()
        .ok_or("fresh upload with staging_key must enqueue blob.promote_recover")?;

    // Simulate process crash right before promote! Canonical object is absent.
    assert!(!store.contains(&digest));
    let held: bool = owner
        .query_one("SELECT public.blob_is_held_or_retained($1, 0)", &[&digest])
        .await?
        .get(0);
    assert!(
        held,
        "pending blob.promote_recover must hold sha256 against GC"
    );

    owner
        .execute(
            "UPDATE public.work_items SET run_at = now() - interval '1 second' WHERE id = $1",
            &[&recover_id],
        )
        .await?;
    let wpool = setjoin_pg::WorkerPool::from_dsn(&db.dsn, 4).map_err(|e| e.0)?;
    let wq = setjoin_workqueue::WorkQueue::new(wpool);
    let consumer = BlobPromoteConsumer::new(store.clone());
    let claimed = consumer.drain_once(&wq, "stress-f-worker", None).await?;
    assert!(claimed >= 1);

    assert!(
        store.contains(&digest),
        "blob.promote_recover must promote staging -> canonical"
    );
    assert!(
        !store.contains(staging),
        "blob.promote_recover must delete staging after promotion"
    );
    let held_after: bool = owner
        .query_one("SELECT public.blob_is_held_or_retained($1, 0)", &[&digest])
        .await?
        .get(0);
    assert!(
        !held_after,
        "completed promote_recover must release GC hold"
    );

    owner
        .execute(
            "DELETE FROM public.work_items WHERE id = $1",
            &[&recover_id],
        )
        .await?;
    cleanup_blob(&owner, &digest).await;
    common::remove_blob_account(&owner, &account).await?;
    Ok(())
}

/// Wave 2.4 Supervisor & Drain integration:
/// 1. `WorkerSupervisor` with empty cron list still registers and claims `"blob-cleanup"`
///    via `ScheduleRunner` (`safe_to_release = false`, `timeout_secs = 300`).
/// 2. `BlobReapRetryConsumer` skips S3 delete when `public.blobs` row exists, and
///    deletes S3 via `delete_blob_checked` when `public.blobs` row is gone.
/// 3. `WormArmConsumer` atomically persists `worm_locked_until` in `blob_gc_state`
///    inside the same `WorkerTx` as `work_queue_complete`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn supervisor_empty_cron_blob_cleanup_schedule_and_consumers() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("blob-gc-supervisor") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let wpool = setjoin_pg::WorkerPool::from_dsn(&db.dsn, 6).map_err(|e| e.0)?;
    let wq = setjoin_workqueue::WorkQueue::new(wpool.clone());

    // 1. Empty-cron ScheduleRunner claiming `"blob-cleanup"` callback
    let store = ControlledStore::new();
    let due_sha = sha("sup-schedule-due");
    owner
        .execute(
            "INSERT INTO public.blobs (sha256, minio_ref, size_bytes, created_at) \
             VALUES ($1, $2, 5, now() - interval '72 hours') ON CONFLICT (sha256) DO NOTHING",
            &[&due_sha, &format!("mailblobs/{due_sha}")],
        )
        .await?;
    owner
        .execute(
            "INSERT INTO public.blob_gc_state (blob_sha256, gc_state, reclaim_eligible_at, last_touched_at) \
             VALUES ($1, 'reclaim_eligible', now() - interval '25 hours', now() - interval '72 hours') \
             ON CONFLICT (blob_sha256) DO UPDATE SET gc_state='reclaim_eligible', reclaim_eligible_at=EXCLUDED.reclaim_eligible_at",
            &[&due_sha],
        )
        .await?;
    store.seed(&due_sha, b"stale");

    let task_name = "blob-cleanup";
    let sup_cfg = setjoin_gateway::supervisor::SupervisorConfig::new(&db.dsn)
        .with_node_id("test-blob-sup")
        .with_drain_timeout(Duration::from_secs(5));
    let mut sup = setjoin_gateway::supervisor::WorkerSupervisor::boot(sup_cfg).await?;
    // Exercise the REAL production schedule-registration builder with an empty `cron:` list!
    let tasks = setjoin_gateway::runtime::build_supervised_schedule_tasks(
        true,
        "",
        false,
        Some(store.clone()),
    )?;
    let task_names: Vec<&str> = tasks.iter().map(|t| t.spec.task_name.as_str()).collect();
    assert_eq!(
        task_names,
        vec![
            "prune-scope-revocations",
            "prune-chat-changes",
            task_name,
        ],
        "production builder must register Wave 2 maintenance tasks and blob-cleanup even when cron:* list is empty"
    );
    let runner = setjoin_gateway::supervisor::schedule::ScheduleRunner::new(
        tasks,
        setjoin_gateway::supervisor::schedule::ScheduleRunnerConfig {
            poll_interval: Duration::from_millis(50),
            ..Default::default()
        },
    );
    let sched_store = setjoin_workqueue::ScheduleStore::new(wpool.clone());
    runner.register_all(&sched_store).await?;
    // Force schedule immediately due and run one supervised tick via WorkerSupervisor!
    owner
        .execute(
            "UPDATE public.worker_schedules SET next_due_at = now() - interval '1 second' WHERE task_name = $1",
            &[&task_name],
        )
        .await?;
    sup.spawn("schedule-runner", move |ctx| async move {
        runner.run(ctx).await
    });

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while store.contains(&due_sha) && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    sup.shutdown().await?;
    assert!(
        !store.contains(&due_sha),
        "WorkerSupervisor empty-cron ScheduleRunner must claim and execute blob-cleanup tick"
    );

    // 2. BlobReapRetryConsumer: live row skipped; deleted row reaped
    let sha_live = sha("sup-reap-live");
    let sha_gone = sha("sup-reap-gone");
    owner
        .execute(
            "INSERT INTO public.blobs (sha256, minio_ref, size_bytes) VALUES ($1, $2, 5) ON CONFLICT DO NOTHING",
            &[&sha_live, &format!("mailblobs/{sha_live}")],
        )
        .await?;
    let reap_store = ControlledStore::new();
    reap_store.seed(&sha_live, b"live");
    reap_store.seed(&sha_gone, b"gone");

    for s in [&sha_live, &sha_gone] {
        wq.enqueue(&setjoin_workqueue::WorkRequest::new(
            blob_retention::WORK_KIND_REAP_RETRY,
            serde_json::json!({"sha256": s}),
        ))
        .await?;
    }
    let reap_consumer = BlobReapRetryConsumer::new(reap_store.clone());
    let drained = reap_consumer
        .drain_once(&wq, "test-reap-drain", Some(Duration::ZERO))
        .await?;
    assert!(drained >= 2);
    assert!(
        reap_store.contains(&sha_live),
        "BlobReapRetryConsumer must NOT delete S3 when public.blobs row still exists"
    );
    assert!(
        !reap_store.contains(&sha_gone),
        "BlobReapRetryConsumer must delete S3 when public.blobs row is gone"
    );

    // 3. WormArmConsumer records effective_until in blob_gc_state atomically
    let sha_worm = sha("sup-worm-atomic");
    owner
        .execute(
            "INSERT INTO public.blobs (sha256, minio_ref, size_bytes) VALUES ($1, $2, 5) ON CONFLICT DO NOTHING",
            &[&sha_worm, &format!("mailblobs/{sha_worm}")],
        )
        .await?;
    let worm_store = ControlledStore::new();
    worm_store.seed(&sha_worm, b"worm-bytes");
    std::env::set_var("WORM_MODE", "governance");
    std::env::set_var("WORM_RETENTION_DAYS", "30");
    let worm_payload = blob_retention::WormArmPayload {
        sha256: sha_worm.clone(),
        object_key: sha_worm.clone(),
        mode: "GOVERNANCE".to_owned(),
        retain_days: 30,
        retain_until: (chrono::Utc::now() + chrono::Duration::days(30)).to_rfc3339(),
        version_id: None,
    };
    wq.enqueue(&setjoin_workqueue::WorkRequest::new(
        blob_retention::WORK_KIND_WORM_ARM,
        serde_json::to_value(&worm_payload)?,
    ))
    .await?;
    let worm_consumer = WormArmConsumer::new(worm_store);
    let worm_res = worm_consumer
        .drain_once(&wq, "test-worm-atomic", Some(Duration::ZERO))
        .await;
    std::env::remove_var("WORM_MODE");
    std::env::remove_var("WORM_RETENTION_DAYS");
    worm_res?;

    let recorded: bool = owner
        .query_one(
            "SELECT worm_locked_until > now() + interval '29 days' FROM public.blob_gc_state WHERE blob_sha256 = $1",
            &[&sha_worm],
        )
        .await?
        .get(0);
    assert!(
        recorded,
        "WormArmConsumer must record worm_locked_until atomically in blob_gc_state"
    );

    owner
        .execute(
            "DELETE FROM public.work_items WHERE kind IN ('blob.s3_reap_retry','blob.worm_arm')",
            &[],
        )
        .await?;
    cleanup_blob(&owner, &sha_live).await;
    cleanup_blob(&owner, &sha_worm).await;
    Ok(())
}

/// Wave 2.4 Upgrade & Versioned Abandoned-Staging Sweep:
/// 1. Replays `V001..V292` + `provision-roles.sql` on a fresh disposable DB,
///    applies ONLY `V293__retire_blobs_refcount_cutover_gc.sql` as non-superuser
///    `setjoin_owner` (`NOSUPERUSER NOBYPASSRLS`), and asserts:
///    `blob_gc_config.mode = 'live'`, `other_secdef_drifted = 0`, retired
///    `blobs.ref_count`/`blob_cleanup_queue`, and `blob_live_catalog()` callable
///    by `setjoin_owner` while denied (`42501`) to `setjoin_app`.
/// 2. Exercises `sweep_abandoned_staging` against a versioned fake S3 serving an
///    old (>24h) hidden concrete version + delete marker under `tmp/blob-upload/`,
///    proving `list_object_versions_prefix` discovers and permanently deletes both.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn v292_to_v293_upgrade_as_non_superuser_setjoin_owner_and_versioned_staging_sweep(
) -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("blob-gc-v293-upgrade") else {
        return Ok(());
    };

    // Part 1: Real V292 -> V293 upgrade under non-superuser setjoin_owner
    let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .and_then(|p| p.parent())
        .ok_or("resolve repo root")?;
    let schema_dir = repo_root.join("sql/dbschema");
    let provision_sql = repo_root.join("scripts/provision-roles.sql");
    let v289_path = schema_dir.join("V293__retire_blobs_refcount_cutover_gc.sql");

    let mut parsed_url = url::Url::parse(&db.dsn)?;
    let temp_db_name = format!("mailserver_v289_upg_{}", std::process::id());
    let mut maint_url = parsed_url.clone();
    maint_url.set_path("/postgres");
    let (maint, maint_conn) =
        tokio_postgres::connect(maint_url.as_str(), tokio_postgres::NoTls).await?;
    tokio::spawn(async move {
        let _ = maint_conn.await;
    });

    let _ = maint
        .batch_execute(&format!(
            "DROP DATABASE IF EXISTS {temp_db_name} WITH (FORCE)"
        ))
        .await;
    maint
        .batch_execute(&format!("CREATE DATABASE {temp_db_name}"))
        .await?;

    let upgrade_res: Result<(), BoxError> = async {
        parsed_url.set_path(&format!("/{temp_db_name}"));
        let (sup_client, sup_conn) =
            tokio_postgres::connect(parsed_url.as_str(), tokio_postgres::NoTls).await?;
        tokio::spawn(async move {
            let _ = sup_conn.await;
        });

        // Load pre-pass provision-roles.sql + V001..V292 + post-pass provision-roles.sql
        // via `psql` (V001__baseline.sql uses psql-formatted DDL/seed), mirroring load-test-schema.sh.
        let psql_bin = if std::path::Path::new("/Users/cat/.local/pg17/bin/psql").is_file() {
            "/Users/cat/.local/pg17/bin/psql"
        } else {
            "psql"
        };
        let run_psql = |file: &std::path::Path| -> Result<(), BoxError> {
            let out = std::process::Command::new(psql_bin)
                .arg(parsed_url.as_str())
                .arg("-q")
                .arg("-v")
                .arg("ON_ERROR_STOP=1")
                .arg("-f")
                .arg(file)
                .output()
                .map_err(|e| format!("spawn {psql_bin} for {}: {e}", file.display()))?;
            if !out.status.success() {
                return Err(format!(
                    "psql {} failed: {}",
                    file.display(),
                    String::from_utf8_lossy(&out.stderr)
                )
                .into());
            }
            Ok(())
        };

        run_psql(&provision_sql)?;

        let mut migrations: Vec<(u32, String, std::path::PathBuf)> = Vec::new();
        for entry in std::fs::read_dir(&schema_dir)? {
            let path = entry?.path();
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if let Some(rest) = name.strip_prefix('V') {
                if let Some((num_str, _)) = rest.split_once("__") {
                    if let Ok(ver) = num_str.parse::<u32>() {
                        if ver <= 292 {
                            migrations.push((ver, name.to_owned(), path));
                        }
                    }
                }
            }
        }
        migrations.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
        assert!(
            migrations.last().is_some_and(|(v, _, _)| *v == 292),
            "expected V292 as last pre-upgrade migration"
        );
        for (_ver, _name, path) in &migrations {
            run_psql(path)?;
        }
        run_psql(&provision_sql)?;
        sup_client
            .batch_execute(
                "ALTER ROLE setjoin_owner NOSUPERUSER NOBYPASSRLS; \
                 ALTER SCHEMA public OWNER TO setjoin_owner; \
                 GRANT setjoin_worker TO setjoin_owner; \
                 DO $$ \
                 DECLARE r record; \
                 BEGIN \
                   FOR r IN SELECT tablename FROM pg_tables WHERE schemaname = 'public' LOOP \
                     EXECUTE format('ALTER TABLE public.%I OWNER TO setjoin_owner', r.tablename); \
                   END LOOP; \
                   FOR r IN SELECT oid::regprocedure AS sig FROM pg_proc \
                             WHERE pronamespace = 'public'::regnamespace \
                               AND NOT prosecdef \
                               AND pg_get_userbyid(proowner) <> 'setjoin_worker' LOOP \
                     EXECUTE format('ALTER FUNCTION %s OWNER TO setjoin_owner', r.sig); \
                   END LOOP; \
                 END $$;",
            )
            .await?;

        // Snapshot pre-V293 non-V293 SECURITY DEFINER owners to prove 0 drift.
        sup_client
            .batch_execute(
                "CREATE TEMP TABLE pre_secdef AS \
                 SELECT oid::regprocedure::text AS sig, pg_get_userbyid(proowner) AS owner \
                   FROM pg_proc \
                  WHERE pronamespace = 'public'::regnamespace AND prosecdef;",
            )
            .await?;

        // Seed a live avatar blob + unreferenced blob on V292 schema.
        let live_sha = sha("v289-upg-live-avatar");
        let dead_sha = sha("v289-upg-dead-blob");
        sup_client
            .execute(
                "INSERT INTO public.blobs (sha256, minio_ref, size_bytes) \
                 VALUES ($1, $2, 10), ($3, $4, 10)",
                &[
                    &live_sha,
                    &format!("mailblobs/{live_sha}"),
                    &dead_sha,
                    &format!("mailblobs/{dead_sha}"),
                ],
            )
            .await?;
        sup_client
            .execute(
                "INSERT INTO public.domains (name) VALUES ('v289upg.test') ON CONFLICT DO NOTHING",
                &[],
            )
            .await?;
        sup_client
            .execute(
                "INSERT INTO public.users (username, email, display_name, domain_id, password_hash, avatar_sha256) \
                 SELECT 'upg', 'upg@v289upg.test', 'Upgrade User', id, 'x', $1 FROM public.domains WHERE name = 'v289upg.test'",
                &[&live_sha],
            )
            .await?;

        // Apply ONLY V293 as non-superuser setjoin_owner (NOSUPERUSER NOBYPASSRLS)!
        sup_client.batch_execute("SET ROLE setjoin_owner;").await?;
        let owner_flags = sup_client
            .query_one(
                "SELECT current_user::text, rolsuper, rolbypassrls \
                   FROM pg_roles WHERE rolname = current_user",
                &[],
            )
            .await?;
        assert_eq!(owner_flags.get::<_, String>(0), "setjoin_owner");
        assert!(!owner_flags.get::<_, bool>(1), "setjoin_owner must be NOSUPERUSER");
        assert!(!owner_flags.get::<_, bool>(2), "setjoin_owner must be NOBYPASSRLS");

        let v289_sql = std::fs::read_to_string(&v289_path)?;
        sup_client.batch_execute(&v289_sql).await?;

        // Verify blob_live_catalog() works as non-superuser setjoin_owner!
        let live_cnt: i64 = sup_client
            .query_one(
                "SELECT count(*) FROM public.blob_live_catalog() WHERE sha256 = $1",
                &[&live_sha],
            )
            .await?
            .get(0);
        let dead_cnt: i64 = sup_client
            .query_one(
                "SELECT count(*) FROM public.blob_live_catalog() WHERE sha256 = $1",
                &[&dead_sha],
            )
            .await?
            .get(0);
        assert_eq!(live_cnt, 1, "setjoin_owner must see live blob in blob_live_catalog()");
        assert_eq!(dead_cnt, 0, "blob_live_catalog() must exclude unreferenced blob");

        // Verify setjoin_app is denied blob_live_catalog() with 42501.
        sup_client.batch_execute("RESET ROLE; SET ROLE setjoin_app;").await?;
        let app_err = sup_client
            .query("SELECT * FROM public.blob_live_catalog()", &[])
            .await
            .expect_err("setjoin_app must be denied blob_live_catalog()");
        assert_eq!(
            app_err.code().map(|c| c.code()),
            Some("42501"),
            "expected SQLSTATE 42501 for setjoin_app"
        );
        sup_client.batch_execute("RESET ROLE;").await?;

        // Verify V293 invariants: mode=live, ref_count dropped, blob_cleanup_queue dropped, 0 secdef drift.
        let mode: String = sup_client
            .query_one("SELECT mode FROM public.blob_gc_config WHERE id = 1", &[])
            .await?
            .get(0);
        assert_eq!(mode, "live", "V293 must flip blob_gc_config.mode to live");
        let ref_count_cols: i64 = sup_client
            .query_one(
                "SELECT count(*) FROM information_schema.columns \
                  WHERE table_schema = 'public' AND table_name = 'blobs' AND column_name = 'ref_count'",
                &[],
            )
            .await?
            .get(0);
        assert_eq!(ref_count_cols, 0, "blobs.ref_count must be dropped");
        let queue_exists: bool = sup_client
            .query_one("SELECT to_regclass('public.blob_cleanup_queue') IS NOT NULL", &[])
            .await?
            .get(0);
        assert!(!queue_exists, "blob_cleanup_queue must be dropped");

        let drifted: i64 = sup_client
            .query_one(
                "SELECT count(*) FROM pre_secdef pre \
                   JOIN pg_proc p ON p.oid::regprocedure::text = pre.sig \
                  WHERE pg_get_userbyid(p.proowner) <> pre.owner",
                &[],
            )
            .await?
            .get(0);
        assert_eq!(drifted, 0, "V293 must produce 0 other_secdef_drifted rows");
        Ok(())
    }
    .await;

    let _ = maint
        .batch_execute(&format!(
            "DROP DATABASE IF EXISTS {temp_db_name} WITH (FORCE)"
        ))
        .await;
    upgrade_res?;

    // Part 2: Versioned abandoned staging sweep (hidden old version + delete marker >24h)
    let stale_staging_key = "tmp/blob-upload/0123456789abcdef0123456789abcdef";
    let deleted_staging_versions = Arc::new(Mutex::new(Vec::<String>::new()));
    let dsv_s = deleted_staging_versions.clone();
    let endpoint = common::fake_upstream(move |request| {
        let dsv = dsv_s.clone();
        async move {
            let query = request.uri().query().unwrap_or("");
            let path = request.uri().path();
            if request.method() == hyper::Method::GET && query == "location=" {
                return hyper::Response::new(common::full(
                    "<LocationConstraint>us-east-1</LocationConstraint>",
                ));
            }
            if request.method() == hyper::Method::GET && query.contains("versions") {
                let body = format!(
                    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
                     <ListVersionsResult>\
                       <IsTruncated>false</IsTruncated>\
                       <DeleteMarker>\
                         <Key>{stale_staging_key}</Key>\
                         <VersionId>dm-stale-1</VersionId>\
                         <LastModified>2025-01-01T00:00:00.000Z</LastModified>\
                       </DeleteMarker>\
                       <Version>\
                         <Key>{stale_staging_key}</Key>\
                         <VersionId>v-stale-1</VersionId>\
                         <LastModified>2025-01-01T00:00:00.000Z</LastModified>\
                       </Version>\
                     </ListVersionsResult>"
                );
                return hyper::Response::builder()
                    .header("content-type", "application/xml")
                    .body(common::full(body))
                    .unwrap();
            }
            if request.method() == hyper::Method::DELETE && path.ends_with(stale_staging_key) {
                let vid = query
                    .split('&')
                    .find_map(|p| p.strip_prefix("versionId="))
                    .unwrap_or("")
                    .to_owned();
                dsv.lock().unwrap().push(vid);
                return hyper::Response::builder()
                    .status(204)
                    .body(common::full(""))
                    .unwrap();
            }
            hyper::Response::builder()
                .status(404)
                .body(common::full(""))
                .unwrap()
        }
    })
    .await;

    let s3_store = Arc::new(S3Store::new(
        &format!("http://{endpoint}"),
        "mailblobs",
        "test-access",
        "test-secret",
    )?);
    let wdb = WorkerDatabase::new(&db.dsn)?;
    let conn = wdb.connect().await?;
    let gc = BlobGcWorker::new(wdb, s3_store);
    let swept = gc
        .sweep_abandoned_staging(&conn, std::time::Instant::now())
        .await;
    assert_eq!(
        swept, 1,
        "versioned abandoned staging sweep must discover and permanently delete hidden old staging versions"
    );
    let vids = deleted_staging_versions.lock().unwrap().clone();
    assert_eq!(
        vids,
        vec!["v-stale-1".to_owned(), "dm-stale-1".to_owned()],
        "must delete concrete version first then delete marker"
    );
    Ok(())
}
