//! Live-PostgreSQL gateway WorkQueue & BlobGcWorker integration tests for Wave 3.2 (#557):
//! - Enqueues `"search.extract"` and `"search.index_batch"` items through `WorkQueue`,
//!   executes `SearchExtractConsumer::drain_once` (concurrent per-item heartbeats + shared
//!   `ExtractionSingleFlight`) + `SearchIndexConsumer::drain_once` under `WorkerPool`,
//!   proves deduplicated single extraction + Tantivy indexing + monotonic watermark +
//!   exact `SnapshotFreshnessFence` `(generation, dirty_count)` + `has_more` continuation
//!   re-enqueue + lease-loss fencing.
//! - Exercises `BlobGcWorker::tick()` in live mode proving Mark-and-Sweep GC invokes
//!   `search_extracted_text_gc_sweep` automatically.

use chrono::Utc;
use setjoin_conformance::db_gate::{resolve as resolve_db_gate, DbGate};
use setjoin_gateway::blob_gc::{BlobGcWorker, GcMode};
use setjoin_gateway::recovery_worker::ObjectStore;
use setjoin_gateway::supervisor::search_worker::{
    ObjectStoreByteReader, SearchEdiscoveryConsumer, SearchExtractConsumer, SearchIndexConsumer,
    SearchPurgeConsumer, WorkerPoolSearchDb,
};
use setjoin_pg::workers::WorkerDatabase;
use setjoin_pg::WorkerPool;
use setjoin_search::{
    enqueue_outbox, extract_bytes, CandidateQuery, ContentExtractionService, ContentExtractor,
    DocCorpus, ExtractionResult, ExtractionSingleFlight, ExtractionStoragePlane, NormalizedQuery,
    ScopeHint, SearchConfig, SearchEngine, SearchError, SearchExtractPayload,
    SearchIndexBatchPayload, SearchIndexPipeline, SearchVisibility, SnapshotFreshnessFence,
    TantivySearchEngine, WORK_KIND_SEARCH_EXTRACT, WORK_KIND_SEARCH_INDEX_BATCH,
};
use setjoin_workqueue::{WorkQueue, WorkRequest};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tempfile::TempDir;
use tokio_postgres::NoTls;

static SEED_SEQ: AtomicI64 = AtomicI64::new(657_000);
static GW_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn next_tag() -> i64 {
    let seq = SEED_SEQ.fetch_add(1, Ordering::SeqCst);
    (Utc::now().timestamp_micros() & 0x0FFF_FFFF).saturating_add(seq)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

fn swap_dsn_user(dsn: &str, new_user: &str) -> String {
    if let Some(rest) = dsn.strip_prefix("postgres://") {
        if let Some((_u, after)) = rest.split_once('@') {
            return format!("postgres://{new_user}@{after}");
        }
    }
    if let Some(rest) = dsn.strip_prefix("postgresql://") {
        if let Some((_u, after)) = rest.split_once('@') {
            return format!("postgresql://{new_user}@{after}");
        }
    }
    dsn.to_owned()
}

#[derive(Default)]
struct MockStore {
    blobs: Mutex<HashMap<String, Vec<u8>>>,
}

impl MockStore {
    fn put_mem(&self, key: impl Into<String>, bytes: Vec<u8>) {
        self.blobs.lock().expect("lock").insert(key.into(), bytes);
    }
}

impl ObjectStore for MockStore {
    fn read<'a>(
        &'a self,
        key: &'a str,
        maximum: usize,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, String>> + Send + 'a>> {
        let key = key.to_owned();
        Box::pin(async move {
            let map = self.blobs.lock().expect("lock");
            let Some(bytes) = map.get(&key) else {
                return Err(format!("missing object: {key}"));
            };
            Ok(bytes[..bytes.len().min(maximum)].to_vec())
        })
    }

    fn remove<'a>(
        &'a self,
        key: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        let key = key.to_owned();
        Box::pin(async move {
            self.blobs.lock().expect("lock").remove(&key);
            Ok(())
        })
    }
}

struct CountingExtractor {
    calls: Arc<AtomicUsize>,
}

impl ContentExtractor for CountingExtractor {
    fn extract(
        &self,
        bytes: &[u8],
        content_type: Option<&str>,
        filename: Option<&str>,
    ) -> ExtractionResult {
        self.calls.fetch_add(1, Ordering::SeqCst);
        extract_bytes(bytes, content_type, filename)
    }
}

#[tokio::test]
async fn workqueue_extract_index_continuation_fence_lease_loss_and_blob_gc_e2e() {
    let _guard = GW_TEST_LOCK.lock().await;
    let dsn = match resolve_db_gate(|k| std::env::var(k).ok()) {
        DbGate::Run { dsn, .. } => dsn,
        DbGate::Skip => {
            eprintln!("SETJOIN-GATEWAY-557-SKIP (reason=no-dsn)");
            return;
        }
        DbGate::Missing => panic!("REQUIRE_DB=1 set but TEST_DB_DSN/DB_DSN is absent"),
    };
    let worker_dsn = swap_dsn_user(&dsn, "setjoin_worker");

    let (owner, owner_conn) = tokio_postgres::connect(&dsn, NoTls).await.expect("owner");
    tokio::spawn(async move {
        let _ = owner_conn.await;
    });
    let (worker_client, worker_conn) = tokio_postgres::connect(&worker_dsn, NoTls)
        .await
        .expect("worker");
    tokio::spawn(async move {
        let _ = worker_conn.await;
    });

    // Clean queue/outbox/watermarks for deterministic continuation & fence assertions.
    worker_client
        .execute("DELETE FROM public.search_index_watermarks", &[])
        .await
        .expect("clear wm");
    worker_client
        .execute("DELETE FROM public.search_index_outbox", &[])
        .await
        .expect("clear outbox");
    worker_client
        .execute("DELETE FROM public.search_dirty_keys", &[])
        .await
        .expect("clear dirty");
    worker_client
        .execute(
            "DELETE FROM public.work_items WHERE kind IN ('search.extract', 'search.index_batch')",
            &[],
        )
        .await
        .expect("clear work_items");

    let pool = WorkerPool::from_dsn(&worker_dsn, 6).expect("worker pool");
    let queue = WorkQueue::new(pool.clone());
    let store = Arc::new(MockStore::default());
    let single_flight = Arc::new(ExtractionSingleFlight::default());
    let calls = Arc::new(AtomicUsize::new(0));
    let dir = TempDir::new().expect("tempdir");
    let engine = Arc::new(TantivySearchEngine::open_or_degraded(SearchConfig {
        tier2_enabled: true,
        index_dir: dir.path().to_path_buf(),
        ..SearchConfig::default()
    }));
    let fence = Arc::new(SnapshotFreshnessFence::unset());

    let tag = next_tag();
    let email = format!("gw557_{tag}@example.test");
    let seed_row = owner
        .query_one(
            "WITH dom AS ( \
               INSERT INTO public.domains (name) VALUES ('example.test') \
               ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name RETURNING id \
             ), u AS ( \
               INSERT INTO public.users (domain_id, email, username, password_hash, display_name) \
               SELECT id, $1, $2, 'hash', $2 FROM dom RETURNING id, domain_id \
             ), mb AS ( \
               INSERT INTO public.mailboxes (user_id, domain_id, email, display_name, is_primary) \
               SELECT u.id, u.domain_id, $1, $2, true FROM u RETURNING id \
             ), f AS ( \
               INSERT INTO public.folders (mailbox_id, name, path, role) \
               SELECT mb.id, 'Inbox', 'Inbox', 'inbox' FROM mb RETURNING id, mailbox_id \
             ) SELECT mb.id, f.id FROM mb JOIN f ON f.mailbox_id = mb.id",
            &[&email, &format!("ugw557_{tag}")],
        )
        .await
        .expect("seed");
    let mailbox_id: i64 = seed_row.try_get(0).expect("mb");
    let folder_id: i64 = seed_row.try_get(1).expect("folder");

    let payload_bytes = format!("GatewayWorkQueueExtractedToken_{tag}").into_bytes();
    let sha = sha256_hex(&payload_bytes);
    store.put_mem(&sha, payload_bytes.clone());

    let msg_row_1 = owner
        .query_one(
            "INSERT INTO public.messages ( \
               mailbox_id, folder_id, message_id, subject, from_addr, body_text, thread_id, raw_ref \
             ) VALUES ($1, $2, $3, $4, 's@example.test', 'msg body 1', $3, 'inline:gw1') \
             RETURNING id, received_at",
            &[
                &mailbox_id,
                &folder_id,
                &format!("<gw557-1-{tag}@ex>"),
                &format!("GWSubj1_{tag}"),
            ],
        )
        .await
        .expect("msg1");
    let msg_id_1: i64 = msg_row_1.try_get(0).expect("msg_id_1");
    let received_at_1: chrono::DateTime<Utc> = msg_row_1.try_get(1).expect("ts1");

    let msg_row_2 = owner
        .query_one(
            "INSERT INTO public.messages ( \
               mailbox_id, folder_id, message_id, subject, from_addr, body_text, thread_id, raw_ref \
             ) VALUES ($1, $2, $3, $4, 's@example.test', $5, $3, 'inline:gw2') \
             RETURNING id, received_at",
            &[
                &mailbox_id,
                &folder_id,
                &format!("<gw557-2-{tag}@ex>"),
                &format!("GWSubj2_{tag}"),
                &format!("SecondBatchContinuationToken_{tag}"),
            ],
        )
        .await
        .expect("msg2");
    let msg_id_2: i64 = msg_row_2.try_get(0).expect("msg_id_2");
    let received_at_2: chrono::DateTime<Utc> = msg_row_2.try_get(1).expect("ts2");

    owner
        .execute(
            "INSERT INTO public.blobs (sha256, minio_ref, size_bytes, content_type) \
             VALUES ($1, $1, $2, 'text/plain') ON CONFLICT (sha256) DO NOTHING",
            &[&sha, &(payload_bytes.len() as i64)],
        )
        .await
        .expect("blob");
    owner
        .execute(
            "INSERT INTO public.message_attachments \
               (message_id, received_at, blob_sha256, filename, content_type, size_bytes) \
             VALUES ($1, $2, $3, $4, 'text/plain', $5)",
            &[
                &msg_id_1,
                &received_at_1,
                &sha,
                &format!("gw_att_{tag}.txt"),
                &(payload_bytes.len() as i64),
            ],
        )
        .await
        .expect("att");

    // 1. Enqueue TWO concurrent search.extract WorkQueue items for the SAME sha256
    //    -> concurrent drain_once with shared ExtractionSingleFlight extracts strictly ONCE!
    let extract_payload = serde_json::to_value(SearchExtractPayload {
        content_sha256: sha.clone(),
        storage_plane: ExtractionStoragePlane::Blob,
        object_key: None,
        drive_version_id: None,
        content_type: Some("text/plain".into()),
        filename: Some(format!("gw_att_{tag}.txt")),
    })
    .expect("json");
    queue
        .enqueue(&WorkRequest::new(
            WORK_KIND_SEARCH_EXTRACT,
            extract_payload.clone(),
        ))
        .await
        .expect("enqueue extract 1");
    queue
        .enqueue(&WorkRequest::new(WORK_KIND_SEARCH_EXTRACT, extract_payload))
        .await
        .expect("enqueue extract 2");

    let extract_consumer = SearchExtractConsumer::new(Arc::clone(&store))
        .with_single_flight(Arc::clone(&single_flight))
        .with_extractor(Arc::new(CountingExtractor {
            calls: Arc::clone(&calls),
        }));
    let drained = extract_consumer
        .drain_once(&queue, "gw-test-worker", None)
        .await
        .expect("drain extract");
    assert_eq!(drained, 2);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "concurrent WorkQueue search.extract must deduplicate by sha256"
    );

    // 2. Enqueue TWO outbox rows and ONE search.index_batch item with batch_limit = 1:
    //    - First drain_once processes row 1, sets SnapshotFreshnessFence dirty_count == 1,
    //      and automatically re-enqueues a follow-up continuation item!
    //    - Second drain_once drains row 2 and sets SnapshotFreshnessFence dirty_count == 0!
    let seq1 = enqueue_outbox(
        &worker_client,
        DocCorpus::Mail,
        "upsert",
        mailbox_id,
        msg_id_1,
        0,
        Some(received_at_1),
        Some(&sha),
    )
    .await
    .expect("outbox 1");
    let seq2 = enqueue_outbox(
        &worker_client,
        DocCorpus::Mail,
        "upsert",
        mailbox_id,
        msg_id_2,
        0,
        Some(received_at_2),
        None,
    )
    .await
    .expect("outbox 2");
    let idx_payload = serde_json::to_value(SearchIndexBatchPayload {
        corpus: Some(DocCorpus::Mail),
        batch_limit: Some(1),
    })
    .expect("json");
    queue
        .enqueue(
            &WorkRequest::new(WORK_KIND_SEARCH_INDEX_BATCH, idx_payload)
                .with_idempotency_key("search.index_batch:mail"),
        )
        .await
        .expect("enqueue index");

    let index_consumer = SearchIndexConsumer::new(Arc::clone(&engine), Arc::clone(&store))
        .with_single_flight(Arc::clone(&single_flight))
        .with_freshness_fence(Arc::clone(&fence));

    let first_drain = index_consumer
        .drain_once(&queue, "gw-test-worker", None)
        .await
        .expect("drain index 1");
    assert_eq!(first_drain, 1);

    let wm_after_1 = fence
        .watermark(DocCorpus::Mail)
        .expect("fence updated after batch 1");
    assert_eq!(
        wm_after_1.dirty_count, 1,
        "exact remaining outbox row count must be published to SnapshotFreshnessFence"
    );
    let db_wm_1: i64 = worker_client
        .query_one(
            "SELECT indexed_outbox_seq FROM public.search_index_watermarks WHERE corpus = 'mail'",
            &[],
        )
        .await
        .expect("wm1")
        .try_get(0)
        .expect("seq1");
    assert_eq!(db_wm_1, seq1);

    // Follow-up continuation item MUST already be pending without external re-enqueue!
    let second_drain = index_consumer
        .drain_once(&queue, "gw-test-worker", None)
        .await
        .expect("drain continuation batch 2");
    assert_eq!(
        second_drain, 1,
        "has_more continuation work item must drain remaining backlog automatically"
    );
    let wm_after_2 = fence
        .watermark(DocCorpus::Mail)
        .expect("fence updated after batch 2");
    assert_eq!(
        wm_after_2.dirty_count, 0,
        "dirty_count must drop to 0 once backlog is fully drained"
    );

    let hits_1 = engine
        .candidates(&CandidateQuery {
            corpus: DocCorpus::Mail,
            scope_hint: ScopeHint::Mailbox(mailbox_id),
            terms: NormalizedQuery::parse(&format!("GatewayWorkQueueExtractedToken_{tag}"))
                .expect("q1"),
            visibility: SearchVisibility::Live,
            limit: 10,
            continuation: None,
            metadata_only: false,
            calculate_total: false,
        })
        .await
        .expect("search 1");
    assert_eq!(hits_1.keys.len(), 1);

    let hits_2 = engine
        .candidates(&CandidateQuery {
            corpus: DocCorpus::Mail,
            scope_hint: ScopeHint::Mailbox(mailbox_id),
            terms: NormalizedQuery::parse(&format!("SecondBatchContinuationToken_{tag}"))
                .expect("q2"),
            visibility: SearchVisibility::Live,
            limit: 10,
            continuation: None,
            metadata_only: false,
            calculate_total: false,
        })
        .await
        .expect("search 2");
    assert_eq!(hits_2.keys.len(), 1);

    let wm_seq: i64 = worker_client
        .query_one(
            "SELECT indexed_outbox_seq FROM public.search_index_watermarks WHERE corpus = 'mail'",
            &[],
        )
        .await
        .expect("wm2")
        .try_get(0)
        .expect("seq2");
    assert!(wm_seq >= seq2);

    // 3. Mid-batch lease-loss fencing: flip lease_lost=true INSIDE extraction while
    //    run_batch_cancellable is actively executing -> MUST abort before Tantivy commit
    //    or advancing search_index_watermarks!
    struct LeaseFlippingExtractor {
        lease_lost: Arc<AtomicBool>,
    }
    impl ContentExtractor for LeaseFlippingExtractor {
        fn extract(
            &self,
            bytes: &[u8],
            content_type: Option<&str>,
            filename: Option<&str>,
        ) -> ExtractionResult {
            self.lease_lost.store(true, Ordering::Release);
            extract_bytes(bytes, content_type, filename)
        }
    }

    let mid_bytes = format!("MidBatchLeaseLossAttachment_{tag}").into_bytes();
    let mid_sha = sha256_hex(&mid_bytes);
    store.put_mem(&mid_sha, mid_bytes.clone());
    let msg_row_3 = owner
        .query_one(
            "INSERT INTO public.messages ( \
               mailbox_id, folder_id, message_id, subject, from_addr, body_text, thread_id, raw_ref \
             ) VALUES ($1, $2, $3, $4, 's@example.test', $5, $3, 'inline:gw3') \
             RETURNING id, received_at",
            &[
                &mailbox_id,
                &folder_id,
                &format!("<gw557-3-{tag}@ex>"),
                &format!("MidBatchLostSubject_{tag}"),
                &format!("MidBatchLostBody_{tag}"),
            ],
        )
        .await
        .expect("msg3");
    let msg_id_3: i64 = msg_row_3.try_get(0).expect("msg_id_3");
    let received_at_3: chrono::DateTime<Utc> = msg_row_3.try_get(1).expect("ts3");
    owner
        .execute(
            "INSERT INTO public.blobs (sha256, minio_ref, size_bytes, content_type) \
             VALUES ($1, $2, $3, 'text/plain') ON CONFLICT (sha256) DO NOTHING",
            &[
                &mid_sha,
                &format!("mailblobs/{mid_sha}"),
                &(mid_bytes.len() as i64),
            ],
        )
        .await
        .expect("blob3");
    owner
        .execute(
            "INSERT INTO public.message_attachments \
               (message_id, received_at, blob_sha256, filename, content_type, size_bytes) \
             VALUES ($1, $2, $3, $4, 'text/plain', $5)",
            &[
                &msg_id_3,
                &received_at_3,
                &mid_sha,
                &format!("mid_loss_{tag}.txt"),
                &(mid_bytes.len() as i64),
            ],
        )
        .await
        .expect("att3");

    let seq3 = enqueue_outbox(
        &worker_client,
        DocCorpus::Mail,
        "upsert",
        mailbox_id,
        msg_id_3,
        0,
        Some(received_at_3),
        None,
    )
    .await
    .expect("outbox 3");
    let lost_flag = Arc::new(AtomicBool::new(false));
    let db_arc: Arc<dyn setjoin_search::SearchPipelineDb> =
        Arc::new(WorkerPoolSearchDb::new(pool.clone()));
    let reader_arc: Arc<dyn setjoin_search::ObjectByteReader> =
        Arc::new(ObjectStoreByteReader::new(Arc::clone(&store)));
    let flip_svc = Arc::new(
        ContentExtractionService::new(Arc::clone(&db_arc), reader_arc).with_extractor(Arc::new(
            LeaseFlippingExtractor {
                lease_lost: Arc::clone(&lost_flag),
            },
        )),
    );
    let direct_pipeline =
        SearchIndexPipeline::new(db_arc, Arc::clone(&engine)).with_extraction_service(flip_svc);
    let lost_res = direct_pipeline
        .run_batch_cancellable(
            &SearchIndexBatchPayload {
                corpus: Some(DocCorpus::Mail),
                batch_limit: Some(10),
            },
            Some(Arc::clone(&lost_flag)),
        )
        .await;
    assert!(
        lost_flag.load(Ordering::Acquire),
        "extractor hook must have flipped lease_lost mid-batch"
    );
    assert!(
        matches!(lost_res, Err(SearchError::Unavailable(_))),
        "mid-batch lease loss must abort before Tantivy commit or advancing watermarks"
    );
    let lost_hits = engine
        .candidates(&CandidateQuery {
            corpus: DocCorpus::Mail,
            scope_hint: ScopeHint::Mailbox(mailbox_id),
            terms: NormalizedQuery::parse(&format!("MidBatchLostBody_{tag}")).expect("q3"),
            visibility: SearchVisibility::Live,
            limit: 10,
            continuation: None,
            metadata_only: false,
            calculate_total: false,
        })
        .await
        .expect("search lost");
    assert!(
        lost_hits.keys.is_empty(),
        "mid-batch lease loss must not commit doc into Tantivy"
    );
    let wm_after_loss: i64 = worker_client
        .query_one(
            "SELECT indexed_outbox_seq FROM public.search_index_watermarks WHERE corpus = 'mail'",
            &[],
        )
        .await
        .expect("wm loss")
        .try_get(0)
        .expect("seq");
    assert!(
        wm_after_loss < seq3,
        "watermark must NOT advance when lease is lost mid-batch"
    );

    // 4. Seed an aged orphaned search_extracted_text row and run BlobGcWorker live tick -> swept!
    let orphan_sha = sha256_hex(format!("gw-orphan-{tag}").as_bytes());
    worker_client
        .execute(
            "INSERT INTO public.search_extracted_text \
               (content_sha256, storage_plane, extraction_status, extracted_text, extracted_bytes, extracted_at) \
             VALUES ($1, 'blob', 'extracted', 'stale', 5, now() - interval '48 hours')",
            &[&orphan_sha],
        )
        .await
        .expect("seed orphan");

    let db = WorkerDatabase::from_dsns(&dsn, Some(&worker_dsn)).expect("worker db");
    let gc = BlobGcWorker::new(db, Arc::clone(&store))
        .with_mode(GcMode::Live)
        .with_worm_config(setjoin_gateway::blob_retention::Config::Off);
    let tick = gc.tick().await.expect("blob gc live tick");
    assert!(
        tick.extracted_text_swept >= 1,
        "BlobGcWorker live tick must sweep orphaned search_extracted_text"
    );

    let orphan_left: i64 = worker_client
        .query_one(
            "SELECT count(*) FROM public.search_extracted_text WHERE content_sha256 = $1",
            &[&orphan_sha],
        )
        .await
        .expect("orphan count")
        .try_get(0)
        .expect("c");
    assert_eq!(orphan_left, 0);
}

#[tokio::test]
async fn wave33_purge_consumer_ediscovery_consumer_and_ha_rpc_gateway_e2e() {
    let _serial = GW_TEST_LOCK.lock().await;
    let dsn = match resolve_db_gate(|k| std::env::var(k).ok()) {
        DbGate::Run { dsn, .. } => dsn,
        DbGate::Skip => {
            eprintln!("GATEWAY-SEARCH-WORKER-33-SKIP");
            return;
        }
        DbGate::Missing => panic!("REQUIRE_DB=1 set but TEST_DB_DSN/DB_DSN is absent"),
    };
    let worker_dsn = std::env::var("DB_WORKER_DSN")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| swap_dsn_user(&dsn, "setjoin_worker"));

    let (owner_client, owner_conn) = tokio_postgres::connect(&dsn, NoTls)
        .await
        .expect("connect owner");
    tokio::spawn(async move {
        let _ = owner_conn.await;
    });
    let worker_pool = WorkerPool::from_dsn(&worker_dsn, 4).expect("worker pool");
    let queue = WorkQueue::new(worker_pool.clone());
    let tag = next_tag();

    let email = format!("gw558_{tag}@example.test");
    let row = owner_client
        .query_one(
            "WITH dom AS ( \
               INSERT INTO public.domains (name) VALUES ('example.test') \
               ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name RETURNING id \
             ), u AS ( \
               INSERT INTO public.users (domain_id, email, username, password_hash, display_name) \
               SELECT id, $1, $2, 'hash', $2 FROM dom RETURNING id, domain_id \
             ), mb AS ( \
               INSERT INTO public.mailboxes (user_id, domain_id, email, display_name, is_primary) \
               SELECT u.id, u.domain_id, $1, $2, true FROM u RETURNING id, user_id \
             ), f AS ( \
               INSERT INTO public.folders (mailbox_id, name, path, role) \
               SELECT mb.id, 'Inbox', 'Inbox', 'inbox' FROM mb RETURNING id, mailbox_id \
             ) \
             SELECT mb.user_id, mb.id, f.id FROM mb JOIN f ON f.mailbox_id = mb.id",
            &[&email, &format!("gw558_{tag}")],
        )
        .await
        .expect("seed user");
    let user_id: i64 = row.try_get(0).expect("uid");
    let mailbox_id: i64 = row.try_get(1).expect("mb");
    let folder_id: i64 = row.try_get(2).expect("fid");

    let dir = TempDir::new().expect("tempdir");
    let rpc_secret = b"gateway-wave33-ha-rpc-secret-32b".to_vec();
    let cfg = SearchConfig {
        tier2_enabled: true,
        index_dir: dir.path().to_path_buf(),
        rpc_secret: rpc_secret.clone(),
        ..SearchConfig::default()
    };
    let runtime = Arc::new(setjoin_search::SearchRuntime::from_config(
        cfg.clone(),
        setjoin_search::PgSearchCapabilities::default(),
    ));
    let engine = Arc::clone(runtime.tier2().expect("tier2"));

    // 1. Seed a message with a unique purge canary, index it, and verify purge eviction via SearchPurgeConsumer!
    let canary = format!("gwpurgecanary{tag}");
    let msg_row = owner_client
        .query_one(
            "INSERT INTO public.messages \
               (mailbox_id, folder_id, message_id, subject, from_addr, body_text, thread_id, raw_ref) \
             VALUES ($1, $2, $3, $4, 'purge@example.test', $5, $3, 'inline:gw558') \
             RETURNING id, received_at",
            &[
                &mailbox_id,
                &folder_id,
                &format!("<gw558-purge-{tag}@example.test>"),
                &canary,
                &format!("body with {canary}"),
            ],
        )
        .await
        .expect("seed msg");
    let msg_id: i64 = msg_row.try_get(0).expect("id");
    let msg_ts: chrono::DateTime<Utc> = msg_row.try_get(1).expect("ts");

    let keep_token = format!("gwkeepedisc{tag}");
    let keep_row = owner_client
        .query_one(
            "INSERT INTO public.messages \
               (mailbox_id, folder_id, message_id, subject, from_addr, body_text, thread_id, raw_ref) \
             VALUES ($1, $2, $3, $4, 'keep@example.test', $5, $3, 'inline:gw558-keep') \
             RETURNING id, received_at",
            &[
                &mailbox_id,
                &folder_id,
                &format!("<gw558-keep-{tag}@example.test>"),
                &keep_token,
                &format!("kept body {keep_token}"),
            ],
        )
        .await
        .expect("seed keep");
    let keep_id: i64 = keep_row.try_get(0).expect("keep_id");
    let keep_ts: chrono::DateTime<Utc> = keep_row.try_get(1).expect("keep_ts");

    let m = engine
        .rebuild_epoch(
            &[
                setjoin_search::IndexDocument {
                    key: setjoin_search::DocumentKey::Mail {
                        mailbox_id,
                        id: msg_id,
                        received_at: msg_ts,
                    },
                    visibility: SearchVisibility::Live,
                    title: canary.clone(),
                    body: Some(format!("body with {canary}")),
                    headers: vec!["purge@example.test".to_owned()],
                    identifiers: vec![canary.clone()],
                    sort_i64: msg_ts.timestamp_micros(),
                    sort_name: canary.clone(),
                    crypto_sealed: false,
                },
                setjoin_search::IndexDocument {
                    key: setjoin_search::DocumentKey::Mail {
                        mailbox_id,
                        id: keep_id,
                        received_at: keep_ts,
                    },
                    visibility: SearchVisibility::Live,
                    title: keep_token.clone(),
                    body: Some(format!("kept body {keep_token}")),
                    headers: vec!["keep@example.test".to_owned()],
                    identifiers: vec![keep_token.clone()],
                    sort_i64: keep_ts.timestamp_micros(),
                    sort_name: keep_token.clone(),
                    crypto_sealed: false,
                },
            ],
            1,
            Some(Utc::now()),
        )
        .expect("rebuild");
    runtime
        .freshness_fence()
        .set_watermark(DocCorpus::Mail, m.generation, 0);
    runtime
        .freshness_fence()
        .set_watermark(DocCorpus::MailAttachment, m.generation, 0);

    // Enqueue search.purge_evict and drain via SearchPurgeConsumer!
    queue
        .enqueue(&WorkRequest::new(
            setjoin_search::WORK_KIND_SEARCH_PURGE_EVICT,
            serde_json::json!({
                "corpus": "mail",
                "scope_id": mailbox_id,
                "entity_id": msg_id,
                "sub_id": 0,
                "received_at": msg_ts,
            }),
        ))
        .await
        .expect("enqueue purge");
    let purge_consumer = SearchPurgeConsumer::new(Arc::clone(&engine))
        .with_freshness_fence(runtime.freshness_fence().clone());
    let mut purged_items = 0usize;
    while let Ok(n) = purge_consumer
        .drain_once(&queue, "gw-test-leader", None)
        .await
    {
        if n == 0 {
            break;
        }
        purged_items += n;
    }
    assert!(purged_items >= 1);
    assert!(
        !engine
            .contains_doc_key(&setjoin_search::DocumentKey::Mail {
                mailbox_id,
                id: msg_id,
                received_at: msg_ts,
            })
            .expect("contains"),
        "purged key must be absent after SearchPurgeConsumer"
    );

    // 2. Enqueue search.ediscovery and drain via SearchEdiscoveryConsumer!
    let search_row = owner_client
        .query_one(
            "INSERT INTO public.ediscovery_searches (name, created_by, query, status) \
             VALUES ($1, $2, $3::text::jsonb, 'pending') RETURNING id",
            &[
                &format!("gw-edisc-{tag}"),
                &user_id,
                &serde_json::json!({ "keywords": keep_token, "mailboxIds": [mailbox_id] })
                    .to_string(),
            ],
        )
        .await
        .expect("seed ediscovery search");
    let search_id: i64 = search_row.try_get(0).expect("search_id");
    queue
        .enqueue(&WorkRequest::new(
            setjoin_search::WORK_KIND_SEARCH_EDISCOVERY,
            serde_json::json!({ "search_id": search_id, "actor_id": user_id }),
        ))
        .await
        .expect("enqueue edisc");
    let edisc_consumer =
        SearchEdiscoveryConsumer::new(Some(Arc::clone(&engine) as Arc<dyn SearchEngine>));
    let drained_edisc = edisc_consumer
        .drain_once(&queue, "gw-test-edisc", None)
        .await
        .expect("drain edisc");
    assert!(drained_edisc >= 1);
    let status_row = owner_client
        .query_one(
            "SELECT status, result_count, search_provenance::text \
               FROM public.ediscovery_searches WHERE id = $1",
            &[&search_id],
        )
        .await
        .expect("read search");
    let status: String = status_row.try_get(0).expect("status");
    let count: i32 = status_row.try_get(1).expect("count");
    let prov_text: String = status_row.try_get(2).expect("prov");
    assert_eq!(status, "complete");
    assert_eq!(count, 1);
    let prov: serde_json::Value = serde_json::from_str(&prov_text).expect("prov json");
    assert!(prov["engine_tier"].as_str().is_some());

    // 2b. KQL eDiscovery via SearchEdiscoveryConsumer MUST execute real KQL AST (never unfiltered full-org scan)!
    let kql_search_id: i64 = owner_client
        .query_one(
            "INSERT INTO public.ediscovery_searches (name, created_by, query, status) \
             VALUES ($1, $2, $3::text::jsonb, 'pending') RETURNING id",
            &[
                &format!("gw-kql-{tag}"),
                &user_id,
                &serde_json::json!({ "kql": format!("subject:{keep_token}") }).to_string(),
            ],
        )
        .await
        .expect("seed kql search")
        .try_get(0)
        .expect("kql_search_id");
    queue
        .enqueue(&WorkRequest::new(
            setjoin_search::WORK_KIND_SEARCH_EDISCOVERY,
            serde_json::json!({ "search_id": kql_search_id, "actor_id": user_id }),
        ))
        .await
        .expect("enqueue kql");
    while edisc_consumer
        .drain_once(&queue, "gw-test-kql", None)
        .await
        .expect("drain kql")
        > 0
    {}
    let kql_row = owner_client
        .query_one(
            "SELECT status, result_count, search_provenance::text \
               FROM public.ediscovery_searches WHERE id = $1",
            &[&kql_search_id],
        )
        .await
        .expect("read kql search");
    assert_eq!(kql_row.try_get::<_, String>(0).expect("st"), "complete");
    assert_eq!(
        kql_row.try_get::<_, i32>(1).expect("cnt"),
        1,
        "KQL search must return ONLY the single matching message, never a full-org scan"
    );
    let kql_audit_cnt: i64 = owner_client
        .query_one(
            "SELECT count(*) FROM public.admin_audit_log \
              WHERE action = 'ediscovery_search_complete' AND target_id = $1",
            &[&kql_search_id],
        )
        .await
        .expect("kql audit")
        .try_get(0)
        .expect("cnt");
    assert_eq!(kql_audit_cnt, 1);

    // 2c. GatewaySearchFacade wire-contract & ACL parity (Mail jmap_email_state + tag/snooze,
    //     Chat bare JSON array + GUEST_HISTORY_FLOOR, Drive 8-field JSON + node-level ACL grant)!
    let app_dsn = std::env::var("DB_APP_DSN")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| swap_dsn_user(&dsn, "setjoin_app"));
    let app_pool = setjoin_pg::AppPool::from_dsn(&app_dsn, 4).expect("facade app pool");
    let facade =
        setjoin_gateway::search_facade::GatewaySearchFacade::new(Arc::clone(&runtime), app_pool);

    // Seed Mail location tag + snooze tag and verify inMailbox + snooze exclusion + exact JMAP JSON shape!
    let inbox_tag: i64 = owner_client
        .query_one(
            "INSERT INTO public.tags (mailbox_id, name, exclusive_group) \
             VALUES ($1, $2, 'location') RETURNING id",
            &[&mailbox_id, &format!("Inbox558_{tag}")],
        )
        .await
        .expect("inbox tag")
        .try_get(0)
        .expect("tid");
    let snooze_tag: i64 = owner_client
        .query_one(
            "INSERT INTO public.tags (mailbox_id, name, exclusive_group) \
             VALUES ($1, $2, 'snooze') RETURNING id",
            &[&mailbox_id, &format!("Snoozed558_{tag}")],
        )
        .await
        .expect("snooze tag")
        .try_get(0)
        .expect("stid");
    owner_client
        .execute(
            "INSERT INTO public.message_tags (message_id, received_at, tag_id) VALUES ($1, $2, $3)",
            &[&keep_id, &keep_ts, &inbox_tag],
        )
        .await
        .expect("tag keep");
    let actor_id = setjoin_contracts::ids::ActorId::new(user_id).expect("actor id");
    let mb_id = setjoin_contracts::ids::MailboxId::new(mailbox_id).expect("mb id");
    let mb_auth = setjoin_pg::MailboxAuthContext::from_authenticated_session(
        actor_id,
        mb_id,
        setjoin_contracts::ids::Generation(1),
    );
    let filter_in_box = serde_json::json!({
        "text": keep_token,
        "inMailbox": inbox_tag.to_string(),
    })
    .to_string();
    let mail_json_str = facade
        .try_mail_query(&mb_auth, Some(&filter_in_box), None, 0, 20)
        .await
        .expect("facade mail query");
    let mail_json: serde_json::Value = serde_json::from_str(&mail_json_str).expect("mail json");
    assert_eq!(mail_json["accountId"], mailbox_id.to_string());
    assert!(
        mail_json["state"].as_str().is_some(),
        "must emit canonical 'state' from jmap_email_state"
    );
    assert_eq!(mail_json["canCalculateChanges"], false);
    assert_eq!(mail_json["position"], 0);
    assert_eq!(mail_json["total"], 1);
    assert_eq!(mail_json["ids"], serde_json::json!([keep_id.to_string()]));

    // Adding a snooze tag must exclude the message from the 'location' inMailbox view!
    owner_client
        .execute(
            "INSERT INTO public.message_tags (message_id, received_at, tag_id) VALUES ($1, $2, $3)",
            &[&keep_id, &keep_ts, &snooze_tag],
        )
        .await
        .expect("snooze keep");
    let snoozed_str = facade
        .try_mail_query(&mb_auth, Some(&filter_in_box), None, 0, 20)
        .await
        .expect("facade snoozed mail query");
    let snoozed_json: serde_json::Value = serde_json::from_str(&snoozed_str).expect("snoozed json");
    assert_eq!(snoozed_json["total"], 0);
    assert_eq!(snoozed_json["ids"], serde_json::json!([]));

    // Seed Chat message + Drive node reachable ONLY via node-level drive_acl_grants (no drive_space_members)!
    let ch_id: i64 = owner_client
        .query_one(
            "INSERT INTO public.chat_channels (kind, visibility, name, created_by) \
             VALUES ('channel', 'private', $1, $2) RETURNING id",
            &[&format!("gwch558-{tag}"), &user_id],
        )
        .await
        .expect("ch")
        .try_get(0)
        .expect("cid");
    owner_client
        .execute(
            "INSERT INTO public.chat_channel_members (channel_id, user_id, role, history_floor_seq, joined_at) \
             VALUES ($1, $2, 'member', 1, now() - interval '1 minute')",
            &[&ch_id, &user_id],
        )
        .await
        .expect("ch member");
    let chat_tok = format!("gwchatfacade{tag}");
    let ch_pre: i64 = owner_client
        .query_one(
            "INSERT INTO public.chat_messages (channel_id, author_id, body, seq, created_at) \
             VALUES ($1, $2, $3, 1, now() - interval '5 minutes') RETURNING id",
            &[&ch_id, &user_id, &format!("pre floor {chat_tok}")],
        )
        .await
        .expect("pre")
        .try_get(0)
        .expect("id");
    let ch_post: i64 = owner_client
        .query_one(
            "INSERT INTO public.chat_messages (channel_id, author_id, body, seq, created_at) \
             VALUES ($1, $2, $3, 2, now()) RETURNING id",
            &[&ch_id, &user_id, &format!("post floor {chat_tok}")],
        )
        .await
        .expect("post")
        .try_get(0)
        .expect("id");

    // Seed second user owning a Drive space, grant user_id node-level read_metadata ONLY!
    let owner2_id: i64 = owner_client
        .query_one(
            "INSERT INTO public.users (domain_id, email, username, password_hash, display_name) \
             SELECT domain_id, $1, $2, 'hash', $2 FROM public.users WHERE id = $3 RETURNING id",
            &[
                &format!("drvowner558_{tag}@example.test"),
                &format!("drvowner558_{tag}"),
                &user_id,
            ],
        )
        .await
        .expect("owner2")
        .try_get(0)
        .expect("o2");
    let sp_id: i64 = owner_client
        .query_one(
            "INSERT INTO public.drive_spaces (name, classification, owner_user_id, acl_mode) \
             VALUES ($1, 'regular', $2, 'acl') RETURNING id",
            &[&format!("gwsp558-{tag}"), &owner2_id],
        )
        .await
        .expect("sp")
        .try_get(0)
        .expect("sid");
    let drv_tok = format!("gwdrivegrant{tag}");
    let dn_id: i64 = owner_client
        .query_one(
            "INSERT INTO public.drive_nodes (space_id, kind, name, created_by) \
             VALUES ($1, 'file', $2, $3) RETURNING id",
            &[&sp_id, &format!("{drv_tok}.pdf"), &owner2_id],
        )
        .await
        .expect("dn")
        .try_get(0)
        .expect("dn_id");
    owner_client
        .execute(
            "INSERT INTO public.drive_node_closure (space_id, ancestor_id, descendant_id, depth) \
             VALUES ($1, $2, $2, 0) ON CONFLICT DO NOTHING",
            &[&sp_id, &dn_id],
        )
        .await
        .expect("closure");
    owner_client
        .execute(
            "INSERT INTO public.drive_acl_grants \
               (space_id, node_id, subject_kind, subject_user_id, preset, capabilities, propagation, state, created_by) \
             VALUES ($1, $2, 'user', $3, 'custom', ARRAY['read_metadata'], 'self', 'active', $4)",
            &[&sp_id, &dn_id, &user_id, &owner2_id],
        )
        .await
        .expect("acl grant");

    // Index chat & drive docs into Tantivy and advance freshness fence.
    use setjoin_search::SearchIndexer;
    engine
        .upsert_batch(&[
            setjoin_search::IndexDocument {
                key: setjoin_search::DocumentKey::Chat {
                    channel_id: ch_id,
                    id: ch_pre,
                },
                visibility: SearchVisibility::Live,
                title: String::new(),
                body: Some(format!("pre floor {chat_tok}")),
                headers: Vec::new(),
                identifiers: vec![chat_tok.clone()],
                sort_i64: 1,
                sort_name: String::new(),
                crypto_sealed: false,
            },
            setjoin_search::IndexDocument {
                key: setjoin_search::DocumentKey::Chat {
                    channel_id: ch_id,
                    id: ch_post,
                },
                visibility: SearchVisibility::Live,
                title: String::new(),
                body: Some(format!("post floor {chat_tok}")),
                headers: Vec::new(),
                identifiers: vec![chat_tok.clone()],
                sort_i64: 2,
                sort_name: String::new(),
                crypto_sealed: false,
            },
            setjoin_search::IndexDocument {
                key: setjoin_search::DocumentKey::Drive {
                    space_id: sp_id,
                    id: dn_id,
                },
                visibility: SearchVisibility::Live,
                title: format!("{drv_tok}.pdf"),
                body: None,
                headers: Vec::new(),
                identifiers: vec![format!("{drv_tok}.pdf")],
                sort_i64: 3,
                sort_name: format!("{drv_tok}.pdf"),
                crypto_sealed: false,
            },
        ])
        .await
        .expect("upsert chat/drive");
    let new_gen = engine.commit_generation().await.expect("commit gen");
    for c in [
        DocCorpus::Mail,
        DocCorpus::MailAttachment,
        DocCorpus::Chat,
        DocCorpus::Drive,
        DocCorpus::DriveFile,
    ] {
        runtime.freshness_fence().set_watermark(c, new_gen, 0);
    }

    let chat_raw = facade
        .try_chat_search_actor(actor_id, &chat_tok, None, None, None, None)
        .await
        .expect("facade chat search");
    let chat_arr: serde_json::Value = serde_json::from_str(&chat_raw).expect("chat json");
    let chat_items = chat_arr
        .as_array()
        .expect("chat_search must return bare JSON array, NOT {messages: [...]}");
    assert_eq!(chat_items.len(), 1, "GUEST_HISTORY_FLOOR must hide ch_pre");
    assert_eq!(chat_items[0]["messageId"], ch_post);
    assert_eq!(chat_items[0]["channelId"], ch_id);

    let drive_val = facade
        .try_drive_search_actor(actor_id, None, &drv_tok, None)
        .await
        .expect("facade drive search");
    let drive_items = drive_val.as_array().expect("drive array");
    assert_eq!(
        drive_items.len(),
        1,
        "drive search must discover space via node-level drive_acl_grants"
    );
    let d0 = &drive_items[0];
    assert_eq!(d0["id"], dn_id);
    assert_eq!(d0["spaceId"], sp_id);
    assert!(d0.get("parentId").is_some());
    assert_eq!(d0["kind"], "file");
    assert_eq!(d0["name"], format!("{drv_tok}.pdf"));
    assert!(d0.get("sizeBytes").is_some());
    assert!(d0.get("contentType").is_some());
    assert!(d0.get("createdAt").is_some());

    // 3. Boot a real Gateway HTTP listener with SearchRuntime and verify:
    //    - Unauthenticated / stale-timestamp / bad-sig requests to /_internal/search/* get 403
    //    - Authenticated RemoteSearchEngine hits Tier-2 leader cleanly
    //    - Stopping leader causes TwoTierSearchEngine to fall back cleanly to Tier-1 PG!
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let base_url = format!("http://{addr}");
    let gateway = setjoin_gateway::Gateway::new(
        setjoin_gateway::Config {
            upstream: None,
            upstream_header_timeout: std::time::Duration::from_secs(5),
            trusted_proxies: setjoin_gateway::TrustedProxies::default(),
            edge_limit: None,
        },
        setjoin_gateway::RouteTable::proxy_all(),
    )
    .expect("gateway")
    .with_search_runtime(Arc::clone(&runtime));
    let shutdown_tok = tokio_util::sync::CancellationToken::new();
    let srv_tok = shutdown_tok.clone();
    let srv_handle = tokio::spawn(async move {
        gateway.serve_until(listener, srv_tok.cancelled()).await;
    });

    // Unauthenticated health probe -> 403
    let http = reqwest::Client::new();
    let unauth = http
        .get(format!(
            "{base_url}{}",
            setjoin_search::INTERNAL_SEARCH_HEALTH_PATH
        ))
        .send()
        .await
        .expect("unauth req");
    assert_eq!(unauth.status().as_u16(), 403);

    // Replay-expired timestamp -> 403
    let expired_ts = Utc::now().timestamp() - 120;
    let expired_sig = setjoin_search::sign_rpc_request(
        &rpc_secret,
        "GET",
        setjoin_search::INTERNAL_SEARCH_HEALTH_PATH,
        expired_ts,
        b"",
    )
    .expect("sign expired");
    let replay = http
        .get(format!(
            "{base_url}{}",
            setjoin_search::INTERNAL_SEARCH_HEALTH_PATH
        ))
        .header(setjoin_search::HEADER_SEARCH_TS, expired_ts.to_string())
        .header(setjoin_search::HEADER_SEARCH_SIG, expired_sig)
        .send()
        .await
        .expect("replay req");
    assert_eq!(replay.status().as_u16(), 403);

    // Fresh SearchRuntime defaults to leader_active=false (HTTP-only stateless nodes
    // and un-elected nodes MUST return 503 on BOTH /_internal/search/health and /candidates)!
    let init_ts = Utc::now().timestamp();
    let init_sig = setjoin_search::sign_rpc_request(
        &rpc_secret,
        "GET",
        setjoin_search::INTERNAL_SEARCH_HEALTH_PATH,
        init_ts,
        b"",
    )
    .expect("sign init");
    let init_health = http
        .get(format!(
            "{base_url}{}",
            setjoin_search::INTERNAL_SEARCH_HEALTH_PATH
        ))
        .header(setjoin_search::HEADER_SEARCH_TS, init_ts.to_string())
        .header(setjoin_search::HEADER_SEARCH_SIG, init_sig)
        .send()
        .await
        .expect("init health req");
    assert_eq!(
        init_health.status().as_u16(),
        503,
        "un-elected / HTTP-only SearchRuntime must default to 503 on /_internal/search/health"
    );

    // Activate leader lease with a real deadline window -> 200 healthy=true
    runtime.set_leader_active_for(std::time::Duration::from_secs(30));
    let now_ts = Utc::now().timestamp();
    let ok_sig = setjoin_search::sign_rpc_request(
        &rpc_secret,
        "GET",
        setjoin_search::INTERNAL_SEARCH_HEALTH_PATH,
        now_ts,
        b"",
    )
    .expect("sign ok");
    let health_resp = http
        .get(format!(
            "{base_url}{}",
            setjoin_search::INTERNAL_SEARCH_HEALTH_PATH
        ))
        .header(setjoin_search::HEADER_SEARCH_TS, now_ts.to_string())
        .header(setjoin_search::HEADER_SEARCH_SIG, ok_sig)
        .send()
        .await
        .expect("health req");
    assert_eq!(health_resp.status().as_u16(), 200);
    let health_json: serde_json::Value =
        serde_json::from_slice(&health_resp.bytes().await.expect("body")).expect("json");
    assert_eq!(health_json["healthy"], true);

    // Follower RemoteSearchEngine wired into TwoTierSearchEngine hits live leader!
    let remote = Arc::new(
        setjoin_search::RemoteSearchEngine::new(
            Arc::new(setjoin_search::StaticLeaderResolver::new(base_url.clone())),
            rpc_secret,
            std::time::Duration::from_millis(500),
        )
        .expect("remote engine"),
    );
    let fallback_key = setjoin_search::DocumentKey::Mail {
        mailbox_id,
        id: 999_999,
        received_at: keep_ts,
    };
    let fb_clone = fallback_key.clone();
    let tier1 = Arc::new(setjoin_search::Tier1PgSearchEngine::new(
        setjoin_search::PgSearchCapabilities::default(),
        Arc::new(move |_q| {
            let k = fb_clone.clone();
            Box::pin(async move {
                Ok(setjoin_search::CandidateBatch {
                    keys: vec![k],
                    generation: 0,
                    continuation: None,
                    tier: setjoin_search::SearchTier::Tier1Pg,
                    degraded: false,
                })
            })
        }),
    ));
    let follower = setjoin_search::TwoTierSearchEngine::with_remote_tier2(cfg, tier1, remote);
    let q = CandidateQuery {
        corpus: DocCorpus::Mail,
        scope_hint: ScopeHint::Mailbox(mailbox_id),
        terms: NormalizedQuery::parse(&keep_token).expect("q"),
        visibility: SearchVisibility::Live,
        limit: 10,
        continuation: None,
        metadata_only: false,
        calculate_total: false,
    };
    let live_batch = follower.candidates(&q).await.expect("follower rpc hit");
    assert_eq!(live_batch.tier, setjoin_search::SearchTier::Tier2Tantivy);
    assert!(!live_batch.degraded);
    assert!(live_batch.keys.iter().any(|k| matches!(
        k,
        setjoin_search::DocumentKey::Mail { id, .. } if *id == keep_id
    )));

    // Natural lease-deadline expiry WITHOUT manually calling `set_leader_active(false)`:
    // `/_internal/search/health` and `/_internal/search/candidates` MUST flip to 503 automatically
    // once the conservative deadline elapses, causing follower to fall back cleanly to Tier-1 PG!
    runtime.set_leader_active_for(std::time::Duration::from_millis(120));
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let demoted_ts = Utc::now().timestamp();
    let demoted_sig = setjoin_search::sign_rpc_request(
        &runtime.config().rpc_secret,
        "GET",
        setjoin_search::INTERNAL_SEARCH_HEALTH_PATH,
        demoted_ts,
        b"",
    )
    .expect("sign demoted");
    let demoted_health = http
        .get(format!(
            "{base_url}{}",
            setjoin_search::INTERNAL_SEARCH_HEALTH_PATH
        ))
        .header(setjoin_search::HEADER_SEARCH_TS, demoted_ts.to_string())
        .header(setjoin_search::HEADER_SEARCH_SIG, demoted_sig)
        .send()
        .await
        .expect("demoted health req");
    assert_eq!(
        demoted_health.status().as_u16(),
        503,
        "expired leader deadline must automatically return HTTP 503 on /_internal/search/health"
    );
    let demoted_batch = follower
        .candidates(&q)
        .await
        .expect("follower fallback on deadline-expired leader");
    assert_eq!(demoted_batch.tier, setjoin_search::SearchTier::Tier1Pg);
    assert!(demoted_batch.degraded);
    assert_eq!(demoted_batch.keys, vec![fallback_key.clone()]);

    // Shut down leader -> follower transparently degrades to Tier-1 PG!
    shutdown_tok.cancel();
    let _ = srv_handle.await;
    let degraded_batch = follower
        .candidates(&q)
        .await
        .expect("follower fallback after leader stop");
    assert_eq!(degraded_batch.tier, setjoin_search::SearchTier::Tier1Pg);
    assert!(degraded_batch.degraded);
    assert_eq!(degraded_batch.keys, vec![fallback_key]);
}
