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
    ObjectStoreByteReader, SearchExtractConsumer, SearchIndexConsumer, WorkerPoolSearchDb,
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
