//! Live-PostgreSQL integration tests for Wave 3.2 (`#557`):
//! - AC #1: Content-addressed deduplication extracts identical bytes strictly once
//!   across Mail attachments AND Drive file versions (same SHA-256 across planes),
//!   and cross-plane GC retains the cache when one plane deletes while the other lives.
//! - AC #2: Encrypted, unsupported, oversized, and corrupt files index filenames/headers
//!   cleanly without failing the batch.
//! - AC #3: Full-domain Mail (incl. S/MIME boundary), Chat (`chat_messages`,
//!   `chat_message_revisions` strictly `ComplianceOnly`, attachments, camelCase `"channelId"`
//!   scheduled Chat + scheduled Mail draft hydration + cancellation eviction), and Drive
//!   (`drive_nodes` + `drive_file_versions`) indexing with epoch-safe monotonic watermarks.
//! - AC #4: `search_extracted_text_gc_sweep` reclaims orphaned blob & Drive cache rows
//!   while preserving live references AND Drive 30-day recoverable admin trash (`purged_at`).
//! - Review-hardening proofs: per-key chronological `upsert`->`delete` ordering, delete-only
//!   batch on fresh uninitialized index, `> 16 MiB` batch chunking, spoofed Drive `content_sha256`
//!   tenant isolation, and production write-capture trigger -> outbox -> `work_items` E2E.

use chrono::{Duration, Utc};
use setjoin_conformance::db_gate::{resolve as resolve_db_gate, DbGate};
use setjoin_search::{
    chat_revision_doc_id, enqueue_outbox, ensure_search_watermarks_initialized, extract_bytes,
    normalize_blob_object_key, scheduled_action_doc_id, BoxFuture, CandidateQuery,
    ContentExtractionService, ContentExtractor, DocCorpus, DocumentKey, ExtractionResult,
    ExtractionStatus, ExtractionStoragePlane, NormalizedQuery, ObjectByteReader, ScopeHint,
    SearchConfig, SearchEngine, SearchError, SearchExtractPayload, SearchIndexBatchPayload,
    SearchIndexPipeline, SearchVisibility, TantivySearchEngine,
};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::{Cursor, Write};
use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tempfile::TempDir;
use tokio_postgres::NoTls;
use zip::write::SimpleFileOptions;
use zip::ZipWriter;

static SEED_SEQ: AtomicI64 = AtomicI64::new(557_000);
static DB_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn next_tag() -> i64 {
    let seq = SEED_SEQ.fetch_add(1, Ordering::SeqCst);
    (Utc::now().timestamp_micros() & 0x0FFF_FFFF).saturating_add(seq)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

fn swap_dsn_user(dsn: &str, new_user: &str) -> String {
    if let Some(rest) = dsn.strip_prefix("postgres://") {
        if let Some((_user_part, after_at)) = rest.split_once('@') {
            return format!("postgres://{new_user}@{after_at}");
        }
    }
    if let Some(rest) = dsn.strip_prefix("postgresql://") {
        if let Some((_user_part, after_at)) = rest.split_once('@') {
            return format!("postgresql://{new_user}@{after_at}");
        }
    }
    dsn.to_owned()
}

async fn connect_as(dsn: &str) -> tokio_postgres::Client {
    let (client, conn) = tokio_postgres::connect(dsn, NoTls)
        .await
        .expect("connect postgres");
    tokio::spawn(async move {
        let _ = conn.await;
    });
    client
}

async fn reset_outbox_and_watermarks(worker: &tokio_postgres::Client) {
    worker
        .execute("DELETE FROM public.search_index_watermarks", &[])
        .await
        .expect("clear watermarks");
    worker
        .execute("DELETE FROM public.search_index_outbox", &[])
        .await
        .expect("clear outbox");
    worker
        .execute("DELETE FROM public.search_dirty_keys", &[])
        .await
        .expect("clear dirty keys");
}

fn make_docx(text: &str) -> Vec<u8> {
    let xml = format!(
        r#"<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>{text}</w:t></w:r></w:p></w:body></w:document>"#
    );
    let mut cur = Cursor::new(Vec::new());
    {
        let mut writer = ZipWriter::new(&mut cur);
        let opts =
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        writer
            .start_file("word/document.xml", opts)
            .expect("start_file");
        writer.write_all(xml.as_bytes()).expect("write");
        writer.finish().expect("finish");
    }
    cur.into_inner()
}

#[derive(Default)]
struct InMemoryObjectReader {
    objects: Mutex<HashMap<String, Vec<u8>>>,
}

impl InMemoryObjectReader {
    fn insert(&self, key: impl Into<String>, bytes: Vec<u8>) {
        self.objects.lock().expect("lock").insert(key.into(), bytes);
    }
}

impl ObjectByteReader for InMemoryObjectReader {
    fn read_bytes<'a>(
        &'a self,
        key: &'a str,
        max_bytes: usize,
    ) -> BoxFuture<'a, Result<Vec<u8>, SearchError>> {
        let key = key.to_owned();
        Box::pin(async move {
            let map = self.objects.lock().expect("lock");
            let Some(bytes) = map.get(&key) else {
                return Err(SearchError::Io(format!("object not found: {key}")));
            };
            let end = bytes.len().min(max_bytes);
            Ok(bytes[..end].to_vec())
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

async fn seed_user_and_mailbox(owner: &tokio_postgres::Client, suffix: &str) -> (i64, i64, i64) {
    let email = format!("search557_{suffix}@example.test");
    let row = owner
        .query_one(
            "WITH dom AS ( \
               INSERT INTO public.domains (name) VALUES ('example.test') \
               ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name \
               RETURNING id \
             ), u AS ( \
               INSERT INTO public.users (domain_id, email, username, password_hash, display_name) \
               SELECT id, $1, $2, 'hash', $2 FROM dom \
               RETURNING id, domain_id \
             ), mb AS ( \
               INSERT INTO public.mailboxes (user_id, domain_id, email, display_name, is_primary) \
               SELECT u.id, u.domain_id, $1, $2, true FROM u \
               RETURNING id, user_id \
             ), f AS ( \
               INSERT INTO public.folders (mailbox_id, name, path, role) \
               SELECT mb.id, 'Inbox', 'Inbox', 'inbox' FROM mb \
               RETURNING id, mailbox_id \
             ) \
             SELECT mb.user_id, mb.id, f.id FROM mb JOIN f ON f.mailbox_id = mb.id",
            &[&email, &format!("u557_{suffix}")],
        )
        .await
        .expect("seed user+mailbox+folder");
    (
        row.try_get(0).expect("user_id"),
        row.try_get(1).expect("mailbox_id"),
        row.try_get(2).expect("folder_id"),
    )
}

async fn seed_message(
    owner: &tokio_postgres::Client,
    mailbox_id: i64,
    folder_id: i64,
    subject: &str,
    body_text: &str,
    crypto_type: Option<&str>,
) -> (i64, chrono::DateTime<Utc>) {
    let msg_id = format!("<msg557-{}@example.test>", next_tag());
    let received_at = Utc::now() - Duration::seconds(5);
    let row = owner
        .query_one(
            "INSERT INTO public.messages ( \
               mailbox_id, folder_id, message_id, subject, from_addr, from_name, \
               body_text, thread_id, raw_ref, is_deleted, held, crypto_type, received_at \
             ) VALUES ( \
               $1, $2, $3, $4, 'alice@example.test', 'Alice', $5, $3, 'inline:test', false, false, $6, $7 \
             ) RETURNING id, received_at",
            &[
                &mailbox_id,
                &folder_id,
                &msg_id,
                &subject,
                &body_text,
                &crypto_type,
                &received_at,
            ],
        )
        .await
        .expect("seed message");
    (
        row.try_get(0).expect("id"),
        row.try_get(1).expect("received_at"),
    )
}

async fn seed_blob_and_attachment(
    owner: &tokio_postgres::Client,
    msg_id: i64,
    received_at: chrono::DateTime<Utc>,
    sha: &str,
    size_bytes: i64,
    filename: &str,
    content_type: &str,
) -> i64 {
    owner
        .execute(
            "INSERT INTO public.blobs (sha256, minio_ref, size_bytes, content_type) \
             VALUES ($1, $1, $2, $3) ON CONFLICT (sha256) DO NOTHING",
            &[&sha, &size_bytes, &content_type],
        )
        .await
        .expect("insert blob");
    let row = owner
        .query_one(
            "INSERT INTO public.message_attachments ( \
               message_id, received_at, blob_sha256, filename, content_type, size_bytes \
             ) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
            &[
                &msg_id,
                &received_at,
                &sha,
                &filename,
                &content_type,
                &size_bytes,
            ],
        )
        .await
        .expect("insert message_attachment");
    row.try_get(0).expect("att_id")
}

async fn seed_drive_file_with_chunk(
    owner: &tokio_postgres::Client,
    user_id: i64,
    space_id: i64,
    name: &str,
    content_bytes: &[u8],
    content_type: &str,
    reader: &InMemoryObjectReader,
) -> (i64, i64, String) {
    let sha = sha256_hex(content_bytes);
    let storage_ref = format!("drive/g/{sha}");
    reader.insert(&storage_ref, content_bytes.to_vec());

    let node_row = owner
        .query_one(
            "INSERT INTO public.drive_nodes (space_id, kind, name, created_by) \
             VALUES ($1, 'file', $2, $3) RETURNING id",
            &[&space_id, &name, &user_id],
        )
        .await
        .expect("insert drive_node");
    let node_id: i64 = node_row.try_get(0).expect("node_id");

    owner
        .execute(
            "INSERT INTO public.drive_files (node_id, space_id, size_bytes, content_type) \
             VALUES ($1, $2, $3, $4)",
            &[
                &node_id,
                &space_id,
                &(content_bytes.len() as i64),
                &content_type,
            ],
        )
        .await
        .expect("insert drive_files");

    let ver_row = owner
        .query_one(
            "INSERT INTO public.drive_file_versions ( \
               file_node_id, space_id, content_sha256, size_bytes, content_type, author_user_id \
             ) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
            &[
                &node_id,
                &space_id,
                &sha,
                &(content_bytes.len() as i64),
                &content_type,
                &user_id,
            ],
        )
        .await
        .expect("insert drive_file_versions");
    let version_id: i64 = ver_row.try_get(0).expect("version_id");

    owner
        .execute(
            "UPDATE public.drive_files SET head_version_id = $1 WHERE node_id = $2",
            &[&version_id, &node_id],
        )
        .await
        .expect("set head_version_id");

    owner
        .execute(
            "INSERT INTO public.drive_chunks (scope_key, sha256, size_bytes, ref_count, storage_ref) \
             VALUES ('g', $1, $2, 1, $3) \
             ON CONFLICT (scope_key, sha256) DO UPDATE SET ref_count = public.drive_chunks.ref_count + 1",
            &[&sha, &(content_bytes.len().max(1) as i32), &storage_ref],
        )
        .await
        .expect("insert drive_chunks");

    owner
        .execute(
            "INSERT INTO public.drive_version_chunks (version_id, stream, ordinal, scope_key, chunk_sha256) \
             VALUES ($1, 'content', 0, 'g', $2)",
            &[&version_id, &sha],
        )
        .await
        .expect("insert drive_version_chunks");

    (node_id, version_id, sha)
}

#[tokio::test]
async fn ac1_content_addressed_dedup_extracts_strictly_once_across_mail_and_drive() {
    let _guard = DB_TEST_LOCK.lock().await;
    let dsn = match resolve_db_gate(|k| std::env::var(k).ok()) {
        DbGate::Run { dsn, .. } => dsn,
        DbGate::Skip => {
            eprintln!("SETJOIN-SEARCH-557-SKIP (reason=no-dsn)");
            return;
        }
        DbGate::Missing => panic!("REQUIRE_DB=1 set but TEST_DB_DSN/DB_DSN is absent"),
    };
    let owner = connect_as(&dsn).await;
    let worker = Arc::new(connect_as(&swap_dsn_user(&dsn, "setjoin_worker")).await);
    reset_outbox_and_watermarks(worker.as_ref()).await;

    let reader = Arc::new(InMemoryObjectReader::default());
    let calls = Arc::new(AtomicUsize::new(0));
    let svc = ContentExtractionService::new(worker.clone(), reader.clone()).with_extractor(
        Arc::new(CountingExtractor {
            calls: Arc::clone(&calls),
        }),
    );

    let tag = next_tag();
    let (user_id, mailbox_id, folder_id) =
        seed_user_and_mailbox(&owner, &format!("ac1_{tag}")).await;

    // 1. Identical DOCX bytes shared across TWO Mail attachments AND a Drive file version
    //    -> MUST extract strictly ONCE across both storage planes!
    let shared_docx = make_docx(&format!("CrossPlaneDedupToken_{tag}"));
    let shared_sha = sha256_hex(&shared_docx);
    reader.insert(&shared_sha, shared_docx.clone());

    let (m1, ts1) = seed_message(&owner, mailbox_id, folder_id, "M1", "body1", None).await;
    let (m2, ts2) = seed_message(&owner, mailbox_id, folder_id, "M2", "body2", None).await;
    let a1 = seed_blob_and_attachment(
        &owner,
        m1,
        ts1,
        &shared_sha,
        shared_docx.len() as i64,
        "shared.docx",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    )
    .await;
    let a2 = seed_blob_and_attachment(
        &owner,
        m2,
        ts2,
        &shared_sha,
        shared_docx.len() as i64,
        "shared_copy.docx",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    )
    .await;

    let sp_row = owner
        .query_one(
            "INSERT INTO public.drive_spaces (name, classification, owner_user_id) \
             VALUES ($1, 'regular', $2) RETURNING id",
            &[&format!("sp_ac1_{tag}"), &user_id],
        )
        .await
        .expect("insert drive_space");
    let space_id: i64 = sp_row.try_get(0).expect("space_id");
    let (_n1, v1, drive_sha) = seed_drive_file_with_chunk(
        &owner,
        user_id,
        space_id,
        "shared_in_drive.docx",
        &shared_docx,
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        &reader,
    )
    .await;
    assert_eq!(shared_sha, drive_sha);

    let req_mail_1 = SearchExtractPayload {
        content_sha256: shared_sha.clone(),
        storage_plane: ExtractionStoragePlane::Blob,
        object_key: None,
        drive_version_id: None,
        content_type: Some(
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document".into(),
        ),
        filename: Some("shared.docx".into()),
    };
    let req_mail_2 = SearchExtractPayload {
        filename: Some("shared_copy.docx".into()),
        ..req_mail_1.clone()
    };
    let req_drive = SearchExtractPayload {
        content_sha256: shared_sha.clone(),
        storage_plane: ExtractionStoragePlane::DriveFileVersion,
        object_key: None,
        drive_version_id: Some(v1),
        content_type: Some(
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document".into(),
        ),
        filename: Some("shared_in_drive.docx".into()),
    };

    let out1 = svc.extract_and_cache(&req_mail_1).await.expect("mail 1");
    let out2 = svc.extract_and_cache(&req_mail_2).await.expect("mail 2");
    let out_drive = svc.extract_and_cache(&req_drive).await.expect("drive");
    assert!(!out1.cache_hit);
    assert!(out2.cache_hit);
    assert!(
        out_drive.cache_hit,
        "Drive version sharing Mail attachment SHA-256 must hit cross-plane cache"
    );
    assert_eq!(out1.result.status, ExtractionStatus::Extracted);
    assert_eq!(out_drive.result.status, ExtractionStatus::Extracted);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "identical Mail + Drive content must extract strictly once"
    );

    // Delete BOTH Mail attachments and age the cache row, then run GC sweep:
    // the cache row (even though inserted with storage_plane='blob') MUST SURVIVE
    // because drive_file_versions still references shared_sha!
    owner
        .execute(
            "DELETE FROM public.message_attachments WHERE id IN ($1, $2)",
            &[&a1, &a2],
        )
        .await
        .expect("delete mail attachments");
    worker
        .execute(
            "UPDATE public.search_extracted_text \
                SET extracted_at = now() - interval '48 hours' \
              WHERE content_sha256 = $1",
            &[&shared_sha],
        )
        .await
        .expect("age cache row");

    let _swept: i32 = worker
        .query_one(
            "SELECT public.search_extracted_text_gc_sweep(1440, 500)",
            &[],
        )
        .await
        .expect("gc sweep")
        .try_get(0)
        .expect("swept");
    let surviving: i64 = worker
        .query_one(
            "SELECT count(*) FROM public.search_extracted_text WHERE content_sha256 = $1",
            &[&shared_sha],
        )
        .await
        .expect("count")
        .try_get(0)
        .expect("c");
    assert_eq!(
        surviving, 1,
        "cross-plane GC sweep must retain cache row while Drive still references SHA-256"
    );
}

#[tokio::test]
async fn ac2_encrypted_unsupported_oversized_and_corrupt_index_filenames_without_aborting_batch() {
    let _guard = DB_TEST_LOCK.lock().await;
    let dsn = match resolve_db_gate(|k| std::env::var(k).ok()) {
        DbGate::Run { dsn, .. } => dsn,
        DbGate::Skip => {
            eprintln!("SETJOIN-SEARCH-557-SKIP (reason=no-dsn)");
            return;
        }
        DbGate::Missing => panic!("REQUIRE_DB=1 set but TEST_DB_DSN/DB_DSN is absent"),
    };
    let owner = connect_as(&dsn).await;
    let worker = Arc::new(connect_as(&swap_dsn_user(&dsn, "setjoin_worker")).await);
    reset_outbox_and_watermarks(worker.as_ref()).await;

    let reader = Arc::new(InMemoryObjectReader::default());
    let dir = TempDir::new().expect("tempdir");
    let engine = Arc::new(TantivySearchEngine::open_or_degraded(SearchConfig {
        tier2_enabled: true,
        index_dir: dir.path().to_path_buf(),
        ..SearchConfig::default()
    }));
    let extract_svc = Arc::new(ContentExtractionService::new(
        worker.clone(),
        reader.clone(),
    ));
    let pipeline = SearchIndexPipeline::new(worker.clone(), engine.clone())
        .with_extraction_service(extract_svc);

    let tag = next_tag();
    let (_uid, mailbox_id, folder_id) = seed_user_and_mailbox(&owner, &format!("ac2_{tag}")).await;
    let (msg_id, ts) = seed_message(
        &owner,
        mailbox_id,
        folder_id,
        "AC2 Batch Subject",
        "hello",
        None,
    )
    .await;

    // 1. Encrypted ZIP
    let mut enc_zip = b"PK\x03\x04\x14\x00\x01\x00".to_vec();
    enc_zip.extend_from_slice(&format!("enc-{tag}").into_bytes());
    let sha_enc = sha256_hex(&enc_zip);
    reader.insert(&sha_enc, enc_zip.clone());
    seed_blob_and_attachment(
        &owner,
        msg_id,
        ts,
        &sha_enc,
        enc_zip.len() as i64,
        &format!("secret_alpha_{tag}.docx"),
        "application/zip",
    )
    .await;

    // 2. Unsupported PNG binary
    let mut png = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
    png.extend_from_slice(&format!("png-{tag}").into_bytes());
    let sha_png = sha256_hex(&png);
    reader.insert(&sha_png, png.clone());
    seed_blob_and_attachment(
        &owner,
        msg_id,
        ts,
        &sha_png,
        png.len() as i64,
        &format!("diagram_bravo_{tag}.png"),
        "image/png",
    )
    .await;

    // 3. Oversized > 20 MiB declared blob
    let sha_big = sha256_hex(format!("oversized-{tag}").as_bytes());
    reader.insert(&sha_big, b"placeholder".to_vec());
    seed_blob_and_attachment(
        &owner,
        msg_id,
        ts,
        &sha_big,
        25 * 1024 * 1024,
        &format!("huge_charlie_{tag}.txt"),
        "text/plain",
    )
    .await;

    // 4. Corrupt DOCX
    let bad_docx = format!("not-a-valid-zip-{tag}").into_bytes();
    let sha_bad = sha256_hex(&bad_docx);
    reader.insert(&sha_bad, bad_docx.clone());
    seed_blob_and_attachment(
        &owner,
        msg_id,
        ts,
        &sha_bad,
        bad_docx.len() as i64,
        &format!("broken_delta_{tag}.docx"),
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    )
    .await;

    // 5. Valid DOCX in the same batch
    let valid_docx = make_docx(&format!("QuarterlyAuditToken_{tag}"));
    let sha_ok = sha256_hex(&valid_docx);
    reader.insert(&sha_ok, valid_docx.clone());
    seed_blob_and_attachment(
        &owner,
        msg_id,
        ts,
        &sha_ok,
        valid_docx.len() as i64,
        &format!("valid_echo_{tag}.docx"),
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    )
    .await;

    enqueue_outbox(
        worker.as_ref(),
        DocCorpus::Mail,
        "upsert",
        mailbox_id,
        msg_id,
        0,
        Some(ts),
        None,
    )
    .await
    .expect("enqueue mail");

    let summary = pipeline
        .run_batch(&SearchIndexBatchPayload {
            corpus: Some(DocCorpus::Mail),
            batch_limit: Some(50),
        })
        .await
        .expect("batch must not fail on encrypted/unsupported/oversized/corrupt");
    assert!(summary.upserted_docs >= 6);

    for (sha, expected_status) in [
        (&sha_enc, "encrypted"),
        (&sha_png, "unsupported"),
        (&sha_big, "truncated_limit"),
        (&sha_bad, "failed"),
        (&sha_ok, "extracted"),
    ] {
        let row = worker
            .query_one(
                "SELECT extraction_status, extracted_text FROM public.search_extracted_text WHERE content_sha256 = $1",
                &[sha],
            )
            .await
            .expect("status row");
        let st: String = row.try_get(0).expect("status");
        let txt: Option<String> = row.try_get(1).expect("text");
        assert_eq!(st, expected_status, "sha={sha}");
        if expected_status != "extracted" {
            assert!(
                txt.is_none(),
                "non-extracted status {expected_status} must store NULL text"
            );
        }
    }

    for fname in [
        format!("secret_alpha_{tag}.docx"),
        format!("diagram_bravo_{tag}.png"),
        format!("huge_charlie_{tag}.txt"),
        format!("broken_delta_{tag}.docx"),
        format!("valid_echo_{tag}.docx"),
    ] {
        let batch = engine
            .candidates(&CandidateQuery {
                corpus: DocCorpus::MailAttachment,
                scope_hint: ScopeHint::Mailbox(mailbox_id),
                terms: NormalizedQuery::parse(&fname).expect("valid query"),
                visibility: SearchVisibility::Live,
                limit: 10,
                continuation: None,
                metadata_only: false,
                calculate_total: false,
            })
            .await
            .expect("search filename");
        assert!(!batch.keys.is_empty(), "filename {fname} must be indexed");
    }

    let ok_hits = engine
        .candidates(&CandidateQuery {
            corpus: DocCorpus::MailAttachment,
            scope_hint: ScopeHint::Mailbox(mailbox_id),
            terms: NormalizedQuery::parse(&format!("QuarterlyAuditToken_{tag}")).expect("query"),
            visibility: SearchVisibility::Live,
            limit: 10,
            continuation: None,
            metadata_only: false,
            calculate_total: false,
        })
        .await
        .expect("search valid docx content");
    assert_eq!(ok_hits.keys.len(), 1);
}

#[tokio::test]
async fn ac3_full_domain_mail_chat_revisions_scheduled_and_drive_monotonic_watermark() {
    let _guard = DB_TEST_LOCK.lock().await;
    let dsn = match resolve_db_gate(|k| std::env::var(k).ok()) {
        DbGate::Run { dsn, .. } => dsn,
        DbGate::Skip => {
            eprintln!("SETJOIN-SEARCH-557-SKIP (reason=no-dsn)");
            return;
        }
        DbGate::Missing => panic!("REQUIRE_DB=1 set but TEST_DB_DSN/DB_DSN is absent"),
    };
    let owner = connect_as(&dsn).await;
    let worker = Arc::new(connect_as(&swap_dsn_user(&dsn, "setjoin_worker")).await);
    reset_outbox_and_watermarks(worker.as_ref()).await;

    let reader = Arc::new(InMemoryObjectReader::default());
    let dir = TempDir::new().expect("tempdir");
    let engine = Arc::new(TantivySearchEngine::open_or_degraded(SearchConfig {
        tier2_enabled: true,
        index_dir: dir.path().to_path_buf(),
        ..SearchConfig::default()
    }));
    let extract_svc = Arc::new(ContentExtractionService::new(
        worker.clone(),
        reader.clone(),
    ));
    let pipeline = SearchIndexPipeline::new(worker.clone(), engine.clone())
        .with_extraction_service(extract_svc);

    let tag = next_tag();
    let (user_id, mailbox_id, folder_id) =
        seed_user_and_mailbox(&owner, &format!("ac3_{tag}")).await;

    // 1. Mail: cleartext + S/MIME sealed message (V029 C7 boundary) + scheduled Mail draft.
    let (m_plain, ts_plain) = seed_message(
        &owner,
        mailbox_id,
        folder_id,
        &format!("ClearSubject_{tag}"),
        &format!("ClearMailBodyToken_{tag}"),
        None,
    )
    .await;
    let (m_sealed, ts_sealed) = seed_message(
        &owner,
        mailbox_id,
        folder_id,
        &format!("SealedSubject_{tag}"),
        &format!("SealedSecretLeakToken_{tag}"),
        Some("smime-encrypted"),
    )
    .await;
    let (m_sched_draft, ts_sched_draft) = seed_message(
        &owner,
        mailbox_id,
        folder_id,
        &format!("ScheduledDraftSubject_{tag}"),
        &format!("ScheduledDraftBodyToken_{tag}"),
        None,
    )
    .await;

    // 2. Drive space + file version (also attached to Chat).
    let sp_row = owner
        .query_one(
            "INSERT INTO public.drive_spaces (name, classification, owner_user_id) \
             VALUES ($1, 'regular', $2) RETURNING id",
            &[&format!("sp_ac3_{tag}"), &user_id],
        )
        .await
        .expect("insert drive_space");
    let space_id: i64 = sp_row.try_get(0).expect("space_id");
    let drive_docx = make_docx(&format!("DriveVersionDeepContent_{tag}"));
    let (drive_node_id, drive_ver_id, _drive_sha) = seed_drive_file_with_chunk(
        &owner,
        user_id,
        space_id,
        &format!("roadmap_{tag}.docx"),
        &drive_docx,
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        &reader,
    )
    .await;

    // 3. Chat: channel + message + historical revision + attachment.
    let ch_row = owner
        .query_one(
            "INSERT INTO public.chat_channels (kind, visibility, name, created_by) \
             VALUES ('channel', 'private', $1, $2) RETURNING id",
            &[&format!("ch_ac3_{tag}"), &user_id],
        )
        .await
        .expect("insert chat_channel");
    let channel_id: i64 = ch_row.try_get(0).expect("channel_id");
    let cm_row = owner
        .query_one(
            "INSERT INTO public.chat_messages (channel_id, seq, author_id, body) \
             VALUES ($1, 1, $2, $3) RETURNING id",
            &[&channel_id, &user_id, &format!("ChatCurrentBody_{tag}")],
        )
        .await
        .expect("insert chat_message");
    let chat_msg_id: i64 = cm_row.try_get(0).expect("chat_msg_id");
    owner
        .execute(
            "INSERT INTO public.chat_message_revisions (channel_id, message_id, prior_body, edited_by) \
             VALUES ($1, $2, $3, $4)",
            &[
                &channel_id,
                &chat_msg_id,
                &format!("ChatHistoricalRevision_{tag}"),
                &user_id,
            ],
        )
        .await
        .expect("insert chat_message_revisions");
    owner
        .execute(
            "INSERT INTO public.chat_message_attachments \
               (channel_id, message_id, file_node_id, version_id, filename, content_type, size_bytes) \
             VALUES ($1, $2, $3, $4, $5, 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', $6)",
            &[
                &channel_id,
                &chat_msg_id,
                &drive_node_id,
                &drive_ver_id,
                &format!("chat_attach_{tag}.docx"),
                &(drive_docx.len() as i64),
            ],
        )
        .await
        .expect("insert chat_message_attachments");

    // 4. Scheduled Chat (camelCase "channelId", status='enqueued') + Scheduled Mail ('send', status='pending').
    let sched_chat_payload = format!(
        r#"{{"userId": {user_id}, "channelId": {channel_id}, "body": "PendingScheduledCompliance_{tag}"}}"#
    );
    let sched_chat_uuid: String = owner
        .query_one(
            "INSERT INTO public.scheduled_actions (action_kind, fire_at, payload, status, mailbox_id) \
             VALUES ('chat_send', now() + interval '1 hour', $1::text::jsonb, 'enqueued', $2) \
             RETURNING id::text",
            &[&sched_chat_payload, &mailbox_id],
        )
        .await
        .expect("insert scheduled chat")
        .try_get(0)
        .expect("uuid");

    let sched_mail_payload = format!(
        r#"{{"message_id": {m_sched_draft}, "received_at": "{}"}}"#,
        ts_sched_draft.to_rfc3339()
    );
    let sched_mail_uuid: String = owner
        .query_one(
            "INSERT INTO public.scheduled_actions (action_kind, fire_at, payload, status, mailbox_id) \
             VALUES ('send', now() + interval '1 hour', $1::text::jsonb, 'pending', $2) \
             RETURNING id::text",
            &[&sched_mail_payload, &mailbox_id],
        )
        .await
        .expect("insert scheduled mail")
        .try_get(0)
        .expect("uuid");

    // Enqueue outbox events for Mail, Chat, Drive.
    let seq_mail_1 = enqueue_outbox(
        worker.as_ref(),
        DocCorpus::Mail,
        "upsert",
        mailbox_id,
        m_plain,
        0,
        Some(ts_plain),
        None,
    )
    .await
    .expect("enqueue mail 1");
    let seq_mail_2 = enqueue_outbox(
        worker.as_ref(),
        DocCorpus::Mail,
        "upsert",
        mailbox_id,
        m_sealed,
        0,
        Some(ts_sealed),
        None,
    )
    .await
    .expect("enqueue mail 2");
    let seq_chat = enqueue_outbox(
        worker.as_ref(),
        DocCorpus::Chat,
        "upsert",
        channel_id,
        chat_msg_id,
        0,
        None,
        None,
    )
    .await
    .expect("enqueue chat");
    let seq_drive = enqueue_outbox(
        worker.as_ref(),
        DocCorpus::Drive,
        "upsert",
        space_id,
        drive_node_id,
        0,
        None,
        None,
    )
    .await
    .expect("enqueue drive");

    let summary = pipeline
        .run_batch(&SearchIndexBatchPayload::default())
        .await
        .expect("full-domain batch");
    assert!(summary.outbox_rows_processed >= 4);
    assert!(summary.scheduled_actions_indexed >= 2);

    // Mail assertions (including S/MIME boundary).
    let plain_hits = engine
        .candidates(&CandidateQuery {
            corpus: DocCorpus::Mail,
            scope_hint: ScopeHint::Mailbox(mailbox_id),
            terms: NormalizedQuery::parse(&format!("ClearMailBodyToken_{tag}")).expect("q"),
            visibility: SearchVisibility::Live,
            limit: 10,
            continuation: None,
            metadata_only: false,
            calculate_total: false,
        })
        .await
        .expect("plain mail search");
    assert_eq!(plain_hits.keys.len(), 1);

    let sealed_subject_hits = engine
        .candidates(&CandidateQuery {
            corpus: DocCorpus::Mail,
            scope_hint: ScopeHint::Mailbox(mailbox_id),
            terms: NormalizedQuery::parse(&format!("SealedSubject_{tag}")).expect("q"),
            visibility: SearchVisibility::Live,
            limit: 10,
            continuation: None,
            metadata_only: false,
            calculate_total: false,
        })
        .await
        .expect("sealed subject search");
    assert_eq!(sealed_subject_hits.keys.len(), 1);

    let sealed_leak_hits = engine
        .candidates(&CandidateQuery {
            corpus: DocCorpus::Mail,
            scope_hint: ScopeHint::Mailbox(mailbox_id),
            terms: NormalizedQuery::parse(&format!("SealedSecretLeakToken_{tag}")).expect("q"),
            visibility: SearchVisibility::Live,
            limit: 10,
            continuation: None,
            metadata_only: false,
            calculate_total: false,
        })
        .await
        .expect("sealed body must not leak");
    assert!(
        sealed_leak_hits.keys.is_empty(),
        "S/MIME body MUST never be indexed"
    );

    // Chat Live assertions: current body + attachment filename & extracted content.
    for term in [
        format!("ChatCurrentBody_{tag}"),
        format!("chat_attach_{tag}.docx"),
        format!("DriveVersionDeepContent_{tag}"),
    ] {
        let hits = engine
            .candidates(&CandidateQuery {
                corpus: DocCorpus::Chat,
                scope_hint: ScopeHint::Channels(vec![channel_id]),
                terms: NormalizedQuery::parse(&term).expect("q"),
                visibility: SearchVisibility::Live,
                limit: 10,
                continuation: None,
                metadata_only: false,
                calculate_total: false,
            })
            .await
            .expect("chat live search");
        assert_eq!(
            hits.keys,
            vec![DocumentKey::Chat {
                channel_id,
                id: chat_msg_id
            }],
            "term={term}"
        );
    }

    // Chat historical revision MUST be strictly ComplianceOnly (0 hits on Live, 1 hit on ComplianceOnly)!
    let rev_live = engine
        .candidates(&CandidateQuery {
            corpus: DocCorpus::Chat,
            scope_hint: ScopeHint::Channels(vec![channel_id]),
            terms: NormalizedQuery::parse(&format!("ChatHistoricalRevision_{tag}")).expect("q"),
            visibility: SearchVisibility::Live,
            limit: 10,
            continuation: None,
            metadata_only: false,
            calculate_total: false,
        })
        .await
        .expect("chat rev live");
    assert!(
        rev_live.keys.is_empty(),
        "edited-away chat_message_revisions MUST NOT appear in Live search"
    );
    let rev_comp = engine
        .candidates(&CandidateQuery {
            corpus: DocCorpus::Chat,
            scope_hint: ScopeHint::GlobalCompliance,
            terms: NormalizedQuery::parse(&format!("ChatHistoricalRevision_{tag}")).expect("q"),
            visibility: SearchVisibility::ComplianceOnly,
            limit: 10,
            continuation: None,
            metadata_only: false,
            calculate_total: false,
        })
        .await
        .expect("chat rev compliance");
    assert_eq!(
        rev_comp.keys,
        vec![DocumentKey::Chat {
            channel_id,
            id: chat_revision_doc_id(chat_msg_id)
        }]
    );

    // Scheduled Chat (camelCase "channelId"): invisible to Live, visible to ComplianceOnly!
    let sched_live = engine
        .candidates(&CandidateQuery {
            corpus: DocCorpus::Chat,
            scope_hint: ScopeHint::GlobalCompliance,
            terms: NormalizedQuery::parse(&format!("PendingScheduledCompliance_{tag}")).expect("q"),
            visibility: SearchVisibility::Live,
            limit: 10,
            continuation: None,
            metadata_only: false,
            calculate_total: false,
        })
        .await
        .expect("scheduled live");
    assert!(
        sched_live.keys.is_empty(),
        "scheduled_action must be ComplianceOnly"
    );

    let sched_comp = engine
        .candidates(&CandidateQuery {
            corpus: DocCorpus::Chat,
            scope_hint: ScopeHint::GlobalCompliance,
            terms: NormalizedQuery::parse(&format!("PendingScheduledCompliance_{tag}")).expect("q"),
            visibility: SearchVisibility::ComplianceOnly,
            limit: 10,
            continuation: None,
            metadata_only: false,
            calculate_total: false,
        })
        .await
        .expect("scheduled compliance");
    assert_eq!(
        sched_comp.keys,
        vec![DocumentKey::Chat {
            channel_id,
            id: scheduled_action_doc_id(&sched_chat_uuid)
        }]
    );

    // Scheduled Mail ('send'): hydrates referenced draft subject & body under ComplianceOnly!
    let sched_mail_comp = engine
        .candidates(&CandidateQuery {
            corpus: DocCorpus::Mail,
            scope_hint: ScopeHint::GlobalCompliance,
            terms: NormalizedQuery::parse(&format!("ScheduledDraftBodyToken_{tag}")).expect("q"),
            visibility: SearchVisibility::ComplianceOnly,
            limit: 10,
            continuation: None,
            metadata_only: false,
            calculate_total: false,
        })
        .await
        .expect("scheduled mail compliance");
    assert_eq!(sched_mail_comp.keys.len(), 1);
    assert!(matches!(
        sched_mail_comp.keys[0],
        DocumentKey::Mail { id, .. } if id == scheduled_action_doc_id(&sched_mail_uuid)
    ));

    // Drive assertions: node name + extracted version body.
    for term in [
        format!("roadmap_{tag}.docx"),
        format!("DriveVersionDeepContent_{tag}"),
    ] {
        let hits = engine
            .candidates(&CandidateQuery {
                corpus: DocCorpus::Drive,
                scope_hint: ScopeHint::Spaces(vec![space_id]),
                terms: NormalizedQuery::parse(&term).expect("q"),
                visibility: SearchVisibility::Live,
                limit: 10,
                continuation: None,
                metadata_only: false,
                calculate_total: false,
            })
            .await
            .expect("drive search");
        assert_eq!(
            hits.keys,
            vec![DocumentKey::Drive {
                space_id,
                id: drive_node_id
            }],
            "term={term}"
        );
    }

    // Cancel scheduled Chat via DELETE (with watermarks seeded so V291 trigger emits outbox delete!)
    // and verify next batch evicts the ComplianceOnly document from Tantivy!
    owner
        .execute(
            "DELETE FROM public.scheduled_actions WHERE id = $1::text::uuid",
            &[&sched_chat_uuid],
        )
        .await
        .expect("cancel scheduled chat");
    let _evict_summary = pipeline
        .run_batch(&SearchIndexBatchPayload {
            corpus: Some(DocCorpus::Chat),
            batch_limit: Some(50),
        })
        .await
        .expect("eviction batch");
    let after_cancel = engine
        .candidates(&CandidateQuery {
            corpus: DocCorpus::Chat,
            scope_hint: ScopeHint::GlobalCompliance,
            terms: NormalizedQuery::parse(&format!("PendingScheduledCompliance_{tag}")).expect("q"),
            visibility: SearchVisibility::ComplianceOnly,
            limit: 10,
            continuation: None,
            metadata_only: false,
            calculate_total: false,
        })
        .await
        .expect("after cancel");
    assert!(
        after_cancel.keys.is_empty(),
        "canceled scheduled_action must be evicted from Tantivy"
    );

    // Monotonic watermark verification: indexed_outbox_seq advanced and never regresses.
    assert!(
        summary
            .watermarks
            .get(&DocCorpus::Mail)
            .copied()
            .unwrap_or(0)
            >= seq_mail_2.max(seq_mail_1)
    );
    assert!(
        summary
            .watermarks
            .get(&DocCorpus::Chat)
            .copied()
            .unwrap_or(0)
            >= seq_chat
    );
    assert!(
        summary
            .watermarks
            .get(&DocCorpus::Drive)
            .copied()
            .unwrap_or(0)
            >= seq_drive
    );

    let regressed: i64 = worker
        .query_one(
            "SELECT indexed_outbox_seq FROM public.search_watermark_advance('mail', 1, 1, 1, 'hash')",
            &[],
        )
        .await
        .expect("advance lower seq")
        .try_get(0)
        .expect("seq");
    assert!(
        regressed >= seq_mail_2,
        "indexed_outbox_seq must be strictly monotonic"
    );

    let _ = owner
        .execute(
            "DELETE FROM public.scheduled_actions WHERE id = $1::text::uuid",
            &[&sched_mail_uuid],
        )
        .await;
}

#[tokio::test]
async fn ac4_search_extracted_text_gc_sweep_reclaims_orphans_and_preserves_live_and_admin_trash() {
    let _guard = DB_TEST_LOCK.lock().await;
    let dsn = match resolve_db_gate(|k| std::env::var(k).ok()) {
        DbGate::Run { dsn, .. } => dsn,
        DbGate::Skip => {
            eprintln!("SETJOIN-SEARCH-557-SKIP (reason=no-dsn)");
            return;
        }
        DbGate::Missing => panic!("REQUIRE_DB=1 set but TEST_DB_DSN/DB_DSN is absent"),
    };
    let owner = connect_as(&dsn).await;
    let worker = connect_as(&swap_dsn_user(&dsn, "setjoin_worker")).await;
    let app = connect_as(&swap_dsn_user(&dsn, "setjoin_app")).await;
    let reader = InMemoryObjectReader::default();

    let tag = next_tag();
    let (user_id, mailbox_id, folder_id) =
        seed_user_and_mailbox(&owner, &format!("ac4_{tag}")).await;
    let (msg_id, ts) = seed_message(&owner, mailbox_id, folder_id, "GC Live", "body", None).await;

    // 1. Live blob cache row -> SURVIVES.
    let live_blob_sha = sha256_hex(format!("live-blob-{tag}").as_bytes());
    seed_blob_and_attachment(
        &owner,
        msg_id,
        ts,
        &live_blob_sha,
        64,
        "live.txt",
        "text/plain",
    )
    .await;

    // 2. Orphaned blob cache row -> RECLAIMED.
    let orphan_blob_sha = sha256_hex(format!("orphan-blob-{tag}").as_bytes());

    // 3. Drive admin-trash (purged_at IS NOT NULL while drive_file_versions exists) -> SURVIVES until hard delete!
    let sp_row = owner
        .query_one(
            "INSERT INTO public.drive_spaces (name, classification, owner_user_id) \
             VALUES ($1, 'regular', $2) RETURNING id",
            &[&format!("sp_ac4_{tag}"), &user_id],
        )
        .await
        .expect("insert drive_space");
    let space_id: i64 = sp_row.try_get(0).expect("space_id");
    let (trash_node, trash_ver, trash_drive_sha) = seed_drive_file_with_chunk(
        &owner,
        user_id,
        space_id,
        "admin_trash_drive.txt",
        format!("admin-trash-drive-{tag}").as_bytes(),
        "text/plain",
        &reader,
    )
    .await;
    owner
        .execute(
            "UPDATE public.drive_nodes SET deleted_at = now() - interval '1 day', purged_at = now() WHERE id = $1",
            &[&trash_node],
        )
        .await
        .expect("mark admin trash");

    // 4. Orphaned Drive cache row -> RECLAIMED.
    let orphan_drive_sha = sha256_hex(format!("orphan-drive-{tag}").as_bytes());

    for (sha, plane) in [
        (&live_blob_sha, "blob"),
        (&orphan_blob_sha, "blob"),
        (&trash_drive_sha, "drive_file_version"),
        (&orphan_drive_sha, "drive_file_version"),
    ] {
        worker
            .execute(
                "INSERT INTO public.search_extracted_text \
                   (content_sha256, storage_plane, extraction_status, extracted_text, extracted_bytes, extracted_at) \
                 VALUES ($1, $2, 'extracted', 'cached text', 11, now() - interval '48 hours') \
                 ON CONFLICT (content_sha256) DO NOTHING",
                &[sha, &plane],
            )
            .await
            .expect("seed cache row");
    }

    let swept: i32 = worker
        .query_one(
            "SELECT public.search_extracted_text_gc_sweep(1440, 500)",
            &[],
        )
        .await
        .expect("gc sweep")
        .try_get(0)
        .expect("swept count");
    assert!(swept >= 2);

    for (sha, should_exist) in [
        (&live_blob_sha, true),
        (&orphan_blob_sha, false),
        (&trash_drive_sha, true),
        (&orphan_drive_sha, false),
    ] {
        let count: i64 = worker
            .query_one(
                "SELECT count(*) FROM public.search_extracted_text WHERE content_sha256 = $1",
                &[sha],
            )
            .await
            .expect("count")
            .try_get(0)
            .expect("c");
        assert_eq!(count == 1, should_exist, "sha={sha}");
    }

    // Hard-delete drive_file_versions (after 30-day admin trash expiry) -> now GC sweep reclaims it!
    owner
        .execute(
            "UPDATE public.drive_files SET head_version_id = NULL WHERE node_id = $1",
            &[&trash_node],
        )
        .await
        .expect("clear head_version_id");
    owner
        .execute(
            "DELETE FROM public.drive_file_versions WHERE id = $1",
            &[&trash_ver],
        )
        .await
        .expect("hard delete drive version");
    let swept_after_hard_delete: i32 = worker
        .query_one(
            "SELECT public.search_extracted_text_gc_sweep(1440, 500)",
            &[],
        )
        .await
        .expect("gc sweep 2")
        .try_get(0)
        .expect("swept2");
    assert!(swept_after_hard_delete >= 1);
    let trash_remaining: i64 = worker
        .query_one(
            "SELECT count(*) FROM public.search_extracted_text WHERE content_sha256 = $1",
            &[&trash_drive_sha],
        )
        .await
        .expect("count trash")
        .try_get(0)
        .expect("c");
    assert_eq!(trash_remaining, 0);

    // setjoin_app MUST be denied direct SELECT on search_extracted_text and search_index_outbox (42501).
    let err_cache = app
        .query("SELECT count(*) FROM public.search_extracted_text", &[])
        .await
        .expect_err("setjoin_app denied search_extracted_text");
    assert_eq!(err_cache.code().map(|c| c.code()), Some("42501"));

    let err_outbox = app
        .query("SELECT count(*) FROM public.search_index_outbox", &[])
        .await
        .expect_err("setjoin_app denied search_index_outbox");
    assert_eq!(err_outbox.code().map(|c| c.code()), Some("42501"));
}

#[tokio::test]
async fn per_key_chronological_upsert_then_delete_and_empty_index_delete_only_batch() {
    let _guard = DB_TEST_LOCK.lock().await;
    let dsn = match resolve_db_gate(|k| std::env::var(k).ok()) {
        DbGate::Run { dsn, .. } => dsn,
        DbGate::Skip => return,
        DbGate::Missing => panic!("REQUIRE_DB=1 set but TEST_DB_DSN/DB_DSN is absent"),
    };
    let owner = connect_as(&dsn).await;
    let worker = Arc::new(connect_as(&swap_dsn_user(&dsn, "setjoin_worker")).await);
    reset_outbox_and_watermarks(worker.as_ref()).await;

    let tag = next_tag();
    let (_uid, mailbox_id, folder_id) =
        seed_user_and_mailbox(&owner, &format!("order_{tag}")).await;
    let (msg_id, ts) = seed_message(
        &owner,
        mailbox_id,
        folder_id,
        &format!("UpsertThenDelete_{tag}"),
        "ephemeral",
        None,
    )
    .await;

    // 1. Delete-only batch on a fresh uninitialized TantivySearchEngine must succeed cleanly!
    let dir_empty = TempDir::new().expect("tempdir");
    let empty_engine = Arc::new(TantivySearchEngine::open_or_degraded(SearchConfig {
        tier2_enabled: true,
        index_dir: dir_empty.path().to_path_buf(),
        ..SearchConfig::default()
    }));
    let empty_pipeline = SearchIndexPipeline::new(worker.clone(), empty_engine.clone());

    let del_seq = enqueue_outbox(
        worker.as_ref(),
        DocCorpus::Mail,
        "delete",
        mailbox_id,
        msg_id,
        0,
        Some(ts),
        None,
    )
    .await
    .expect("enqueue delete");
    let del_summary = empty_pipeline
        .run_batch(&SearchIndexBatchPayload {
            corpus: Some(DocCorpus::Mail),
            batch_limit: Some(10),
        })
        .await
        .expect("delete-only batch on fresh uninitialized index must succeed");
    assert_eq!(del_summary.outbox_rows_processed, 1);
    assert_eq!(
        del_summary.watermarks.get(&DocCorpus::Mail).copied(),
        Some(del_seq)
    );

    // 2. Same-batch chronological upsert(K) followed by delete(K) MUST leave K absent!
    let dir = TempDir::new().expect("tempdir");
    let engine = Arc::new(TantivySearchEngine::open_or_degraded(SearchConfig {
        tier2_enabled: true,
        index_dir: dir.path().to_path_buf(),
        ..SearchConfig::default()
    }));
    let pipeline = SearchIndexPipeline::new(worker.clone(), engine.clone());

    // First index one anchor message so the index has a live epoch.
    let (anchor_id, anchor_ts) = seed_message(
        &owner,
        mailbox_id,
        folder_id,
        &format!("AnchorMsg_{tag}"),
        "stay",
        None,
    )
    .await;
    enqueue_outbox(
        worker.as_ref(),
        DocCorpus::Mail,
        "upsert",
        mailbox_id,
        anchor_id,
        0,
        Some(anchor_ts),
        None,
    )
    .await
    .expect("anchor");
    // Now enqueue upsert(msg_id) THEN delete(msg_id) in the SAME batch!
    enqueue_outbox(
        worker.as_ref(),
        DocCorpus::Mail,
        "upsert",
        mailbox_id,
        msg_id,
        0,
        Some(ts),
        None,
    )
    .await
    .expect("upsert");
    enqueue_outbox(
        worker.as_ref(),
        DocCorpus::Mail,
        "delete",
        mailbox_id,
        msg_id,
        0,
        Some(ts),
        None,
    )
    .await
    .expect("delete");

    let batch_summary = pipeline
        .run_batch(&SearchIndexBatchPayload {
            corpus: Some(DocCorpus::Mail),
            batch_limit: Some(50),
        })
        .await
        .expect("batch");
    assert!(batch_summary.outbox_rows_processed >= 3);
    assert_eq!(batch_summary.upserted_docs, 1);

    let hits = engine
        .candidates(&CandidateQuery {
            corpus: DocCorpus::Mail,
            scope_hint: ScopeHint::Mailbox(mailbox_id),
            terms: NormalizedQuery::parse(&format!("UpsertThenDelete_{tag}")).expect("q"),
            visibility: SearchVisibility::Live,
            limit: 10,
            continuation: None,
            metadata_only: false,
            calculate_total: false,
        })
        .await
        .expect("search");
    assert!(
        hits.keys.is_empty(),
        "upsert(K) followed by delete(K) in same batch must leave K deleted"
    );
}

#[tokio::test]
async fn batch_chunking_exceeding_16mb_inflight_cap_succeeds() {
    let _guard = DB_TEST_LOCK.lock().await;
    let dsn = match resolve_db_gate(|k| std::env::var(k).ok()) {
        DbGate::Run { dsn, .. } => dsn,
        DbGate::Skip => return,
        DbGate::Missing => panic!("REQUIRE_DB=1 set but TEST_DB_DSN/DB_DSN is absent"),
    };
    let owner = connect_as(&dsn).await;
    let worker = Arc::new(connect_as(&swap_dsn_user(&dsn, "setjoin_worker")).await);
    reset_outbox_and_watermarks(worker.as_ref()).await;

    let tag = next_tag();
    let (_uid, mailbox_id, folder_id) =
        seed_user_and_mailbox(&owner, &format!("chunk_{tag}")).await;

    // 38 messages x 480 KiB ~= 18.2 MiB (> 16 MiB MAX_INFLIGHT_BYTES).
    let filler = "x ".repeat(240 * 1024);
    for i in 0..38 {
        let body = format!("ChunkBigToken_{tag}_{i} {filler}");
        let (mid, ts) = seed_message(
            &owner,
            mailbox_id,
            folder_id,
            &format!("BigSubject_{tag}_{i}"),
            &body,
            None,
        )
        .await;
        enqueue_outbox(
            worker.as_ref(),
            DocCorpus::Mail,
            "upsert",
            mailbox_id,
            mid,
            0,
            Some(ts),
            None,
        )
        .await
        .expect("enqueue big");
    }

    let dir = TempDir::new().expect("tempdir");
    let engine = Arc::new(TantivySearchEngine::open_or_degraded(SearchConfig {
        tier2_enabled: true,
        index_dir: dir.path().to_path_buf(),
        ..SearchConfig::default()
    }));
    let pipeline = SearchIndexPipeline::new(worker.clone(), engine.clone());

    let summary = pipeline
        .run_batch(&SearchIndexBatchPayload {
            corpus: Some(DocCorpus::Mail),
            batch_limit: Some(100),
        })
        .await
        .expect("batch > 16 MiB must chunk cleanly inside MAX_INFLIGHT_BYTES");
    assert_eq!(summary.upserted_docs, 38);

    let last_hit = engine
        .candidates(&CandidateQuery {
            corpus: DocCorpus::Mail,
            scope_hint: ScopeHint::Mailbox(mailbox_id),
            terms: NormalizedQuery::parse(&format!("ChunkBigToken_{tag}_37")).expect("q"),
            visibility: SearchVisibility::Live,
            limit: 10,
            continuation: None,
            metadata_only: false,
            calculate_total: false,
        })
        .await
        .expect("search last chunk doc");
    assert_eq!(last_hit.keys.len(), 1);
}

#[tokio::test]
async fn drive_spoofed_content_sha256_does_not_leak_or_poison_shared_cache() {
    let _guard = DB_TEST_LOCK.lock().await;
    let dsn = match resolve_db_gate(|k| std::env::var(k).ok()) {
        DbGate::Run { dsn, .. } => dsn,
        DbGate::Skip => return,
        DbGate::Missing => panic!("REQUIRE_DB=1 set but TEST_DB_DSN/DB_DSN is absent"),
    };
    let owner = connect_as(&dsn).await;
    let worker = Arc::new(connect_as(&swap_dsn_user(&dsn, "setjoin_worker")).await);
    let reader = Arc::new(InMemoryObjectReader::default());
    let svc = ContentExtractionService::new(worker.clone(), reader.clone());

    let tag = next_tag();
    let (user_a, _, _) = seed_user_and_mailbox(&owner, &format!("spoof_a_{tag}")).await;
    let (user_b, _, _) = seed_user_and_mailbox(&owner, &format!("spoof_b_{tag}")).await;

    let victim_bytes = format!("VICTIM_CONFIDENTIAL_SECRET_{tag}").into_bytes();
    let victim_sha = sha256_hex(&victim_bytes);
    reader.insert(&victim_sha, victim_bytes.clone());
    owner
        .execute(
            "INSERT INTO public.blobs (sha256, minio_ref, size_bytes, content_type) \
             VALUES ($1, $1, $2, 'text/plain') ON CONFLICT (sha256) DO NOTHING",
            &[&victim_sha, &(victim_bytes.len() as i64)],
        )
        .await
        .expect("victim blob");

    // Victim populates legitimate cache row for victim_sha.
    let victim_out = svc
        .extract_and_cache(&SearchExtractPayload {
            content_sha256: victim_sha.clone(),
            storage_plane: ExtractionStoragePlane::Blob,
            object_key: None,
            drive_version_id: None,
            content_type: Some("text/plain".into()),
            filename: Some("victim.txt".into()),
        })
        .await
        .expect("victim extract");
    assert_eq!(victim_out.result.status, ExtractionStatus::Extracted);

    // Attacker creates a Drive version claiming content_sha256 = victim_sha while
    // storing DIFFERENT actual chunk bytes (attacker_bytes)!
    let sp_row = owner
        .query_one(
            "INSERT INTO public.drive_spaces (name, classification, owner_user_id) \
             VALUES ($1, 'regular', $2) RETURNING id",
            &[&format!("sp_spoof_{tag}"), &user_b],
        )
        .await
        .expect("space");
    let space_id: i64 = sp_row.try_get(0).expect("sid");
    let attacker_bytes = format!("ATTACKER_PAYLOAD_{tag}").into_bytes();
    let attacker_chunk_sha = sha256_hex(&attacker_bytes);
    let attacker_ref = format!("drive/g/{attacker_chunk_sha}");
    reader.insert(&attacker_ref, attacker_bytes.clone());

    let node_id: i64 = owner
        .query_one(
            "INSERT INTO public.drive_nodes (space_id, kind, name, created_by) \
             VALUES ($1, 'file', 'spoof.txt', $2) RETURNING id",
            &[&space_id, &user_b],
        )
        .await
        .expect("node")
        .try_get(0)
        .expect("nid");
    owner
        .execute(
            "INSERT INTO public.drive_files (node_id, space_id, size_bytes, content_type) \
             VALUES ($1, $2, $3, 'text/plain')",
            &[&node_id, &space_id, &(attacker_bytes.len() as i64)],
        )
        .await
        .expect("drive_files");
    let ver_id: i64 = owner
        .query_one(
            "INSERT INTO public.drive_file_versions \
               (file_node_id, space_id, content_sha256, size_bytes, content_type, author_user_id) \
             VALUES ($1, $2, $3, $4, 'text/plain', $5) RETURNING id",
            &[
                &node_id,
                &space_id,
                &victim_sha, // SPOOFED!
                &(attacker_bytes.len() as i64),
                &user_b,
            ],
        )
        .await
        .expect("spoofed version")
        .try_get(0)
        .expect("vid");
    owner
        .execute(
            "INSERT INTO public.drive_chunks (scope_key, sha256, size_bytes, ref_count, storage_ref) \
             VALUES ('g', $1, $2, 1, $3) ON CONFLICT (scope_key, sha256) DO NOTHING",
            &[
                &attacker_chunk_sha,
                &(attacker_bytes.len() as i32),
                &attacker_ref,
            ],
        )
        .await
        .expect("chunk");
    owner
        .execute(
            "INSERT INTO public.drive_version_chunks (version_id, stream, ordinal, scope_key, chunk_sha256) \
             VALUES ($1, 'content', 0, 'g', $2)",
            &[&ver_id, &attacker_chunk_sha],
        )
        .await
        .expect("vchunk");

    let attacker_out = svc
        .extract_and_cache(&SearchExtractPayload {
            content_sha256: victim_sha.clone(),
            storage_plane: ExtractionStoragePlane::DriveFileVersion,
            object_key: None,
            drive_version_id: Some(ver_id),
            content_type: Some("text/plain".into()),
            filename: Some("spoof.txt".into()),
        })
        .await
        .expect("spoofed extract");
    assert!(!attacker_out.cache_hit);
    let attacker_text = attacker_out.result.extracted_text.unwrap_or_default();
    assert!(
        !attacker_text.contains("VICTIM_CONFIDENTIAL_SECRET"),
        "spoofed Drive content_sha256 MUST NOT leak victim cached text"
    );
    assert!(attacker_text.contains(&format!("ATTACKER_PAYLOAD_{tag}")));

    // Victim's shared cache row must remain unpoisoned!
    let cached_victim_text: String = worker
        .query_one(
            "SELECT extracted_text FROM public.search_extracted_text WHERE content_sha256 = $1",
            &[&victim_sha],
        )
        .await
        .expect("victim cache")
        .try_get(0)
        .expect("txt");
    assert!(
        cached_victim_text.contains(&format!("VICTIM_CONFIDENTIAL_SECRET_{tag}")),
        "spoofed Drive upload MUST NOT poison victim's shared cache entry"
    );
    let _ = user_a;
}

#[tokio::test]
async fn production_triggers_capture_writes_into_outbox_and_workqueue_e2e() {
    let _guard = DB_TEST_LOCK.lock().await;
    let dsn = match resolve_db_gate(|k| std::env::var(k).ok()) {
        DbGate::Run { dsn, .. } => dsn,
        DbGate::Skip => return,
        DbGate::Missing => panic!("REQUIRE_DB=1 set but TEST_DB_DSN/DB_DSN is absent"),
    };
    let owner = connect_as(&dsn).await;
    let worker = Arc::new(connect_as(&swap_dsn_user(&dsn, "setjoin_worker")).await);
    reset_outbox_and_watermarks(worker.as_ref()).await;

    // Activate production triggers via the exact startup helper SearchIndexConsumer::run calls!
    ensure_search_watermarks_initialized(worker.as_ref())
        .await
        .expect("seed watermarks");

    let tag = next_tag();
    let (user_id, mailbox_id, folder_id) =
        seed_user_and_mailbox(&owner, &format!("trg_{tag}")).await;

    // Insert directly into production tables WITHOUT manual enqueue_outbox calls!
    let (_msg_id, _ts) = seed_message(
        &owner,
        mailbox_id,
        folder_id,
        &format!("TriggerCapturedMail_{tag}"),
        "trigger body",
        None,
    )
    .await;

    let ch_id: i64 = owner
        .query_one(
            "INSERT INTO public.chat_channels (kind, visibility, name, created_by) \
             VALUES ('channel', 'private', $1, $2) RETURNING id",
            &[&format!("ch_trg_{tag}"), &user_id],
        )
        .await
        .expect("ch")
        .try_get(0)
        .expect("cid");
    owner
        .execute(
            "INSERT INTO public.chat_messages (channel_id, seq, author_id, body) \
             VALUES ($1, 1, $2, $3)",
            &[&ch_id, &user_id, &format!("TriggerCapturedChat_{tag}")],
        )
        .await
        .expect("chat msg");

    let sp_id: i64 = owner
        .query_one(
            "INSERT INTO public.drive_spaces (name, classification, owner_user_id) \
             VALUES ($1, 'regular', $2) RETURNING id",
            &[&format!("sp_trg_{tag}"), &user_id],
        )
        .await
        .expect("sp")
        .try_get(0)
        .expect("sid");
    owner
        .execute(
            "INSERT INTO public.drive_nodes (space_id, kind, name, created_by) \
             VALUES ($1, 'file', $2, $3)",
            &[&sp_id, &format!("TriggerCapturedDrive_{tag}.txt"), &user_id],
        )
        .await
        .expect("drive node");

    // Verify work_items received coalesced search.index_batch items from the triggers!
    let wq_count: i64 = worker
        .query_one(
            "SELECT count(*) FROM public.work_items \
              WHERE kind = 'search.index_batch' \
                AND idempotency_key IN ('search.index_batch:mail', 'search.index_batch:chat', 'search.index_batch:drive')",
            &[],
        )
        .await
        .expect("wq count")
        .try_get(0)
        .expect("c");
    assert!(
        wq_count >= 3,
        "triggers must enqueue search.index_batch work items for mail/chat/drive"
    );

    let dir = TempDir::new().expect("tempdir");
    let engine = Arc::new(TantivySearchEngine::open_or_degraded(SearchConfig {
        tier2_enabled: true,
        index_dir: dir.path().to_path_buf(),
        ..SearchConfig::default()
    }));
    let pipeline = SearchIndexPipeline::new(worker.clone(), engine.clone());
    let summary = pipeline
        .run_batch(&SearchIndexBatchPayload::default())
        .await
        .expect("index triggered outbox");
    assert!(summary.outbox_rows_processed >= 3);

    let mail_hits = engine
        .candidates(&CandidateQuery {
            corpus: DocCorpus::Mail,
            scope_hint: ScopeHint::Mailbox(mailbox_id),
            terms: NormalizedQuery::parse(&format!("TriggerCapturedMail_{tag}")).expect("q"),
            visibility: SearchVisibility::Live,
            limit: 10,
            continuation: None,
            metadata_only: false,
            calculate_total: false,
        })
        .await
        .expect("mail");
    assert_eq!(mail_hits.keys.len(), 1);

    let chat_hits = engine
        .candidates(&CandidateQuery {
            corpus: DocCorpus::Chat,
            scope_hint: ScopeHint::Channels(vec![ch_id]),
            terms: NormalizedQuery::parse(&format!("TriggerCapturedChat_{tag}")).expect("q"),
            visibility: SearchVisibility::Live,
            limit: 10,
            continuation: None,
            metadata_only: false,
            calculate_total: false,
        })
        .await
        .expect("chat");
    assert_eq!(chat_hits.keys.len(), 1);

    let drive_hits = engine
        .candidates(&CandidateQuery {
            corpus: DocCorpus::Drive,
            scope_hint: ScopeHint::Spaces(vec![sp_id]),
            terms: NormalizedQuery::parse(&format!("TriggerCapturedDrive_{tag}.txt")).expect("q"),
            visibility: SearchVisibility::Live,
            limit: 10,
            continuation: None,
            metadata_only: false,
            calculate_total: false,
        })
        .await
        .expect("drive");
    assert_eq!(drive_hits.keys.len(), 1);
}

#[tokio::test]
async fn gap_free_out_of_order_commits_never_skip_lower_seq() {
    let _guard = DB_TEST_LOCK.lock().await;
    let dsn = match resolve_db_gate(|k| std::env::var(k).ok()) {
        DbGate::Run { dsn, .. } => dsn,
        DbGate::Skip => return,
        DbGate::Missing => panic!("REQUIRE_DB=1 set but TEST_DB_DSN/DB_DSN is absent"),
    };
    let owner = connect_as(&dsn).await;
    let worker = Arc::new(connect_as(&swap_dsn_user(&dsn, "setjoin_worker")).await);
    reset_outbox_and_watermarks(worker.as_ref()).await;

    let tag = next_tag();
    let (_uid, mailbox_id, folder_id) = seed_user_and_mailbox(&owner, &format!("ooo_{tag}")).await;
    let (m1, ts1) = seed_message(
        &owner,
        mailbox_id,
        folder_id,
        &format!("LateCommitSeqOne_{tag}"),
        "seq one body",
        None,
    )
    .await;
    let (m2, ts2) = seed_message(
        &owner,
        mailbox_id,
        folder_id,
        &format!("EarlyCommitSeqTwo_{tag}"),
        "seq two body",
        None,
    )
    .await;

    // Two concurrent worker connections simulating out-of-order commits:
    // Tx A allocates LOWER seq1 and stays OPEN; Tx B allocates HIGHER seq2 and COMMITS first!
    let worker_a = connect_as(&swap_dsn_user(&dsn, "setjoin_worker")).await;
    let worker_b = connect_as(&swap_dsn_user(&dsn, "setjoin_worker")).await;

    worker_a.batch_execute("BEGIN").await.expect("begin A");
    let seq1: i64 = worker_a
        .query_one(
            "SELECT public.search_outbox_enqueue('mail', 'upsert', $1, $2, 0, $3, NULL)",
            &[&mailbox_id, &m1, &ts1],
        )
        .await
        .expect("enqueue A")
        .try_get(0)
        .expect("seq1");

    worker_b.batch_execute("BEGIN").await.expect("begin B");
    let seq2: i64 = worker_b
        .query_one(
            "SELECT public.search_outbox_enqueue('mail', 'upsert', $1, $2, 0, $3, NULL)",
            &[&mailbox_id, &m2, &ts2],
        )
        .await
        .expect("enqueue B")
        .try_get(0)
        .expect("seq2");
    assert!(seq1 < seq2, "Tx A must hold lower seq than Tx B");
    worker_b.batch_execute("COMMIT").await.expect("commit B");

    let dir = TempDir::new().expect("tempdir");
    let engine = Arc::new(TantivySearchEngine::open_or_degraded(SearchConfig {
        tier2_enabled: true,
        index_dir: dir.path().to_path_buf(),
        ..SearchConfig::default()
    }));
    let pipeline = SearchIndexPipeline::new(worker.clone(), engine.clone());

    // Batch 1 runs while Tx A is STILL uncommitted: processes seq2 cleanly!
    let s1 = pipeline
        .run_batch(&SearchIndexBatchPayload {
            corpus: Some(DocCorpus::Mail),
            batch_limit: Some(50),
        })
        .await
        .expect("batch 1");
    assert_eq!(s1.outbox_rows_processed, 1);

    // NOW Tx A commits the lower seq1!
    worker_a.batch_execute("COMMIT").await.expect("commit A");

    // Batch 2 MUST claim and index the late-committing seq1 (never skipped by seq > watermark)!
    let s2 = pipeline
        .run_batch(&SearchIndexBatchPayload {
            corpus: Some(DocCorpus::Mail),
            batch_limit: Some(50),
        })
        .await
        .expect("batch 2");
    assert_eq!(
        s2.outbox_rows_processed, 1,
        "late-committing lower seq1 MUST be claimed and indexed"
    );

    for term in [
        format!("LateCommitSeqOne_{tag}"),
        format!("EarlyCommitSeqTwo_{tag}"),
    ] {
        let hits = engine
            .candidates(&CandidateQuery {
                corpus: DocCorpus::Mail,
                scope_hint: ScopeHint::Mailbox(mailbox_id),
                terms: NormalizedQuery::parse(&term).expect("q"),
                visibility: SearchVisibility::Live,
                limit: 10,
                continuation: None,
                metadata_only: false,
                calculate_total: false,
            })
            .await
            .expect("search");
        assert_eq!(hits.keys.len(), 1, "missing indexed doc for {term}");
    }
}

#[tokio::test]
async fn attachment_delete_reindexes_parent_mail_and_message_cascade_evicts_attachments() {
    let _guard = DB_TEST_LOCK.lock().await;
    let dsn = match resolve_db_gate(|k| std::env::var(k).ok()) {
        DbGate::Run { dsn, .. } => dsn,
        DbGate::Skip => return,
        DbGate::Missing => panic!("REQUIRE_DB=1 set but TEST_DB_DSN/DB_DSN is absent"),
    };
    let owner = connect_as(&dsn).await;
    let worker = Arc::new(connect_as(&swap_dsn_user(&dsn, "setjoin_worker")).await);
    reset_outbox_and_watermarks(worker.as_ref()).await;
    ensure_search_watermarks_initialized(worker.as_ref())
        .await
        .expect("seed watermarks");

    let reader = Arc::new(InMemoryObjectReader::default());
    let dir = TempDir::new().expect("tempdir");
    let engine = Arc::new(TantivySearchEngine::open_or_degraded(SearchConfig {
        tier2_enabled: true,
        index_dir: dir.path().to_path_buf(),
        ..SearchConfig::default()
    }));
    let extract_svc = Arc::new(ContentExtractionService::new(
        worker.clone(),
        reader.clone(),
    ));
    let pipeline = SearchIndexPipeline::new(worker.clone(), engine.clone())
        .with_extraction_service(extract_svc);

    let tag = next_tag();
    let (_uid, mailbox_id, folder_id) =
        seed_user_and_mailbox(&owner, &format!("attdel_{tag}")).await;

    // 1. Direct attachment deletion: parent Mail must drop deleted attachment text!
    let (m1, ts1) = seed_message(
        &owner,
        mailbox_id,
        folder_id,
        &format!("ParentMail_{tag}"),
        "plain body",
        None,
    )
    .await;
    let att1_bytes = format!("DirectDeleteAttachmentSecret_{tag}").into_bytes();
    let att1_sha = sha256_hex(&att1_bytes);
    // Test production minio_ref = "mailblobs/<sha>" normalization too!
    reader.insert(&att1_sha, att1_bytes.clone());
    assert_eq!(
        normalize_blob_object_key(&att1_sha, &format!("mailblobs/{att1_sha}")),
        att1_sha
    );
    owner
        .execute(
            "INSERT INTO public.blobs (sha256, minio_ref, size_bytes, content_type) \
             VALUES ($1, $2, $3, 'text/plain') ON CONFLICT (sha256) DO NOTHING",
            &[
                &att1_sha,
                &format!("mailblobs/{att1_sha}"),
                &(att1_bytes.len() as i64),
            ],
        )
        .await
        .expect("blob1");
    let att1_id: i64 = owner
        .query_one(
            "INSERT INTO public.message_attachments \
               (message_id, received_at, blob_sha256, filename, content_type, size_bytes) \
             VALUES ($1, $2, $3, $4, 'text/plain', $5) RETURNING id",
            &[
                &m1,
                &ts1,
                &att1_sha,
                &format!("removable_{tag}.txt"),
                &(att1_bytes.len() as i64),
            ],
        )
        .await
        .expect("att1")
        .try_get(0)
        .expect("id");

    // 2. Cascading message deletion: BEFORE DELETE trigger captures real mailbox_id
    //    so MailAttachment doc is cleanly evicted from Tantivy!
    let (m2, ts2) = seed_message(
        &owner,
        mailbox_id,
        folder_id,
        &format!("CascadeMail_{tag}"),
        "cascade body",
        None,
    )
    .await;
    let att2_bytes = format!("CascadeAttachmentSecret_{tag}").into_bytes();
    let att2_sha = sha256_hex(&att2_bytes);
    reader.insert(&att2_sha, att2_bytes.clone());
    let _att2_id = seed_blob_and_attachment(
        &owner,
        m2,
        ts2,
        &att2_sha,
        att2_bytes.len() as i64,
        &format!("cascaded_{tag}.txt"),
        "text/plain",
    )
    .await;

    // Initial index of both messages + attachments via triggered outbox.
    pipeline
        .run_batch(&SearchIndexBatchPayload::default())
        .await
        .expect("initial index");

    let parent_before = engine
        .candidates(&CandidateQuery {
            corpus: DocCorpus::Mail,
            scope_hint: ScopeHint::Mailbox(mailbox_id),
            terms: NormalizedQuery::parse(&format!("DirectDeleteAttachmentSecret_{tag}"))
                .expect("q"),
            visibility: SearchVisibility::Live,
            limit: 10,
            continuation: None,
            metadata_only: false,
            calculate_total: false,
        })
        .await
        .expect("before");
    assert_eq!(parent_before.keys.len(), 1);

    let cascade_att_before = engine
        .candidates(&CandidateQuery {
            corpus: DocCorpus::MailAttachment,
            scope_hint: ScopeHint::Mailbox(mailbox_id),
            terms: NormalizedQuery::parse(&format!("CascadeAttachmentSecret_{tag}")).expect("q"),
            visibility: SearchVisibility::Live,
            limit: 10,
            continuation: None,
            metadata_only: false,
            calculate_total: false,
        })
        .await
        .expect("cascade before");
    assert_eq!(cascade_att_before.keys.len(), 1);

    // Direct delete att1 AND cascade-delete m2!
    owner
        .execute(
            "DELETE FROM public.message_attachments WHERE id = $1",
            &[&att1_id],
        )
        .await
        .expect("direct delete att1");
    owner
        .execute(
            "DELETE FROM public.messages WHERE id = $1 AND received_at = $2",
            &[&m2, &ts2],
        )
        .await
        .expect("cascade delete m2");

    // Verify ZERO broken scope_id = 0 tombstones were emitted by the cascade!
    let broken_scope_count: i64 = worker
        .query_one(
            "SELECT count(*) FROM public.search_index_outbox \
              WHERE corpus = 'mail_attachment' AND op = 'delete' AND scope_id = 0",
            &[],
        )
        .await
        .expect("broken scope check")
        .try_get(0)
        .expect("c");
    assert_eq!(
        broken_scope_count, 0,
        "cascade must never emit scope_id = 0"
    );

    pipeline
        .run_batch(&SearchIndexBatchPayload::default())
        .await
        .expect("post-delete index");

    // Parent Mail m1 MUST still exist by subject, but MUST NO LONGER match deleted att1 text!
    let parent_after_att_term = engine
        .candidates(&CandidateQuery {
            corpus: DocCorpus::Mail,
            scope_hint: ScopeHint::Mailbox(mailbox_id),
            terms: NormalizedQuery::parse(&format!("DirectDeleteAttachmentSecret_{tag}"))
                .expect("q"),
            visibility: SearchVisibility::Live,
            limit: 10,
            continuation: None,
            metadata_only: false,
            calculate_total: false,
        })
        .await
        .expect("after att delete");
    assert!(
        parent_after_att_term.keys.is_empty(),
        "parent Mail doc must drop deleted attachment text on direct attachment delete"
    );

    // Cascaded m2 attachment doc MUST be evicted from Tantivy!
    let cascade_att_after = engine
        .candidates(&CandidateQuery {
            corpus: DocCorpus::MailAttachment,
            scope_hint: ScopeHint::Mailbox(mailbox_id),
            terms: NormalizedQuery::parse(&format!("CascadeAttachmentSecret_{tag}")).expect("q"),
            visibility: SearchVisibility::Live,
            limit: 10,
            continuation: None,
            metadata_only: false,
            calculate_total: false,
        })
        .await
        .expect("cascade after");
    assert!(
        cascade_att_after.keys.is_empty(),
        "cascading message delete must evict MailAttachment doc via BEFORE DELETE trigger"
    );
}

#[tokio::test]
async fn drive_missing_chunks_fails_closed_without_bare_sha_s3_fallback() {
    let _guard = DB_TEST_LOCK.lock().await;
    let dsn = match resolve_db_gate(|k| std::env::var(k).ok()) {
        DbGate::Run { dsn, .. } => dsn,
        DbGate::Skip => return,
        DbGate::Missing => panic!("REQUIRE_DB=1 set but TEST_DB_DSN/DB_DSN is absent"),
    };
    let owner = connect_as(&dsn).await;
    let worker = Arc::new(connect_as(&swap_dsn_user(&dsn, "setjoin_worker")).await);
    let reader = Arc::new(InMemoryObjectReader::default());
    let svc = ContentExtractionService::new(worker.clone(), reader.clone());

    let tag = next_tag();
    let (user_id, _, _) = seed_user_and_mailbox(&owner, &format!("nochunk_{tag}")).await;
    let secret_bytes = format!("UNRELATED_MAIL_BLOB_SECRET_{tag}").into_bytes();
    let secret_sha = sha256_hex(&secret_bytes);
    // Put an unrelated Mail S3 object at bare key = secret_sha.
    reader.insert(&secret_sha, secret_bytes.clone());

    let sp_id: i64 = owner
        .query_one(
            "INSERT INTO public.drive_spaces (name, classification, owner_user_id) \
             VALUES ($1, 'regular', $2) RETURNING id",
            &[&format!("sp_nochunk_{tag}"), &user_id],
        )
        .await
        .expect("sp")
        .try_get(0)
        .expect("sid");
    let node_id: i64 = owner
        .query_one(
            "INSERT INTO public.drive_nodes (space_id, kind, name, created_by) \
             VALUES ($1, 'file', 'empty_chunks.txt', $2) RETURNING id",
            &[&sp_id, &user_id],
        )
        .await
        .expect("node")
        .try_get(0)
        .expect("nid");
    owner
        .execute(
            "INSERT INTO public.drive_files (node_id, space_id, size_bytes, content_type) \
             VALUES ($1, $2, 32, 'text/plain')",
            &[&node_id, &sp_id],
        )
        .await
        .expect("df");
    let ver_id: i64 = owner
        .query_one(
            "INSERT INTO public.drive_file_versions \
               (file_node_id, space_id, content_sha256, size_bytes, content_type, author_user_id) \
             VALUES ($1, $2, $3, 32, 'text/plain', $4) RETURNING id",
            &[&node_id, &sp_id, &secret_sha, &user_id],
        )
        .await
        .expect("ver")
        .try_get(0)
        .expect("vid");

    // Zero drive_version_chunks & no explicit object_key -> MUST error, NEVER read bare secret_sha!
    let res = svc
        .extract_and_cache(&SearchExtractPayload {
            content_sha256: secret_sha,
            storage_plane: ExtractionStoragePlane::DriveFileVersion,
            object_key: None,
            drive_version_id: Some(ver_id),
            content_type: Some("text/plain".into()),
            filename: Some("empty_chunks.txt".into()),
        })
        .await;
    assert!(
        matches!(res, Err(SearchError::Io(_))),
        "Drive version with missing chunks must fail closed instead of falling back to bare SHA key"
    );
}
