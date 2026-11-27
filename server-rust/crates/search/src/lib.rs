#![forbid(unsafe_code)]
//! Foundation two-tier search crate (`setjoin-search`, Wave 3.1 / #556).
//!
//! Provides:
//! - Object-safe [`SearchEngine`] and [`SearchIndexer`] trait seams.
//! - 100% permissive pure-MIT Tantivy tokenizers (`zh_jieba`, `cjk_bigram`, `ident_exact`)
//!   with lazy `OnceLock<Arc<_>>` dictionary loading (zero startup/RAM cost for Tier-1-only).
//! - Embedded [`TantivySearchEngine`] with `<= 50 MB` writer heap cap, atomic `(reader, generation)`
//!   swap, S/MIME `V029` C7 encryption boundary, and single-deadline `Semaphore(4)` + `250ms`
//!   timeout + `catch_unwind`.
//! - Optional `pg_bigm` [`Tier1PgSearchEngine`] baseline and mandatory PG re-authorization
//!   helpers (`reauthorize_mail_candidates`, `reauthorize_chat_candidates`,
//!   `reauthorize_drive_candidates`) + bounded overfetch pagination (`<= 1500` candidates).

pub mod config;
pub mod extract;
pub mod model;
pub mod pipeline;
pub mod reauth;
pub mod tantivy_engine;
pub mod tier1_pg;
pub mod tokenizers;
pub mod two_tier;

pub use config::{
    clamp_writer_heap_bytes, generate_cursor_secret, SearchConfig, DEFAULT_INDEX_DIR,
    DEFAULT_MAX_CONCURRENT_SEARCHES, DEFAULT_QUERY_TIMEOUT, DEFAULT_WRITER_HEAP_BYTES,
    MAX_DOC_BODY_BYTES, MAX_INFLIGHT_BYTES, MAX_INFLIGHT_DOCS, MAX_WRITER_HEAP_BYTES,
    MIN_WRITER_HEAP_BYTES,
};
pub use extract::{
    decode_text_bytes, extract_bytes, extract_html_text, truncate_utf8_owned, ExtractionResult,
    ExtractionStatus, ExtractionStoragePlane, EXTRACTOR_VERSION, MAX_EXTRACTED_TEXT_BYTES,
    MAX_EXTRACT_INPUT_BYTES, MAX_ZIP_COMPRESSION_RATIO, MAX_ZIP_DECOMPRESSED_BYTES,
    MAX_ZIP_ENTRIES,
};
pub use model::{
    BoxFuture, CandidateBatch, CandidateQuery, CursorBinding, DocCorpus, DocumentKey, EngineHealth,
    IndexDocument, NormalizedQuery, OpaqueCursor, QueryValidationError, ScopeHint, SearchEngine,
    SearchError, SearchIndexer, SearchTier, SearchVisibility, MAX_CANDIDATE_LIMIT,
    MAX_CURSOR_OFFSET, MAX_CURSOR_TOKEN_BYTES, MAX_QUERY_BYTES, MAX_QUERY_TERMS, MAX_SCOPE_IDS,
};
pub use pipeline::{
    chat_revision_doc_id, enqueue_outbox, ensure_search_watermarks_initialized,
    has_unprocessed_outbox_rows, normalize_blob_object_key, scheduled_action_doc_id,
    unprocessed_counts_by_corpus, ContentExtractionService, ContentExtractor,
    DefaultContentExtractor, ExtractCacheOutcome, ExtractionSingleFlight, IndexBatchSummary,
    ObjectByteReader, SearchExtractPayload, SearchIndexBatchPayload, SearchIndexPipeline,
    SearchPipelineDb, SingleFlightGuard, DEFAULT_INDEX_BATCH_LIMIT, WORK_KIND_SEARCH_EXTRACT,
    WORK_KIND_SEARCH_INDEX_BATCH,
};
pub use reauth::{
    execute_overfetch_page, overfetch_limit, reauthorize_chat_candidates,
    reauthorize_drive_candidates, reauthorize_mail_candidates, AuthorizedChatHit,
    AuthorizedDriveHit, AuthorizedMailHit, AuthorizedPage, MailReauthFilter,
    MAX_OVERFETCH_CANDIDATES, MAX_OVERFETCH_ROUNDS,
};
pub use tantivy_engine::{schema_hash, EpochManifest, TantivySearchEngine};
pub use tier1_pg::{
    escape_like_pattern, probe_pg_capabilities_client, probe_pg_capabilities_exec,
    tier1_chat_candidates, tier1_drive_candidates, tier1_mail_candidates, PgSearchCapabilities,
    Tier1PgSearchEngine, Tier1Resolver,
};
pub use tokenizers::{
    is_cjk_char, is_jieba_initialized, register_tokenizers, CjkBigramTokenizer,
    IdentExactTokenizer, ZhJiebaTokenizer, CJK_BIGRAM_TOKENIZER, IDENT_EXACT_TOKENIZER,
    ZH_JIEBA_TOKENIZER,
};
pub use two_tier::{
    AlwaysFresh, FreshnessFence, SearchRuntime, SnapshotFreshnessFence, TwoTierSearchEngine,
    WatermarkSnapshot,
};

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;
    use tempfile::TempDir;

    fn mail_doc(
        mailbox_id: i64,
        id: i64,
        subject: &str,
        body: Option<&str>,
        headers: Vec<&str>,
        identifiers: Vec<&str>,
        crypto_sealed: bool,
    ) -> IndexDocument {
        IndexDocument {
            key: DocumentKey::Mail {
                mailbox_id,
                id,
                received_at: Utc::now(),
            },
            visibility: SearchVisibility::Live,
            title: subject.to_owned(),
            body: body.map(str::to_owned),
            headers: headers.into_iter().map(str::to_owned).collect(),
            identifiers: identifiers.into_iter().map(str::to_owned).collect(),
            sort_i64: id,
            sort_name: subject.to_owned(),
            crypto_sealed,
        }
    }

    fn mail_query(mailbox_id: i64, raw: &str) -> CandidateQuery {
        CandidateQuery {
            corpus: DocCorpus::Mail,
            scope_hint: ScopeHint::Mailbox(mailbox_id),
            terms: NormalizedQuery::parse(raw).expect("valid query"),
            visibility: SearchVisibility::Live,
            limit: 20,
            continuation: None,
            metadata_only: false,
            calculate_total: false,
        }
    }

    fn stub_tier1(keys: Vec<DocumentKey>, calls: Arc<AtomicUsize>) -> Arc<dyn SearchEngine> {
        Arc::new(Tier1PgSearchEngine::new(
            PgSearchCapabilities::default(),
            Arc::new(move |_q: &CandidateQuery| {
                let keys = keys.clone();
                let calls = Arc::clone(&calls);
                Box::pin(async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok(CandidateBatch {
                        keys,
                        generation: 0,
                        continuation: None,
                        tier: SearchTier::Tier1Pg,
                        degraded: false,
                    })
                })
            }),
        ))
    }

    #[test]
    fn traits_are_object_safe() {
        fn assert_engine(_: Arc<dyn SearchEngine>) {}
        fn assert_indexer(_: Arc<dyn SearchIndexer>) {}

        let dir = TempDir::new().expect("tempdir");
        let cfg = SearchConfig {
            tier2_enabled: true,
            index_dir: dir.path().to_path_buf(),
            ..SearchConfig::default()
        };
        let eng = Arc::new(TantivySearchEngine::open_or_degraded(cfg));
        let e: Arc<dyn SearchEngine> = eng.clone();
        let i: Arc<dyn SearchIndexer> = eng;
        assert_engine(e);
        assert_indexer(i);
    }

    #[test]
    fn writer_heap_budget_strictly_clamps_to_50mb_cap() {
        assert_eq!(clamp_writer_heap_bytes(0), MIN_WRITER_HEAP_BYTES);
        assert_eq!(clamp_writer_heap_bytes(1_000_000), MIN_WRITER_HEAP_BYTES);
        assert_eq!(clamp_writer_heap_bytes(32_000_000), 32_000_000);
        assert_eq!(clamp_writer_heap_bytes(50_000_000), MAX_WRITER_HEAP_BYTES);
        assert_eq!(clamp_writer_heap_bytes(128_000_000), MAX_WRITER_HEAP_BYTES);
        assert_eq!(clamp_writer_heap_bytes(usize::MAX), MAX_WRITER_HEAP_BYTES);

        let env_cfg = SearchConfig::from_lookup(&|k| match k {
            "SETJOIN_SEARCH_WRITER_HEAP_BYTES" => Some("256000000".to_owned()),
            _ => None,
        });
        assert_eq!(env_cfg.effective_writer_heap_bytes(), MAX_WRITER_HEAP_BYTES);
        assert!(!env_cfg.tier2_enabled, "Tier-2 must default OFF");
        assert_eq!(env_cfg.cursor_secret.len(), 32);
    }

    #[test]
    fn query_validation_enforces_dos_bounds_and_allows_paths() {
        // 256 bytes allowed, 257 bytes rejected
        let ok_256 = "a".repeat(MAX_QUERY_BYTES);
        assert!(NormalizedQuery::parse(&ok_256).is_ok());
        let too_long_257 = "a".repeat(MAX_QUERY_BYTES + 1);
        assert!(matches!(
            NormalizedQuery::parse(&too_long_257),
            Err(QueryValidationError::TooLong {
                bytes: 257,
                max: 256
            })
        ));

        // Leading wildcards rejected
        assert_eq!(
            NormalizedQuery::parse("*invoice"),
            Err(QueryValidationError::LeadingWildcard)
        );
        assert_eq!(
            NormalizedQuery::parse("report ?foo"),
            Err(QueryValidationError::LeadingWildcard)
        );

        // User regex rejected, while filesystem paths like /var/lib/setjoin are allowed
        assert_eq!(
            NormalizedQuery::parse("/inv-[0-9]+/"),
            Err(QueryValidationError::RegexNotAllowed)
        );
        assert_eq!(
            NormalizedQuery::parse("/secret/i"),
            Err(QueryValidationError::RegexNotAllowed)
        );
        assert_eq!(
            NormalizedQuery::parse("/secret/gim"),
            Err(QueryValidationError::RegexNotAllowed)
        );
        assert!(
            NormalizedQuery::parse("/var/lib/setjoin").is_ok(),
            "filesystem paths must not be misclassified as regexes"
        );

        // > 32 terms rejected
        let terms_33 = (0..33)
            .map(|i| format!("t{i}"))
            .collect::<Vec<_>>()
            .join(" ");
        assert!(matches!(
            NormalizedQuery::parse(&terms_33),
            Err(QueryValidationError::TooManyTerms { terms: 33, max: 32 })
        ));

        // Empty / control chars rejected
        assert_eq!(
            NormalizedQuery::parse("   "),
            Err(QueryValidationError::Empty)
        );
        assert_eq!(
            NormalizedQuery::parse("abc\0def"),
            Err(QueryValidationError::ControlCharacter)
        );
    }

    #[test]
    fn opaque_cursor_binds_full_context_and_enforces_caps() {
        let secret = b"unit-test-secret-key-32-bytes-ok";
        let base = CursorBinding {
            corpus: DocCorpus::Mail,
            visibility: SearchVisibility::Live,
            scope_key: "mail:42",
            query_hash: "hash-a",
            generation: 7,
        };
        let cursor = OpaqueCursor::mint(secret, base, 100).expect("mint");
        assert_eq!(cursor.verify(secret, base).expect("ok"), 100);

        // Wrong corpus
        assert_eq!(
            cursor.verify(
                secret,
                CursorBinding {
                    corpus: DocCorpus::Chat,
                    ..base
                }
            ),
            Err(SearchError::InvalidCursor)
        );
        // Wrong visibility
        assert_eq!(
            cursor.verify(
                secret,
                CursorBinding {
                    visibility: SearchVisibility::ComplianceOnly,
                    ..base
                }
            ),
            Err(SearchError::InvalidCursor)
        );
        // Wrong scope
        assert_eq!(
            cursor.verify(
                secret,
                CursorBinding {
                    scope_key: "mail:99",
                    ..base
                }
            ),
            Err(SearchError::InvalidCursor)
        );
        // Wrong query hash
        assert_eq!(
            cursor.verify(
                secret,
                CursorBinding {
                    query_hash: "hash-b",
                    ..base
                }
            ),
            Err(SearchError::InvalidCursor)
        );
        // Stale generation
        assert_eq!(
            cursor.verify(
                secret,
                CursorBinding {
                    generation: 8,
                    ..base
                }
            ),
            Err(SearchError::InvalidCursor)
        );
        // Offset > MAX_CURSOR_OFFSET rejected
        assert_eq!(
            OpaqueCursor::mint(secret, base, MAX_CURSOR_OFFSET + 1),
            Err(SearchError::InvalidCursor)
        );
        // Oversized cursor (> 512 bytes) rejected before hex decode
        let huge = OpaqueCursor::from_raw("a".repeat(MAX_CURSOR_TOKEN_BYTES + 1));
        assert_eq!(huge.verify(secret, base), Err(SearchError::InvalidCursor));
    }

    #[tokio::test]
    async fn punctuation_only_queries_fail_closed_with_empty_batch() {
        let dir = TempDir::new().expect("tempdir");
        let cfg = SearchConfig {
            tier2_enabled: true,
            index_dir: dir.path().to_path_buf(),
            ..SearchConfig::default()
        };
        let engine = TantivySearchEngine::open_or_degraded(cfg);
        engine
            .rebuild_epoch(
                &[mail_doc(
                    10,
                    1,
                    "Important Invoice",
                    Some("hello world"),
                    vec![],
                    vec![],
                    false,
                )],
                1,
                Some(Utc::now()),
            )
            .expect("rebuild");

        for punct in [",", "!", "()", "[]", ";;", "Important ()"] {
            let batch = engine
                .candidates(&mail_query(10, punct))
                .await
                .expect("punct query");
            assert!(
                batch.keys.is_empty(),
                "punctuation query {punct:?} must fail closed (0 hits), got {:?}",
                batch.keys
            );
        }
    }

    #[tokio::test]
    async fn monotonic_generation_crash_recovery_stale_epoch_and_scope_dedup() {
        let dir = TempDir::new().expect("tempdir");
        let cfg = SearchConfig {
            tier2_enabled: true,
            index_dir: dir.path().to_path_buf(),
            ..SearchConfig::default()
        };
        let eng_a = TantivySearchEngine::open_or_degraded(cfg.clone());
        let m1 = eng_a
            .rebuild_epoch(
                &[mail_doc(1, 1, "one", None, vec![], vec![], false)],
                5,
                Some(Utc::now()),
            )
            .expect("epoch 1");
        assert_eq!(m1.epoch, 1);
        assert_eq!(m1.generation, 5);

        // Even if caller passes a lower/equal generation on rebuild, generation advances strictly monotonically!
        let m2 = eng_a
            .rebuild_epoch(
                &[mail_doc(1, 2, "two", None, vec![], vec![], false)],
                5,
                Some(Utc::now()),
            )
            .expect("epoch 2");
        assert_eq!(m2.epoch, 2);
        assert_eq!(m2.generation, 6);

        // Simulate stale writer holding old epoch 2 while an out-of-band rebuild advances CURRENT to epoch 3.
        let eng_b = TantivySearchEngine::open_or_degraded(cfg.clone());
        let m3 = eng_b
            .rebuild_epoch(
                &[mail_doc(1, 3, "three", None, vec![], vec![], false)],
                6,
                Some(Utc::now()),
            )
            .expect("epoch 3");
        assert_eq!(m3.epoch, 3);
        assert_eq!(m3.generation, 7);

        assert!(matches!(
            eng_a
                .upsert_batch(&[mail_doc(1, 4, "stale", None, vec![], vec![], false)])
                .await,
            Err(SearchError::StaleEpoch {
                expected: 2,
                on_disk: 3
            })
        ));

        // Simulate crash leaving clean_shutdown == false on disk -> open recovers by bumping generation!
        let mut dirty_manifest = m3.clone();
        dirty_manifest.clean_shutdown = false;
        std::fs::write(
            dir.path().join("CURRENT"),
            serde_json::to_vec_pretty(&dirty_manifest).expect("json"),
        )
        .expect("write dirty CURRENT");
        let recovered = TantivySearchEngine::open_or_degraded(cfg);
        let rec_m = recovered.current_manifest().expect("recovered manifest");
        assert!(rec_m.clean_shutdown);
        assert_eq!(rec_m.generation, m3.generation + 1);

        // ScopeHint deduplicates & caps to MAX_SCOPE_IDS before Tantivy clauses.
        let dup_scope = ScopeHint::Channels(vec![5, 5, 2, 5, 2, 1]);
        assert_eq!(
            dup_scope.tantivy_scope_keys(),
            Some(vec![
                "chat:1".to_owned(),
                "chat:2".to_owned(),
                "chat:5".to_owned()
            ])
        );
    }

    #[tokio::test]
    async fn cjk_1_and_2_char_zh_ja_ko_recall_and_ident_exact_recall() {
        let dir = TempDir::new().expect("tempdir");
        let cfg = SearchConfig {
            tier2_enabled: true,
            index_dir: dir.path().to_path_buf(),
            ..SearchConfig::default()
        };
        let engine = TantivySearchEngine::open_or_degraded(cfg);

        // Verify schema stores ONLY doc_key (zero plaintext body storage).
        assert_eq!(engine.stored_field_names(), vec!["doc_key".to_owned()]);

        let docs = vec![
            mail_doc(
                10,
                1,
                "北京人工智能发票审批",
                Some("请核对上海项目月报与财务合同，单字测试：龙"),
                vec!["a+b@example.org", "Alice Zhang"],
                vec![
                    "inv-2026_01.pdf",
                    "550e8400-e29b-41d4-a716-446655440000",
                    "a+b@example.org",
                    "ÜBER-FILE.PDF",
                ],
                false,
            ),
            mail_doc(
                10,
                2,
                "東京プロジェクト報告書",
                Some("カタカナ検索とひらがな確認：桜"),
                vec!["tanaka@corp.jp"],
                vec!["spec_v2.jp.pdf"],
                false,
            ),
            mail_doc(
                10,
                3,
                "서울 프로젝트 보고서",
                Some("한국어 검색 테스트 단일 글자: 별"),
                vec!["kim@corp.kr"],
                vec!["kr-report-2026.xlsx"],
                false,
            ),
        ];

        let manifest = engine
            .rebuild_epoch(&docs, 1, Some(Utc::now()))
            .expect("rebuild");
        assert_eq!(manifest.epoch, 1);
        assert_eq!(manifest.generation, 1);

        // Verify Unix 0o700 permissions on private index directory.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.path())
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o700, "index_dir must have 0700 permissions");
        }

        // Chinese 1-char & 2-char & compound recall
        for q in ["龙", "发票", "北京", "人工智能", "财务"] {
            let batch = engine
                .candidates(&mail_query(10, q))
                .await
                .expect("zh search");
            assert_eq!(batch.keys.len(), 1, "expected 1 ZH hit for query {q:?}");
            assert!(matches!(batch.keys[0], DocumentKey::Mail { id: 1, .. }));
        }

        // Japanese 1-char & 2-char Kanji/Katakana/Hiragana recall
        for q in ["桜", "東京", "検索", "カタ", "ひらがな"] {
            let batch = engine
                .candidates(&mail_query(10, q))
                .await
                .expect("ja search");
            assert_eq!(batch.keys.len(), 1, "expected 1 JA hit for query {q:?}");
            assert!(matches!(batch.keys[0], DocumentKey::Mail { id: 2, .. }));
        }

        // Korean 1-char & 2-char Hangul recall
        for q in ["별", "서울", "검색", "프로젝트"] {
            let batch = engine
                .candidates(&mail_query(10, q))
                .await
                .expect("ko search");
            assert_eq!(batch.keys.len(), 1, "expected 1 KO hit for query {q:?}");
            assert!(matches!(batch.keys[0], DocumentKey::Mail { id: 3, .. }));
        }

        // Exact email, filename, UUID, Unicode lowercase, and delimiter sub-token recall via ident_exact
        for q in [
            "a+b@example.org",
            "inv-2026_01.pdf",
            "550e8400-e29b-41d4-a716-446655440000",
            "über-file.pdf",
            "example",
            "pdf",
        ] {
            let batch = engine
                .candidates(&mail_query(10, q))
                .await
                .expect("ident search");
            assert!(
                batch
                    .keys
                    .iter()
                    .any(|k| matches!(k, DocumentKey::Mail { id: 1, .. })),
                "expected doc 1 hit for identifier query {q:?}"
            );
        }
    }

    #[tokio::test]
    async fn smime_crypto_sealed_omits_body_attachment_and_non_envelope_identifiers() {
        let dir = TempDir::new().expect("tempdir");
        let cfg = SearchConfig {
            tier2_enabled: true,
            index_dir: dir.path().to_path_buf(),
            ..SearchConfig::default()
        };
        let engine = TantivySearchEngine::open_or_degraded(cfg);

        let sealed_mail = mail_doc(
            77,
            501,
            "Cleartext Envelope Subject",
            Some("TOP_SECRET_SMIME_PLAINTEXT_TOKEN 机密正文密码"),
            vec!["sender.sealed@example.org", "Bob Encrypted"],
            vec!["NON_ENVELOPE_BODY_IDENT_SECRET"],
            true, // V029 C7: crypto_sealed = true
        );
        let sealed_attachment = IndexDocument {
            key: DocumentKey::MailAttachment {
                mailbox_id: 77,
                id: 501,
                received_at: Utc::now(),
                sub_id: 99,
            },
            visibility: SearchVisibility::Live,
            title: "SECRET_ATTACHMENT_FILENAME.pdf".to_owned(),
            body: Some("SECRET_ATTACHMENT_BODY".to_owned()),
            headers: vec!["sender.sealed@example.org".to_owned()],
            identifiers: vec!["SECRET_ATTACHMENT_FILENAME.pdf".to_owned()],
            sort_i64: 501,
            sort_name: "SECRET_ATTACHMENT_FILENAME.pdf".to_owned(),
            crypto_sealed: true,
        };
        engine
            .rebuild_epoch(&[sealed_mail, sealed_attachment], 1, Some(Utc::now()))
            .expect("rebuild");

        // Cleartext subject & From header MUST remain searchable.
        let subj_hits = engine
            .candidates(&mail_query(77, "Envelope"))
            .await
            .expect("subject search");
        assert_eq!(subj_hits.keys.len(), 1);
        let hdr_hits = engine
            .candidates(&mail_query(77, "sender.sealed@example.org"))
            .await
            .expect("header search");
        assert_eq!(hdr_hits.keys.len(), 1);

        // Sealed body plaintext AND non-envelope identifiers MUST NOT be indexed.
        for forbidden in [
            "TOP_SECRET_SMIME_PLAINTEXT_TOKEN",
            "机密正文密码",
            "机密",
            "NON_ENVELOPE_BODY_IDENT_SECRET",
        ] {
            let hits = engine
                .candidates(&mail_query(77, forbidden))
                .await
                .expect("sealed mail probe");
            assert!(
                hits.keys.is_empty(),
                "V029 C7 violation: sealed mail term {forbidden:?} matched!"
            );
        }

        // Sealed MailAttachment filename/body MUST NOT be indexed.
        for forbidden in ["SECRET_ATTACHMENT_FILENAME.pdf", "SECRET_ATTACHMENT_BODY"] {
            let q = CandidateQuery {
                corpus: DocCorpus::MailAttachment,
                scope_hint: ScopeHint::Mailbox(77),
                terms: NormalizedQuery::parse(forbidden).expect("q"),
                visibility: SearchVisibility::Live,
                limit: 20,
                continuation: None,
                metadata_only: false,
                calculate_total: false,
            };
            let hits = engine
                .candidates(&q)
                .await
                .expect("sealed attachment probe");
            assert!(
                hits.keys.is_empty(),
                "V029 C7 violation: sealed attachment term {forbidden:?} matched!"
            );
        }
    }

    #[tokio::test]
    async fn atomic_epoch_swap_incremental_generation_and_corrupt_fallback() {
        let dir = TempDir::new().expect("tempdir");
        let cfg = SearchConfig {
            tier2_enabled: true,
            index_dir: dir.path().to_path_buf(),
            ..SearchConfig::default()
        };
        let engine = Arc::new(TantivySearchEngine::open_or_degraded(cfg.clone()));

        // Epoch 1 -> doc 1
        let m1 = engine
            .rebuild_epoch(
                &[mail_doc(
                    5,
                    1,
                    "alpha-epoch-one",
                    None,
                    vec![],
                    vec![],
                    false,
                )],
                1,
                Some(Utc::now()),
            )
            .expect("epoch 1");
        assert_eq!(m1.epoch, 1);
        assert!(engine.epoch_dir_path(1).is_dir());

        // Incremental upsert via non-blocking SearchIndexer advances generation atomically!
        let upserted = engine
            .upsert_batch(&[mail_doc(
                5,
                11,
                "incremental-upsert-token",
                None,
                vec![],
                vec![],
                false,
            )])
            .await
            .expect("upsert");
        assert_eq!(upserted, 1);
        assert_eq!(engine.current_manifest().expect("m").generation, 2);

        // Atomic swap to Epoch 2 -> doc 2; Epoch 1 dir is cleaned up on drop.
        let m2 = engine
            .rebuild_epoch(
                &[mail_doc(
                    5,
                    2,
                    "beta-epoch-two",
                    None,
                    vec![],
                    vec![],
                    false,
                )],
                3,
                Some(Utc::now()),
            )
            .expect("epoch 2");
        assert_eq!(m2.epoch, 2);
        assert!(engine.epoch_dir_path(2).is_dir());
        assert!(!engine.epoch_dir_path(1).exists());

        let hit_old = engine
            .candidates(&mail_query(5, "alpha-epoch-one"))
            .await
            .expect("old term");
        assert!(hit_old.keys.is_empty());
        let hit_new = engine
            .candidates(&mail_query(5, "beta-epoch-two"))
            .await
            .expect("new term");
        assert_eq!(hit_new.keys.len(), 1);
        assert_eq!(hit_new.generation, 3);

        // Corrupt CURRENT JSON on disk -> fresh open degrades cleanly to Tier-1!
        std::fs::write(dir.path().join("CURRENT"), b"{corrupt json").expect("corrupt CURRENT");
        let reopened = Arc::new(TantivySearchEngine::open_or_degraded(cfg.clone()));
        assert!(!reopened.health().is_healthy());

        let fallback_calls = Arc::new(AtomicUsize::new(0));
        let fallback_key = DocumentKey::Mail {
            mailbox_id: 5,
            id: 999,
            received_at: Utc::now(),
        };
        let two_tier = TwoTierSearchEngine::new(
            cfg,
            stub_tier1(vec![fallback_key.clone()], Arc::clone(&fallback_calls)),
            Some(reopened),
        );
        let res = two_tier
            .candidates(&mail_query(5, "beta-epoch-two"))
            .await
            .expect("graceful fallback");
        assert_eq!(res.tier, SearchTier::Tier1Pg);
        assert!(res.degraded);
        assert_eq!(res.keys, vec![fallback_key]);
        assert_eq!(fallback_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn fail_closed_watermark_timeout_and_panic_degrade_to_tier1() {
        let dir = TempDir::new().expect("tempdir");
        let cfg = SearchConfig {
            tier2_enabled: true,
            index_dir: dir.path().to_path_buf(),
            query_timeout: Duration::from_millis(40),
            ..SearchConfig::default()
        };
        let t2 = Arc::new(TantivySearchEngine::open_or_degraded(cfg.clone()));
        t2.rebuild_epoch(
            &[mail_doc(
                9,
                10,
                "quarterly budget",
                None,
                vec![],
                vec![],
                false,
            )],
            3,
            Some(Utc::now()),
        )
        .expect("rebuild");

        let fallback_calls = Arc::new(AtomicUsize::new(0));
        let fallback_key = DocumentKey::Mail {
            mailbox_id: 9,
            id: 777,
            received_at: Utc::now(),
        };
        // Default fence is UNSET -> must fail closed to Tier-1!
        let fence = Arc::new(SnapshotFreshnessFence::unset());
        let two_tier = TwoTierSearchEngine::new(
            cfg,
            stub_tier1(vec![fallback_key.clone()], Arc::clone(&fallback_calls)),
            Some(Arc::clone(&t2)),
        )
        .with_freshness_fence(Arc::clone(&fence) as Arc<dyn FreshnessFence>);

        let unset_res = two_tier
            .candidates(&mail_query(9, "quarterly"))
            .await
            .expect("unset fails closed");
        assert_eq!(unset_res.tier, SearchTier::Tier1Pg);
        assert!(unset_res.degraded);
        assert_eq!(fallback_calls.load(Ordering::SeqCst), 1);

        // Generation mismatch (behind or ahead) -> fails closed to Tier-1
        fence.set_watermark(DocCorpus::Mail, 4, 0);
        let behind = two_tier
            .candidates(&mail_query(9, "quarterly"))
            .await
            .expect("behind fails closed");
        assert_eq!(behind.tier, SearchTier::Tier1Pg);
        assert!(behind.degraded);
        assert_eq!(fallback_calls.load(Ordering::SeqCst), 2);

        fence.set_watermark(DocCorpus::Mail, 2, 0);
        let ahead = two_tier
            .candidates(&mail_query(9, "quarterly"))
            .await
            .expect("ahead fails closed");
        assert_eq!(ahead.tier, SearchTier::Tier1Pg);
        assert!(ahead.degraded);
        assert_eq!(fallback_calls.load(Ordering::SeqCst), 3);

        // Exact generation match + dirty_count == 0 -> Tier-2 serves!
        fence.set_watermark(DocCorpus::Mail, 3, 0);
        let ok = two_tier
            .candidates(&mail_query(9, "quarterly"))
            .await
            .expect("healthy tier2");
        assert_eq!(ok.tier, SearchTier::Tier2Tantivy);
        assert!(!ok.degraded);
        assert_eq!(fallback_calls.load(Ordering::SeqCst), 3);

        // Dirty keys present -> degrades to Tier-1
        fence.set_watermark(DocCorpus::Mail, 3, 1);
        let dirty = two_tier
            .candidates(&mail_query(9, "quarterly"))
            .await
            .expect("dirty fallback");
        assert_eq!(dirty.tier, SearchTier::Tier1Pg);
        assert!(dirty.degraded);
        assert_eq!(fallback_calls.load(Ordering::SeqCst), 4);
        fence.set_watermark(DocCorpus::Mail, 3, 0);

        // Panic inside spawn_blocking -> caught by catch_unwind, degrades to Tier-1
        t2.set_inject_panic(true);
        let panicked = two_tier
            .candidates(&mail_query(9, "quarterly"))
            .await
            .expect("panic fallback");
        assert_eq!(panicked.tier, SearchTier::Tier1Pg);
        assert!(panicked.degraded);
        assert_eq!(fallback_calls.load(Ordering::SeqCst), 5);
        t2.set_inject_panic(false);

        // Timeout (> 40ms) -> degrades to Tier-1
        t2.set_inject_delay_ms(120);
        let timed_out = two_tier
            .candidates(&mail_query(9, "quarterly"))
            .await
            .expect("timeout fallback");
        assert_eq!(timed_out.tier, SearchTier::Tier1Pg);
        assert!(timed_out.degraded);
        assert_eq!(fallback_calls.load(Ordering::SeqCst), 6);
        t2.set_inject_delay_ms(0);
    }

    #[tokio::test]
    async fn overfetch_pagination_caps_total_candidates_and_falls_back() {
        assert_eq!(overfetch_limit(10), 64);
        assert_eq!(overfetch_limit(50), 150);
        assert_eq!(overfetch_limit(200), 500);

        let dir = TempDir::new().expect("tempdir");
        let cfg = SearchConfig {
            tier2_enabled: true,
            index_dir: dir.path().to_path_buf(),
            ..SearchConfig::default()
        };
        let t2 = TantivySearchEngine::open_or_degraded(cfg);

        // Index 1700 docs matching "overfetchtoken", request page_limit=200 (overfetch=500):
        // Round 1=500, Round 2=500, Round 3=500 -> total=1500 (strictly <= MAX_OVERFETCH_CANDIDATES!)
        let docs: Vec<IndexDocument> = (1..=1700)
            .map(|i| mail_doc(4, i, "overfetchtoken item", None, vec![], vec![], false))
            .collect();
        t2.rebuild_epoch(&docs, 1, Some(Utc::now()))
            .expect("rebuild");

        let q = mail_query(4, "overfetchtoken");
        let page: AuthorizedPage<i64> = execute_overfetch_page(
            &t2,
            &q,
            200,
            |_cands| async { Ok(Vec::new()) },
            || async { Ok(vec![42]) },
        )
        .await
        .expect("overfetch fallback");
        assert_eq!(page.tier, SearchTier::Tier1Pg);
        assert!(page.degraded);
        assert!(
            page.inspected_candidates <= MAX_OVERFETCH_CANDIDATES,
            "inspected {} exceeded hard cap {}",
            page.inspected_candidates,
            MAX_OVERFETCH_CANDIDATES
        );
        assert_eq!(page.inspected_candidates, MAX_OVERFETCH_CANDIDATES);
        assert_eq!(page.items, vec![42]);
    }
}
