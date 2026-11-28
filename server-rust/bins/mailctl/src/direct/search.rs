//! Direct operator subcommands for Tier-2 search maintenance (`#558`):
//! - `mailctl search rebuild`: online zero-downtime streaming epoch rebuild inside
//!   a single `REPEATABLE READ READ ONLY` MVCC snapshot using keyset pagination,
//!   verified single-chunk Drive SHA checks, historical Drive versions, Chat
//!   attachment extracted text, non-blocking staging (acquiring `rebuild.lock` only
//!   for the atomic `CURRENT` swap), no cross-process deletion of the previous epoch,
//!   and gap-free outbox settlement preserving all concurrent mutations.
//! - `mailctl search verify`: strictly read-only verification of `CURRENT`, schema
//!   hash, all 5 PG corpus watermarks (`wm_epoch == local_epoch && wm_gen <= local_gen`),
//!   unprocessed outbox lag (fail-closed unless `--allow-lag`), extraction status
//!   breakdown, and sampled live + hard-deleted key parity (exits 0 on pass, 1 on fail).

use crate::flags::Flags;
use chrono::{DateTime, Utc};
use serde::Serialize;
use setjoin_pg::operator::OperatorConnection;
use setjoin_pg::Type;
use setjoin_search::{
    chat_revision_doc_id, extract_html_text, normalize_blob_object_key, scheduled_action_doc_id,
    schema_hash, DocCorpus, DocumentKey, IndexDocument, SearchConfig, SearchVisibility,
    StagingEpoch, TantivySearchEngine, DEFAULT_INDEX_DIR, MAX_DOC_BODY_BYTES,
    MAX_EXTRACT_INPUT_BYTES,
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

const ALL_CORPORA: [&str; 5] = ["mail", "mail_attachment", "chat", "drive", "drive_file"];

pub(super) async fn execute(action: &str, args: &[String]) -> Result<i32, String> {
    if action.is_empty() || matches!(action, "-h" | "--help" | "help") {
        print_usage();
        return Ok(0);
    }
    match action {
        "rebuild" => execute_rebuild(args).await,
        "verify" => execute_verify(args).await,
        other => Err(format!(
            "unknown search subcommand {other:?} (expected 'rebuild' or 'verify')"
        )),
    }
}

fn print_usage() {
    println!("mailctl search — online Tier-2 Tantivy search index maintenance");
    println!();
    println!("USAGE:");
    println!(
        "  mailctl search rebuild [--index-dir PATH] [--corpus all] [--batch-size N] [--json] [--quiet]"
    );
    println!(
        "  mailctl search verify  [--index-dir PATH] [--sample N] [--allow-lag] [--json] [--quiet]"
    );
    println!();
    println!("ENVIRONMENT:");
    println!("  DB_WORKER_DSN           PostgreSQL worker DSN (fallback: DB_DSN)");
    println!(
        "  SETJOIN_SEARCH_INDEX_DIR  Tantivy index root directory (default: {DEFAULT_INDEX_DIR})"
    );
}

fn parse_search_args(
    command: &str,
    args: &[String],
    value_flags: &[&str],
    bool_flags: &[&str],
) -> Result<Flags, String> {
    let fs = crate::flags::parse(command, args, value_flags, bool_flags, false);
    if !fs.positional.is_empty() {
        return Err(format!("unexpected argument: {}", fs.positional[0]));
    }
    Ok(fs)
}

async fn search_database() -> Result<OperatorConnection, String> {
    let dsn = std::env::var("DB_WORKER_DSN")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| {
            std::env::var("DB_DSN")
                .ok()
                .filter(|s| !s.trim().is_empty())
        })
        .ok_or_else(|| {
            "missing database DSN: set DB_WORKER_DSN (preferred) or DB_DSN".to_owned()
        })?;
    OperatorConnection::connect(&dsn).await
}

fn resolve_index_dir(fs: &Flags) -> PathBuf {
    let flag_dir = fs.get("index-dir");
    if !flag_dir.is_empty() {
        return PathBuf::from(flag_dir);
    }
    let env_dir = std::env::var("SETJOIN_SEARCH_INDEX_DIR").unwrap_or_default();
    let env_dir = env_dir.trim();
    if !env_dir.is_empty() {
        return PathBuf::from(env_dir);
    }
    PathBuf::from(DEFAULT_INDEX_DIR)
}

#[derive(Serialize)]
struct RebuildReport {
    ok: bool,
    index_dir: String,
    epoch: u64,
    generation: u64,
    schema_hash: String,
    baseline_outbox_seq: i64,
    docs_indexed: usize,
    mail_docs: usize,
    mail_attachment_docs: usize,
    chat_docs: usize,
    chat_revision_docs: usize,
    scheduled_action_docs: usize,
    drive_docs: usize,
    drive_file_docs: usize,
    stale_epochs_removed: usize,
}

fn flush_bounded_batches(
    staging: &mut StagingEpoch,
    docs: &mut Vec<IndexDocument>,
) -> Result<(), String> {
    const MAX_DOCS: usize = 500;
    const MAX_BYTES: usize = 8_000_000;
    if docs.is_empty() {
        return Ok(());
    }
    let mut chunk: Vec<IndexDocument> = Vec::new();
    let mut chunk_bytes = 0usize;
    for mut doc in docs.drain(..) {
        if let Some(ref mut b) = doc.body {
            if b.len() > MAX_DOC_BODY_BYTES {
                let mut end = MAX_DOC_BODY_BYTES;
                while end > 0 && !b.is_char_boundary(end) {
                    end -= 1;
                }
                b.truncate(end);
            }
        }
        let est = doc.title.len()
            + doc.sort_name.len()
            + doc.body.as_ref().map_or(0, String::len)
            + doc.headers.iter().map(String::len).sum::<usize>()
            + doc.identifiers.iter().map(String::len).sum::<usize>();
        if !chunk.is_empty() && (chunk.len() >= MAX_DOCS || chunk_bytes + est > MAX_BYTES) {
            staging
                .add_batch(&chunk)
                .map_err(|e| format!("staging add_batch failed: {e}"))?;
            chunk.clear();
            chunk_bytes = 0;
        }
        chunk_bytes += est;
        chunk.push(doc);
    }
    if !chunk.is_empty() {
        staging
            .add_batch(&chunk)
            .map_err(|e| format!("staging add_batch failed: {e}"))?;
    }
    Ok(())
}

async fn execute_rebuild(args: &[String]) -> Result<i32, String> {
    let fs = parse_search_args(
        "search rebuild",
        args,
        &["index-dir", "corpus", "batch-size", "s3-endpoint"],
        &["json", "quiet"],
    )?;
    let corpus_arg = fs.get("corpus");
    if !corpus_arg.is_empty() && corpus_arg != "all" {
        return Err(format!(
            "unsupported --corpus {corpus_arg:?}: online epoch-swap rebuild requires --corpus=all so other corpora are never wiped from CURRENT"
        ));
    }
    let batch_size: i64 = {
        let raw = fs.get("batch-size");
        if raw.is_empty() {
            500
        } else {
            raw.parse::<i64>()
                .map_err(|_| format!("invalid --batch-size: {raw:?}"))?
                .clamp(10, 1000)
        }
    };
    let index_dir = resolve_index_dir(&fs);
    let s3_endpoint_flag = fs.get("s3-endpoint");
    let blob_store = optional_blob_store(s3_endpoint_flag);
    let json_out = fs.boolean("json");
    let quiet = fs.boolean("quiet");

    let db = search_database().await?;

    // 1. Ensure watermark rows exist before opening the REPEATABLE READ snapshot.
    let _ = db
        .query(
            "INSERT INTO public.search_index_watermarks \
                 (corpus, epoch, generation, indexed_outbox_seq, schema_hash) \
             VALUES ('mail', 0, 0, 0, ''), \
                    ('mail_attachment', 0, 0, 0, ''), \
                    ('chat', 0, 0, 0, ''), \
                    ('drive', 0, 0, 0, ''), \
                    ('drive_file', 0, 0, 0, '') \
             ON CONFLICT (corpus) DO NOTHING",
            &[],
        )
        .await?;

    // 2. Open a single REPEATABLE READ READ ONLY transaction so EVERY source scan,
    //    the exact MVCC snapshot (`pg_current_snapshot()`), and the captured visible
    //    outbox sequences come from ONE atomic MVCC snapshot.
    let _ = db
        .query(
            "BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY",
            &[],
        )
        .await?;

    let snapshot_result =
        run_snapshot_rebuild(&db, &index_dir, batch_size, blob_store.as_ref()).await;
    let _ = db.query("COMMIT", &[]).await;

    let (engine, staging, visible_unprocessed_seqs, snapshot_max_seq, snapshot_text, counts) =
        snapshot_result?;

    let docs_indexed = staging.docs_added();
    // Atomically swap CURRENT (acquiring rebuild.lock ONLY for authoritative epoch assignment,
    // rename from private staging dir, and CURRENT swap) WITHOUT deleting the previous epoch
    // directory so any live gateway readers finish safely on their open handles.
    let manifest = engine
        .commit_rebuild_online(staging, Some(Utc::now()))
        .map_err(|e| format!("commit online rebuild: {e}"))?;

    // 3. Inside ONE settlement transaction AFTER `CURRENT` points to `v{next_epoch}`:
    //    (a) mark ONLY the exact outbox rows that were visible inside our REPEATABLE READ snapshot;
    //    (b) re-queue (`processed_at = NULL`) EVERY outbox row committed AFTER our MVCC snapshot
    //        (including rows processed on the old epoch before `CURRENT` swapped!) so ZERO live
    //        updates are ever lost across an online rebuild;
    //    (c) compute exact gap-free contiguous watermarks and advance all 5 `search_index_watermarks`.
    let _ = db.query("BEGIN", &[]).await?;
    let settle_res: Result<i64, String> = async {
        // Lock all watermark rows FIRST in deterministic order so any concurrent epoch-fenced
        // writer taking FOR SHARE on `search_index_watermarks` serializes strictly before our
        // outbox re-queue pass or observes the new epoch after commit.
        let _ = db
            .query(
                "SELECT corpus FROM public.search_index_watermarks ORDER BY corpus FOR UPDATE",
                &[],
            )
            .await?;

        if !visible_unprocessed_seqs.is_empty() {
            for chunk in visible_unprocessed_seqs.chunks(10_000) {
                let chunk_vec = chunk.to_vec();
                let _ = db
                    .query(
                        "UPDATE public.search_index_outbox \
                            SET processed_at = now() \
                          WHERE seq = ANY($1::bigint[]) AND processed_at IS NULL",
                        &[(&chunk_vec, Type::INT8_ARRAY)],
                    )
                    .await?;
            }
        }

        // Re-queue any outbox row committed outside our MVCC snapshot that was already marked
        // processed against the superseded epoch before `CURRENT` swapped.
        let _ = db
            .query(
                "UPDATE public.search_index_outbox \
                    SET processed_at = NULL \
                  WHERE processed_at IS NOT NULL \
                    AND (seq > $1 \
                         OR (txid IS NOT NULL \
                             AND NOT pg_catalog.pg_visible_in_snapshot(txid, $2::pg_snapshot)))",
                &[
                    (&snapshot_max_seq, Type::INT8),
                    (&snapshot_text, Type::TEXT),
                ],
            )
            .await?;

        let epoch_i64 = i64::try_from(manifest.epoch).unwrap_or(i64::MAX);
        let gen_i64 = i64::try_from(manifest.generation).unwrap_or(i64::MAX);
        let mut min_committed_seq = snapshot_max_seq;
        for corpus in ALL_CORPORA {
            let gap_rows = db
                .query(
                    "SELECT COALESCE( \
                       (SELECT MIN(o.seq) - 1 FROM public.search_index_outbox o \
                         WHERE o.corpus = $1 AND o.processed_at IS NULL AND o.seq <= $2), \
                       $2 \
                     )::bigint",
                    &[(&corpus, Type::TEXT), (&snapshot_max_seq, Type::INT8)],
                )
                .await?;
            let contiguous_seq: i64 = gap_rows
                .first()
                .and_then(|r| r.try_get(0).ok())
                .unwrap_or(0)
                .max(0);
            min_committed_seq = min_committed_seq.min(contiguous_seq);
            let _ = db
                .query(
                    "SELECT corpus FROM public.search_watermark_advance($1, $2, $3, $4, $5)",
                    &[
                        (&corpus, Type::TEXT),
                        (&epoch_i64, Type::INT8),
                        (&gen_i64, Type::INT8),
                        (&contiguous_seq, Type::INT8),
                        (&manifest.schema_hash, Type::TEXT),
                    ],
                )
                .await?;
        }
        Ok(min_committed_seq)
    }
    .await;

    let min_committed_seq = match settle_res {
        Ok(seq) => {
            let _ = db.query("COMMIT", &[]).await?;
            seq
        }
        Err(err) => {
            let _ = db.query("ROLLBACK", &[]).await;
            return Err(err);
        }
    };

    let report = RebuildReport {
        ok: true,
        index_dir: index_dir.display().to_string(),
        epoch: manifest.epoch,
        generation: manifest.generation,
        schema_hash: manifest.schema_hash,
        baseline_outbox_seq: min_committed_seq,
        docs_indexed,
        mail_docs: counts.mail_docs,
        mail_attachment_docs: counts.mail_attachment_docs,
        chat_docs: counts.chat_docs,
        chat_revision_docs: counts.chat_revision_docs,
        scheduled_action_docs: counts.scheduled_action_docs,
        drive_docs: counts.drive_docs,
        drive_file_docs: counts.drive_file_docs,
        stale_epochs_removed: 0,
    };

    if !quiet {
        if json_out {
            println!(
                "{}",
                serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?
            );
        } else {
            println!(
                "Rebuilt search epoch v{:06} (generation={}, docs={}, baseline_outbox_seq={})",
                report.epoch, report.generation, report.docs_indexed, report.baseline_outbox_seq
            );
        }
    }
    Ok(0)
}

#[derive(Default)]
struct RebuildCounts {
    mail_docs: usize,
    mail_attachment_docs: usize,
    chat_docs: usize,
    chat_revision_docs: usize,
    scheduled_action_docs: usize,
    drive_docs: usize,
    drive_file_docs: usize,
}

fn optional_blob_store(s3_endpoint_flag: &str) -> Option<setjoin_backup::store::Store> {
    let env_nonempty = |k: &str| std::env::var(k).ok().filter(|s| !s.trim().is_empty());
    let provider = env_nonempty("STORAGE_PROVIDER").unwrap_or_default();
    let endpoint = if !s3_endpoint_flag.trim().is_empty() {
        s3_endpoint_flag.trim().to_owned()
    } else if let Some(ep) = env_nonempty("S3_ENDPOINT").or_else(|| env_nonempty("MINIO_ENDPOINT"))
    {
        ep
    } else if provider == "posix" {
        String::new()
    } else {
        return None;
    };
    let bucket = env_nonempty("S3_BUCKET")
        .or_else(|| env_nonempty("MINIO_BUCKET"))
        .unwrap_or_else(|| "mailblobs".to_owned());
    let region = env_nonempty("S3_REGION").unwrap_or_else(|| "us-east-1".to_owned());
    let access = env_nonempty("S3_ACCESS_KEY")
        .or_else(|| env_nonempty("MINIO_ACCESS_KEY"))
        .unwrap_or_default();
    let secret = env_nonempty("S3_SECRET_KEY")
        .or_else(|| env_nonempty("MINIO_SECRET_KEY"))
        .unwrap_or_default();
    setjoin_backup::store::Store::driver(&provider, &endpoint, &region, &bucket, &access, &secret)
        .ok()
}

/// Verify multi-chunk Drive file version whole-file SHA-256 against `drive_file_versions.content_sha256`
/// (matching `pipeline.rs:443`) so verified multi-chunk extracted text is preserved during rebuild
/// while spoofed `content_sha256` values can never read or poison shared cache rows.
async fn verify_multi_chunk_version_sha(
    db: &OperatorConnection,
    store: Option<&setjoin_backup::store::Store>,
    cache: &mut HashMap<i64, bool>,
    version_id: i64,
    claimed_sha: &str,
) -> Result<bool, String> {
    if let Some(&verified) = cache.get(&version_id) {
        return Ok(verified);
    }
    let Some(store) = store else {
        cache.insert(version_id, false);
        return Ok(false);
    };
    let chunk_rows = db
        .query(
            "SELECT vc.chunk_sha256, dc.storage_ref \
               FROM public.drive_version_chunks vc \
               JOIN public.drive_chunks dc \
                 ON dc.scope_key = vc.scope_key AND dc.sha256 = vc.chunk_sha256 \
              WHERE vc.version_id = $1 AND vc.stream = 'content' \
              ORDER BY vc.ordinal ASC",
            &[(&version_id, Type::INT8)],
        )
        .await?;
    if chunk_rows.is_empty() {
        cache.insert(version_id, false);
        return Ok(false);
    }
    let mut hasher = Sha256::new();
    let mut total_bytes: usize = 0;
    for crow in &chunk_rows {
        let chunk_sha: String = crow
            .try_get(0)
            .map_err(|e| format!("decode drive chunk sha256: {e}"))?;
        let storage_ref: String = crow
            .try_get(1)
            .map_err(|e| format!("decode drive chunk storage_ref: {e}"))?;
        let remaining = MAX_EXTRACT_INPUT_BYTES.saturating_sub(total_bytes);
        if remaining == 0 {
            cache.insert(version_id, false);
            return Ok(false);
        }
        let key = normalize_blob_object_key(&chunk_sha, &storage_ref);
        let Ok(bytes) = store.get(&key, remaining).await else {
            cache.insert(version_id, false);
            return Ok(false);
        };
        total_bytes = total_bytes.saturating_add(bytes.len());
        hasher.update(&bytes);
    }
    let digest = hasher.finalize();
    let actual_sha: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    let ok = actual_sha.eq_ignore_ascii_case(claimed_sha);
    cache.insert(version_id, ok);
    Ok(ok)
}

async fn run_snapshot_rebuild(
    db: &OperatorConnection,
    index_dir: &Path,
    batch_size: i64,
    blob_store: Option<&setjoin_backup::store::Store>,
) -> Result<
    (
        TantivySearchEngine,
        StagingEpoch,
        Vec<i64>,
        i64,
        String,
        RebuildCounts,
    ),
    String,
> {
    let snap_rows = db
        .query(
            "SELECT COALESCE(MAX(seq), 0)::bigint, pg_catalog.pg_current_snapshot()::text \
               FROM public.search_index_outbox",
            &[],
        )
        .await?;
    let snapshot_max_seq: i64 = snap_rows
        .first()
        .and_then(|r| r.try_get(0).ok())
        .unwrap_or(0);
    let snapshot_text: String = snap_rows
        .first()
        .and_then(|r| r.try_get(1).ok())
        .ok_or_else(|| "failed to capture pg_current_snapshot()".to_owned())?;
    let mut verified_multi_chunk_versions: HashMap<i64, bool> = HashMap::new();

    // Capture exact unprocessed outbox seqs visible inside this REPEATABLE READ snapshot.
    let mut visible_unprocessed_seqs: Vec<i64> = Vec::new();
    let mut last_seq: i64 = 0;
    loop {
        let rows = db
            .query(
                "SELECT seq FROM public.search_index_outbox \
                  WHERE processed_at IS NULL AND seq > $1 \
                  ORDER BY seq ASC LIMIT 5000",
                &[(&last_seq, Type::INT8)],
            )
            .await?;
        if rows.is_empty() {
            break;
        }
        let fetched = rows.len();
        for r in &rows {
            let s: i64 = r
                .try_get(0)
                .map_err(|e| format!("decode outbox seq: {e}"))?;
            last_seq = s;
            visible_unprocessed_seqs.push(s);
        }
        if fetched < 5000 {
            break;
        }
    }

    let pg_epoch_rows = db
        .query(
            "SELECT COALESCE(MAX(epoch), 0)::bigint FROM public.search_index_watermarks",
            &[],
        )
        .await?;
    let pg_max_epoch: u64 = pg_epoch_rows
        .first()
        .and_then(|r| r.try_get::<_, i64>(0).ok())
        .and_then(|v| u64::try_from(v).ok())
        .unwrap_or(0);

    let cfg = SearchConfig {
        tier2_enabled: true,
        index_dir: index_dir.to_path_buf(),
        ..SearchConfig::default()
    };
    let engine = TantivySearchEngine::open_or_degraded(cfg);
    let mut staging = engine
        .begin_rebuild_at_min_epoch(pg_max_epoch.saturating_add(1))
        .map_err(|e| format!("begin online rebuild: {e}"))?;

    let mut counts = RebuildCounts::default();
    let mut pending: Vec<IndexDocument> = Vec::new();

    // 1. Stream Mail + MailAttachment using keyset pagination on (received_at, id).
    {
        let mut last_ts: Option<DateTime<Utc>> = None;
        let mut last_id: i64 = 0;
        loop {
            let rows = db
                .query(
                    "SELECT m.mailbox_id, m.id, m.received_at, coalesce(m.subject, ''), \
                            m.from_addr, coalesce(m.from_name, ''), coalesce(m.body_text, ''), \
                            coalesce(m.body_html, ''), m.is_deleted, m.held, \
                            coalesce(m.crypto_type = 'smime-encrypted', false) \
                       FROM public.messages m \
                      WHERE NOT (m.is_deleted = true AND m.held = false) \
                        AND ($1::timestamptz IS NULL OR (m.received_at, m.id) > ($1, $2)) \
                      ORDER BY m.received_at ASC, m.id ASC \
                      LIMIT $3",
                    &[
                        (&last_ts, Type::TIMESTAMPTZ),
                        (&last_id, Type::INT8),
                        (&batch_size, Type::INT8),
                    ],
                )
                .await?;
            if rows.is_empty() {
                break;
            }
            let fetched = rows.len() as i64;
            for row in &rows {
                let mailbox_id: i64 = row
                    .try_get(0)
                    .map_err(|e| format!("decode mail mailbox_id: {e}"))?;
                let id: i64 = row.try_get(1).map_err(|e| format!("decode mail id: {e}"))?;
                let received_at: DateTime<Utc> = row
                    .try_get(2)
                    .map_err(|e| format!("decode mail received_at: {e}"))?;
                last_ts = Some(received_at);
                last_id = id;
                let subject: String = row
                    .try_get(3)
                    .map_err(|e| format!("decode mail subject: {e}"))?;
                let from_addr: String = row
                    .try_get(4)
                    .map_err(|e| format!("decode mail from_addr: {e}"))?;
                let from_name: String = row
                    .try_get(5)
                    .map_err(|e| format!("decode mail from_name: {e}"))?;
                let body_text: String = row
                    .try_get(6)
                    .map_err(|e| format!("decode mail body_text: {e}"))?;
                let body_html: String = row
                    .try_get(7)
                    .map_err(|e| format!("decode mail body_html: {e}"))?;
                let is_deleted: bool = row
                    .try_get(8)
                    .map_err(|e| format!("decode mail is_deleted: {e}"))?;
                let held: bool = row
                    .try_get(9)
                    .map_err(|e| format!("decode mail held: {e}"))?;
                let crypto_sealed: bool = row
                    .try_get(10)
                    .map_err(|e| format!("decode mail crypto_sealed: {e}"))?;

                let visibility = if is_deleted && held {
                    SearchVisibility::ComplianceOnly
                } else {
                    SearchVisibility::Live
                };
                let mut headers = Vec::new();
                if !from_addr.is_empty() {
                    headers.push(from_addr.clone());
                }
                if !from_name.is_empty() {
                    headers.push(from_name.clone());
                }
                let mut identifiers = Vec::new();
                if !from_addr.is_empty() {
                    identifiers.push(from_addr);
                }

                let mut combined_body = if crypto_sealed {
                    String::new()
                } else if !body_text.trim().is_empty() {
                    body_text
                } else if !body_html.trim().is_empty() {
                    extract_html_text(&body_html)
                } else {
                    String::new()
                };

                let att_rows = db
                    .query(
                        "SELECT ma.id, coalesce(ma.filename, ''), et.extraction_status, et.extracted_text \
                           FROM public.message_attachments ma \
                           LEFT JOIN public.search_extracted_text et \
                             ON et.content_sha256 = ma.blob_sha256 \
                          WHERE ma.message_id = $1 AND ma.received_at = $2 \
                          ORDER BY ma.id ASC",
                        &[(&id, Type::INT8), (&received_at, Type::TIMESTAMPTZ)],
                    )
                    .await?;
                for arow in &att_rows {
                    let att_id: i64 = arow.try_get(0).map_err(|e| format!("decode att id: {e}"))?;
                    let filename: String = arow
                        .try_get(1)
                        .map_err(|e| format!("decode att filename: {e}"))?;
                    let status_opt: Option<String> = arow
                        .try_get(2)
                        .map_err(|e| format!("decode att status: {e}"))?;
                    let text_opt: Option<String> = arow
                        .try_get(3)
                        .map_err(|e| format!("decode att text: {e}"))?;
                    let idx_text = if crypto_sealed {
                        None
                    } else if matches!(status_opt.as_deref(), Some("extracted" | "truncated_limit"))
                    {
                        text_opt
                    } else {
                        None
                    };
                    if !crypto_sealed {
                        if !filename.is_empty() {
                            identifiers.push(filename.clone());
                            headers.push(filename.clone());
                        }
                        if let Some(ref txt) = idx_text {
                            if !txt.is_empty() {
                                if !combined_body.is_empty() {
                                    combined_body.push('\n');
                                }
                                combined_body.push_str(txt);
                            }
                        }
                    }
                    pending.push(IndexDocument {
                        key: DocumentKey::MailAttachment {
                            mailbox_id,
                            id,
                            received_at,
                            sub_id: att_id,
                        },
                        visibility,
                        title: if crypto_sealed {
                            String::new()
                        } else {
                            filename.clone()
                        },
                        body: idx_text,
                        headers: if crypto_sealed {
                            Vec::new()
                        } else {
                            headers.clone()
                        },
                        identifiers: if crypto_sealed || filename.is_empty() {
                            Vec::new()
                        } else {
                            vec![filename.clone()]
                        },
                        sort_i64: received_at.timestamp_micros(),
                        sort_name: if crypto_sealed {
                            String::new()
                        } else {
                            filename
                        },
                        crypto_sealed,
                    });
                    counts.mail_attachment_docs += 1;
                }

                pending.push(IndexDocument {
                    key: DocumentKey::Mail {
                        mailbox_id,
                        id,
                        received_at,
                    },
                    visibility,
                    title: subject.clone(),
                    body: if crypto_sealed || combined_body.is_empty() {
                        None
                    } else {
                        Some(combined_body)
                    },
                    headers,
                    identifiers,
                    sort_i64: received_at.timestamp_micros(),
                    sort_name: subject,
                    crypto_sealed,
                });
                counts.mail_docs += 1;
                if pending.len() >= 250 {
                    flush_bounded_batches(&mut staging, &mut pending)?;
                }
            }
            flush_bounded_batches(&mut staging, &mut pending)?;
            if fetched < batch_size {
                break;
            }
        }
    }

    // 2. Stream Chat messages + historical chat_message_revisions + verified Chat attachment text.
    {
        let mut last_id: i64 = 0;
        loop {
            let rows = db
                .query(
                    "SELECT cm.id, cm.channel_id, cm.body, cm.deleted_at, cm.created_at \
                       FROM public.chat_messages cm \
                      WHERE cm.id > $1 \
                      ORDER BY cm.id ASC \
                      LIMIT $2",
                    &[(&last_id, Type::INT8), (&batch_size, Type::INT8)],
                )
                .await?;
            if rows.is_empty() {
                break;
            }
            let fetched = rows.len() as i64;
            for row in &rows {
                let id: i64 = row.try_get(0).map_err(|e| format!("decode chat id: {e}"))?;
                last_id = id;
                let channel_id: i64 = row
                    .try_get(1)
                    .map_err(|e| format!("decode chat channel_id: {e}"))?;
                let mut body: String = row
                    .try_get(2)
                    .map_err(|e| format!("decode chat body: {e}"))?;
                let deleted_at: Option<DateTime<Utc>> = row
                    .try_get(3)
                    .map_err(|e| format!("decode chat deleted_at: {e}"))?;
                let created_at: DateTime<Utc> = row
                    .try_get(4)
                    .map_err(|e| format!("decode chat created_at: {e}"))?;

                let visibility = if deleted_at.is_some() {
                    SearchVisibility::ComplianceOnly
                } else {
                    SearchVisibility::Live
                };

                // Historical revisions -> strictly ComplianceOnly under negative chat_revision_doc_id.
                let rev_rows = db
                    .query(
                        "SELECT r.prior_body FROM public.chat_message_revisions r \
                          WHERE r.message_id = $1 ORDER BY r.id ASC",
                        &[(&id, Type::INT8)],
                    )
                    .await?;
                let mut rev_parts = Vec::new();
                for rrow in &rev_rows {
                    let prior: String = rrow
                        .try_get(0)
                        .map_err(|e| format!("decode chat rev prior_body: {e}"))?;
                    if !prior.trim().is_empty() {
                        rev_parts.push(prior);
                    }
                }
                if !rev_parts.is_empty() {
                    pending.push(IndexDocument {
                        key: DocumentKey::Chat {
                            channel_id,
                            id: chat_revision_doc_id(id),
                        },
                        visibility: SearchVisibility::ComplianceOnly,
                        title: String::new(),
                        body: Some(rev_parts.join("\n")),
                        headers: Vec::new(),
                        identifiers: vec![format!("chat_rev:{id}")],
                        sort_i64: created_at.timestamp_micros(),
                        sort_name: String::new(),
                        crypto_sealed: false,
                    });
                    counts.chat_revision_docs += 1;
                }

                // Chat attachments: filename + single-chunk OR store-verified multi-chunk extracted text.
                let att_rows = db
                    .query(
                        "SELECT cma.filename, dfv.id, dfv.content_sha256, \
                                COALESCE(( \
                                  SELECT count(*) = 1 AND min(vc.chunk_sha256) = dfv.content_sha256 \
                                    FROM public.drive_version_chunks vc \
                                    JOIN public.drive_chunks dc \
                                      ON dc.scope_key = vc.scope_key AND dc.sha256 = vc.chunk_sha256 \
                                   WHERE vc.version_id = dfv.id AND vc.stream = 'content' \
                                ), false) AS single_chunk_ok, \
                                et.extraction_status, et.extracted_text \
                           FROM public.chat_message_attachments cma \
                           LEFT JOIN public.drive_file_versions dfv ON dfv.id = cma.version_id \
                           LEFT JOIN public.search_extracted_text et \
                             ON et.content_sha256 = dfv.content_sha256 \
                          WHERE cma.message_id = $1 \
                          ORDER BY cma.ordinal ASC, cma.id ASC",
                        &[(&id, Type::INT8)],
                    )
                    .await?;
                let mut headers = Vec::new();
                let mut identifiers = Vec::new();
                for arow in &att_rows {
                    let fname: String = arow
                        .try_get(0)
                        .map_err(|e| format!("decode chat att filename: {e}"))?;
                    let vid_opt: Option<i64> = arow
                        .try_get(1)
                        .map_err(|e| format!("decode chat att version_id: {e}"))?;
                    let sha_opt: Option<String> = arow
                        .try_get(2)
                        .map_err(|e| format!("decode chat att sha: {e}"))?;
                    let single_chunk_ok: bool = arow
                        .try_get(3)
                        .map_err(|e| format!("decode chat att single_chunk_ok: {e}"))?;
                    let st_opt: Option<String> = arow
                        .try_get(4)
                        .map_err(|e| format!("decode chat att status: {e}"))?;
                    let txt_opt: Option<String> = arow
                        .try_get(5)
                        .map_err(|e| format!("decode chat att text: {e}"))?;
                    if !fname.is_empty() {
                        headers.push(fname.clone());
                        identifiers.push(fname);
                    }
                    if matches!(st_opt.as_deref(), Some("extracted" | "truncated_limit")) {
                        let verified = if single_chunk_ok {
                            true
                        } else if let (Some(vid), Some(sha)) = (vid_opt, sha_opt.as_deref()) {
                            verify_multi_chunk_version_sha(
                                db,
                                blob_store,
                                &mut verified_multi_chunk_versions,
                                vid,
                                sha,
                            )
                            .await?
                        } else {
                            false
                        };
                        if verified {
                            if let Some(txt) = txt_opt.filter(|t| !t.trim().is_empty()) {
                                if !body.is_empty() {
                                    body.push('\n');
                                }
                                body.push_str(&txt);
                            }
                        }
                    }
                }

                pending.push(IndexDocument {
                    key: DocumentKey::Chat { channel_id, id },
                    visibility,
                    title: headers.first().cloned().unwrap_or_default(),
                    body: if body.is_empty() { None } else { Some(body) },
                    headers,
                    identifiers,
                    sort_i64: created_at.timestamp_micros(),
                    sort_name: String::new(),
                    crypto_sealed: false,
                });
                counts.chat_docs += 1;
                if pending.len() >= 250 {
                    flush_bounded_batches(&mut staging, &mut pending)?;
                }
            }
            flush_bounded_batches(&mut staging, &mut pending)?;
            if fetched < batch_size {
                break;
            }
        }
    }

    // 3. Stream pending/enqueued/processing/failed scheduled_actions using keyset
    //    pagination on (updated_at, id) as ComplianceOnly.
    {
        let mut last_updated_at: Option<DateTime<Utc>> = None;
        let mut last_id: String = String::new();
        loop {
            let srows = db
                .query(
                    "SELECT id::text, action_kind, fire_at, payload::text, mailbox_id, updated_at \
                       FROM public.scheduled_actions \
                      WHERE status IN ('pending', 'enqueued', 'processing', 'failed') \
                        AND ($1::timestamptz IS NULL \
                             OR (updated_at, id::text) > ($1, $2)) \
                      ORDER BY updated_at ASC, id::text ASC \
                      LIMIT $3",
                    &[
                        (&last_updated_at, Type::TIMESTAMPTZ),
                        (&last_id, Type::TEXT),
                        (&batch_size, Type::INT8),
                    ],
                )
                .await?;
            if srows.is_empty() {
                break;
            }
            let fetched = srows.len() as i64;
            for row in &srows {
                let id_str: String = row
                    .try_get(0)
                    .map_err(|e| format!("decode sched id: {e}"))?;
                let action_kind: String = row
                    .try_get(1)
                    .map_err(|e| format!("decode sched kind: {e}"))?;
                let fire_at: DateTime<Utc> = row
                    .try_get(2)
                    .map_err(|e| format!("decode sched fire_at: {e}"))?;
                let payload_text: String = row
                    .try_get(3)
                    .map_err(|e| format!("decode sched payload: {e}"))?;
                let mailbox_id: Option<i64> = row
                    .try_get(4)
                    .map_err(|e| format!("decode sched mailbox_id: {e}"))?;
                let updated_at: DateTime<Utc> = row
                    .try_get(5)
                    .map_err(|e| format!("decode sched updated_at: {e}"))?;
                last_updated_at = Some(updated_at);
                last_id = id_str.clone();
                let payload_json: serde_json::Value =
                    serde_json::from_str(&payload_text).unwrap_or(serde_json::Value::Null);
                let is_chat = action_kind.to_ascii_lowercase().contains("chat")
                    || payload_json.get("channelId").is_some()
                    || payload_json.get("channel_id").is_some();
                let neg_id = scheduled_action_doc_id(&id_str);
                let doc_key = if is_chat {
                    let ch = payload_json
                        .get("channelId")
                        .or_else(|| payload_json.get("channel_id"))
                        .and_then(|v| {
                            v.as_i64()
                                .or_else(|| v.as_str().and_then(|s| s.parse::<i64>().ok()))
                        })
                        .unwrap_or(0);
                    DocumentKey::Chat {
                        channel_id: ch,
                        id: neg_id,
                    }
                } else {
                    let mb = mailbox_id.unwrap_or(0);
                    DocumentKey::Mail {
                        mailbox_id: mb,
                        id: neg_id,
                        received_at: fire_at,
                    }
                };
                let subject = payload_json
                    .get("subject")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or(&action_kind)
                    .to_owned();
                pending.push(IndexDocument {
                    key: doc_key,
                    visibility: SearchVisibility::ComplianceOnly,
                    title: subject.clone(),
                    body: Some(payload_text),
                    headers: vec![action_kind.clone()],
                    identifiers: vec![id_str, action_kind],
                    sort_i64: fire_at.timestamp_micros(),
                    sort_name: subject,
                    crypto_sealed: false,
                });
                counts.scheduled_action_docs += 1;
                if pending.len() >= 250 {
                    flush_bounded_batches(&mut staging, &mut pending)?;
                }
            }
            flush_bounded_batches(&mut staging, &mut pending)?;
            if fetched < batch_size {
                break;
            }
        }
    }

    // 4. Stream Drive nodes + ALL file versions (head + historical ComplianceOnly) using
    //    single-chunk SHA verification (`drive_version_chunks` + `drive_chunks`) so spoofed
    //    client `content_sha256` values can NEVER poison extracted text.
    {
        let mut last_id: i64 = 0;
        loop {
            let rows = db
                .query(
                    "SELECT dn.id, dn.space_id, dn.name, dn.deleted_at, dn.created_at, \
                            df.head_version_id \
                       FROM public.drive_nodes dn \
                       LEFT JOIN public.drive_files df ON df.node_id = dn.id \
                      WHERE dn.purged_at IS NULL AND dn.id > $1 \
                      ORDER BY dn.id ASC \
                      LIMIT $2",
                    &[(&last_id, Type::INT8), (&batch_size, Type::INT8)],
                )
                .await?;
            if rows.is_empty() {
                break;
            }
            let fetched = rows.len() as i64;
            for row in &rows {
                let id: i64 = row
                    .try_get(0)
                    .map_err(|e| format!("decode drive id: {e}"))?;
                last_id = id;
                let space_id: i64 = row
                    .try_get(1)
                    .map_err(|e| format!("decode drive space_id: {e}"))?;
                let name: String = row
                    .try_get(2)
                    .map_err(|e| format!("decode drive name: {e}"))?;
                let deleted_at: Option<DateTime<Utc>> = row
                    .try_get(3)
                    .map_err(|e| format!("decode drive deleted_at: {e}"))?;
                let created_at: DateTime<Utc> = row
                    .try_get(4)
                    .map_err(|e| format!("decode drive created_at: {e}"))?;
                let head_vid: Option<i64> = row
                    .try_get(5)
                    .map_err(|e| format!("decode drive head_version_id: {e}"))?;

                let node_vis = if deleted_at.is_some() {
                    SearchVisibility::ComplianceOnly
                } else {
                    SearchVisibility::Live
                };
                let idents = if name.is_empty() {
                    Vec::new()
                } else {
                    vec![name.clone()]
                };

                // Load ALL versions (head + historical) with strict single-chunk OR
                // object-store-verified multi-chunk whole-file SHA verification.
                let ver_rows = db
                    .query(
                        "SELECT dfv.id, dfv.content_sha256, \
                                COALESCE(( \
                                  SELECT count(*) = 1 AND min(vc.chunk_sha256) = dfv.content_sha256 \
                                    FROM public.drive_version_chunks vc \
                                    JOIN public.drive_chunks dc \
                                      ON dc.scope_key = vc.scope_key AND dc.sha256 = vc.chunk_sha256 \
                                   WHERE vc.version_id = dfv.id AND vc.stream = 'content' \
                                ), false) AS single_chunk_ok, \
                                et.extraction_status, et.extracted_text \
                           FROM public.drive_file_versions dfv \
                           LEFT JOIN public.search_extracted_text et \
                             ON et.content_sha256 = dfv.content_sha256 \
                          WHERE dfv.file_node_id = $1 \
                          ORDER BY dfv.id ASC",
                        &[(&id, Type::INT8)],
                    )
                    .await?;

                let mut head_text: Option<String> = None;
                for vrow in &ver_rows {
                    let vid: i64 = vrow
                        .try_get(0)
                        .map_err(|e| format!("decode drive version id: {e}"))?;
                    let sha_opt: Option<String> = vrow
                        .try_get(1)
                        .map_err(|e| format!("decode drive version sha: {e}"))?;
                    let single_chunk_ok: bool = vrow
                        .try_get(2)
                        .map_err(|e| format!("decode drive version single_chunk_ok: {e}"))?;
                    let status_opt: Option<String> = vrow
                        .try_get(3)
                        .map_err(|e| format!("decode drive version status: {e}"))?;
                    let text_opt: Option<String> = vrow
                        .try_get(4)
                        .map_err(|e| format!("decode drive version text: {e}"))?;
                    let ver_text =
                        if matches!(status_opt.as_deref(), Some("extracted" | "truncated_limit")) {
                            let verified = if single_chunk_ok {
                                true
                            } else if let Some(sha) = sha_opt.as_deref() {
                                verify_multi_chunk_version_sha(
                                    db,
                                    blob_store,
                                    &mut verified_multi_chunk_versions,
                                    vid,
                                    sha,
                                )
                                .await?
                            } else {
                                false
                            };
                            if verified {
                                text_opt
                            } else {
                                None
                            }
                        } else {
                            None
                        };
                    let is_head = head_vid == Some(vid);
                    if is_head {
                        head_text = ver_text.clone();
                    }
                    let ver_vis = if is_head {
                        node_vis
                    } else {
                        SearchVisibility::ComplianceOnly
                    };
                    pending.push(IndexDocument {
                        key: DocumentKey::DriveFile {
                            space_id,
                            id,
                            sub_id: vid,
                        },
                        visibility: ver_vis,
                        title: name.clone(),
                        body: ver_text,
                        headers: Vec::new(),
                        identifiers: idents.clone(),
                        sort_i64: created_at.timestamp_micros(),
                        sort_name: name.clone(),
                        crypto_sealed: false,
                    });
                    counts.drive_file_docs += 1;
                }

                pending.push(IndexDocument {
                    key: DocumentKey::Drive { space_id, id },
                    visibility: node_vis,
                    title: name.clone(),
                    body: head_text,
                    headers: Vec::new(),
                    identifiers: idents,
                    sort_i64: created_at.timestamp_micros(),
                    sort_name: name,
                    crypto_sealed: false,
                });
                counts.drive_docs += 1;
                if pending.len() >= 250 {
                    flush_bounded_batches(&mut staging, &mut pending)?;
                }
            }
            flush_bounded_batches(&mut staging, &mut pending)?;
            if fetched < batch_size {
                break;
            }
        }
    }

    Ok((
        engine,
        staging,
        visible_unprocessed_seqs,
        snapshot_max_seq,
        snapshot_text,
        counts,
    ))
}

#[derive(Serialize)]
struct VerifyReport {
    ok: bool,
    index_dir: String,
    local_epoch: Option<u64>,
    local_generation: Option<u64>,
    local_schema_hash: Option<String>,
    expected_schema_hash: String,
    schema_matches: bool,
    clean_shutdown: bool,
    num_docs: u64,
    num_segments: usize,
    watermarks_aligned: bool,
    watermark_mismatches: Vec<String>,
    outbox_lag: BTreeMap<String, i64>,
    extraction_statuses: BTreeMap<String, i64>,
    sampled_live_checked: usize,
    missing_live_keys: Vec<String>,
    sampled_deleted_checked: usize,
    stale_deleted_keys: Vec<String>,
    errors: Vec<String>,
}

async fn execute_verify(args: &[String]) -> Result<i32, String> {
    let fs = parse_search_args(
        "search verify",
        args,
        &["index-dir", "sample"],
        &["json", "quiet", "allow-lag"],
    )?;
    let index_dir = resolve_index_dir(&fs);
    let sample_limit: i64 = {
        let raw = fs.get("sample");
        if raw.is_empty() {
            25
        } else {
            raw.parse::<i64>()
                .map_err(|_| format!("invalid --sample: {raw:?}"))?
                .clamp(1, 500)
        }
    };
    let allow_lag = fs.boolean("allow-lag");
    let json_out = fs.boolean("json");
    let quiet = fs.boolean("quiet");

    let expected_schema_hash = schema_hash();
    let cfg = SearchConfig {
        tier2_enabled: true,
        index_dir: index_dir.to_path_buf(),
        ..SearchConfig::default()
    };

    // Strictly read-only open: NEVER runs crash recovery or mutates CURRENT/rebuild.lock!
    let mut errors: Vec<String> = Vec::new();
    let engine_opt = match TantivySearchEngine::open_read_only(cfg) {
        Ok(eng) => Some(eng),
        Err(err) => {
            errors.push(format!("local index read-only open failed: {err}"));
            None
        }
    };
    let inspect = match engine_opt.as_ref() {
        Some(engine) => match engine.inspect_epoch() {
            Ok(stats) => Some(stats),
            Err(err) => {
                errors.push(format!("local index inspection failed: {err}"));
                None
            }
        },
        None => None,
    };

    let mut watermark_mismatches: Vec<String> = Vec::new();
    let mut outbox_lag: BTreeMap<String, i64> = BTreeMap::new();
    let mut extraction_statuses: BTreeMap<String, i64> = BTreeMap::new();
    let mut missing_live_keys: Vec<String> = Vec::new();
    let mut stale_deleted_keys: Vec<String> = Vec::new();
    let mut sampled_live_checked = 0usize;
    let mut sampled_deleted_checked = 0usize;

    let db = search_database().await?;

    // 1. Check ALL 5 PG search_index_watermarks against local CURRENT.
    //    Single-corpus writes advance Tantivy's shared global generation, so require
    //    `wm_epoch == local_epoch` and `wm_gen <= local_gen` (never `wm_gen > local_gen`).
    let wm_rows = db
        .query(
            "SELECT corpus, epoch, generation, indexed_outbox_seq, schema_hash \
               FROM public.search_index_watermarks ORDER BY corpus",
            &[],
        )
        .await?;
    let mut wm_map: HashMap<String, (i64, i64, String)> = HashMap::new();
    for row in &wm_rows {
        let c: String = row.try_get(0).map_err(|e| format!("wm corpus: {e}"))?;
        let ep: i64 = row.try_get(1).map_err(|e| format!("wm epoch: {e}"))?;
        let gn: i64 = row.try_get(2).map_err(|e| format!("wm generation: {e}"))?;
        let sh: String = row.try_get(4).map_err(|e| format!("wm schema_hash: {e}"))?;
        wm_map.insert(c, (ep, gn, sh));
    }

    if let Some(ref stats) = inspect {
        if !stats.schema_matches {
            errors.push(format!(
                "schema_hash mismatch: local={} expected={expected_schema_hash}",
                stats.schema_hash
            ));
        }
        if !stats.clean_shutdown {
            errors.push("local CURRENT manifest has clean_shutdown=false".to_owned());
        }
        let local_ep = i64::try_from(stats.epoch).unwrap_or(i64::MAX);
        let local_gn = i64::try_from(stats.generation).unwrap_or(i64::MAX);
        for required_corpus in ALL_CORPORA {
            match wm_map.get(required_corpus) {
                None => {
                    watermark_mismatches.push(format!(
                        "{required_corpus}: missing watermark row in public.search_index_watermarks"
                    ));
                }
                Some((ep, gn, sh)) => {
                    if *ep != local_ep
                        || *gn > local_gn
                        || (!sh.is_empty() && *sh != stats.schema_hash)
                    {
                        watermark_mismatches.push(format!(
                            "{required_corpus}: pg=(epoch={ep},gen={gn},hash={sh}) incompatible with local=(epoch={local_ep},gen={local_gn},hash={})",
                            stats.schema_hash
                        ));
                    }
                }
            }
        }
    }

    // 2. Measure unprocessed outbox lag per corpus (fail closed unless `--allow-lag`).
    let lag_rows = db
        .query(
            "SELECT corpus, count(*)::bigint \
               FROM public.search_index_outbox \
              WHERE processed_at IS NULL \
              GROUP BY corpus ORDER BY corpus",
            &[],
        )
        .await?;
    let mut total_lag: i64 = 0;
    for row in &lag_rows {
        let c: String = row.try_get(0).map_err(|e| format!("lag corpus: {e}"))?;
        let cnt: i64 = row.try_get(1).map_err(|e| format!("lag count: {e}"))?;
        total_lag = total_lag.saturating_add(cnt);
        outbox_lag.insert(c, cnt);
    }
    if total_lag > 0 && !allow_lag {
        errors.push(format!(
            "unprocessed search_index_outbox lag={total_lag} (pass --allow-lag to tolerate live ingestion backlog)"
        ));
    }

    // 3. Measure extraction status distribution.
    let ext_rows = db
        .query(
            "SELECT extraction_status, count(*)::bigint \
               FROM public.search_extracted_text \
              GROUP BY extraction_status ORDER BY extraction_status",
            &[],
        )
        .await?;
    for row in &ext_rows {
        let st: String = row.try_get(0).map_err(|e| format!("ext status: {e}"))?;
        let cnt: i64 = row.try_get(1).map_err(|e| format!("ext count: {e}"))?;
        extraction_statuses.insert(st, cnt);
    }

    // 4. Sampled PG-vs-Tantivy parity check (live docs present + hard-purged docs absent).
    if let (Some(engine), Some(_)) = (engine_opt.as_ref(), inspect.as_ref()) {
        let mail_rows = db
            .query(
                "SELECT mailbox_id, id, received_at FROM public.messages \
                  WHERE is_deleted = false ORDER BY received_at DESC, id DESC LIMIT $1",
                &[(&sample_limit, Type::INT8)],
            )
            .await?;
        for row in &mail_rows {
            let key = DocumentKey::Mail {
                mailbox_id: row.try_get(0).map_err(|e| format!("sample mail mb: {e}"))?,
                id: row.try_get(1).map_err(|e| format!("sample mail id: {e}"))?,
                received_at: row.try_get(2).map_err(|e| format!("sample mail ts: {e}"))?,
            };
            sampled_live_checked += 1;
            match engine.contains_doc_key(&key) {
                Ok(true) => {}
                Ok(false) => missing_live_keys.push(key.encode_doc_key()),
                Err(err) => errors.push(format!("sample mail lookup failed: {err}")),
            }
        }

        let chat_rows = db
            .query(
                "SELECT channel_id, id FROM public.chat_messages \
                  WHERE deleted_at IS NULL ORDER BY id DESC LIMIT $1",
                &[(&sample_limit, Type::INT8)],
            )
            .await?;
        for row in &chat_rows {
            let key = DocumentKey::Chat {
                channel_id: row.try_get(0).map_err(|e| format!("sample chat ch: {e}"))?,
                id: row.try_get(1).map_err(|e| format!("sample chat id: {e}"))?,
            };
            sampled_live_checked += 1;
            match engine.contains_doc_key(&key) {
                Ok(true) => {}
                Ok(false) => missing_live_keys.push(key.encode_doc_key()),
                Err(err) => errors.push(format!("sample chat lookup failed: {err}")),
            }
        }

        let drive_rows = db
            .query(
                "SELECT space_id, id FROM public.drive_nodes \
                  WHERE deleted_at IS NULL AND purged_at IS NULL ORDER BY id DESC LIMIT $1",
                &[(&sample_limit, Type::INT8)],
            )
            .await?;
        for row in &drive_rows {
            let key = DocumentKey::Drive {
                space_id: row
                    .try_get(0)
                    .map_err(|e| format!("sample drive sp: {e}"))?,
                id: row
                    .try_get(1)
                    .map_err(|e| format!("sample drive id: {e}"))?,
            };
            sampled_live_checked += 1;
            match engine.contains_doc_key(&key) {
                Ok(true) => {}
                Ok(false) => missing_live_keys.push(key.encode_doc_key()),
                Err(err) => errors.push(format!("sample drive lookup failed: {err}")),
            }
        }

        // Check processed hard-delete tombstones whose source rows are gone from PG.
        let del_rows = db
            .query(
                "SELECT o.corpus, o.scope_id, o.entity_id, o.sub_id, o.received_at \
                   FROM public.search_index_outbox o \
                  WHERE o.op = 'delete' AND o.processed_at IS NOT NULL \
                  ORDER BY o.seq DESC LIMIT $1",
                &[(&sample_limit, Type::INT8)],
            )
            .await?;
        for row in &del_rows {
            let corpus_s: String = row.try_get(0).map_err(|e| format!("del corpus: {e}"))?;
            let scope_id: i64 = row.try_get(1).map_err(|e| format!("del scope: {e}"))?;
            let entity_id: i64 = row.try_get(2).map_err(|e| format!("del entity: {e}"))?;
            let sub_id: i64 = row.try_get(3).map_err(|e| format!("del sub: {e}"))?;
            let received_at: Option<DateTime<Utc>> =
                row.try_get(4).map_err(|e| format!("del ts: {e}"))?;
            let key_opt = match DocCorpus::parse(&corpus_s) {
                Some(DocCorpus::Mail) => received_at.map(|ts| DocumentKey::Mail {
                    mailbox_id: scope_id,
                    id: entity_id,
                    received_at: ts,
                }),
                Some(DocCorpus::MailAttachment) => {
                    received_at.map(|ts| DocumentKey::MailAttachment {
                        mailbox_id: scope_id,
                        id: entity_id,
                        received_at: ts,
                        sub_id,
                    })
                }
                Some(DocCorpus::Chat) => Some(DocumentKey::Chat {
                    channel_id: scope_id,
                    id: entity_id,
                }),
                Some(DocCorpus::Drive) => Some(DocumentKey::Drive {
                    space_id: scope_id,
                    id: entity_id,
                }),
                Some(DocCorpus::DriveFile) => Some(DocumentKey::DriveFile {
                    space_id: scope_id,
                    id: entity_id,
                    sub_id,
                }),
                None => None,
            };
            if let Some(key) = key_opt {
                sampled_deleted_checked += 1;
                match engine.contains_doc_key(&key) {
                    Ok(true) => stale_deleted_keys.push(key.encode_doc_key()),
                    Ok(false) => {}
                    Err(err) => errors.push(format!("sample deleted lookup failed: {err}")),
                }
            }
        }
    }

    let watermarks_aligned = watermark_mismatches.is_empty();
    let schema_matches = inspect.as_ref().is_some_and(|s| s.schema_matches);
    let clean_shutdown = inspect.as_ref().is_some_and(|s| s.clean_shutdown);
    let ok = errors.is_empty()
        && schema_matches
        && clean_shutdown
        && watermarks_aligned
        && missing_live_keys.is_empty()
        && stale_deleted_keys.is_empty();

    let report = VerifyReport {
        ok,
        index_dir: index_dir.display().to_string(),
        local_epoch: inspect.as_ref().map(|s| s.epoch),
        local_generation: inspect.as_ref().map(|s| s.generation),
        local_schema_hash: inspect.as_ref().map(|s| s.schema_hash.clone()),
        expected_schema_hash,
        schema_matches,
        clean_shutdown,
        num_docs: inspect.as_ref().map_or(0, |s| s.num_docs),
        num_segments: inspect.as_ref().map_or(0, |s| s.num_segments),
        watermarks_aligned,
        watermark_mismatches,
        outbox_lag,
        extraction_statuses,
        sampled_live_checked,
        missing_live_keys,
        sampled_deleted_checked,
        stale_deleted_keys,
        errors,
    };

    if !quiet {
        if json_out {
            println!(
                "{}",
                serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?
            );
        } else {
            println!(
                "Search index verification: {} (epoch={:?}, generation={}, docs={}, sampled_live={}, missing_live={}, stale_deleted={})",
                if report.ok { "OK" } else { "FAILED" },
                report.local_epoch,
                report.local_generation.unwrap_or(0),
                report.num_docs,
                report.sampled_live_checked,
                report.missing_live_keys.len(),
                report.stale_deleted_keys.len(),
            );
            for err in &report.errors {
                eprintln!("  error: {err}");
            }
            for wm in &report.watermark_mismatches {
                eprintln!("  watermark mismatch: {wm}");
            }
        }
    }

    Ok(if ok { 0 } else { 1 })
}
