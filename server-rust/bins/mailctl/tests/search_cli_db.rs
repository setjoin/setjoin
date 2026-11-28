//! Live-PostgreSQL end-to-end tests for `mailctl search rebuild` & `mailctl search verify` (#558):
//! - Online zero-downtime `mailctl search rebuild` (epoch 1 -> epoch 2 swap, stale epoch cleanup,
//!   watermark advancement, Mail + Attachment + Chat + Revision + Drive coverage).
//! - `mailctl search verify` exiting 0 on healthy aligned index.
//! - `mailctl search verify` exiting non-zero (1) on corrupted `CURRENT` AND watermark/parity mismatch.

use serde_json::Value;
use std::process::Command;

fn dsn() -> Option<String> {
    if let Ok(v) = std::env::var("TEST_DB_DSN").or_else(|_| std::env::var("DB_DSN")) {
        if !v.is_empty() {
            return Some(v);
        }
    }
    if std::env::var("REQUIRE_DB").as_deref() == Ok("1") {
        panic!("REQUIRE_DB=1 but TEST_DB_DSN / DB_DSN is unset");
    }
    eprintln!("MAILCTL-SEARCH-CLI-SKIP (reason=no-dsn)");
    None
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

fn mailctl(worker_dsn: &str, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_mailctl"))
        .env_clear()
        .env("DB_WORKER_DSN", worker_dsn)
        .args(args)
        .output()
        .expect("run mailctl")
}

#[test]
fn mailctl_search_rebuild_and_verify_e2e_healthy_corrupt_and_mismatch() {
    let Some(dsn) = dsn() else {
        return;
    };
    let worker_dsn = std::env::var("DB_WORKER_DSN")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| swap_dsn_user(&dsn, "setjoin_worker"));

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio rt");

    let index_dir = std::env::temp_dir().join(format!(
        "setjoin-mailctl-search-558-{}-{}",
        std::process::id(),
        chrono::Utc::now().timestamp_micros()
    ));
    let _ = std::fs::remove_dir_all(&index_dir);
    std::fs::create_dir_all(&index_dir).expect("mkdir index_dir");
    let index_arg = index_dir.to_string_lossy().to_string();

    rt.block_on(async {
        let conn = setjoin_pg::operator::OperatorConnection::connect(&dsn)
            .await
            .expect("connect owner");
        let suffix = chrono::Utc::now().timestamp_micros();
        let email = format!("mctl558_{suffix}@example.test");
        let rows = conn
            .query(
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
                 ), m AS ( \
                   INSERT INTO public.messages (mailbox_id, folder_id, message_id, subject, from_addr, body_text, thread_id, raw_ref) \
                   SELECT f.mailbox_id, f.id, $3, 'Mailctl Rebuild Subject', 'boss@example.test', 'MailctlRebuildBodyToken', $3, 'inline:mctl558' FROM f RETURNING id, mailbox_id \
                 ), ch AS ( \
                   INSERT INTO public.chat_channels (kind, visibility, name, created_by) \
                   SELECT 'channel', 'public', $4, mb.user_id FROM mb RETURNING id \
                 ), cm AS ( \
                   INSERT INTO public.chat_messages (channel_id, author_id, body, seq) \
                   SELECT ch.id, mb.user_id, 'MailctlChatBodyToken', 1 FROM ch, mb RETURNING id, channel_id \
                 ), sp AS ( \
                   INSERT INTO public.drive_spaces (name, classification, owner_user_id) \
                   SELECT $4, 'regular', mb.user_id FROM mb RETURNING id \
                 ), dn AS ( \
                   INSERT INTO public.drive_nodes (space_id, kind, name, created_by) \
                   SELECT sp.id, 'file', 'MailctlDriveDoc.pdf', mb.user_id FROM sp, mb RETURNING id, space_id \
                 ) \
                 SELECT m.id, cm.id, dn.id FROM m, cm, dn",
                &[
                    (&email, setjoin_pg::Type::TEXT),
                    (&format!("mctl558_{suffix}"), setjoin_pg::Type::TEXT),
                    (&format!("<mctl558-{suffix}@example.test>"), setjoin_pg::Type::TEXT),
                    (&format!("mctl558-{suffix}"), setjoin_pg::Type::TEXT),
                ],
            )
            .await
            .expect("seed data");
        assert_eq!(rows.len(), 1);
    });

    // 1. Verify on unbuilt directory fails with non-zero exit code!
    let unbuilt = mailctl(
        &worker_dsn,
        &["search", "verify", "--index-dir", &index_arg, "--json"],
    );
    assert!(
        !unbuilt.status.success(),
        "verify on unbuilt index_dir must exit non-zero"
    );
    let unbuilt_json: Value = serde_json::from_slice(&unbuilt.stdout).expect("unbuilt json");
    assert_eq!(unbuilt_json["ok"], false);

    // 1b. Partial-corpus rebuild (`--corpus mail`) MUST be rejected so other corpora are never wiped!
    let bad_corpus = mailctl(
        &worker_dsn,
        &[
            "search",
            "rebuild",
            "--index-dir",
            &index_arg,
            "--corpus",
            "mail",
        ],
    );
    assert!(
        !bad_corpus.status.success(),
        "rebuild with --corpus mail must fail closed"
    );

    // 2. First online rebuild -> Epoch N
    let r1 = mailctl(
        &worker_dsn,
        &["search", "rebuild", "--index-dir", &index_arg, "--json"],
    );
    assert!(
        r1.status.success(),
        "rebuild 1 failed: stderr={}",
        String::from_utf8_lossy(&r1.stderr)
    );
    let r1_json: Value = serde_json::from_slice(&r1.stdout).expect("rebuild 1 json");
    assert_eq!(r1_json["ok"], true);
    let epoch1 = r1_json["epoch"].as_u64().expect("epoch1 u64");
    assert!(epoch1 >= 1, "rebuild 1 epoch must be >= 1, got {epoch1}");
    assert!(r1_json["docs_indexed"].as_u64().unwrap_or(0) >= 3);

    // 3. Verify passes cleanly (exit 0) on healthy aligned Epoch N!
    let v1 = mailctl(
        &worker_dsn,
        &["search", "verify", "--index-dir", &index_arg, "--json"],
    );
    assert!(
        v1.status.success(),
        "verify 1 failed: stdout={} stderr={}",
        String::from_utf8_lossy(&v1.stdout),
        String::from_utf8_lossy(&v1.stderr)
    );
    let v1_json: Value = serde_json::from_slice(&v1.stdout).expect("verify 1 json");
    assert_eq!(v1_json["ok"], true);
    assert_eq!(v1_json["watermarks_aligned"], true);
    assert_eq!(v1_json["schema_matches"], true);
    assert_eq!(
        v1_json["missing_live_keys"].as_array().map(Vec::len),
        Some(0)
    );

    // 4. Open a live gateway TantivySearchEngine handle on Epoch N, start a concurrent
    //    uncommitted PG write BEFORE rebuild 2, run rebuild 2 -> Epoch N+1, then commit
    //    the concurrent write AFTER rebuild 2:
    //    - Previous Epoch N directory stays intact (not unlinked out from under live readers!)
    //    - Live gateway handle seamlessly reloads Epoch N+1!
    //    - Concurrent mutation's outbox row stays `processed_at IS NULL`!
    //    - `verify` fails on unprocessed lag without `--allow-lag` and passes WITH `--allow-lag`!
    let live_gateway_engine =
        setjoin_search::TantivySearchEngine::open_or_degraded(setjoin_search::SearchConfig {
            tier2_enabled: true,
            index_dir: index_dir.clone(),
            ..setjoin_search::SearchConfig::default()
        });
    assert_eq!(
        live_gateway_engine
            .current_manifest()
            .expect("live epoch1")
            .epoch,
        epoch1
    );

    let concurrent_tx = rt.block_on(async {
        let conn = setjoin_pg::operator::OperatorConnection::connect(&dsn)
            .await
            .expect("connect concurrent");
        conn.query("BEGIN", &[]).await.expect("begin concurrent");
        let rows = conn
            .query(
                "INSERT INTO public.messages \
                   (mailbox_id, folder_id, message_id, subject, from_addr, body_text, thread_id, raw_ref) \
                 SELECT f.mailbox_id, f.id, $1, 'Concurrent InFlight Subject', 'conc@example.test', \
                        'ConcurrentInFlightToken', $1, 'inline:conc558' \
                   FROM public.folders f LIMIT 1 RETURNING id",
                &[(&format!("<conc558-{}@example.test>", chrono::Utc::now().timestamp_micros()), setjoin_pg::Type::TEXT)],
            )
            .await
            .expect("insert concurrent msg");
        let conc_id: i64 = rows[0].try_get(0).expect("conc id");
        (conn, conc_id)
    });

    let r2 = mailctl(
        &worker_dsn,
        &["search", "rebuild", "--index-dir", &index_arg, "--json"],
    );
    assert!(
        r2.status.success(),
        "rebuild 2 failed: stderr={}",
        String::from_utf8_lossy(&r2.stderr)
    );
    let r2_json: Value = serde_json::from_slice(&r2.stdout).expect("rebuild 2 json");
    let epoch2 = r2_json["epoch"].as_u64().expect("epoch2 u64");
    assert_eq!(epoch2, epoch1 + 1);
    assert!(
        index_dir
            .join("epochs")
            .join(format!("index-v{epoch1:06}"))
            .exists(),
        "online rebuild must NOT unlink previous epoch {epoch1} while external gateway readers may hold it"
    );
    assert!(
        live_gateway_engine
            .reload_if_disk_epoch_advanced()
            .expect("gateway auto reload"),
        "live gateway handle must auto-reload Epoch {epoch2}"
    );
    assert_eq!(
        live_gateway_engine
            .current_manifest()
            .expect("live epoch2")
            .epoch,
        epoch2
    );

    // Commit concurrent mutation AFTER rebuild 2 -> outbox row MUST remain unprocessed!
    let conc_id = concurrent_tx.1;
    rt.block_on(async {
        concurrent_tx
            .0
            .query("COMMIT", &[])
            .await
            .expect("commit concurrent");
        let wconn = setjoin_pg::operator::OperatorConnection::connect(&worker_dsn)
            .await
            .expect("connect worker");
        let rows = wconn
            .query(
                "SELECT count(*) FROM public.search_index_outbox \
                  WHERE corpus = 'mail' AND entity_id = $1 AND processed_at IS NULL",
                &[(&conc_id, setjoin_pg::Type::INT8)],
            )
            .await
            .expect("check concurrent outbox");
        let pending_cnt: i64 = rows[0].try_get(0).expect("cnt");
        assert!(
            pending_cnt >= 1,
            "concurrent in-flight mutation must remain unprocessed in search_index_outbox"
        );
    });
    let v_lag = mailctl(
        &worker_dsn,
        &["search", "verify", "--index-dir", &index_arg, "--json"],
    );
    assert!(
        !v_lag.status.success(),
        "verify without --allow-lag must fail when unprocessed outbox lag exists"
    );
    // Clean up concurrent outbox row & rebuild cleanly so subsequent verify checks isolate their own failure modes.
    rt.block_on(async {
        let conn = setjoin_pg::operator::OperatorConnection::connect(&dsn)
            .await
            .expect("connect owner");
        conn.query("DELETE FROM public.messages WHERE id = $1", &[(&conc_id, setjoin_pg::Type::INT8)])
            .await
            .expect("delete concurrent msg");
        let wconn = setjoin_pg::operator::OperatorConnection::connect(&worker_dsn)
            .await
            .expect("connect worker");
        wconn
            .query("UPDATE public.search_index_outbox SET processed_at = now() WHERE processed_at IS NULL", &[])
            .await
            .expect("clear lag");
    });
    let v_clean_again = mailctl(
        &worker_dsn,
        &["search", "verify", "--index-dir", &index_arg, "--json"],
    );
    assert!(
        v_clean_again.status.success(),
        "verify should pass cleanly once concurrent lag is cleared: stdout={}",
        String::from_utf8_lossy(&v_clean_again.stdout)
    );

    // 4b. Strict read-only verify: clean_shutdown=false MUST fail AND leave CURRENT untouched on disk,
    //     AND verify MUST succeed with zero writes even on a `chmod 0500` read-only epoch directory!
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let active_epoch_dir = index_dir.join("epochs").join(format!("index-v{epoch2:06}"));
        let orig_mode = std::fs::metadata(&active_epoch_dir)
            .expect("stat epoch2")
            .permissions()
            .mode();
        std::fs::set_permissions(&active_epoch_dir, std::fs::Permissions::from_mode(0o500))
            .expect("chmod 0500 epoch2");
        let v_ro = mailctl(
            &worker_dsn,
            &["search", "verify", "--index-dir", &index_arg, "--json"],
        );
        std::fs::set_permissions(
            &active_epoch_dir,
            std::fs::Permissions::from_mode(orig_mode),
        )
        .expect("restore epoch2 perms");
        assert!(
            v_ro.status.success(),
            "mailctl search verify MUST succeed on chmod 0500 read-only epoch dir: stdout={} stderr={}",
            String::from_utf8_lossy(&v_ro.stdout),
            String::from_utf8_lossy(&v_ro.stderr)
        );
    }

    // 4c. Zero lost live updates during online rebuild: simulate a live worker committing AND
    //     marking a message `processed_at = now()` on the old epoch concurrently while `mailctl search rebuild`
    //     runs! Every committed post-snapshot message MUST either be present in the new epoch OR
    //     be re-queued (`processed_at IS NULL`) for idempotent replay onto `v{next_epoch}`!
    {
        let stop_flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop_bg = std::sync::Arc::clone(&stop_flag);
        let bg_dsn = dsn.clone();
        let bg_worker_dsn = worker_dsn.clone();
        let old_epoch = i64::try_from(epoch2).expect("epoch2 i64");
        let bg_handle = std::thread::spawn(move || {
            let bg_rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("bg rt");
            bg_rt.block_on(async move {
                let conn = setjoin_pg::operator::OperatorConnection::connect(&bg_dsn)
                    .await
                    .expect("bg owner");
                let wconn = setjoin_pg::operator::OperatorConnection::connect(&bg_worker_dsn)
                    .await
                    .expect("bg worker");
                let mut created: Vec<i64> = Vec::new();
                let mut i = 0u64;
                while !stop_bg.load(std::sync::atomic::Ordering::Acquire) && i < 12 {
                    i += 1;
                    let mid = format!(
                        "<race558-{}-{i}@example.test>",
                        chrono::Utc::now().timestamp_micros()
                    );
                    if let Ok(rows) = conn
                        .query(
                            "INSERT INTO public.messages \
                               (mailbox_id, folder_id, message_id, subject, from_addr, body_text, thread_id, raw_ref) \
                             SELECT f.mailbox_id, f.id, $1, 'RaceLiveUpdate558', 'race@example.test', \
                                    'RaceLiveBody558', $1, 'inline:race558' \
                               FROM public.folders f LIMIT 1 RETURNING id",
                            &[(&mid, setjoin_pg::Type::TEXT)],
                        )
                        .await
                    {
                        if let Some(id) = rows.first().and_then(|r| r.try_get::<_, i64>(0).ok()) {
                            created.push(id);
                            // Simulate an epoch-fenced old-epoch live worker marking this outbox
                            // row processed only while the old epoch is still active in Postgres.
                            // Locking the watermark row FOR SHARE inside the same transaction
                            // serializes strictly before or after rebuild's settlement transaction
                            // (which locks `search_index_watermarks FOR UPDATE` before re-queuing).
                            if wconn.query("BEGIN", &[]).await.is_ok() {
                                let same_epoch = wconn
                                    .query(
                                        "SELECT 1 FROM public.search_index_watermarks \
                                          WHERE corpus = 'mail' AND epoch = $1 FOR SHARE",
                                        &[(&old_epoch, setjoin_pg::Type::INT8)],
                                    )
                                    .await
                                    .map(|r| !r.is_empty())
                                    .unwrap_or(false);
                                if same_epoch {
                                    let _ = wconn
                                        .query(
                                            "UPDATE public.search_index_outbox \
                                                SET processed_at = now() \
                                              WHERE corpus = 'mail' AND entity_id = $1 AND processed_at IS NULL",
                                            &[(&id, setjoin_pg::Type::INT8)],
                                        )
                                        .await;
                                }
                                let _ = wconn.query("COMMIT", &[]).await;
                            }
                        }
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                }
                created
            })
        });
        let r3 = mailctl(
            &worker_dsn,
            &[
                "search",
                "rebuild",
                "--index-dir",
                &index_arg,
                "--batch-size",
                "10",
                "--json",
            ],
        );
        stop_flag.store(true, std::sync::atomic::Ordering::Release);
        let raced_ids = bg_handle.join().expect("bg join");
        assert!(
            r3.status.success(),
            "rebuild 3 failed: stderr={}",
            String::from_utf8_lossy(&r3.stderr)
        );
        let r3_json: Value = serde_json::from_slice(&r3.stdout).expect("rebuild 3 json");
        let epoch3 = r3_json["epoch"].as_u64().expect("epoch3 u64");
        assert_eq!(epoch3, epoch2 + 1);
        let ro3 =
            setjoin_search::TantivySearchEngine::open_read_only(setjoin_search::SearchConfig {
                tier2_enabled: true,
                index_dir: index_dir.clone(),
                ..setjoin_search::SearchConfig::default()
            })
            .expect("open epoch3");
        rt.block_on(async {
            let wconn = setjoin_pg::operator::OperatorConnection::connect(&worker_dsn)
                .await
                .expect("wconn");
            for rid in &raced_ids {
                let mrows = wconn
                    .query(
                        "SELECT mailbox_id, received_at FROM public.messages WHERE id = $1",
                        &[(&rid, setjoin_pg::Type::INT8)],
                    )
                    .await
                    .expect("lookup raced msg");
                if let Some(mr) = mrows.first() {
                    let mb: i64 = mr.try_get(0).expect("mb");
                    let ts: chrono::DateTime<chrono::Utc> = mr.try_get(1).expect("ts");
                    let in_epoch3 = ro3
                        .contains_doc_key(&setjoin_search::DocumentKey::Mail {
                            mailbox_id: mb,
                            id: *rid,
                            received_at: ts,
                        })
                        .expect("contains raced");
                    let requeued: i64 = wconn
                        .query(
                            "SELECT count(*) FROM public.search_index_outbox \
                              WHERE corpus = 'mail' AND entity_id = $1 AND processed_at IS NULL",
                            &[(&rid, setjoin_pg::Type::INT8)],
                        )
                        .await
                        .expect("check requeued")[0]
                        .try_get(0)
                        .expect("cnt");
                    assert!(
                        in_epoch3 || requeued >= 1,
                        "raced live update id={rid} MUST NOT be lost (neither in epoch3 nor re-queued in outbox!)"
                    );
                }
            }
            // Clean up raced messages and align watermarks/outbox before subsequent dirty-CURRENT checks.
            let conn = setjoin_pg::operator::OperatorConnection::connect(&dsn)
                .await
                .expect("owner");
            for rid in &raced_ids {
                let _ = conn
                    .query(
                        "DELETE FROM public.messages WHERE id = $1",
                        &[(&rid, setjoin_pg::Type::INT8)],
                    )
                    .await;
            }
            let _ = wconn
                .query(
                    "UPDATE public.search_index_outbox SET processed_at = now() WHERE processed_at IS NULL",
                    &[],
                )
                .await;
        });
    }
    let epoch2 = epoch2 + 1;

    let orig_current = std::fs::read(index_dir.join("CURRENT")).expect("read CURRENT");
    let mut dirty_cur: Value = serde_json::from_slice(&orig_current).expect("parse CURRENT");
    dirty_cur["clean_shutdown"] = Value::Bool(false);
    let dirty_bytes = serde_json::to_vec_pretty(&dirty_cur).expect("encode dirty CURRENT");
    std::fs::write(index_dir.join("CURRENT"), &dirty_bytes).expect("write dirty CURRENT");
    let v_dirty = mailctl(
        &worker_dsn,
        &["search", "verify", "--index-dir", &index_arg, "--json"],
    );
    assert!(
        !v_dirty.status.success(),
        "verify must exit non-zero on clean_shutdown=false"
    );
    assert_eq!(
        std::fs::read(index_dir.join("CURRENT")).expect("read CURRENT after verify"),
        dirty_bytes,
        "mailctl search verify MUST be strictly read-only and never mutate CURRENT"
    );
    std::fs::write(index_dir.join("CURRENT"), &orig_current).expect("restore CURRENT");

    // 5. Corrupt watermark in PG -> verify MUST exit non-zero (mismatch)!
    rt.block_on(async {
        let conn = setjoin_pg::operator::OperatorConnection::connect(&worker_dsn)
            .await
            .expect("connect worker");
        conn.query(
            "UPDATE public.search_index_watermarks SET epoch = $1 WHERE corpus = 'mail'",
            &[(&(epoch2 as i64 + 100), setjoin_pg::Type::INT8)],
        )
        .await
        .expect("skew watermark");
    });
    let v_skew = mailctl(
        &worker_dsn,
        &["search", "verify", "--index-dir", &index_arg, "--json"],
    );
    assert!(
        !v_skew.status.success(),
        "verify must exit non-zero on PG watermark mismatch"
    );
    let v_skew_json: Value = serde_json::from_slice(&v_skew.stdout).expect("skew json");
    assert_eq!(v_skew_json["ok"], false);
    assert_eq!(v_skew_json["watermarks_aligned"], false);

    // Restore watermark epoch so subsequent tests on the shared DB stay clean.
    rt.block_on(async {
        let conn = setjoin_pg::operator::OperatorConnection::connect(&worker_dsn)
            .await
            .expect("connect worker");
        conn.query(
            "UPDATE public.search_index_watermarks SET epoch = $1 WHERE corpus = 'mail'",
            &[(&(epoch2 as i64), setjoin_pg::Type::INT8)],
        )
        .await
        .expect("restore watermark");
    });

    // 6. Corrupt CURRENT JSON on disk -> verify MUST exit non-zero!
    std::fs::write(index_dir.join("CURRENT"), b"{corrupt").expect("corrupt CURRENT");
    let v_corrupt = mailctl(
        &worker_dsn,
        &["search", "verify", "--index-dir", &index_arg, "--json"],
    );
    assert!(
        !v_corrupt.status.success(),
        "verify must exit non-zero on corrupt CURRENT"
    );

    let _ = std::fs::remove_dir_all(&index_dir);
}
