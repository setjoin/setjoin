//! Live-PostgreSQL integration tests for Wave 3.3 (`#558`):
//! 1. Mandatory PG ACL re-auth under real `AppPool` (`setjoin_app`, `NOBYPASSRLS`)
//!    `MailboxTx<ReadOnly>` / `UserTx<ReadOnly>` + `GUEST_HISTORY_FLOOR` + `ComplianceOnly`
//!    never leaking to user search.
//! 2. `AdminReadTx<Standard>` (`AdminWorkerPool` + RBAC `AdminPermissionProof`) compliance
//!    re-auth returning held/soft-deleted Mail, `chat_message_revisions`, pending
//!    `scheduled_actions`, and trashed Drive nodes.
//! 3. `WorkQueue`-backed deterministic eDiscovery completeness (`EdiscoverySearchExecutor`):
//!    Tantivy hit + PG tail row inserted AFTER `indexed_outbox_seq` BOTH returned in union,
//!    honest `ExtractionStatusSummary` (`extracted`, `encrypted`, `unsupported`, `truncated_limit`,
//!    `failed`, `pending_extraction`), persisted `ediscovery_searches.search_provenance`,
//!    core `admin_audit_log` entry, and transparent Tier-1 PG fallback when degraded/misaligned.
//! 4. Lawful purge physical eviction + segment compaction removing purged bytes from every file
//!    on disk + `V299` hard-delete trigger enqueueing `"search.purge_evict"`.
//! 5. HA two-node `SKIP LOCKED` leader election (`try_acquire`, contention, `heartbeat`,
//!    graceful `release`, takeover with monotonic `fencing_token`, stale-leader rejection) +
//!    live follower `RemoteSearchEngine` querying a loopback leader via HMAC-SHA256 + `DbLeaderResolver`
//!    and transparently degrading to Tier-1 PG when leader stops.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::Utc;
use hmac::{Hmac, Mac};
use setjoin_authz::groups::GroupResolver;
use setjoin_authz::legacy_jwt::LegacyKeys;
use setjoin_authz::policy_gate::{GateCredential, GateRequest, PolicyGate, ProtocolSurface};
use setjoin_authz::principals::TxFactory;
use setjoin_authz::token::KeySource;
use setjoin_conformance::db_gate::{resolve as resolve_db_gate, DbGate};
use setjoin_pg::{AdminWorkerPool, AppPool, ScopedExecutor};
use setjoin_search::{
    chat_revision_doc_id, current_search_leader, ensure_search_watermarks_initialized,
    heartbeat_search_leader, reauthorize_admin_chat_candidates, reauthorize_admin_drive_candidates,
    reauthorize_admin_mail_candidates, reauthorize_chat_candidates, reauthorize_mail_candidates,
    release_search_leader, scheduled_action_doc_id, try_acquire_search_leader, verify_rpc_request,
    AdminChatReauthFilter, AdminDriveReauthFilter, AdminMailReauthFilter, CandidateBatch,
    CandidateQuery, DbLeaderResolver, DocCorpus, DocumentKey, EdiscoverySearchExecutor,
    MailReauthFilter, NormalizedQuery, PgSearchCapabilities, RemoteSearchEngine,
    RpcCandidateRequest, RpcCandidateResponse, ScopeHint, SearchConfig, SearchEngine,
    SearchIndexBatchPayload, SearchIndexPipeline, SearchTier, SearchVisibility,
    TantivySearchEngine, Tier1PgSearchEngine, TwoTierSearchEngine, HEADER_SEARCH_SIG,
    HEADER_SEARCH_TS, INTERNAL_SEARCH_CANDIDATES_PATH,
};
use sha2::Sha256;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_postgres::NoTls;

static SEED_SEQ: AtomicI64 = AtomicI64::new(558_000);
static TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn next_tag() -> i64 {
    let seq = SEED_SEQ.fetch_add(1, Ordering::SeqCst);
    (Utc::now().timestamp_micros() & 0x0FFF_FFFF).saturating_add(seq)
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

async fn connect_as(dsn: &str) -> tokio_postgres::Client {
    let (client, conn) = tokio_postgres::connect(dsn, NoTls)
        .await
        .expect("connect postgres");
    tokio::spawn(async move {
        let _ = conn.await;
    });
    client
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest;
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

fn mint_hs256_jwt(secret: &[u8], user_id: i64, email: &str) -> String {
    type HmacSha256 = Hmac<Sha256>;
    let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"HS256","typ":"JWT","kid":"authserver-hmac-1"}"#);
    let now_s = Utc::now().timestamp();
    let payload = URL_SAFE_NO_PAD.encode(
        serde_json::json!({
            "iss": "mailserver",
            "aud": "mailserver-gateway",
            "typ": "access",
            "uid": user_id,
            "email": email,
            "iat": now_s - 5,
            "exp": now_s + 3600,
        })
        .to_string(),
    );
    let input = format!("{header}.{payload}");
    let mut mac = HmacSha256::new_from_slice(secret).expect("hmac");
    mac.update(input.as_bytes());
    let sig = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    format!("{input}.{sig}")
}

fn count_needle_in_dir(root: &std::path::Path, needle: &[u8]) -> usize {
    let mut total = 0usize;
    let mut stack = vec![root.to_path_buf()];
    while let Some(path) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&path) else {
            continue;
        };
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.is_file() {
                if let Ok(bytes) = std::fs::read(&p) {
                    if !needle.is_empty() && bytes.len() >= needle.len() {
                        total += bytes.windows(needle.len()).filter(|w| *w == needle).count();
                    }
                }
            }
        }
    }
    total
}

struct TestKeys {
    legacy: LegacyKeys,
}

impl KeySource for TestKeys {
    async fn key(&self, _kid: &str) -> Option<setjoin_authz::es256::VerifyingKey> {
        None
    }

    fn legacy_keys(&self) -> Option<&LegacyKeys> {
        Some(&self.legacy)
    }
}

#[tokio::test]
async fn wave33_reauth_admin_ediscovery_purge_compaction_and_ha_leader_rpc() {
    let _serial = TEST_LOCK.lock().await;
    let (owner_dsn, app_opt) = match resolve_db_gate(|k| std::env::var(k).ok()) {
        DbGate::Run { dsn, app, .. } => (dsn, app),
        DbGate::Skip => {
            eprintln!("SEARCH-WAVE33-DB-SKIP");
            return;
        }
        DbGate::Missing => panic!("REQUIRE_DB=1 set but TEST_DB_DSN/DB_DSN is absent"),
    };
    let app_dsn = app_opt.unwrap_or_else(|| swap_dsn_user(&owner_dsn, "setjoin_app"));
    let worker_dsn = std::env::var("DB_WORKER_DSN")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| swap_dsn_user(&owner_dsn, "setjoin_worker"));

    let owner = connect_as(&owner_dsn).await;
    let worker = Arc::new(connect_as(&worker_dsn).await);
    let tag = next_tag();

    // Seed two users (user_a = compliance admin, user_b = guest/member)
    let email_a = format!("admin558_{tag}@example.test");
    let email_b = format!("guest558_{tag}@example.test");
    let row_a = owner
        .query_one(
            "WITH dom AS ( \
               INSERT INTO public.domains (name) VALUES ('example.test') \
               ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name RETURNING id \
             ), u AS ( \
               INSERT INTO public.users (domain_id, email, username, password_hash, display_name, is_admin) \
               SELECT id, $1, $2, 'hash', $2, true FROM dom RETURNING id, domain_id \
             ), mb AS ( \
               INSERT INTO public.mailboxes (user_id, domain_id, email, display_name, is_primary) \
               SELECT u.id, u.domain_id, $1, $2, true FROM u RETURNING id, user_id \
             ), f AS ( \
               INSERT INTO public.folders (mailbox_id, name, path, role) \
               SELECT mb.id, 'Inbox', 'Inbox', 'inbox' FROM mb RETURNING id, mailbox_id \
             ) \
             SELECT mb.user_id, mb.id, f.id FROM mb JOIN f ON f.mailbox_id = mb.id",
            &[&email_a, &format!("admin558_{tag}")],
        )
        .await
        .expect("seed user_a");
    let user_a: i64 = row_a.try_get(0).expect("ua");
    let mb_a: i64 = row_a.try_get(1).expect("mba");
    let folder_a: i64 = row_a.try_get(2).expect("fa");

    // Grant user_a global compliance RBAC role so PolicyGate mints AdminPermissionProof cleanly!
    let role_group_id: i64 = owner
        .query_one(
            "INSERT INTO public.admin_role_groups (name, permissions, sod_class) \
             VALUES ($1, ARRAY['compliance.read','compliance.write','audit.read'], 'audit') \
             RETURNING id",
            &[&format!("wave33-compliance-{tag}")],
        )
        .await
        .expect("insert admin role group")
        .try_get(0)
        .expect("role_group_id");
    owner
        .execute(
            "INSERT INTO public.admin_role_assignments (user_id, role_group_id) \
             VALUES ($1, $2) ON CONFLICT DO NOTHING",
            &[&user_a, &role_group_id],
        )
        .await
        .expect("grant compliance role");

    let row_b = owner
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
            &[&email_b, &format!("guest558_{tag}")],
        )
        .await
        .expect("seed user_b");
    let user_b: i64 = row_b.try_get(0).expect("ub");
    let mb_b: i64 = row_b.try_get(1).expect("mbb");
    let _folder_b: i64 = row_b.try_get(2).expect("fb");

    // =========================================================================
    // 1. User AppPool (setjoin_app, NOBYPASSRLS) + AdminReadTx<Standard> Re-auth
    // =========================================================================
    let jwt_secret = b"wave33-test-jwt-secret-32-bytes!";
    let keys = Arc::new(TestKeys {
        legacy: LegacyKeys::new(jwt_secret, &["authserver-hmac-1"], None).expect("legacy"),
    });
    let app_exec = ScopedExecutor::from_dsn(&app_dsn, 4).expect("app exec");
    let app_pool = AppPool::from_dsn(&app_dsn, 4).expect("app pool");
    let admin_pool = AdminWorkerPool::from_dsn(&worker_dsn, 4).expect("admin pool");
    let groups = Arc::new(GroupResolver::new(app_pool.clone()));
    let factory = TxFactory::with_admin_pool(app_pool, admin_pool, groups);
    let gate = PolicyGate::new(app_exec, keys, "mailserver").with_tx_factory(factory.clone());

    // Seed:
    // - Live Mail in mb_a
    // - Held soft-deleted Mail (`is_deleted = true, held = true`) in mb_a (`ComplianceOnly`)
    // - Chat channel with msg1 (seq=1, below guest floor), msg2 (seq=2, edited with revision),
    //   msg3 (seq=3, soft-deleted), and pending chat scheduled_action
    // - Drive space with live file and soft-trashed file
    let live_mail_row = owner
        .query_one(
            "INSERT INTO public.messages \
               (mailbox_id, folder_id, message_id, subject, from_addr, body_text, thread_id, raw_ref) \
             VALUES ($1, $2, $3, 'Live Mail 558', 'alice@example.test', 'live body', $3, 'inline:live558') \
             RETURNING id, received_at",
            &[&mb_a, &folder_a, &format!("<live558-{tag}@example.test>")],
        )
        .await
        .expect("live mail");
    let live_mail_id: i64 = live_mail_row.try_get(0).expect("id");
    let live_mail_ts: chrono::DateTime<Utc> = live_mail_row.try_get(1).expect("ts");

    let held_mail_row = owner
        .query_one(
            "INSERT INTO public.messages \
               (mailbox_id, folder_id, message_id, subject, from_addr, body_text, is_deleted, held, thread_id, raw_ref) \
             VALUES ($1, $2, $3, 'Held Deleted Compliance Mail', 'legal@example.test', 'held secret', true, true, $3, 'inline:held558') \
             RETURNING id, received_at",
            &[&mb_a, &folder_a, &format!("<held558-{tag}@example.test>")],
        )
        .await
        .expect("held mail");
    let held_mail_id: i64 = held_mail_row.try_get(0).expect("id");
    let held_mail_ts: chrono::DateTime<Utc> = held_mail_row.try_get(1).expect("ts");

    let ch_id: i64 = owner
        .query_one(
            "INSERT INTO public.chat_channels (kind, visibility, name, created_by) \
             VALUES ('channel', 'private', $1, $2) RETURNING id",
            &[&format!("ch558-{tag}"), &user_a],
        )
        .await
        .expect("channel")
        .try_get(0)
        .expect("cid");
    owner
        .execute(
            "INSERT INTO public.chat_channel_members (channel_id, user_id, role, history_floor_seq, joined_at) \
             VALUES ($1, $2, 'owner', NULL, now() - interval '1 hour'), \
                    ($1, $3, 'member', 1, now() - interval '1 minute')",
            &[&ch_id, &user_a, &user_b],
        )
        .await
        .expect("members");

    let cm1_id: i64 = owner
        .query_one(
            "INSERT INTO public.chat_messages (channel_id, author_id, body, seq, created_at) \
             VALUES ($1, $2, 'Pre-join secret message', 1, now() - interval '30 minutes') RETURNING id",
            &[&ch_id, &user_a],
        )
        .await
        .expect("cm1")
        .try_get(0)
        .expect("id");
    let cm2_id: i64 = owner
        .query_one(
            "INSERT INTO public.chat_messages (channel_id, author_id, body, seq, created_at) \
             VALUES ($1, $2, 'Edited current text', 2, now()) RETURNING id",
            &[&ch_id, &user_a],
        )
        .await
        .expect("cm2")
        .try_get(0)
        .expect("id");
    owner
        .execute(
            "INSERT INTO public.chat_message_revisions (message_id, channel_id, prior_body, edited_by) \
             VALUES ($1, $2, 'Original redacted prior revision', $3)",
            &[&cm2_id, &ch_id, &user_a],
        )
        .await
        .expect("rev");
    let cm3_del_id: i64 = owner
        .query_one(
            "INSERT INTO public.chat_messages (channel_id, author_id, body, seq, deleted_at, created_at) \
             VALUES ($1, $2, 'Soft deleted chat msg', 3, now(), now()) RETURNING id",
            &[&ch_id, &user_a],
        )
        .await
        .expect("cm3")
        .try_get(0)
        .expect("id");

    let sched_uuid: String = owner
        .query_one(
            "INSERT INTO public.scheduled_actions (mailbox_id, action_kind, fire_at, payload, status) \
             VALUES ($1, 'chat_send', now() + interval '1 hour', $2::text::jsonb, 'pending') \
             RETURNING id::text",
            &[
                &mb_a,
                &serde_json::json!({ "channelId": ch_id, "body": "Scheduled pending chat secret" }).to_string(),
            ],
        )
        .await
        .expect("sched chat")
        .try_get(0)
        .expect("uuid");
    let sched_doc_id = scheduled_action_doc_id(&sched_uuid);
    let rev_doc_id = chat_revision_doc_id(cm2_id);

    let sp_id: i64 = owner
        .query_one(
            "INSERT INTO public.drive_spaces (name, classification, owner_user_id) \
             VALUES ($1, 'regular', $2) RETURNING id",
            &[&format!("sp558-{tag}"), &user_a],
        )
        .await
        .expect("space")
        .try_get(0)
        .expect("sp");
    let trashed_drive_id: i64 = owner
        .query_one(
            "INSERT INTO public.drive_nodes (space_id, kind, name, created_by, deleted_at) \
             VALUES ($1, 'file', 'TrashedCompliance.pdf', $2, now()) RETURNING id",
            &[&sp_id, &user_a],
        )
        .await
        .expect("trashed drive")
        .try_get(0)
        .expect("dn");

    // Authenticate user_a (admin) and user_b (guest with history_floor_seq=1) via real PolicyGate!
    let tok_a = mint_hs256_jwt(jwt_secret, user_a, &email_a);
    let tok_b = mint_hs256_jwt(jwt_secret, user_b, &email_b);
    fn make_req(tok: &str) -> GateRequest<'_> {
        GateRequest {
            surface: ProtocolSurface::Http,
            credential: GateCredential::Jwt {
                token: tok,
                from_cookie: false,
            },
            client_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            user_agent: "wave33-test",
            scheme: "https",
            method: "GET",
            path: "/api/search",
            headers: None,
            body: &[],
            tls_active: true,
            require_tls: false,
            production: false,
            allowed_origin_host: "",
            required_app: None,
            drive_path: false,
            now_secs: None,
        }
    }
    let adm_a = gate.admit(&make_req(&tok_a)).await.expect("admit a");
    let adm_b = gate.admit(&make_req(&tok_b)).await.expect("admit b");

    // A) Normal user Mail re-auth (`MailboxTx<ReadOnly>`, `setjoin_app`): returns live mail ONLY, NEVER held-deleted compliance mail!
    let mb_principal_a = adm_a.mint_primary_mailbox(&factory).await.expect("mb a");
    let read_cap_a = mb_principal_a.require_read().expect("read cap a");
    {
        let mut mtx = factory
            .begin_mailbox_read(&read_cap_a)
            .await
            .expect("begin mailbox read");
        let hits = reauthorize_mail_candidates(
            &mut mtx,
            &[
                DocumentKey::Mail {
                    mailbox_id: mb_a,
                    id: live_mail_id,
                    received_at: live_mail_ts,
                },
                DocumentKey::Mail {
                    mailbox_id: mb_a,
                    id: held_mail_id,
                    received_at: held_mail_ts,
                },
                DocumentKey::Mail {
                    mailbox_id: mb_b,
                    id: live_mail_id,
                    received_at: live_mail_ts,
                },
            ],
            &MailReauthFilter::default(),
        )
        .await
        .expect("reauth mail");
        mtx.finish().await.expect("finish");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].id, live_mail_id);
    }

    // B) Normal user Chat re-auth (`UserTx<ReadOnly>`, `setjoin_app`): enforces GUEST_HISTORY_FLOOR and NEVER returns revisions/deleted/scheduled!
    let user_principal_b = adm_b.mint_user(&factory).await.expect("mint user b");
    {
        let mut utx = factory
            .begin_user_read(&user_principal_b)
            .await
            .expect("begin user read");
        let hits = reauthorize_chat_candidates(
            &mut utx,
            &[
                DocumentKey::Chat {
                    channel_id: ch_id,
                    id: cm1_id, // below history_floor_seq=1
                },
                DocumentKey::Chat {
                    channel_id: ch_id,
                    id: cm2_id, // visible live
                },
                DocumentKey::Chat {
                    channel_id: ch_id,
                    id: cm3_del_id, // soft deleted
                },
                DocumentKey::Chat {
                    channel_id: ch_id,
                    id: rev_doc_id, // ComplianceOnly revision
                },
                DocumentKey::Chat {
                    channel_id: ch_id,
                    id: sched_doc_id, // ComplianceOnly scheduled send
                },
            ],
            Some(ch_id),
        )
        .await
        .expect("reauth chat");
        utx.finish().await.expect("finish");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].id, cm2_id);
    }

    // C) Compliance/Admin re-auth (`AdminReadTx<Standard>`): hydrates BOTH Live AND ComplianceOnly
    //    (held-deleted Mail, chat_message_revisions, pending scheduled_actions, trashed Drive nodes)!
    let admin_p = adm_a.mint_admin(&factory).await.expect("mint admin");
    let proof = admin_p
        .require_global_permission(&["compliance.write"])
        .expect("compliance proof");
    {
        let mut atx = factory
            .begin_admin_read(&proof)
            .await
            .expect("begin admin read");
        let mail_hits = reauthorize_admin_mail_candidates(
            &mut atx,
            &[
                DocumentKey::Mail {
                    mailbox_id: mb_a,
                    id: live_mail_id,
                    received_at: live_mail_ts,
                },
                DocumentKey::Mail {
                    mailbox_id: mb_a,
                    id: held_mail_id,
                    received_at: held_mail_ts,
                },
            ],
            &AdminMailReauthFilter {
                mailbox_ids: Some(vec![mb_a]),
                include_deleted: true,
                ..AdminMailReauthFilter::default()
            },
        )
        .await
        .expect("admin mail reauth");
        assert_eq!(mail_hits.len(), 2);
        assert!(mail_hits
            .iter()
            .any(|h| h.id == held_mail_id && h.is_deleted && h.held));

        let chat_hits = reauthorize_admin_chat_candidates(
            &mut atx,
            &[
                DocumentKey::Chat {
                    channel_id: ch_id,
                    id: cm3_del_id,
                },
                DocumentKey::Chat {
                    channel_id: ch_id,
                    id: rev_doc_id,
                },
                DocumentKey::Chat {
                    channel_id: ch_id,
                    id: sched_doc_id,
                },
            ],
            &AdminChatReauthFilter {
                channel_ids: Some(vec![ch_id]),
                include_deleted: true,
                ..AdminChatReauthFilter::default()
            },
        )
        .await
        .expect("admin chat reauth");
        assert_eq!(chat_hits.len(), 3);
        assert!(chat_hits.iter().any(|h| h.id == cm3_del_id && h.is_deleted));
        assert!(chat_hits
            .iter()
            .any(|h| h.is_revision && h.body.contains("Original redacted")));
        assert!(chat_hits
            .iter()
            .any(|h| h.is_scheduled && h.action_id.as_deref() == Some(sched_uuid.as_str())));

        let drive_hits = reauthorize_admin_drive_candidates(
            &mut atx,
            &[DocumentKey::Drive {
                space_id: sp_id,
                id: trashed_drive_id,
            }],
            &AdminDriveReauthFilter {
                space_ids: Some(vec![sp_id]),
                include_trashed: true,
                ..AdminDriveReauthFilter::default()
            },
        )
        .await
        .expect("admin drive reauth");
        assert_eq!(drive_hits.len(), 1);
        assert!(drive_hits[0].is_trashed);
        atx.finish().await.expect("finish admin");
    }

    // =========================================================================
    // 2. Deterministic Watermark eDiscovery Completeness + ExtractionStatusSummary
    // =========================================================================
    ensure_search_watermarks_initialized(worker.as_ref())
        .await
        .expect("init watermarks");

    let dir = TempDir::new().expect("tempdir");
    let cfg = SearchConfig {
        tier2_enabled: true,
        index_dir: dir.path().to_path_buf(),
        ..SearchConfig::default()
    };
    let engine = Arc::new(TantivySearchEngine::open_or_degraded(cfg.clone()));
    let wm_row = worker
        .query_one(
            "SELECT COALESCE(MAX(epoch), 1)::bigint, COALESCE(MAX(generation), 1)::bigint \
               FROM public.search_index_watermarks",
            &[],
        )
        .await
        .expect("read watermark epoch/gen");
    let wm_epoch: i64 = wm_row.try_get(0).expect("epoch");
    let wm_gen: i64 = wm_row.try_get(1).expect("gen");
    let mut staging = engine
        .begin_rebuild_at_min_epoch(wm_epoch.max(1) as u64)
        .expect("begin aligned bootstrap");
    let _ = staging.add_batch(&[]).expect("empty batch");
    let boot_m = engine
        .commit_rebuild(staging, Some(Utc::now()))
        .expect("commit aligned bootstrap");
    if boot_m.generation < wm_gen as u64 {
        let _ = engine
            .rebuild_epoch(&[], wm_gen as u64, Some(Utc::now()))
            .expect("bump generation to watermark");
    }

    let edisc_token = format!("edisccompleteness{tag}");
    // Mail 1: indexed into Tantivy BEFORE watermark cutoff
    let ed_m1 = owner
        .query_one(
            "INSERT INTO public.messages \
               (mailbox_id, folder_id, message_id, subject, from_addr, body_text, is_deleted, held, thread_id, raw_ref) \
             VALUES ($1, $2, $3, $4, 'target@example.test', $5, true, true, $3, 'inline:edm1') \
             RETURNING id, received_at",
            &[
                &mb_a,
                &folder_a,
                &format!("<edm1-{tag}@example.test>"),
                &format!("Held Indexed {edisc_token}"),
                &format!("body {edisc_token}"),
            ],
        )
        .await
        .expect("ed_m1");
    let ed_m1_id: i64 = ed_m1.try_get(0).expect("id1");
    let ed_m1_ts: chrono::DateTime<Utc> = ed_m1.try_get(1).expect("ts1");

    // Seed 6 attachments covering ALL 6 ExtractionStatusSummary buckets!
    let statuses = [
        ("extracted", Some("extracted attachment text")),
        ("encrypted", None),
        ("unsupported", None),
        ("truncated_limit", Some("truncated text")),
        ("failed", None),
        ("pending_extraction", None),
    ];
    for (idx, (st, txt)) in statuses.iter().enumerate() {
        let sha = sha256_hex(format!("edisc558-{tag}-{idx}-{st}").as_bytes());
        owner
            .execute(
                "INSERT INTO public.blobs (sha256, minio_ref, size_bytes, content_type) \
                 VALUES ($1, $1, 16, 'application/octet-stream') ON CONFLICT DO NOTHING",
                &[&sha],
            )
            .await
            .expect("blob");
        owner
            .execute(
                "INSERT INTO public.message_attachments \
                   (message_id, received_at, filename, content_type, size_bytes, blob_sha256) \
                 VALUES ($1, $2, $3, 'application/octet-stream', 16, $4)",
                &[&ed_m1_id, &ed_m1_ts, &format!("file_{st}.bin"), &sha],
            )
            .await
            .expect("att");
        if *st != "pending_extraction" {
            worker
                .execute(
                    "INSERT INTO public.search_extracted_text \
                       (content_sha256, storage_plane, extraction_status, extracted_text, extracted_bytes) \
                     VALUES ($1, 'blob', $2, $3, 10) \
                     ON CONFLICT (content_sha256) DO NOTHING",
                    &[&sha, st, txt],
                )
                .await
                .expect("cache row");
        }
    }

    // Drain outbox into Tantivy so ed_m1 is indexed and watermark advances!
    let pipeline = SearchIndexPipeline::new(Arc::clone(&worker) as _, Arc::clone(&engine));
    let batch1 = pipeline
        .run_batch(&SearchIndexBatchPayload {
            corpus: None,
            batch_limit: Some(500),
        })
        .await
        .expect("run batch 1");
    assert!(batch1.generation >= 1);

    // Mail 2: inserted AFTER indexed_outbox_seq (unindexed PG tail row!)
    let ed_m2 = owner
        .query_one(
            "INSERT INTO public.messages \
               (mailbox_id, folder_id, message_id, subject, from_addr, body_text, thread_id, raw_ref) \
             VALUES ($1, $2, $3, $4, 'target@example.test', $5, $3, 'inline:edm2') \
             RETURNING id, received_at",
            &[
                &mb_a,
                &folder_a,
                &format!("<edm2-{tag}@example.test>"),
                &format!("Tail Unindexed {edisc_token}"),
                &format!("tail body {edisc_token}"),
            ],
        )
        .await
        .expect("ed_m2");
    let ed_m2_id: i64 = ed_m2.try_get(0).expect("id2");

    // Execute watermark-complete eDiscovery search -> MUST return BOTH ed_m1 (Tantivy ComplianceOnly)
    // AND ed_m2 (PG outbox tail) + exact ExtractionStatusSummary + admin_audit_log provenance!
    let search_id: i64 = owner
        .query_one(
            "INSERT INTO public.ediscovery_searches (name, created_by, query, status) \
             VALUES ($1, $2, $3::text::jsonb, 'pending') RETURNING id",
            &[
                &format!("edisc-union-{tag}"),
                &user_a,
                &serde_json::json!({
                    "keywords": edisc_token,
                    "fromAddr": "target@example.test",
                    "mailboxIds": [mb_a],
                })
                .to_string(),
            ],
        )
        .await
        .expect("seed search")
        .try_get(0)
        .expect("sid");

    // Also seed an S/MIME encrypted message with an attachment whose blob WAS extracted:
    // honest ExtractionStatusSummary MUST count it under `encrypted`, NEVER `extracted`!
    let smime_row = owner
        .query_one(
            "INSERT INTO public.messages \
               (mailbox_id, folder_id, message_id, subject, from_addr, body_text, crypto_type, thread_id, raw_ref) \
             VALUES ($1, $2, $3, 'Sealed S/MIME', 'target@example.test', 'sealed', 'smime-encrypted', $3, 'inline:smime558') \
             RETURNING id, received_at",
            &[&mb_a, &folder_a, &format!("<edsmime-{tag}@example.test>")],
        )
        .await
        .expect("smime msg");
    let smime_id: i64 = smime_row.try_get(0).expect("smime id");
    let smime_ts: chrono::DateTime<Utc> = smime_row.try_get(1).expect("smime ts");
    let smime_sha = sha256_hex(format!("edisc558-smime-{tag}").as_bytes());
    owner
        .execute(
            "INSERT INTO public.blobs (sha256, minio_ref, size_bytes, content_type) \
             VALUES ($1, $1, 16, 'application/octet-stream') ON CONFLICT DO NOTHING",
            &[&smime_sha],
        )
        .await
        .expect("smime blob");
    owner
        .execute(
            "INSERT INTO public.message_attachments \
               (message_id, received_at, filename, content_type, size_bytes, blob_sha256) \
             VALUES ($1, $2, 'sealed_att.pdf', 'application/pdf', 16, $3)",
            &[&smime_id, &smime_ts, &smime_sha],
        )
        .await
        .expect("smime att");
    worker
        .execute(
            "INSERT INTO public.search_extracted_text \
               (content_sha256, storage_plane, extraction_status, extracted_text, extracted_bytes) \
             VALUES ($1, 'blob', 'extracted', 'should not count as extracted', 29) \
             ON CONFLICT (content_sha256) DO NOTHING",
            &[&smime_sha],
        )
        .await
        .expect("smime cache row");

    let executor = EdiscoverySearchExecutor::new(
        Arc::clone(&worker) as _,
        Some(Arc::clone(&engine) as Arc<dyn SearchEngine>),
    )
    .with_local_tantivy(Arc::clone(&engine));
    let prov = executor
        .execute(search_id, user_a)
        .await
        .expect("ediscovery execute");
    assert_eq!(prov.engine_tier, "tier2_tantivy_plus_pg_tail");
    assert!(prov.tail_rows_scanned >= 1);
    assert_eq!(prov.result_count, 2);
    assert_eq!(prov.extraction_status_counts.extracted, 1);
    // 1 encrypted attachment on ed_m1 + 1 crypto_sealed S/MIME attachment = 2!
    assert_eq!(prov.extraction_status_counts.encrypted, 2);
    assert_eq!(prov.extraction_status_counts.unsupported, 1);
    assert_eq!(prov.extraction_status_counts.truncated_limit, 1);
    assert_eq!(prov.extraction_status_counts.failed, 1);
    assert_eq!(prov.extraction_status_counts.pending_extraction, 1);

    // Idempotent WorkQueue retry: re-executing completed search must NOT duplicate admin_audit_log!
    let prov_retry = executor
        .execute(search_id, user_a)
        .await
        .expect("idempotent retry");
    assert_eq!(prov_retry.result_count, 2);

    let persisted_ids: Vec<i64> = owner
        .query(
            "SELECT message_id FROM public.ediscovery_search_results WHERE search_id = $1 ORDER BY message_id",
            &[&search_id],
        )
        .await
        .expect("results")
        .into_iter()
        .map(|r| r.try_get(0).expect("mid"))
        .collect();
    let mut expected_ids = vec![ed_m1_id, ed_m2_id];
    expected_ids.sort_unstable();
    assert_eq!(persisted_ids, expected_ids);

    // Verify admin_audit_log recorded immutable core provenance!
    let audit_cnt: i64 = owner
        .query_one(
            "SELECT count(*) FROM public.admin_audit_log \
              WHERE action = 'ediscovery_search_complete' \
                AND target_type = 'ediscovery_search' \
                AND target_id = $1",
            &[&search_id],
        )
        .await
        .expect("audit")
        .try_get(0)
        .expect("cnt");
    assert_eq!(audit_cnt, 1);

    // Degraded/unconfigured Tier-2 fallback -> exact same 2 results via Tier-1 PG!
    let fb_search_id: i64 = owner
        .query_one(
            "INSERT INTO public.ediscovery_searches (name, created_by, query, status) \
             VALUES ($1, $2, $3::text::jsonb, 'pending') RETURNING id",
            &[
                &format!("edisc-fallback-{tag}"),
                &user_a,
                &serde_json::json!({
                    "keywords": edisc_token,
                    "fromAddr": "target@example.test",
                    "mailboxIds": [mb_a],
                })
                .to_string(),
            ],
        )
        .await
        .expect("seed fb search")
        .try_get(0)
        .expect("sid");
    let fb_executor = EdiscoverySearchExecutor::new(Arc::clone(&worker) as _, None);
    let fb_prov = fb_executor
        .execute(fb_search_id, user_a)
        .await
        .expect("fallback execute");
    assert_eq!(fb_prov.engine_tier, "tier1_pg_fallback");
    assert!(fb_prov.degraded_reason.is_some());
    assert_eq!(fb_prov.result_count, 2);

    // =========================================================================
    // 3. Lawful Purge Hard-Delete Trigger + Physical Disk Segment Compaction
    // =========================================================================
    let purge_canary = format!("lawfulpurgedbcanary{tag}");
    let p_row = owner
        .query_one(
            "INSERT INTO public.messages \
               (mailbox_id, folder_id, message_id, subject, from_addr, body_text, thread_id, raw_ref) \
             VALUES ($1, $2, $3, $4, 'purge@example.test', $5, $3, 'inline:purge558') \
             RETURNING id, received_at",
            &[
                &mb_a,
                &folder_a,
                &format!("<purge558-{tag}@example.test>"),
                &purge_canary,
                &format!("secret {purge_canary}"),
            ],
        )
        .await
        .expect("seed purge msg");
    let p_id: i64 = p_row.try_get(0).expect("pid");
    let p_ts: chrono::DateTime<Utc> = p_row.try_get(1).expect("pts");

    pipeline
        .run_batch(&SearchIndexBatchPayload {
            corpus: Some(DocCorpus::Mail),
            batch_limit: Some(500),
        })
        .await
        .expect("index purge msg");
    let epoch_dir = engine.epoch_dir_path(engine.current_manifest().expect("m").epoch);
    assert!(
        count_needle_in_dir(&epoch_dir, purge_canary.as_bytes()) > 0,
        "canary must exist on disk before lawful purge"
    );

    // Hard DELETE in PG -> V299 trigger enqueues 'search.purge_evict'!
    owner
        .execute(
            "DELETE FROM public.messages WHERE id = $1 AND received_at = $2",
            &[&p_id, &p_ts],
        )
        .await
        .expect("hard delete message");
    let purge_work_cnt: i64 = worker
        .query_one(
            "SELECT count(*) FROM public.work_items \
              WHERE kind = 'search.purge_evict' \
                AND idempotency_key = $1",
            &[&format!("search.purge_evict:mail:{mb_a}:{p_id}:0")],
        )
        .await
        .expect("purge work check")
        .try_get(0)
        .expect("cnt");
    assert_eq!(
        purge_work_cnt, 1,
        "V299 hard-delete trigger must enqueue search.purge_evict"
    );

    // Evict & compact physically off disk!
    engine
        .evict_and_compact(&[DocumentKey::Mail {
            mailbox_id: mb_a,
            id: p_id,
            received_at: p_ts,
        }])
        .await
        .expect("evict_and_compact");
    assert_eq!(
        count_needle_in_dir(&epoch_dir, purge_canary.as_bytes()),
        0,
        "0 bytes of purged canary may remain anywhere under epoch dir after compaction"
    );

    // =========================================================================
    // 4. HA Two-Node SKIP LOCKED Leader Election + Live Follower RemoteSearchEngine
    // =========================================================================
    worker
        .execute("DELETE FROM public.search_leader_leases", &[])
        .await
        .expect("clean leases");

    let rpc_secret = b"wave33-db-ha-rpc-shared-secret-32".to_vec();
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let leader_url = format!("http://{addr}");

    // Node A acquires lease
    let acq_a = try_acquire_search_leader(worker.as_ref(), "node-alpha", &leader_url, 30)
        .await
        .expect("acquire a");
    assert!(acq_a.acquired);
    assert_eq!(acq_a.fencing_token, 1);

    // Node B fails to steal active lease
    let acq_b_fail =
        try_acquire_search_leader(worker.as_ref(), "node-beta", "http://127.0.0.1:1", 30)
            .await
            .expect("acquire b blocked");
    assert!(!acq_b_fail.acquired);
    assert_eq!(acq_b_fail.holder_node_id, "node-alpha");

    // Heartbeat updates epoch & generation
    let m_cur = engine.current_manifest().expect("manifest");
    assert!(heartbeat_search_leader(
        worker.as_ref(),
        "node-alpha",
        acq_a.fencing_token,
        m_cur.epoch,
        m_cur.generation,
        30,
    )
    .await
    .expect("hb a"));
    let cur = current_search_leader(worker.as_ref())
        .await
        .expect("current")
        .expect("some leader");
    assert_eq!(cur.holder_node_id, "node-alpha");
    assert_eq!(cur.rpc_url, leader_url);

    // Serve authenticated POST /_internal/search/candidates on loopback for follower RemoteSearchEngine!
    let srv_engine = Arc::clone(&engine);
    let srv_secret = rpc_secret.clone();
    let (stop_tx, mut stop_rx) = tokio::sync::oneshot::channel::<()>();
    let srv_task = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut stop_rx => break,
                accepted = listener.accept() => {
                    let Ok((mut stream, _)) = accepted else { break };
                    let eng = Arc::clone(&srv_engine);
                    let sec = srv_secret.clone();
                    tokio::spawn(async move {
                        let mut buf = vec![0u8; 65536];
                        let n = stream.read(&mut buf).await.unwrap_or(0);
                        if n == 0 { return; }
                        let req_str = String::from_utf8_lossy(&buf[..n]);
                        let Some((head, body_str)) = req_str.split_once("\r\n\r\n") else { return; };
                        let mut ts = None;
                        let mut sig = None;
                        for line in head.lines().skip(1) {
                            if let Some((k, v)) = line.split_once(':') {
                                if k.eq_ignore_ascii_case(HEADER_SEARCH_TS) {
                                    ts = Some(v.trim().to_owned());
                                } else if k.eq_ignore_ascii_case(HEADER_SEARCH_SIG) {
                                    sig = Some(v.trim().to_owned());
                                }
                            }
                        }
                        let body_bytes = body_str.as_bytes();
                        if verify_rpc_request(
                            &sec,
                            "POST",
                            INTERNAL_SEARCH_CANDIDATES_PATH,
                            ts.as_deref(),
                            sig.as_deref(),
                            body_bytes,
                            Utc::now().timestamp(),
                        ).is_err() {
                            let _ = stream.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 2\r\n\r\n{}").await;
                            return;
                        }
                        let dto: RpcCandidateRequest = serde_json::from_slice(body_bytes).expect("dto");
                        let q = dto.into_query().expect("q");
                        let batch = eng.candidates(&q).await.expect("candidates");
                        let resp_json = serde_json::to_string(&RpcCandidateResponse {
                            keys: batch.keys,
                            generation: batch.generation,
                            continuation: batch.continuation,
                            degraded: batch.degraded,
                        }).expect("json");
                        let raw = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                            resp_json.len(),
                            resp_json
                        );
                        let _ = stream.write_all(raw.as_bytes()).await;
                    });
                }
            }
        }
    });

    let resolver = Arc::new(DbLeaderResolver::new(Arc::clone(&worker) as _));
    let remote = Arc::new(
        RemoteSearchEngine::new(resolver, rpc_secret, Duration::from_millis(500)).expect("remote"),
    );
    let fb_key = DocumentKey::Mail {
        mailbox_id: mb_a,
        id: 888_888,
        received_at: ed_m1_ts,
    };
    let fb_clone = fb_key.clone();
    let tier1 = Arc::new(Tier1PgSearchEngine::new(
        PgSearchCapabilities::default(),
        Arc::new(move |_q| {
            let k = fb_clone.clone();
            Box::pin(async move {
                Ok(CandidateBatch {
                    keys: vec![k],
                    generation: 0,
                    continuation: None,
                    tier: SearchTier::Tier1Pg,
                    degraded: false,
                })
            })
        }),
    ));
    let follower = TwoTierSearchEngine::with_remote_tier2(cfg, tier1, remote);
    let q = CandidateQuery {
        corpus: DocCorpus::Mail,
        scope_hint: ScopeHint::Mailbox(mb_a),
        terms: NormalizedQuery::parse(&edisc_token).expect("q"),
        visibility: SearchVisibility::ComplianceOnly,
        limit: 10,
        continuation: None,
        metadata_only: false,
        calculate_total: false,
    };
    let rpc_hits = follower.candidates(&q).await.expect("follower rpc hit");
    assert_eq!(rpc_hits.tier, SearchTier::Tier2Tantivy);
    assert!(!rpc_hits.degraded);
    assert!(rpc_hits
        .keys
        .iter()
        .any(|k| matches!(k, DocumentKey::Mail { id, .. } if *id == ed_m1_id)));

    // Graceful leader release -> Node B takes over immediately with fencing_token = 2!
    assert!(
        release_search_leader(worker.as_ref(), "node-alpha", acq_a.fencing_token)
            .await
            .expect("release a")
    );
    assert!(current_search_leader(worker.as_ref())
        .await
        .expect("current none")
        .is_none());
    let acq_b_ok =
        try_acquire_search_leader(worker.as_ref(), "node-beta", "http://127.0.0.1:1", 30)
            .await
            .expect("acquire b takeover");
    assert!(acq_b_ok.acquired);
    assert_eq!(acq_b_ok.fencing_token, 2);
    // Verify child-table hard DELETE triggers on message_attachments & scheduled_actions enqueue purge_evict!
    let del_att_id: i64 = owner
        .query_one(
            "SELECT id FROM public.message_attachments WHERE message_id = $1 AND received_at = $2 LIMIT 1",
            &[&smime_id, &smime_ts],
        )
        .await
        .expect("find att")
        .try_get(0)
        .expect("att_id");
    owner
        .execute(
            "DELETE FROM public.message_attachments WHERE id = $1",
            &[&del_att_id],
        )
        .await
        .expect("delete child attachment");
    let att_purge_cnt: i64 = worker
        .query_one(
            "SELECT count(*) FROM public.work_items \
              WHERE kind = 'search.purge_evict' \
                AND idempotency_key = $1",
            &[&format!(
                "search.purge_evict:mail_attachment:{mb_a}:{smime_id}:{del_att_id}"
            )],
        )
        .await
        .expect("att purge queue")
        .try_get(0)
        .expect("cnt");
    assert!(
        att_purge_cnt >= 1,
        "direct DELETE on message_attachments must enqueue search.purge_evict for mail_attachment"
    );
    let parent_mail_purge_cnt: i64 = worker
        .query_one(
            "SELECT count(*) FROM public.work_items \
              WHERE kind = 'search.purge_evict' \
                AND idempotency_key = $1",
            &[&format!("search.purge_evict:mail:{mb_a}:{smime_id}:0")],
        )
        .await
        .expect("parent mail purge queue")
        .try_get(0)
        .expect("cnt");
    assert!(
        parent_mail_purge_cnt >= 1,
        "direct DELETE on message_attachments must also enqueue parent mail purge eviction"
    );

    // Verify websearch boolean `OR` eDiscovery query cleanly defers to Tier-1 PG `websearch_to_tsquery`
    // and returns hits matching EITHER side (never dropped by Tantivy `Occur::Must`)!
    let or_search_id: i64 = owner
        .query_one(
            "INSERT INTO public.ediscovery_searches (name, created_by, query, status) \
             VALUES ($1, $2, $3::text::jsonb, 'pending') RETURNING id",
            &[
                &format!("edisc-or-558-{tag}"),
                &user_a,
                &serde_json::json!({
                    "keywords": format!("{edisc_token} OR nonexistent_other_token_558"),
                    "mailboxIds": [mb_a]
                })
                .to_string(),
            ],
        )
        .await
        .expect("seed or search")
        .try_get(0)
        .expect("id");
    let or_prov = executor
        .execute(or_search_id, user_a)
        .await
        .expect("execute OR ediscovery");
    assert_eq!(
        or_prov.engine_tier, "tier1_pg_fallback",
        "websearch OR query must defer cleanly to Tier-1 PG websearch_to_tsquery"
    );
    assert_eq!(
        or_prov.result_count, 2,
        "OR query must return BOTH matching messages (Tantivy indexed + PG tail)"
    );

    owner
        .execute(
            "DELETE FROM public.scheduled_actions WHERE id::text = $1",
            &[&sched_uuid],
        )
        .await
        .expect("delete scheduled_action");
    let sched_purge_cnt: i64 = worker
        .query_one(
            "SELECT count(*) FROM public.work_items \
              WHERE kind = 'search.purge_evict' \
                AND idempotency_key = $1",
            &[&format!("search.purge_evict:chat:{ch_id}:{sched_doc_id}:0")],
        )
        .await
        .expect("sched purge queue")
        .try_get(0)
        .expect("cnt");
    assert!(
        sched_purge_cnt >= 1,
        "direct DELETE on scheduled_actions must enqueue search.purge_evict"
    );

    // Same-node re-acquisition after release/expiry MUST increment fencing_token monotonically (2 -> 3)!
    assert!(
        release_search_leader(worker.as_ref(), "node-beta", acq_b_ok.fencing_token)
            .await
            .expect("release b")
    );
    let acq_b_again =
        try_acquire_search_leader(worker.as_ref(), "node-beta", "http://127.0.0.1:1", 30)
            .await
            .expect("same-node expired re-acquire");
    assert!(acq_b_again.acquired);
    assert_eq!(
        acq_b_again.fencing_token, 3,
        "same-node expired re-acquire must increment fencing_token monotonically"
    );

    // Stale Node A heartbeat with fencing_token = 1 is rejected!
    assert!(!heartbeat_search_leader(
        worker.as_ref(),
        "node-alpha",
        1,
        m_cur.epoch,
        m_cur.generation,
        30
    )
    .await
    .expect("stale hb rejected"));

    // Stop leader HTTP server -> follower degrades cleanly to Tier-1 PG!
    let _ = stop_tx.send(());
    let _ = srv_task.await;
    let degraded = follower
        .candidates(&q)
        .await
        .expect("fallback on dead leader");
    assert_eq!(degraded.tier, SearchTier::Tier1Pg);
    assert!(degraded.degraded);
    assert_eq!(degraded.keys, vec![fb_key]);
}
