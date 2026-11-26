//! Live-PostgreSQL integration tests for `setjoin-search` (Wave 3.1 / #556).
//!
//! Covers:
//! 1. Tier-1 search without `pg_bigm` (Xinchuang simulation on local PG17), including
//!    `ScopeHint::Channels`/`Spaces` filtering, empty-scope fail-closed, and `ComplianceOnly` rejection.
//! 2. R1–R4 cross-mailbox & cross-user candidate poisoning blocked by PG `setjoin_app`
//!    (`NOBYPASSRLS`) re-authorization across Mail, MailAttachment (`sub_id`), Chat, and Drive.
//! 3. Deleted / held / `compliance_only` row filtering + S/MIME `V029` C7 boundary +
//!    guest `history_floor_seq` and parent-message history floor enforcement.
//! 4. `search_dirty_keys` and `search_index_watermarks` deny-all under `setjoin_app` (`42501`)
//!    with `setjoin_worker` BYPASSRLS control (and clean state restoration afterwards).
//! 5. Strict `pg_dump` / `PGDATA` exclusion proof (asserts `pg_dump` exits 0 with non-empty SQL
//!    and zero Tantivy index files/paths).

use chrono::{Duration, Utc};
use setjoin_authz::principals::TxFactory;
use setjoin_conformance::db_gate::{resolve as resolve_db_gate, DbGate};
use setjoin_contracts::ids::ActorId;
use setjoin_pg::AppPool;
use setjoin_search::{
    execute_overfetch_page, probe_pg_capabilities_client, reauthorize_chat_candidates,
    reauthorize_drive_candidates, reauthorize_mail_candidates, tier1_chat_candidates,
    tier1_drive_candidates, tier1_mail_candidates, CandidateQuery, DocCorpus, DocumentKey,
    IndexDocument, MailReauthFilter, NormalizedQuery, ScopeHint, SearchConfig, SearchError,
    SearchTier, SearchVisibility, TantivySearchEngine,
};
use std::process::Command;
use std::sync::atomic::{AtomicI64, Ordering};
use tempfile::TempDir;
use tokio_postgres::types::ToSql;
use tokio_postgres::NoTls;

static SEED_SEQ: AtomicI64 = AtomicI64::new(910_000);

fn next_tag() -> i64 {
    let seq = SEED_SEQ.fetch_add(1, Ordering::SeqCst);
    (Utc::now().timestamp_micros() & 0x0FFF_FFFF).saturating_add(seq)
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

async fn seed_user_and_mailbox(
    owner: &tokio_postgres::Client,
    suffix: &str,
) -> (i64, i64, i64, String) {
    let email = format!("search556_{suffix}@example.test");
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
            &[&email, &format!("u_{suffix}")],
        )
        .await
        .expect("seed user+mailbox+folder");
    let user_id: i64 = row.try_get(0).expect("user_id");
    let mailbox_id: i64 = row.try_get(1).expect("mailbox_id");
    let folder_id: i64 = row.try_get(2).expect("folder_id");
    (user_id, mailbox_id, folder_id, email)
}

#[allow(clippy::too_many_arguments)]
async fn seed_message(
    owner: &tokio_postgres::Client,
    mailbox_id: i64,
    folder_id: i64,
    subject: &str,
    from_addr: &str,
    body_text: &str,
    is_deleted: bool,
    held: bool,
    crypto_type: Option<&str>,
) -> (i64, chrono::DateTime<Utc>) {
    let msg_id = format!("<msg-{}@example.test>", next_tag());
    let received_at = Utc::now() - Duration::seconds(5);
    let row = owner
        .query_one(
            "INSERT INTO public.messages ( \
               mailbox_id, folder_id, message_id, subject, from_addr, from_name, \
               body_text, thread_id, raw_ref, is_deleted, held, crypto_type, received_at \
             ) VALUES ( \
               $1, $2, $3, $4, $5, 'Sender', $6, $3, 'sha256:test', $7, $8, $9, $10 \
             ) RETURNING id, received_at",
            &[
                &mailbox_id,
                &folder_id,
                &msg_id,
                &subject,
                &from_addr,
                &body_text,
                &is_deleted,
                &held,
                &crypto_type,
                &received_at,
            ],
        )
        .await
        .expect("insert message");
    (
        row.try_get(0).expect("id"),
        row.try_get(1).expect("received_at"),
    )
}

#[tokio::test]
async fn live_db_two_tier_security_isolation_xinchuang_and_pg_dump_exclusion() {
    let (owner_dsn, app_opt) = match resolve_db_gate(|k| std::env::var(k).ok()) {
        DbGate::Run { dsn, app, .. } => (dsn, app),
        DbGate::Skip => {
            eprintln!("SETJOIN-SEARCH-DB-SKIP (reason=no-dsn)");
            return;
        }
        DbGate::Missing => panic!("REQUIRE_DB=1 set but TEST_DB_DSN/DB_DSN is absent"),
    };

    let owner = connect_as(&owner_dsn).await;
    let app_dsn = app_opt.unwrap_or_else(|| swap_dsn_user(&owner_dsn, "setjoin_app"));
    let worker_dsn = std::env::var("DB_WORKER_DSN")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| swap_dsn_user(&owner_dsn, "setjoin_worker"));

    // 1. Confirm V290 registered + probe capabilities without pg_bigm (Xinchuang simulation).
    let v290: bool = owner
        .query_one(
            "SELECT EXISTS(SELECT 1 FROM public.schema_migrations WHERE version = 290)",
            &[],
        )
        .await
        .expect("query schema_migrations")
        .try_get(0)
        .expect("bool");
    assert!(v290, "V290 migration must be applied");

    let caps = probe_pg_capabilities_client(&owner)
        .await
        .expect("probe pg capabilities");
    assert!(
        !caps.has_pg_bigm,
        "local PG17 Xinchuang test expects pg_bigm absent (got {caps:?})"
    );

    // 2. Verify search_dirty_keys & search_index_watermarks deny-all under setjoin_app (42501)
    //    and writable under setjoin_worker (BYPASSRLS), snapshotting & restoring any pre-existing watermark.
    let worker_client = connect_as(&worker_dsn).await;
    let tag = next_tag();
    let prior_watermark: Option<(i64, i64, String, chrono::DateTime<Utc>)> = worker_client
        .query_opt(
            "SELECT epoch, generation, schema_hash, watermark_ts \
               FROM public.search_index_watermarks WHERE corpus = 'mail_attachment'",
            &[],
        )
        .await
        .expect("snapshot prior watermark")
        .map(|row| {
            (
                row.try_get(0).expect("epoch"),
                row.try_get(1).expect("generation"),
                row.try_get(2).expect("schema_hash"),
                row.try_get(3).expect("watermark_ts"),
            )
        });
    worker_client
        .execute(
            "INSERT INTO public.search_dirty_keys (corpus, scope_id, doc_id, received_at_us, sub_id, op, generation) \
             VALUES ('mail', $1, $2, 1000, 0, 'upsert', 1) \
             ON CONFLICT (corpus, scope_id, doc_id, received_at_us, sub_id) DO UPDATE SET generation = EXCLUDED.generation",
            &[&tag, &tag],
        )
        .await
        .expect("setjoin_worker must write search_dirty_keys");
    worker_client
        .execute(
            "INSERT INTO public.search_index_watermarks (corpus, epoch, generation, schema_hash) \
             VALUES ('mail_attachment', 1, 1, 'test-hash') \
             ON CONFLICT (corpus) DO UPDATE SET epoch = EXCLUDED.epoch, generation = EXCLUDED.generation, schema_hash = EXCLUDED.schema_hash",
            &[],
        )
        .await
        .expect("setjoin_worker must write search_index_watermarks");

    let app_client = connect_as(&app_dsn).await;
    for stmt in [
        "SELECT count(*) FROM public.search_dirty_keys",
        "INSERT INTO public.search_dirty_keys (corpus, scope_id, doc_id, op) VALUES ('mail', 1, 1, 'upsert')",
        "SELECT count(*) FROM public.search_index_watermarks",
        "INSERT INTO public.search_index_watermarks (corpus, epoch, generation) VALUES ('chat', 1, 1)",
    ] {
        let err = app_client
            .simple_query(stmt)
            .await
            .expect_err("setjoin_app must be denied on search staging tables");
        let code = err.code().map(|c| c.code().to_owned());
        assert_eq!(
            code.as_deref(),
            Some("42501"),
            "expected SQLSTATE 42501 for `{stmt}`, got {err:?}"
        );
    }

    // Restore staging/watermark rows written by this test.
    worker_client
        .execute(
            "DELETE FROM public.search_dirty_keys WHERE corpus = 'mail' AND scope_id = $1 AND doc_id = $2",
            &[&tag, &tag],
        )
        .await
        .expect("cleanup dirty key");
    if let Some((epoch, generation, schema_hash, watermark_ts)) = prior_watermark {
        worker_client
            .execute(
                "INSERT INTO public.search_index_watermarks (corpus, epoch, generation, schema_hash, watermark_ts) \
                 VALUES ('mail_attachment', $1, $2, $3, $4) \
                 ON CONFLICT (corpus) DO UPDATE SET epoch = EXCLUDED.epoch, generation = EXCLUDED.generation, schema_hash = EXCLUDED.schema_hash, watermark_ts = EXCLUDED.watermark_ts",
                &[&epoch, &generation, &schema_hash, &watermark_ts],
            )
            .await
            .expect("restore prior watermark");
    } else {
        worker_client
            .execute(
                "DELETE FROM public.search_index_watermarks WHERE corpus = 'mail_attachment'",
                &[],
            )
            .await
            .expect("cleanup watermark");
    }

    // 3. Seed two isolated tenants (A and B) with mail, attachment, S/MIME sealed mail,
    //    deleted/held mail, chat messages (including guest history floor & parent floor), and drive nodes.
    let (user_a, mb_a, folder_a, email_a) =
        seed_user_and_mailbox(&owner, &format!("a_{tag}")).await;
    let (user_b, mb_b, folder_b, _email_b) =
        seed_user_and_mailbox(&owner, &format!("b_{tag}")).await;

    let token = format!("xinchuangtok{tag}");
    let cjk_token = "北京审批合同";
    let (msg_a_live, ts_a_live) = seed_message(
        &owner,
        mb_a,
        folder_a,
        &format!("{cjk_token} {token} live"),
        "alice@example.test",
        &format!("Normal body {token} {cjk_token}"),
        false,
        false,
        None,
    )
    .await;
    // Seed a valid attachment on msg_a_live to verify MailAttachment sub_id authorization.
    let att_sha = format!("{:064x}", tag);
    owner
        .execute(
            "INSERT INTO public.blobs (sha256, minio_ref, size_bytes, content_type) \
             VALUES ($1, $2, 128, 'application/pdf') ON CONFLICT (sha256) DO NOTHING",
            &[&att_sha, &format!("blobs/{att_sha}")],
        )
        .await
        .expect("seed blob");
    let att_a_id: i64 = owner
        .query_one(
            "INSERT INTO public.message_attachments (message_id, received_at, blob_sha256, filename, content_type, size_bytes) \
             VALUES ($1, $2, $3, 'invoice.pdf', 'application/pdf', 128) RETURNING id",
            &[&msg_a_live, &ts_a_live, &att_sha],
        )
        .await
        .expect("seed attachment")
        .try_get(0)
        .expect("att id");

    let (msg_a_deleted, ts_a_deleted) = seed_message(
        &owner,
        mb_a,
        folder_a,
        &format!("{token} soft-deleted"),
        "alice@example.test",
        &format!("Deleted body {token}"),
        true,
        false,
        None,
    )
    .await;
    let (msg_a_held_deleted, ts_a_held_deleted) = seed_message(
        &owner,
        mb_a,
        folder_a,
        &format!("{token} compliance-only held tombstone"),
        "alice@example.test",
        &format!("Compliance held deleted body {token}"),
        true,
        true,
        None,
    )
    .await;
    let (msg_a_held_live, ts_a_held_live) = seed_message(
        &owner,
        mb_a,
        folder_a,
        &format!("{token} held-live"),
        "alice@example.test",
        &format!("Held live body {token}"),
        false,
        true,
        None,
    )
    .await;
    let smime_secret = format!("smimeciphertextsecret{tag}");
    let (msg_a_smime, ts_a_smime) = seed_message(
        &owner,
        mb_a,
        folder_a,
        &format!("{token} smime-cleartext-subject"),
        "smime@example.test",
        &smime_secret,
        false,
        false,
        Some("smime-encrypted"),
    )
    .await;
    let (msg_b_poison, ts_b_poison) = seed_message(
        &owner,
        mb_b,
        folder_b,
        &format!("{token} TENANT-B-SECRET"),
        "bob@example.test",
        &format!("Tenant B confidential {token}"),
        false,
        false,
        None,
    )
    .await;

    // Seed Chat channels:
    // - ch_a: user A is owner (no floor)
    // - ch_floor: user A has history_floor_seq = 5 (guest history floor test + parent floor test)
    // - ch_b: user B only (non-member poison test)
    let ch_a_name = format!("ch-a-{tag}");
    let ch_floor_name = format!("ch-floor-{tag}");
    let ch_b_name = format!("ch-b-{tag}");
    let ch_a: i64 = owner
        .query_one(
            "INSERT INTO public.chat_channels (kind, name, visibility, created_by) \
             VALUES ('channel', $1, 'private', $2) RETURNING id",
            &[&ch_a_name as &(dyn ToSql + Sync), &user_a],
        )
        .await
        .expect("ch_a")
        .try_get(0)
        .expect("ch_a id");
    let ch_floor: i64 = owner
        .query_one(
            "INSERT INTO public.chat_channels (kind, name, visibility, created_by) \
             VALUES ('channel', $1, 'private', $2) RETURNING id",
            &[&ch_floor_name as &(dyn ToSql + Sync), &user_b],
        )
        .await
        .expect("ch_floor")
        .try_get(0)
        .expect("ch_floor id");
    let ch_b: i64 = owner
        .query_one(
            "INSERT INTO public.chat_channels (kind, name, visibility, created_by) \
             VALUES ('channel', $1, 'private', $2) RETURNING id",
            &[&ch_b_name as &(dyn ToSql + Sync), &user_b],
        )
        .await
        .expect("ch_b")
        .try_get(0)
        .expect("ch_b id");
    owner
        .execute(
            "INSERT INTO public.chat_channel_members (channel_id, user_id, role) \
             VALUES ($1, $2, 'owner'), ($3, $4, 'owner'), ($5, $4, 'owner')",
            &[&ch_a, &user_a, &ch_b, &user_b, &ch_floor],
        )
        .await
        .expect("chat members");
    // User A joined ch_floor with history_floor_seq = 5 at joined_at = now() - 60s.
    let floor_joined_at = Utc::now() - Duration::seconds(60);
    owner
        .execute(
            "INSERT INTO public.chat_channel_members (channel_id, user_id, role, joined_at, history_floor_seq) \
             VALUES ($1, $2, 'member', $3, 5)",
            &[&ch_floor, &user_a, &floor_joined_at],
        )
        .await
        .expect("chat guest floor member");

    let chat_a_live: i64 = owner
        .query_one(
            "INSERT INTO public.chat_messages (channel_id, seq, author_id, body) VALUES ($1, 1, $2, $3) RETURNING id",
            &[&ch_a, &user_a, &format!("{cjk_token} chat live {token}")],
        )
        .await
        .expect("chat_a_live")
        .try_get(0)
        .expect("id");
    let chat_a_deleted: i64 = owner
        .query_one(
            "INSERT INTO public.chat_messages (channel_id, seq, author_id, body, deleted_at) VALUES ($1, 2, $2, $3, now()) RETURNING id",
            &[&ch_a, &user_a, &format!("chat deleted {token}")],
        )
        .await
        .expect("chat_a_deleted")
        .try_get(0)
        .expect("id");
    let chat_b_poison: i64 = owner
        .query_one(
            "INSERT INTO public.chat_messages (channel_id, seq, author_id, body) VALUES ($1, 1, $2, $3) RETURNING id",
            &[&ch_b, &user_b, &format!("chat tenant B {token}")],
        )
        .await
        .expect("chat_b_poison")
        .try_get(0)
        .expect("id");

    // Pre-floor parent message (seq=3 <= 5, created before joined_at)
    let floor_pre_parent: i64 = owner
        .query_one(
            "INSERT INTO public.chat_messages (channel_id, seq, author_id, body, created_at) \
             VALUES ($1, 3, $2, $3, $4) RETURNING id",
            &[
                &ch_floor,
                &user_b,
                &format!("prefloor parent {token}"),
                &(floor_joined_at - Duration::seconds(120)),
            ],
        )
        .await
        .expect("floor_pre_parent")
        .try_get(0)
        .expect("id");
    // Post-floor reply whose parent is PRE-FLOOR (seq=6 > 5, created after joined_at, parent seq=3 <= 5 -> MUST BE HIDDEN!)
    let floor_reply_to_pre_parent: i64 = owner
        .query_one(
            "INSERT INTO public.chat_messages (channel_id, seq, author_id, parent_message_id, body, created_at) \
             VALUES ($1, 6, $2, $3, $4, $5) RETURNING id",
            &[
                &ch_floor,
                &user_b,
                &floor_pre_parent,
                &format!("reply to prefloor parent {token}"),
                &(floor_joined_at + Duration::seconds(10)),
            ],
        )
        .await
        .expect("floor_reply_to_pre_parent")
        .try_get(0)
        .expect("id");
    // Post-floor top-level message (seq=7 > 5, created after joined_at -> MUST BE VISIBLE!)
    let floor_post_visible: i64 = owner
        .query_one(
            "INSERT INTO public.chat_messages (channel_id, seq, author_id, body, created_at) \
             VALUES ($1, 7, $2, $3, $4) RETURNING id",
            &[
                &ch_floor,
                &user_b,
                &format!("postfloor visible {token}"),
                &(floor_joined_at + Duration::seconds(20)),
            ],
        )
        .await
        .expect("floor_post_visible")
        .try_get(0)
        .expect("id");

    // Seed Drive spaces & nodes (A owns space_a + extra space_a2; B owns space_b).
    let space_a_name = format!("space-a-{tag}");
    let space_a2_name = format!("space-a2-{tag}");
    let space_b_name = format!("space-b-{tag}");
    let space_a: i64 = owner
        .query_one(
            "INSERT INTO public.drive_spaces (is_personal, owner_user_id, name) VALUES (true, $1, $2) RETURNING id",
            &[&user_a as &(dyn ToSql + Sync), &space_a_name],
        )
        .await
        .expect("space_a")
        .try_get(0)
        .expect("space_a id");
    let space_a2: i64 = owner
        .query_one(
            "INSERT INTO public.drive_spaces (is_personal, owner_user_id, name) VALUES (false, $1, $2) RETURNING id",
            &[&user_a as &(dyn ToSql + Sync), &space_a2_name],
        )
        .await
        .expect("space_a2")
        .try_get(0)
        .expect("space_a2 id");
    let space_b: i64 = owner
        .query_one(
            "INSERT INTO public.drive_spaces (is_personal, owner_user_id, name) VALUES (true, $1, $2) RETURNING id",
            &[&user_b as &(dyn ToSql + Sync), &space_b_name],
        )
        .await
        .expect("space_b")
        .try_get(0)
        .expect("space_b id");
    owner
        .execute(
            "INSERT INTO public.drive_space_members (space_id, user_id, role, granted_by) \
             VALUES ($1, $2, 'manager', $2), ($3, $2, 'manager', $2), ($4, $5, 'manager', $5)",
            &[&space_a, &user_a, &space_a2, &space_b, &user_b],
        )
        .await
        .expect("drive members");
    let node_a_live: i64 = owner
        .query_one(
            "INSERT INTO public.drive_nodes (space_id, kind, name, created_by) VALUES ($1, 'file', $2, $3) RETURNING id",
            &[&space_a, &format!("{cjk_token}-{token}.pdf"), &user_a],
        )
        .await
        .expect("node_a_live")
        .try_get(0)
        .expect("id");
    let _node_a2_other_space: i64 = owner
        .query_one(
            "INSERT INTO public.drive_nodes (space_id, kind, name, created_by) VALUES ($1, 'file', $2, $3) RETURNING id",
            &[&space_a2, &format!("{cjk_token}-other-{token}.pdf"), &user_a],
        )
        .await
        .expect("node_a2")
        .try_get(0)
        .expect("id");
    let node_a_deleted: i64 = owner
        .query_one(
            "INSERT INTO public.drive_nodes (space_id, kind, name, created_by, deleted_at) VALUES ($1, 'file', $2, $3, now()) RETURNING id",
            &[&space_a, &format!("deleted-{token}.pdf"), &user_a],
        )
        .await
        .expect("node_a_deleted")
        .try_get(0)
        .expect("id");
    let node_b_poison: i64 = owner
        .query_one(
            "INSERT INTO public.drive_nodes (space_id, kind, name, created_by) VALUES ($1, 'file', $2, $3) RETURNING id",
            &[&space_b, &format!("tenant-b-{token}.pdf"), &user_b],
        )
        .await
        .expect("node_b_poison")
        .try_get(0)
        .expect("id");

    // 4. Open AppPool as setjoin_app (NOBYPASSRLS) via TxFactory and mint Tenant A principals.
    let app_pool = AppPool::from_dsn(&app_dsn, 4).expect("AppPool as setjoin_app");
    let factory = TxFactory::new(app_pool);
    let actor_a = ActorId::new(user_a).expect("actor A");
    let mb_principal_a = factory
        .mint_capability_primary_mailbox(actor_a, &email_a, "127.0.0.1")
        .await
        .expect("mint mailbox A");
    let read_cap_a = mb_principal_a.require_read().expect("read cap A");
    let user_principal_a = factory
        .mint_capability_user(actor_a, &email_a, "127.0.0.1")
        .await
        .expect("mint user A");

    // 4a. Tier-1 Mail search WITHOUT pg_bigm (CJK + S/MIME C7 + ComplianceOnly rejection).
    {
        let mut tx = factory
            .begin_mailbox_read(&read_cap_a)
            .await
            .expect("begin mailbox read");
        let q_cjk = CandidateQuery {
            corpus: DocCorpus::Mail,
            scope_hint: ScopeHint::Mailbox(mb_a),
            terms: NormalizedQuery::parse(cjk_token).expect("q"),
            visibility: SearchVisibility::Live,
            limit: 20,
            continuation: None,
            metadata_only: false,
            calculate_total: false,
        };
        let batch = tier1_mail_candidates(&mut tx, &q_cjk, caps)
            .await
            .expect("tier1 mail cjk");
        assert_eq!(batch.tier, SearchTier::Tier1Pg);
        assert!(
            batch
                .keys
                .iter()
                .any(|k| matches!(k, DocumentKey::Mail { id, .. } if *id == msg_a_live)),
            "Tier-1 without pg_bigm must recall live CJK mail"
        );
        assert!(
            !batch.keys.iter().any(|k| matches!(k, DocumentKey::Mail { id, .. } if *id == msg_b_poison || *id == msg_a_deleted || *id == msg_a_held_deleted)),
            "Tier-1 mail must exclude tenant B and deleted/compliance-only rows"
        );

        // S/MIME V029 C7: searching encrypted body ciphertext MUST return 0 hits!
        let q_smime = CandidateQuery {
            corpus: DocCorpus::Mail,
            scope_hint: ScopeHint::Mailbox(mb_a),
            terms: NormalizedQuery::parse(&smime_secret).expect("q"),
            visibility: SearchVisibility::Live,
            limit: 20,
            continuation: None,
            metadata_only: false,
            calculate_total: false,
        };
        let smime_batch = tier1_mail_candidates(&mut tx, &q_smime, caps)
            .await
            .expect("tier1 smime check");
        assert!(
            smime_batch.keys.is_empty(),
            "V029 C7 violation: Tier-1 matched smime-encrypted body_text!"
        );

        // ComplianceOnly rejected on user-scoped Tier-1.
        let mut q_comp = q_cjk.clone();
        q_comp.visibility = SearchVisibility::ComplianceOnly;
        assert!(matches!(
            tier1_mail_candidates(&mut tx, &q_comp, caps).await,
            Err(SearchError::Unavailable(_))
        ));
        tx.finish().await.expect("finish");
    }

    // 4b. R1-R4 Mail & MailAttachment Candidate Poisoning Proof.
    {
        let poisoned = vec![
            // Tenant B key (mismatched mailbox_id)
            DocumentKey::Mail {
                mailbox_id: mb_b,
                id: msg_b_poison,
                received_at: ts_b_poison,
            },
            // Poisoned key claiming mb_a but carrying Tenant B's (id, received_at)
            DocumentKey::Mail {
                mailbox_id: mb_a,
                id: msg_b_poison,
                received_at: ts_b_poison,
            },
            DocumentKey::Mail {
                mailbox_id: mb_a,
                id: msg_a_deleted,
                received_at: ts_a_deleted,
            },
            DocumentKey::Mail {
                mailbox_id: mb_a,
                id: msg_a_held_deleted,
                received_at: ts_a_held_deleted,
            },
            DocumentKey::Mail {
                mailbox_id: mb_a,
                id: msg_a_live,
                received_at: ts_a_live,
            },
            // Unverified bogus MailAttachment sub_id -> MUST be rejected!
            DocumentKey::MailAttachment {
                mailbox_id: mb_a,
                id: msg_a_live,
                received_at: ts_a_live,
                sub_id: 999_999_999,
            },
            // Valid MailAttachment sub_id -> MUST be admitted!
            DocumentKey::MailAttachment {
                mailbox_id: mb_a,
                id: msg_a_live,
                received_at: ts_a_live,
                sub_id: att_a_id,
            },
            DocumentKey::Mail {
                mailbox_id: mb_a,
                id: msg_a_held_live,
                received_at: ts_a_held_live,
            },
            DocumentKey::Mail {
                mailbox_id: mb_a,
                id: msg_a_smime,
                received_at: ts_a_smime,
            },
        ];

        let mut tx = factory
            .begin_mailbox_read(&read_cap_a)
            .await
            .expect("begin mailbox read");
        let auth_default =
            reauthorize_mail_candidates(&mut tx, &poisoned, &MailReauthFilter::default())
                .await
                .expect("reauth mail");
        let ids: Vec<i64> = auth_default.iter().map(|h| h.id).collect();
        assert_eq!(
            ids,
            vec![msg_a_live, msg_a_live, msg_a_held_live, msg_a_smime],
            "PG re-auth under setjoin_app MUST block Tenant B poison, bogus sub_id, deleted, and held-deleted rows"
        );
        assert!(
            auth_default[3].crypto_sealed,
            "smime row must report crypto_sealed=true"
        );

        let auth_no_held = reauthorize_mail_candidates(
            &mut tx,
            &poisoned,
            &MailReauthFilter {
                exclude_held: true,
                ..MailReauthFilter::default()
            },
        )
        .await
        .expect("reauth exclude_held");
        let no_held_ids: Vec<i64> = auth_no_held.iter().map(|h| h.id).collect();
        assert_eq!(no_held_ids, vec![msg_a_live, msg_a_live, msg_a_smime]);
        tx.finish().await.expect("finish");
    }

    // 4c. Tier-1 Chat (scope filter, empty scope, guest history floor + parent floor) + R1-R4 Re-Auth.
    {
        let mut tx = factory
            .begin_user_read(&user_principal_a)
            .await
            .expect("begin user read");

        // ScopeHint::Channels([ch_floor]) proves BOTH scope filtering (excludes ch_a!)
        // AND guest history_floor_seq + parent-message floor enforcement!
        let q_floor = CandidateQuery {
            corpus: DocCorpus::Chat,
            scope_hint: ScopeHint::Channels(vec![ch_floor]),
            terms: NormalizedQuery::parse(&token).expect("q"),
            visibility: SearchVisibility::Live,
            limit: 20,
            continuation: None,
            metadata_only: false,
            calculate_total: false,
        };
        let floor_t1 = tier1_chat_candidates(&mut tx, &q_floor, caps)
            .await
            .expect("tier1 chat floor");
        assert_eq!(
            floor_t1.keys,
            vec![DocumentKey::Chat {
                channel_id: ch_floor,
                id: floor_post_visible
            }],
            "Tier-1 chat must enforce ScopeHint::Channels, guest history_floor_seq, and parent history floor"
        );

        // Empty ScopeHint::Channels([]) returns empty immediately.
        let q_empty = CandidateQuery {
            scope_hint: ScopeHint::Channels(vec![]),
            ..q_floor.clone()
        };
        let empty_t1 = tier1_chat_candidates(&mut tx, &q_empty, caps)
            .await
            .expect("tier1 chat empty scope");
        assert!(empty_t1.keys.is_empty());

        // ComplianceOnly rejected on user-scoped Tier-1 Chat.
        let mut q_comp = q_floor.clone();
        q_comp.visibility = SearchVisibility::ComplianceOnly;
        assert!(matches!(
            tier1_chat_candidates(&mut tx, &q_comp, caps).await,
            Err(SearchError::Unavailable(_))
        ));

        // Re-auth blocks Tenant B, deleted, pre-floor parent, AND post-floor reply to pre-floor parent!
        let poisoned_chat = vec![
            DocumentKey::Chat {
                channel_id: ch_b,
                id: chat_b_poison,
            },
            DocumentKey::Chat {
                channel_id: ch_a,
                id: chat_a_deleted,
            },
            DocumentKey::Chat {
                channel_id: ch_floor,
                id: floor_pre_parent,
            },
            DocumentKey::Chat {
                channel_id: ch_floor,
                id: floor_reply_to_pre_parent,
            },
            DocumentKey::Chat {
                channel_id: ch_floor,
                id: floor_post_visible,
            },
            DocumentKey::Chat {
                channel_id: ch_a,
                id: chat_a_live,
            },
        ];
        let auth_chat = reauthorize_chat_candidates(&mut tx, &poisoned_chat, None)
            .await
            .expect("reauth chat");
        let auth_chat_ids: Vec<i64> = auth_chat.iter().map(|h| h.id).collect();
        assert_eq!(auth_chat_ids, vec![floor_post_visible, chat_a_live]);
        tx.finish().await.expect("finish");
    }

    // 4d. Tier-1 Drive (ScopeHint::Spaces filter + empty scope + ComplianceOnly rejection) + R1-R4 Re-Auth.
    {
        let mut tx = factory
            .begin_user_read(&user_principal_a)
            .await
            .expect("begin user read");
        let q_drive = CandidateQuery {
            corpus: DocCorpus::Drive,
            scope_hint: ScopeHint::Spaces(vec![space_a, space_b]), // excludes space_a2!
            terms: NormalizedQuery::parse(cjk_token).expect("q"),
            visibility: SearchVisibility::Live,
            limit: 20,
            continuation: None,
            metadata_only: false,
            calculate_total: false,
        };
        let drive_t1 = tier1_drive_candidates(&mut tx, &q_drive, caps)
            .await
            .expect("tier1 drive");
        assert_eq!(
            drive_t1.keys,
            vec![DocumentKey::Drive {
                space_id: space_a,
                id: node_a_live
            }],
            "Tier-1 drive must honor ScopeHint::Spaces (excluding space_a2 and foreign space_b)"
        );

        let q_empty = CandidateQuery {
            scope_hint: ScopeHint::Spaces(vec![]),
            ..q_drive.clone()
        };
        assert!(tier1_drive_candidates(&mut tx, &q_empty, caps)
            .await
            .expect("empty drive scope")
            .keys
            .is_empty());

        let mut q_comp = q_drive.clone();
        q_comp.visibility = SearchVisibility::ComplianceOnly;
        assert!(matches!(
            tier1_drive_candidates(&mut tx, &q_comp, caps).await,
            Err(SearchError::Unavailable(_))
        ));

        let poisoned_drive = vec![
            DocumentKey::Drive {
                space_id: space_b,
                id: node_b_poison,
            },
            DocumentKey::Drive {
                space_id: space_a,
                id: node_a_deleted,
            },
            DocumentKey::Drive {
                space_id: space_a,
                id: node_a_live,
            },
        ];
        let auth_drive = reauthorize_drive_candidates(&mut tx, &poisoned_drive, None)
            .await
            .expect("reauth drive");
        assert_eq!(auth_drive.len(), 1);
        assert_eq!(auth_drive[0].id, node_a_live);
        tx.finish().await.expect("finish");
    }

    // 5. End-to-end Tier-2 Tantivy + Mandatory PG Re-Authorization + strict pg_dump exclusion proof!
    let index_dir = TempDir::new().expect("temp search root");
    let cfg = SearchConfig {
        tier2_enabled: true,
        index_dir: index_dir.path().to_path_buf(),
        ..SearchConfig::default()
    };
    let tantivy = TantivySearchEngine::open_or_degraded(cfg);
    let docs = vec![
        IndexDocument {
            key: DocumentKey::Mail {
                mailbox_id: mb_a, // poisoned scope tag pointing to Tenant B's row ID!
                id: msg_b_poison,
                received_at: ts_b_poison,
            },
            visibility: SearchVisibility::Live,
            title: format!("{token} poisoned-b"),
            body: Some(token.clone()),
            headers: vec![],
            identifiers: vec![],
            sort_i64: msg_b_poison,
            sort_name: "poison".to_owned(),
            crypto_sealed: false,
        },
        IndexDocument {
            key: DocumentKey::Mail {
                mailbox_id: mb_a,
                id: msg_a_deleted,
                received_at: ts_a_deleted,
            },
            visibility: SearchVisibility::Live,
            title: format!("{token} deleted-a"),
            body: Some(token.clone()),
            headers: vec![],
            identifiers: vec![],
            sort_i64: msg_a_deleted,
            sort_name: "deleted".to_owned(),
            crypto_sealed: false,
        },
        IndexDocument {
            key: DocumentKey::Mail {
                mailbox_id: mb_a,
                id: msg_a_live,
                received_at: ts_a_live,
            },
            visibility: SearchVisibility::Live,
            title: format!("{token} live-a"),
            body: Some(token.clone()),
            headers: vec![],
            identifiers: vec![],
            sort_i64: msg_a_live,
            sort_name: "live".to_owned(),
            crypto_sealed: false,
        },
    ];
    tantivy
        .rebuild_epoch(&docs, 1, Some(Utc::now()))
        .expect("rebuild epoch");

    let q_e2e = CandidateQuery {
        corpus: DocCorpus::Mail,
        scope_hint: ScopeHint::Mailbox(mb_a),
        terms: NormalizedQuery::parse(&token).expect("q"),
        visibility: SearchVisibility::Live,
        limit: 10,
        continuation: None,
        metadata_only: false,
        calculate_total: false,
    };
    let page = execute_overfetch_page(
        &tantivy,
        &q_e2e,
        10,
        |cands| {
            let factory = &factory;
            let cap = &read_cap_a;
            async move {
                let mut tx = factory
                    .begin_mailbox_read(cap)
                    .await
                    .map_err(|e| SearchError::Database(format!("{e:?}")))?;
                let hits =
                    reauthorize_mail_candidates(&mut tx, &cands, &MailReauthFilter::default())
                        .await?;
                tx.finish()
                    .await
                    .map_err(|e| SearchError::Database(format!("{e:?}")))?;
                Ok(hits)
            }
        },
        || async { Ok(Vec::new()) },
    )
    .await
    .expect("two-tier page");
    assert_eq!(page.tier, SearchTier::Tier2Tantivy);
    assert!(!page.degraded);
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.items[0].id, msg_a_live);

    // 6. Strict pg_dump & PGDATA exclusion proof (must execute pg_dump and exit 0!).
    let pgdata: String = owner
        .query_one("SHOW data_directory", &[])
        .await
        .expect("SHOW data_directory")
        .try_get(0)
        .expect("pgdata");
    assert!(
        !index_dir.path().starts_with(&pgdata),
        "Tantivy root {} must be outside PGDATA {pgdata}",
        index_dir.path().display()
    );
    assert!(index_dir.path().join("CURRENT").is_file());
    assert!(index_dir
        .path()
        .join("epochs/index-v000001/meta.json")
        .is_file());

    let pg_dump_bin = std::env::var("PG_DUMP")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "pg_dump".to_owned());
    // Full pg_dump (schema + data, NOT --schema-only) proves zero Tantivy bytes exist in PG backups.
    let output = Command::new(&pg_dump_bin)
        .arg("--dbname")
        .arg(&owner_dsn)
        .output()
        .expect("pg_dump must execute cleanly for backup-exclusion proof");
    assert!(
        output.status.success(),
        "pg_dump must exit 0, stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let dump_text = String::from_utf8_lossy(&output.stdout);
    assert!(
        !dump_text.trim().is_empty(),
        "pg_dump output must be non-empty"
    );
    assert!(
        !dump_text.contains("index-v000001")
            && !dump_text.contains("tantivy")
            && !dump_text.contains(&index_dir.path().display().to_string()),
        "pg_dump must contain zero Tantivy index artifacts or paths"
    );
}
