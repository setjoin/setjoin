//! Real multi-connection concurrency tests for Issue #481:
//! verifies zero PostgreSQL deadlocks (`40P01`), zero cascade foreign-key
//! violations (`23503`), zero lock timeouts (`55P03`), and zero unexpected
//! SQL/business errors across Groups A-F under `deadlock_timeout = '50ms'`
//! and `lock_timeout = '5s'`.
//!
//! Gate: connects via `TEST_DB_DSN` (else `DB_DSN`). Without a DSN, prints
//! `SETJOIN-CALENDAR-DB-SKIP (reason=no-dsn)` unless `REQUIRE_DB=1`.
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use tokio::sync::Barrier;
use tokio_postgres::{Client, NoTls};

fn dsn() -> Option<String> {
    std::env::var("TEST_DB_DSN")
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| std::env::var("DB_DSN").ok().filter(|s| !s.is_empty()))
}

fn require_db() -> bool {
    std::env::var("REQUIRE_DB").is_ok_and(|v| v == "1" || v.eq_ignore_ascii_case("true"))
}

fn skip_or_dsn(case: &str) -> Option<String> {
    match dsn() {
        Some(d) => Some(d),
        None if require_db() => panic!("REQUIRE_DB=1 set but TEST_DB_DSN/DB_DSN is unset ({case})"),
        None => {
            eprintln!("SETJOIN-CALENDAR-DB-SKIP (reason=no-dsn case={case})");
            None
        }
    }
}

async fn connect(dsn: &str) -> Client {
    let (client, conn) = tokio_postgres::connect(dsn, NoTls)
        .await
        .expect("connect to postgres");
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            eprintln!("pg connection error: {e}");
        }
    });
    client
        .batch_execute("SET deadlock_timeout = '50ms'; SET lock_timeout = '5s';")
        .await
        .expect("set deadlock_timeout & lock_timeout");
    client
}

/// Assert that a DB operation either succeeded (`Ok`) or failed with one of the
/// explicitly expected concurrent-race SQLSTATE codes. Never swallows `40P01`
/// (deadlock), `23503` (FK violation), `55P03` (lock_timeout), `BZ300`, `BZ224`,
/// or `42xxx` schema/SQL errors.
/// Returns `true` when the operation succeeded (`Ok`), `false` when it returned
/// an explicitly allowed concurrent-race error.
fn assert_ok_or_race<T>(
    res: Result<T, tokio_postgres::Error>,
    allowed_codes: &[&str],
    ctx: &str,
) -> bool {
    match res {
        Ok(_) => true,
        Err(err) => {
            let code = err.code().map(|c| c.code()).unwrap_or("");
            assert_ne!(code, "40P01", "DEADLOCK (40P01) in {ctx}: {err}");
            assert_ne!(code, "23503", "FK VIOLATION (23503) in {ctx}: {err}");
            assert_ne!(code, "55P03", "LOCK TIMEOUT (55P03) in {ctx}: {err}");
            assert_ne!(code, "BZ300", "FEATURE DISABLED (BZ300) in {ctx}: {err}");
            assert_ne!(
                code, "BZ224",
                "SOURCE/FEATURE DISABLED (BZ224) in {ctx}: {err}"
            );
            assert!(
                !code.starts_with("42"),
                "SQL/SCHEMA ERROR ({code}) in {ctx}: {err}"
            );
            assert!(
                allowed_codes.contains(&code),
                "UNEXPECTED ERROR ({code}) in {ctx} (allowed={allowed_codes:?}): {err}"
            );
            false
        }
    }
}

async fn set_feature_toggle_saving_prior(
    client: &Client,
    key: &str,
    enabled: bool,
) -> Option<bool> {
    let prior: Option<bool> = client
        .query_opt(
            "SELECT enabled FROM feature_toggles WHERE key = $1",
            &[&key],
        )
        .await
        .expect("read prior feature toggle")
        .map(|row| row.get(0));
    client
        .execute(
            "INSERT INTO feature_toggles (key, enabled) VALUES ($1, $2) \
             ON CONFLICT (key) DO UPDATE SET enabled = EXCLUDED.enabled",
            &[&key, &enabled],
        )
        .await
        .expect("enable feature toggle");
    prior
}

async fn restore_feature_toggle(client: &Client, key: &str, prior: Option<bool>) {
    match prior {
        Some(prev) => {
            client
                .execute(
                    "UPDATE feature_toggles SET enabled = $2 WHERE key = $1",
                    &[&key, &prev],
                )
                .await
                .expect("restore feature toggle");
        }
        None => {
            client
                .execute("DELETE FROM feature_toggles WHERE key = $1", &[&key])
                .await
                .expect("remove temporary feature toggle");
        }
    }
}

fn unique_tag(prefix: &str) -> String {
    static SEQ: AtomicUsize = AtomicUsize::new(1);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let clean = prefix.replace('_', "-");
    format!("{clean}-{pid}-{n}")
}

#[allow(dead_code)]
struct SeededAccount {
    domain_id: i64,
    admin_user_id: i64,
    user_id: i64,
    mailbox_id: i64,
    calendar_id: i64,
    event_id: i64,
    addressbook_id: i64,
    contact_id: i64,
    task_id: i64,
    message_id: i64,
    inbox_tag_id: i64,
    sent_tag_id: i64,
    drafts_tag_id: i64,
    email: String,
    scim_ext_id: String,
}

async fn seed_domain_and_admin(client: &Client, tag: &str) -> (i64, i64) {
    let domain = format!("{tag}.test");
    let domain_id: i64 = client
        .query_one(
            "INSERT INTO domains (name, is_local) VALUES ($1, TRUE) RETURNING id",
            &[&domain],
        )
        .await
        .expect("insert domain")
        .get(0);
    let admin_email = format!("admin-{tag}@{domain}");
    let admin_user = format!("adm_{tag}");
    let admin_id: i64 = client
        .query_one(
            "INSERT INTO users (username, domain_id, email, display_name, enabled) \
             VALUES ($1, $2, $3, 'Admin', TRUE) RETURNING id",
            &[&admin_user, &domain_id, &admin_email],
        )
        .await
        .expect("insert admin user")
        .get(0);
    client
        .execute(
            "INSERT INTO admin_role_assignments (user_id, role_group_id) VALUES ($1, 1)",
            &[&admin_id],
        )
        .await
        .expect("grant superadmin");
    (domain_id, admin_id)
}

async fn seed_populated_account_with_primary(
    client: &Client,
    domain_id: i64,
    admin_user_id: i64,
    tag: &str,
    is_primary: bool,
) -> SeededAccount {
    let email = format!("u-{tag}@d{domain_id}.test");
    let username = format!("u_{tag}");
    let scim_ext_id = format!("scim-{tag}");
    let user_id: i64 = client
        .query_one(
            "INSERT INTO users (username, domain_id, email, display_name, enabled, scim_external_id) \
             VALUES ($1, $2, $3, $4, TRUE, $5) RETURNING id",
            &[&username, &domain_id, &email, &username, &scim_ext_id],
        )
        .await
        .expect("insert user")
        .get(0);
    if !is_primary {
        // Give the user a separate primary mailbox so rust_admin_mailbox_delete can
        // delete the populated target mailbox without violating V085 (BZ013).
        let primary_email = format!("pri-{tag}@d{domain_id}.test");
        client
            .execute(
                "INSERT INTO mailboxes (user_id, domain_id, email, type, display_name, is_primary, enabled) \
                 VALUES ($1, $2, $3, 'personal', 'Primary', TRUE, TRUE)",
                &[&user_id, &domain_id, &primary_email],
            )
            .await
            .expect("insert keeper primary mailbox");
    }
    let mailbox_id: i64 = client
        .query_one(
            "INSERT INTO mailboxes (user_id, domain_id, email, type, display_name, is_primary, enabled) \
             VALUES ($1, $2, $3, 'personal', $4, $5, TRUE) RETURNING id",
            &[&user_id, &domain_id, &email, &username, &is_primary],
        )
        .await
        .expect("insert mailbox")
        .get(0);
    client
        .execute("SELECT create_system_tags($1)", &[&mailbox_id])
        .await
        .expect("create_system_tags");
    let inbox_tag_id: i64 = client
        .query_one("SELECT get_tag_id('Inbox', $1)", &[&mailbox_id])
        .await
        .expect("get Inbox tag")
        .get(0);
    let sent_tag_id: i64 = client
        .query_one("SELECT get_tag_id('Sent', $1)", &[&mailbox_id])
        .await
        .expect("get Sent tag")
        .get(0);
    let drafts_tag_id: i64 = client
        .query_one("SELECT get_tag_id('Drafts', $1)", &[&mailbox_id])
        .await
        .expect("get Drafts tag")
        .get(0);
    let calendar_id: i64 = client
        .query_one(
            "INSERT INTO calendars (mailbox_id, name, is_default) VALUES ($1, 'Default', TRUE) RETURNING id",
            &[&mailbox_id],
        )
        .await
        .expect("insert calendar")
        .get(0);
    let uid = format!("uid-{tag}");
    let event_id: i64 = client
        .query_one(
            "INSERT INTO calendar_events (calendar_id, uid, title, start_at, end_at, organizer_email, is_meeting) \
             VALUES ($1, $2, 'Evt', now() + interval '2 days', now() + interval '2 days 1 hour', $3, TRUE) RETURNING id",
            &[&calendar_id, &uid, &email],
        )
        .await
        .expect("insert event")
        .get(0);
    client
        .execute(
            "INSERT INTO event_attendees (event_id, email, name, role, status) VALUES ($1, $2, 'User', 'required', 'needs-action')",
            &[&event_id, &email],
        )
        .await
        .expect("insert attendee");
    let addressbook_id: i64 = client
        .query_one(
            "INSERT INTO addressbooks (mailbox_id, name, is_default) VALUES ($1, 'Default', TRUE) RETURNING id",
            &[&mailbox_id],
        )
        .await
        .expect("insert addressbook")
        .get(0);
    let vcard_uid = format!("vcard-{tag}");
    let contact_id: i64 = client
        .query_one(
            "INSERT INTO contacts (addressbook_id, vcard_uid, display_name) VALUES ($1, $2, 'Bob') RETURNING id",
            &[&addressbook_id, &vcard_uid],
        )
        .await
        .expect("insert contact")
        .get(0);
    let task_id: i64 = client
        .query_one(
            "INSERT INTO tasks (mailbox_id, title) VALUES ($1, 'Task 1') RETURNING id",
            &[&mailbox_id],
        )
        .await
        .expect("insert task")
        .get(0);
    let msg_rfc = format!("<msg-{tag}@test>");
    let message_id: i64 = client
        .query_one(
            "INSERT INTO messages (mailbox_id, folder_id, message_id, subject, from_addr, to_addrs, thread_id, raw_ref, size_bytes, received_at) \
             VALUES ($1, $2, $3, 'Subj', $4, '[]'::jsonb, $5, $5, 64, now()) RETURNING id",
            &[&mailbox_id, &inbox_tag_id, &msg_rfc, &email, &tag],
        )
        .await
        .expect("insert message")
        .get(0);
    client
        .execute(
            "INSERT INTO message_tags (message_id, received_at, tag_id, added_by, is_primary) \
             SELECT id, received_at, $2, 'test', TRUE FROM messages WHERE id = $1",
            &[&message_id, &inbox_tag_id],
        )
        .await
        .expect("tag message");

    SeededAccount {
        domain_id,
        admin_user_id,
        user_id,
        mailbox_id,
        calendar_id,
        event_id,
        addressbook_id,
        contact_id,
        task_id,
        message_id,
        inbox_tag_id,
        sent_tag_id,
        drafts_tag_id,
        email,
        scim_ext_id,
    }
}

async fn seed_populated_account(
    client: &Client,
    domain_id: i64,
    admin_user_id: i64,
    tag: &str,
) -> SeededAccount {
    seed_populated_account_with_primary(client, domain_id, admin_user_id, tag, true).await
}

async fn seed_deletable_mailbox_account(
    client: &Client,
    domain_id: i64,
    admin_user_id: i64,
    tag: &str,
) -> SeededAccount {
    seed_populated_account_with_primary(client, domain_id, admin_user_id, tag, false).await
}

async fn cleanup_domain(client: &mut Client, domain_id: i64) {
    let tx = client.transaction().await.expect("begin cleanup tx");
    tx.execute(
        "DELETE FROM outbound_queue_hot WHERE mailbox_id IN (SELECT id FROM mailboxes WHERE domain_id = $1 OR user_id IN (SELECT id FROM users WHERE domain_id = $1))",
        &[&domain_id],
    )
    .await
    .expect("cleanup outbound_queue_hot");
    tx.execute(
        "DELETE FROM outbound_queue WHERE mailbox_id IN (SELECT id FROM mailboxes WHERE domain_id = $1 OR user_id IN (SELECT id FROM users WHERE domain_id = $1))",
        &[&domain_id],
    )
    .await
    .expect("cleanup outbound_queue");
    tx.execute(
        "DELETE FROM aliases WHERE mailbox_id IN (SELECT id FROM mailboxes WHERE domain_id = $1 OR user_id IN (SELECT id FROM users WHERE domain_id = $1))",
        &[&domain_id],
    )
    .await
    .expect("cleanup aliases");
    tx.execute(
        "DELETE FROM message_attachments WHERE message_id IN (SELECT id FROM messages WHERE mailbox_id IN (SELECT id FROM mailboxes WHERE domain_id = $1 OR user_id IN (SELECT id FROM users WHERE domain_id = $1)))",
        &[&domain_id],
    )
    .await
    .expect("cleanup message_attachments");
    tx.execute(
        "DELETE FROM messages WHERE mailbox_id IN (SELECT id FROM mailboxes WHERE domain_id = $1 OR user_id IN (SELECT id FROM users WHERE domain_id = $1))",
        &[&domain_id],
    )
    .await
    .expect("cleanup messages");
    tx.execute(
        "DELETE FROM folders WHERE mailbox_id IN (SELECT id FROM mailboxes WHERE domain_id = $1 OR user_id IN (SELECT id FROM users WHERE domain_id = $1))",
        &[&domain_id],
    )
    .await
    .expect("cleanup folders");
    tx.execute(
        "DELETE FROM mailboxes WHERE domain_id = $1 OR user_id IN (SELECT id FROM users WHERE domain_id = $1)",
        &[&domain_id],
    )
    .await
    .expect("cleanup mailboxes");
    let other_superadmins: i64 = tx
        .query_one(
            "SELECT count(*) FROM admin_role_assignments \
             WHERE role_group_id = 1 AND user_id NOT IN (SELECT id FROM users WHERE domain_id = $1)",
            &[&domain_id],
        )
        .await
        .expect("count other superadmins")
        .get(0);
    if other_superadmins > 0 {
        tx.execute(
            "DELETE FROM admin_role_assignments WHERE user_id IN (SELECT id FROM users WHERE domain_id = $1)",
            &[&domain_id],
        )
        .await
        .expect("cleanup admin_role_assignments");
        tx.execute("DELETE FROM users WHERE domain_id = $1", &[&domain_id])
            .await
            .expect("cleanup users");
        tx.execute("DELETE FROM domains WHERE id = $1", &[&domain_id])
            .await
            .expect("cleanup domain");
    } else {
        // V035 protect_last_super_admin (BZ064) forbids removing the sole Super Admin row
        // on a freshly initialized database; still remove all non-admin users in this domain.
        tx.execute(
            "DELETE FROM users WHERE domain_id = $1 \
             AND id NOT IN (SELECT user_id FROM admin_role_assignments WHERE role_group_id = 1)",
            &[&domain_id],
        )
        .await
        .expect("cleanup non-admin users");
    }
    tx.commit().await.expect("commit cleanup tx");
}

/// 1. Calendar RSVP + event update vs rust_admin_mailbox_delete (Groups A+B+C).
#[tokio::test]
async fn rsvp_and_calendar_update_vs_admin_mailbox_delete() {
    let Some(dsn) = skip_or_dsn("rsvp_and_calendar_update_vs_admin_mailbox_delete") else {
        return;
    };
    let mut setup = connect(&dsn).await;
    let tag = unique_tag("rsvp_del");
    let (domain_id, admin_id) = seed_domain_and_admin(&setup, &tag).await;

    for iter in 0..8 {
        let acc =
            seed_deletable_mailbox_account(&setup, domain_id, admin_id, &format!("{tag}_{iter}"))
                .await;
        let barrier = Arc::new(Barrier::new(2));
        let b1 = barrier.clone();
        let b2 = barrier.clone();
        let d1 = dsn.clone();
        let d2 = dsn.clone();
        let mb = acc.mailbox_id;
        let ev = acc.event_id;
        let em = acc.email.clone();

        let t1 = tokio::spawn(async move {
            let c = connect(&d1).await;
            b1.wait().await;
            let r1 = c
                .execute(
                    "SELECT jmap_calendar_event_rsvp($1, $2, $3, 'accepted')",
                    &[&mb, &ev, &em],
                )
                .await;
            assert_ok_or_race(r1, &[], "rsvp");
            let patch = format!("{{\"{ev}\":{{\"title\":\"Updated\"}}}}");
            let r2 = c
                .execute(
                    "SELECT jmap_calendar_event_set_update($1, $2::text::jsonb)",
                    &[&mb, &patch],
                )
                .await;
            assert_ok_or_race(r2, &[], "cal_event_update");
        });
        let t2 = tokio::spawn(async move {
            let c = connect(&d2).await;
            b2.wait().await;
            let r = c
                .execute("SELECT rust_admin_mailbox_delete($1, 0)", &[&mb])
                .await;
            assert_ok_or_race(r, &[], "rust_admin_mailbox_delete");
        });
        t1.await.unwrap();
        t2.await.unwrap();
    }
    cleanup_domain(&mut setup, domain_id).await;
}

/// 2. users -> mailboxes order: calendar share + subscribe vs rust_admin_user_delete.
#[tokio::test]
async fn users_to_mailboxes_calendar_share_and_subscribe_vs_admin_user_delete() {
    let Some(dsn) =
        skip_or_dsn("users_to_mailboxes_calendar_share_and_subscribe_vs_admin_user_delete")
    else {
        return;
    };
    let mut setup = connect(&dsn).await;
    let tag = unique_tag("usr_del");
    let (domain_id, admin_id) = seed_domain_and_admin(&setup, &tag).await;

    for iter in 0..8 {
        let owner =
            seed_populated_account(&setup, domain_id, admin_id, &format!("{tag}_o_{iter}")).await;
        let target =
            seed_populated_account(&setup, domain_id, admin_id, &format!("{tag}_t_{iter}")).await;
        let barrier = Arc::new(Barrier::new(2));
        let b1 = barrier.clone();
        let b2 = barrier.clone();
        let d1 = dsn.clone();
        let d2 = dsn.clone();
        let o_mb = owner.mailbox_id;
        let o_cal = owner.calendar_id;
        let t_uid = target.user_id;
        let t_mb = target.mailbox_id;
        let t_email = target.email.clone();

        let t1 = tokio::spawn(async move {
            let c = connect(&d1).await;
            let grants = format!("[{{\"userEmail\":\"{t_email}\",\"level\":\"read\"}}]");
            b1.wait().await;
            let r1 = c
                .execute(
                    "SELECT jmap_calendar_share_set($1, $2, $3::text::jsonb, '[]'::jsonb)",
                    &[&o_mb, &o_cal, &grants],
                )
                .await;
            assert_ok_or_race(r1, &[], "jmap_calendar_share_set");
            let r2 = c
                .execute(
                    "SELECT * FROM rust_calendar_subscribe($1, $2, 'Feed', 'https://example.test/x.ics')",
                    &[&t_mb, &t_uid],
                )
                .await;
            // BZ006 when target user/mailbox was already deleted by t2.
            assert_ok_or_race(r2, &["BZ006"], "rust_calendar_subscribe");
        });
        let t2 = tokio::spawn(async move {
            let c = connect(&d2).await;
            b2.wait().await;
            let r = c
                .execute(
                    "SELECT rust_admin_user_delete($1, $2, 0)",
                    &[&admin_id, &t_uid],
                )
                .await;
            assert_ok_or_race(r, &[], "rust_admin_user_delete");
        });
        t1.await.unwrap();
        t2.await.unwrap();
    }
    cleanup_domain(&mut setup, domain_id).await;
}

/// 3. mailbox_purge_execute vs mailbox_lifecycle_transition (Group B).
#[tokio::test]
async fn mailbox_purge_execute_vs_mailbox_lifecycle_transition() {
    let Some(dsn) = skip_or_dsn("mailbox_purge_execute_vs_mailbox_lifecycle_transition") else {
        return;
    };
    let mut setup = connect(&dsn).await;
    let tag = unique_tag("purge_lc");
    let (domain_id, admin_id) = seed_domain_and_admin(&setup, &tag).await;

    // Enable the real mailbox lifecycle toggle and remember prior state to restore in cleanup.
    let prior_toggle =
        set_feature_toggle_saving_prior(&setup, "feature.mailbox_lifecycle_retention", true).await;

    let mut total_purge_wins = 0usize;
    let mut total_reconnect_wins = 0usize;

    for iter in 0..8 {
        let acc =
            seed_populated_account(&setup, domain_id, admin_id, &format!("{tag}_{iter}")).await;
        let mb = acc.mailbox_id;
        // Seed retained lifecycle row (generation=2) + eligible approved purge request (lifecycle_generation=1).
        setup
            .execute(
                "INSERT INTO mailbox_lifecycle (mailbox_id, binding_state, access_state, generation, bound_user_id, was_primary, retained_at, retention_until) \
                 VALUES ($1, 'retained', 'detached', 2, NULL, TRUE, now() - interval '1 day', now() + interval '30 days') \
                 ON CONFLICT (mailbox_id) DO UPDATE SET binding_state = 'retained', access_state = 'detached', generation = 2, bound_user_id = NULL, retained_at = EXCLUDED.retained_at, retention_until = EXCLUDED.retention_until",
                &[&mb],
            )
            .await
            .expect("seed mailbox_lifecycle");
        setup
            .execute(
                "UPDATE mailboxes SET user_id = NULL, is_primary = FALSE, enabled = FALSE WHERE id = $1",
                &[&mb],
            )
            .await
            .expect("detach mailbox");
        // Seed a second admin to be the independent approver.
        let approver_email = format!("app-{tag}-{iter}@d{domain_id}.test");
        let approver_name = format!("app_{tag}_{iter}");
        let approver_id: i64 = setup
            .query_one(
                "INSERT INTO users (username, domain_id, email, display_name, enabled) \
                 VALUES ($1, $2, $3, 'Approver', TRUE) RETURNING id",
                &[&approver_name, &domain_id, &approver_email],
            )
            .await
            .expect("insert approver")
            .get(0);
        let preview_digest = "c".repeat(64);
        let purge_id_str: String = setup
            .query_one(
                "INSERT INTO mailbox_purge_requests (mailbox_id, operation_id, preview_digest, requested_by, approved_by, state, lifecycle_generation, eligible_at, reason) \
                 VALUES ($1, gen_random_uuid(), $2, $3, $4, 'approved', 1, now() - interval '1 minute', 'test purge') RETURNING id::text",
                &[&mb, &preview_digest, &admin_id, &approver_id],
            )
            .await
            .expect("insert purge request")
            .get(0);
        let target_uid = acc.user_id;
        setup
            .execute(
                "INSERT INTO user_lifecycle_authorities (user_id, authority_kind) VALUES ($1, 'local') \
                 ON CONFLICT (user_id) DO UPDATE SET authority_kind = 'local'",
                &[&target_uid],
            )
            .await
            .expect("seed user_lifecycle_authorities");

        let barrier = Arc::new(Barrier::new(2));
        let b1 = barrier.clone();
        let b2 = barrier.clone();
        let d1 = dsn.clone();
        let d2 = dsn.clone();
        let digest = "a".repeat(64);
        let digest2 = "b".repeat(64);

        let purge_id_cleanup = purge_id_str.clone();
        let t1 = tokio::spawn(async move {
            let c = connect(&d1).await;
            b1.wait().await;
            let r = c
                .execute(
                    "SELECT mailbox_purge_execute($1, $2::text::uuid, gen_random_uuid(), $3)",
                    &[&admin_id, &purge_id_str, &digest],
                )
                .await;
            // BZ304 when reconnect won and bumped lifecycle generation / state.
            assert_ok_or_race(r, &["BZ304"], "mailbox_purge_execute")
        });
        let t2 = tokio::spawn(async move {
            let c = connect(&d2).await;
            b2.wait().await;
            let r = c
                .execute(
                    "SELECT mailbox_lifecycle_transition($1, $2, gen_random_uuid(), 'reconnect', 2, $3, 'test reconnect', $4, 'local_user')",
                    &[&admin_id, &mb, &digest2, &target_uid],
                )
                .await;
            // BZ302 when purge won and deleted mailbox + lifecycle row.
            assert_ok_or_race(r, &["BZ302"], "mailbox_lifecycle_transition")
        });
        let purge_ok = t1.await.unwrap();
        let reconnect_ok = t2.await.unwrap();
        assert_eq!(
            usize::from(purge_ok) + usize::from(reconnect_ok),
            1,
            "iter {iter}: exactly one of purge_execute ({purge_ok}) or lifecycle_transition ({reconnect_ok}) must succeed"
        );
        if purge_ok {
            total_purge_wins += 1;
        } else {
            total_reconnect_wins += 1;
        }

        setup
            .execute(
                "DELETE FROM mailbox_tombstones WHERE purge_request_id = $1::text::uuid",
                &[&purge_id_cleanup],
            )
            .await
            .expect("cleanup mailbox_tombstones");
        setup
            .execute(
                "DELETE FROM mailbox_purge_requests WHERE id = $1::text::uuid",
                &[&purge_id_cleanup],
            )
            .await
            .expect("cleanup mailbox_purge_requests");
        setup
            .execute(
                "DELETE FROM mailbox_lifecycle_effects WHERE mailbox_id = $1",
                &[&mb],
            )
            .await
            .expect("cleanup mailbox_lifecycle_effects");
        setup
            .execute(
                "DELETE FROM mailbox_lifecycle_outbox WHERE operation_id IN (SELECT operation_id FROM mailbox_lifecycle_operations WHERE mailbox_id = $1)",
                &[&mb],
            )
            .await
            .expect("cleanup mailbox_lifecycle_outbox");
        setup
            .execute(
                "DELETE FROM mailbox_lifecycle_operations WHERE mailbox_id = $1",
                &[&mb],
            )
            .await
            .expect("cleanup mailbox_lifecycle_operations");
        setup
            .execute(
                "DELETE FROM mailbox_lifecycle WHERE mailbox_id = $1",
                &[&mb],
            )
            .await
            .expect("cleanup mailbox_lifecycle");
    }

    assert_eq!(
        total_purge_wins + total_reconnect_wins,
        8,
        "expected 8 decisive races in Test 3 (purge_wins={total_purge_wins}, reconnect_wins={total_reconnect_wins})"
    );
    restore_feature_toggle(&setup, "feature.mailbox_lifecycle_retention", prior_toggle).await;
    cleanup_domain(&mut setup, domain_id).await;
}

/// 4. scim_delete_group vs identity_source_entry_apply vs identity_source_attributes_apply (Group B).
#[tokio::test]
async fn scim_delete_group_vs_identity_source_apply() {
    let Some(dsn) = skip_or_dsn("scim_delete_group_vs_identity_source_apply") else {
        return;
    };
    let setup = connect(&dsn).await;
    let tag = unique_tag("scim_grp");
    let (domain_id, admin_id) = seed_domain_and_admin(&setup, &tag).await;

    let prior_toggle =
        set_feature_toggle_saving_prior(&setup, "feature.identity_model_v2", true).await;

    for iter in 0..6 {
        let source_key = format!("scim-src-{tag}-{iter}");
        let source_id: i64 = setup
            .query_one(
                "INSERT INTO identity_sources (source_key, display_name, kind, capabilities, state, generation) \
                 VALUES ($1, $1, 'scim', '{\"provision\":true}'::jsonb, 'active', 1) RETURNING id",
                &[&source_key],
            )
            .await
            .expect("insert identity_source")
            .get(0);
        let acc =
            seed_populated_account(&setup, domain_id, admin_id, &format!("{tag}_{iter}")).await;
        let grp_email = format!("grp-{tag}-{iter}@d{domain_id}.test");
        let grp_mb: i64 = setup
            .query_one(
                "INSERT INTO mailboxes (user_id, domain_id, email, type, display_name, is_primary, enabled) \
                 VALUES (NULL, $1, $2, 'personal', 'Grp', FALSE, TRUE) RETURNING id",
                &[&domain_id, &grp_email],
            )
            .await
            .expect("insert group mailbox")
            .get(0);
        let grp_ext = format!("grp-ext-{tag}-{iter}");
        let grp_id: i64 = setup
            .query_one(
                "INSERT INTO distribution_groups (mailbox_id, scim_source_id, scim_external_id) \
                 VALUES ($1, $2, $3) RETURNING id",
                &[&grp_mb, &source_id, &grp_ext],
            )
            .await
            .expect("insert distribution_group")
            .get(0);
        let link_subj = format!("subj-{tag}-{iter}");
        let link_id: i64 = setup
            .query_one(
                "INSERT INTO user_identity_links (user_id, source_id, external_subject, purposes, state, link_method) \
                 VALUES ($1, $2, $3, ARRAY['provision']::text[], 'active', 'hard_anchor') RETURNING id",
                &[&acc.user_id, &source_id, &link_subj],
            )
            .await
            .expect("insert user_identity_link")
            .get(0);
        setup
            .execute(
                "INSERT INTO user_lifecycle_authorities (user_id, authority_kind, link_id) \
                 VALUES ($1, 'source', $2) \
                 ON CONFLICT (user_id) DO UPDATE SET authority_kind = 'source', link_id = EXCLUDED.link_id",
                &[&acc.user_id, &link_id],
            )
            .await
            .expect("seed lifecycle authority");
        let batch_id: String = setup
            .query_one(
                "INSERT INTO identity_source_batches (source_id, batch_id, source_generation, remote_cursor, remote_cursor_digest, state, entry_count) \
                 VALUES ($1, gen_random_uuid(), 1, '{}'::jsonb, digest('{}', 'sha256'), 'staged', 2) RETURNING batch_id::text",
                &[&source_id],
            )
            .await
            .expect("insert batch")
            .get(0);
        let obj_key = format!("obj-{tag}-{iter}");
        let obj_key_attr = format!("obj-attr-{tag}-{iter}");
        let payload = format!(
            "{{\"email\":\"{}\",\"displayName\":\"Updated {iter}\",\"department\":\"Dept {iter}\"}}",
            acc.email
        );
        let attr_payload =
            format!("{{\"displayName\":\"Attr {iter}\",\"jobTitle\":\"Engineer {iter}\"}}");
        setup
            .execute(
                "INSERT INTO identity_source_inbox \
                 (source_id, batch_id, object_key, source_generation, remote_cursor, remote_cursor_digest, immutable_subject, sanitized_payload, state) \
                 VALUES ($1, $2::text::uuid, $3, 1, '{}'::jsonb, digest('{}', 'sha256'), $4, $5::text::jsonb, 'pending')",
                &[&source_id, &batch_id, &obj_key, &link_subj, &payload],
            )
            .await
            .expect("insert inbox entry");
        setup
            .execute(
                "INSERT INTO identity_source_inbox \
                 (source_id, batch_id, object_key, source_generation, remote_cursor, remote_cursor_digest, immutable_subject, sanitized_payload, state) \
                 VALUES ($1, $2::text::uuid, $3, 1, '{}'::jsonb, digest('{}', 'sha256'), $4, $5::text::jsonb, 'pending')",
                &[&source_id, &batch_id, &obj_key_attr, &link_subj, &attr_payload],
            )
            .await
            .expect("insert second inbox entry for attributes_apply");

        let barrier = Arc::new(Barrier::new(3));
        let b1 = barrier.clone();
        let b2 = barrier.clone();
        let b3 = barrier.clone();
        let d1 = dsn.clone();
        let d2 = dsn.clone();
        let d3 = dsn.clone();
        let batch_id_3 = batch_id.clone();

        let t1 = tokio::spawn(async move {
            let c = connect(&d1).await;
            b1.wait().await;
            let r = c
                .execute(
                    "SELECT scim_delete_group($1, 1, $2)",
                    &[&source_id, &grp_id],
                )
                .await;
            assert!(
                assert_ok_or_race(r, &[], "scim_delete_group"),
                "scim_delete_group must succeed"
            );
        });
        let t2 = tokio::spawn(async move {
            let c = connect(&d2).await;
            b2.wait().await;
            let r = c
                .execute(
                    "SELECT identity_source_entry_apply($1, 1, $2::text::uuid, $3)",
                    &[&source_id, &batch_id, &obj_key],
                )
                .await;
            assert!(
                assert_ok_or_race(r, &[], "identity_source_entry_apply"),
                "identity_source_entry_apply must succeed"
            );
        });
        let t3 = tokio::spawn(async move {
            let c = connect(&d3).await;
            b3.wait().await;
            let r = c
                .execute(
                    "SELECT identity_source_attributes_apply($1, 1, $2, $3::text::uuid, $4, $5::text::jsonb)",
                    &[&source_id, &link_id, &batch_id_3, &obj_key_attr, &attr_payload],
                )
                .await;
            assert!(
                assert_ok_or_race(r, &[], "identity_source_attributes_apply"),
                "identity_source_attributes_apply must succeed"
            );
        });
        t1.await.unwrap();
        t2.await.unwrap();
        t3.await.unwrap();

        // identity_link_events is append-only (ON DELETE RESTRICT to users/links/sources),
        // so clean up mutable staging/authority rows while leaving append-only audit anchors.
        setup
            .execute(
                "DELETE FROM identity_attribute_authority WHERE source_id = $1",
                &[&source_id],
            )
            .await
            .expect("cleanup identity_attribute_authority");
        setup
            .execute(
                "DELETE FROM user_lifecycle_authorities WHERE link_id = $1",
                &[&link_id],
            )
            .await
            .expect("cleanup user_lifecycle_authorities");
        setup
            .execute(
                "DELETE FROM identity_source_inbox WHERE source_id = $1",
                &[&source_id],
            )
            .await
            .expect("cleanup identity_source_inbox");
        setup
            .execute(
                "DELETE FROM identity_source_batches WHERE source_id = $1",
                &[&source_id],
            )
            .await
            .expect("cleanup identity_source_batches");
    }

    restore_feature_toggle(&setup, "feature.identity_model_v2", prior_toggle).await;
}

/// 5. booking_cancel vs jmap_calendar_event_set_destroy (Group C).
#[tokio::test]
async fn booking_cancel_vs_calendar_event_destroy() {
    let Some(dsn) = skip_or_dsn("booking_cancel_vs_calendar_event_destroy") else {
        return;
    };
    let mut setup = connect(&dsn).await;
    let tag = unique_tag("bk_can");
    let (domain_id, admin_id) = seed_domain_and_admin(&setup, &tag).await;

    for iter in 0..8 {
        let acc =
            seed_populated_account(&setup, domain_id, admin_id, &format!("{tag}_{iter}")).await;
        let slug = format!("slug-{tag}-{iter}");
        let page_id: i64 = setup
            .query_one(
                "INSERT INTO booking_pages (mailbox_id, slug, title, enabled) VALUES ($1, $2, 'Book', TRUE) RETURNING id",
                &[&acc.mailbox_id, &slug],
            )
            .await
            .expect("insert booking page")
            .get(0);
        let cancel_tok = format!("cancel-{tag}-{iter}");
        let verify_tok = format!("verify-{tag}-{iter}");
        setup
            .execute(
                "INSERT INTO booking_requests \
                 (page_id, mailbox_id, booker_email, booker_name, slot_start, slot_end, status, event_id, verify_token_hash, verify_expires_at, cancel_token_hash) \
                 VALUES ($1, $2, 'guest@ext.test', 'Guest', now() + interval '2 days', now() + interval '2 days 30 minutes', 'confirmed', $3, $4, now() + interval '1 day', $5)",
                &[&page_id, &acc.mailbox_id, &acc.event_id, &verify_tok, &cancel_tok],
            )
            .await
            .expect("insert booking request");

        let barrier = Arc::new(Barrier::new(2));
        let b1 = barrier.clone();
        let b2 = barrier.clone();
        let d1 = dsn.clone();
        let d2 = dsn.clone();
        let mb = acc.mailbox_id;
        let ev = acc.event_id;

        let t1 = tokio::spawn(async move {
            let c = connect(&d1).await;
            b1.wait().await;
            let r = c.execute("SELECT booking_cancel($1)", &[&cancel_tok]).await;
            assert_ok_or_race(r, &["BZ137"], "booking_cancel");
        });
        let t2 = tokio::spawn(async move {
            let c = connect(&d2).await;
            b2.wait().await;
            let r = c
                .execute(
                    "SELECT jmap_calendar_event_set_destroy($1, ARRAY[$2::bigint])",
                    &[&mb, &ev],
                )
                .await;
            assert_ok_or_race(r, &[], "jmap_calendar_event_set_destroy");
        });
        t1.await.unwrap();
        t2.await.unwrap();
    }
    cleanup_domain(&mut setup, domain_id).await;
}

/// 6. task_list_delete vs jmap_task_set_update (Group E).
#[tokio::test]
async fn task_list_delete_vs_jmap_task_set_update() {
    let Some(dsn) = skip_or_dsn("task_list_delete_vs_jmap_task_set_update") else {
        return;
    };
    let mut setup = connect(&dsn).await;
    let tag = unique_tag("tl_del");
    let (domain_id, admin_id) = seed_domain_and_admin(&setup, &tag).await;

    for iter in 0..8 {
        let owner =
            seed_populated_account(&setup, domain_id, admin_id, &format!("{tag}_o_{iter}")).await;
        let member =
            seed_populated_account(&setup, domain_id, admin_id, &format!("{tag}_m_{iter}")).await;
        let list_id: i64 = setup
            .query_one(
                "SELECT (task_list_create($1, 'List 481')->>'id')::bigint",
                &[&owner.user_id],
            )
            .await
            .expect("create task list")
            .get(0);
        setup
            .execute(
                "SELECT task_list_add_member($1, $2, $3)",
                &[&owner.user_id, &list_id, &member.email],
            )
            .await
            .expect("add member");
        let task_id: i64 = setup
            .query_one(
                "INSERT INTO tasks (mailbox_id, list_id, title) VALUES ($1, $2, 'Shared Task') RETURNING id",
                &[&member.mailbox_id, &list_id],
            )
            .await
            .expect("insert shared task")
            .get(0);

        let barrier = Arc::new(Barrier::new(2));
        let b1 = barrier.clone();
        let b2 = barrier.clone();
        let d1 = dsn.clone();
        let d2 = dsn.clone();
        let o_uid = owner.user_id;
        let m_mb = member.mailbox_id;

        let t1 = tokio::spawn(async move {
            let c = connect(&d1).await;
            b1.wait().await;
            let r = c
                .execute("SELECT task_list_delete($1, $2)", &[&o_uid, &list_id])
                .await;
            assert_ok_or_race(r, &[], "task_list_delete");
        });
        let t2 = tokio::spawn(async move {
            let c = connect(&d2).await;
            let patch = format!("{{\"{task_id}\":{{\"title\":\"Raced\"}}}}");
            b2.wait().await;
            let r = c
                .execute(
                    "SELECT jmap_task_set_update($1, $2::text::jsonb)",
                    &[&m_mb, &patch],
                )
                .await;
            assert_ok_or_race(r, &[], "jmap_task_set_update");
        });
        t1.await.unwrap();
        t2.await.unwrap();
    }
    cleanup_domain(&mut setup, domain_id).await;
}

/// 7. task_list_add_member vs rust_admin_user_delete (Group B+E).
#[tokio::test]
async fn task_list_add_member_vs_admin_user_delete() {
    let Some(dsn) = skip_or_dsn("task_list_add_member_vs_admin_user_delete") else {
        return;
    };
    let mut setup = connect(&dsn).await;
    let tag = unique_tag("tl_add");
    let (domain_id, admin_id) = seed_domain_and_admin(&setup, &tag).await;

    for iter in 0..8 {
        let owner =
            seed_populated_account(&setup, domain_id, admin_id, &format!("{tag}_o_{iter}")).await;
        let invitee =
            seed_populated_account(&setup, domain_id, admin_id, &format!("{tag}_i_{iter}")).await;
        let list_id: i64 = setup
            .query_one(
                "SELECT (task_list_create($1, 'Roster 481')->>'id')::bigint",
                &[&owner.user_id],
            )
            .await
            .expect("create task list")
            .get(0);

        let barrier = Arc::new(Barrier::new(2));
        let b1 = barrier.clone();
        let b2 = barrier.clone();
        let d1 = dsn.clone();
        let d2 = dsn.clone();
        let o_uid = owner.user_id;
        let i_uid = invitee.user_id;
        let i_email = invitee.email.clone();

        let t1 = tokio::spawn(async move {
            let c = connect(&d1).await;
            b1.wait().await;
            let r = c
                .execute(
                    "SELECT task_list_add_member($1, $2, $3)",
                    &[&o_uid, &list_id, &i_email],
                )
                .await;
            // BZ131 when invitee was already deleted by t2.
            assert_ok_or_race(r, &["BZ131"], "task_list_add_member");
        });
        let t2 = tokio::spawn(async move {
            let c = connect(&d2).await;
            b2.wait().await;
            let r = c
                .execute(
                    "SELECT rust_admin_user_delete($1, $2, 0)",
                    &[&admin_id, &i_uid],
                )
                .await;
            assert_ok_or_race(r, &[], "rust_admin_user_delete(invitee)");
        });
        t1.await.unwrap();
        t2.await.unwrap();
    }
    cleanup_domain(&mut setup, domain_id).await;
}

/// 8. jmap_mailbox_set_update + jmap_email_set_update vs rust_admin_mailbox_delete (Group B+F).
#[tokio::test]
async fn jmap_mailbox_and_email_update_vs_admin_mailbox_delete() {
    let Some(dsn) = skip_or_dsn("jmap_mailbox_and_email_update_vs_admin_mailbox_delete") else {
        return;
    };
    let mut setup = connect(&dsn).await;
    let tag = unique_tag("mb_upd");
    let (domain_id, admin_id) = seed_domain_and_admin(&setup, &tag).await;

    for iter in 0..8 {
        let acc =
            seed_deletable_mailbox_account(&setup, domain_id, admin_id, &format!("{tag}_{iter}"))
                .await;
        let barrier = Arc::new(Barrier::new(3));
        let b1 = barrier.clone();
        let b2 = barrier.clone();
        let b3 = barrier.clone();
        let d1 = dsn.clone();
        let d2 = dsn.clone();
        let d3 = dsn.clone();
        let mb = acc.mailbox_id;
        let inbox = acc.inbox_tag_id;
        let msg = acc.message_id;

        let t1 = tokio::spawn(async move {
            let c = connect(&d1).await;
            let patch = format!("{{\"{inbox}\":{{\"sortOrder\":7}}}}");
            b1.wait().await;
            let r = c
                .execute(
                    "SELECT jmap_mailbox_set_update($1, $2::text::jsonb)",
                    &[&mb, &patch],
                )
                .await;
            assert_ok_or_race(r, &[], "jmap_mailbox_set_update");
        });
        let t2 = tokio::spawn(async move {
            let c = connect(&d2).await;
            let patch = format!("{{\"{msg}\":{{\"keywords\":{{\"$seen\":true}}}}}}");
            b2.wait().await;
            let r = c
                .execute(
                    "SELECT jmap_email_set_update($1, $2::text::jsonb)",
                    &[&mb, &patch],
                )
                .await;
            assert_ok_or_race(r, &[], "jmap_email_set_update");
        });
        let t3 = tokio::spawn(async move {
            let c = connect(&d3).await;
            b3.wait().await;
            let r = c
                .execute("SELECT rust_admin_mailbox_delete($1, 0)", &[&mb])
                .await;
            assert_ok_or_race(r, &[], "rust_admin_mailbox_delete");
        });
        t1.await.unwrap();
        t2.await.unwrap();
        t3.await.unwrap();
    }
    cleanup_domain(&mut setup, domain_id).await;
}

/// 9. calendar_book_resource vs room mailbox delete (Group B+C).
#[tokio::test]
async fn calendar_book_resource_vs_room_mailbox_delete() {
    let Some(dsn) = skip_or_dsn("calendar_book_resource_vs_room_mailbox_delete") else {
        return;
    };
    let mut setup = connect(&dsn).await;
    let tag = unique_tag("room_bk");
    let (domain_id, admin_id) = seed_domain_and_admin(&setup, &tag).await;

    for iter in 0..8 {
        let booker =
            seed_populated_account(&setup, domain_id, admin_id, &format!("{tag}_b_{iter}")).await;
        let room_email = format!("room-{tag}-{iter}@d{domain_id}.test");
        let room_mb: i64 = setup
            .query_one(
                "INSERT INTO mailboxes (user_id, domain_id, email, type, display_name, is_primary, enabled) \
                 VALUES (NULL, $1, $2, 'personal', 'Room A', FALSE, TRUE) RETURNING id",
                &[&domain_id, &room_email],
            )
            .await
            .expect("insert room mailbox")
            .get(0);
        let room_cal: i64 = setup
            .query_one(
                "INSERT INTO calendars (mailbox_id, name, is_default, resource_type, booking_policy) \
                 VALUES ($1, 'Room A', TRUE, 'room', 'auto-accept') RETURNING id",
                &[&room_mb],
            )
            .await
            .expect("insert room calendar")
            .get(0);

        let barrier = Arc::new(Barrier::new(2));
        let b1 = barrier.clone();
        let b2 = barrier.clone();
        let d1 = dsn.clone();
        let d2 = dsn.clone();
        let b_mb = booker.mailbox_id;
        let b_ev = booker.event_id;
        let b_uid = booker.user_id;

        let t1 = tokio::spawn(async move {
            let c = connect(&d1).await;
            b1.wait().await;
            let r = c
                .execute(
                    "SELECT calendar_book_resource($1, $2, $3, $4)",
                    &[&b_mb, &room_cal, &b_ev, &b_uid],
                )
                .await;
            assert_ok_or_race(r, &[], "calendar_book_resource");
        });
        let t2 = tokio::spawn(async move {
            let c = connect(&d2).await;
            b2.wait().await;
            let r = c
                .execute("SELECT rust_admin_mailbox_delete($1, 0)", &[&room_mb])
                .await;
            assert_ok_or_race(r, &[], "rust_admin_mailbox_delete(room)");
        });
        t1.await.unwrap();
        t2.await.unwrap();
    }
    cleanup_domain(&mut setup, domain_id).await;
}

/// 10. 20-account concurrent hammer across all domains (Groups A-F):
/// asserts strictly 0 `40P01` deadlocks, 0 `23503` FK violations, 0 `55P03`
/// lock timeouts, 0 unexpected errors, all 20 deletes succeed, and writer
/// operations record real successes.
#[tokio::test]
async fn twenty_account_concurrent_hammer_zero_deadlocks_zero_23503() {
    let Some(dsn) = skip_or_dsn("twenty_account_concurrent_hammer_zero_deadlocks_zero_23503")
    else {
        return;
    };
    let mut setup = connect(&dsn).await;
    let tag = unique_tag("hammer20");
    let (domain_id, admin_id) = seed_domain_and_admin(&setup, &tag).await;

    let mut accounts = Vec::with_capacity(20);
    for i in 0..20 {
        let acc = if i % 3 == 0 {
            seed_deletable_mailbox_account(&setup, domain_id, admin_id, &format!("{tag}_{i}")).await
        } else {
            seed_populated_account(&setup, domain_id, admin_id, &format!("{tag}_{i}")).await
        };
        accounts.push(acc);
    }

    let writer_ok = Arc::new(AtomicUsize::new(0));
    let deleter_ok = Arc::new(AtomicUsize::new(0));
    let barrier = Arc::new(Barrier::new(accounts.len() * 2));
    let mut handles = Vec::with_capacity(accounts.len() * 2);

    for (idx, acc) in accounts.into_iter().enumerate() {
        let d_w = dsn.clone();
        let b_w = barrier.clone();
        let w_ok = writer_ok.clone();

        let mb = acc.mailbox_id;
        let uid = acc.user_id;
        let ev = acc.event_id;
        let contact = acc.contact_id;
        let task = acc.task_id;
        let msg = acc.message_id;
        let inbox = acc.inbox_tag_id;
        let email = acc.email.clone();
        let scim_ext = acc.scim_ext_id.clone();

        // Writer task exercising Groups C, D, E, F concurrently on this account
        handles.push(tokio::spawn(async move {
            let c = connect(&d_w).await;
            b_w.wait().await;
            let ops: Vec<(&str, &[&str], Result<u64, tokio_postgres::Error>)> = vec![
                (
                    "cal_create",
                    &[],
                    c.execute(
                        "SELECT jmap_calendar_event_set_create($1, $2, $3, '{\"k1\":{\"title\":\"Hammer\"}}'::jsonb)",
                        &[&mb, &uid, &email],
                    )
                    .await,
                ),
                (
                    "cal_rsvp",
                    &[],
                    c.execute(
                        "SELECT jmap_calendar_event_rsvp($1, $2, $3, 'accepted')",
                        &[&mb, &ev, &email],
                    )
                    .await,
                ),
                (
                    "contact_upd",
                    &[],
                    c.execute(
                        "SELECT jmap_contact_set_update($1, $2::text::jsonb)",
                        &[&mb, &format!("{{\"{contact}\":{{\"displayName\":\"Hammered\"}}}}")],
                    )
                    .await,
                ),
                (
                    "task_upd",
                    &[],
                    c.execute(
                        "SELECT jmap_task_set_update($1, $2::text::jsonb)",
                        &[&mb, &format!("{{\"{task}\":{{\"title\":\"Hammered\"}}}}")],
                    )
                    .await,
                ),
                (
                    "email_upd",
                    &[],
                    c.execute(
                        "SELECT jmap_email_set_update($1, $2::text::jsonb)",
                        &[&mb, &format!("{{\"{msg}\":{{\"keywords\":{{\"$seen\":true}}}}}}")],
                    )
                    .await,
                ),
                (
                    "mb_upd",
                    &[],
                    c.execute(
                        "SELECT jmap_mailbox_set_update($1, $2::text::jsonb)",
                        &[&mb, &format!("{{\"{inbox}\":{{\"sortOrder\":9}}}}")],
                    )
                    .await,
                ),
            ];
            for (name, allowed, res) in ops {
                if assert_ok_or_race(res, allowed, &format!("writer[{idx}].{name}")) {
                    w_ok.fetch_add(1, Ordering::Relaxed);
                }
            }
        }));

        // Deleter task alternating all 3 Group B delete paths across the 20 accounts
        let d_d = dsn.clone();
        let b_d = barrier.clone();
        let d_ok = deleter_ok.clone();
        handles.push(tokio::spawn(async move {
            let c = connect(&d_d).await;
            b_d.wait().await;
            let (name, res) = match idx % 3 {
                0 => (
                    "rust_admin_mailbox_delete",
                    c.execute("SELECT rust_admin_mailbox_delete($1, 0)", &[&mb])
                        .await,
                ),
                1 => (
                    "rust_admin_user_delete",
                    c.execute(
                        "SELECT rust_admin_user_delete($1, $2, 0)",
                        &[&admin_id, &uid],
                    )
                    .await,
                ),
                _ => (
                    "scim_delete_user",
                    c.execute("SELECT scim_delete_user($1, TRUE)", &[&scim_ext])
                        .await,
                ),
            };
            if assert_ok_or_race(res, &[], &format!("deleter[{idx}].{name}")) {
                d_ok.fetch_add(1, Ordering::Relaxed);
            }
        }));
    }

    for h in handles {
        h.await.expect("hammer task panicked");
    }

    cleanup_domain(&mut setup, domain_id).await;

    assert_eq!(
        deleter_ok.load(Ordering::Relaxed),
        20,
        "expected all 20 concurrent deletes to succeed"
    );
    assert!(
        writer_ok.load(Ordering::Relaxed) > 0,
        "expected concurrent writer operations to record real successes"
    );
}

/// 11. Review Finding 1 regression: concurrent `deliver()` and `jmap_email_set_create()`
/// on the same mailbox must take `mailboxes FOR UPDATE` upfront (no `FOR KEY SHARE` ->
/// `check_quota()` `FOR UPDATE` lock-upgrade `40P01` deadlock), and both must succeed.
#[tokio::test]
async fn concurrent_deliver_and_email_create_same_mailbox_zero_deadlocks() {
    let Some(dsn) = skip_or_dsn("concurrent_deliver_and_email_create_same_mailbox_zero_deadlocks")
    else {
        return;
    };
    let mut setup = connect(&dsn).await;
    let tag = unique_tag("quota_up");
    let (domain_id, admin_id) = seed_domain_and_admin(&setup, &tag).await;
    let acc = seed_populated_account(&setup, domain_id, admin_id, &tag).await;

    // (a) Two concurrent deliver() calls on the same mailbox.
    for iter in 0..8 {
        let barrier = Arc::new(Barrier::new(2));
        let mut tasks = Vec::with_capacity(2);
        for side in 0..2 {
            let b = barrier.clone();
            let d = dsn.clone();
            let rcpt = acc.email.clone();
            let raw_ref = format!("raw-deliv-{tag}-{iter}-{side}");
            let msg_id = format!("<deliv-{tag}-{iter}-{side}@ext.test>");
            tasks.push(tokio::spawn(async move {
                let c = connect(&d).await;
                b.wait().await;
                let row = c
                    .query_one(
                        "SELECT deliver(\
                           $1, $2, 'sender@ext.test', 'Sender', $3::text, \
                           jsonb_build_array(jsonb_build_object('email', $3::text)), '[]'::jsonb, '[]'::jsonb, \
                           'Concurrent Deliver', NULL, NULL, 'hello', NULL, 64, FALSE, now(), \
                           'pass', NULL, NULL, 0.0, NULL)",
                        &[&raw_ref, &msg_id, &rcpt],
                    )
                    .await;
                let row = match row {
                    Ok(r) => r,
                    Err(e) => {
                        assert_ok_or_race::<()>(Err(e), &[], &format!("deliver[{iter}][{side}]"));
                        unreachable!()
                    }
                };
                let id: Option<i64> = row.get(0);
                assert!(id.is_some(), "deliver[{iter}][{side}] must return a message id");
            }));
        }
        for t in tasks {
            t.await.unwrap();
        }
    }

    // (b) Two concurrent jmap_email_set_create() calls on the same mailbox.
    for iter in 0..8 {
        let barrier = Arc::new(Barrier::new(2));
        let mut tasks = Vec::with_capacity(2);
        for side in 0..2 {
            let b = barrier.clone();
            let d = dsn.clone();
            let mb = acc.mailbox_id;
            let drafts = acc.drafts_tag_id;
            let payload = format!(
                "{{\"c{iter}_{side}\":{{\"mailboxIds\":{{\"{drafts}\":true}},\"subject\":\"Draft {iter}-{side}\",\"bodyValues\":{{\"text\":{{\"value\":\"body\"}}}}}}}}"
            );
            tasks.push(tokio::spawn(async move {
                let c = connect(&d).await;
                b.wait().await;
                let row = c
                    .query_one(
                        "SELECT (r->'notCreated')::text, (r->'created')::text \
                         FROM (SELECT jmap_email_set_create($1, $2::text::jsonb) AS r) s",
                        &[&mb, &payload],
                    )
                    .await;
                let row = match row {
                    Ok(r) => r,
                    Err(e) => {
                        assert_ok_or_race::<()>(
                            Err(e),
                            &[],
                            &format!("jmap_email_set_create[{iter}][{side}]"),
                        );
                        unreachable!()
                    }
                };
                let not_created: String = row.get(0);
                let created: String = row.get(1);
                assert_eq!(
                    not_created, "{}",
                    "jmap_email_set_create[{iter}][{side}] had notCreated={not_created}"
                );
                assert!(
                    created.contains(&format!("c{iter}_{side}")),
                    "jmap_email_set_create[{iter}][{side}] missing created entry: {created}"
                );
            }));
        }
        for t in tasks {
            t.await.unwrap();
        }
    }

    // (c) Concurrent deliver() vs jmap_email_set_create() on the same mailbox.
    for iter in 0..8 {
        let barrier = Arc::new(Barrier::new(2));
        let b1 = barrier.clone();
        let b2 = barrier.clone();
        let d1 = dsn.clone();
        let d2 = dsn.clone();
        let rcpt = acc.email.clone();
        let mb = acc.mailbox_id;
        let drafts = acc.drafts_tag_id;
        let raw_ref = format!("raw-mix-{tag}-{iter}");
        let msg_id = format!("<mix-{tag}-{iter}@ext.test>");
        let payload = format!(
            "{{\"m{iter}\":{{\"mailboxIds\":{{\"{drafts}\":true}},\"subject\":\"Mix {iter}\",\"bodyValues\":{{\"text\":{{\"value\":\"body\"}}}}}}}}"
        );

        let t1 = tokio::spawn(async move {
            let c = connect(&d1).await;
            b1.wait().await;
            let r = c
                .query_one(
                    "SELECT deliver(\
                       $1, $2, 'sender@ext.test', 'Sender', $3::text, \
                       jsonb_build_array(jsonb_build_object('email', $3::text)), '[]'::jsonb, '[]'::jsonb, \
                       'Mixed Deliver', NULL, NULL, 'hello', NULL, 64, FALSE, now(), \
                       'pass', NULL, NULL, 0.0, NULL)",
                    &[&raw_ref, &msg_id, &rcpt],
                )
                .await;
            assert!(assert_ok_or_race(r, &[], &format!("mixed deliver[{iter}]")));
        });
        let t2 = tokio::spawn(async move {
            let c = connect(&d2).await;
            b2.wait().await;
            let r = c
                .query_one(
                    "SELECT (jmap_email_set_create($1, $2::text::jsonb)->'notCreated')::text",
                    &[&mb, &payload],
                )
                .await;
            match r {
                Ok(row) => {
                    let not_created: String = row.get(0);
                    assert_eq!(
                        not_created, "{}",
                        "mixed create[{iter}] notCreated={not_created}"
                    );
                }
                Err(e) => {
                    assert_ok_or_race::<()>(Err(e), &[], &format!("mixed create[{iter}]"));
                }
            }
        });
        t1.await.unwrap();
        t2.await.unwrap();
    }

    cleanup_domain(&mut setup, domain_id).await;
}

/// 12. Review Finding 2 regression: concurrent `send()` vs `jmap_mailbox_set_update`
/// on the `Sent` tag of the same mailbox (plus concurrent `send()` vs `send()`).
/// Restoring `mailboxes FOR UPDATE` in `send.sql` prevents the lock-upgrade `40P01`
/// deadlock against `jmap_mailbox_set_update` (which locks `mailboxes FOR KEY SHARE`
/// -> `tags` -> `mailboxes FOR NO KEY UPDATE`).
#[tokio::test]
async fn concurrent_send_vs_jmap_mailbox_set_update_sent_tag_zero_deadlocks() {
    let Some(dsn) =
        skip_or_dsn("concurrent_send_vs_jmap_mailbox_set_update_sent_tag_zero_deadlocks")
    else {
        return;
    };
    let mut setup = connect(&dsn).await;
    let tag = unique_tag("send_tag");
    let (domain_id, admin_id) = seed_domain_and_admin(&setup, &tag).await;
    let acc = seed_populated_account(&setup, domain_id, admin_id, &tag).await;

    for iter in 0..12 {
        let barrier = Arc::new(Barrier::new(2));
        let b1 = barrier.clone();
        let b2 = barrier.clone();
        let d1 = dsn.clone();
        let d2 = dsn.clone();
        let uid = acc.user_id;
        let mb = acc.mailbox_id;
        let sent_tag = acc.sent_tag_id;
        let from_addr = acc.email.clone();
        let raw_ref = format!("raw-send-{tag}-{iter}");
        let msg_id = format!("<send-{tag}-{iter}@d{domain_id}.test>");
        let patch = format!("{{\"{sent_tag}\":{{\"sortOrder\":{}}}}}", 10 + iter);

        let t1 = tokio::spawn(async move {
            let c = connect(&d1).await;
            b1.wait().await;
            let r = c
                .query_one(
                    "SELECT send(\
                       $1, $2, $3, $4, $5, \
                       '[{\"email\":\"ext@external.example\"}]'::jsonb, '[]'::jsonb, '[]'::jsonb, \
                       'Concurrent Send', '', '', 'hello', NULL, 64, FALSE, NULL)",
                    &[&uid, &mb, &raw_ref, &msg_id, &from_addr],
                )
                .await;
            match r {
                Ok(row) => {
                    let sent_id: Option<i64> = row.get(0);
                    assert!(
                        sent_id.is_some(),
                        "send[{iter}] must return a Sent message id"
                    );
                }
                Err(e) => {
                    assert_ok_or_race::<()>(Err(e), &[], &format!("send[{iter}]"));
                }
            }
        });
        let t2 = tokio::spawn(async move {
            let c = connect(&d2).await;
            b2.wait().await;
            let r = c
                .query_one(
                    "SELECT (r->'notUpdated')::text, (r->'updated')::text \
                     FROM (SELECT jmap_mailbox_set_update($1, $2::text::jsonb) AS r) s",
                    &[&mb, &patch],
                )
                .await;
            match r {
                Ok(row) => {
                    let not_updated: String = row.get(0);
                    let updated: String = row.get(1);
                    assert_eq!(
                        not_updated, "{}",
                        "jmap_mailbox_set_update[{iter}] had notUpdated={not_updated}"
                    );
                    assert!(
                        updated.contains(&sent_tag.to_string()),
                        "jmap_mailbox_set_update[{iter}] did not update Sent tag {sent_tag}: {updated}"
                    );
                }
                Err(e) => {
                    assert_ok_or_race::<()>(
                        Err(e),
                        &[],
                        &format!("jmap_mailbox_set_update[{iter}]"),
                    );
                }
            }
        });
        t1.await.unwrap();
        t2.await.unwrap();
    }

    cleanup_domain(&mut setup, domain_id).await;
}
