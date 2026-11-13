//! Owner-approved security fixes of 2026-11-05 (#512): cross-tenant data paths. Each test
//! drives the real Rust command, read or pure function with the secure expectation; the
//! mutants (feature `oracle-mutants`, `SETJOIN_SECFIX3_MUTANT`, scripts/test-secfix6-mutants.py)
//! restore frozen Go's behaviour and must make these tests (or the re-baselined recorded
//! replays named in the mutant script) fail.
mod common;
use common::BoxError;
use serde_json::{json, Value};
use setjoin_conformance::{fixture, harness::Db};
use tokio_postgres::Client;

async fn actor(exec: &setjoin_pg::ScopedExecutor, user: i64) -> Result<setjoin_authz::Authorized, BoxError> {
    let mut headers = hyper::HeaderMap::new();
    headers.insert("host", "mail.test".parse()?);
    headers.insert("origin", "http://mail.test".parse()?);
    let token = common::recovery_token_with(user, json!({"admin": true}));
    headers.insert("authorization", format!("Bearer {token}").parse()?);
    Ok(
        setjoin_authz::authorize_request(exec, &common::recovery_keys(), "mailserver", &headers, "http")
            .await
            .ok_or("verified actor")?,
    )
}

async fn cleanup(owner: &Client) -> Result<(), BoxError> {
    owner.batch_execute(
        "BEGIN; SET LOCAL session_replication_role=replica; \
         DELETE FROM admin_role_assignments WHERE role_group_id IN (SELECT id FROM admin_role_groups WHERE name LIKE 'secfix6-%'); \
         DELETE FROM admin_role_groups WHERE name LIKE 'secfix6-%'; \
         DELETE FROM devices WHERE user_id IN (SELECT id FROM users WHERE email LIKE 'secfix6-%'); \
         DELETE FROM calendar_subscriptions WHERE user_id IN (SELECT id FROM users WHERE email LIKE 'secfix6-%'); \
         DELETE FROM calendars WHERE mailbox_id IN (SELECT id FROM mailboxes WHERE email LIKE 'secfix6-%'); \
         DELETE FROM outbound_queue WHERE message_id LIKE 'secfix6-%'; \
         DELETE FROM outbound_queue_hot WHERE message_id LIKE 'secfix6-%'; \
         DELETE FROM orphaned_message_blobs WHERE raw_ref LIKE 'secfix6-%'; \
         CREATE TEMP TABLE secfix6_domains ON COMMIT DROP AS SELECT DISTINCT domain_id FROM users WHERE email LIKE 'secfix6-%'; \
         DELETE FROM mailbox_audit_log WHERE mailbox_id IN (SELECT id FROM mailboxes WHERE email LIKE 'secfix6-%'); \
         DELETE FROM messages WHERE mailbox_id IN (SELECT id FROM mailboxes WHERE email LIKE 'secfix6-%'); \
         DELETE FROM message_trace WHERE details->>'mailbox_id' IN (SELECT id::text FROM mailboxes WHERE email LIKE 'secfix6-%'); \
         DELETE FROM message_tags WHERE tag_id IN (SELECT id FROM tags WHERE mailbox_id IN (SELECT id FROM mailboxes WHERE email LIKE 'secfix6-%')); \
         DELETE FROM imap_membership_uid_ledger WHERE tag_id IN (SELECT id FROM tags WHERE mailbox_id IN (SELECT id FROM mailboxes WHERE email LIKE 'secfix6-%')); \
         DELETE FROM tags WHERE mailbox_id IN (SELECT id FROM mailboxes WHERE email LIKE 'secfix6-%'); \
         DELETE FROM folders WHERE mailbox_id IN (SELECT id FROM mailboxes WHERE email LIKE 'secfix6-%'); \
         DELETE FROM jmap_changes_journal WHERE mailbox_id IN (SELECT id FROM mailboxes WHERE email LIKE 'secfix6-%'); \
         DELETE FROM jmap_entity_state WHERE mailbox_id IN (SELECT id FROM mailboxes WHERE email LIKE 'secfix6-%'); \
         DELETE FROM mailbox_address_claims WHERE mailbox_id IN (SELECT id FROM mailboxes WHERE email LIKE 'secfix6-%'); \
         DELETE FROM mailbox_lifecycle WHERE mailbox_id IN (SELECT id FROM mailboxes WHERE email LIKE 'secfix6-%') OR bound_user_id IN (SELECT id FROM users WHERE email LIKE 'secfix6-%'); \
         DELETE FROM sender_control_state WHERE user_id IN (SELECT id FROM users WHERE email LIKE 'secfix6-%'); \
         DELETE FROM user_lifecycle_authorities WHERE user_id IN (SELECT id FROM users WHERE email LIKE 'secfix6-%'); \
         DELETE FROM mailboxes WHERE email LIKE 'secfix6-%'; \
         DELETE FROM users WHERE email LIKE 'secfix6-%'; \
         DELETE FROM domains WHERE id IN (SELECT domain_id FROM secfix6_domains); \
         COMMIT;",
    )
    .await?;
    Ok(())
}

async fn world(case: &str) -> Result<Option<(Db, Client, fixture::Account, fixture::Account)>, BoxError> {
    let Some(db) = Db::for_case(case) else { return Ok(None) };
    let owner = db.connect().await?;
    cleanup(&owner).await?;
    let a = fixture::account(&owner, "secfix6-a").await?;
    let b = fixture::account(&owner, "secfix6-b").await?;
    Ok(Some((db, owner, a, b)))
}

async fn queue_row(owner: &Client, table: &str, mailbox: i64, message_id: &str, status: &str) -> Result<(), BoxError> {
    owner
        .execute(
            &format!(
                "INSERT INTO {table}(message_id,from_addr,rcpt_addrs,raw_ref,status,next_attempt_at,mailbox_id) \
                 VALUES($1,'secfix6@example.test',ARRAY['x@example.test'],'secfix6-raw',$2,now()+interval '1 hour',$3)"
            ),
            &[&message_id, &status, &mailbox],
        )
        .await?;
    Ok(())
}

async fn queue_count(owner: &Client, table: &str, mailbox: i64) -> Result<i64, BoxError> {
    Ok(owner
        .query_one(&format!("SELECT count(*) FROM {table} WHERE mailbox_id=$1 AND message_id LIKE 'secfix6-%'"), &[&mailbox])
        .await?
        .get(0))
}

/// #476: undoing a send deletes only the caller's queue rows, not another tenant's row that
/// shares the Message-ID.
/// The cases share one database, fixed fixtures and reducers: libtest's threads must take turns.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[tokio::test]
async fn undo_send_never_deletes_another_tenants_queue_row() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some((_db, owner, a, b)) = world("secfix6-undo").await? else { return Ok(()) };
    let result = async {
        let shared = "secfix6-shared@oracle.test";
        owner.execute("UPDATE messages SET message_id=$2 WHERE id=$1", &[&a.inbox_only, &shared]).await?;
        owner
            .execute(
                "INSERT INTO message_tags(message_id,received_at,tag_id,added_by,is_primary) \
                 SELECT m.id,m.received_at,t.id,'send',false FROM messages m JOIN tags t ON t.mailbox_id=m.mailbox_id AND t.name='Sent' WHERE m.id=$1",
                &[&a.inbox_only],
            )
            .await?;
        for (mailbox, table, status) in [
            (a.mailbox, "outbound_queue", "deferred"),
            (a.mailbox, "outbound_queue_hot", "pending"),
            (b.mailbox, "outbound_queue", "deferred"),
            (b.mailbox, "outbound_queue_hot", "pending"),
        ] {
            queue_row(&owner, table, mailbox, shared, status).await?;
        }
        let undone: String = owner.query_one("SELECT undo_send($1,$2)::text", &[&a.mailbox, &a.inbox_only]).await?.get(0);
        let undone: Value = serde_json::from_str(&undone)?;
        assert_eq!(undone["queueItemsCleared"], 2, "{undone}");
        for table in ["outbound_queue", "outbound_queue_hot"] {
            assert_eq!(queue_count(&owner, table, a.mailbox).await?, 0, "own {table} row not cleared");
            assert_eq!(queue_count(&owner, table, b.mailbox).await?, 1, "foreign {table} row was deleted");
        }
        Ok::<_, BoxError>(())
    }
    .await;
    cleanup(&owner).await?;
    result
}

/// #470: the shared-blob check of a purge counts only the caller's mailbox, so another tenant's
/// message with the same raw_ref neither decides the outcome nor leaks its existence.
#[tokio::test]
async fn purge_blob_check_ignores_another_tenants_message() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some((_db, owner, a, b)) = world("secfix6-purge").await? else { return Ok(()) };
    let result = async {
        let raw = "secfix6-shared-raw";
        owner.execute("UPDATE messages SET raw_ref=$2, is_deleted=true, deleted_at=now() WHERE id=$1", &[&a.inbox_only, &raw]).await?;
        owner.execute("UPDATE messages SET raw_ref=$2 WHERE id=$1", &[&b.inbox_only, &raw]).await?;
        let ids = vec![a.inbox_only];
        let purged: String = owner.query_one("SELECT jmap_email_purge($1,$2,false)::text", &[&a.mailbox, &ids]).await?.get(0);
        let purged: Value = serde_json::from_str(&purged)?;
        assert_eq!(purged["purged"], json!([a.inbox_only.to_string()]), "{purged}");
        let queued: bool = owner
            .query_one("SELECT EXISTS(SELECT 1 FROM orphaned_message_blobs WHERE raw_ref=$1)", &[&raw])
            .await?
            .get(0);
        assert!(queued, "another tenant's message with the same raw_ref decided the purge");
        Ok::<_, BoxError>(())
    }
    .await;
    cleanup(&owner).await?;
    result
}

/// #478 item 2: the system-tag precheck of Mailbox/set update looks at the caller's own tags
/// only, so a foreign system tag id answers like a missing tag instead of "Cannot modify system tag".
#[tokio::test]
async fn mailbox_set_system_tag_precheck_is_mailbox_scoped() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some((_db, owner, a, b)) = world("secfix6-systag").await? else { return Ok(()) };
    let result = async {
        let foreign_inbox = b.inbox;
        let patch = json!({ foreign_inbox.to_string(): {"name": "renamed"} });
        let out: String = owner.query_one("SELECT jmap_mailbox_set_update($1,$2::text::jsonb)::text", &[&a.mailbox, &patch.to_string()]).await?.get(0);
        let out: Value = serde_json::from_str(&out)?;
        let err = &out["notUpdated"][foreign_inbox.to_string()];
        assert_eq!(err["type"], "notFound", "{out}");
        let name: String = owner.query_one("SELECT name FROM tags WHERE id=$1", &[&foreign_inbox]).await?.get(0);
        assert_eq!(name, "Inbox");
        // The caller's own system tag stays protected.
        let own = json!({ a.inbox.to_string(): {"name": "renamed"} });
        let out: String = owner.query_one("SELECT jmap_mailbox_set_update($1,$2::text::jsonb)::text", &[&a.mailbox, &own.to_string()]).await?.get(0);
        let out: Value = serde_json::from_str(&out)?;
        assert_eq!(out["notUpdated"][a.inbox.to_string()]["type"], "invalidArguments", "{out}");
        Ok::<_, BoxError>(())
    }
    .await;
    cleanup(&owner).await?;
    result
}

/// #423: the calendar subscription cap counts the caller's rows under the RLS-bound request
/// credential (frozen Go counted on the unscoped pool, saw 0 and never tripped the cap).
#[tokio::test]
async fn subscription_cap_counts_under_the_rls_bound_credential() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some((db, owner, a, _b)) = world("secfix6-subscription-cap").await? else { return Ok(()) };
    let result = async {
        for i in 0..setjoin_calendar::MAX_SUBSCRIPTIONS_PER_USER {
            let calendar: i64 = owner
                .query_one("INSERT INTO calendars(mailbox_id,name,color) VALUES($1,$2,'#6366f1') RETURNING id", &[&a.mailbox, &format!("secfix6-sub-{i}")])
                .await?
                .get(0);
            owner
                .execute("INSERT INTO calendar_subscriptions(user_id,calendar_id,url) VALUES($1,$2,$3)", &[&a.user, &calendar, &format!("https://example.test/secfix6-{i}.ics")])
                .await?;
        }
        let app = db.app.as_deref().ok_or("DB_APP_DSN is required for the RLS case")?;
        let exec = common::patient_exec(app, 4)?;
        let authorized = actor(&common::patient_exec(&db.dsn, 2)?, a.user).await?;
        let counted = setjoin_calendar::subscription_count(&exec, authorized.context()).await.map_err(|e| e.message)?;
        assert_eq!(counted, setjoin_calendar::MAX_SUBSCRIPTIONS_PER_USER, "the cap saw {counted} rows under RLS");
        Ok::<_, BoxError>(())
    }
    .await;
    cleanup(&owner).await?;
    result
}

/// #430: the M365 consent URL escapes the stored client id and takes the redirect host from
/// the configured public host, never from the client-supplied Host header.
#[test]
fn m365_consent_url_is_built_from_trusted_inputs() {
    let url = setjoin_gateway::migration::consent_url(
        "https://login.microsoftonline.com",
        "id&redirect_uri=https://evil.test/x#<",
        "mail.example.test",
        "attacker.test",
        "tok",
    );
    assert_eq!(
        url,
        "https://login.microsoftonline.com/organizations/adminconsent?client_id=id%26redirect_uri%3Dhttps%3A%2F%2Fevil.test%2Fx%23%3C&redirect_uri=https%3A%2F%2Fmail.example.test%2Fadmin%2Fmigration%2Fm365%2Fcallback&state=tok"
    );
    assert!(!url.contains("attacker.test"));
}

/// #436: a NUL anywhere in a KQL query is refused up front (frozen Go's parser could not advance
/// over a quoted NUL and hung the request).
#[test]
fn kql_refuses_a_quoted_nul() {
    for query in ["\"a\u{0}b\"", "a\u{0}", "from:\u{0}"] {
        let (tx, rx) = std::sync::mpsc::channel();
        let owned = query.to_owned();
        std::thread::spawn(move || {
            let _ = tx.send(setjoin_compliance::kql::parse(&owned).map(|_| ()));
        });
        match rx.recv_timeout(std::time::Duration::from_secs(5)) {
            Ok(Err(error)) => assert!(error.contains("NUL"), "{error}"),
            Ok(Ok(())) => panic!("a NUL query was parsed: {query:?}"),
            Err(_) => panic!("the KQL parser did not return for {query:?}"),
        }
    }
    assert!(setjoin_compliance::kql::parse("from:alice").is_ok());
}

/// #456: the update-device summary and list of a domain-scoped admin cover only the devices of
/// users inside its reach; an organization-wide admin still sees every tenant.
#[tokio::test]
async fn update_devices_are_confined_to_the_callers_reach() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some((db, owner, a, b)) = world("secfix6-updates").await? else { return Ok(()) };
    let result = async {
        let scoped = fixture::account(&owner, "secfix6-scoped").await?;
        let scoped_domain = scoped.domain;
        for (user, tag) in [(a.user, "a"), (b.user, "b"), (scoped.user, "s")] {
            owner
                .execute("INSERT INTO devices(user_id,fingerprint,device_name,platform,enroll_state) VALUES($1,$2,$2,'desktop','approved')", &[&user, &format!("secfix6-{tag}")])
                .await?;
        }
        let role: i64 = owner
            .query_one("INSERT INTO admin_role_groups(name,permissions,domain_scope) VALUES('secfix6-scoped',ARRAY['system.config'],$1) RETURNING id", &[&scoped_domain])
            .await?
            .get(0);
        owner.execute("INSERT INTO admin_role_assignments(user_id,role_group_id,granted_by) VALUES($1,$2,$1)", &[&scoped.user, &role]).await?;
        let exec = common::patient_exec(&db.dsn, 4)?;
        let total = |text: &str| -> Result<i64, BoxError> {
            let value: Value = serde_json::from_str(text.trim())?;
            Ok(value["total_devices"].as_i64().ok_or("total_devices")?)
        };
        let all: i64 = owner.query_one("SELECT count(*) FROM devices", &[]).await?.get(0);
        let scoped_summary = total(&setjoin_platform::updates::summary(&exec, scoped.user).await)?;
        assert_eq!(scoped_summary, 1, "a domain-scoped admin counted other tenants' devices");
        let global_summary = total(&setjoin_platform::updates::summary(&exec, 0).await)?;
        assert_eq!(global_summary, all);
        let listed = setjoin_platform::updates::devices(&exec, scoped.user, 50, 0).await.map_err(|e| e.message)?;
        assert!(listed.contains("secfix6-s"), "{listed}");
        assert!(!listed.contains("secfix6-a") && !listed.contains("secfix6-b"), "{listed}");
        Ok::<_, BoxError>(())
    }
    .await;
    cleanup(&owner).await?;
    result
}

/// #469 add-on: dot names never become archive entries and an oversized message is refused.
#[tokio::test]
async fn attachments_zip_neutralises_dot_names_and_bounds_entries() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    use setjoin_gateway::jmap::messages_zip::{archive_bytes, entries_allowed, entry_name, MAX_ENTRIES};
    assert_eq!(entry_name(".."), "attachment");
    assert_eq!(entry_name("."), "attachment");
    assert_eq!(entry_name("report.pdf"), "report.pdf");
    assert_eq!(entry_name("a/../b"), "a_.._b");
    assert!(entries_allowed(MAX_ENTRIES));
    assert!(!entries_allowed(MAX_ENTRIES + 1));
    let source = setjoin_jmap::messages::ZipSource {
        entries: vec![("sha-1".into(), "..".into()), ("sha-2".into(), ".".into())],
        subject: None,
    };
    let bytes = archive_bytes(source).await?;
    let mut names = Vec::new();
    let mut at = 0;
    while let Some(found) = bytes[at..].windows(4).position(|w| w == b"PK\x01\x02") {
        let start = at + found;
        let len = u16::from_le_bytes([bytes[start + 28], bytes[start + 29]]) as usize;
        names.push(String::from_utf8(bytes[start + 46..start + 46 + len].to_vec())?);
        at = start + 46 + len;
    }
    assert_eq!(names, ["attachment", "attachment-2"], "dot names must become ordinary entries");
    Ok(())
}
