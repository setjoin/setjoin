//! Owner-approved security fixes of 2026-11-07 (#536: Microsoft migration calendar ownership,
//! Graph bearer origin pinning, worker-only auxiliary-object reducers). Each test states the
//! secure behaviour at the real seam; the mutants (feature `oracle-mutants`,
//! `SETJOIN_SECFIX3_MUTANT`, scripts/test-secfix9-mutants.py) restore frozen behaviour and
//! must make these tests fail.
mod common;
#[path = "common/fake_microsoft.rs"]
mod fake_microsoft;
use common::BoxError;
use serde_json::json;
use setjoin_conformance::{fixture, harness::Db};
use setjoin_gateway::migration_runner::{
    m365::{M365Config, M365Connector},
    Change, Config as RunnerConfig, Dialer, ItemKind, Orchestrator, SourceItem,
};
use std::{collections::BTreeMap, future::Future, pin::Pin, sync::Arc};
use tokio_postgres::Client;

struct NoStore;
impl setjoin_gateway::recovery_worker::ObjectStore for NoStore {
    fn remove<'a>(
        &'a self,
        _key: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async { Ok(()) })
    }
}

fn ics(uid: &str, title: &str) -> String {
    format!(
        "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:{uid}\r\nSUMMARY:{title}\r\n\
         DTSTART:20261107T100000Z\r\nDTEND:20261107T110000Z\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
    )
}

fn item(ics: String) -> SourceItem {
    SourceItem {
        kind: ItemKind::Calendar,
        change: Change::Upsert,
        object_id: "event".into(),
        version: "v1".into(),
        folder_id: "calendar".into(),
        raw: vec![],
        ics,
        vcf: String::new(),
        folder_path: vec![],
        tags: vec![],
        uid: 0,
        uid_validity: 0,
    }
}

struct World {
    owner: Client,
    runner: Orchestrator,
    /// The migration target (the job's mailbox) and the other tenant whose calendar id
    /// equals the target's mailbox id.
    target: fixture::Account,
    victim: fixture::Account,
    victim_calendar: i64,
}

/// Removes every `secfix9-*` fixture (a panicking, mutant-rejected test leaves its accounts
/// behind; leftovers would otherwise reach the migration oracle's thread reconciliation).
async fn cleanup(owner: &Client) -> Result<(), BoxError> {
    // Undo the probe-failure test's column rename if a panic left it behind.
    owner
        .batch_execute(
            "DO $$ BEGIN IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='calendar_events' AND column_name='uid_probe_broken') THEN ALTER TABLE calendar_events RENAME COLUMN uid_probe_broken TO uid; END IF; END $$",
        )
        .await?;
    owner
        .batch_execute(
            "BEGIN; SET LOCAL session_replication_role=replica; \
             CREATE TEMP TABLE secfix9_domains ON COMMIT DROP AS SELECT DISTINCT domain_id FROM users WHERE email LIKE 'secfix9-%'; \
             DELETE FROM calendar_events WHERE calendar_id IN (SELECT id FROM calendars WHERE mailbox_id IN (SELECT id FROM mailboxes WHERE email LIKE 'secfix9-%')); \
             DELETE FROM calendars WHERE mailbox_id IN (SELECT id FROM mailboxes WHERE email LIKE 'secfix9-%'); \
             DELETE FROM mailbox_audit_log WHERE mailbox_id IN (SELECT id FROM mailboxes WHERE email LIKE 'secfix9-%'); \
             DELETE FROM messages WHERE mailbox_id IN (SELECT id FROM mailboxes WHERE email LIKE 'secfix9-%'); \
             DELETE FROM message_trace WHERE details->>'mailbox_id' IN (SELECT id::text FROM mailboxes WHERE email LIKE 'secfix9-%'); \
             DELETE FROM message_tags WHERE tag_id IN (SELECT id FROM tags WHERE mailbox_id IN (SELECT id FROM mailboxes WHERE email LIKE 'secfix9-%')); \
             DELETE FROM imap_membership_uid_ledger WHERE tag_id IN (SELECT id FROM tags WHERE mailbox_id IN (SELECT id FROM mailboxes WHERE email LIKE 'secfix9-%')); \
             DELETE FROM tags WHERE mailbox_id IN (SELECT id FROM mailboxes WHERE email LIKE 'secfix9-%'); \
             DELETE FROM folders WHERE mailbox_id IN (SELECT id FROM mailboxes WHERE email LIKE 'secfix9-%'); \
             DELETE FROM jmap_changes_journal WHERE mailbox_id IN (SELECT id FROM mailboxes WHERE email LIKE 'secfix9-%'); \
             DELETE FROM jmap_entity_state WHERE mailbox_id IN (SELECT id FROM mailboxes WHERE email LIKE 'secfix9-%'); \
             DELETE FROM mailbox_address_claims WHERE mailbox_id IN (SELECT id FROM mailboxes WHERE email LIKE 'secfix9-%'); \
             DELETE FROM mailbox_lifecycle WHERE mailbox_id IN (SELECT id FROM mailboxes WHERE email LIKE 'secfix9-%') OR bound_user_id IN (SELECT id FROM users WHERE email LIKE 'secfix9-%'); \
             DELETE FROM sender_control_state WHERE user_id IN (SELECT id FROM users WHERE email LIKE 'secfix9-%'); \
             DELETE FROM user_lifecycle_authorities WHERE user_id IN (SELECT id FROM users WHERE email LIKE 'secfix9-%'); \
             DELETE FROM mailboxes WHERE email LIKE 'secfix9-%'; \
             DELETE FROM users WHERE email LIKE 'secfix9-%'; \
             DELETE FROM domains WHERE id IN (SELECT domain_id FROM secfix9_domains); \
             COMMIT;",
        )
        .await?;
    Ok(())
}

/// A target mailbox without a default calendar, and a victim whose calendar carries the
/// target's mailbox id as its own id (frozen Go used the mailbox id as the calendar id).
async fn world(case: &str) -> Result<Option<World>, BoxError> {
    let Some(db) = Db::for_case(case) else { return Ok(None) };
    let owner = db.connect().await?;
    cleanup(&owner).await?;
    let mut spare = vec![];
    let target = loop {
        let candidate = fixture::account(&owner, "secfix9-target").await?;
        let taken: bool = owner
            .query_one("SELECT EXISTS(SELECT 1 FROM calendars WHERE id=$1)", &[&candidate.mailbox])
            .await?
            .get(0);
        if !taken {
            break candidate;
        }
        spare.push(candidate);
        if spare.len() > 50 {
            return Err("no mailbox id free of calendar ids".into());
        }
    };
    let victim = fixture::account(&owner, "secfix9-victim").await?;
    owner
        .execute(
            "INSERT INTO calendars(id,mailbox_id,name,is_default) VALUES($1,$2,'Victim',true)",
            &[&target.mailbox, &victim.mailbox],
        )
        .await?;
    owner
        .execute(
            "INSERT INTO calendar_events(calendar_id,uid,title,start_at,end_at) VALUES($1,'shared-uid','Victim event','2026-11-07 10:00Z','2026-11-07 11:00Z')",
            &[&target.mailbox],
        )
        .await?;
    let runner = Orchestrator::new(RunnerConfig {
        db: setjoin_pg::workers::WorkerDatabase::new(&db.dsn)?
            .with_audit_keys("22".repeat(32), String::new()),
        store: Arc::new(NoStore),
        root: "22".repeat(32),
        dialer: Dialer::system(),
        dispatcher: None,
    });
    let victim_calendar = target.mailbox;
    Ok(Some(World { owner, runner, target, victim, victim_calendar }))
}

impl World {
    async fn finish(self) -> Result<(), BoxError> {
        cleanup(&self.owner).await
    }
    async fn uids(&self, calendar_mailbox: i64) -> Result<Vec<String>, BoxError> {
        Ok(self
            .owner
            .query(
                "SELECT e.uid FROM calendar_events e JOIN calendars c ON c.id=e.calendar_id WHERE c.mailbox_id=$1 ORDER BY e.uid",
                &[&calendar_mailbox],
            )
            .await?
            .iter()
            .map(|r| r.get(0))
            .collect())
    }
}

/// #536 item 1: the legacy auxiliary projection writes into the target mailbox's own default
/// calendar. Frozen Go used the mailbox id as the calendar id, so with a foreign calendar of
/// that id the probe saw the foreign events and the INSERT wrote into the foreign calendar.
/// The cases share one database, fixed fixtures and reducers: libtest's threads must take turns.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[tokio::test]
async fn legacy_calendar_projection_writes_only_the_target_mailboxs_own_calendar() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(w) = world("secfix9-calendar-own").await? else { return Ok(()) };
    let result = async {
        w.owner
            .execute(
                "INSERT INTO calendars(mailbox_id,name,is_default) VALUES($1,'Target',true)",
                &[&w.target.mailbox],
            )
            .await?;
        // A uid unknown to both calendars, then the uid the foreign calendar already holds:
        // the foreign event must neither be written next to nor be treated as a conflict.
        for uid in ["fresh-uid", "shared-uid"] {
            let outcome = w
                .runner
                .project_legacy_aux(1, w.target.mailbox, &item(ics(uid, "Migrated")))
                .await;
            assert_eq!(outcome, Ok(String::new()), "projection of {uid}");
        }
        assert_eq!(
            w.uids(w.victim.mailbox).await?,
            ["shared-uid"],
            "an event was written into another mailbox's calendar"
        );
        let title: String = w
            .owner
            .query_one("SELECT title FROM calendar_events WHERE calendar_id=$1", &[&w.victim_calendar])
            .await?
            .get(0);
        assert_eq!(title, "Victim event", "the foreign event was altered");
        assert_eq!(
            w.uids(w.target.mailbox).await?,
            ["fresh-uid", "shared-uid"],
            "the target's own default calendar did not receive the events"
        );
        Ok::<_, BoxError>(())
    }
    .await;
    w.finish().await?;
    result
}

/// Owner-approved 2026-11-12 (failure-only divergence from Go's bool `exists`,
/// vcf_import.go:171-181, ics_import.go:~166-176): a failed conflict probe fails the row. Go
/// read the error as "no conflict" and went on to insert. The probe is broken here by renaming
/// the column it reads, which the INSERT would also need, so only the probe error can be seen.
#[tokio::test]
async fn a_failed_conflict_probe_fails_the_row_and_inserts_nothing() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(w) = world("secfix9-probe-fails").await? else { return Ok(()) };
    let result = async {
        w.owner
            .execute(
                "INSERT INTO calendars(mailbox_id,name,is_default) VALUES($1,'Target',true)",
                &[&w.target.mailbox],
            )
            .await?;
        w.owner.batch_execute("ALTER TABLE calendar_events RENAME COLUMN uid TO uid_probe_broken").await?;
        let outcome = w
            .runner
            .project_legacy_aux(1, w.target.mailbox, &item(ics("fresh-uid", "Migrated")))
            .await;
        w.owner.batch_execute("ALTER TABLE calendar_events RENAME COLUMN uid_probe_broken TO uid").await?;
        let error = outcome.expect_err("a failed conflict probe must fail the row");
        assert!(error.contains("conflict probe"), "unexpected error: {error}");
        assert!(
            w.uids(w.target.mailbox).await?.is_empty(),
            "an event was inserted although its conflict probe failed"
        );
        Ok::<_, BoxError>(())
    }
    .await;
    w.finish().await?;
    result
}

/// #536 item 1: with no default calendar for the target mailbox the projection fails closed
/// instead of writing into whichever calendar carries the mailbox's numeric id.
#[tokio::test]
async fn legacy_calendar_projection_fails_closed_without_a_default_calendar() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(w) = world("secfix9-calendar-none").await? else { return Ok(()) };
    let result = async {
        let outcome = w
            .runner
            .project_legacy_aux(1, w.target.mailbox, &item(ics("fresh-uid", "Migrated")))
            .await;
        let error = outcome.expect_err("no default calendar must fail the object");
        assert!(error.contains("no default calendar"), "unexpected error: {error}");
        assert_eq!(
            w.uids(w.victim.mailbox).await?,
            ["shared-uid"],
            "an event was written into another mailbox's calendar"
        );
        Ok::<_, BoxError>(())
    }
    .await;
    w.finish().await?;
    result
}

fn graph_config() -> M365Config {
    cloud_config("global")
}

fn cloud_config(cloud: &str) -> M365Config {
    M365Config {
        client_id: "client".into(),
        client_secret: "secret".into(),
        tenant_id: "tenant".into(),
        cloud: cloud.into(),
        source_email: "source@example.test".into(),
        source_user_id: "source-user".into(),
    }
}

/// A client that reaches the loopback fake for the Graph, login and attacker hosts alike and
/// accepts its certificate, so only the connector's own origin check can stop a request.
fn lenient_client(peer: &fake_microsoft::Peer) -> Result<reqwest::Client, BoxError> {
    let mut builder = reqwest::Client::builder()
        .no_proxy()
        .http1_only()
        .redirect(reqwest::redirect::Policy::none())
        .danger_accept_invalid_certs(true);
    for name in [
        "graph.microsoft.com",
        "login.microsoftonline.com",
        "microsoftgraph.chinacloudapi.cn",
        "login.chinacloudapi.cn",
        "evil.example.test",
    ] {
        builder = builder.resolve(name, peer.address);
    }
    Ok(builder.build()?)
}

fn stolen(peer: &fake_microsoft::Peer) -> Vec<String> {
    peer.seen
        .lock()
        .unwrap()
        .iter()
        .filter(|r| r["path"].as_str().is_some_and(|p| p.contains("steal")))
        .map(|r| r.to_string())
        .collect()
}

/// #536 item 2: a delta link restored from a checkpoint must stay on the Graph origin
/// (https, the cloud's Graph host, default port, no userinfo) or the restore fails closed.
#[tokio::test]
async fn restored_delta_links_must_stay_on_the_graph_origin() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let peer = fake_microsoft::Peer::start("127.0.0.97:443", "success").await?;
    let good = "https://graph.microsoft.com/v1.0/users/source-user/events?$select=id".to_owned();
    let mut ok = M365Connector::with_client(graph_config(), lenient_client(&peer)?);
    ok.restore(&BTreeMap::from([("events".to_owned(), good.clone())]), &[])
        .expect("a Graph link is accepted");
    ok.restore(&BTreeMap::new(), &[("events".into(), "m365_delta_link".into(), json!(good))])
        .expect("a durable Graph link is accepted");
    for bad in [
        "https://evil.example.test/v1.0/steal-restore",
        "http://graph.microsoft.com/v1.0/steal-http",
        "https://graph.microsoft.com:8443/v1.0/steal-port",
        "https://user:pw@graph.microsoft.com/v1.0/steal-userinfo",
        "https://graph.microsoft.com@evil.example.test/v1.0/steal-confusion",
        "/v1.0/steal-relative",
    ] {
        let mut c = M365Connector::with_client(graph_config(), lenient_client(&peer)?);
        let legacy = c.restore(&BTreeMap::from([("events".to_owned(), bad.to_owned())]), &[]);
        assert!(legacy.is_err(), "legacy checkpoint {bad} was restored");
        let durable =
            c.restore(&BTreeMap::new(), &[("events".into(), "m365_delta_link".into(), json!(bad))]);
        assert!(durable.is_err(), "durable checkpoint {bad} was restored");
        // Whatever restore did, driving the connector must not send the token there.
        let _ = c.next_batch().await;
    }
    assert!(stolen(&peer).is_empty(), "requests reached a forbidden origin: {:?}", stolen(&peer));
    Ok(())
}

/// #536 item 2: an `@odata.nextLink` naming another origin is refused before any request,
/// so the bearer token never leaves the Graph host.
#[tokio::test]
async fn a_next_link_to_another_origin_never_receives_the_bearer_token() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let peer = fake_microsoft::Peer::start("127.0.0.97:443", "next-link").await?;
    let mut c = M365Connector::with_client(graph_config(), lenient_client(&peer)?);
    let error = match c.next_batch().await {
        Ok(_) => return Err("a foreign nextLink was followed".into()),
        Err(e) => e,
    };
    assert!(error.contains("refusing Graph link"), "unexpected error: {error}");
    assert!(stolen(&peer).is_empty(), "the bearer token reached the foreign origin: {:?}", stolen(&peer));
    Ok(())
}

/// #536 item 2: the two clouds are isolated from each other. A china connector refuses the
/// global Graph host (restore and live), a global connector refuses the china host, and each
/// accepts its own; the china fake answering global links (the old fixture) is refused live.
#[tokio::test]
async fn the_two_graph_clouds_refuse_each_others_links() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let global = "https://graph.microsoft.com/v1.0/users/source-user/events?$select=id";
    let china = "https://microsoftgraph.chinacloudapi.cn/v1.0/users/source-user/events?$select=id";
    let peer = fake_microsoft::Peer::start("127.0.0.97:443", "success").await?;
    for (cloud, own, foreign) in [("china", china, global), ("global", global, china)] {
        let mut c = M365Connector::with_client(cloud_config(cloud), lenient_client(&peer)?);
        c.restore(&BTreeMap::from([("events".to_owned(), own.to_owned())]), &[])
            .unwrap_or_else(|e| panic!("{cloud} refused its own host: {e}"));
        let mut c = M365Connector::with_client(cloud_config(cloud), lenient_client(&peer)?);
        assert!(
            c.restore(&BTreeMap::from([("events".to_owned(), foreign.to_owned())]), &[]).is_err(),
            "{cloud} restored the other cloud's link"
        );
        assert!(
            c.restore(&BTreeMap::new(), &[("events".into(), "m365_delta_link".into(), json!(foreign))]).is_err(),
            "{cloud} restored the other cloud's durable link"
        );
    }
    let wrong = fake_microsoft::Peer::start("127.0.0.98:443", "wrong-cloud-link").await?;
    let mut c = M365Connector::with_client(cloud_config("china"), lenient_client(&wrong)?);
    let error = match c.next_batch().await {
        Ok(_) => return Err("a global link was followed by a china connector".into()),
        Err(e) => e,
    };
    assert!(error.contains("refusing Graph link"), "unexpected error: {error}");
    Ok(())
}

/// #536 item 3: the auxiliary-object reducers are worker-only; the request-pool role can
/// neither run them (it could pass any job id to a SECURITY DEFINER projection) nor hold
/// PUBLIC execute.
#[tokio::test]
async fn auxiliary_object_reducers_are_worker_only() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("secfix9-acl") else { return Ok(()) };
    let owner = db.connect().await?;
    let app = db.app.as_deref().ok_or("DB_APP_DSN (setjoin_app) is required for the ACL test")?;
    let (client, connection) = tokio_postgres::connect(app, tokio_postgres::NoTls).await?;
    tokio::spawn(connection);
    let functions = [
        "rust_migration_apply_aux_object(bigint,uuid,text,text,text,text,text,text,jsonb,text)",
        "migration_aux_object_begin(bigint,uuid,text,text,text,text,text,text)",
        "migration_aux_object_complete(bigint,uuid,text,text,bigint)",
    ];
    for function in functions {
        for role in ["setjoin_app", "public"] {
            let held: bool = owner
                .query_one(
                    &format!("SELECT has_function_privilege('{role}','{function}'::regprocedure,'EXECUTE')"),
                    &[],
                )
                .await?
                .get(0);
            assert!(!held, "{role} may execute {function}");
        }
        let worker: bool = owner
            .query_one(
                &format!("SELECT has_function_privilege('setjoin_worker','{function}'::regprocedure,'EXECUTE')"),
                &[],
            )
            .await?
            .get(0);
        assert!(worker, "the worker role cannot execute {function}");
    }
    let denied = client
        .query(
            "SELECT rust_migration_apply_aux_object(1,'00000000-0000-5000-8000-000000000001','calendar','e','v','f','upsert',NULL,'[]',NULL)",
            &[],
        )
        .await
        .expect_err("the request-pool role ran the reducer");
    assert_eq!(
        denied.code().map(|c| c.code()),
        Some("42501"),
        "expected permission denied, got {denied}"
    );
    Ok(())
}
