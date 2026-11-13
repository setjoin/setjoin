//! Owner-approved security fixes of 2026-11-05 (#511): Exchange replacement group domain
//! scope (#434), device lockdown (#435), offline devices (#440), quarantine (#448). Each
//! test drives the real Rust command or read with three actors: a domain-scoped admin on a
//! foreign object (refused exactly like a missing one), on its own domain's object
//! (allowed) and an organization-wide admin (allowed). The mutants (feature
//! `oracle-mutants`, `SETJOIN_SECFIX3_MUTANT`, scripts/test-secfix5-mutants.py) restore
//! frozen Go's behaviour and must make these tests fail. The device-credential re-seal
//! test (#513 item 1) lives in crates/authz/tests/device_credential.rs.
mod common;
use common::BoxError;
use serde_json::json;
use setjoin_conformance::{fixture, harness::Db};
use setjoin_pg::{CommandOutcome, Rejection, ScopedExecutor};
use tokio_postgres::Client;

fn op() -> [u8; 16] {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    let mut out = [0u8; 16];
    out[..8].copy_from_slice(&nanos.to_be_bytes());
    out[8..].copy_from_slice(&NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst).to_be_bytes());
    out
}

async fn actor(exec: &ScopedExecutor, user: i64) -> Result<setjoin_authz::Authorized, BoxError> {
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

/// One role group holding `perms`, assigned to `user`; `domain` makes the GROUP domain-scoped.
async fn grant(owner: &Client, user: i64, perms: &[&str], domain: Option<i64>) -> Result<i64, BoxError> {
    let name = format!("secfix5-{user}-{}", perms.join("+"));
    let perms: Vec<String> = perms.iter().map(|p| p.to_string()).collect();
    let role: i64 = owner
        .query_one(
            "INSERT INTO admin_role_groups(name,permissions,domain_scope) VALUES($1,$2,$3) RETURNING id",
            &[&name, &perms, &domain],
        )
        .await?
        .get(0);
    owner
        .execute(
            "INSERT INTO admin_role_assignments(user_id,role_group_id,granted_by) VALUES($1,$2,$1)",
            &[&user, &role],
        )
        .await?;
    Ok(role)
}

async fn cleanup(owner: &Client) -> Result<(), BoxError> {
    owner.batch_execute(
        "BEGIN; SET LOCAL session_replication_role=replica; \
         DELETE FROM admin_role_assignments WHERE role_group_id IN (SELECT id FROM admin_role_groups WHERE name LIKE 'secfix5-%'); \
         DELETE FROM admin_role_groups WHERE name LIKE 'secfix5-%'; \
         DELETE FROM user_devices WHERE user_id IN (SELECT id FROM users WHERE email LIKE 'secfix5-%'); \
         DELETE FROM device_enroll_events WHERE device_id IN (SELECT id FROM devices WHERE user_id IN (SELECT id FROM users WHERE email LIKE 'secfix5-%')); \
         DELETE FROM devices WHERE user_id IN (SELECT id FROM users WHERE email LIKE 'secfix5-%'); \
         DELETE FROM quarantined_messages WHERE mailbox_id IN (SELECT id FROM mailboxes WHERE email LIKE 'secfix5-%'); \
         CREATE TEMP TABLE secfix5_domains ON COMMIT DROP AS SELECT DISTINCT domain_id FROM users WHERE email LIKE 'secfix5-%'; \
         DELETE FROM mailbox_audit_log WHERE mailbox_id IN (SELECT id FROM mailboxes WHERE email LIKE 'secfix5-%'); \
         DELETE FROM messages WHERE mailbox_id IN (SELECT id FROM mailboxes WHERE email LIKE 'secfix5-%'); \
         DELETE FROM message_trace WHERE details->>'mailbox_id' IN (SELECT id::text FROM mailboxes WHERE email LIKE 'secfix5-%'); \
         DELETE FROM message_tags WHERE tag_id IN (SELECT id FROM tags WHERE mailbox_id IN (SELECT id FROM mailboxes WHERE email LIKE 'secfix5-%')); \
         DELETE FROM imap_membership_uid_ledger WHERE tag_id IN (SELECT id FROM tags WHERE mailbox_id IN (SELECT id FROM mailboxes WHERE email LIKE 'secfix5-%')); \
         DELETE FROM tags WHERE mailbox_id IN (SELECT id FROM mailboxes WHERE email LIKE 'secfix5-%'); \
         DELETE FROM folders WHERE mailbox_id IN (SELECT id FROM mailboxes WHERE email LIKE 'secfix5-%'); \
         DELETE FROM jmap_changes_journal WHERE mailbox_id IN (SELECT id FROM mailboxes WHERE email LIKE 'secfix5-%'); \
         DELETE FROM jmap_entity_state WHERE mailbox_id IN (SELECT id FROM mailboxes WHERE email LIKE 'secfix5-%'); \
         DELETE FROM mailbox_address_claims WHERE mailbox_id IN (SELECT id FROM mailboxes WHERE email LIKE 'secfix5-%'); \
         DELETE FROM mailbox_lifecycle WHERE mailbox_id IN (SELECT id FROM mailboxes WHERE email LIKE 'secfix5-%') OR bound_user_id IN (SELECT id FROM users WHERE email LIKE 'secfix5-%'); \
         DELETE FROM sender_control_state WHERE user_id IN (SELECT id FROM users WHERE email LIKE 'secfix5-%'); \
         DELETE FROM user_lifecycle_authorities WHERE user_id IN (SELECT id FROM users WHERE email LIKE 'secfix5-%'); \
         DELETE FROM mailboxes WHERE email LIKE 'secfix5-%'; \
         DELETE FROM users WHERE email LIKE 'secfix5-%'; \
         DELETE FROM domains WHERE id IN (SELECT domain_id FROM secfix5_domains); \
         COMMIT;",
    )
    .await?;
    Ok(())
}

struct World {
    owner: Client,
    exec: ScopedExecutor,
    a: fixture::Account,
    b: fixture::Account,
    scoped: fixture::Account,
    global: fixture::Account,
}

/// The executor uses the request credential that bypasses RLS (the pre-flip posture), so
/// the unrelated Go RLS bug of the lockdown/offline reducers (missing user GUC) does not
/// mask the scope assertions.
async fn world(case: &str) -> Result<Option<World>, BoxError> {
    let Some(db) = Db::for_case(case) else { return Ok(None) };
    let owner = db.connect().await?;
    cleanup(&owner).await?;
    let a = fixture::account(&owner, "secfix5-a").await?;
    let b = fixture::account(&owner, "secfix5-b").await?;
    let scoped = fixture::account(&owner, "secfix5-scoped").await?;
    let global = fixture::account(&owner, "secfix5-global").await?;
    let exec = common::patient_exec(&db.dsn, 4)?.with_audit_keys("22".repeat(32), String::new());
    Ok(Some(World { owner, exec, a, b, scoped, global }))
}

impl World {
    async fn finish(self) -> Result<(), BoxError> {
        cleanup(&self.owner).await
    }
}

fn state_of<T: std::fmt::Debug>(outcome: &CommandOutcome<T, setjoin_pg::StatementFailure>) -> Option<String> {
    match outcome {
        CommandOutcome::RolledBack(Rejection::Statement(e) | Rejection::Body(e)) => e.sqlstate.clone(),
        _ => None,
    }
}

/// The cases share one database, fixed fixtures and reducers: libtest's threads must take turns.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[tokio::test]
async fn exchange_group_domain_scope_confines_a_scoped_admin() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(w) = world("secfix5-exchange").await? else { return Ok(()) };
    let result = async {
        let perm = "exchange.assessment.run";
        grant(&w.owner, w.scoped.user, &[perm], Some(w.a.domain)).await?;
        grant(&w.owner, w.global.user, &[perm], None).await?;
        // The assignment override alone must keep confining, as before.
        let role: i64 = w.owner.query_one("INSERT INTO admin_role_groups(name,permissions) VALUES('secfix5-override',$1) RETURNING id", &[&vec![perm.to_string()]]).await?.get(0);
        w.owner.execute("INSERT INTO admin_role_assignments(user_id,role_group_id,granted_by,domain_override) VALUES($1,$2,$1,$3)", &[&w.a.user, &role, &w.a.domain]).await?;
        let allowed = |user: i64, domain: i64| {
            let owner = &w.owner;
            async move {
                let ok: bool = owner
                    .query_one("SELECT exchange_assessment_domain_authorized($1,$2,$3)", &[&user, &domain, &perm])
                    .await?
                    .get(0);
                Ok::<_, BoxError>(ok)
            }
        };
        assert!(!allowed(w.scoped.user, w.b.domain).await?, "group-scoped admin authorised for a foreign domain");
        assert!(allowed(w.scoped.user, w.a.domain).await?, "group-scoped admin refused its own domain");
        assert!(allowed(w.global.user, w.a.domain).await? && allowed(w.global.user, w.b.domain).await?, "org-wide admin refused");
        assert!(!allowed(w.a.user, w.b.domain).await?, "override-scoped admin authorised for a foreign domain");
        assert!(allowed(w.a.user, w.a.domain).await?);
        Ok::<_, BoxError>(())
    }
    .await;
    w.finish().await?;
    result
}

async fn device(owner: &Client, user: i64, tag: &str) -> Result<i64, BoxError> {
    Ok(owner
        .query_one(
            "INSERT INTO devices(user_id,fingerprint,hmac_secret,enroll_state,device_name,platform) VALUES($1,$2,'seed-secret','enrolled','secfix5 phone','ios') RETURNING id",
            &[&user, &format!("secfix5-{tag}-{user}")],
        )
        .await?
        .get(0))
}

async fn enroll_state(owner: &Client, id: i64) -> Result<String, BoxError> {
    Ok(owner.query_one("SELECT enroll_state FROM devices WHERE id=$1", &[&id]).await?.get(0))
}

#[tokio::test]
async fn lockdown_console_is_confined_to_the_callers_reach() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    use setjoin_devices::lockdown;
    let Some(w) = world("secfix5-lockdown").await? else { return Ok(()) };
    let result = async {
        grant(&w.owner, w.scoped.user, &["mam.read", "mam.write"], Some(w.a.domain)).await?;
        grant(&w.owner, w.global.user, &["mam.read", "mam.write"], None).await?;
        let (own, foreign) = (device(&w.owner, w.a.user, "own").await?, device(&w.owner, w.b.user, "foreign").await?);
        let scoped = actor(&w.exec, w.scoped.user).await?;
        let global = actor(&w.exec, w.global.user).await?;
        // Reads: the approval queue and the per-user list.
        let queue = lockdown::queue(&w.exec, scoped.context(), "enrolled", "", 500).await.map_err(|e| e.message)?;
        assert!(queue.contains(&format!("\"id\":{own},")), "own device missing from the scoped queue");
        assert!(!queue.contains(&format!("\"id\":{foreign},")), "scoped queue lists a foreign device");
        let wide = lockdown::queue(&w.exec, global.context(), "enrolled", "", 500).await.map_err(|e| e.message)?;
        assert!(wide.contains(&format!("\"id\":{foreign},")), "org-wide queue lost a device");
        assert_eq!(lockdown::devices_of(&w.exec, scoped.context(), w.b.user).await.map_err(|e| e.message)?.trim(), "[]", "scoped admin listed a foreign user's devices");
        assert!(lockdown::devices_of(&w.exec, scoped.context(), w.a.user).await.map_err(|e| e.message)?.contains(&format!("\"id\":{own}")));
        // Writes: a foreign device answers exactly like a missing one and stays unchanged.
        let denied = lockdown::transition(&w.exec, scoped.context(), foreign, "approved", "x", op()).await;
        let missing = lockdown::transition(&w.exec, scoped.context(), 999_999_999, "approved", "x", op()).await;
        assert_eq!(state_of(&denied).as_deref(), Some("BZ095"), "scoped admin transitioned a foreign device: {denied:?}");
        let (CommandOutcome::RolledBack(d), CommandOutcome::RolledBack(m)) = (&denied, &missing) else { return Err("expected refusals".into()) };
        assert_eq!(lockdown::transition_refusal(d).0, lockdown::transition_refusal(m).0);
        assert_eq!(enroll_state(&w.owner, foreign).await?, "enrolled");
        let allowed = lockdown::transition(&w.exec, scoped.context(), own, "approved", "x", op()).await;
        assert!(matches!(allowed, CommandOutcome::Committed(())), "own-domain device refused: {allowed:?}");
        assert_eq!(enroll_state(&w.owner, own).await?, "approved");
        let wide = lockdown::transition(&w.exec, global.context(), foreign, "approved", "x", op()).await;
        assert!(matches!(wide, CommandOutcome::Committed(())), "org-wide admin refused: {wide:?}");
        Ok::<_, BoxError>(())
    }
    .await;
    w.finish().await?;
    result
}

async fn user_device(owner: &Client, user: i64, tag: &str, state: &str) -> Result<i64, BoxError> {
    Ok(owner
        .query_one(
            "INSERT INTO user_devices(user_id,device_name,platform,fingerprint_hash,offline_approval,last_seen_at) VALUES($1,$2,'desktop',$3,$4,now()) RETURNING id",
            &[&user, &format!("secfix5 {tag}"), &format!("secfix5-{tag}-{user}").into_bytes(), &state],
        )
        .await?
        .get(0))
}

#[tokio::test]
async fn offline_devices_are_confined_to_the_callers_reach() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    use setjoin_devices::offline;
    let Some(w) = world("secfix5-offline").await? else { return Ok(()) };
    let result = async {
        grant(&w.owner, w.scoped.user, &["mam.read", "mam.write"], Some(w.a.domain)).await?;
        grant(&w.owner, w.global.user, &["mam.read", "mam.write"], None).await?;
        let (pend_own, pend_foreign) = (user_device(&w.owner, w.a.user, "pend", "pending").await?, user_device(&w.owner, w.b.user, "pend", "pending").await?);
        let (appr_own, appr_foreign) = (user_device(&w.owner, w.a.user, "appr", "approved").await?, user_device(&w.owner, w.b.user, "appr", "approved").await?);
        let scoped = actor(&w.exec, w.scoped.user).await?;
        let global = actor(&w.exec, w.global.user).await?;
        let ids = |text: String| -> Vec<i64> { serde_json::from_str::<Vec<serde_json::Value>>(&text).unwrap().iter().map(|v| v["id"].as_i64().unwrap()).collect() };
        let queue = ids(offline::pending(&w.exec, scoped.context()).await.map_err(|e| e.message)?);
        assert!(queue.contains(&pend_own), "own pending device missing from the scoped queue");
        assert!(!queue.contains(&pend_foreign), "scoped pending queue lists a foreign device");
        let wide = ids(offline::pending(&w.exec, global.context()).await.map_err(|e| e.message)?);
        assert!(wide.contains(&pend_own) && wide.contains(&pend_foreign), "org-wide queue lost a device");
        let approval = |id: i64| {
            let owner = &w.owner;
            async move {
                let row = owner.query_one("SELECT offline_approval, wipe_requested FROM user_devices WHERE id=$1", &[&id]).await?;
                Ok::<_, BoxError>((row.get::<_, String>(0), row.get::<_, bool>(1)))
            }
        };
        let run = |ctx: &setjoin_authz::Authorized, action: &'static str, id: i64| {
            let (exec, ctx) = (w.exec.clone(), ctx.context().clone());
            async move { offline::command(&exec, &ctx, action, json!({"id": id}), op()).await }
        };
        // A foreign device answers exactly like a missing one and stays untouched.
        let missing = run(&scoped, "wipe", 999_999_999).await;
        for (action, id, from) in [("wipe", appr_foreign, "approved"), ("revoke", appr_foreign, "approved"), ("approve", pend_foreign, "pending"), ("deny", pend_foreign, "pending")] {
            let denied = run(&scoped, action, id).await;
            assert_eq!(state_of(&denied).as_deref(), Some("BZ100"), "scoped admin could {action} a foreign device: {denied:?}");
            let (CommandOutcome::RolledBack(d), CommandOutcome::RolledBack(m)) = (&denied, &missing) else { return Err("expected refusals".into()) };
            let (Rejection::Statement(d) | Rejection::Body(d), Rejection::Statement(m) | Rejection::Body(m)) = (d, m) else { return Err("statement refusals".into()) };
            assert_eq!(d.hint.as_deref().map(|h| h.contains("not_found")), m.hint.as_deref().map(|h| h.contains("not_found")));
            assert_eq!(approval(id).await?, (from.to_string(), false), "{action} changed a foreign device");
        }
        let own = run(&scoped, "wipe", appr_own).await;
        assert!(matches!(own, CommandOutcome::Committed(_)), "own-domain wipe refused: {own:?}");
        assert_eq!(approval(appr_own).await?, ("revoked".to_string(), true));
        let wide = run(&global, "wipe", appr_foreign).await;
        assert!(matches!(wide, CommandOutcome::Committed(_)), "org-wide wipe refused: {wide:?}");
        assert_eq!(approval(appr_foreign).await?, ("revoked".to_string(), true));
        let wide = run(&global, "approve", pend_foreign).await;
        assert!(matches!(wide, CommandOutcome::Committed(_)), "org-wide approve refused: {wide:?}");
        Ok::<_, BoxError>(())
    }
    .await;
    w.finish().await?;
    result
}

async fn quarantine(owner: &Client, account: &fixture::Account, tag: &str) -> Result<i64, BoxError> {
    let message = fixture::message(owner, account.mailbox, account.inbox, &[account.inbox], false).await?;
    owner.execute("UPDATE messages SET subject=$2, body_html='<p>q</p>' WHERE id=$1", &[&message, &format!("secfix5 {tag}")]).await?;
    owner
        .execute("SELECT quarantine_message($1,$2,'secfix5','virus','Test-Virus',FALSE)", &[&message, &account.mailbox])
        .await?;
    Ok(owner.query_one("SELECT id FROM quarantined_messages WHERE message_id=$1", &[&message]).await?.get(0))
}

#[tokio::test]
async fn quarantine_admin_actions_are_confined_to_the_callers_reach() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    use setjoin_mail_security::quarantine;
    let Some(w) = world("secfix5-quarantine").await? else { return Ok(()) };
    let result = async {
        let perms = ["mail.security", "mail.export", "security.write"];
        grant(&w.owner, w.scoped.user, &perms, Some(w.a.domain)).await?;
        grant(&w.owner, w.global.user, &perms, None).await?;
        let (own, foreign) = (quarantine(&w.owner, &w.a, "own").await?, quarantine(&w.owner, &w.b, "foreign").await?);
        let scoped = actor(&w.exec, w.scoped.user).await?;
        let global = actor(&w.exec, w.global.user).await?;
        // Preview and stats.
        assert!(quarantine::admin_preview(&w.exec, scoped.context(), foreign).await.map_err(|e| e.message)?.is_none(), "scoped admin previewed a foreign message");
        assert!(quarantine::admin_preview(&w.exec, scoped.context(), own).await.map_err(|e| e.message)?.is_some(), "own message not previewable");
        assert!(quarantine::admin_preview(&w.exec, global.context(), foreign).await.map_err(|e| e.message)?.is_some(), "org-wide admin refused");
        let stats = serde_json::from_str::<serde_json::Value>(&quarantine::admin_stats(&w.exec, scoped.context()).await)?;
        assert_eq!(stats["active"], 1, "scoped stats count a foreign domain: {stats}");
        let wide = serde_json::from_str::<serde_json::Value>(&quarantine::admin_stats(&w.exec, global.context()).await)?;
        assert!(wide["active"].as_i64().unwrap() >= 2, "org-wide stats lost a row: {wide}");
        // Release and reject: a foreign row answers like a missing one and stays active.
        let state = |id: i64| {
            let owner = &w.owner;
            async move {
                let row = owner.query_one("SELECT released_at IS NOT NULL, rejected_at IS NOT NULL, (SELECT count(*) FROM messages m WHERE m.id=q.message_id) FROM quarantined_messages q WHERE id=$1", &[&id]).await?;
                Ok::<_, BoxError>((row.get::<_, bool>(0), row.get::<_, bool>(1), row.get::<_, i64>(2)))
            }
        };
        for reject in [false, true] {
            let denied = quarantine::resolve(&w.exec, scoped.context(), foreign, true, reject, op()).await;
            assert!(matches!(denied, CommandOutcome::Committed(false)), "scoped admin acted on a foreign message (reject={reject}): {denied:?}");
            assert_eq!(state(foreign).await?, (false, false, 1), "foreign message changed (reject={reject})");
        }
        let released = quarantine::resolve(&w.exec, scoped.context(), own, true, false, op()).await;
        assert!(matches!(released, CommandOutcome::Committed(true)), "own-domain release refused: {released:?}");
        assert_eq!(state(own).await?.0, true);
        let rejected = quarantine::resolve(&w.exec, global.context(), foreign, true, true, op()).await;
        assert!(matches!(rejected, CommandOutcome::Committed(true)), "org-wide reject refused: {rejected:?}");
        assert_eq!(state(foreign).await?, (false, true, 0));
        Ok::<_, BoxError>(())
    }
    .await;
    w.finish().await?;
    result
}
