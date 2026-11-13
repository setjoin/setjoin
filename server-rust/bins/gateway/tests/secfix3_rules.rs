//! Owner-approved security fixes of 2026-11-05 (#484). Mutants: feature
//! `oracle-mutants`, `SETJOIN_SECFIX3_MUTANT` (see scripts/test-secfix3-mutants.py).
mod common;
use common::BoxError;
use setjoin_conformance::{fixture, harness::Db};
use std::sync::Arc;

async fn actor(
    exec: &setjoin_pg::ScopedExecutor,
    user: i64,
    extra: serde_json::Value,
) -> Result<setjoin_authz::Authorized, BoxError> {
    let mut headers = hyper::HeaderMap::new();
    headers.insert("host", "mail.test".parse()?);
    headers.insert("origin", "http://mail.test".parse()?);
    headers.insert("authorization", format!("Bearer {}", common::recovery_token_with(user, extra)).parse()?);
    Ok(setjoin_authz::authorize_request(exec, &common::recovery_keys(), "mailserver", &headers, "http").await.ok_or("verified actor")?)
}
fn rule(name: &str) -> setjoin_rules::input::Rule {
    let mut r: setjoin_rules::input::Rule = serde_json::from_str(&format!(r#"{{"name":"{name}","enabled":true,"priority":1,"runOn":"server","conditions":[],"actions":[{{"type":"mark_read"}}]}}"#)).unwrap();
    setjoin_rules::input::validate(&mut r, true).unwrap();
    r
}
fn op() -> [u8; 16] {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos() as u64;
    let mut out = [0u8; 16];
    out[..8].copy_from_slice(&nanos.to_be_bytes());
    out[8..].copy_from_slice(&NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst).to_be_bytes());
    out
}

#[tokio::test]
async fn concurrent_personal_creates_cannot_exceed_the_rule_cap() -> Result<(), BoxError> {
    let Some(db) = Db::for_case("secfix3-rule-cap") else { return Ok(()) };
    let owner = db.connect().await?;
    let a = fixture::account(&owner, "secfix3-cap").await?;
    let exec = common::patient_exec(db.app.as_deref().unwrap_or(&db.dsn), 8)?.with_audit_keys("22".repeat(32), String::new());
    let result = async {
        let auth = Arc::new(actor(&exec, a.user, serde_json::json!({})).await?);
        let tasks: Vec<_> = (0..130)
            .map(|i| {
                let (exec, auth) = (exec.clone(), auth.clone());
                tokio::spawn(async move { setjoin_rules::personal_create(&exec, auth.context(), &rule(&format!("cap-{i}")), op()).await })
            })
            .collect();
        for t in tasks {
            t.await?;
        }
        let n: i64 = owner.query_one("SELECT count(*) FROM rules WHERE mailbox_id=$1", &[&a.mailbox]).await?.get(0);
        assert_eq!(n, 100, "personal rule cap exceeded or under-filled");
        Ok::<_, BoxError>(())
    }.await;
    owner.execute("DELETE FROM rules WHERE mailbox_id=$1", &[&a.mailbox]).await?;
    fixture::remove(&owner, &a).await?;
    result
}

#[tokio::test]
async fn concurrent_sweeps_cannot_exceed_the_active_sweep_cap() -> Result<(), BoxError> {
    let Some(db) = Db::for_case("secfix3-sweep-cap") else { return Ok(()) };
    let owner = db.connect().await?;
    let a = fixture::account(&owner, "secfix3-sweep").await?;
    let exec = common::patient_exec(db.app.as_deref().unwrap_or(&db.dsn), 8)?.with_audit_keys("22".repeat(32), String::new());
    let result = async {
        let auth = Arc::new(actor(&exec, a.user, serde_json::json!({})).await?);
        let mut ids = Vec::new();
        for i in 0..8 {
            let id: i64 = owner.query_one("INSERT INTO rules(mailbox_id,name,enabled,priority,run_on,conditions,actions) VALUES($1,$2,true,1,'server','[]','[]') RETURNING id", &[&a.mailbox, &format!("sweep-{i}")]).await?.get(0);
            ids.push(id);
        }
        let tasks: Vec<_> = ids
            .into_iter()
            .map(|id| {
                let (exec, auth) = (exec.clone(), auth.clone());
                tokio::spawn(async move { setjoin_rules::apply(&exec, auth.context(), id, "90d", op()).await })
            })
            .collect();
        for t in tasks {
            t.await?;
        }
        let n: i64 = owner.query_one("SELECT count(*) FROM scheduled_actions WHERE mailbox_id=$1 AND action_kind='rules_retro' AND status IN('pending','processing')", &[&a.mailbox]).await?.get(0);
        assert_eq!(n, 3, "active sweep cap exceeded");
        Ok::<_, BoxError>(())
    }.await;
    owner.execute("DELETE FROM scheduled_actions WHERE mailbox_id=$1", &[&a.mailbox]).await?;
    owner.execute("DELETE FROM rules WHERE mailbox_id=$1", &[&a.mailbox]).await?;
    fixture::remove(&owner, &a).await?;
    result
}

#[tokio::test]
async fn failed_authority_lookup_drops_signed_grants() -> Result<(), BoxError> {
    let Some(db) = Db::for_case("secfix3-authority-lookup") else { return Ok(()) };
    let owner = db.connect().await?;
    let a = fixture::account(&owner, "secfix3-authority").await?;
    let exec = common::patient_exec(db.app.as_deref().unwrap_or(&db.dsn), 2)?.with_audit_keys("22".repeat(32), String::new());
    let result = async {
        let auth = actor(&exec, a.user, serde_json::json!({"perms":["mail.pipeline","mail.security"],"domain_scope":7})).await?;
        let ctx = auth.context();
        assert_eq!(ctx.signed_permissions(), ["mail.pipeline", "mail.security"], "fixture must carry signed grants");
        let kept = setjoin_rules::authority::resolve(&exec, ctx).await.map_err(|e| e.message)?;
        assert!(kept.allows(&setjoin_rules::authority::PIPELINE), "control: a non-admin keeps its claim grants");
        let failed = setjoin_rules::authority::lookup_failed(ctx);
        assert!(!failed.allows(&setjoin_rules::authority::PIPELINE), "failed lookup kept signed grants");
        assert!(!failed.allows(&setjoin_rules::authority::MAIL_CONSOLE));
        assert_eq!(failed.domain, None);
        Ok::<_, BoxError>(())
    }.await;
    fixture::remove(&owner, &a).await?;
    result
}
