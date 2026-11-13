//! Owner-approved security fixes of 2026-11-05 (#499 items 2-4). Each test breaks
//! one table through a shadowing view, so the engine's read fails at runtime; the
//! mutant script (`scripts/test-secfix3-mutants.py`) restores each frozen-Go defect.
use setjoin_conditional_access::policy::eval::{Context, Engine};
use setjoin_conformance::{
    fixture,
    harness::{BoxError, Db},
};
use setjoin_pg::ScopedExecutor;

// The tests share one schema, fixed ids and priorities: libtest's threads take turns.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
const SCHEMA: &str = "secfix3_ca_fault";
async fn faulted(db: &Db, owner: &tokio_postgres::Client) -> Result<Engine, BoxError> {
    owner.batch_execute(&format!("DROP SCHEMA IF EXISTS {SCHEMA} CASCADE; CREATE SCHEMA {SCHEMA}; GRANT USAGE ON SCHEMA {SCHEMA} TO setjoin_app;")).await?;
    let app = db.app.as_deref().unwrap_or(&db.dsn);
    let sep = if app.contains('?') { "&" } else { "?" };
    let dsn = format!("{app}{sep}options=-csearch_path%3D{SCHEMA}%2Cpublic");
    Ok(Engine::new(ScopedExecutor::from_dsn(&dsn, 2).map_err(|e| e.0)?))
}
async fn break_table(owner: &tokio_postgres::Client, table: &str) -> Result<(), BoxError> {
    owner.batch_execute(&format!("CREATE VIEW {SCHEMA}.{table} AS SELECT * FROM public.{table} WHERE 1/(SELECT 0)=0; GRANT SELECT ON {SCHEMA}.{table} TO setjoin_app;")).await?;
    Ok(())
}
async fn policy(owner: &tokio_postgres::Client, id: i64, user: i64, actions: &str) -> Result<(), BoxError> {
    owner.execute("INSERT INTO conditional_access_policies(id,priority,name,state,scope_type,scope_target,conditions,actions) VALUES($1,-403,'secfix3','on','user',$2,'{}',$3::text::jsonb)", &[&id as &(dyn tokio_postgres::types::ToSql + Sync), &user.to_string(), &actions as &(dyn tokio_postgres::types::ToSql + Sync)]).await?;
    Ok(())
}
async fn cleanup(owner: &tokio_postgres::Client, id: i64) -> Result<(), BoxError> {
    owner.batch_execute(&format!("DROP SCHEMA IF EXISTS {SCHEMA} CASCADE")).await?;
    owner.execute("DELETE FROM conditional_access_policies WHERE id=$1", &[&id]).await?;
    Ok(())
}
fn ctx(user: i64, country: &str) -> Context {
    Context { user_id: user, country: country.into(), ..Default::default() }
}

#[tokio::test]
async fn invalidated_policy_cache_fails_closed_when_the_reload_fails() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("secfix3-policy-invalidate") else { return Ok(()) };
    let owner = db.connect().await?;
    let (a, b) = (fixture::account(&owner, "secfix3-inv-a").await?, fixture::account(&owner, "secfix3-inv-b").await?);
    let result = async {
        policy(&owner, 946201, a.user, r#"{"grants":[{"type":"block"}]}"#).await?;
        let engine = faulted(&db, &owner).await?;
        if engine.evaluate(ctx(b.user, "")).await.decision != "allow" { return Err("control evaluation must allow".into()); }
        engine.invalidate().await;
        break_table(&owner, "conditional_access_policies").await?;
        let r = engine.evaluate(ctx(b.user, "")).await;
        if r.decision != "block" { return Err(format!("reload failure after invalidation must fail closed: {r:?}").into()); }
        Ok::<_, BoxError>(())
    }.await;
    cleanup(&owner, 946201).await?;
    fixture::remove(&owner, &a).await?;
    fixture::remove(&owner, &b).await?;
    result
}

#[tokio::test]
async fn legacy_step_up_policy_counts_as_enforcing_on_evaluation_errors() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("secfix3-policy-step-up") else { return Ok(()) };
    let owner = db.connect().await?;
    let (a, b, c) = (fixture::account(&owner, "secfix3-su-a").await?, fixture::account(&owner, "secfix3-su-b").await?, fixture::account(&owner, "secfix3-su-c").await?);
    let result = async {
        policy(&owner, 946202, a.user, r#"{"action":"step_up"}"#).await?;
        let engine = faulted(&db, &owner).await?;
        if engine.evaluate(ctx(b.user, "")).await.decision != "allow" { return Err("control evaluation must allow".into()); }
        break_table(&owner, "user_group_members").await?;
        let r = engine.evaluate(ctx(c.user, "")).await;
        if r.decision != "block" { return Err(format!("an enforcing step_up policy must fail closed: {r:?}").into()); }
        Ok::<_, BoxError>(())
    }.await;
    cleanup(&owner, 946202).await?;
    for x in [&a, &b, &c] {
        fixture::remove(&owner, x).await?;
    }
    result
}

#[tokio::test]
async fn geo_tier_lookup_error_takes_the_checked_failure_path() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("secfix3-policy-geo") else { return Ok(()) };
    let owner = db.connect().await?;
    let (a, b) = (fixture::account(&owner, "secfix3-geo-a").await?, fixture::account(&owner, "secfix3-geo-b").await?);
    let result = async {
        policy(&owner, 946203, a.user, r#"{"grants":[{"type":"block"}]}"#).await?;
        let engine = faulted(&db, &owner).await?;
        if engine.evaluate(ctx(b.user, "US")).await.decision != "allow" { return Err("control evaluation must allow".into()); }
        break_table(&owner, "geo_country_tiers").await?;
        let r = engine.evaluate(ctx(b.user, "US")).await;
        if r.decision != "block" { return Err(format!("geo lookup error must not become a low-risk allow: {r:?}").into()); }
        Ok::<_, BoxError>(())
    }.await;
    cleanup(&owner, 946203).await?;
    fixture::remove(&owner, &a).await?;
    fixture::remove(&owner, &b).await?;
    result
}
