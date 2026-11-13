use setjoin_conditional_access::policy::eval::{evaluate, Context, Snapshot};
use setjoin_conformance::{
    fixture,
    harness::{BoxError, Db},
};
use setjoin_pg::ScopedExecutor;

#[tokio::test]
async fn uncached_policy_snapshot_observes_committed_changes() -> Result<(), BoxError> {
    let Some(db) = Db::for_case("authzgates-policy-store") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let a = fixture::account(&owner, "authzgates-store").await?;
    let exec =
        ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn), 2).map_err(|e| e.0)?;
    let result=async{
  owner.execute("INSERT INTO conditional_access_policies(id,priority,name,state,scope_type,scope_target,conditions,actions) VALUES(946001,-405,'authzgates-store','on','user',$1,'{}','{\"grants\":[{\"type\":\"block\"}]}')",&[&a.user.to_string()]).await?;
  let context=Context{user_id:a.user,..Default::default()};
  assert_eq!(evaluate(&Snapshot::load(&exec).await.map_err(|e|e.message)?,&context).decision,"block");
  owner.execute("UPDATE conditional_access_policies SET actions='{\"grants\":[{\"type\":\"allow\"}]}' WHERE id=946001",&[]).await?;
  assert_eq!(evaluate(&Snapshot::load(&exec).await.map_err(|e|e.message)?,&context).decision,"allow");
  Ok::<_,BoxError>(())
 }.await;
    owner
        .execute(
            "DELETE FROM conditional_access_policies WHERE id=946001",
            &[],
        )
        .await?;
    fixture::remove(&owner, &a).await?;
    result
}

#[tokio::test]
async fn live_policy_snapshot_changes_only_after_invalidation() -> Result<(), BoxError> {
    use setjoin_conditional_access::policy::eval::Engine;
    let Some(db) = Db::for_case("authzgates-policy-cache") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let a = fixture::account(&owner, "authzgates-cache").await?;
    let exec =
        ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn), 2).map_err(|e| e.0)?;
    let result=async{
  owner.execute("INSERT INTO conditional_access_policies(id,priority,name,state,scope_type,scope_target,conditions,actions) VALUES(946002,-404,'authzgates-cache','on','user',$1,'{}','{\"grants\":[{\"type\":\"block\"}]}')",&[&a.user.to_string()]).await?;
  let engine=Engine::new(exec);let context=Context{user_id:a.user,..Default::default()};
  if engine.evaluate(context.clone()).await.decision!="block"{return Err("initial block missing".into());}
  owner.execute("UPDATE conditional_access_policies SET actions='{\"grants\":[{\"type\":\"allow\"}]}' WHERE id=946002",&[]).await?;
  if engine.evaluate(context.clone()).await.decision!="block"{return Err("cache unexpectedly bypassed".into());}
  engine.invalidate().await;
  if engine.evaluate(context).await.decision!="allow"{return Err("invalidation retained old policy".into());}
  Ok::<_,BoxError>(())
 }.await;
    owner
        .execute(
            "DELETE FROM conditional_access_policies WHERE id=946002",
            &[],
        )
        .await?;
    fixture::remove(&owner, &a).await?;
    result
}

#[tokio::test]
async fn cold_policy_failure_obeys_startup_fail_mode_and_break_glass() -> Result<(), BoxError> {
    use setjoin_conditional_access::policy::eval::Engine;
    let Some(db) = Db::for_case("authzgates-fail-mode") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let a = fixture::account(&owner, "authzgates-fail-mode").await?;
    let saved:Vec<String>=owner.query("SELECT to_jsonb(c)::text FROM system_config c WHERE key IN ('ca_fail_mode','ca_break_glass_user_ids')",&[]).await?.iter().map(|r|r.get(0)).collect();
    owner.batch_execute("CREATE SCHEMA authzgates_policy_fault; CREATE VIEW authzgates_policy_fault.system_config AS SELECT * FROM public.system_config; GRANT USAGE ON SCHEMA authzgates_policy_fault TO setjoin_app; GRANT SELECT ON authzgates_policy_fault.system_config TO setjoin_app;").await?;
    let app = db.app.as_deref().unwrap_or(&db.dsn);
    let sep = if app.contains('?') { "&" } else { "?" };
    let fault_dsn =
        format!("{app}{sep}options=-csearch_path%3Dauthzgates_policy_fault%2Cpg_catalog");
    let result=async{
  for(mode,bg,expected)in[("closed",false,"block"),("open",false,"allow"),("closed",true,"allow")]{
   owner.execute("UPDATE system_config SET value=$1::text::jsonb WHERE key='ca_fail_mode'",&[&format!("\"{mode}\"")]).await?;
   owner.execute("UPDATE system_config SET value=$1::text::jsonb WHERE key='ca_break_glass_user_ids'",&[&if bg{format!("[{}]",a.user)}else{"[]".into()}]).await?;
   let engine=Engine::new(ScopedExecutor::from_dsn(&fault_dsn,2).map_err(|e|e.0)?);
   let r=engine.evaluate(Context{user_id:a.user,..Default::default()}).await;
   if r.decision!=expected{return Err(format!("mode={mode} break_glass={bg}: {r:?}").into());}
  }
  Ok::<_,BoxError>(())
 }.await;
    owner.batch_execute("DROP SCHEMA authzgates_policy_fault CASCADE; DELETE FROM system_config WHERE key IN ('ca_fail_mode','ca_break_glass_user_ids')").await?;
    for row in saved {
        owner.execute("INSERT INTO system_config SELECT * FROM jsonb_populate_record(NULL::system_config,$1::text::jsonb)",&[&row]).await?;
    }
    fixture::remove(&owner, &a).await?;
    result
}

#[tokio::test]
async fn missing_locations_fail_closed_even_when_condition_value_is_null() -> Result<(), BoxError> {
    use setjoin_conditional_access::policy::eval::Engine;
    let Some(db) = Db::for_case("authzgates-location-failure") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    // Private schema, without a public fallback: only the location read fails.
    // No global policy/config rows or authenticated identities are changed.
    owner.batch_execute("CREATE SCHEMA authzgates_location_fault;
        CREATE TABLE authzgates_location_fault.system_config(key text,value jsonb);
        CREATE TABLE authzgates_location_fault.conditional_access_policies(
            id bigint,priority integer,name text,state text,deleted_at timestamptz,
            scope_type text,conditions jsonb,actions jsonb);
        INSERT INTO authzgates_location_fault.conditional_access_policies VALUES
            (1,0,'first allow','on',NULL,'global','{\"location_in\":null}','{\"action\":\"allow\"}'),
            (2,1,'other enforcing policy','on',NULL,'global','{\"auth_method\":\"password\"}','{\"action\":\"block\"}');
        CREATE TABLE authzgates_location_fault.auth_strengths(id bigint);
        GRANT USAGE ON SCHEMA authzgates_location_fault TO setjoin_app;
        GRANT SELECT ON ALL TABLES IN SCHEMA authzgates_location_fault TO setjoin_app;").await?;
    let app = db.app.as_deref().unwrap_or(&db.dsn);
    let sep = if app.contains('?') { "&" } else { "?" };
    let dsn = format!("{app}{sep}options=-csearch_path%3Dauthzgates_location_fault%2Cpg_catalog");
    let engine = Engine::new(ScopedExecutor::from_dsn(&dsn, 2).map_err(|e| e.0)?);
    let actual = engine
        .evaluate(Context {
            auth_method: "jwt_bearer".into(),
            ..Default::default()
        })
        .await;
    owner
        .batch_execute("DROP SCHEMA authzgates_location_fault CASCADE")
        .await?;
    assert_eq!(
        (actual.decision.as_str(), actual.reason.as_str()),
        ("block", "eval error (fail closed)")
    );
    Ok(())
}
