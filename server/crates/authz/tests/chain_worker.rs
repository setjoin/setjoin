//! Public chain admission and actual direct LISTEN, replayed without Go.
use serde_json::{json, Value};
use setjoin_authz::auth_chain::Chain;
use setjoin_conformance::{golden, harness::Db};
use std::{sync::Arc, time::Duration};
async fn point(chain: &Chain, name: &str, want: bool) -> Value {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
    while chain.basic_allowed() != want {
        assert!(
            tokio::time::Instant::now() < deadline,
            "{name}: admission never became {want}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    json!({"event":name,"basic_allowed":chain.basic_allowed()})
}
#[tokio::test]
async fn chain_reloads_notifications_and_repairs_missed_changes() {
    let db = Db::for_case("IDLOGIN3-chain").unwrap();
    let c = db.connect().await.unwrap();
    c.query_one(
        "SELECT pg_advisory_lock(hashtextextended('gofree-idlogin1-oracle',0))",
        &[],
    )
    .await
    .unwrap();
    let old = c
        .query_opt(
            "SELECT enabled FROM feature_toggles WHERE key='feature.disable_basic_auth'",
            &[],
        )
        .await
        .unwrap()
        .map(|r| r.get::<_, bool>(0));
    c.execute("INSERT INTO feature_toggles(key,enabled) VALUES('feature.disable_basic_auth',true) ON CONFLICT(key) DO UPDATE SET enabled=true",&[]).await.unwrap();
    let chain = Arc::new(Chain::default());
    let exec =
        setjoin_pg::ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn), 2).unwrap();
    chain.reload(&exec).await.unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(chain.clone().listen(
        exec.clone(),
        format!("{}?application_name=gofree-idlogin3-chain-rust", db.direct),
        rx,
    ));
    let result=std::panic::AssertUnwindSafe(async {
  let mut trace=vec![point(&chain,"startup-disabled",false).await];
  for(name,on,want)in[("notify-enable",false,true),("notify-disable",true,false)]{
   c.execute("UPDATE feature_toggles SET enabled=$1 WHERE key='feature.disable_basic_auth'",&[&on]).await.unwrap();trace.push(point(&chain,name,want).await);
  }
  c.execute("DELETE FROM feature_toggles WHERE key='feature.disable_basic_auth'",&[]).await.unwrap();
  c.execute("SELECT pg_notify('config_changed','{}')",&[]).await.unwrap();chain.reload(&exec).await.unwrap();trace.push(point(&chain,"missing-toggle",false).await);
  c.execute("INSERT INTO feature_toggles(key,enabled) VALUES('feature.disable_basic_auth',false)",&[]).await.unwrap();trace.push(point(&chain,"notify-restore",true).await);
  c.execute("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname=current_database() AND application_name='gofree-idlogin3-chain-rust'",&[]).await.unwrap();
  c.execute("UPDATE feature_toggles SET enabled=true WHERE key='feature.disable_basic_auth'",&[]).await.unwrap();trace.push(point(&chain,"reconnect-authority",false).await);
  // Wait for reconnect before committing the next notification.
  let deadline=tokio::time::Instant::now()+Duration::from_secs(8);loop{let n:i64=c.query_one("SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND application_name='gofree-idlogin3-chain-rust'",&[]).await.unwrap().get(0);if n>0{break}assert!(tokio::time::Instant::now()<deadline);tokio::time::sleep(Duration::from_millis(20)).await;}
  c.execute("UPDATE feature_toggles SET enabled=false WHERE key='feature.disable_basic_auth'",&[]).await.unwrap();trace.push(point(&chain,"post-reconnect-notify",true).await);
  let broken=setjoin_pg::ScopedExecutor::from_dsn(&format!("{}?options=-csearch_path%3Dpg_catalog",db.dsn),1).unwrap();
  assert!(chain.reload(&broken).await.is_err());trace.push(point(&chain,"query-failure",false).await);
  let expected:Value=serde_json::from_str(&std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/conformance/identity-token/goldens/chain-worker.json")).unwrap()).unwrap();
  let actual=json!({"format":1,"go_source":"d431c0ecdbb362809c3fdba781a395712612bf61","worker":"auth-chain-reload","trace":trace});golden::compare(&expected,&actual).unwrap();
  chain.reload(&exec).await.unwrap();assert!(chain.basic_allowed());
  let address=setjoin_conformance::ports::address();
  let(failed_stop,failed_rx)=tokio::sync::oneshot::channel();
  let failed=tokio::spawn(chain.clone().listen(exec.clone(),format!("postgres://postgres:gofree@{address}/gofree_e2e_idlogin3"),failed_rx));
  let deadline=tokio::time::Instant::now()+Duration::from_secs(2);while chain.basic_allowed()&&tokio::time::Instant::now()<deadline{tokio::time::sleep(Duration::from_millis(20)).await;}
  let allowed=chain.basic_allowed();let _=failed_stop.send(());failed.await.unwrap();assert!(!allowed,"failed initial subscription retained password authority");
  let initial:Value=serde_json::from_str(&std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/conformance/identity-token/goldens/chain-initial-worker.json")).unwrap()).unwrap();
  assert_eq!(initial["trace"].as_array().unwrap().last().unwrap(),&json!({"event":"initial-subscription-failure","basic_allowed":allowed}));
 }).catch_unwind().await;
    let _ = tx.send(());
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap();
    if let Some(on) = old {
        c.execute(
            "UPDATE feature_toggles SET enabled=$1 WHERE key='feature.disable_basic_auth'",
            &[&on],
        )
        .await
        .unwrap();
    } else {
        c.execute(
            "DELETE FROM feature_toggles WHERE key='feature.disable_basic_auth'",
            &[],
        )
        .await
        .unwrap();
    }
    if let Err(p) = result {
        std::panic::resume_unwind(p)
    }
}
use futures_util::FutureExt;
