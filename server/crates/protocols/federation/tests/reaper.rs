//! Seed-plus-one-tick parity at the worker/DB seam, with immutable Go effects.
use setjoin_conformance::harness::Db;
use setjoin_federation::{db::WorkerPool, reap::Reaper};
use setjoin_pg::workers::WorkerDatabase;
use std::sync::Arc;

#[tokio::test]
async fn residue_reap_seed_plus_one_tick() {
    let Some(db) = Db::for_case("federation-residue-reap") else {
        return;
    };
    let owner = db.connect().await.unwrap();
    owner
        .batch_execute(include_str!("../oracle/reap-seed.sql"))
        .await
        .unwrap();
    Reaper::new(Arc::new(WorkerPool::new(
        WorkerDatabase::new(&db.dsn).unwrap(),
    )))
    .tick()
    .await
    .unwrap();
    let sql = format!(
        "{}::text",
        include_str!("../oracle/reap-observe.sql")
            .trim()
            .trim_end_matches(';')
    );
    let after: String = owner.query_one(&sql, &[]).await.unwrap().get(0);
    owner
        .batch_execute(include_str!("../oracle/reap-cleanup.sql"))
        .await
        .unwrap();
    let golden: serde_json::Value =
        serde_json::from_str(include_str!("../oracle/reap-go.json")).unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&after).unwrap(),
        golden["after"]
    );
}
