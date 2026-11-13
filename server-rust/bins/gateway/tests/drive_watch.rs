//! #276 drive-watch worker: frozen-Go seed + one `drive` NOTIFY tick, then the
//! per-watcher `drive-watch:<uid>` pushes. Replay runs the Rust worker with Go
//! unset; recording runs only Go's `drive-watch` worker (others are off).
mod common;
use common::BoxError;
use serde_json::{json, Value};
use setjoin_conformance::{fixture as accounts, golden, harness::Db};
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[tokio::test]
async fn drive_watch_change() -> Result<(), BoxError> {
    run("change").await
}
#[tokio::test]
async fn drive_watch_lock() -> Result<(), BoxError> {
    run("lock").await
}
#[tokio::test]
async fn drive_watch_dedupe() -> Result<(), BoxError> {
    run("dedupe").await
}
#[tokio::test]
async fn drive_watch_malformed() -> Result<(), BoxError> {
    run("malformed").await
}

async fn run(case: &str) -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("drive-watch") else {
        return Ok(());
    };
    let c = db.connect().await?;
    let owner = accounts::account(&c, "dwatch-owner").await?;
    let peer = accounts::account(&c, "dwatch-peer").await?;
    let outsider = accounts::account(&c, "dwatch-outsider").await?;
    for a in [&peer, &outsider] {
        c.execute(
            "UPDATE users SET domain_id=$2 WHERE id=$1",
            &[&a.user, &owner.domain],
        )
        .await?;
        c.execute(
            "UPDATE mailboxes SET domain_id=$2 WHERE id=$1",
            &[&a.mailbox, &owner.domain],
        )
        .await?;
    }
    let toggles = c
        .query(
            "SELECT key,enabled FROM feature_toggles WHERE key='feature.drive'",
            &[],
        )
        .await?;
    c.execute(
        "UPDATE feature_toggles SET enabled=true WHERE key='feature.drive'",
        &[],
    )
    .await?;
    let space: i64 = c
        .query_one(
            "SELECT drive_space_create($1,'Watch','regular')",
            &[&owner.user],
        )
        .await?
        .get(0);
    let root: i64 = c
        .query_one(
            "SELECT drive_node_create($1,$2,NULL,'folder','Root')",
            &[&owner.user, &space],
        )
        .await?
        .get(0);
    c.query_one(
        "SELECT drive_member_grant($1,$2,$3,'editor')",
        &[&owner.user, &space, &peer.user],
    )
    .await?;
    c.query_one(
        "SELECT drive_watch_set($1,$2,ARRAY['create','lock'])",
        &[&owner.user, &root],
    )
    .await?;
    c.query_one("SELECT drive_watch_set($1,$2,NULL)", &[&peer.user, &root])
        .await?;
    // A watch row that outlived its membership: it must receive nothing.
    c.execute(
        "INSERT INTO drive_watches(node_id,user_id,ops) VALUES($1,$2,NULL)",
        &[&root, &outsider.user],
    )
    .await?;
    let result = async {
        let endpoint = common::fake_upstream(|_| async { hyper::Response::new(common::full("")) }).await;
        let oracle = common::go_oracle::start_named(&db, endpoint, None, "gofree-drive4-watch").await?;
        let recording = oracle.is_some();
        let mut task = None;
        if !recording {
            let direct = format!("{}{}application_name=gofree-drive4-watch-listener", db.dsn, if db.dsn.contains('?') { "&" } else { "?" });
            let worker = setjoin_drive::watch::DriveWatch::new(db.dsn.clone());
            let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
            let handle = tokio::spawn(worker.run_until(direct, async move {
                let _ = stopped.await;
            }));
            task = Some((stop, handle));
            let mut ready = false;
            for _ in 0..100 {
                ready = c.query_one("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND application_name='gofree-drive4-watch-listener' AND query LIKE 'LISTEN%')", &[]).await?.get(0);
                if ready {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            if !ready {
                return Err("drive-watch listener did not become ready".into());
            }
        }
        let mut listeners = vec![];
        for a in [&owner, &peer, &outsider] {
            listeners.push(db.listen(&format!("drive-watch:{}", a.user)).await?);
        }
        let lock = json!({"spaceId":space,"kind":"lock","nodeId":root}).to_string();
        match case {
            "change" => {
                c.query_one("SELECT drive_node_create($1,$2,$3,'file','new.txt')", &[&owner.user, &space, &root]).await?;
            }
            "lock" => {
                c.execute("SELECT pg_notify('drive',$1)", &[&lock]).await?;
            }
            "dedupe" => {
                c.execute("SELECT pg_notify('drive',$1)", &[&lock]).await?;
                tokio::time::sleep(std::time::Duration::from_millis(300)).await;
                c.execute("SELECT pg_notify('drive',$1)", &[&lock]).await?;
            }
            _ => {
                c.execute("SELECT pg_notify('drive','not json')", &[]).await?;
            }
        }
        tokio::time::sleep(std::time::Duration::from_secs(if case == "malformed" { 1 } else { 2 })).await;
        let mut pushes = serde_json::Map::new();
        for (label, a, l) in [("owner", &owner, 0), ("peer", &peer, 1), ("outsider", &outsider, 2)] {
            let mut items = vec![];
            for payload in listeners[l].drain(&c).await? {
                let mut v: Value = serde_json::from_str(&payload)?;
                if v["nodeId"] == json!(root) {
                    v["nodeId"] = json!("<root>");
                } else {
                    v["nodeId"] = json!("<created>");
                }
                v["spaceId"] = json!("<space>");
                items.push(v);
            }
            let _ = a;
            pushes.insert(label.into(), json!(items));
        }
        if let Some((stop, handle)) = task {
            let _ = stop.send(());
            tokio::time::timeout(std::time::Duration::from_secs(3), handle).await??;
        }
        let observed = json!({"pushes":pushes});
        let file = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!("../../tests/conformance/drive-c/goldens/worker-watch-{case}.json"));
        if recording {
            golden::record(&file, &json!({"format":1,"worker":"drive-watch","case":format!("seed-one-tick-{case}"),"go_source":std::env::var("GOFREE_GO_SOURCE")?,"observation":observed}))?;
        } else {
            let expected: Value = serde_json::from_slice(&std::fs::read(file)?)?;
            golden::compare(&expected["observation"], &observed)?;
            println!("GOLDEN-REPLAY: worker drive-watch :: {case}");
        }
        Ok::<_, BoxError>(())
    }
    .await;
    c.execute("DELETE FROM drive_nodes WHERE space_id=$1", &[&space])
        .await?;
    c.batch_execute(&format!("BEGIN; SET LOCAL session_replication_role=replica; DELETE FROM drive_audit_log WHERE space_id={space}; COMMIT;")).await?;
    c.execute(
        "DELETE FROM drive_spaces WHERE owner_user_id=$1",
        &[&owner.user],
    )
    .await?;
    for t in toggles {
        c.execute(
            "UPDATE feature_toggles SET enabled=$2 WHERE key=$1",
            &[&t.get::<_, String>(0), &t.get::<_, bool>(1)],
        )
        .await?;
    }
    for a in [&peer, &outsider, &owner] {
        accounts::remove(&c, a).await?;
    }
    result
}
