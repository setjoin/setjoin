//! Frozen Go cache-task seed/tick and private-network discovery seam.
mod common;
include!("saml_oracle/harness.rs");
#[path = "saml_oracle/flows.rs"]
mod flows;
async fn observe(env: &flows::Env, path: &str) -> Result<Value, Err> {
    let response = request(env.gw.addr, "GET", path, String::new(), &[]).await?;
    flows::normalize(response)
}
async fn wait(env: &flows::Env, path: &str, status: u16) -> Result<Value, Err> {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(12);
    loop {
        let value = observe(env, path).await?;
        if value["status"] == status {
            return Ok(value);
        }
        if tokio::time::Instant::now() > deadline {
            return Err(format!("cache tick never reached {status}: {value}").into());
        }
        tokio::time::sleep(std::time::Duration::from_millis(2000)).await;
    }
}
fn check(name: &str, actual: &Value, record: bool) -> Result<(), Err> {
    let path = corpus().join(format!("{name}.json"));
    if record && !path.exists() {
        setjoin_conformance::golden::record(&path, actual)?;
    }
    setjoin_conformance::golden::compare(&flows::expected_for(&path, actual)?, actual)?;
    if !record && actual.get("observation").is_some() {
        flows::qualified_compare(actual, false)?;
    }
    Ok(())
}
#[tokio::test]
async fn saml_sp_seed_and_tick() {
    let _serial = SERIAL.lock().await;
    let env = flows::Env::start(false).await.unwrap();
    let listener = if env.recording {
        None
    } else {
        env.native
            .start_saml_listener("saml_sp", "saml_sp")
            .await
            .unwrap()
    };
    let result=async{
        let seed=observe(&env,"/auth/saml/idfed3/login").await?;
        env.c.execute("UPDATE saml_sp_registrations SET enabled=false WHERE id=34101",&[]).await?;
        env.c.execute("SELECT pg_notify('config_changed','{\"key\":\"saml_sp\"}')",&[]).await?;
        let tick=wait(&env,"/auth/saml/idfed3/login",404).await?;
        check("worker",&json!({"format":1,"go_source":SOURCE,"worker":"saml_sp","seed":seed,"tick":tick,"effects":[],"audit":[],"notify":[]}),env.recording)
    }.await;
    drop(listener);
    env.close().await.unwrap();
    result.unwrap();
}
#[test]
fn saml_sp_requires_go_retirement() {
    use std::os::unix::process::CommandExt;
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_setjoin-auth"))
        .arg0("gofree-idfed3-worker-guard")
        .env("RUST_WORKERS_ON", "saml_sp")
        .env_remove("GO_WORKERS_OFF")
        .env_remove("SETJOIN_CONFIG")
        .env("JWT_SECRET", flows::fixture()["secret"].as_str().unwrap())
        .env("DB_DSN", "invalid")
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("GO_WORKERS_OFF=saml_sp"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[tokio::test]
async fn library_worker_transfer_guard() {
    let _serial = SERIAL.lock().await;
    let env = flows::Env::start(false).await.unwrap();
    assert!(env
        .native
        .start_saml_listener("saml_sp-other", "saml_sp")
        .await
        .unwrap()
        .is_none());
    assert!(env.native.start_saml_listener("saml_sp", "").await.is_err());
    let task = env
        .native
        .start_saml_listener(" oidc_rp, saml_sp ", "other, saml_sp")
        .await
        .unwrap();
    assert!(task.is_some());
    drop(task);
    env.close().await.unwrap();
}

#[tokio::test]
async fn saml_sp_go_json_field_folding() {
    let _serial = SERIAL.lock().await;
    let env = flows::Env::start(false).await.unwrap();
    let listener = if env.recording {
        None
    } else {
        env.native
            .start_saml_listener("saml_sp", "saml_sp")
            .await
            .unwrap()
    };
    let result=async{
        env.c.batch_execute("BEGIN;SET LOCAL session_replication_role=replica;UPDATE saml_sp_registrations SET enabled=false WHERE id=34101;COMMIT").await?;
        env.c.execute("SELECT pg_notify('config_changed','{\"KeY\":\"saml_sp\"}')",&[]).await?;
        let disabled=wait(&env,"/auth/saml/idfed3/login",404).await?;
        env.c.execute("UPDATE saml_sp_registrations SET enabled=true,group_mappings='[{\"IDP_GROUP\":\"team\"}]'::jsonb WHERE id=34101",&[]).await?;
        env.c.execute("SELECT pg_notify('config_changed','{\"key\":\"auth_methods\"}')",&[]).await?;
        let enabled=wait(&env,"/auth/saml/idfed3/login",302).await?;
        check("worker-go-json",&json!({"format":1,"go_source":SOURCE,"worker":"saml_sp","disabled":disabled,"enabled":enabled,"effects":[],"audit":[],"notify":[]}),env.recording)
    }.await;
    drop(listener);
    env.close().await.unwrap();
    result.unwrap();
}
