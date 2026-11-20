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
        env.native.start_saml_listener().await
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
#[tokio::test]
async fn saml_login_refuses_a_deleted_idp_with_workers_off() {
    use std::os::unix::process::CommandExt;
    use std::process::{Child, Command};

    struct Owned(Child);
    impl Drop for Owned {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    let _serial = SERIAL.lock().await;
    let db = Db::for_case("IDFED3-saml").expect("assigned DB required");
    let env = flows::Env::start(false).await.unwrap();
    let result = async {
        let reservation = setjoin_conformance::ports::std_listener();
        let addr = reservation.local_addr()?;
        drop(reservation);
        let mut auth = Owned(
            Command::new(env!("CARGO_BIN_EXE_setjoin-auth"))
                .arg0("gofree-idfed3-saml-revocation")
                .env_remove("SETJOIN_CONFIG")
                .env("RUST_WORKERS_ON", "")
                .env("GO_WORKERS_OFF", "")
                .env("DB_DSN", &db.dsn)
                .env("DB_DIRECT_DSN", &db.direct)
                .env("DB_WORKER_DSN", &db.dsn)
                .env("DB_ENCRYPTION_KEY", flows::ENC)
                .env("LISTEN_ADDR", addr.to_string())
                .env_remove("TLS_CERT")
                .env_remove("TLS_KEY")
                .env("JWT_SECRET", flows::fixture()["secret"].as_str().unwrap())
                .env("JWT_SIGNING_ALG", "ES256")
                .env("CRYPTO_ALGORITHM_PROFILE", "standard")
                .env("OIDC_ENABLED", "false")
                .env("OIDC_PROVIDER_ENABLED", "false")
                .env("SAML_ENABLED", "true")
                .env("SAML_CERT_FILE", corpus().join("sp-cert.pem"))
                .env("SAML_KEY_FILE", corpus().join("sp-key.pem"))
                .spawn()?,
        );
        let path = "/auth/saml/idfed3/login";
        let seed = tokio::time::timeout(std::time::Duration::from_secs(15), async {
            loop {
                if auth.0.try_wait()?.is_some() {
                    return Err("auth exited before serving SAML".into());
                }
                if let Ok(response) = request(addr, "GET", path, String::new(), &[]).await {
                    return Ok::<_, Err>(response.0);
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await??;
        if seed != 302 {
            return Err(format!("configured SAML IdP returned {seed}, expected 302").into());
        }

        // The replacement identifies the snapshot that includes the deletion.
        let replaced = env.c.execute(
            "WITH removed AS (
                 DELETE FROM saml_sp_registrations WHERE id=34101
                 RETURNING idp_metadata_url,idp_sso_url,idp_cert_enc,sp_entity_id,sp_acs_url,group_mappings
             )
             INSERT INTO saml_sp_registrations(id,idp_entity_id,idp_metadata_url,idp_sso_url,idp_cert_enc,sp_entity_id,sp_acs_url,group_mappings)
             SELECT 34102,'idfed3-after-delete',idp_metadata_url,idp_sso_url,idp_cert_enc,sp_entity_id,sp_acs_url,group_mappings
             FROM removed",
            &[],
        ).await?;
        if replaced != 1 {
            return Err("SAML fixture registration was not deleted".into());
        }
        tokio::time::timeout(std::time::Duration::from_secs(12), async {
            loop {
                let response = request(
                    addr,
                    "GET",
                    "/auth/saml/idfed3-after-delete/login",
                    String::new(),
                    &[],
                )
                .await?;
                if response.0 == 302 {
                    return Ok::<(), Err>(());
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await
        .map_err(|_| "auth did not reload SAML after deletion")??;
        let refused = request(addr, "GET", path, String::new(), &[]).await?;
        Ok::<_, Err>((refused.0, refused.1.get("location").is_none()))
    }
    .await;
    env.close().await.unwrap();
    assert_eq!(result.unwrap(), (404, true));
}

#[tokio::test]
async fn saml_sp_go_json_field_folding() {
    let _serial = SERIAL.lock().await;
    let env = flows::Env::start(false).await.unwrap();
    let listener = if env.recording {
        None
    } else {
        env.native.start_saml_listener().await
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
