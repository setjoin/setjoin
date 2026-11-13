//! OIDC RP public HTTP seam through the real front door; frozen-Go captures.
mod common;
include!("rp_oracle/harness.rs");
#[path = "rp_oracle/flows.rs"]
mod flows;
#[path = "rp_oracle/idp.rs"]
mod idp;

#[tokio::test]
async fn enabled_rp_rejects_unknown_provider_without_go() {
    use std::os::unix::process::CommandExt;
    if std::env::var_os("IDFED2_CONFIG_PROBE").is_none() {
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .arg0("gofree-idfed2-config-probe")
            .args([
                "--exact",
                "enabled_rp_rejects_unknown_provider_without_go",
                "--nocapture",
            ])
            .env("IDFED2_CONFIG_PROBE", "1")
            .env_remove("SETJOIN_CONFIG")
            .env("OIDC_ENABLED", "true")
            .env("JWT_SECRET", fixture()["secret"].as_str().unwrap())
            .env("CRYPTO_ALGORITHM_PROFILE", "standard")
            .env_remove("AUTH_GO_UPSTREAM")
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        return;
    }
    let db = Db::for_case("IDFED2-rp").expect("assigned DB required");
    let c = db.connect().await.unwrap();
    c.query_one(
        "SELECT pg_advisory_lock(hashtextextended('gofree-idlogin1-oracle',0))",
        &[],
    )
    .await
    .unwrap();
    common::signing_key(&c).await;
    let config = Config::from_env().unwrap();
    let auth = AuthServer::load(
        setjoin_pg::ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn), 4).unwrap(),
        config,
    )
    .await
    .unwrap();
    let r = auth
        .handle(
            Request::builder()
                .uri("/auth/oidc/login?provider=missing")
                .body(body(""))
                .unwrap(),
        )
        .await;
    assert_eq!(r.status(), 400);
    let bytes = r.into_body().collect().await.unwrap().to_bytes();
    assert!(String::from_utf8_lossy(&bytes).contains("unknown OIDC provider"));
}
fn fixture() -> Value {
    serde_json::from_str(include_str!(
        "../../../tests/conformance/identity-login/keys.json"
    ))
    .unwrap()
}

#[tokio::test]
async fn login_success() {
    flows::login("success", false).await.unwrap();
}

#[tokio::test]
async fn login_cross_tenant() {
    flows::login("cross-tenant", false).await.unwrap();
}
#[tokio::test]
async fn login_invalid_input() {
    flows::login("invalid-input", false).await.unwrap();
}
#[tokio::test]
async fn login_head() {
    flows::login("head", false).await.unwrap();
}
#[tokio::test]
async fn login_status_mutant() {
    flows::login("success", true).await.unwrap();
}
#[tokio::test]
async fn callback_invalid_input() {
    flows::callback_guard("invalid-input").await.unwrap();
}

#[tokio::test]
async fn callback_verifier_guards() {
    for kind in ["missing-verifier", "bad-verifier"] {
        flows::callback_guard(kind).await.unwrap();
    }
}

#[tokio::test]
async fn callback_provider_guards() {
    for kind in ["missing-provider", "unknown-provider", "redirect-mismatch"] {
        flows::callback_guard(kind).await.unwrap();
    }
}
#[tokio::test]
async fn callback_unverified_email() {
    flows::token_claims("unverified-email").await.unwrap();
}

#[tokio::test]
async fn callback_pkce_mismatch() {
    flows::token_claims("pkce-mismatch").await.unwrap();
}

#[tokio::test]
async fn callback_id_token_checks() {
    for kind in [
        "bad-nonce",
        "missing-nonce-cookie",
        "bad-signature",
        "bad-issuer",
        "bad-audience",
        "multi-audience-no-azp",
        "multi-audience-azp",
        "bad-azp",
        "expired",
        "future-iat",
        "bad-at-hash",
        "valid-at-hash",
    ] {
        flows::token_claims(kind).await.unwrap();
    }
}

#[tokio::test]
async fn callback_verified_assertion_guards() {
    for kind in ["no-email", "invalid-groups", "unknown-user"] {
        flows::token_claims(kind).await.unwrap();
    }
}

#[path = "rp_oracle/settlement.rs"]
mod settlement;
#[tokio::test]
async fn callback_success() {
    settlement::run("success").await.unwrap();
}

#[tokio::test]
async fn rp_ssrf_private_issuer() {
    for host in ["127.0.0.1", "localhost"] {
        let _serial = SERIAL.lock().await;
        let listener = TcpListener::bind("127.0.0.1:19442").await.unwrap();
        let hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = hits.clone();
        let (stop, rx) = oneshot::channel();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            tokio::pin!(rx);
            loop {
                tokio::select! {_=&mut rx=>break,accepted=listener.accept()=>{let (_stream,_)=accepted.unwrap();counter.fetch_add(1,std::sync::atomic::Ordering::SeqCst);}}
            }
        });
        let peer = Server {
            stop: Some(stop),
            task,
            addr,
        };
        let env = flows::Env::issuer(false, &format!("https://{host}:19442"))
            .await
            .unwrap();
        let result=async{
            let response=request(env.gw.addr,"GET","/auth/oidc/login?provider=idfed2",String::new(),&[]).await?;
            let count=hits.load(std::sync::atomic::Ordering::SeqCst);
            let actual=json!({"format":1,"go_source":SOURCE,"route":"GET /auth/oidc/login","case":format!("ssrf-{host}"),"observation":{"request":{"method":"GET","path":"/auth/oidc/login","query":"provider=idfed2"},"response":{"status":response.0,"headers":response.1,"body":response.2},"effects":[],"audit":[],"notify":[],"private_tcp_connections":count}});
            let path=corpus().join("goldens").join(format!("ssrf-{host}.json"));
            if env.recording&&!path.exists(){setjoin_conformance::golden::record(&path,&actual)?;}
            let expected:Value=serde_json::from_slice(&std::fs::read(path)?)?;
            setjoin_conformance::golden::compare(&expected,&actual)?;
            if count!=0||response.0!=400{return Err("private issuer reached network or survived reload".into());}
            observation::replay(&actual,env.recording)?;
            Ok::<(),Err>(())
        }.await;
        env.close().await.unwrap();
        peer.close().await;
        result.unwrap();
    }
}

#[tokio::test]
async fn callback_account_guards() {
    for kind in [
        "cross-tenant",
        "address-collision",
        "disabled",
        "profile-invalid",
        "profile-conflict",
    ] {
        settlement::run(kind).await.unwrap();
    }
}

#[tokio::test]
async fn oidc_rp_worker_seed_and_tick() {
    let _serial = SERIAL.lock().await;
    let env = flows::Env::start(false).await.unwrap();
    let result=async{
        let seed=request(env.gw.addr,"GET","/auth/oidc/login?provider=idfed2",String::new(),&[]).await?;
        let (seed,_)=flows::normalize_flow(seed)?;
        env.c.execute("UPDATE system_config SET value=jsonb_set(value,'{enabled}','false'::jsonb) WHERE key='oidc_provider_idfed2_config'",&[]).await?;
        let deadline=tokio::time::Instant::now()+std::time::Duration::from_secs(5);
        let tick=loop{
            let response=request(env.gw.addr,"GET","/auth/oidc/login?provider=idfed2",String::new(),&[]).await?;
            if response.0==400||tokio::time::Instant::now()>deadline{break response;}
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        };
        let (tick,_)=flows::normalize_flow(tick)?;
        let actual=json!({"format":1,"go_source":SOURCE,"worker":"oidc_rp","seed":seed,"tick":tick,"effects":[],"audit":[],"notify":[]});
        let path=corpus().join("worker.json");
        if env.recording&&!path.exists(){setjoin_conformance::golden::record(&path,&actual)?;}
        let expected=observation::expected_for(&path,&actual)?;
        setjoin_conformance::golden::compare(&expected,&actual)?;
        Ok::<(),Err>(())
    }.await;
    env.close().await.unwrap();
    result.unwrap();
}
#[test]
fn oidc_rp_worker_requires_go_retirement() {
    use std::os::unix::process::CommandExt;
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_setjoin-auth"))
        .arg0("gofree-idfed2-worker-guard")
        .env("RUST_WORKERS_ON", "oidc_rp")
        .env_remove("GO_WORKERS_OFF")
        .env_remove("SETJOIN_CONFIG")
        .env("JWT_SECRET", fixture()["secret"].as_str().unwrap())
        .env("DB_DSN", "invalid")
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("GO_WORKERS_OFF=oidc_rp"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[tokio::test]
async fn callback_profile_update() {
    settlement::run("jit").await.unwrap();
}

#[tokio::test]
async fn callback_group_mappings() {
    for kind in [
        "groups-first",
        "groups-failure",
        "groups-remove",
        "groups-absent",
    ] {
        settlement::run(kind).await.unwrap();
    }
}

#[tokio::test]
async fn callback_jit_create() {
    settlement::run("jit-create").await.unwrap();
}

#[tokio::test]
async fn callback_normalized_identity() {
    for kind in ["normalized", "normalized-stale"] {
        settlement::run(kind).await.unwrap();
    }
}

#[path = "rp_oracle/link.rs"]
mod link;
#[tokio::test]
async fn link_success() {
    link::begin("success").await.unwrap();
}
#[tokio::test]
async fn link_cross_tenant() {
    link::begin("cross-tenant").await.unwrap();
}
#[tokio::test]
async fn link_invalid_input() {
    link::begin("invalid-input").await.unwrap();
}
#[tokio::test]
async fn link_no_session() {
    link::begin("no-session").await.unwrap();
}
#[tokio::test]
async fn callback_explicit_link() {
    for kind in [
        "success",
        "cross-session",
        "no-session",
        "inactive-session",
        "bad-flow",
        "mapping-failure",
        "replay",
        "revoked-elevation",
        "foreign-subject",
    ] {
        link::callback(kind).await.unwrap();
    }
}

#[tokio::test]
async fn callback_cross_tenant() {
    settlement::run("cross-tenant").await.unwrap();
}
#[tokio::test]
async fn callback_repeat() {
    settlement::run("repeat").await.unwrap();
}
#[tokio::test]
async fn link_repeat() {
    link::begin("repeat").await.unwrap();
}
#[tokio::test]
async fn callback_status_mutant() {
    settlement::run_variant("success", true).await.unwrap();
}
#[tokio::test]
async fn link_status_mutant() {
    link::begin_variant("success", true).await.unwrap();
}
#[path = "rp_oracle/mux.rs"]
mod mux;
#[tokio::test]
async fn alias_success() {
    mux::run("alias", "success", false).await.unwrap();
}
#[tokio::test]
async fn alias_cross_tenant() {
    mux::run("alias", "cross-tenant", false).await.unwrap();
}
#[tokio::test]
async fn alias_invalid_input() {
    mux::run("alias", "invalid-input", false).await.unwrap();
}
#[tokio::test]
async fn alias_head() {
    mux::run("alias", "head", false).await.unwrap();
}
#[tokio::test]
async fn alias_status_mutant() {
    mux::run("alias", "success", true).await.unwrap();
}
#[tokio::test]
async fn mux_success() {
    mux::run("mux", "success", false).await.unwrap();
}
#[tokio::test]
async fn mux_cross_tenant() {
    mux::run("mux", "cross-tenant", false).await.unwrap();
}
#[tokio::test]
async fn mux_invalid_input() {
    mux::run("mux", "invalid-input", false).await.unwrap();
}
#[tokio::test]
async fn mux_status_mutant() {
    mux::run("mux", "success", true).await.unwrap();
}
#[path = "rp_oracle/observation.rs"]
mod observation;

#[tokio::test]
async fn callback_client_secret() {
    flows::token_claims("client-secret").await.unwrap();
}
