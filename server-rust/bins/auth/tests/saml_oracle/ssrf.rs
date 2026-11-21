//! Shared public discovery oracle, kept in the route replay binary for coverage.
use super::*;
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
    setjoin_conformance::golden::compare(&serde_json::from_slice(&std::fs::read(path)?)?, actual)?;
    if !record && actual.get("observation").is_some() {
        flows::qualified_compare(actual, false)?;
    }
    Ok(())
}
pub async fn run() {
    for host in ["127.0.0.1", "localhost"] {
        let _serial = SERIAL.lock().await;
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = tcp.local_addr().unwrap().port();
        let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = count.clone();
        let (stop, mut rx) = oneshot::channel::<()>();
        let task = tokio::spawn(async move {
            loop {
                tokio::select! {_=&mut rx=>break,accepted=tcp.accept()=>{let (_stream,_)=accepted.unwrap();counter.fetch_add(1,std::sync::atomic::Ordering::SeqCst);}}
            }
        });
        let env = flows::Env::start(false).await.unwrap();
        let listener = if env.recording {
            None
        } else {
            env.native.start_saml_listener().await
        };
        let result=async{
            let path = "/auth/saml/idfed3/login";
            let sentinel = "/auth/saml/idfed3-sentinel/login";
            wait(&env, path, 302).await?;
            // Commit both entries together so the listener reconciles one snapshot.
            env.c.execute(
                "WITH changed AS (
                     UPDATE saml_sp_registrations SET idp_metadata_url=$1 WHERE id=34101
                     RETURNING idp_sso_url,idp_cert_enc,sp_entity_id,sp_acs_url,group_mappings
                 )
                 INSERT INTO saml_sp_registrations(id,idp_entity_id,idp_metadata_url,idp_sso_url,idp_cert_enc,sp_entity_id,sp_acs_url,group_mappings)
                 SELECT 34102,'idfed3-sentinel',$2,idp_sso_url,idp_cert_enc,sp_entity_id,sp_acs_url,group_mappings FROM changed",
                &[&format!("https://{host}:{port}/metadata"), &flows::metadata("Redirect")],
            ).await?;
            let response = if env.recording {
                wait(&env, sentinel, 302).await?;
                observe(&env, path).await?
            } else {
                let response = wait(&env, path, 404).await?;
                if observe(&env, sentinel).await?["status"] != 404 {
                    return Err("failed SAML reload published a healthy registration".into());
                }
                env.c.execute("DELETE FROM saml_sp_registrations WHERE id=34101", &[]).await?;
                wait(&env, sentinel, 302).await?;
                response
            };
            let connections=count.load(std::sync::atomic::Ordering::SeqCst);
            if response["status"]!=404||connections!=0{return Err(format!("private metadata admitted: {response}, connections={connections}").into());}
            check(&format!("ssrf-{host}"),&json!({"format":1,"go_source":SOURCE,"route":"GET /auth/saml/{idp}/login","case":format!("ssrf-{host}"),"observation":{"request":{"method":"GET","path":"/auth/saml/idfed3/login","metadata_url":format!("https://{host}:_private_port/metadata")},"response":response,"effects":[],"audit":[],"notify":[],"private_tcp_connections":connections}}),env.recording)
        }.await;
        drop(listener);
        env.close().await.unwrap();
        let _ = stop.send(());
        task.await.unwrap();
        result.unwrap();
    }
}
