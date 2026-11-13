//! The same complete family registration used by the executable, over HTTP.
mod common;
use hyper::{Request, Response};
use serde_json::json;
use setjoin_conformance::{fixture, harness::Db};
use setjoin_gateway::{
    f16::{F16Config, F16Route},
    recovery_begin::ReceiptKeys,
    recovery_worker::S3Store,
    Config, Gateway, RouteTable, TrustedProxies,
};
use setjoin_pg::ScopedExecutor;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
#[tokio::test]
async fn every_f16_registration_dispatches_without_go() -> Result<(), common::BoxError> {
    run(false).await
}
#[tokio::test]
async fn family_kill_switch_forwards_the_same_requests_to_go() -> Result<(), common::BoxError> {
    run(true).await
}
async fn run(kill: bool) -> Result<(), common::BoxError> {
    let _serial = common::recovery::SERIAL.lock().await;
    let Some(db) = Db::for_case("f16-dispatch") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let a = fixture::account(&owner, "blobs1-dispatch").await?;
    let previous: Option<bool> = owner
        .query_opt(
            "SELECT enabled FROM feature_toggles WHERE key='feature.client_recovery_ingest'",
            &[],
        )
        .await?
        .map(|r| r.get(0));
    let result=async {
 owner.execute("INSERT INTO feature_toggles(key,enabled) VALUES('feature.client_recovery_ingest',true) ON CONFLICT(key) DO UPDATE SET enabled=true",&[]).await?;
 let s3=common::fake_upstream(|_|async{Response::new(common::full(""))}).await;
 let count=Arc::new(AtomicUsize::new(0));let hits=count.clone();let go=common::fake_upstream(move|mut r|{let hits=hits.clone();async move{use http_body_util::BodyExt;let body=r.body_mut().collect().await.unwrap().to_bytes();assert!(body.is_empty()||body=="{}");hits.fetch_add(1,Ordering::SeqCst);Response::builder().status(202).body(common::full("Go rollback")).unwrap()}}).await;
 let exec=ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn),4).map_err(|e|e.0)?;
 let route=F16Route::new(F16Config{exec,worker_exec:ScopedExecutor::from_dsn(&db.dsn,4).map_err(|e|e.0)?,keys:Arc::new(common::recovery_keys()),issuer:"mailserver".into(),denylist:None,store:Arc::new(S3Store::new(&format!("http://{s3}"),"mailblobs","test-access","test-secret")?),continuity:Some(Arc::new(ReceiptKeys::single("test",vec![0;32]))),scanner:None,attachment_secret:b"blobs1-test-jwt-secret-for-recording".to_vec(),attachment_previous_secret:None});
 let g=Gateway::new(Config{upstream:if kill{Some(format!("http://{go}").parse()?)}else{None},trusted_proxies:TrustedProxies::parse("")?,upstream_header_timeout:setjoin_gateway::proxy::DEFAULT_HEADER_TIMEOUT,edge_limit:None},RouteTable::proxy_all().with(route))?.with_inventory(include_str!("../route-inventory.json"))?.with_enabled(!kill);
 let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await?;let addr=listener.local_addr()?;let server=tokio::spawn(g.serve(listener));
 for(method,path,body,status)in[("GET","/mail-attachment/invalid","",401),("GET","/api/blobs/invalid","",404),("PUT","/api/blobs/invalid","",400),("GET","/api/recovery/incidents","",200),("POST","/api/recovery/uploads","{}",400),("PUT","/api/recovery/uploads/invalid/items/raw","",400),("POST","/api/recovery/uploads/invalid/items/raw/commit","",400),("POST","/api/recovery/uploads/invalid/finalize","",400),("DELETE","/api/recovery/uploads/invalid","",400),("POST","/api/recovery/artifacts/invalid/fork-consent","{}",400)]{
 let response=common::send(addr,Request::builder().method(method).uri(path).header("host","mail.test").header("origin","http://mail.test").header("authorization",format!("Bearer {}",if path.starts_with("/mail-attachment/"){attachment_token(a.user)}else{common::recovery_token(a.user)})).body(common::full(body))?).await;
 let actual=response.status().as_u16();let bytes=common::body_bytes(response).await;if actual!=if kill{202}else{status}{server.abort();return Err(format!("{method} {path}: {actual} {bytes:?}").into());}
 }
 if !kill{let response=common::send(addr,Request::get("/_gateway/metrics").body(common::full(""))?).await;let metrics=String::from_utf8(common::body_bytes(response).await.to_vec())?;if !metrics.contains("setjoin_gateway_proxied_to_go_total 0"){return Err(format!("native calls reached Go: {metrics}").into());}}
 server.abort();assert_eq!(count.load(Ordering::SeqCst),if kill{10}else{0});Ok::<_,common::BoxError>(())
 }.await;
    common::remove_blob_account(&owner, &a).await?;
    if let Some(v) = previous {
        owner
            .execute(
                "UPDATE feature_toggles SET enabled=$1 WHERE key='feature.client_recovery_ingest'",
                &[&v],
            )
            .await?;
    } else {
        owner
            .execute(
                "DELETE FROM feature_toggles WHERE key='feature.client_recovery_ingest'",
                &[],
            )
            .await?;
    }
    result
}

fn attachment_token(user: i64) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let token = common::recovery_token(user);
    let payload = token.split('.').nth(1).unwrap();
    let mut claims: serde_json::Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap();
    claims["scp"] = json!("mail-attachment");
    claims["attachment"] = json!({"sha256":"a".repeat(64)});
    let h = URL_SAFE_NO_PAD.encode(r#"{"alg":"HS256","kid":"mailserver-mail-attachment-1"}"#);
    let p = URL_SAFE_NO_PAD.encode(claims.to_string());
    let mut extract =
        Hmac::<Sha256>::new_from_slice(b"mailserver-mail-attachment-token-v1").unwrap();
    extract.update(b"blobs1-test-jwt-secret-for-recording");
    let mut expand = Hmac::<Sha256>::new_from_slice(&extract.finalize().into_bytes()).unwrap();
    expand.update(&[1]);
    let mut sign = Hmac::<Sha256>::new_from_slice(&expand.finalize().into_bytes()).unwrap();
    sign.update(format!("{h}.{p}").as_bytes());
    format!(
        "{h}.{p}.{}",
        URL_SAFE_NO_PAD.encode(sign.finalize().into_bytes())
    )
}
