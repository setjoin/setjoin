mod common;
use common::*;
use serde_json::Value;
use setjoin_imap::{Server, ThreatPolicy, WebhookPolicy};
use setjoin_threat::{Config, Gate};
use std::sync::Arc;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    sync::watch,
};
#[tokio::test]
async fn login_and_authenticate_replay_go_policy_and_outcome_effects() {
    replay("go-effects.json", false).await;
}
#[tokio::test]
async fn initial_response_extension_replays_go_without_advertising_sasl_ir() {
    replay("go.json", false).await;
}
async fn replay(corpus_name: &str, mutant: bool) {
    let db = setjoin_conformance::harness::Db::for_case("AUTHRT-IMAP").unwrap();
    let owner = db.connect().await.unwrap();
    seed(&owner).await;
    let hashes: Value =
        serde_json::from_str(include_str!("../oracle/password-hashes.json")).unwrap();
    let corpus: Value = serde_json::from_str(
        &std::fs::read_to_string(format!(
            "{}/oracle/threat/{corpus_name}",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap(),
    )
    .unwrap();
    for case in corpus.as_array().unwrap() {
        owner
            .batch_execute(include_str!("../oracle/threat/reset.sql"))
            .await
            .unwrap();
        reset_fixture(&owner, &hashes).await;
        let name = case["name"].as_str().unwrap();
        let sql=match name{
   "feed"=>"INSERT INTO threat_feed_blocks(cidr,source) VALUES('127.0.0.1/32','authrt')",
   "ip"=>"INSERT INTO ip_rules(cidr,action,description) VALUES('127.0.0.1/32','block','authrt')",
   "lockout"=>"INSERT INTO auth_lockouts(lockout_key,locked_until) VALUES('user:alice@imap1.test',now()+interval '800 milliseconds')",
   "device_country_null"=>"INSERT INTO device_registry(user_id,device_hash,user_agent,ip_prefix,country,auth_count) VALUES(9343011,encode(sha256('|127.0.0.0'::bytea),'hex'),'','127.0.0.0',NULL,1)",
   "rate"=>"INSERT INTO rate_limit_counters(key,count,window_start) VALUES('auth:imap:127.0.0.1',20,now())",
   "policy"=>r#"INSERT INTO conditional_access_policies(id,name,priority,state,scope_type,scope_target,conditions,actions) VALUES(9420420,'authrt',9420,'on','user','9343011','{}','{"action":"block"}')"#,
   _=>"SELECT 1",
  };
        owner.batch_execute(sql).await.unwrap();
        let mut config = Config::default();
        for k in [
            "geo_block",
            "spray_detect",
            "captcha",
            "tarpit",
            "rate_limit",
            "conditional_access",
        ] {
            config.overrides.insert(format!("feature.{k}"), false);
        }
        config
            .overrides
            .insert("feature.threat_feed".into(), !(mutant && name == "feed"));
        config
            .overrides
            .insert("feature.rate_limit".into(), name == "rate");
        config
            .overrides
            .insert("feature.conditional_access".into(), name == "policy");
        let gate = Gate::load(
            executor(&db),
            setjoin_threat::WorkerPools::from_dsn(&db.dsn).unwrap(),
            config,
            None,
        )
        .await
        .unwrap();
        let server = Server::new(
            executor(&db),
            ThreatPolicy::Enforced(gate),
            WebhookPolicy::Unwired,
        )
        .with_tls(tls_server());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (stop, rx) = watch::channel(false);
        let task = tokio::spawn(Arc::new(server).serve(listener, rx));
        let mut peer =
            BufReader::new(tls_client(tokio::net::TcpStream::connect(addr).await.unwrap()).await);
        let mut greeting = String::new();
        peer.read_line(&mut greeting).await.unwrap();
        peer.write_all(case["request"].as_str().unwrap().as_bytes())
            .await
            .unwrap();
        if case["method"] == "AUTHENTICATE" && case["payload"].is_string() {
            let mut continuation = String::new();
            peer.read_line(&mut continuation).await.unwrap();
            assert_eq!(continuation, case["continuation"]);
            peer.write_all(case["payload"].as_str().unwrap().as_bytes())
                .await
                .unwrap();
        }
        let mut reply = String::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(20),
            peer.read_line(&mut reply),
        )
        .await
        .unwrap()
        .unwrap();
        drop(peer);
        stop.send(true).unwrap();
        task.await.unwrap().unwrap();
        let attempts:Vec<String>=owner.query("SELECT outcome||'|'||protocol||'|'||coalesce(geo_country,'')||'|'||coalesce(device_fingerprint,'') FROM auth_attempts WHERE target_username='alice@imap1.test' ORDER BY id",&[]).await.unwrap().iter().map(|r|r.get(0)).collect();
        let signin: i64 = owner
            .query_one(
                "SELECT count(*) FROM login_events WHERE user_id=9343011",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        let devices:i64=owner.query_one("SELECT coalesce(sum(auth_count),0)::bigint FROM device_registry WHERE user_id=9343011",&[]).await.unwrap().get(0);
        if let Some(expected) = case.get("effects") {
            let mut effects = serde_json::Map::new();
            for(key,sql)in [
    ("attempts","SELECT (to_jsonb(t)-'id'-'occurred_at')::text FROM auth_attempts t WHERE target_username='alice@imap1.test' ORDER BY id"),
    ("signins","SELECT (to_jsonb(t)-'id'-'occurred_at')::text FROM login_events t WHERE user_id=9343011 OR (user_id IS NULL AND client='imap' AND source_ip='127.0.0.1') ORDER BY id"),
    ("devices","SELECT (to_jsonb(t)-'id'-'first_seen'-'last_seen')::text FROM device_registry t WHERE user_id=9343011 ORDER BY device_hash"),
    ("audit","SELECT (to_jsonb(t)-'id'-'occurred_at')::text FROM audit_log t WHERE user_id=9343011 AND event_type IN ('device_new','device_country_changed') ORDER BY id"),
    ("lockouts","SELECT jsonb_build_object('key',lockout_key,'failed_count',failed_count,'escalation_level',escalation_level)::text FROM auth_lockouts WHERE lockout_key IN ('ip:127.0.0.1','user:alice@imap1.test','ip_user:127.0.0.1:alice@imap1.test') ORDER BY lockout_key")]{
    let rows=owner.query(sql,&[]).await.unwrap().iter().map(|r|serde_json::from_str::<Value>(&r.get::<_,String>(0)).unwrap()).collect::<Vec<_>>();effects.insert(key.into(),serde_json::json!(rows));
   }
            assert_eq!(Value::Object(effects), *expected, "complete effects {name}");
        }
        assert_eq!(greeting, case["greeting"], "{name}");
        assert_eq!(reply, case["reply"], "{name}");
        assert_eq!(serde_json::json!(attempts), case["attempts"], "{name}");
        assert_eq!(signin, case["signins"].as_i64().unwrap(), "{name}");
        assert_eq!(devices, case["device_auths"].as_i64().unwrap(), "{name}");
    }
    owner
        .batch_execute(include_str!("../oracle/threat/reset.sql"))
        .await
        .unwrap();
    owner
        .batch_execute(include_str!("../oracle/cleanup.sql"))
        .await
        .unwrap();
}

#[tokio::test]
async fn feed_bypass_mutant_is_rejected_by_recorded_socket_and_effects() {
    use futures_util::FutureExt;
    let outcome = std::panic::AssertUnwindSafe(replay("go-effects.json", true))
        .catch_unwind()
        .await;
    let db = setjoin_conformance::harness::Db::for_case("AUTHRT-IMAP-mutant-cleanup").unwrap();
    let owner = db.connect().await.unwrap();
    owner
        .batch_execute(include_str!("../oracle/threat/reset.sql"))
        .await
        .unwrap();
    owner
        .batch_execute(include_str!("../oracle/cleanup.sql"))
        .await
        .unwrap();
    let panic = outcome.expect_err("feed-bypass mutant survived its Go recording");
    let message = panic
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| panic.downcast_ref::<&str>().copied())
        .unwrap_or("");
    assert!(message.contains("complete effects feed"), "mutant failed before the recorded feed assertion: {message}");
}

#[tokio::test]
async fn nullable_device_country_replays_go_new_device_audit() {
    replay("go-device-null.json", false).await;
}
