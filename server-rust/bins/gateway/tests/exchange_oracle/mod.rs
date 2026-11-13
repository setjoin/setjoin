//! Frozen-Go HTTP, committed rows, audit and notifications. No Go in replay.
use crate::common::{self, BoxError};
use hyper::{Request, Response};
use serde_json::{json, Value};
use setjoin_conformance::{golden, harness::Db};
use setjoin_gateway::{
    Body, BoxFuture, Config, Gateway, Intercept, RequestContext, RouteTable, TrustedProxies,
};
use setjoin_pg::ScopedExecutor;
mod artifact;
#[path = "../drive_workers_oracle/fake_s3.rs"]
#[allow(dead_code)]
mod fake_s3;
mod plan;
pub mod worker;
use plan::{plan, Fx};
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct Probe {
    inner: setjoin_gateway::exchange::ExchangeRoute<setjoin_gateway::jmap::jwks::Jwks>,
    changed: bool,
}
impl Intercept for Probe {
    fn matches(&self, r: &Request<Body>) -> bool {
        self.inner.matches(r)
    }
    fn admits_member(&self, h: hyper::HeaderMap, s: &'static str) -> BoxFuture<bool> {
        self.inner.admits_member(h, s)
    }
    fn handle(&self, r: Request<Body>, c: RequestContext) -> BoxFuture<Response<Body>> {
        let future = self.inner.handle(r, c);
        let changed = self.changed;
        Box::pin(async move {
            let mut response = future.await;
            if changed {
                *response.status_mut() = hyper::StatusCode::IM_A_TEAPOT;
            }
            response
        })
    }
}
fn mask_time(s: &str) -> String {
    let mut out = String::new();
    let mut i = 0;
    while i < s.len() {
        let rest = &s[i..];
        let b = rest.as_bytes();
        if b.len() > 20
            && b[0] == b'"'
            && b[5] == b'-'
            && b[8] == b'-'
            && (b[11] == b'T' || b[11] == b' ')
            && b[14] == b':'
        {
            if let Some(end) = rest[1..].find('"') {
                out.push_str("\"<timestamp>\"");
                i += end + 2;
                continue;
            }
        }
        let ch = rest.chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}
fn mask_text(text: &str, fx: &Fx, table: &str) -> String {
    let mut out = fx.names(text);
    let mut ids = vec![
        ("domain_id", fx.a.domain, "<domain-a>"),
        ("domain_id", fx.b.domain, "<domain-b>"),
        ("domainId", fx.a.domain, "<domain-a>"),
        ("domainId", fx.b.domain, "<domain-b>"),
        ("tenantId", fx.a.domain, "<domain-a>"),
        ("tenantId", fx.b.domain, "<domain-b>"),
    ];
    for key in [
        "user_id",
        "created_by",
        "createdBy",
        "actor_id",
        "actor",
        "requested_by",
        "resolved_by",
        "published_by",
        "actor_id",
    ] {
        ids.push((key, fx.a.user, "<admin>"));
        ids.push((key, fx.b.user, "<other>"));
    }
    for key in ["projectId", "project_id"] {
        ids.push((key, fx.pa, "<project-a>"));
        ids.push((key, fx.pb, "<project-b>"));
    }
    for key in ["runId", "run_id"] {
        ids.push((key, fx.ra, "<run-a>"));
        ids.push((key, fx.rb, "<run-b>"));
    }
    if table == "projects" {
        ids.push(("target_id", fx.pa, "<project-a>"));
        ids.push(("target_id", fx.pb, "<project-b>"));
        ids.push(("id", fx.pa, "<project-a>"));
        ids.push(("id", fx.pb, "<project-b>"));
    }
    if table == "runs" {
        ids.push(("target_id", fx.ra, "<run-a>"));
        ids.push(("target_id", fx.rb, "<run-b>"));
        ids.push(("id", fx.ra, "<run-a>"));
        ids.push(("id", fx.rb, "<run-b>"));
    }
    for (key, id, name) in ids {
        for sep in [":", ": "] {
            for end in [",", "}"] {
                out = out.replace(
                    &format!("\"{key}\"{sep}{id}{end}"),
                    &format!("\"{key}\"{sep}\"{name}\"{end}"),
                );
            }
        }
    }
    for (kind, id, name) in fx.symbols.lock().unwrap().iter() {
        let keys = if kind == table {
            vec!["id", "target_id"]
        } else {
            vec![]
        };
        for key in keys.into_iter().chain(match kind.as_str() {
            "projects" => vec!["projectId", "project_id"],
            "runs" => vec!["runId", "run_id"],
            "artifacts" => vec![
                "artifactId",
                "artifact_id",
                "receiptArtifactId",
                "receipt_artifact_id",
            ],
            _ => vec![],
        }) {
            for sep in [":", ": "] {
                for end in [",", "}"] {
                    out = out.replace(
                        &format!("\"{key}\"{sep}{id}{end}"),
                        &format!("\"{key}\"{sep}\"{name}\"{end}"),
                    );
                }
            }
        }
    }
    for digest in fx.digests.lock().unwrap().iter() {
        out = out.replace(&format!("\"{digest}\""), "\"<projection-sha256>\"");
    }
    for (key, value) in fx.objects.lock().unwrap().iter() {
        out = out.replace(key, value);
    }
    for digest in fx.object_digests.lock().unwrap().iter() {
        out = out.replace(digest, "<object-key-sha256>");
    }
    for (raw, value) in fx.crypto_literals.lock().unwrap().iter() {
        out = out.replace(raw, value);
    }
    if !fx.installation.is_empty() {
        out = out.replace(&fx.installation, "<installation>");
    }
    mask_time(&out)
}
async fn snapshot(
    c: &tokio_postgres::Client,
    fx: &Fx,
    action: &str,
    request: &str,
) -> Result<Value, BoxError> {
    let mut out = serde_json::Map::new();
    for (name, table, predicate) in [
        (
            "projects",
            "exchange_assessment_projects",
            format!("domain_id IN ({},{})", fx.a.domain, fx.b.domain),
        ),
        (
            "runs",
            "exchange_assessment_runs",
            format!("project_id IN ({},{})", fx.pa, fx.pb),
        ),
    ] {
        let rows = c
            .query(
                &format!("SELECT to_jsonb(x)::text FROM {table} x WHERE {predicate} ORDER BY id"),
                &[],
            )
            .await?;
        for row in &rows {
            let v: Value = serde_json::from_str(&row.get::<_, String>(0))?;
            if (name == "projects" && v["name"] == "Created Project")
                || (name == "runs" && v["id"].as_i64().is_some_and(|n| n != fx.ra && n != fx.rb))
            {
                let id = v["id"].as_i64().ok_or("project id")?;
                let mut symbols = fx.symbols.lock().unwrap();
                if !symbols.iter().any(|(t, n, _)| t == name && *n == id) {
                    symbols.push((
                        name.into(),
                        id,
                        if name == "projects" {
                            "<project-created>"
                        } else {
                            "<run-created>"
                        }
                        .into(),
                    ));
                }
            }
        }
        let values: Vec<Value> = rows
            .iter()
            .map(|r| serde_json::from_str(&mask_text(&r.get::<_, String>(0), fx, name)))
            .collect::<Result<_, _>>()?;
        out.insert(name.into(), json!(values));
    }
    if matches!(action, "create-project" | "create-run") {
        let mut values = vec![];
        for row in c.query("SELECT to_jsonb(x)::text FROM exchange_assessment_idempotency x WHERE actor_id=$1 ORDER BY idempotency_key",&[&fx.a.user]).await? {
          let mut v:Value=serde_json::from_str(&row.get::<_,String>(0))?;
          let req:Value=serde_json::from_str(request)?;
          let canonical=if action=="create-project" {format!("{{\"domainId\":{},\"name\":{},\"retentionUntil\":null}}",req["domainId"],serde_json::to_string(&req["name"])?)}else{format!("{{\"supportCellId\":{},\"supportCellDigest\":{},\"registryVersion\":{},\"registryDigest\":{},\"catalogVersion\":{},\"collectorVersion\":{}}}",req["supportCellId"],req["supportCellDigest"],req["registryVersion"],req["registryDigest"],req["catalogVersion"],req["collectorVersion"])};
          use sha2::{Digest,Sha256};
          let expected=format!("{:x}",Sha256::digest(canonical.as_bytes()));
          if v["payload_sha256"]!=expected {return Err("Go request canonical digest mismatch".into());}
          v["payload_sha256"]=json!("<request-sha256>");
          values.push(serde_json::from_str::<Value>(&mask_text(&v.to_string(),fx,if action=="create-project"{"projects"}else{"runs"}))?);
       }
        out.insert("idempotency".into(), json!(values));
    }
    if matches!(
        action,
        "attestation" | "decision" | "resolve" | "delete" | "audit" | "bundle" | "publish"
    ) {
        let tables = if action == "attestation" {
            vec![("attestations", "exchange_assessment_attestations")]
        } else if action == "decision" {
            vec![
                ("decisions", "exchange_assessment_decisions"),
                ("claims", "exchange_assessment_claim_snapshots"),
            ]
        } else if action == "resolve" {
            vec![("claims", "exchange_assessment_claim_snapshots")]
        } else if action == "delete" {
            vec![("deletions", "exchange_assessment_deletion_requests")]
        } else if action == "publish" {
            vec![
                ("claims", "exchange_assessment_claim_snapshots"),
                ("artifacts", "exchange_assessment_artifacts"),
                ("receipts", "exchange_assessment_receipts"),
                ("publications", "exchange_assessment_publications"),
            ]
        } else if action == "bundle" {
            vec![("artifacts", "exchange_assessment_artifacts")]
        } else {
            vec![
                ("artifacts", "exchange_assessment_artifacts"),
                ("claims", "exchange_assessment_claim_snapshots"),
                ("attestations", "exchange_assessment_attestations"),
                ("evidence", "exchange_assessment_evidence"),
                ("publications", "exchange_assessment_publications"),
            ]
        };
        for (name, table) in tables {
            let mut values = vec![];
            for row in c
                .query(
                    &format!(
                        "SELECT to_jsonb(x)::text FROM {table} x WHERE {}=ANY($1) ORDER BY id",
                        if name == "deletions" {
                            "project_id"
                        } else {
                            "run_id"
                        }
                    ),
                    &[&if name == "deletions" {
                        vec![fx.pa, fx.pb]
                    } else {
                        vec![fx.ra, fx.rb]
                    }],
                )
                .await?
            {
                let mut v: Value = serde_json::from_str(&row.get::<_, String>(0))?;
                let id = v["id"].as_i64().ok_or("child id")?;
                {
                    let mut symbols = fx.symbols.lock().unwrap();
                    if !symbols.iter().any(|(t, n, _)| t == name && *n == id) {
                        let index = symbols.iter().filter(|(t, _, _)| t == name).count();
                        let singular = match name {
                            "attestations" => "attestation",
                            "decisions" => "decision",
                            "deletions" => "deletion",
                            "artifacts" => "artifact",
                            "evidence" => "evidence",
                            "publications" => "publication",
                            "receipts" => "receipt",
                            _ => "claim",
                        };
                        symbols.push((name.into(), id, format!("<{singular}-{index}>")));
                    }
                }
                if matches!(action, "resolve" | "publish") && name == "claims" {
                    let digest = v["projection_digest"].as_str().ok_or("projection digest")?;
                    let projection:String=c.query_one("SELECT projection::text FROM exchange_assessment_claim_snapshots WHERE id=$1",&[&id]).await?.get(0);
                    use sha2::{Digest, Sha256};
                    if format!("{:x}", Sha256::digest(projection.as_bytes())) != digest {
                        return Err("projection SHA-256 mismatch".into());
                    }
                    let mut digests = fx.digests.lock().unwrap();
                    if !digests.iter().any(|d| d == digest) {
                        digests.push(digest.into());
                    }
                }
                if matches!(action, "bundle" | "publish") && name == "artifacts" {
                    let _ = artifact::inspect(fx, &mut v).await?;
                }
                if action == "publish" && name == "receipts" {
                    artifact::inspect_receipt_row(fx, &mut v)?;
                }
                values.push(serde_json::from_str::<Value>(&mask_text(
                    &v.to_string(),
                    fx,
                    name,
                ))?);
            }
            out.insert(name.into(), json!(values));
        }
    }
    Ok(Value::Object(out))
}
pub async fn run(action: &str, kind: &str) -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let changed = kind == "status-mutant";
    let kind = if changed {
        if action == "registry" {
            "seeded"
        } else {
            "success"
        }
    } else {
        kind
    };
    let Some(db) = Db::for_case("exchange-http") else {
        return Ok(());
    };
    let c = db.connect().await?;
    let fx = Fx::build(&c, action, kind).await?;
    let p = plan(action, kind, &fx);
    let audit_start: i64 = c
        .query_one("SELECT COALESCE(max(id),0) FROM admin_audit_log", &[])
        .await?
        .get(0);
    let receipts: Vec<String> = c
        .query(
            "SELECT operation_id::text FROM rust_operation_receipts WHERE family='F05'",
            &[],
        )
        .await?
        .iter()
        .map(|r| r.get(0))
        .collect();
    let result=async {
 let storage=if matches!(action,"bundle"|"publish"){Some(fake_s3::DriveS3::start().await)}else{None};
 let s3=if let Some(store)=&storage{store.addr}else{common::fake_upstream(|_|async{Response::new(common::full(""))}).await};
 if storage.is_some(){*fx.storage.lock().unwrap()=Some(s3);}
 let mut go_env=vec![("CRYPTO_ALGORITHM_PROFILE",fx.profile.clone())];
 if fx.profile=="smx"{go_env.push(("SM2_PRIVATE_KEY_FILE","/src/server-rust/tests/conformance/exchange/fixtures/sm2-key.pem".into()));}
 let go=common::go_oracle::start_named_with_env(&db,s3,"gofree-mbox3-http",&go_env).await?;
 let recording=go.is_some();
 if let Some(store)=&storage{store.reset();if kind=="put-denied"{store.reject_put();}}
 let mut inventory:Value=serde_json::from_str(include_str!("../../route-inventory.json"))?;
 for row in inventory["routes"].as_array_mut().unwrap(){if row["slice"]=="exchange-replacement"{row["state"]=json!(if recording{"OFF"}else{"ON"});row["upstream"]=json!(if recording{"go-mail"}else{"local-rust"});row["oracle_commands"]=json!([""]);}}
 let exec=ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn),4).map_err(|e|e.0)?.with_audit_keys("22".repeat(32),String::new());
 let worker=ScopedExecutor::from_dsn(&db.dsn,4).map_err(|e|e.0)?.with_audit_keys("22".repeat(32),String::new());
 let adapter=Probe{inner:setjoin_gateway::exchange::ExchangeRoute{exec,worker,keys:std::sync::Arc::new(common::recovery_keys()),issuer:"mailserver".into(),artifacts:setjoin_gateway::exchange::Artifacts {
 signer:Some(std::sync::Arc::new(setjoin_mailboxes::exchange_artifact::ReceiptSigner::from_pkcs8(&[&[0x30,0x2e,0x02,0x01,0x00,0x30,0x05,0x06,0x03,0x2b,0x65,0x70,0x04,0x22,0x04,0x20][..],&[0x22;32]].concat(),"blobs1-test-continuity")?)),
 store:if storage.is_some(){Some(std::sync::Arc::new(setjoin_gateway::recovery_worker::S3Store::new(&format!("http://{s3}"),"mailblobs","test-access","test-secret")?))}else{None},master:"22".repeat(32),profile:setjoin_mailboxes::exchange_artifact::Profile::parse(&fx.profile),
 }},changed};
 let gateway=Gateway::new(Config{upstream:go.as_ref().map(|g|format!("http://{}",g.address).parse()).transpose()?,trusted_proxies:TrustedProxies::parse("")?,upstream_header_timeout:setjoin_gateway::proxy::DEFAULT_HEADER_TIMEOUT,edge_limit:None},RouteTable::proxy_all().with(adapter))?.with_inventory(&inventory.to_string())?;
 let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await?;let address=listener.local_addr()?;let server=tokio::spawn(gateway.serve(listener));
 let before=snapshot(&c,&fx,action,&p.body).await?;
 let mut notify_a=db.listen("exchange_assessment").await?;let mut notify_b=db.listen("exchange_assessment_changed").await?;
 if kind=="repeat"{let first=send_request(address,&fx,&p,kind).await?;let first_status=first.status().as_u16();let _=common::body_bytes(first).await;if !(200..300).contains(&first_status){return Err(format!("first request failed: {first_status}").into());}}
 let response=send_request(address,&fx,&p,kind).await?;
 let status=response.status().as_u16();let mut headers=serde_json::Map::new();for name in response.headers().keys(){headers.insert(name.to_string(),json!(response.headers().get_all(name).iter().map(|v|v.to_str().unwrap()).collect::<Vec<_>>()));}
 let raw=String::from_utf8(common::body_bytes(response).await.to_vec())?;
 if recording && std::env::var_os("GOFREE_ORACLE_LEARN").is_some(){eprintln!("LEARN {action}/{kind} {status} {}",raw.chars().take(500).collect::<String>().replace('\n'," "));server.abort();return Ok(());}
 let io=storage.as_ref().map(|s|s.take_log());
 let after=snapshot(&c,&fx,action,&p.body).await?;
 let table=match action{"projects"|"create-project"=>"projects","attestation"=>"attestations","decision"=>"decisions","resolve"=>"claims","delete"=>"deletions","bundle"=>"artifacts","publish"=>"publications",_=>"runs"};let body=if action=="audit" && p.method!="HEAD" && (status==200||changed) {
    let fields:std::collections::BTreeMap<String,&serde_json::value::RawValue>=serde_json::from_str(&raw)?;
    let mut body=raw.clone();for key in ["claims","attestations","evidence","publications"]{let field=fields.get(key).ok_or("audit collection missing")?;body=body.replacen(&format!("\"{key}\":{}",field.get()),&format!("\"{key}\":{}",mask_text(field.get(),&fx,key)),1);}body
 }else{mask_text(&raw,&fx,table)};
 if headers.contains_key("date"){headers.insert("date".into(),json!(["<timestamp>"]));}
 if headers.contains_key("content-length"){
 if p.method=="HEAD"{if !raw.is_empty(){return Err("HEAD returned a body".into());}let get=plan::Plan{method:"GET",pattern:p.pattern,path:p.path.clone(),body:p.body.clone()};let response=send_request(address,&fx,&get,kind).await?;let bytes=common::body_bytes(response).await;if headers["content-length"]!=json!([bytes.len().to_string()]){return Err("HEAD length differs from GET bytes".into());}headers.insert("content-length".into(),json!(["<GET body length>"]));}
 else{if headers["content-length"]!=json!([raw.len().to_string()]){return Err("Content-Length differs from body bytes".into());}headers.insert("content-length".into(),json!([body.len().to_string()]));}}

 let mut audit=vec![];for row in c.query("SELECT to_jsonb(a)::text FROM admin_audit_log a WHERE id>$1 ORDER BY id",&[&audit_start]).await? {
 let mut v:Value=serde_json::from_str(&row.get::<_,String>(0))?;
 if let Some(n)=v["target_id"].as_i64(){
    let target=match v["target_type"].as_str().unwrap_or("") {"exchange_assessment_run"=>if n==fx.ra{Some("<run-a>".to_owned())}else if n==fx.rb{Some("<run-b>".to_owned())}else{fx.symbols.lock().unwrap().iter().find(|(t,id,_)|t=="runs"&&*id==n).map(|(_,_,name)|name.clone())},"exchange_assessment_project"=>if n==fx.pa{Some("<project-a>".to_owned())}else if n==fx.pb{Some("<project-b>".to_owned())}else{fx.symbols.lock().unwrap().iter().find(|(t,id,_)|t=="projects"&&*id==n).map(|(_,_,name)|name.clone())},_=>None};
    if let Some(name)=target{v["target_id"]=json!(name);}
 }
 v["id"]=json!("<audit>");for key in ["checksum","prev_checksum"]{if v[key].as_str().is_some_and(|s|!s.is_empty()){v[key]=json!("<checksum>");}}
 audit.push(serde_json::from_str::<Value>(&mask_text(&v.to_string(),&fx,table))?);
 }
 let mut notify=vec![];for (channel,listener) in [("exchange_assessment",&mut notify_a),("exchange_assessment_changed",&mut notify_b)]{for payload in listener.drain(&c).await?{notify.push(json!({"channel":channel,"payload":serde_json::from_str::<Value>(&mask_text(&payload,&fx,table))?}));}}
 let mut obs=json!({"request":{"method":p.method,"path":p.pattern,"external_path":format!("/api{}",p.pattern)},"response":{"status":status,"headers":headers,"body":body},"effects":[{"table":"exchange_assessment","before":before,"after":after}],"audit":audit,"notify":notify});
 if let Some(mut io)=io {
    for entry in &mut io{if entry["method"]=="PUT"{
       let key=entry["path"].as_str().ok_or("S3 path")?.strip_prefix("/mailblobs/").ok_or("S3 bucket")?;
       let run=if key.starts_with(&format!("exchange-assessment/{}/{}/{}/",fx.a.domain,fx.pa,fx.ra)){fx.ra}else{fx.rb};
       let _=artifact::remember_key(&fx,key,run)?;if entry["content_type"]!="application/vnd.setjoin.exchange-artifact+json"{return Err("wrong object content type".into());}entry["body_sha256"]=json!("<AEAD-validated envelope>");entry["body_len"]=json!("<encoded envelope>");}}
    obs["io"]=serde_json::from_str::<Value>(&mask_text(&serde_json::to_string(&io)?,&fx,"artifacts"))?;
 }
 if !p.body.is_empty(){obs["request"]["body"]=json!(mask_text(&p.body,&fx,table));}
 if !recording{let metrics=common::send(address,Request::get("/_gateway/metrics").body(common::full(""))?).await;let metrics=String::from_utf8(common::body_bytes(metrics).await.to_vec())?;if !metrics.contains("setjoin_gateway_proxied_to_go_by_family_total{family=\"F05\"} 0"){return Err(format!("forwarded to Go: {metrics}").into());}}
 server.abort();
 let dir=std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/conformance/exchange/goldens");std::fs::create_dir_all(&dir)?;
 let name=format!("{action}-{kind}");let path=dir.join(format!("{name}.json"));let row_path=dir.join(format!("{name}-row-effects.json"));let route=format!("{} {}",p.method,p.pattern);
 if recording {
 if action=="bundle" {
    let wanted=match kind{"foreign"=>404,"invalid"|"empty"|"bad-generation"|"bad-sha"=>400,"denied"|"weak-aal"|"stale-aal"=>403,"stale-generation"|"bad-state"=>409,"put-denied"=>503,"repeat"=>200,_=>201};
    if status!=wanted{return Err(format!("Go bundle/{kind}: wanted {wanted}, got {status}: {raw}").into());}
 }
 if matches!(kind,"success"|"seeded"|"smx"|"hybrid") {
    let wanted=match action{"create-project"|"create-run"|"attestation"|"resolve"|"bundle"|"publish"=>201,"delete"=>202,_=>200};
    if status!=wanted{return Err(format!("Go {action}/{kind}: expected success {wanted}, got {status}: {raw}").into());}
 }
 let source=std::env::var("GOFREE_GO_SOURCE")?;
 record(&path,&json!({"format":1,"route":route,"case":kind,"go_source":source,"observation":obs}))?;
 record(&row_path,&json!({"format":1,"route":route,"case":format!("{kind}-row-effects"),"go_source":source,"effects":obs["effects"]}))?;
 }else{
 let expected:Value=common::golden_doc(&path,"observation",&obs);let compared=golden::compare(&expected["observation"],&obs);
 if changed{let error=compared.err().ok_or("status mutant survived")?;if !error.contains("/response/status"){return Err(error.into());}eprintln!("MUTANT-REJECTED: {route} :: changed-status");return Ok(());}
 compared?;let expected:Value=common::golden_doc(&row_path,"effects",&obs["effects"]);golden::compare(&expected["effects"],&obs["effects"])?;eprintln!("GOLDEN-REPLAY: {route} :: {kind}");
 }
 Ok::<_,BoxError>(())
 }.await;
    c.execute(
        "DELETE FROM rust_operation_receipts WHERE family='F05' AND operation_id::text<>ALL($1)",
        &[&receipts],
    )
    .await?;
    fx.remove(&c).await?;
    c.batch_execute(&format!("BEGIN; SET LOCAL session_replication_role=replica; DELETE FROM admin_audit_log WHERE id>{audit_start}; COMMIT;")).await?;
    result
}
fn token(user: i64, kind: &str) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use p256::ecdsa::{signature::Signer, SigningKey};
    let source = common::recovery_token(user);
    let f: Vec<_> = source.split('.').collect();
    let mut claims: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(f[1]).unwrap()).unwrap();
    claims["admin"] = json!(true);
    claims["acr"] = json!("aal2");
    claims["amr"] = json!(["pwd", "otp", "mfa"]);
    if kind == "denied" {
        claims["perms"] = json!(plan::PERMS);
    }
    if kind == "weak-aal" {
        claims["amr"] = json!(["pwd"]);
    }
    if kind == "stale-aal" {
        claims["iat"] = json!(claims["iat"].as_i64().unwrap() - 600);
    }
    let payload = URL_SAFE_NO_PAD.encode(claims.to_string());
    let key = SigningKey::from_slice(&[0x11; 32]).unwrap();
    let sig: p256::ecdsa::Signature = key.sign(format!("{}.{payload}", f[0]).as_bytes());
    format!(
        "{}.{payload}.{}",
        f[0],
        URL_SAFE_NO_PAD.encode(sig.to_bytes())
    )
}

async fn send_request(
    address: std::net::SocketAddr,
    fx: &Fx,
    p: &plan::Plan,
    kind: &str,
) -> Result<Response<hyper::body::Incoming>, BoxError> {
    let mut request = Request::builder()
        .method(p.method)
        .uri(format!("/api{}", p.path))
        .header("host", "mail.test")
        .header("origin", "http://mail.test")
        .header("content-type", "application/json")
        .header(
            "authorization",
            format!("Bearer {}", token(fx.a.user, kind)),
        )
        .header("x-request-id", "gofree-mbox3")
        .header("idempotency-key", plan::KEY);
    if p.pattern.ends_with("/bundle") {
        use sha2::{Digest, Sha256};
        let generation = match kind {
            "bad-generation" => "0",
            "stale-generation" => "2",
            _ => "1",
        };
        let digest = match kind {
            "invalid" => "e".repeat(64),
            "bad-sha" => "wrong".into(),
            _ => format!("{:x}", Sha256::digest(p.body.as_bytes())),
        };
        request = request
            .header("x-run-generation", generation)
            .header("x-content-sha256", digest);
    }
    if kind != "reason-required" {
        request = request.header("x-audit-reason", "Exchange assessment oracle");
    }
    if kind == "locale-invalid" {
        request = request.header("accept-language", "zh-CN, en;q=0.5");
    }
    Ok(common::send(address, request.body(common::full(p.body.clone()))?).await)
}

fn record(path: &std::path::Path, value: &Value) -> Result<(), BoxError> {
    if std::env::var_os("GOFREE_VERIFY_GO").is_some() {
        let expected: Value = serde_json::from_slice(&std::fs::read(path)?)?;
        golden::compare(&expected, value)?;
    } else {
        golden::record(path, value)?;
    }
    Ok(())
}
