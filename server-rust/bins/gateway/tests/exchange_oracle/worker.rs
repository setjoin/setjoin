//! Seed plus one real frozen-Go tick. Replay starts no Go process.
use super::*;
#[path = "../drain_oracle/mod.rs"]
mod tick;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ring::signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey, ED25519};
use sha2::{Digest, Sha256};
fn hash(b: &[u8]) -> String {
    format!("{:x}", Sha256::digest(b))
}
fn signer() -> Result<setjoin_mailboxes::exchange_artifact::ReceiptSigner, BoxError> {
    Ok(
        setjoin_mailboxes::exchange_artifact::ReceiptSigner::from_pkcs8(
            &[
                &[
                    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04,
                    0x22, 0x04, 0x20,
                ][..],
                &[0x22; 32],
            ]
            .concat(),
            "blobs1-test-continuity",
        )?,
    )
}
async fn observe(
    c: &tokio_postgres::Client,
    fx: &Fx,
    subjects: &[(i64, String)],
    start: i64,
) -> Result<Value, BoxError> {
    let mut out = json!({});
    for (name, table, filter) in [
        (
            "artifacts",
            "exchange_assessment_artifacts",
            "run_id=ANY($1)",
        ),
        (
            "deletions",
            "exchange_assessment_deletion_requests",
            "project_id=ANY($1)",
        ),
        (
            "receipts",
            "exchange_assessment_receipts",
            "created_by=ANY($1)",
        ),
        (
            "tombstones",
            "exchange_assessment_tombstones",
            "run_id=ANY($1)",
        ),
    ] {
        let ids = if name == "deletions" {
            vec![fx.pa, fx.pb]
        } else if name == "receipts" {
            vec![fx.a.user, fx.b.user]
        } else {
            vec![fx.ra, fx.rb]
        };
        let rows = c
            .query(
                &format!(
                    "SELECT to_jsonb(x)::text FROM {table} x WHERE {filter} ORDER BY {}",
                    if name == "tombstones" {
                        "run_id,artifact_digest"
                    } else {
                        "id"
                    }
                ),
                &[&ids],
            )
            .await?;
        let mut values = vec![];
        for row in rows {
            let mut v: Value = serde_json::from_str(&row.get::<_, String>(0))?;
            if name == "tombstones" {
                let run = v["run_id"].as_i64().ok_or("tombstone run")?;
                let project = if run == fx.ra {
                    fx.pa
                } else if run == fx.rb {
                    fx.pb
                } else {
                    return Err("tombstone run scope".into());
                };
                let artifact = out["artifacts"]
                    .as_array()
                    .ok_or("artifact observations")?
                    .iter()
                    .find(|a| a["run_id"] == run && a["sha256"] == v["artifact_digest"])
                    .ok_or("tombstone artifact")?;
                let receipt = out["receipts"]
                    .as_array()
                    .ok_or("receipt observations")?
                    .iter()
                    .find(|r| r["receipt"]["claims"]["projectId"] == project)
                    .ok_or("tombstone receipt")?;
                let expected = format!(
                    "{}-{}",
                    receipt["receipt"]["claims"]["receiptId"]
                        .as_str()
                        .ok_or("receiptId")?,
                    artifact["id"]
                );
                if v["receipt_id"] != expected {
                    return Err("tombstone receipt binding".into());
                }
            }
            let id = if name == "tombstones" {
                0
            } else {
                v["id"].as_i64().ok_or("id")?
            };
            {
                let mut symbols = fx.symbols.lock().unwrap();
                if name != "tombstones" && !symbols.iter().any(|(t, n, _)| t == name && *n == id) {
                    let n = symbols.iter().filter(|(t, _, _)| t == name).count();
                    symbols.push((name.into(), id, format!("<{name}-{n}>")));
                }
            }
            if name == "receipts" {
                let cl = &v["receipt"]["claims"];
                let subject = cl["subjectSha256"].as_str().ok_or("subject")?;
                if !subjects.iter().any(|(_, s)| s == subject)
                    || v["subject_digest"] != subject
                    || cl["kind"] != "deletion"
                    || cl["disposition"] != "backup_expiry_pending"
                    || cl["schemaVersion"] != "setjoin.exchange.receipt/v1"
                    || cl["installationId"] != fx.installation
                    || cl["keyId"] != "blobs1-test-continuity"
                {
                    return Err("deletion receipt claims".into());
                }
                let project = cl["projectId"].as_i64().ok_or("project")?;
                if project
                    != if v["created_by"] == fx.a.user {
                        fx.pa
                    } else {
                        fx.pb
                    }
                    || (project != fx.pa && project != fx.pb)
                    || cl["tenantId"]
                        != if project == fx.pa {
                            fx.a.domain
                        } else {
                            fx.b.domain
                        }
                {
                    return Err("receipt ownership".into());
                }
                let pubkey = Ed25519KeyPair::from_seed_unchecked(&[0x22; 32]).map_err(|_| "key")?;
                let sig = URL_SAFE_NO_PAD
                    .decode(v["receipt"]["signature"].as_str().ok_or("signature")?)?;
                UnparsedPublicKey::new(&ED25519, pubkey.public_key())
                    .verify(artifact::receipt_bytes(cl, false)?.as_bytes(), &sig)
                    .map_err(|_| "signature")?;
                let receipt_id = hash(artifact::receipt_bytes(cl, true)?.as_bytes());
                if cl["receiptId"] != receipt_id
                    || v["signature_algorithm"] != "ed25519"
                    || v["signing_key_id"] != "blobs1-test-continuity"
                    || v["signature"]
                        != format!(
                            "\\x{}",
                            sig.iter().map(|b| format!("{b:02x}")).collect::<String>()
                        )
                {
                    return Err("receipt metadata".into());
                }
                let issued = cl["issuedAt"].as_str().ok_or("issuedAt")?;
                if issued.len() != 20
                    || !issued.ends_with('Z')
                    || (chrono::Utc::now() - chrono::DateTime::parse_from_rfc3339(issued)?.to_utc())
                        .num_seconds()
                        .abs()
                        > 120
                {
                    return Err("receipt time".into());
                }
                fx.crypto_literals
                    .lock()
                    .unwrap()
                    .push((receipt_id, "<receipt-id>".into()));
                v["signature"] = json!("<64-byte Ed25519 signature>");
                v["receipt"]["signature"] = json!("<Ed25519 signature>");
            }
            values.push(v);
        }
        out[name] = json!(values);
    }
    let mut audit = vec![];
    for r in c
        .query(
            "SELECT to_jsonb(x)::text FROM admin_audit_log x WHERE id>$1 ORDER BY id",
            &[&start],
        )
        .await?
    {
        let mut v: Value = serde_json::from_str(&r.get::<_, String>(0))?;
        v["id"] = json!("<audit>");
        v["target_id"] = if v["target_id"] == fx.pa {
            json!("<project-a>")
        } else {
            json!("<project-b>")
        };
        for k in ["checksum", "prev_checksum"] {
            if v[k].as_str().is_some_and(|s| !s.is_empty()) {
                v[k] = json!("<checksum>");
            }
        }
        audit.push(v);
    }
    out["audit"] = json!(audit);
    Ok(out)
}
fn normalize(v: &Value, fx: &Fx, subjects: &[(i64, String)]) -> Result<Value, BoxError> {
    let mut text = v.to_string();
    for (n, (_, s)) in subjects.iter().enumerate() {
        text = text.replace(s, &format!("<deletion-subject-{n}>"));
    }
    for (table, id, name) in fx.symbols.lock().unwrap().iter() {
        for k in match table.as_str() {
            "artifacts" => vec!["artifact_id"],
            "deletions" => vec!["requestId"],
            "receipts" => vec!["receiptId"],
            _ => vec![],
        } {
            text = text.replace(&format!("\"{k}\":{id},"), &format!("\"{k}\":\"{name}\","));
        }
    }
    // Table-specific primary ids (and tombstone receipt suffixes) are normalized before shared keys.
    let mut v: Value = serde_json::from_str(&text)?;
    for table in ["artifacts", "deletions", "receipts", "tombstones"] {
        if let Some(rows) = v[table].as_array_mut() {
            for row in rows {
                let symbols = fx.symbols.lock().unwrap();
                if table != "tombstones" {
                    let id = row["id"].as_i64().ok_or("row id")?;
                    row["id"] = json!(
                        symbols
                            .iter()
                            .find(|(t, n, _)| t == table && *n == id)
                            .ok_or("symbol")?
                            .2
                    );
                }
                if table == "tombstones" {
                    let receipt = row["receipt_id"].as_str().ok_or("tombstone receipt")?;
                    let (rid, aid) = receipt.rsplit_once('-').ok_or("receipt suffix")?;
                    let aid: i64 = aid.parse()?;
                    let a = symbols
                        .iter()
                        .find(|(t, n, _)| t == "artifacts" && *n == aid)
                        .ok_or("artifact suffix")?;
                    row["receipt_id"] = json!(format!("{rid}-{}", a.2));
                }
            }
        }
    }
    Ok(serde_json::from_str(&mask_text(
        &v.to_string(),
        fx,
        "worker",
    ))?)
}
pub async fn run(kind: &str) -> Result<(), BoxError> {
    let mutant = kind == "state-mutant";
    let kind = if mutant { "project" } else { kind };
    let _lock = SERIAL.lock().await;
    let Some(db) = Db::for_case("exchange-deletion-worker") else {
        return Ok(());
    };
    let c = db.connect().await?;
    let fx = Fx::build(&c, "bundle", "success").await?;
    let start: i64 = c
        .query_one("SELECT COALESCE(max(id),0) FROM admin_audit_log", &[])
        .await?
        .get(0);
    let result=async {
  let s3=fake_s3::DriveS3::start().await;let mut requests=vec![];
  for (n,(project,run,actor)) in [(fx.pa,fx.ra,fx.a.user),(fx.pb,fx.rb,fx.b.user)].into_iter().enumerate(){
   let mut artifacts=vec![];
   if kind!="empty"{for j in 0..2{let key=format!("gofree-mbox3-exchange/{project}/{run}/{j}");s3.put(&key,b"opaque encrypted artifact",0);if kind=="fail-delete"&&n==0&&j==0{s3.reject_delete(&key);}
    let id:i64=c.query_one("INSERT INTO exchange_assessment_artifacts(run_id,kind,object_key,sha256,crypto_profile,key_id) VALUES ($1,'bundle',$2,$3,'standard','db-encryption-key:v1') RETURNING id",&[&run,&key,&format!("{n}{j}{}","a".repeat(62))]).await?.get(0);artifacts.push((id,run,key,format!("{n}{j}{}","a".repeat(62))));}}
   let scope=if kind=="artifact"{"artifact"}else if kind=="run"{"run"}else{"project"};let artifact=if scope=="artifact"{Some(artifacts[0].0)}else{None};let run_id=if scope=="project"{None}else{Some(run)};
   let id:i64=c.query_one("INSERT INTO exchange_assessment_deletion_requests(project_id,run_id,artifact_id,scope,reason,requested_by) VALUES ($1,$2,$3,$4,'retention expired',$5) RETURNING id",&[&project,&run_id,&artifact,&scope,&actor]).await?.get(0);
   let artifacts:Vec<Value>=artifacts.iter().filter(|(id,_,_,_)|artifact.is_none_or(|a|a==*id)).map(|(id,run,key,sha)|json!({"id":id,"runId":run,"objectKey":key,"sha256":sha})).collect();
   // json! map is sorted: encode the Go struct order explicitly, including each artifact.
   let a=artifacts.iter().map(|a|format!("{{\"id\":{},\"runId\":{},\"objectKey\":{},\"sha256\":{}}}",a["id"],a["runId"],a["objectKey"],a["sha256"])).collect::<Vec<_>>().join(",");
   let subject=format!("{{\"requestId\":{id},\"projectId\":{project},\"scope\":\"{scope}\",\"artifacts\":[{a}]}}");requests.push((id,hash(subject.as_bytes())));
  }
  if kind=="feature-off"{c.execute("UPDATE feature_toggles SET enabled=false WHERE key='feature.exchange_replacement_assessment'",&[]).await?;}
  let before=observe(&c,&fx,&requests,start).await?;
  let mut notify=db.listen("exchange_assessment").await?;
  let recording=std::env::var_os("GOFREE_RECORD_GO_BINARY").is_some();
  if recording{
   let task=tick::GoTick{package:"internal/admin",overlay:"exchange_deletion_tick_test.go.txt",test:"TestGoFreeExchangeDeletionTick",file:"gofree_exchange_deletion_tick_test.go",env:vec![("GOFREE_DRAIN_DSN".into(),db.dsn.clone()),("GOFREE_DRAIN_S3".into(),s3.addr.to_string()),("DB_ENCRYPTION_KEY".into(),"22".repeat(32))],docker:vec![]};
   tokio::task::spawn_blocking(move||task.run()).await??;
  }else{
   let db=setjoin_pg::workers::WorkerDatabase::from_dsns("postgres://invalid:invalid@127.0.0.1:1/invalid",Some(&db.dsn))?.with_audit_keys("22".repeat(32),String::new());
   let store=std::sync::Arc::new(setjoin_gateway::recovery_worker::S3Store::new(&format!("http://{}",s3.addr),"mailblobs","test-access","test-secret")?);
   setjoin_gateway::exchange_deletion::DeletionWorker::new(db,store,std::sync::Arc::new(signer()?)).tick().await;
  }
  let after=observe(&c,&fx,&requests,start).await?;
  let notes=notify.drain(&c).await?.iter().map(|s|serde_json::from_str::<Value>(s)).collect::<Result<Vec<_>,_>>()?;
  let mut obs=json!({"before":normalize(&before,&fx,&requests)?,"after":normalize(&after,&fx,&requests)?,"notify":notes,"io":s3.take_log()});
  let mut text=mask_text(&obs.to_string(),&fx,"worker");
  for (n,(id,_)) in requests.iter().enumerate(){text=text.replace(&format!("\"requestId\":{id}"),&format!("\"requestId\":\"<deletions-{n}>\""));}
  for (project,run,tag) in [(fx.pa,fx.ra,"a"),(fx.pb,fx.rb,"b")]{text=text.replace(&format!("gofree-mbox3-exchange/{project}/{run}/"),&format!("gofree-mbox3-exchange/<project-{tag}>/<run-{tag}>/"));}
  obs=serde_json::from_str(&text)?;
  let path=std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/conformance/exchange/goldens").join(format!("worker-{kind}.json"));
  if recording{super::record(&path,&json!({"format":1,"case":kind,"go_source":std::env::var("GOFREE_GO_SOURCE")?,"observation":obs}))?;}else{let expected:Value=serde_json::from_slice(&std::fs::read(path)?)?;if mutant{obs["after"]["deletions"][0]["state"]=json!("requested");let error=golden::compare(&expected["observation"],&obs).err().ok_or("worker state mutant survived")?;if !error.contains("/after/deletions/0/state"){return Err(error.into());}eprintln!("MUTANT-REJECTED: exchange-assessment-deletion :: state");}else{golden::compare(&expected["observation"],&obs)?;}eprintln!("GOLDEN-REPLAY: exchange-assessment-deletion :: {kind}");}
  Ok::<_,BoxError>(())
 }.await;
    fx.remove(&c).await?;
    c.batch_execute(&format!("BEGIN; SET LOCAL session_replication_role=replica; DELETE FROM admin_audit_log WHERE id>{start}; COMMIT;")).await?;
    result
}
