//! Seed-plus-one-tick oracle at DB and signed fake-S3 boundaries, no Go on replay.
mod common;
mod drain_oracle;
use drain_oracle::{BoxError, GoTick};
use flate2::{read::GzDecoder, write::GzEncoder, Compression};
use http_body_util::Full;
use hyper::{body::Incoming, service::service_fn, Request, Response};
use hyper_util::rt::TokioIo;
use serde_json::{json, Value};
use setjoin_conformance::{fixture, harness::Db};
use setjoin_gateway::{recovery_worker::S3Store, spam_trainer::SpamTrainer};
use setjoin_pg::workers::WorkerDatabase;
use sha2::{Digest, Sha256};
use std::{
    convert::Infallible,
    io::{Read, Write},
    sync::{Arc, Mutex},
};

const USER: i64 = 9451001;
const MAILBOX: i64 = 9451101;
const DOMAIN: i64 = 9451201;
const MESSAGE: i64 = 9451301;
const RAW:&str="From: sender@example.test\r\nSubject: FREE OFFER\r\n\r\nClick free prize https://shop.example.test/offer now!";
fn root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/conformance/spam-trainer")
}
fn read_blob(name: &str) -> Result<Vec<u8>, BoxError> {
    let mut v = Vec::new();
    GzDecoder::new(std::fs::File::open(root().join(format!("{name}.gz")))?).read_to_end(&mut v)?;
    Ok(v)
}
fn event(user: i64, message: i64, spam: bool) -> String {
    json!({"user_id":user,"message_id":message,"is_spam":spam}).to_string()
}
struct Peer {
    endpoint: String,
    seen: Arc<Mutex<Vec<Value>>>,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<()>,
}
impl Peer {
    async fn start(
        owner: Arc<tokio_postgres::Client>,
        mutation: &str,
        status: u16,
        modified: &'static str,
    ) -> Result<Self, BoxError> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let endpoint = format!("http://{}", listener.local_addr()?);
        let seen = Arc::new(Mutex::new(Vec::new()));
        let calls = seen.clone();
        let mutation = mutation.to_string();
        let (stop, mut stopped) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            loop {
                let accepted = tokio::select! {_=&mut stopped=>break,v=listener.accept()=>v};
                let Ok((stream, _)) = accepted else { break };
                let calls = calls.clone();
                let owner = owner.clone();
                let mutation = mutation.clone();
                // One request per connection; production clients close their response before the next GET.
                let service = service_fn(move |request: Request<Incoming>| {
                    let calls = calls.clone();
                    let owner = owner.clone();
                    let mutation = mutation.clone();
                    async move {
                        let checked =
                            common::s3::observe(&request, &[]).expect("signed S3 request");
                        calls.lock().unwrap().push(json!({"method":checked["method"],"uri":checked["uri"],"body":checked["body"],"scope":checked["scope"],"signature_valid":checked["signature_valid"]}));
                        if !mutation.is_empty() {
                            owner.batch_execute(&mutation).await.unwrap();
                        }
                        let body = if status == 404 {
                            "<Error><Code>NoSuchKey</Code><Message>missing</Message></Error>"
                        } else {
                            RAW
                        };
                        let mut response = Response::builder()
                            .status(status)
                            .header("Content-Length", body.len())
                            .header("Last-Modified", modified)
                            .header("ETag", "\"oracle\"")
                            .header("Connection", "close");
                        if status == 206 {
                            response = response.header(
                                "Content-Range",
                                format!("bytes 0-{}/{}", body.len() - 1, body.len()),
                            );
                        }
                        Ok::<_, Infallible>(
                            response
                                .body(Full::new(bytes::Bytes::from_static(body.as_bytes())))
                                .unwrap(),
                        )
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            }
        });
        Ok(Self {
            endpoint,
            seen,
            stop: Some(stop),
            task,
        })
    }
    async fn close(mut self) -> Vec<Value> {
        let _ = self.stop.take().unwrap().send(());
        self.task.await.unwrap();
        self.seen.lock().unwrap().clone()
    }
}

async fn seed(c: &tokio_postgres::Client) -> Result<fixture::Account, BoxError> {
    c.batch_execute(&format!("BEGIN; INSERT INTO domains(id,name,is_local) VALUES({DOMAIN},'mailsec3b-oracle.test',true); INSERT INTO users(id,username,domain_id,email,display_name,password_hash) VALUES({USER},'trainer@mailsec3b-oracle.test',{DOMAIN},'trainer@mailsec3b-oracle.test','trainer','x'); INSERT INTO mailboxes(id,user_id,domain_id,email,display_name,type,is_primary) VALUES({MAILBOX},{USER},{DOMAIN},'trainer@mailsec3b-oracle.test','trainer','personal',true); COMMIT;")).await?;
    c.batch_execute(&format!("INSERT INTO messages(id,mailbox_id,folder_id,message_id,subject,from_addr,size_bytes,thread_id,raw_ref,received_at) VALUES({MESSAGE},{MAILBOX},(SELECT id FROM tags WHERE mailbox_id={MAILBOX} AND name='Inbox'),'<spam-trainer@oracle.test>','spam','sender@example.test',100,'spam-trainer','inbound/raw','2026-11-01');")).await?;
    Ok(fixture::Account {
        domain: DOMAIN,
        user: USER,
        mailbox: MAILBOX,
        inbox: 0,
        label: 0,
        two_labels: MESSAGE,
        inbox_only: MESSAGE,
    })
}

const CASES: &[&str] = &[
    "cold",
    "warm",
    "placeholder",
    "disabled",
    "corrupt",
    "foreign-seal",
    "negative-n",
    "nan",
    "foreign-message",
    "missing-message",
    "missing-object",
    "inline",
    "flip-cancels",
    "same-label-deduplicates",
    "malformed",
    "empty-features",
    "reset-fence",
    "disable-fence",
    "competing-save-fence",
    "cold-disable-fence",
    "cold-competing-fence",
    "batch-overflow",
    "warm-statistics",
    "partial-object",
    "invalid-object-date",
    "unexpected-object-status",
    "legacy-object-date",
];

async fn prepare(c: &tokio_postgres::Client, name: &str) -> Result<(), BoxError> {
    c.execute("DELETE FROM user_spam_model WHERE user_id=$1", &[&USER])
        .await?;
    c.execute(
        "UPDATE messages SET raw_ref='inbound/raw' WHERE id=$1 AND mailbox_id=$2",
        &[&MESSAGE, &MAILBOX],
    )
    .await?;
    if matches!(
        name,
        "warm"
            | "warm-statistics"
            | "disabled"
            | "foreign-seal"
            | "negative-n"
            | "nan"
            | "reset-fence"
            | "disable-fence"
            | "competing-save-fence"
    ) {
        let mut bytes = read_blob("tick-cold")?;
        match name {
            "foreign-seal" => bytes[4] ^= 1,
            "negative-n" => {
                let at = 16 + (1 << 20) * 16;
                bytes[at..at + 8].copy_from_slice(&(-1f64).to_le_bytes());
            }
            "nan" => bytes[16..24].copy_from_slice(&f64::NAN.to_le_bytes()),
            _ => {}
        }
        c.execute("INSERT INTO user_spam_model(user_id,model_bytes,sample_count,trained_at,disabled) VALUES($1,$2,7,'2026-01-01',$3)", &[&USER, &bytes, &(name=="disabled")]).await?;
    } else if matches!(name, "placeholder" | "corrupt") {
        let bytes = if name == "corrupt" {
            vec![1u8, 2]
        } else {
            vec![]
        };
        c.execute(
            "INSERT INTO user_spam_model(user_id,model_bytes,sample_count) VALUES($1,$2,0)",
            &[&USER, &bytes],
        )
        .await?;
    }
    if name == "warm-statistics" {
        c.execute("UPDATE user_spam_model SET fp_count=11,fn_count=13,classified_count=17 WHERE user_id=$1", &[&USER]).await?;
    }
    if matches!(name, "inline" | "empty-features") {
        let raw = if name == "inline" {
            RAW
        } else {
            "Message-Id:\nDate:\n\n"
        };
        c.execute(
            "UPDATE messages SET raw_ref=$1 WHERE id=$2 AND mailbox_id=$3",
            &[&raw, &MESSAGE, &MAILBOX],
        )
        .await?;
    }
    if name == "batch-overflow" {
        c.batch_execute(&format!("INSERT INTO messages(id,mailbox_id,folder_id,message_id,subject,from_addr,size_bytes,thread_id,raw_ref,received_at) SELECT {MESSAGE}+100+i,{MAILBOX},(SELECT id FROM tags WHERE mailbox_id={MAILBOX} AND name='Inbox'),'<spam-'||i||'@oracle.test>','spam','sender@example.test',100,'spam-trainer','inbound/raw','2026-11-01'::timestamptz FROM generate_series(1,101) i;")).await?;
    }
    Ok(())
}

fn mutation(name: &str) -> String {
    match name {
        "reset-fence" => format!("DELETE FROM user_spam_model WHERE user_id={USER}"),
        "disable-fence" => format!("UPDATE user_spam_model SET disabled=true WHERE user_id={USER}"),
        "competing-save-fence" => {
            format!("UPDATE user_spam_model SET model_bytes='\\x1234' WHERE user_id={USER}")
        }
        "cold-disable-fence" => format!(
            "INSERT INTO user_spam_model(user_id,model_bytes,disabled) VALUES({USER},'\\x',true)"
        ),
        "cold-competing-fence" => {
            format!("INSERT INTO user_spam_model(user_id,model_bytes) VALUES({USER},'\\x1234')")
        }
        _ => String::new(),
    }
}

fn payloads(name: &str) -> Vec<String> {
    let base = event(
        if name == "foreign-message" {
            USER + 1
        } else {
            USER
        },
        if name == "missing-message" {
            MESSAGE + 1
        } else {
            MESSAGE
        },
        name != "warm",
    );
    match name {
        "batch-overflow" => (1..=101)
            .map(|i| event(USER, MESSAGE + 100 + i, true))
            .collect(),
        "flip-cancels" => vec![base, event(USER, MESSAGE, false)],
        "same-label-deduplicates" => vec![base.clone(), base],
        "malformed" => vec!["{".into(), "{\"user_id\":\"bad\"}".into()],
        _ => vec![base],
    }
}

async fn advance(db: &Db, peer: &Peer, name: &str, recording: bool) -> Result<(), BoxError> {
    let payloads = payloads(name);
    if recording {
        let tick = GoTick {
            package: "internal/spam",
            overlay: "spam_trainer_tick_test.go.txt",
            test: "TestGoFreeSpamTrainerTick",
            file: "gofree_spam_trainer_tick_test.go",
            env: vec![
                ("GOFREE_DRAIN_DSN".into(), db.dsn.clone()),
                (
                    "GOFREE_SPAM_S3".into(),
                    peer.endpoint.trim_start_matches("http://").to_owned(),
                ),
                (
                    "GOFREE_SPAM_EVENTS".into(),
                    serde_json::to_string(&payloads)?,
                ),
                (
                    "GOFREE_SPAM_SECOND_TICK".into(),
                    if name == "batch-overflow" { "1" } else { "0" }.into(),
                ),
            ],
            docker: vec![],
        };
        tokio::task::spawn_blocking(move || tick.run()).await??;
    } else {
        let store = S3Store::new(&peer.endpoint, "mail", "test-access", "test-secret")?
            .with_region("us-east-1".into());
        let mut trainer = SpamTrainer::new(WorkerDatabase::new(&db.dsn)?, Some(store));
        for p in &payloads {
            trainer.on_notification(p);
        }
        trainer.tick().await;
        if name == "batch-overflow" {
            trainer.tick().await;
        }
    }
    Ok(())
}

async fn snapshot(
    c: &tokio_postgres::Client,
    name: &str,
    recording: bool,
    io: Vec<Value>,
) -> Result<Value, BoxError> {
    let rows=c.query("SELECT model_bytes,sample_count,disabled,trained_at>'2026-01-02',fp_count,fn_count,classified_count FROM user_spam_model WHERE user_id=$1", &[&USER]).await?;
    let row = if let Some(r) = rows.first() {
        let bytes: Vec<u8> = r.get(0);
        if recording {
            let path = root().join(format!("tick-{name}.gz"));
            let mut z = GzEncoder::new(
                std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(path)?,
                Compression::default(),
            );
            z.write_all(&bytes)?;
            z.finish()?;
        } else {
            assert!(
                bytes == read_blob(&format!("tick-{name}"))?,
                "{name}: entire sealed blob differs"
            );
        }
        let mut row = json!({"sha256":format!("{:x}",Sha256::digest(&bytes)),"bytes":bytes.len(),"sample_count":r.get::<_,i32>(1),"disabled":r.get::<_,bool>(2),"trained":r.get::<_,Option<bool>>(3)});
        let statistics = [r.get::<_, i64>(4), r.get::<_, i64>(5), r.get::<_, i64>(6)];
        if name == "warm-statistics" {
            row["statistics"] = json!(statistics);
        } else {
            assert_eq!(
                statistics,
                [0, 0, 0],
                "{name}: classification statistics changed"
            );
        }
        row
    } else {
        Value::Null
    };
    Ok(json!({"row":row,"s3":io}))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn frozen_go_spam_trainer_seed_plus_one_tick() -> Result<(), BoxError> {
    let Some(db) = Db::for_case("spam-trainer") else {
        return Ok(());
    };
    let owner = Arc::new(db.connect().await?);
    let account = seed(&owner).await?;
    let recording = std::env::var_os("GOFREE_RECORD_SPAM").is_some();
    let only = std::env::var("GOFREE_SPAM_ONLY").ok();
    let result=async {
        let mut ran=0;
        for &name in CASES {
            // Selection is recording-only; normal replay always checks every case.
            if recording && only.as_deref().is_some_and(|s| !s.split(',').any(|n|n==name)) {continue;}
            ran+=1;
            prepare(&owner,name).await?;
            let status=match name {"missing-object"=>404,"partial-object"=>206,"unexpected-object-status"=>204,_=>200};
            let modified=match name {"invalid-object-date"=>"invalid","legacy-object-date"=>"Tue, 2 Nov 26 0:00:00,123 GMT",_=>"Mon, 02 Nov 2026 00:00:00 GMT"};
            let peer=Peer::start(owner.clone(), &mutation(name), status, modified).await?;
            let advanced=advance(&db,&peer,name,recording).await;
            let io=peer.close().await;
            advanced?;
            let observation=snapshot(&owner,name,recording,io).await?;
            let path=root().join(format!("tick-{name}.json"));
            if recording {
                setjoin_conformance::golden::record(&path,&json!({"go_source":std::env::var("GOFREE_GO_SOURCE")?,"observation":observation}))?;
            } else {
                let golden:Value=serde_json::from_slice(&std::fs::read(path)?)?;
                setjoin_conformance::golden::compare(&golden["observation"],&observation)?;
                println!("GOLDEN-REPLAY: spam-trainer :: {name}");
            }
        }
        if ran==0 {return Err("no recording case selected".into());}
        Ok::<_,BoxError>(())
    }.await;
    fixture::remove(&owner, &account).await?;
    result
}
