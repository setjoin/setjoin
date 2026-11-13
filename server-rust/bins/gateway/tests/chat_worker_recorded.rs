//! #268: actual frozen-Go one-tick worker effects, replayed without Go.
mod common;
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
use common::BoxError;
use serde_json::{json, Value};
use setjoin_conformance::harness::Db;

#[tokio::test]
async fn unfurl_reap_tick() -> Result<(), BoxError> {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(db) = Db::for_case("chat3-unfurl-reap") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let prefix = format!("gofree-chat3-reap-{}", std::process::id());
    use sha2::{Digest, Sha256};
    let blob = format!("{:x}", Sha256::digest(format!("{prefix}-blob")));
    let hashes = (0..4)
        .map(|i| format!("{:x}", Sha256::digest(format!("{prefix}-{i}"))))
        .collect::<Vec<_>>();
    owner.execute("INSERT INTO blobs(sha256,minio_ref,size_bytes,content_type,ref_count) VALUES($1,$2,3,'image/png',1)",&[&blob,&format!("mailblobs/{blob}")]).await?;
    for (i, hash) in hashes.iter().enumerate() {
        let date = if i == 3 { "2099-01-01" } else { "2000-01-01" };
        let status = if i == 1 {
            "pending"
        } else if i == 2 {
            "error"
        } else {
            "ok"
        };
        let image = if i == 0 { Some(blob.clone()) } else { None };
        owner.execute("INSERT INTO chat_link_previews(url_hash,url,status,image_blob_sha256,fetched_at) VALUES($1,$2,$3,$4,$5::text::timestamptz)",&[hash,&format!("https://{prefix}.test/{i}"),&status,&image,&date]).await?;
    }
    let result=async{
  let before=observe(&owner,&hashes,&blob).await?;
  if std::env::var_os("GOFREE_RECORD_CHAT_WORKER").is_some(){record_tick(&db)?;}else{
   setjoin_chat::workers::reap(&setjoin_pg::workers::WorkerDatabase::new(&db.dsn)?).await?;
  }
  let after=observe(&owner,&hashes,&blob).await?;
  let observation=json!({"before":before,"after":after});
  let path=std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/conformance/chat-b/goldens/worker-unfurl-reap.json");
  if std::env::var_os("GOFREE_RECORD_CHAT_WORKER").is_some(){
   if after["previews"]!=json!([{"index":3,"status":"ok"}])||after["refCount"]!=0||after["cleanupQueued"]!=true{return Err(format!("unexpected Go eviction effects: {after}").into());}
   setjoin_conformance::golden::record(&path,&json!({"format":1,"case":"worker-unfurl-reap","go_source":std::env::var("GOFREE_GO_SOURCE")?,"observation":observation}))?;
  }else{let golden:Value=serde_json::from_slice(&std::fs::read(path)?)?;setjoin_conformance::golden::compare(&golden["observation"],&observation)?;}
  Ok::<_,BoxError>(())
 }.await;
    for hash in &hashes {
        owner
            .execute("DELETE FROM chat_link_previews WHERE url_hash=$1", &[hash])
            .await?;
    }
    owner
        .execute(
            "DELETE FROM blob_cleanup_queue WHERE blob_sha256=$1",
            &[&blob],
        )
        .await?;
    owner
        .execute("DELETE FROM blobs WHERE sha256=$1", &[&blob])
        .await?;
    result
}
async fn observe(
    owner: &tokio_postgres::Client,
    hashes: &[String],
    blob: &str,
) -> Result<Value, BoxError> {
    let mut previews = Vec::new();
    for (i, hash) in hashes.iter().enumerate() {
        if let Some(row) = owner
            .query_opt(
                "SELECT status FROM chat_link_previews WHERE url_hash=$1",
                &[hash],
            )
            .await?
        {
            previews.push(json!({"index":i,"status":row.get::<_,String>(0)}));
        }
    }
    let refs: i32 = owner
        .query_one("SELECT ref_count FROM blobs WHERE sha256=$1", &[&blob])
        .await?
        .get(0);
    let queued: bool = owner
        .query_one(
            "SELECT EXISTS(SELECT 1 FROM blob_cleanup_queue WHERE blob_sha256=$1)",
            &[&blob],
        )
        .await?
        .get(0);
    Ok(json!({"previews":previews,"refCount":refs,"cleanupQueued":queued}))
}
fn record_tick(db: &Db) -> Result<(), BoxError> {
    use std::io::Write;
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()?;
    let prefix = std::env::var("GOFREE_RESOURCE_PREFIX").unwrap_or_else(|_| "gofree-chat3".into());
    let folder = root.join(format!("test-results/{prefix}"));
    std::fs::create_dir_all(&folder)?;
    let overlay = folder.join("worker-overlay.json");
    std::fs::write(
        &overlay,
        serde_json::to_vec(
            &json!({"Replace":{"/src/mailserver/internal/chat/gofree_chat3_tick_test.go":"/src/server-rust/tests/conformance/chat-b/unfurl_tick_test.go.txt"}}),
        )?,
    )?;
    let name = format!("{prefix}-worker-oracle-{}", std::process::id());
    if let Ok(ledger) = std::env::var("GOFREE_RESOURCE_LEDGER") {
        writeln!(std::fs::OpenOptions::new().append(true).open(ledger)?,"Planned {name}, local Docker context, shared Go build/module caches retained; assigned DB only; --rm")?;
    }
    let output = std::process::Command::new("docker")
        .args([
            "run",
            "--rm",
            "--name",
            &name,
            "--label",
            &format!("org.setjoin.task={prefix}"),
            "--network",
            "host",
            "-v",
        ])
        .arg(format!("{}:/src", root.display()))
        .args([
            "-w",
            "/src/mailserver",
            "-v",
            &gofree_go_mod_mount(),
            "-v",
            &gofree_go_build_mount(),
            "-e",
        ])
        .arg(format!("GOFREE_CHAT_WORKER_DSN={}", db.dsn))
        .args([
            "-e",
            "GOMAXPROCS=1",
            "-e",
            "GOGC=20",
            "-e",
            "GOMEMLIMIT=768MiB",
            "setjoin-ci-linux-tc:local-amd64",
            "go",
            "test",
            "-p=1",
            "-gcflags=github.com/microsoftgraph/msgraph-sdk-go/models=-N -l",
            "-vet=off",
            &format!("-overlay=/src/test-results/{prefix}/worker-overlay.json"),
            "./internal/chat",
            "-run",
            "^TestGoFreeChat3ReapTick$",
            "-count=1",
        ])
        .output()?;
    std::fs::write(
        folder.join("worker-go-record.log"),
        [output.stdout.as_slice(), output.stderr.as_slice()].concat(),
    )?;
    if !output.status.success() {
        return Err("frozen Go tick failed: see worker-go-record.log".into());
    }
    Ok(())
}

fn token(user: i64) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use p256::ecdsa::{signature::Signer, SigningKey};
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let header =
        URL_SAFE_NO_PAD.encode(json!({"alg":"ES256","kid":"test-es256-1","typ":"JWT"}).to_string());
    let claims=URL_SAFE_NO_PAD.encode(json!({"uid":user,"email":"chat-oracle@test","admin":true,"perms":["chat.compliance_manage"],"typ":"access","jti":"chat3-test","fam":"chat3-test","iss":"mailserver","aud":["mailserver-gateway"],"iat":now-10,"exp":now+600}).to_string());
    let key = SigningKey::from_slice(&[0x11; 32]).unwrap();
    let sig: p256::ecdsa::Signature = key.sign(format!("{header}.{claims}").as_bytes());
    format!(
        "{header}.{claims}.{}",
        URL_SAFE_NO_PAD.encode(sig.to_bytes())
    )
}

#[tokio::test]
async fn unfurl_metadata_tick() -> Result<(), BoxError> {
    run_unfurl("metadata").await
}

#[tokio::test]
async fn unfurl_fetched_tick() -> Result<(), BoxError> {
    run_unfurl("fetch").await
}

#[tokio::test]
async fn unfurl_cached_tick() -> Result<(), BoxError> {
    run_unfurl("cached").await
}

#[tokio::test]
async fn unfurl_image_tick() -> Result<(), BoxError> {
    run_unfurl("image").await
}

#[tokio::test]
async fn unfurl_redirect_tick() -> Result<(), BoxError> {
    run_unfurl("redirect").await
}

#[tokio::test]
async fn unfurl_gzip_tick() -> Result<(), BoxError> {
    run_unfurl("gzip").await
}

#[tokio::test]
async fn unfurl_rejected_fetches_match_go() -> Result<(), BoxError> {
    for case in [
        "private_redirect",
        "userinfo_redirect",
        "redirect_cap",
        "bad_type",
        "oversize_html",
        "gzip_bomb",
        "dns_private",
    ] {
        run_unfurl(case).await?;
    }
    Ok(())
}

#[tokio::test]
async fn unfurl_image_failure_keeps_preview() -> Result<(), BoxError> {
    for case in [
        "image_private",
        "image_only_private",
        "image_wrong_type",
        "image_oversize",
    ] {
        run_unfurl(case).await?;
    }
    Ok(())
}

#[tokio::test]
async fn unfurl_pending_and_error_hits_are_inert() -> Result<(), BoxError> {
    for case in ["pending", "error"] {
        run_unfurl(case).await?;
    }
    Ok(())
}

async fn run_unfurl(case: &str) -> Result<(), BoxError> {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(db) = Db::for_case("chat3-unfurl") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let account = setjoin_conformance::fixture::account(&owner, "chat3-unfurl").await?;
    let channel:i64=owner.query_one("INSERT INTO chat_channels(kind,name,visibility,created_by) VALUES('channel',$1,'private',$2) RETURNING id",&[&format!("gofree-chat3-unfurl-{}",account.user),&account.user]).await?.get(0);
    owner
        .execute(
            "INSERT INTO chat_channel_members(channel_id,user_id,role) VALUES($1,$2,'owner')",
            &[&channel, &account.user],
        )
        .await?;
    let sent:String=owner.query_one("SELECT chat_message_send($1,$2,$3,NULL,'{}'::bigint[],NULL,'[]'::jsonb,'text',NULL)::text",&[&account.user,&channel,&"worker message"]).await?.get(0);
    let message = serde_json::from_str::<Value>(&sent)?["messageId"]
        .as_i64()
        .ok_or("message ID")?;
    let mut listener = db.listen(&format!("chat:{}", account.user)).await?;
    let requests = std::sync::Arc::new(std::sync::Mutex::new(Vec::<Value>::new()));
    let seen = requests.clone();
    let inert = matches!(case, "pending" | "error");
    let rejected = matches!(
        case,
        "private_redirect"
            | "userinfo_redirect"
            | "redirect_cap"
            | "bad_type"
            | "oversize_html"
            | "gzip_bomb"
            | "dns_private"
    );
    let html=if case=="image_private"{r#"<title>Picture article</title><meta property="og:image" content="http://127.0.0.1:9/private">"#}else if case=="image_only_private"{r#"<meta property="og:image" content="http://127.0.0.1:9/private">"#}else if matches!(case,"image"|"image_wrong_type"|"image_oversize"){r#"<title>Picture article</title><meta property="og:image" content="/cover.png">"#}else if case=="metadata"{r#"<title>Fallback</title><script>"<meta property='og:title' content='script'>"</script><!--<meta property='og:title' content='comment'>--><meta property="og:title" content="wrong" content=" Named &amp; title "><meta name="description" content="First brief"><meta property="og:description" content="Ignored second">"#}else{"<title>Fetched title</title>"}.to_owned();
    let image_oversize = case == "image_oversize";
    let image_wrong_type = case == "image_wrong_type";
    let peer = common::fake_upstream(move |request| {
        let seen = seen.clone();
        let html = html.clone();
        async move {
            seen.lock()
                .unwrap()
                .push(json!({"method":request.method().as_str(),"uri":request.uri().to_string()}));
            let path = request.uri().path();
            if path.starts_with("/private_redirect/")
                || path.starts_with("/userinfo_redirect/")
                || path.starts_with("/redirect_cap/")
            {
                let location = if path.starts_with("/private_redirect/") {
                    "http://127.0.0.1:9/private"
                } else if path.starts_with("/userinfo_redirect/") {
                    "http://user:pass@page.test/private"
                } else {
                    "/redirect_cap/again"
                };
                return hyper::Response::builder()
                    .status(302)
                    .header("location", location)
                    .body(common::full(""))
                    .unwrap();
            }
            if path.starts_with("/bad_type/") {
                return hyper::Response::builder()
                    .header("content-type", "application/json")
                    .body(common::full("{}"))
                    .unwrap();
            }
            let html = if path.starts_with("/oversize_html/") || path.starts_with("/gzip_bomb/") {
                format!("<title>Large</title>{}", "x".repeat((2 << 20) + 1))
            } else {
                html
            };
            if request.uri().path().starts_with("/gzip/")
                || request.uri().path().starts_with("/gzip_bomb/")
            {
                use std::io::Write;
                let mut gzip =
                    flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
                gzip.write_all(html.as_bytes()).unwrap();
                return hyper::Response::builder()
                    .header("content-type", "text/html")
                    .header("content-encoding", "gzip")
                    .body(common::full(gzip.finish().unwrap()))
                    .unwrap();
            }
            if request.uri().path().starts_with("/redirect/") {
                return hyper::Response::builder()
                    .status(302)
                    .header("location", "/article")
                    .body(common::full(""))
                    .unwrap();
            }
            if request.uri().path() == "/cover.png" {
                return hyper::Response::builder()
                    .header(
                        "content-type",
                        if image_wrong_type {
                            "text/plain"
                        } else {
                            "image/png"
                        },
                    )
                    .body(common::full(if image_oversize {
                        vec![b'x'; (5 << 20) + 1]
                    } else {
                        b"chat4-image-bytes".to_vec()
                    }))
                    .unwrap();
            }
            hyper::Response::builder()
                .header("content-type", "text/html")
                .body(common::full(html))
                .unwrap()
        }
    })
    .await;
    let storage = std::sync::Arc::new(std::sync::Mutex::new(Vec::<Value>::new()));
    let stored = storage.clone();
    let s3 = common::fake_upstream(move |request| {
        let stored=stored.clone();
        async move {
            use http_body_util::BodyExt;
            let (parts,body)=request.into_parts();
            let bytes=body.collect().await.unwrap().to_bytes();
            let request=hyper::Request::from_parts(parts,());
            let observed=common::s3::observe(&request,&bytes).unwrap();
            stored.lock().unwrap().push(json!({"method":observed["method"],"uri":observed["uri"],"body":observed["body"],"contentType":if request.method()==hyper::Method::PUT {request.headers().get("content-type").map(|v|v.to_str().unwrap())}else{None},"signatureValid":observed["signature_valid"]}));
            hyper::Response::builder().header("content-type","application/xml").header("etag","\"chat4-image\"").body(common::full(if request.method()==hyper::Method::GET {"<LocationConstraint>us-east-1</LocationConstraint>"}else{""})).unwrap()
        }
    }).await;
    let host = if case == "dns_private" {
        "localhost"
    } else {
        "page.test"
    };
    let url = format!("http://{host}:{}/{case}/{}", peer.port(), account.user);
    use sha2::{Digest, Sha256};
    let hash = format!("{:x}", Sha256::digest(url.as_bytes()));
    let old: std::collections::BTreeSet<String> = owner
        .query(
            "SELECT operation_id::text FROM rust_operation_receipts WHERE family='F12'",
            &[],
        )
        .await?
        .into_iter()
        .map(|r| r.get(0))
        .collect();
    if matches!(case, "cached" | "pending" | "error") {
        let status = if case == "cached" { "ok" } else { case };
        owner.execute("INSERT INTO chat_link_previews(url_hash,url,title,description,status) VALUES($1,$2,'Cached title','Cached description',$3)",&[&hash,&url,&status]).await?;
    }
    let result=async{
  if std::env::var_os("GOFREE_RECORD_CHAT_WORKER").is_some(){record_unfurl(&db,peer,s3,message,&url,case=="dns_private").await?;}else{
   let exec=setjoin_pg::ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn),1).map_err(|e|e.0)?.with_audit_keys("22".repeat(32),String::new());
   let mut headers=hyper::HeaderMap::new();headers.insert("host","mail.test".parse()?);headers.insert("origin","http://mail.test".parse()?);headers.insert("authorization",format!("Bearer {}",token(account.user)).parse()?);
   let actor=setjoin_authz::authorize_request(&exec,&common::recovery_keys(),"mailserver",&headers,"http").await.ok_or("verified worker actor")?;
   let client=reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).no_proxy().resolve("page.test",peer).build()?;
   let store=std::sync::Arc::new(setjoin_gateway::recovery_worker::S3Store::new(&format!("http://{s3}"),"mailblobs","test-access","test-secret")?);
   let unfurl=if case=="dns_private" {setjoin_gateway::chat_unfurl::Unfurl::production(exec,store)}else{setjoin_gateway::chat_unfurl::Unfurl::new(exec,store,client)};
   unfurl.process(actor.context(),message,&url).await;
  }
  if std::env::var_os("GOFREE_RECORD_CHAT_WORKER").is_none() {
   let previous:Vec<String>=old.iter().cloned().collect();
   let receipts:Vec<String>=owner.query("SELECT command FROM rust_operation_receipts WHERE family='F12' AND NOT(operation_id::text=ANY($1)) ORDER BY command",&[&previous]).await?.iter().map(|r|r.get(0)).collect();
   let expected=if inert {vec![]}else if rejected {vec!["chat_link_preview_cache_write","chat_link_preview_claim"]}else{match case {
    "cached"=>vec!["chat_message_unfurl_apply"],
    "image"=>vec!["chat_link_preview_cache_write","chat_link_preview_claim","chat_message_unfurl_apply","chat_unfurl_blob_insert"],
    _=>vec!["chat_link_preview_cache_write","chat_link_preview_claim","chat_message_unfurl_apply"],
   }};
   assert_eq!(receipts,expected,"separate committed unfurl transactions remain receipted");
  }
  let raw:String=owner.query_one("SELECT jsonb_build_object('payload',payload,'seq',seq,'changeSeq',(SELECT change_seq FROM chat_channels WHERE id=$2))::text FROM chat_messages WHERE id=$1 AND channel_id=$2",&[&message,&channel]).await?.get(0);
  let preview=owner.query_opt("SELECT jsonb_build_object('status',status,'title',title,'description',description,'image',image_blob_sha256)::text FROM chat_link_previews WHERE url_hash=$1",&[&hash]).await?.map(|r|serde_json::from_str::<Value>(r.get::<_,&str>(0))).transpose()?;
  let mut notify=listener.drain(&owner).await?.into_iter().map(|raw|serde_json::from_str::<Value>(&raw)).collect::<Result<Vec<_>,_>>()?;
  for n in &mut notify{if n["channelId"]==channel{n["channelId"]="<channel>".into();}if n["messageId"]==message{n["messageId"]="<message>".into();}}
  let mut row:Value=serde_json::from_str(&raw)?;if let Some(link)=row.pointer_mut("/payload/preview/url"){*link="<url>".into();}
  let mut http=requests.lock().unwrap().clone();
  for request in &mut http{if let Some(uri)=request["uri"].as_str(){request["uri"]=uri.replace(&format!("/{account_id}",account_id=account.user),"/<actor>").into();}}
  let mut observed=json!({"row":row,"preview":preview,"notify":notify,"http":http});
  if case=="image" {
   let blob=owner.query_opt("SELECT jsonb_build_object('sha256',sha256,'size',size_bytes,'contentType',content_type,'refCount',ref_count,'ref',minio_ref)::text FROM blobs WHERE sha256=(SELECT image_blob_sha256 FROM chat_link_previews WHERE url_hash=$1)",&[&hash]).await?.map(|r|serde_json::from_str::<Value>(r.get::<_,&str>(0))).transpose()?;
   observed["blob"]=json!(blob);observed["s3"]=json!(storage.lock().unwrap().clone());
  }
  let path=std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("../../tests/conformance/chat-b/goldens/worker-unfurl-{case}.json"));
  if std::env::var_os("GOFREE_RECORD_CHAT_WORKER").is_some(){
   if inert {if observed["preview"]["status"]!=case || !observed["row"]["payload"].is_null() || observed["notify"]!=json!([]) || observed["http"]!=json!([]) {return Err(format!("Go retried inert cache entry: {observed}").into())}}else if rejected {if observed["preview"]["status"]!="error" || !observed["row"]["payload"].is_null() || observed["notify"]!=json!([]){return Err(format!("Go did not reject fetch: {observed}").into());}}else if observed["row"]["payload"]["preview"]["appliedBy"]!="chat_message_unfurl_apply"{return Err(format!("Go did not enrich: {observed}").into());}
   setjoin_conformance::golden::record(&path,&json!({"format":1,"case":format!("worker-unfurl-{case}"),"go_source":std::env::var("GOFREE_GO_SOURCE")?,"observation":observed}))?;
  }else{let golden:Value=serde_json::from_slice(&std::fs::read(path)?)?;setjoin_conformance::golden::compare(&golden["observation"],&observed)?;}
  Ok::<_,BoxError>(())
 }.await;
    let image: Option<String> = owner
        .query_one(
            "SELECT (SELECT image_blob_sha256 FROM chat_link_previews WHERE url_hash=$1)",
            &[&hash],
        )
        .await?
        .get(0);
    owner
        .execute("DELETE FROM chat_link_previews WHERE url_hash=$1", &[&hash])
        .await?;
    if let Some(image) = image {
        owner
            .execute(
                "DELETE FROM blob_cleanup_queue WHERE blob_sha256=$1",
                &[&image],
            )
            .await?;
        owner
            .execute(
                "DELETE FROM blobs WHERE sha256=$1 AND ref_count=0",
                &[&image],
            )
            .await?;
    }
    owner.batch_execute(&format!("BEGIN;SET LOCAL session_replication_role=replica;DELETE FROM chat_audit_log WHERE channel_id={channel};DELETE FROM admin_audit_log WHERE user_id={};COMMIT",account.user)).await?;
    owner
        .execute("DELETE FROM chat_messages WHERE channel_id=$1", &[&channel])
        .await?;
    owner
        .execute(
            "DELETE FROM chat_channels WHERE id=$1 AND created_by=$2",
            &[&channel, &account.user],
        )
        .await?;
    for r in owner
        .query(
            "SELECT operation_id::text FROM rust_operation_receipts WHERE family='F12'",
            &[],
        )
        .await?
    {
        let id: String = r.get(0);
        if !old.contains(&id) {
            owner.execute("DELETE FROM rust_operation_receipts WHERE operation_id=$1::text::uuid AND family='F12'",&[&id]).await?;
        }
    }
    setjoin_conformance::fixture::remove(&owner, &account).await?;
    result
}

async fn record_unfurl(
    db: &Db,
    peer: std::net::SocketAddr,
    s3: std::net::SocketAddr,
    message: i64,
    url: &str,
    safe_client: bool,
) -> Result<(), BoxError> {
    use std::io::Write;
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()?;
    let prefix = std::env::var("GOFREE_RESOURCE_PREFIX").unwrap_or_else(|_| "gofree-chat3".into());
    let folder = root.join(format!("test-results/{prefix}"));
    std::fs::create_dir_all(&folder)?;
    let overlay = folder.join("unfurl-overlay.json");
    std::fs::write(
        &overlay,
        serde_json::to_vec(
            &json!({"Replace":{"/src/mailserver/internal/chat/gofree_chat3_unfurl_test.go":"/src/server-rust/tests/conformance/chat-b/unfurl_process_test.go.txt"}}),
        )?,
    )?;
    let name = format!("{prefix}-unfurl-oracle-{}", std::process::id());
    if let Ok(ledger) = std::env::var("GOFREE_RESOURCE_LEDGER") {
        writeln!(std::fs::OpenOptions::new().append(true).open(ledger)?,"Planned {name}; assigned DB, temporary overlay, shared Go caches retained; local Docker --rm")?;
    }
    let mut command = std::process::Command::new("docker");
    command
        .args([
            "run",
            "--rm",
            "--name",
            &name,
            "--label",
            &format!("org.setjoin.task={prefix}"),
            "--network",
            "host",
            "-v",
        ])
        .arg(format!("{}:/src", root.display()))
        .args([
            "-w",
            "/src/mailserver",
            "-v",
            &gofree_go_mod_mount(),
            "-v",
            &gofree_go_build_mount(),
        ]);
    for (k, v) in [
        (
            "GOFREE_CHAT_APP_DSN",
            db.app.as_deref().unwrap_or(&db.dsn).to_owned(),
        ),
        ("GOFREE_CHAT_ENCRYPTION", "22".repeat(32)),
        ("GOFREE_CHAT_PEER", peer.to_string()),
        ("GOFREE_CHAT_S3", s3.to_string()),
        ("GOFREE_CHAT_MESSAGE", message.to_string()),
        ("GOFREE_CHAT_URL", url.to_owned()),
        (
            "GOFREE_CHAT_SAFE_CLIENT",
            if safe_client { "1" } else { "0" }.into(),
        ),
        ("GOMAXPROCS", "1".into()),
        ("GOGC", "20".into()),
        ("GOMEMLIMIT", "768MiB".into()),
    ] {
        command.arg("-e").arg(format!("{k}={v}"));
    }
    if let Some(binary) = std::env::var_os("GOFREE_RECORD_CHAT_WORKER_BINARY") {
        use sha2::{Digest, Sha256};
        let binary = std::fs::canonicalize(binary)?;
        let receipt: Value =
            serde_json::from_slice(&std::fs::read(binary.with_extension("receipt.json"))?)?;
        let helper = root.join("server-rust/tests/conformance/chat-b/unfurl_process_test.go.txt");
        if receipt["helper_sha256"] != format!("{:x}", Sha256::digest(std::fs::read(helper)?))
            || receipt["binary_sha256"] != format!("{:x}", Sha256::digest(std::fs::read(&binary)?))
            || receipt["go_source"] != std::env::var("GOFREE_GO_SOURCE")?
        {
            return Err("prebuilt Go worker receipt does not match its inputs".into());
        }
        command
            .arg("setjoin-ci-linux-tc:local-amd64")
            .arg(format!("/src/{}", binary.strip_prefix(&root)?.display()))
            .args(["-test.run", "^TestGoFreeChat3UnfurlTick$", "-test.count=1"]);
    } else {
        command.args([
            "setjoin-ci-linux-tc:local-amd64",
            "go",
            "test",
            "-p=1",
            "-gcflags=github.com/microsoftgraph/msgraph-sdk-go/models=-N -l",
            "-vet=off",
            &format!("-overlay=/src/test-results/{prefix}/unfurl-overlay.json"),
            "./internal/chat",
            "-run",
            "^TestGoFreeChat3UnfurlTick$",
            "-count=1",
        ]);
    }
    // Keep the Tokio reactor serving the real fake peripheral peers during Go's tick.
    let output = tokio::task::spawn_blocking(move || command.output()).await??;
    std::fs::write(
        folder.join("unfurl-go-record.log"),
        [output.stdout.as_slice(), output.stderr.as_slice()].concat(),
    )?;
    if !output.status.success() {
        return Err("Go unfurl worker failed: see unfurl-go-record.log".into());
    }
    Ok(())
}

#[tokio::test]
async fn unfurl_reaper_waits_for_hourly_tick() -> Result<(), BoxError> {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if std::env::var_os("GOFREE_RECORD_CHAT_WORKER").is_some() {
        return Err("cadence contract never records".into());
    }
    let Some(db) = Db::for_case("chat3-reap-cadence") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    use sha2::{Digest, Sha256};
    let expired = format!(
        "{:x}",
        Sha256::digest(format!("gofree-chat3-expired-{}", std::process::id()))
    );
    let fresh = format!(
        "{:x}",
        Sha256::digest(format!("gofree-chat3-fresh-{}", std::process::id()))
    );
    for (hash, date) in [(&expired, "2000-01-01"), (&fresh, "2099-01-01")] {
        owner.execute("INSERT INTO chat_link_previews(url_hash,url,status,fetched_at) VALUES($1,$2,'pending',$3::text::timestamptz)",&[hash,&format!("https://gofree-chat3.test/{hash}"),&date]).await?;
    }
    tokio::time::pause();
    // Keep the reactor runnable while querying PostgreSQL: only explicit advance
    // moves this clock, rather than Tokio's automatic idle-time advancement.
    let keeper = tokio::spawn(async {
        loop {
            tokio::task::yield_now().await;
        }
    });
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let reaper = setjoin_gateway::chat_workers::UnfurlReaper::new(
        setjoin_pg::workers::WorkerDatabase::new(&db.dsn)?,
    );
    let task = tokio::spawn(reaper.run_until(async move {
        let _ = stopped.await;
    }));
    let result = async {
        tokio::task::yield_now().await;
        if !preview_exists(&owner, &expired).await? {
            return Err("reaper ran at startup".into());
        }
        tokio::time::advance(std::time::Duration::from_secs(3599)).await;
        if !preview_exists(&owner, &expired).await? {
            return Err("reaper ran before the hour".into());
        }
        // Tokio rounds timer deadlines to milliseconds; pass the boundary by one.
        tokio::time::advance(std::time::Duration::from_millis(1001)).await;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while preview_exists(&owner, &expired).await? {
            if std::time::Instant::now() > deadline {
                return Err("hourly reaper did not run".into());
            }
            tokio::task::yield_now().await;
        }
        if !preview_exists(&owner, &fresh).await? {
            return Err("hourly reaper deleted a fresh preview".into());
        }
        Ok::<_, BoxError>(())
    }
    .await;
    let _ = stop.send(());
    let joined = task.await;
    keeper.abort();
    let _ = keeper.await;
    tokio::time::resume();
    owner
        .execute(
            "DELETE FROM chat_link_previews WHERE url_hash=ANY($1::text[])",
            &[&vec![expired, fresh]],
        )
        .await?;
    joined?;
    result
}
async fn preview_exists(c: &tokio_postgres::Client, hash: &str) -> Result<bool, BoxError> {
    Ok(
        c.query_one("SELECT chat_link_preview_lookup($1) IS NOT NULL", &[&hash])
            .await?
            .get(0),
    )
}

/// Host Go module cache for the Go recorder container (GOFREE_GO_MOD_CACHE, default $HOME/go/pkg/mod).
#[allow(dead_code)]
fn gofree_go_mod_mount() -> String {
    let host = std::env::var("GOFREE_GO_MOD_CACHE").unwrap_or_else(|_| {
        format!(
            "{}/go/pkg/mod",
            std::env::var("HOME").unwrap_or_else(|_| "/root".into())
        )
    });
    format!("{host}:/root/go/pkg/mod")
}

/// Host Go build cache for the Go recorder container (GOFREE_GO_BUILD_CACHE, default $HOME/.cache/go-build).
#[allow(dead_code)]
fn gofree_go_build_mount() -> String {
    let host = std::env::var("GOFREE_GO_BUILD_CACHE").unwrap_or_else(|_| {
        format!(
            "{}/.cache/go-build",
            std::env::var("HOME").unwrap_or_else(|_| "/root".into())
        )
    });
    format!("{host}:/root/.cache/go-build")
}
