//! #268: Part B HTTP parity, constrained app credential and real committed effects.
mod common;
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
#[path = "common/office_s3.rs"]
mod image_s3;
use common::BoxError;
use hyper::{Request, Response};
use serde_json::{json, Value};
use setjoin_conformance::harness::Db;
use setjoin_gateway::{Config, Gateway, RouteTable, TrustedProxies};

#[tokio::test]
async fn saves_success() -> Result<(), BoxError> {
    run("saves", "success").await
}

#[tokio::test]
async fn native_saves_contract() -> Result<(), BoxError> {
    run("saves", "contract").await
}

#[tokio::test]
async fn native_save_toggle_contract() -> Result<(), BoxError> {
    run("save", "contract").await
}

#[tokio::test]
async fn native_thread_contract() -> Result<(), BoxError> {
    run("thread", "contract").await
}

#[tokio::test]
async fn native_my_threads_contract() -> Result<(), BoxError> {
    run("my-threads", "contract").await
}

#[tokio::test]
async fn native_search_contract() -> Result<(), BoxError> {
    run("search", "contract").await
}

#[tokio::test]
async fn native_han_search_contract() -> Result<(), BoxError> {
    run("search", "han-contract").await
}

#[tokio::test]
async fn saves_foreign() -> Result<(), BoxError> {
    run("saves", "foreign").await
}
#[tokio::test]
async fn saves_invalid() -> Result<(), BoxError> {
    run("saves", "invalid").await
}

#[tokio::test]
async fn thread_success() -> Result<(), BoxError> {
    run("thread", "success").await
}
#[tokio::test]
async fn thread_foreign() -> Result<(), BoxError> {
    run("thread", "foreign").await
}
#[tokio::test]
async fn thread_invalid() -> Result<(), BoxError> {
    run("thread", "invalid").await
}

#[tokio::test]
async fn my_threads_success() -> Result<(), BoxError> {
    run("my-threads", "success").await
}
#[tokio::test]
async fn my_threads_foreign() -> Result<(), BoxError> {
    run("my-threads", "foreign").await
}
#[tokio::test]
async fn my_threads_invalid() -> Result<(), BoxError> {
    run("my-threads", "invalid").await
}
#[tokio::test]
async fn search_success() -> Result<(), BoxError> {
    run("search", "success").await
}
#[tokio::test]
async fn search_foreign() -> Result<(), BoxError> {
    run("search", "foreign").await
}
#[tokio::test]
async fn search_invalid() -> Result<(), BoxError> {
    run("search", "invalid").await
}
#[tokio::test]
async fn search_han() -> Result<(), BoxError> {
    run("search", "han").await
}

#[tokio::test]
async fn native_edit_contract() -> Result<(), BoxError> {
    run("edit", "contract").await
}

#[tokio::test]
async fn edit_success() -> Result<(), BoxError> {
    run("edit", "success").await
}

#[tokio::test]
async fn edit_foreign() -> Result<(), BoxError> {
    run("edit", "foreign").await
}

#[tokio::test]
async fn edit_invalid() -> Result<(), BoxError> {
    run("edit", "invalid").await
}
#[tokio::test]
async fn edit_repeat() -> Result<(), BoxError> {
    run("edit", "repeat").await
}
#[tokio::test]
async fn save_success() -> Result<(), BoxError> {
    run("save", "success").await
}
#[tokio::test]
async fn save_foreign() -> Result<(), BoxError> {
    run("save", "foreign").await
}
#[tokio::test]
async fn save_invalid() -> Result<(), BoxError> {
    run("save", "invalid").await
}
#[tokio::test]
async fn save_repeat() -> Result<(), BoxError> {
    run("save", "repeat").await
}
#[tokio::test]
async fn delete_success() -> Result<(), BoxError> {
    run("delete", "success").await
}

#[tokio::test]
async fn delete_foreign() -> Result<(), BoxError> {
    run("delete", "foreign").await
}
#[tokio::test]
async fn delete_invalid() -> Result<(), BoxError> {
    run("delete", "invalid").await
}
#[tokio::test]
async fn delete_repeat() -> Result<(), BoxError> {
    run("delete", "repeat").await
}

#[tokio::test]
async fn reaction_success() -> Result<(), BoxError> {
    run("reaction", "success").await
}

#[tokio::test]
async fn reaction_foreign() -> Result<(), BoxError> {
    run("reaction", "foreign").await
}
#[tokio::test]
async fn reaction_invalid() -> Result<(), BoxError> {
    run("reaction", "invalid").await
}
#[tokio::test]
async fn reaction_repeat() -> Result<(), BoxError> {
    run("reaction", "repeat").await
}

#[tokio::test]
async fn pin_success() -> Result<(), BoxError> {
    run("pin", "success").await
}

#[tokio::test]
async fn pin_foreign() -> Result<(), BoxError> {
    run("pin", "foreign").await
}
#[tokio::test]
async fn pin_invalid() -> Result<(), BoxError> {
    run("pin", "invalid").await
}
#[tokio::test]
async fn pin_repeat() -> Result<(), BoxError> {
    run("pin", "repeat").await
}

#[tokio::test]
async fn scheduled_success() -> Result<(), BoxError> {
    run("scheduled", "success").await
}

#[tokio::test]
async fn scheduled_foreign() -> Result<(), BoxError> {
    run("scheduled", "foreign").await
}
#[tokio::test]
async fn scheduled_invalid() -> Result<(), BoxError> {
    run("scheduled", "invalid").await
}

#[tokio::test]
async fn cancel_success() -> Result<(), BoxError> {
    run("cancel", "success").await
}

#[tokio::test]
async fn cancel_foreign() -> Result<(), BoxError> {
    run("cancel", "foreign").await
}
#[tokio::test]
async fn cancel_invalid() -> Result<(), BoxError> {
    run("cancel", "invalid").await
}
#[tokio::test]
async fn cancel_repeat() -> Result<(), BoxError> {
    run("cancel", "repeat").await
}

#[tokio::test]
async fn poll_vote_success() -> Result<(), BoxError> {
    run("poll_vote", "success").await
}
#[tokio::test]
async fn poll_vote_foreign() -> Result<(), BoxError> {
    run("poll_vote", "foreign").await
}
#[tokio::test]
async fn poll_vote_invalid() -> Result<(), BoxError> {
    run("poll_vote", "invalid").await
}
#[tokio::test]
async fn poll_vote_repeat() -> Result<(), BoxError> {
    run("poll_vote", "repeat").await
}

#[tokio::test]
async fn poll_close_success() -> Result<(), BoxError> {
    run("poll_close", "success").await
}
#[tokio::test]
async fn poll_close_foreign() -> Result<(), BoxError> {
    run("poll_close", "foreign").await
}
#[tokio::test]
async fn poll_close_invalid() -> Result<(), BoxError> {
    run("poll_close", "invalid").await
}
#[tokio::test]
async fn poll_close_repeat() -> Result<(), BoxError> {
    run("poll_close", "repeat").await
}

#[tokio::test]
async fn poll_results_success() -> Result<(), BoxError> {
    run("poll_results", "success").await
}
#[tokio::test]
async fn poll_results_foreign() -> Result<(), BoxError> {
    run("poll_results", "foreign").await
}
#[tokio::test]
async fn poll_results_invalid() -> Result<(), BoxError> {
    run("poll_results", "invalid").await
}

#[tokio::test]
async fn image_success() -> Result<(), BoxError> {
    run("image", "success").await
}
#[tokio::test]
async fn image_foreign() -> Result<(), BoxError> {
    run("image", "foreign").await
}
#[tokio::test]
async fn image_invalid() -> Result<(), BoxError> {
    run("image", "invalid").await
}

#[tokio::test]
async fn image_large() -> Result<(), BoxError> {
    run("image", "large").await
}
#[tokio::test]
async fn image_head() -> Result<(), BoxError> {
    run("image", "head").await
}
#[tokio::test]
async fn image_no_cache() -> Result<(), BoxError> {
    run("image", "no_cache").await
}
#[tokio::test]
async fn image_storage_missing() -> Result<(), BoxError> {
    run("image", "storage_missing").await
}
#[tokio::test]
async fn image_range() -> Result<(), BoxError> {
    run("image", "range").await
}

#[tokio::test]
async fn saves_raw_number() -> Result<(), BoxError> {
    run("saves", "raw_number").await
}

#[tokio::test]
async fn edit_trailing() -> Result<(), BoxError> {
    run("edit", "trailing").await
}
#[tokio::test]
async fn edit_null() -> Result<(), BoxError> {
    run("edit", "null").await
}
#[tokio::test]
async fn edit_oversize() -> Result<(), BoxError> {
    run("edit", "oversize").await
}
#[tokio::test]
async fn edit_unicode() -> Result<(), BoxError> {
    run("edit", "unicode").await
}

#[tokio::test]
async fn poll_vote_duplicate_null() -> Result<(), BoxError> {
    run("poll_vote", "duplicate_null").await
}
#[tokio::test]
async fn poll_vote_invalid_json() -> Result<(), BoxError> {
    run("poll_vote", "invalid_json").await
}

#[tokio::test]
async fn thread_encoded_invalid() -> Result<(), BoxError> {
    run("thread", "encoded_invalid").await
}
#[tokio::test]
async fn saves_encoded_mount() -> Result<(), BoxError> {
    run("saves", "encoded_mount").await
}

#[tokio::test]
async fn thread_foreign_language() -> Result<(), BoxError> {
    run("thread", "foreign_language").await
}

#[tokio::test]
async fn saves_disabled() -> Result<(), BoxError> {
    run("saves", "disabled").await
}

#[tokio::test]
async fn saves_app_denied() -> Result<(), BoxError> {
    run("saves", "app_denied").await
}

#[tokio::test]
async fn saves_query_fault() -> Result<(), BoxError> {
    run("saves", "query_fault").await
}

#[tokio::test]
async fn search_bad_channel() -> Result<(), BoxError> {
    run("search", "bad_channel").await
}
#[tokio::test]
async fn search_bad_author() -> Result<(), BoxError> {
    run("search", "bad_author").await
}
#[tokio::test]
async fn search_bad_before() -> Result<(), BoxError> {
    run("search", "bad_before").await
}

#[tokio::test]
async fn image_query_fault() -> Result<(), BoxError> {
    run("image", "image_query_fault").await
}

#[tokio::test]
async fn image_storage_partial() -> Result<(), BoxError> {
    run("image", "storage_partial").await
}

#[tokio::test]
async fn image_head_large() -> Result<(), BoxError> {
    run("image", "head_large").await
}

async fn run(route: &str, case: &str) -> Result<(), BoxError> {
    run_inner(route, case, false).await
}

async fn run_inner(route: &str, case: &str, mutant: bool) -> Result<(), BoxError> {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if mutant && std::env::var_os("GOFREE_RECORD_GO_BINARY").is_some() {
        return Err("mutants never record".into());
    }
    if case.ends_with("contract") && std::env::var_os("GOFREE_RECORD_GO_BINARY").is_some() {
        return Err("native contracts cannot run in recording mode".into());
    }
    let Some(mut db) = Db::for_case("chat3") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    use sha2::{Digest, Sha256};
    let image = if matches!(case, "large" | "head_large") {
        format!(
            "<svg xmlns=\"http://www.w3.org/2000/svg\"><!--{}--></svg>",
            "x".repeat(8192)
        )
        .into_bytes()
    } else {
        br#"<svg xmlns="http://www.w3.org/2000/svg"><script>chat3</script></svg>"#.to_vec()
    };
    let image_hash = format!("{:x}", Sha256::digest(&image));

    let old_receipts: std::collections::BTreeSet<String> = owner
        .query(
            "SELECT operation_id::text FROM rust_operation_receipts WHERE family='F12'",
            &[],
        )
        .await?
        .into_iter()
        .map(|r| r.get(0))
        .collect();
    let (account, foreign) = principal_pair(&owner).await?;
    let previous: Option<bool> = owner
        .query_opt(
            "SELECT enabled FROM feature_toggles WHERE key='feature.chat'",
            &[],
        )
        .await?
        .map(|r| r.get(0));
    owner.batch_execute("INSERT INTO feature_toggles(key,enabled) VALUES('feature.chat',true) ON CONFLICT(key) DO UPDATE SET enabled=true").await?;
    let channel:i64=owner.query_one("INSERT INTO chat_channels(kind,name,created_by) VALUES('channel','chat3-oracle',$1) RETURNING id",&[&account.user]).await?.get(0);
    owner
        .execute(
            "INSERT INTO chat_channel_members(channel_id,user_id,role) VALUES($1,$2,'owner')",
            &[&channel, &account.user],
        )
        .await?;
    let audit_level = if case == "app_denied" {
        Some(
            owner
                .query_one("SELECT level FROM audit_policy WHERE id=1", &[])
                .await?
                .get::<_, String>(0),
        )
    } else {
        None
    };
    if audit_level.is_some() {
        owner
            .execute("UPDATE audit_policy SET level='full' WHERE id=1", &[])
            .await?;
    }
    let mut fault_schema = None;
    let result=async {
 owner.batch_execute(&format!("BEGIN; SELECT set_config('app.current_user_id','{}',true);",account.user)).await?;
 let seed_body=if matches!(case,"han"|"han-contract"){"聊天消息"}else{"chat3 root"};
 let seed_payload=if case=="raw_number"{Some(r#"{"n":1234567890123456789012345678901234567890,"html":"<b>&"}"#.to_string())}else{None};
 let raw:String=if route.starts_with("poll_"){owner.query_one("SELECT chat_poll_create($1,$2,'Chat3 choice',ARRAY['one','two'],false,NULL)::text",&[&account.user,&channel]).await?.get(0)}else{owner.query_one("SELECT chat_message_send($1,$2,$3,NULL,'{}',NULL,'[]','text',$4::text::jsonb)::text",&[&account.user,&channel,&seed_body,&seed_payload]).await?.get(0)};
 let poll=serde_json::from_str::<Value>(&raw)?["pollId"].as_i64();
 let options=if let Some(poll)=poll{owner.query("SELECT id FROM chat_poll_options WHERE poll_id=$1 ORDER BY ordinal",&[&poll]).await?.into_iter().map(|r|r.get::<_,i64>(0)).collect::<Vec<_>>()}else{Vec::new()};
 let message=serde_json::from_str::<Value>(&raw)?["messageId"].as_i64().ok_or("message ID absent")?;
 owner.execute("SELECT chat_save_toggle($1,$2)",&[&account.user,&message]).await?;
 let reply=if route=="my-threads" || (route=="thread" && !case.ends_with("contract")) {let raw:String=owner.query_one("SELECT chat_message_send($1,$2,'chat3 reply',$3,'{}',NULL,'[]','text',NULL)::text",&[&account.user,&channel,&message]).await?.get(0);Some(serde_json::from_str::<Value>(&raw)?["messageId"].as_i64().ok_or("reply ID missing")?)}else{None};
 if route=="poll_results" {owner.execute("SELECT chat_poll_vote($1,$2,$3)",&[&account.user,&poll.unwrap(),&options[0]]).await?;}
 let action=if matches!(route,"scheduled"|"cancel") {Some(owner.query_one("SELECT chat_schedule_message($1,$2,'scheduled chat3',NULL,'{}',NULL,'2099-01-01'::timestamptz)::text",&[&account.user,&channel]).await?.get::<_,String>(0))}else{None};
 owner.batch_execute("COMMIT").await?;
 if case=="app_denied"{owner.execute("INSERT INTO user_app_entitlements(user_id,app,enabled) VALUES($1,'chat',false)",&[&account.user]).await?;}
 if case=="disabled"{owner.execute("UPDATE feature_toggles SET enabled=false WHERE key='feature.chat'",&[]).await?;}
 if route=="image"{
  owner.execute("INSERT INTO blobs(sha256,minio_ref,size_bytes,content_type,ref_count) VALUES($1,$2,$3,'image/svg+xml',0)",&[&image_hash,&format!("mailblobs/{image_hash}"),&(image.len() as i64)]).await?;
  if case!="no_cache"{owner.execute("SELECT chat_link_preview_claim($1,'https://chat3-oracle.test/image')",&[&image_hash]).await?;
  owner.execute("SELECT chat_link_preview_cache_write($1,'title','description',$1,'ok')",&[&image_hash]).await?;}
 }
 if matches!(case,"query_fault"|"image_query_fault"){
   let name=format!("gofree_chat3_read_fault_{}",account.user);
   if let Ok(ledger)=std::env::var("GOFREE_RESOURCE_LEDGER"){use std::io::Write;writeln!(std::fs::OpenOptions::new().append(true).open(ledger)?,"Planned private read-fault schema {name}; only assigned CHAT3 database; remove after this case")?;}
   let fault=if case=="image_query_fault"{format!("CREATE FUNCTION {name}.fail_blob_type(text) RETURNS text LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'chat3 injected blob read fault' USING ERRCODE='XX000'; END $$; CREATE VIEW {name}.blobs AS SELECT sha256,{name}.fail_blob_type(content_type) AS content_type FROM public.blobs; GRANT SELECT ON {name}.blobs TO PUBLIC;")}else{format!("CREATE FUNCTION {name}.chat_saves_list(bigint) RETURNS jsonb LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'chat3 injected read fault' USING ERRCODE='XX000'; END $$;")};
   owner.batch_execute(&format!("CREATE SCHEMA {name}; GRANT USAGE ON SCHEMA {name} TO PUBLIC; {fault}")).await?;
   fault_schema=Some(name.clone());
   let base=db.app.as_deref().unwrap_or(&db.dsn);let dsn=if base.contains("://"){format!("{base}{}options=-csearch_path%3D{name}%2Cpublic",if base.contains('?'){"&"}else{"?"})}else{format!("{base} options='-csearch_path={name},public'")};db.app=Some(dsn);
 }
 let storage_events=std::sync::Arc::new(std::sync::Mutex::new(Vec::<Value>::new()));let events=storage_events.clone();
 let storage_errors=std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
 let errors=storage_errors.clone();let is_image=route=="image";
 let fake_image=image.clone();let missing=case=="storage_missing";let partial=case=="storage_partial";
 let endpoint=common::fake_upstream(move |request|{let errors=errors.clone();let image=fake_image.clone();let events=events.clone();async move{
  if !is_image{return Response::new(common::full("unused"))}
  // Frozen Go performs this independent startup inventory before serving Chat.
  // It is not an image read; give it an empty multipart inventory, as other
  // recorders do, while retaining strict signature checks on image GETs.
  if request.uri().query()==Some("delimiter=&encoding-type=url&prefix=&uploads="){return Response::new(common::full("<ListMultipartUploadsResult><Bucket>mailblobs</Bucket></ListMultipartUploadsResult>"))}
  match image_s3::observe(&request,&[]){Ok(event)=>events.lock().unwrap().push(event),Err(error)=>errors.lock().unwrap().push(format!("{} {}: {error}",request.method(),request.uri()))};
  if request.uri().query()==Some("location="){Response::new(common::full("<LocationConstraint>us-east-1</LocationConstraint>"))}
  else if missing && request.uri().path().trim_end_matches('/')!="/mailblobs"{Response::builder().status(404).header("content-type","application/xml").body(common::full("<Error><Code>NoSuchKey</Code></Error>")).unwrap()}
  else if partial && request.method()==hyper::Method::GET{
   use http_body_util::BodyExt;
   let prefix=image[..16].to_vec();
   let stream=futures_util::stream::unfold(0,move|state|{let prefix=prefix.clone();async move{match state{0=>Some((Ok::<_,BoxError>(hyper::body::Frame::data(bytes::Bytes::from(prefix))),1)),1=>{tokio::time::sleep(std::time::Duration::from_millis(50)).await;Some((Err::<hyper::body::Frame<bytes::Bytes>,BoxError>(std::io::Error::other("chat3 injected truncated S3 body").into()),2))},_=>None}}});
   Response::builder().header("content-type","image/svg+xml").header("content-length",image.len()).header("etag","\"chat3\"").header("last-modified","Sat, 31 Oct 2026 00:00:00 GMT").body(http_body_util::StreamBody::new(stream).boxed()).unwrap()
  }
  else{Response::builder().header("content-type","image/svg+xml").header("content-length",image.len()).header("etag","\"chat3\"").header("last-modified","Sat, 31 Oct 2026 00:00:00 GMT").body(common::full(if request.method()==hyper::Method::HEAD{Vec::new()}else{image.to_vec()})).unwrap()}
 }}).await;
 let oracle=common::go_oracle::start_named(&db,endpoint,None,"gofree-chat3").await?;
 let recording=oracle.is_some();
 let writes=true; // Record unchanged state for reads as well as mutations.
 let mut actor_listener=db.listen(&format!("chat:{}",account.user)).await?;
 let mut foreign_listener=db.listen(&format!("chat:{}",foreign.user)).await?;
 let before=if writes{Some(snapshot(&owner,channel,message,reply,account.user,foreign.user,route).await?)}else{None};
 let adapter=setjoin_gateway::chat_b::ChatBRoute{exec:setjoin_pg::ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn),1).map_err(|e|e.0)?.with_audit_keys("22".repeat(32),String::new()),keys:std::sync::Arc::new(common::recovery_keys()),issuer:"mailserver".into(),store:if route=="image"{Some(std::sync::Arc::new(setjoin_gateway::recovery_worker::S3Store::new(&format!("http://{endpoint}"),"mailblobs","test-access","test-secret")?))}else{None}};
 let table=if recording{RouteTable::proxy_all()}else if mutant{RouteTable::proxy_all().with(ChangedStatus(adapter))}else{RouteTable::proxy_all().with(adapter)};
 let gateway=Gateway::new(Config{upstream:oracle.as_ref().map(|o|format!("http://{}",o.address).parse()).transpose()?,trusted_proxies:TrustedProxies::parse("")?,upstream_header_timeout:setjoin_gateway::proxy::DEFAULT_HEADER_TIMEOUT,edge_limit:None},table)?;

 let listen=tokio::net::TcpListener::bind("127.0.0.1:0").await?;let address=listen.local_addr()?;let server=tokio::spawn(gateway.serve(listen));
 let (method,path)=match route {"image"=>(if matches!(case,"head"|"head_large"){"HEAD"}else{"GET"},format!("/api/chat/unfurl/image/{image_hash}")),"poll_results"=>("GET",format!("/api/chat/polls/{}/results",poll.unwrap())),"poll_close"=>("POST",format!("/api/chat/polls/{}/close",poll.unwrap())),"poll_vote"=>("POST",format!("/api/chat/polls/{}/vote",poll.unwrap())),"cancel"=>("DELETE",format!("/api/chat/scheduled/{}",action.as_ref().unwrap())),"scheduled"=>("GET","/api/chat/scheduled".into()),"pin"=>("POST",format!("/api/chat/messages/{message}/pin")),"reaction"=>("POST",format!("/api/chat/messages/{message}/reactions")),"saves"=>("GET","/api/chat/saves".to_string()),"save"=>("POST",format!("/api/chat/messages/{message}/save")),"edit"=>("PATCH",format!("/api/chat/messages/{message}")),"delete"=>("DELETE",format!("/api/chat/messages/{message}")),"thread"=>("GET",format!("/api/chat/messages/{message}/thread")),"my-threads"=>("GET","/api/chat/my-threads?limit=5".to_string()),"search"=>("GET",if matches!(case,"han"|"han-contract"){"/api/chat/search?q=%E8%81%8A%E5%A4%A9".to_string()}else{format!("/api/chat/search?q=root&in={channel}&from={}",account.user)}),_=>return Err("unknown Chat route".into())};
 let path=if case=="invalid"{match route{"saves"=>format!("/api/chat/saves?limit=not-an-integer&userId={}",foreign.user),"thread"=>"/api/chat/messages/bad/thread".into(),"save"=>"/api/chat/messages/bad/save".into(),"my-threads"=>"/api/chat/my-threads?limit=bad".into(),"search"=>"/api/chat/search?q=".into(),"image"=>"/api/chat/unfurl/image/not-a-sha256".into(),"poll_results"=>"/api/chat/polls/bad/results".into(),"poll_close"=>"/api/chat/polls/bad/close".into(),"poll_vote"=>"/api/chat/polls/bad/vote".into(),"cancel"=>"/api/chat/scheduled/bad".into(),"scheduled"=>format!("/api/chat/scheduled?userId={}&limit=bad",foreign.user),"pin"=>"/api/chat/messages/bad/pin".into(),"reaction"=>path.clone(),"delete"=>"/api/chat/messages/bad".into(),"edit"=>path.clone(),_=>return Err("invalid case missing".into())}}else{path};
 let path=match case{"encoded_invalid"=>"/api/chat/messages/%80/thread".into(),"encoded_mount"=>"/a%70i/chat/saves".into(),"app_denied"=>format!("/api/chat/saves?userId={}",foreign.user),"bad_channel"=>"/api/chat/search?q=root&in=no".into(),"bad_author"=>"/api/chat/search?q=root&from=no".into(),"bad_before"=>"/api/chat/search?q=root&before=no".into(),_=>path};
 let wire_body=if route=="edit" && matches!(case,"trailing"|"null"|"oversize"|"unicode") {match case{
 "trailing"=>r#"{"body":"edited"}{}"#.into(),"null"=>"null".into(),"oversize"=>format!("{{\"body\":\"{}\"}}","x".repeat(1<<20)),"unicode"=>r#"{"body":"\ud800"}"#.into(),_=>unreachable!()
 }}else if route=="poll_vote"{match case{"duplicate_null"=>format!(r#"{{"optionId":{},"OPTIONID":null}}"#,options[0]),"invalid_json"=>"{".into(),_=>json!({"optionId":options[0],"userId":foreign.user}).to_string()}}else if route=="reaction"&&case=="invalid"{"{\"emoji\":7}".into()}else if route=="reaction"{json!({"emoji":"👍","userId":foreign.user}).to_string()}else if route=="edit"&&case=="invalid"{"{".to_string()}else if route=="edit"{json!({"body":"chat3 edited","userId":foreign.user,"mailboxId":foreign.mailbox}).to_string()}else{String::new()};
 let request=||Request::builder().method(method).uri(&path).header("host","mail.test").header("origin","http://mail.test").header("authorization",format!("Bearer {}",token(if case.starts_with("foreign"){foreign.user}else{account.user}))).header("x-request-id","chat3-oracle").header("content-type","application/json").header("accept-language",if case=="foreign_language"{"fr-FR"}else{"en"}).header("range",if case=="range"{"bytes=0-1"}else{""}).body(common::full(wire_body.clone()));
 let first=if case=="repeat"{
    let response=common::send(address,request()?).await;
    let status=response.status().as_u16();let mut headers=serde_json::Map::new();for(k,v)in response.headers(){if !matches!(k.as_str(),"date"|"content-length"){headers.insert(k.as_str().into(),v.to_str()?.into());}}
    let bytes=common::body_bytes(response).await;let mut body=if bytes.is_empty(){Value::Null}else{serde_json::from_slice(&bytes)?};normalize(&mut body,channel,message,reply,account.user,foreign.user);
    Some(json!({"status":status,"headers":headers,"body":body}))
 }else{None};
 let response=common::send(address,request()?).await;
 let content_length=response.headers().get("content-length").map(|v|v.to_str().map(str::to_owned)).transpose()?;
 let status=response.status().as_u16();let mut headers=serde_json::Map::new();for(k,v)in response.headers(){if !matches!(k.as_str(),"date"|"content-length"){headers.insert(k.as_str().into(),v.to_str()?.into());}}
 let bytes=common::body_bytes(response).await;
 if !storage_errors.lock().unwrap().is_empty(){return Err(format!("invalid storage signature: {:?}",storage_errors.lock().unwrap()).into());}
 if !recording {
 let metrics=common::send(address,Request::builder().uri("/_gateway/metrics").body(common::full(""))?).await;
 let metrics=String::from_utf8(common::body_bytes(metrics).await.to_vec())?;
 if !metrics.lines().any(|s|s=="setjoin_gateway_proxied_to_go_total 0")||!metrics.lines().any(|s|s=="setjoin_gateway_proxied_to_go_by_family_total{family=\"F12\"} 0"){server.abort();let _=server.await;return Err(format!("native Chat forwarded to Go: {metrics}").into());}
 }
 server.abort();let _=server.await;
 if !recording && !mutant && status!=expected_status(route,case) {return Err(format!("native Chat response differs, got {status}: {}",String::from_utf8_lossy(&bytes)).into());}
 let wire_payloads=if case=="raw_number"{let rows:Vec<std::collections::BTreeMap<String,Box<serde_json::value::RawValue>>>=serde_json::from_slice(&bytes)?;Some(json!(rows.iter().map(|r|r.get("payload").map(|p|p.get()).unwrap_or("null")).collect::<Vec<_>>()))}else{None};
 let mut body:Value=serde_json::from_slice(&bytes).unwrap_or(json!(String::from_utf8_lossy(&bytes)));
 normalize(&mut body,channel,message,reply,account.user,foreign.user);
 let (registered_method,registered_path)=canonical(route).split_once(' ').unwrap();
 let mut observation=json!({"request":{"method":registered_method,"path":registered_path,"wireMethod":method},"response":{"status":status,"headers":headers,"body":body},"effects":{},"audit":[],"notify":[]});if let Some(payloads)=wire_payloads{observation["wirePayloads"]=payloads;}if let Some(first)=first{observation["firstResponse"]=first;}
 if matches!(case,"storage_partial"|"head_large"){observation["imageWire"]=json!({"contentLength":content_length,"storage":storage_events.lock().unwrap().clone()});}
 if writes {
    let after=snapshot(&owner,channel,message,reply,account.user,foreign.user,route).await?;
    let mut notify=Vec::new();
    for(recipient,events)in [("actor",actor_listener.drain(&owner).await?),("foreign",foreign_listener.drain(&owner).await?)]{
      for event in events {let mut payload:Value=serde_json::from_str(&event)?;normalize(&mut payload,channel,message,reply,account.user,foreign.user);notify.push(json!({"recipient":recipient,"payload":payload}));}
    }
    observation["audit"]=after["coreAudit"].clone();
    observation["effects"]=json!({"before":before,"after":after});observation["notify"]=json!(notify);
 }
 if let Some(poll)=poll{normalize_poll(&mut observation,poll,&options,account.user,foreign.user);}
 if case.ends_with("contract") {
  if matches!(route,"saves"|"thread"|"my-threads"|"search") {
   let rows=observation["response"]["body"].as_array().ok_or("saved list must be an array")?;
   if rows.len()!=1 || rows[0]["messageId"]!="<message>" || rows[0]["authorId"]!="<actor>" || rows[0]["channelId"]!="<channel>" || rows[0]["body"]!=seed_body || rows[0]["seq"]!=1 {return Err(format!("saved message is not retrievable: {observation}").into());}
   if route=="my-threads" && (rows[0]["replyCount"]!=1 || rows[0]["unreadCount"]!=2){return Err("my-threads lost reply/unread state".into());}
  } else if route=="edit" {
   if observation["response"]["body"]!=json!({"seq":2}) {return Err(format!("edit response differs: {observation}").into());}
   let row=owner.query_one("SELECT body,seq,author_id FROM chat_messages WHERE id=$1 AND channel_id=$2",&[&message,&channel]).await?;
   let revision=owner.query_one("SELECT prior_body,edited_by FROM chat_message_revisions WHERE message_id=$1 AND channel_id=$2",&[&message,&channel]).await?;
   if row.get::<_,String>(0)!="chat3 edited" || row.get::<_,i64>(1)!=2 || row.get::<_,i64>(2)!=account.user || revision.get::<_,String>(0)!=seed_body || revision.get::<_,i64>(1)!=account.user {return Err("edit lost the owned message or its prior revision".into());}
  } else if route=="save" {
   if observation["response"]["body"]!=json!({"saved":false}) {return Err(format!("unsave response differs: {observation}").into());}
   let remaining:i64=owner.query_one("SELECT count(*) FROM chat_saved_messages WHERE user_id=$1 AND message_id=$2",&[&account.user,&message]).await?.get(0);
   if remaining!=0 {return Err("unsave left the personal bookmark".into());}
  } else {return Err("unknown native contract".into());}
  return Ok(());
 }
 let path=std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("../../tests/conformance/chat-b/goldens/v2-{route}-{case}.json"));
 if recording { if status!=expected_status(route,case){return Err(format!("Go unexpected response: {observation:#}").into());}if writes {setjoin_conformance::golden::record(&path.with_file_name(format!("v2-{route}-{case}-row-effects.json")),&json!({"format":1,"route":canonical(route),"case":format!("{route}-{case}-v2-row-effects"),"go_source":std::env::var("GOFREE_GO_SOURCE")?,"effects":[observation["effects"],observation["notify"]]}))?;}
 setjoin_conformance::golden::record(&path,&json!({"format":1,"route":canonical(route),"case":format!("{route}-{case}-v2"),"go_source":std::env::var("GOFREE_GO_SOURCE")?,"observation":observation}))?; }
 else{let mut expected:Value=serde_json::from_slice(&std::fs::read(&path)?)?;
 normalize(&mut expected,channel,message,reply,account.user,foreign.user);
 if case=="foreign" {if let Some(instance)=expected.pointer_mut("/observation/response/body/instance"){if let Some(text)=instance.as_str(){if let Some(tail)=text.strip_prefix("/chat/messages/"){let (id,suffix)=tail.split_once('/').map(|(a,b)|(a,format!("/{b}"))).unwrap_or((tail,String::new()));if id.parse::<i64>().is_ok(){*instance=json!(format!("/chat/messages/{{id}}{suffix}"));}}}}}if matches!(case,"storage_partial"|"head_large"){normalize_image_wire(&mut expected["observation"])?;normalize_image_wire(&mut observation)?;}
 let comparison=setjoin_conformance::golden::compare(&expected["observation"],&observation);
 if mutant {if observation["response"]["status"]!=501 || expected["observation"]["response"]["status"]==501 || comparison.is_ok(){return Err("actual response status mutant survived".into());}println!("MUTANT-REJECTED: {} :: changed-status",canonical(route));return Ok(());}comparison?;
 if writes {let mut effects:Value=serde_json::from_slice(&std::fs::read(path.with_file_name(format!("v2-{route}-{case}-row-effects.json")))?)?;normalize(&mut effects,channel,message,reply,account.user,foreign.user);setjoin_conformance::golden::compare(&effects["effects"],&json!([observation["effects"],observation["notify"]]))?;}
 eprintln!("GOLDEN-REPLAY: {} :: {route}-{case}-v2",canonical(route));}
 Ok::<_,BoxError>(())
 }.await;
    if let Some(level) = audit_level {
        owner
            .execute("UPDATE audit_policy SET level=$1 WHERE id=1", &[&level])
            .await?;
    }
    let _ = owner.batch_execute("ROLLBACK").await;
    if let Some(name) = fault_schema {
        owner
            .batch_execute(&format!("DROP SCHEMA {name} CASCADE"))
            .await?;
    }
    owner
        .execute(
            "DELETE FROM chat_saved_messages WHERE user_id=$1",
            &[&account.user],
        )
        .await?;
    owner.batch_execute(&format!("BEGIN; SET LOCAL session_replication_role=replica; DELETE FROM chat_audit_log WHERE channel_id={channel}; DELETE FROM admin_audit_log WHERE user_id IN ({},{}); COMMIT;",account.user,foreign.user)).await?;
    owner
        .execute("DELETE FROM chat_messages WHERE channel_id=$1", &[&channel])
        .await?;
    owner
        .execute(
            "DELETE FROM chat_channels WHERE id=$1 AND created_by=$2",
            &[&channel, &account.user],
        )
        .await?;
    for row in owner
        .query(
            "SELECT operation_id::text FROM rust_operation_receipts WHERE family='F12'",
            &[],
        )
        .await?
    {
        let id: String = row.get(0);
        if !old_receipts.contains(&id) {
            owner.execute("DELETE FROM rust_operation_receipts WHERE family='F12' AND operation_id=$1::text::uuid",&[&id]).await?;
        }
    }
    match previous {
        Some(v) => {
            owner
                .execute(
                    "UPDATE feature_toggles SET enabled=$1 WHERE key='feature.chat'",
                    &[&v],
                )
                .await?;
        }
        None => {
            owner
                .execute("DELETE FROM feature_toggles WHERE key='feature.chat'", &[])
                .await?;
        }
    }
    owner
        .execute(
            "DELETE FROM scheduled_actions WHERE action_kind='chat_send' AND payload->>'userId'=$1",
            &[&account.user.to_string()],
        )
        .await?;
    if route == "image" {
        owner
            .execute(
                "DELETE FROM chat_link_previews WHERE url_hash=$1",
                &[&image_hash],
            )
            .await?;
        owner
            .execute(
                "DELETE FROM blob_cleanup_queue WHERE blob_sha256=$1",
                &[&image_hash],
            )
            .await?;
        owner
            .execute("DELETE FROM blobs WHERE sha256=$1", &[&image_hash])
            .await?;
    }
    remove_principal(&owner, &account).await?;
    remove_principal(&owner, &foreign).await?;
    result
}
fn expected_status(route: &str, case: &str) -> u16 {
    if case.starts_with("bad_") {
        return 400;
    }
    if case == "query_fault" {
        return 500;
    }
    if case == "app_denied" {
        return 403;
    }
    if case == "disabled" {
        return 404;
    }
    if case == "foreign_language" {
        return 422;
    }
    if case == "encoded_invalid" {
        return 400;
    }
    if case == "encoded_mount" {
        return 404;
    }
    if route == "poll_vote" && case == "invalid_json" {
        return 400;
    }
    if route == "edit" {
        match case {
            "trailing" | "oversize" => return 400,
            "null" => return 422,
            _ => {}
        }
    }
    if route == "image" {
        return if matches!(case, "invalid" | "no_cache" | "image_query_fault") {
            404
        } else {
            200
        };
    }
    if route == "poll_results" {
        return match case {
            "foreign" => 422,
            "invalid" => 400,
            _ => 200,
        };
    }
    if matches!(route, "poll_vote" | "poll_close") {
        return match case {
            "foreign" => 422,
            "invalid" => 400,
            _ => 204,
        };
    }
    if route == "delete" && case == "repeat" {
        return 403;
    }
    if route == "cancel" {
        return match case {
            "foreign" | "repeat" => 422,
            "invalid" => 400,
            _ => 204,
        };
    }
    if case == "invalid" {
        if matches!(route, "saves" | "scheduled") {
            200
        } else {
            400
        }
    } else if case == "foreign" {
        match route {
            "thread" => 422,
            "edit" | "delete" => 403,
            "save" | "reaction" | "pin" => 404,
            _ => 200,
        }
    } else {
        200
    }
}
fn canonical(route: &str) -> &'static str {
    match route {
        "image" => "GET /chat/unfurl/image/{sha256}",
        "poll_results" => "GET /chat/polls/{id}/results",
        "poll_close" => "POST /chat/polls/{id}/close",
        "poll_vote" => "POST /chat/polls/{id}/vote",
        "cancel" => "DELETE /chat/scheduled/{actionId}",
        "scheduled" => "GET /chat/scheduled",
        "pin" => "POST /chat/messages/{id}/pin",
        "reaction" => "POST /chat/messages/{id}/reactions",
        "delete" => "DELETE /chat/messages/{id}",
        "edit" => "PATCH /chat/messages/{id}",
        "saves" => "GET /chat/saves",
        "save" => "POST /chat/messages/{id}/save",
        "thread" => "GET /chat/messages/{id}/thread",
        "my-threads" => "GET /chat/my-threads",
        "search" => "GET /chat/search",
        _ => panic!("unknown route"),
    }
}

fn normalize(
    v: &mut Value,
    channel: i64,
    message: i64,
    reply: Option<i64>,
    user: i64,
    foreign: i64,
) {
    match v {
        Value::Array(a) => {
            for x in a {
                normalize(x, channel, message, reply, user, foreign)
            }
        }
        Value::Object(o) => {
            for (k, x) in o {
                if !x.is_null()
                    && (k.ends_with("_at")
                        || matches!(
                            k.as_str(),
                            "createdAt"
                                | "updatedAt"
                                | "editedAt"
                                | "deletedAt"
                                | "lastReplyAt"
                                | "created_at"
                                | "updated_at"
                                | "edited_at"
                                | "deleted_at"
                                | "joined_at"
                                | "last_message_at"
                                | "occurred_at"
                        ))
                {
                    *x = "<timestamp>".into()
                } else if matches!(k.as_str(), "channelId" | "channel_id")
                    && x.as_i64() == Some(channel)
                {
                    *x = "<channel>".into()
                } else if matches!(
                    k.as_str(),
                    "messageId" | "parentMessageId" | "message_id" | "parent_message_id"
                ) && x.as_i64() == Some(message)
                {
                    *x = "<message>".into()
                } else if matches!(
                    k.as_str(),
                    "messageId" | "parentMessageId" | "message_id" | "parent_message_id"
                ) && reply.is_some()
                    && x.as_i64() == reply
                {
                    *x = "<reply>".into()
                } else if matches!(
                    k.as_str(),
                    "authorId"
                        | "userId"
                        | "author_id"
                        | "user_id"
                        | "created_by"
                        | "edited_by"
                        | "pinned_by"
                ) && x.as_i64() == Some(user)
                {
                    *x = "<actor>".into()
                } else if matches!(
                    k.as_str(),
                    "authorId"
                        | "userId"
                        | "author_id"
                        | "user_id"
                        | "created_by"
                        | "edited_by"
                        | "pinned_by"
                ) && x.as_i64() == Some(foreign)
                {
                    *x = "<foreign>".into()
                } else if k == "dedup_key" && x.is_string() {
                    *x = "<action-dedup>".into()
                } else if k == "actionId" && x.is_string() {
                    *x = "<action>".into()
                } else if k == "instance" && x.is_string() {
                    let text = x.as_str().unwrap();
                    if text
                        .strip_prefix("/chat/scheduled/")
                        .is_some_and(|s| s.len() == 36)
                    {
                        *x = "/chat/scheduled/{actionId}".into();
                        continue;
                    }
                    let base = format!("/chat/messages/{message}");
                    if text == base {
                        *x = "/chat/messages/{id}".into()
                    } else {
                        *x = text
                            .replace(&format!("{base}/"), "/chat/messages/{id}/")
                            .into();
                    }
                } else {
                    normalize(x, channel, message, reply, user, foreign)
                }
            }
        }
        _ => {}
    }
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

struct Principal {
    user: i64,
    mailbox: i64,
    domain: i64,
}
async fn principal_pair(
    owner: &tokio_postgres::Client,
) -> Result<(Principal, Principal), BoxError> {
    owner.batch_execute("BEGIN").await?;
    let result = async {
        let account = principal_in_transaction(owner, "chat3-actor").await?;
        let foreign = principal_in_transaction(owner, "chat3-foreign").await?;
        owner.batch_execute("COMMIT").await?;
        Ok::<_, tokio_postgres::Error>((account, foreign))
    }
    .await;
    match result {
        Ok(pair) => Ok(pair),
        Err(error) => {
            let _ = owner.batch_execute("ROLLBACK").await;
            Err(format!("Chat principal-pair setup: {error:?}").into())
        }
    }
}
async fn principal_in_transaction(
    owner: &tokio_postgres::Client,
    label: &str,
) -> Result<Principal, tokio_postgres::Error> {
    let unique: String = owner
        .query_one("SELECT replace(gen_random_uuid()::text,'-','')", &[])
        .await?
        .get(0);
    let domain_name = format!("oracle-{unique}.test");
    let email = format!("{label}@{domain_name}");
    let domain: i64 = owner
        .query_one(
            "INSERT INTO domains(name,is_local) VALUES($1,true) RETURNING id",
            &[&domain_name],
        )
        .await?
        .get(0);
    let user:i64=owner.query_one("INSERT INTO users(username,domain_id,email,display_name,password_hash) VALUES($1,$2,$1,$3,'x') RETURNING id",&[&email,&domain,&label]).await?.get(0);
    let mut mailbox: i64 = owner
        .query_one("SELECT nextval('mailboxes_id_seq')", &[])
        .await?
        .get(0);
    if mailbox == user {
        mailbox = owner
            .query_one("SELECT nextval('mailboxes_id_seq')", &[])
            .await?
            .get(0);
    }
    owner.execute("INSERT INTO mailboxes(id,user_id,domain_id,email,display_name,type,is_primary) VALUES($1,$2,$3,$4,$5,'personal',true)",&[&mailbox,&user,&domain,&email,&label]).await?;
    Ok(Principal {
        user,
        mailbox,
        domain,
    })
}
async fn remove_principal(owner: &tokio_postgres::Client, p: &Principal) -> Result<(), BoxError> {
    owner.batch_execute(&format!("BEGIN; SET LOCAL session_replication_role=replica; DELETE FROM mailbox_audit_log WHERE mailbox_id={}; COMMIT;",p.mailbox)).await?;
    owner.batch_execute(&format!("BEGIN; DELETE FROM mailboxes WHERE id={} AND user_id={}; DELETE FROM users WHERE id={} AND domain_id={}; COMMIT;",p.mailbox,p.user,p.user,p.domain)).await?;
    owner
        .execute("DELETE FROM domains WHERE id=$1", &[&p.domain])
        .await?;
    Ok(())
}

// The spec's DB-effect observer: only this disposable fixture's business rows.
// Recovery receipts are Rust-only metadata and are deliberately outside it.
async fn snapshot(
    owner: &tokio_postgres::Client,
    channel: i64,
    message: i64,
    reply: Option<i64>,
    actor: i64,
    foreign: i64,
    route: &str,
) -> Result<Value, BoxError> {
    let mut out = serde_json::Map::new();
    let messages = format!("SELECT id FROM public.chat_messages WHERE channel_id={channel}");
    let mut tables = vec![
        ("chat_channels", format!("id={channel}")),
        ("chat_channel_members", format!("channel_id={channel}")),
        ("chat_messages", format!("channel_id={channel}")),
        ("chat_message_revisions", format!("channel_id={channel}")),
        (
            "chat_message_reactions",
            format!("message_id IN ({messages})"),
        ),
        ("chat_message_pins", format!("channel_id={channel}")),
        (
            "chat_saved_messages",
            format!("user_id IN ({actor},{foreign}) AND message_id IN ({messages})"),
        ),
        ("chat_audit_log", format!("channel_id={channel}")),
    ];
    if route == "cancel" {
        tables.push((
            "scheduled_actions",
            format!("action_kind='chat_send' AND payload->>'userId' IN ('{actor}','{foreign}')"),
        ));
    }
    if route.starts_with("poll_") {
        tables.push(("chat_polls", format!("channel_id={channel}")));
        for table in ["chat_poll_options", "chat_poll_votes"] {
            tables.push((
                table,
                format!("poll_id IN (SELECT id FROM chat_polls WHERE channel_id={channel})"),
            ));
        }
    }
    for (table, predicate) in tables {
        let order = if table == "scheduled_actions" {
            "id::text"
        } else {
            "(to_jsonb(t)->>'id')::bigint NULLS LAST,(to_jsonb(t)->>'user_id')::bigint NULLS LAST"
        };
        let rows=owner.query(&format!("SELECT to_jsonb(t)::text FROM public.{table} t WHERE {predicate} ORDER BY {order}"),&[]).await?;
        let mut values = Vec::new();
        for (index, row) in rows.into_iter().enumerate() {
            let mut value: Value = serde_json::from_str(row.get::<_, &str>(0))?;
            if let Some(object) = value.as_object_mut() {
                if let Some(id) = object.get_mut("id") {
                    *id = if table == "chat_channels" {
                        json!("<channel>")
                    } else if table == "chat_messages" {
                        if id.as_i64() == Some(message) {
                            json!("<message>")
                        } else if reply.is_some() && id.as_i64() == reply {
                            json!("<reply>")
                        } else {
                            json!(format!("<message-{index}>"))
                        }
                    } else {
                        json!(format!("<{table}-{index}>"))
                    };
                }
                if table == "chat_audit_log" {
                    if let Some(after) =
                        object.get_mut("after_state").and_then(Value::as_object_mut)
                    {
                        after.remove("_checksum");
                        after.remove("_prev_checksum");
                    }
                    if let Some(target) = object.get_mut("target_id") {
                        if target.as_i64() == Some(message) {
                            *target = json!("<message>")
                        } else if target.as_i64() == Some(channel) {
                            *target = json!("<channel>")
                        }
                    }
                }
            }
            normalize(&mut value, channel, message, reply, actor, foreign);
            values.push(value);
        }
        out.insert(table.into(), json!(values));
    }
    let audits=owner.query("SELECT jsonb_build_object('userId',user_id,'action',action,'targetType',target_type,'targetId',target_id,'before',before_state,'after',after_state,'notes',notes,'ip',host(ip))::text FROM admin_audit_log WHERE user_id=ANY($1::bigint[]) ORDER BY id",&[&vec![actor,foreign]]).await?;
    let mut audit = Vec::new();
    for row in audits {
        let mut value: Value = serde_json::from_str(row.get::<_, &str>(0))?;
        normalize(&mut value, channel, message, reply, actor, foreign);
        audit.push(value);
    }
    out.insert("coreAudit".into(), json!(audit));
    let valid: bool = owner
        .query_one(
            "SELECT coalesce(bool_and(valid),true) FROM verify_chat_audit_chain($1)",
            &[&channel],
        )
        .await?
        .get(0);
    out.insert("chainValid".into(), json!(valid));
    Ok(Value::Object(out))
}

fn normalize_poll(value: &mut Value, poll: i64, options: &[i64], actor: i64, foreign: i64) {
    fn walk(value: &mut Value, key: &str, poll: i64, options: &[i64], actor: i64, foreign: i64) {
        match value {
            Value::Object(o) => {
                for (k, v) in o {
                    walk(v, k, poll, options, actor, foreign)
                }
            }
            Value::Array(a) => {
                for v in a {
                    walk(v, key, poll, options, actor, foreign)
                }
            }
            _ => {
                if matches!(key, "pollId" | "poll_id") && value.as_i64() == Some(poll) {
                    *value = json!("<poll>")
                } else if matches!(key, "optionId" | "option_id") {
                    if let Some(index) = options.iter().position(|id| value.as_i64() == Some(*id)) {
                        *value = json!(format!("<option-{index}>"));
                    }
                } else if key == "voters" && value.as_i64() == Some(actor) {
                    *value = json!("<actor>")
                } else if key == "voters" && value.as_i64() == Some(foreign) {
                    *value = json!("<foreign>")
                } else if key == "instance" {
                    if let Some(text) = value.as_str() {
                        *value = json!(
                            text.replace(&format!("/chat/polls/{poll}/"), "/chat/polls/{id}/")
                        );
                    }
                }
            }
        }
    }
    walk(value, "", poll, options, actor, foreign)
}

struct ChangedStatus<K: setjoin_authz::token::KeySource + 'static>(
    setjoin_gateway::chat_b::ChatBRoute<K>,
);
impl<K: setjoin_authz::token::KeySource + 'static> setjoin_gateway::Intercept for ChangedStatus<K> {
    fn matches(&self, r: &Request<setjoin_gateway::Body>) -> bool {
        setjoin_gateway::Intercept::matches(&self.0, r)
    }
    fn admits_member(
        &self,
        h: hyper::HeaderMap,
        s: &'static str,
    ) -> setjoin_gateway::BoxFuture<bool> {
        setjoin_gateway::Intercept::admits_member(&self.0, h, s)
    }
    fn handle(
        &self,
        r: Request<setjoin_gateway::Body>,
        c: setjoin_gateway::RequestContext,
    ) -> setjoin_gateway::BoxFuture<Response<setjoin_gateway::Body>> {
        let future = setjoin_gateway::Intercept::handle(&self.0, r, c);
        Box::pin(async move {
            let mut response = future.await;
            *response.status_mut() = hyper::StatusCode::NOT_IMPLEMENTED;
            response
        })
    }
}

#[tokio::test]
async fn saves_rejects_status() -> Result<(), BoxError> {
    run_inner("saves", "success", true).await
}

#[tokio::test]
async fn save_rejects_status() -> Result<(), BoxError> {
    run_inner("save", "success", true).await
}

#[tokio::test]
async fn thread_rejects_status() -> Result<(), BoxError> {
    run_inner("thread", "success", true).await
}

#[tokio::test]
async fn my_threads_rejects_status() -> Result<(), BoxError> {
    run_inner("my-threads", "success", true).await
}

#[tokio::test]
async fn search_rejects_status() -> Result<(), BoxError> {
    run_inner("search", "success", true).await
}

#[tokio::test]
async fn edit_rejects_status() -> Result<(), BoxError> {
    run_inner("edit", "success", true).await
}

#[tokio::test]
async fn delete_rejects_status() -> Result<(), BoxError> {
    run_inner("delete", "success", true).await
}

#[tokio::test]
async fn reaction_rejects_status() -> Result<(), BoxError> {
    run_inner("reaction", "success", true).await
}

#[tokio::test]
async fn pin_rejects_status() -> Result<(), BoxError> {
    run_inner("pin", "success", true).await
}

#[tokio::test]
async fn scheduled_rejects_status() -> Result<(), BoxError> {
    run_inner("scheduled", "success", true).await
}

#[tokio::test]
async fn cancel_rejects_status() -> Result<(), BoxError> {
    run_inner("cancel", "success", true).await
}

#[tokio::test]
async fn poll_vote_rejects_status() -> Result<(), BoxError> {
    run_inner("poll_vote", "success", true).await
}

#[tokio::test]
async fn poll_close_rejects_status() -> Result<(), BoxError> {
    run_inner("poll_close", "success", true).await
}

#[tokio::test]
async fn poll_results_rejects_status() -> Result<(), BoxError> {
    run_inner("poll_results", "success", true).await
}

#[tokio::test]
async fn image_rejects_status() -> Result<(), BoxError> {
    run_inner("image", "success", true).await
}

#[tokio::test]
async fn part_b_rollbacks_and_deferred_routes_preserve_requests() -> Result<(), BoxError> {
    use http_body_util::BodyExt;
    if std::env::var_os("GOFREE_RECORD_GO_BINARY").is_some() {
        return Err("rollback cases never record".into());
    }
    let Some(db) = Db::for_case("chat3-rollback") else {
        return Ok(());
    };
    let endpoint=common::fake_upstream(|request|async move{
  let method=request.method().to_string();let uri=request.uri().to_string();let trace=request.headers()["x-chat3-trace"].to_str().unwrap().to_owned();let bytes=request.into_body().collect().await.unwrap().to_bytes();
  Response::builder().status(418).header("x-chat3-go","yes").body(common::full(json!({"method":method,"uri":uri,"body":String::from_utf8_lossy(&bytes),"trace":trace}).to_string())).unwrap()
 }).await;
    for mode in ["inventory", "global", "deferred"] {
        let mut inventory: Value = serde_json::from_str(include_str!("../route-inventory.json"))?;
        let routes = inventory["routes"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|r| {
                r["family"] == "F12"
                    && r["slice"] == "sub-router-b"
                    // /chat/ is now ON as the shared catch-all mount. This
                    // harness installs only Chat B's 17 concrete handlers; its
                    // unmatched mount still checks whole-request transport.
                    && ((r["path"] == "/chat/") == (mode == "deferred"))
            })
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(routes.len(), if mode == "deferred" { 1 } else { 17 });
        if mode == "inventory" {
            for row in inventory["routes"].as_array_mut().unwrap() {
                if row["family"] == "F12" && row["slice"] == "sub-router-b" {
                    row["state"] = "OFF".into();
                    row["upstream"] = "go-mail".into();
                }
            }
        }
        let adapter = setjoin_gateway::chat_b::ChatBRoute {
            exec: setjoin_pg::ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn), 1)
                .map_err(|e| e.0)?,
            keys: std::sync::Arc::new(common::recovery_keys()),
            issuer: "mailserver".into(),
            store: None,
        };
        let gateway = Gateway::new(
            Config {
                upstream: Some(format!("http://{endpoint}").parse()?),
                trusted_proxies: TrustedProxies::parse("")?,
                upstream_header_timeout: setjoin_gateway::proxy::DEFAULT_HEADER_TIMEOUT,
                edge_limit: None,
            },
            RouteTable::proxy_all().with(adapter),
        )?
        .with_inventory(&inventory.to_string())?
        .with_enabled(mode != "global");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let task = tokio::spawn(gateway.serve(listener));
        let check = async {
            for route in &routes {
                let method = if route["method"] == "*" {
                    "PATCH"
                } else {
                    route["method"].as_str().unwrap()
                };
                let path = format!(
                    "/api{}?rollback=on&x=%2F",
                    route["path"]
                        .as_str()
                        .unwrap()
                        .replace("{id}", "991")
                        .replace("{actionId}", "00000000-0000-4000-8000-000000000001")
                        .replace("{sha256}", &"a".repeat(64))
                );
                let body = r#"{"opaque":"unchanged","userId":0}"#;
                let response = common::send(
                    address,
                    Request::builder()
                        .method(method)
                        .uri(&path)
                        .header("host", "mail.test")
                        .header("authorization", "Bearer intentionally-unsupported")
                        .header("content-type", "application/json")
                        .header("x-chat3-trace", "preserved")
                        .body(common::full(body))?,
                )
                .await;
                assert_eq!(response.status(), 418, "{mode}: {method} {path}");
                assert_eq!(response.headers()["x-chat3-go"], "yes");
                let observed: Value = serde_json::from_slice(&common::body_bytes(response).await)?;
                assert_eq!(
                    observed,
                    json!({"method":method,"uri":path,"body":body,"trace":"preserved"})
                );
            }
            if mode != "global" {
                let response = common::send(
                    address,
                    Request::builder()
                        .uri("/_gateway/metrics")
                        .body(common::full(""))?,
                )
                .await;
                let metrics = String::from_utf8(common::body_bytes(response).await.to_vec())?;
                assert!(
                    metrics.lines().any(|line| line
                        == format!("setjoin_gateway_proxied_to_go_total {}", routes.len())),
                    "{metrics}"
                );
                assert!(
                    metrics.lines().any(|line| line
                        == format!(
                            "setjoin_gateway_proxied_to_go_by_family_total{{family=\"F12\"}} {}",
                            routes.len()
                        )),
                    "{metrics}"
                );
            }
            Ok::<_, BoxError>(())
        }
        .await;
        task.abort();
        let _ = task.await;
        check?;
    }
    Ok(())
}

// Exclude only Go's independent startup bucket HEAD; both clients' SigV4
// signatures are verified before this projection. SDK signed-header sets may differ.
fn normalize_image_wire(observation: &mut Value) -> Result<(), BoxError> {
    let events = observation
        .pointer_mut("/imageWire/storage")
        .and_then(Value::as_array_mut)
        .ok_or("missing signed S3 observations")?;
    events.retain(|event| !(event["method"] == "HEAD" && event["uri"] == "/mailblobs/"));
    for event in events {
        if event["signature_valid"] != true {
            return Err("unverified S3 observation".into());
        }
        event
            .as_object_mut()
            .ok_or("invalid S3 event")?
            .remove("signed_headers");
    }
    Ok(())
}
