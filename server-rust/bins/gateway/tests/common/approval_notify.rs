//! Independent frozen-Go seed + one approval_created delivery tick.
use super::{full, BoxError};
use serde_json::{json, Value};
use setjoin_conformance::{fixture, golden, harness::Db};
pub async fn run() -> Result<(), BoxError> {
    run_case("success").await
}
pub async fn run_case(kind: &str) -> Result<(), BoxError> {
    let Some(db) = Db::for_case("approval-notify") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let a = fixture::account(&owner, "appr1-notify-requester").await?;
    let b = fixture::account(&owner, "appr1-notify-approver").await?;
    owner
        .execute(
            "UPDATE domains SET name='gofree-appr1-notify.test' WHERE id=$1",
            &[&b.domain],
        )
        .await?;
    owner.execute("UPDATE users SET email='approver@gofree-appr1-notify.test',username='approver@gofree-appr1-notify.test' WHERE id=$1",&[&b.user]).await?;
    owner
        .execute(
            "UPDATE mailboxes SET email='approver@gofree-appr1-notify.test' WHERE id=$1",
            &[&b.mailbox],
        )
        .await?;
    let id:i64=owner.query_one("INSERT INTO approval_requests(consumer_type,requester_user_id,subject,payload,approver_kind,approver_ref,created_at,expires_at,domain_id) VALUES('hr.leave',$1,'Leave <notify>','{}','user',$2,'2026-10-01T12:00:00Z','2099-11-01T12:00:00Z',$3) RETURNING id",&[&a.user,&b.user,&a.domain]).await?.get(0);
    let role = if kind == "role-group" {
        let group: i64 = owner
            .query_one(
                "INSERT INTO admin_role_groups(name,permissions) VALUES($1,'{}') RETURNING id",
                &[&format!("appr1-notify-{}", b.user)],
            )
            .await?
            .get(0);
        owner.execute("INSERT INTO admin_role_assignments(user_id,role_group_id,granted_by,expires_at) VALUES($1,$3,$1,now()-interval '1 hour'),($2,$3,$1,NULL)",&[&a.user,&b.user,&group]).await?;
        owner.execute("UPDATE approval_requests SET approver_kind='role_group',approver_ref=$2 WHERE id=$1",&[&id,&group]).await?;
        Some(group)
    } else {
        None
    };
    if kind == "fractional-expiry" {
        owner.execute("UPDATE approval_requests SET expires_at=expires_at+interval '0.875 seconds' WHERE id=$1",&[&id]).await?;
    }
    let result=async{
  let endpoint=super::fake_upstream(|_|async{hyper::Response::new(full(""))}).await;let oracle=super::go_oracle::start_named(&db,endpoint,None,if kind=="off"{"gofree-appr1-notify-off"}else{"gofree-appr1-notify"}).await?;let recording=oracle.is_some();
  let before=state(&owner,b.mailbox).await?;
  let seq=owner.query_one("SELECT last_value,is_called FROM imap_modseq_seq",&[]).await?;let expected_modseq=seq.get::<_,i64>(0)+i64::from(seq.get::<_,bool>(1));
  let payload=if kind=="folded-rbac"{json!({"request_id":id,"CONSUMER_TYPE":"rbac.jit_activation"}).to_string()}else if kind=="malformed"{"bad".into()}else{json!({"request_id":id,"consumer_type":if kind=="rbac"{"rbac.jit_activation"}else{"hr.leave"}}).to_string()};
  let skipped=matches!(kind,"off"|"rbac"|"malformed"|"folded-rbac");
  let mut task=None;
  if !recording && kind!="off" {
   let direct=format!("{}{}application_name=gofree-appr1-approval-listener",db.dsn,if db.dsn.contains('?'){"&"}else{"?"});
   let worker=setjoin_approvals::notify::ApprovalNotify::new(db.dsn.clone(),b"blobs1-test-jwt-secret-for-recording".to_vec(),"https://mail.test".into());let(stop,stopped)=tokio::sync::oneshot::channel::<()>();let handle=tokio::spawn(worker.run_until(direct,async move{let _=stopped.await;}));task=Some((stop,handle));
   let mut ready=false;for _ in 0..100 {ready=owner.query_one("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND application_name='gofree-appr1-approval-listener' AND query LIKE 'LISTEN%')",&[]).await?.get(0);if ready{break}tokio::time::sleep(std::time::Duration::from_millis(10)).await;}if !ready{return Err("approval listener did not become ready".into())}
  }
  owner.execute("SELECT pg_notify('approval_created',$1)",&[&payload]).await?;
  let raw_ref=format!("system:approval-notify:{id}:{}",b.user);
  let mut rows=vec![];
  for attempt in 0..100 {
   rows=owner.query("SELECT id,to_jsonb(m)::text FROM messages m WHERE mailbox_id=$1 AND raw_ref=$2",&[&b.mailbox,&raw_ref]).await?;
   if !rows.is_empty()||(skipped&&attempt>=5){break}tokio::time::sleep(std::time::Duration::from_millis(50)).await;
  }
  let mut messages=vec![];for row in rows{let mut message:Value=serde_json::from_str(&row.get::<_,String>(1))?;let msg=row.get::<_,i64>(0);
   if message["imap_modseq"]!=expected_modseq{return Err("notification modseq did not advance once".into())} message["imap_modseq"]=json!("<modseq>");
   let message_id=message["message_id"].as_str().ok_or("message id")?.to_string();if !message_id.starts_with(&format!("approval-{id}-{}-",b.user))||!message_id.ends_with("@setjoin"){return Err("unbound notification message ID".into())}
   let text=message["body_text"].as_str().ok_or("text")?.to_string();let html=message["body_html"].as_str().ok_or("html")?.to_string();if message["size_bytes"]!=((text.len()+html.len())as i64){return Err("incorrect notification size".into())}
   for decision in ["approve","deny"]{let token=super::approvals::sign_email(id,b.user,decision,4097217600);if !text.contains(&token)||!html.contains(&token){return Err(format!("notification lacks valid bound {decision} capability").into())}message["body_text"]=json!(message["body_text"].as_str().unwrap().replace(&token,&format!("<{decision}-token>")));message["body_html"]=json!(message["body_html"].as_str().unwrap().replace(&token,&format!("<{decision}-token>")));}
   let text=message["body_text"].as_str().unwrap();let html=message["body_html"].as_str().unwrap();message["size_bytes"]=json!(text.len()+html.len());
   for key in ["body_tsv","subject_tsv","from_tsv"]{if message[key].as_str().is_none_or(|s|s.is_empty()){return Err("missing notification search vector".into())}message[key]=json!("<derived-search-vector>");}
   for key in ["sent_at","received_at"]{chrono::DateTime::parse_from_rfc3339(message[key].as_str().ok_or("timestamp")?)?;message[key]=json!("<timestamp>");}
   message["id"]=json!("<message>");message["mailbox_id"]=json!("<approver-mailbox>");message["folder_id"]=json!("<inbox-folder>");message["message_id"]=json!("<message-id>");message["raw_ref"]=json!("system:approval-notify:<request>:<approver>");
   if message["thread_id"]==message_id{message["thread_id"]=json!("<message-id>")}else if message["thread_id"].as_str().is_some_and(|s|s==msg.to_string()){message["thread_id"]=json!("<message>")}
   messages.push(message);
  }
  if let Some((stop,handle))=task{let _=stop.send(());tokio::time::timeout(std::time::Duration::from_secs(3),handle).await??;}
  let after=state(&owner,b.mailbox).await?;
  let observed=json!({"messages":messages,"mailbox_before":before,"mailbox_after":after});
  let file=std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!("../../tests/conformance/approvals/goldens/{}",if kind=="success"{"approval-notify-tick-qualified.json".into()}else{format!("approval-notify-{kind}-tick.json")}));
  if recording{if observed["messages"].as_array().is_none_or(|v|v.len()!=usize::from(!skipped)){return Err("Go notification did not deliver exactly once".into())}golden::record(&file,&json!({"format":1,"worker":"approval-notify","case":if kind=="success"{"seed-one-tick"}else{kind},"go_source":std::env::var("GOFREE_GO_SOURCE")?,"observation":observed}))?;}else{let expected:Value=serde_json::from_slice(&std::fs::read(file)?)?;golden::compare(&expected["observation"],&observed)?;eprintln!("GOLDEN-REPLAY: worker approval-notify :: {kind}");}Ok::<_,BoxError>(())
 }.await;
    owner
        .execute("DELETE FROM approval_requests WHERE id=$1", &[&id])
        .await?;
    if let Some(role) = role {
        owner.execute("UPDATE admin_role_assignments SET expires_at=now()-interval '1 hour' WHERE role_group_id=$1",&[&role]).await?;
        owner
            .execute(
                "DELETE FROM admin_role_assignments WHERE role_group_id=$1",
                &[&role],
            )
            .await?;
        owner
            .execute("DELETE FROM admin_role_groups WHERE id=$1", &[&role])
            .await?;
    }
    super::remove_blob_account(&owner, &a).await?;
    super::remove_blob_account(&owner, &b).await?;
    result
}
async fn state(c: &tokio_postgres::Client, mailbox: i64) -> Result<Value, BoxError> {
    let r=c.query_one("SELECT jsonb_build_object('email',jmap_email_state,'tag',jmap_tag_state,'thread',jmap_thread_state,'mailbox',jmap_mailbox_state,'journal',(SELECT jsonb_agg(jsonb_build_object('datatype',datatype,'state_seq',state_seq,'op',op) ORDER BY datatype,state_seq) FROM jmap_changes_journal WHERE mailbox_id=$1),'tags',(SELECT jsonb_agg(jsonb_build_object('name',name,'total',total_count,'unread',unread_count) ORDER BY name) FROM tags WHERE mailbox_id=$1))::text FROM mailboxes WHERE id=$1",&[&mailbox]).await?;
    Ok(serde_json::from_str(&r.get::<_, String>(0))?)
}
