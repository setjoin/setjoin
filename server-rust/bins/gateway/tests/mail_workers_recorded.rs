//! Frozen-Go seed-plus-one-tick oracle for #295. No Go process during replay.
mod common;
mod drain_oracle;
#[path = "common/meet_peripherals.rs"]
mod meet_peripherals;
use drain_oracle::{BoxError, GoTick};
use serde_json::json;
use setjoin_conformance::{fixture, harness::Db};
use setjoin_gateway::mail_workers::{MailWork, MailboxLifecycle};
use setjoin_pg::workers::WorkerDatabase;
use common::webhook_receiver::{self as hooks, unguarded, Seen};
const HMAC: &str = "gofree-mbox4-audit-hmac";
fn worker_db(dsn: &str) -> Result<WorkerDatabase, BoxError> {
    Ok(WorkerDatabase::new(dsn)?.with_audit_keys(String::new(), HMAC.into()))
}
fn settle(name: &str, observation: serde_json::Value, recording: bool) -> Result<(), BoxError> {
    if recording {
        setjoin_conformance::golden::record(
            &drain_oracle::golden_path(name),
            &json!({"format":1,"case":name,"go_source":std::env::var("GOFREE_GO_SOURCE")?,"observation":observation}),
        )?;
        Ok(())
    } else {
        drain_oracle::settle(name, observation, false)
    }
}
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn observation(
    owner: &tokio_postgres::Client,
    queries: Vec<(&str, String)>,
) -> Result<serde_json::Map<String, serde_json::Value>, BoxError> {
    let mut obs = serde_json::Map::new();
    for (name, sql) in queries {
        let rows = owner
            .query(
                &format!("SELECT v::text FROM ({sql}) AS observation(v)"),
                &[],
            )
            .await?;
        let values = rows
            .iter()
            .map(|r| serde_json::from_str::<serde_json::Value>(&r.get::<_, String>(0)))
            .collect::<Result<Vec<_>, _>>()?;
        obs.insert(name.into(), json!(values));
    }
    Ok(obs)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mailbox_lifecycle_effects_tick() -> Result<(), BoxError> {
    lifecycle_effects_case(false).await
}

async fn lifecycle_effects_case(omit_tick: bool) -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("mailbox-lifecycle-effects") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let a = fixture::account(&owner, "mbox4-lifecycle").await?;
    let b = fixture::account(&owner, "mbox4-foreign").await?;
    let audit: i64 = owner
        .query_one("SELECT coalesce(max(id),0) FROM admin_audit_log", &[])
        .await?
        .get(0);
    let mut notice = db.listen("mailbox_lifecycle").await?;
    let mut revocations = db.listen("session_revoke").await?;
    let result=async {
        owner.batch_execute(&format!("INSERT INTO mailbox_delegates(mailbox_id,user_id,permission,granted_by) VALUES ({},{},'read',{}),({},{},'read',{});",a.mailbox,b.user,a.user,b.mailbox,a.user,b.user)).await?;
        for i in 1..=7 {
            let op=format!("29510000-0000-4000-8000-{i:012}");
            owner.execute("INSERT INTO mailbox_lifecycle_operations(operation_id,mailbox_id,action,actor_user_id,expected_generation,request_digest,before_digest,after_digest,result) VALUES ($1::text::uuid,$2,'suspend',$3,1,repeat('a',64),repeat('b',64),repeat('c',64),'{}')",&[&op,&a.mailbox,&a.user]).await?;
            let kinds=if i==1 {vec!["revoke_sessions","revoke_delegates","notify_clients","evict_media","lifecycle_webhook"]}else if i==2 {vec!["evict_media"]}else if i==7 {vec!["lifecycle_webhook"]}else{vec!["notify_clients"]};
            for kind in kinds {owner.execute("INSERT INTO mailbox_lifecycle_effects(operation_id,mailbox_id,effect_kind,created_at) VALUES ($1::text::uuid,$2,$3,'2026-01-01')",&[&op,&a.mailbox,&kind]).await?;}
            match i {
                1=>{owner.execute("INSERT INTO mailbox_lifecycle_outbox(operation_id,event_kind,dedupe_key,payload,created_at) VALUES ($1::text::uuid,'mailbox.suspended','mbox4-lifecycle','{\"safe\":true}','2026-01-01T12:00:00Z')",&[&op]).await?;}
                2=>{owner.execute("INSERT INTO mailbox_lifecycle_effect_targets(operation_id,room_name,identity) VALUES ($1::text::uuid,'room','user')",&[&op]).await?;}
                3=>{owner.execute("UPDATE mailbox_lifecycle_effects SET state='claimed',claimed_by='other',attempts=1,lease_until=now()+interval '1 hour' WHERE operation_id=$1::text::uuid",&[&op]).await?;}
                4=>{owner.execute("UPDATE mailbox_lifecycle_effects SET attempts=20 WHERE operation_id=$1::text::uuid",&[&op]).await?;}
                5|6=>{owner.execute("UPDATE mailbox_lifecycle_effects SET state=$2,claimed_by='expired',attempts=3,lease_until=now()-interval '1 hour' WHERE operation_id=$1::text::uuid",&[&op,&if i==5 {"claimed"}else{"failed"}]).await?;}
                _=>{}
            }
        }
        let recording=std::env::var_os("GOFREE_RECORD_DRAIN").is_some() && !omit_tick;
        if recording {GoTick{package:"internal/mailboxlifecycle",overlay:"mailbox_lifecycle_tick_test.go.txt",test:"TestGoFreeMailboxLifecycleTick",file:"gofree_mailbox_lifecycle_tick_test.go",env:vec![("GOFREE_DRAIN_DSN".into(),db.dsn.clone())],docker:vec![]}.run()?;}
        else if !omit_tick {MailboxLifecycle::new(worker_db(&db.dsn)?).tick().await;}
        let mut obs=observation(&owner,vec![
          ("effects",format!("SELECT jsonb_build_array(operation_id,effect_kind,state,attempts,claimed_by IS NOT NULL,lease_until>now(),last_error,completed_at IS NOT NULL) FROM mailbox_lifecycle_effects WHERE mailbox_id={} ORDER BY operation_id,effect_kind",a.mailbox)),
          ("outbox",format!("SELECT jsonb_build_array(state,attempts,last_error,completed_at IS NOT NULL) FROM mailbox_lifecycle_outbox WHERE dedupe_key='mbox4-lifecycle'")),
          ("delegates",format!("SELECT jsonb_build_array(mailbox_id={},count(*)) FROM mailbox_delegates WHERE mailbox_id IN ({},{}) GROUP BY mailbox_id ORDER BY mailbox_id",a.mailbox,a.mailbox,b.mailbox)),
          ("revocations",format!("SELECT jsonb_build_array(user_id={},scope,reason) FROM session_revocations WHERE user_id IN ({},{}) ORDER BY id",a.user,a.user,b.user)),
          ("audit",format!("SELECT jsonb_build_array(action,target_type,target_id={}) FROM admin_audit_log WHERE id>{audit} ORDER BY id",a.user))
        ]).await?;
        let mut notices=Vec::new();for text in notice.drain(&owner).await? {let mut v:serde_json::Value=serde_json::from_str(&text)?;v["mailbox_id"]=json!("<mailbox>");notices.push(v);}
        let mut revs=Vec::new();for text in revocations.drain(&owner).await? {let mut v:serde_json::Value=serde_json::from_str(&text)?;v["user_id"]=json!("<actor>");v["not_before"]=json!("<time>");v["expires_at"]=json!("<time>");revs.push(v);}
        obs.insert("notifies".into(),json!(notices));obs.insert("session_notifies".into(),json!(revs));
        settle("mailbox-lifecycle-effects",serde_json::Value::Object(obs),recording)
    }.await;
    owner
        .execute(
            "DELETE FROM mailbox_lifecycle_operations WHERE actor_user_id=$1",
            &[&a.user],
        )
        .await?;
    owner.batch_execute(&format!("BEGIN; SET LOCAL session_replication_role=replica; DELETE FROM admin_audit_log WHERE id>{audit}; COMMIT;")).await?;
    fixture::remove(&owner, &a).await?;
    fixture::remove(&owner, &b).await?;
    result
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_work_metric_tick() -> Result<(), BoxError> {
    metric_case(false).await
}

async fn metric_case(omit_tick: bool) -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("mail-work-metric") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let a = fixture::account(&owner, "mbox4-metric").await?;
    let result = async {
        owner.batch_execute(&format!("INSERT INTO mail_thread_work_events(id,mailbox_id,thread_id,generation,event_type,actor_user_id,actor_display_snapshot,before_state,after_state,reason,occurred_at) VALUES ('29500000-0000-4000-8000-000000000001',{},'metric-thread',1,'completed',{},'Actor','{{}}','{{}}','oracle','2026-01-02T12:00:00Z'); INSERT INTO mail_work_outbox(event_id,consumer_kind,dedupe_key,payload) VALUES ('29500000-0000-4000-8000-000000000001','metric','mbox4-metric','{{}}')", a.mailbox, a.user)).await?;
        let recording = std::env::var_os("GOFREE_RECORD_DRAIN").is_some() && !omit_tick;
        if recording {
            GoTick { package: "internal/mailwork", overlay: "mail_work_tick_test.go.txt", test: "TestGoFreeMailWorkTick", file: "gofree_mail_work_tick_test.go", env: vec![("GOFREE_DRAIN_DSN".into(), db.dsn.clone())], docker: vec![] }.run()?;
        } else if !omit_tick {
            MailWork::new(worker_db(&db.dsn)?).tick().await;
        }
        let rows = owner.query("SELECT consumer_kind,state,attempts,last_error,receipt->>'outcome' FROM mail_work_outbox WHERE dedupe_key='mbox4-metric'", &[]).await?;
        let row = &rows[0];
        let metrics = owner.query("SELECT conversation_count,completed_count,actor_cohort_count FROM mail_work_metric_daily WHERE mailbox_id=$1", &[&a.mailbox]).await?;
        let observation = json!({"outbox": [row.get::<_,String>(0),row.get::<_,String>(1),row.get::<_,i32>(2).to_string(),row.get::<_,Option<String>>(3).unwrap_or_default(),row.get::<_,Option<String>>(4).unwrap_or_default()], "metrics":metrics.iter().map(|r| vec![r.get::<_,i32>(0),r.get::<_,i32>(1),r.get::<_,i32>(2)]).collect::<Vec<_>>()});
        settle("mail-work-metric", observation, recording)
    }.await;
    fixture::remove(&owner, &a).await?;
    result
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_work_scan_and_digest_tick() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("mail-work-scan-digest") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let a = fixture::account(&owner, "mbox4-scan").await?;
    let mut tag = db.listen(&format!("tag:{}", a.mailbox)).await?;
    let mut notice = db.listen(&format!("mailwork:{}", a.user)).await?;
    let toggles = owner.query("SELECT key,enabled FROM feature_toggles WHERE key IN ('feature.shared_mail_work','feature.shared_mail_notifications','feature.shared_mail_integrations')", &[]).await?;
    let result = async {
        owner.batch_execute(&format!("UPDATE feature_toggles SET enabled=(key<>'feature.shared_mail_integrations') WHERE key IN ('feature.shared_mail_work','feature.shared_mail_notifications','feature.shared_mail_integrations');
        INSERT INTO mail_thread_work(mailbox_id,thread_id,status,assignee_user_id,due_at,first_activity_at) VALUES ({},'due-thread','owned',{},'2000-01-01','1999-01-01');
        INSERT INTO mail_work_notification_preferences(mailbox_id,user_id,category,delivery) VALUES ({},{},'assignment','digest');
        INSERT INTO mail_work_digest_ledger(mailbox_id,user_id,category,window_start,dedupe_key,deliver_after) VALUES ({},{},'assignment','2000-01-01','mbox4-due-digest','2000-01-02');", a.mailbox,a.user,a.mailbox,a.user,a.mailbox,a.user)).await?;
        let recording = std::env::var_os("GOFREE_RECORD_DRAIN").is_some();
        if recording {
            GoTick { package:"internal/mailwork", overlay:"mail_work_tick_test.go.txt", test:"TestGoFreeMailWorkTick", file:"gofree_mail_work_tick_test.go", env:vec![("GOFREE_DRAIN_DSN".into(),db.dsn.clone()),("GOFREE_MAIL_TICKS".into(),"2".into())],docker:vec![] }.run()?;
        } else {
            let worker=MailWork::new(worker_db(&db.dsn)?);
            worker.tick().await; worker.tick().await;
        }
        let mut notices=Vec::new();
        for text in notice.drain(&owner).await? { let mut v:serde_json::Value=serde_json::from_str(&text)?; if v.get("eventId").is_some(){v["eventId"]=json!("<event>");} v["mailboxId"]=json!("<mailbox>"); notices.push(v); }
        let mut tags=Vec::new();
        for text in tag.drain(&owner).await? { let mut v:serde_json::Value=serde_json::from_str(&text)?; v["accountId"]=json!("<mailbox>"); tags.push(v); }
        let mut obs=serde_json::Map::new();
        for (name,sql) in [
          ("work","SELECT jsonb_build_array(thread_id,generation,sla_breached_at IS NOT NULL) FROM mail_thread_work WHERE mailbox_id=$1 ORDER BY thread_id"),
          ("outbox","SELECT jsonb_build_array(consumer_kind,state,attempts,last_error,receipt-'outboxId'-'eventId') FROM mail_work_outbox WHERE event_id IN (SELECT id FROM mail_thread_work_events WHERE mailbox_id=$1) ORDER BY consumer_kind"),
          ("digest","SELECT jsonb_build_array(category,delivered_at IS NOT NULL) FROM mail_work_digest_ledger WHERE mailbox_id=$1 ORDER BY category"),
          ("deliveries","SELECT jsonb_build_array(category,channel,outcome,why) FROM mail_work_notification_deliveries WHERE event_id IN (SELECT id FROM mail_thread_work_events WHERE mailbox_id=$1) ORDER BY category,channel"),
          ("state","SELECT to_jsonb(jmap_mailwork_state) FROM mailboxes WHERE id=$1"),
          ("metrics","SELECT jsonb_build_array(conversation_count,breached_count,actor_cohort_count) FROM mail_work_metric_daily WHERE mailbox_id=$1")
        ] { let rows=owner.query(&format!("SELECT v::text FROM ({sql}) AS observation(v)"),&[&a.mailbox]).await?; let values=rows.iter().map(|r|serde_json::from_str::<serde_json::Value>(&r.get::<_,String>(0))).collect::<Result<Vec<_>,_>>()?; obs.insert(name.into(),json!(values)); }
        obs.insert("notices".into(),json!(notices)); obs.insert("tags".into(),json!(tags));
        settle("mail-work-scan-digest",serde_json::Value::Object(obs),recording)
    }.await;
    for r in toggles {
        owner
            .execute(
                "UPDATE feature_toggles SET enabled=$2 WHERE key=$1",
                &[&r.get::<_, String>(0), &r.get::<_, bool>(1)],
            )
            .await?;
    }
    owner
        .execute(
            "DELETE FROM mail_work_digest_ledger WHERE mailbox_id=$1",
            &[&a.mailbox],
        )
        .await?;
    owner
        .execute("DELETE FROM tasks WHERE mailbox_id=$1", &[&a.mailbox])
        .await?;
    fixture::remove(&owner, &a).await?;
    result
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_work_internal_actions_tick() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("mail-work-internal") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let a = fixture::account(&owner, "mbox4-actions").await?;
    let audit_base: i64 = owner
        .query_one("SELECT coalesce(max(id),0) FROM admin_audit_log", &[])
        .await?
        .get(0);
    let shared:i64=owner.query_one("INSERT INTO mailboxes(domain_id,email,display_name,type) VALUES ($1,'shared-'||$1::bigint::text||'@mbox4.test','Shared','personal') RETURNING id",&[&a.domain]).await?.get(0);
    let channel:i64=owner.query_one("INSERT INTO chat_channels(kind,name,created_by) VALUES ('channel','mbox4-actions',$1) RETURNING id",&[&a.user]).await?.get(0);
    let space: i64 = owner
        .query_one(
            "INSERT INTO drive_spaces(name,owner_user_id) VALUES ('mbox4-actions',$1) RETURNING id",
            &[&a.user],
        )
        .await?
        .get(0);
    owner.execute("INSERT INTO drive_space_members(space_id,user_id,role,granted_by) VALUES ($1,$2,'manager',$2)",&[&space,&a.user]).await?;
    let node:i64=owner.query_one("INSERT INTO drive_nodes(space_id,kind,name,created_by) VALUES ($1,'folder','target',$2) RETURNING id",&[&space,&a.user]).await?.get(0);
    let mut tag = db.listen(&format!("tag:{shared}")).await?;
    let result=async {
        owner.batch_execute(&format!("INSERT INTO mailbox_delegates(mailbox_id,user_id,permission,granted_by) VALUES ({shared},{},'full_access',{}); INSERT INTO chat_channel_members(channel_id,user_id,role) VALUES ({channel},{},'owner'); INSERT INTO messages(mailbox_id,folder_id,message_id,from_addr,thread_id,raw_ref,size_bytes,subject) VALUES ({shared},1,'mbox4-action-source','a@x.test','actions','inline',1,'Internal & <sample>'); INSERT INTO mail_thread_work(mailbox_id,thread_id) VALUES ({shared},'actions');",a.user,a.user,a.user)).await?;
        for (i,kind,target,authorized) in [(1,"task",None,true),(2,"chat",Some(channel),true),(3,"drive",Some(node),true),(4,"task",None,false),(5,"chat",Some(channel),false),(6,"drive",Some(node),false)] {
            let event=format!("29500000-0000-4000-8000-{i:012}");
            owner.execute("INSERT INTO mail_thread_work_events(id,mailbox_id,thread_id,generation,event_type,actor_user_id,actor_display_snapshot,before_state,after_state,reason) VALUES ($1::text::uuid,$2,'actions',1,'action_requested',$3,'Actor','{}','{}','oracle')",&[&event,&shared,&a.user]).await?;
            let payload=json!({"actorUserId":if authorized {Some(a.user.to_string())} else {None},"targetId":target.map(|id|id.to_string())}).to_string();
            owner.execute("INSERT INTO mail_work_outbox(event_id,consumer_kind,dedupe_key,payload) VALUES ($1::text::uuid,$2,$3,$4::text::jsonb)",&[&event,&kind,&format!("mbox4-action-{i}"),&payload]).await?;
        }
        let recording=std::env::var_os("GOFREE_RECORD_DRAIN").is_some();
        if recording {GoTick{package:"internal/mailwork",overlay:"mail_work_tick_test.go.txt",test:"TestGoFreeMailWorkTick",file:"gofree_mail_work_tick_test.go",env:vec![("GOFREE_DRAIN_DSN".into(),db.dsn.clone()),("GOFREE_MAIL_TICKS".into(),"2".into())],docker:vec![]}.run()?;}
        else {let worker=MailWork::new(worker_db(&db.dsn)?);worker.tick().await;worker.tick().await;}
        let mut obs=serde_json::Map::new();
        for (name,sql) in [
            ("outbox",format!("SELECT jsonb_build_array(consumer_kind,state,attempts,last_error,receipt->>'actionKind',receipt->>'outcome') FROM mail_work_outbox WHERE dedupe_key LIKE 'mbox4-action-%' ORDER BY dedupe_key")),
            ("links",format!("SELECT jsonb_build_array(action_kind,target_id IS NULL,result_id IS NOT NULL) FROM mail_work_action_links WHERE mailbox_id={shared} ORDER BY action_kind")),
            ("tasks",format!("SELECT jsonb_build_array(title,categories,status) FROM tasks WHERE mailbox_id={} ORDER BY id",a.mailbox)),
            ("chat",format!("SELECT jsonb_build_array(body,msg_type) FROM chat_messages WHERE channel_id={channel} ORDER BY id")),
            ("state",format!("SELECT jsonb_build_array(generation,(SELECT jmap_mailwork_state FROM mailboxes WHERE id={shared})) FROM mail_thread_work WHERE mailbox_id={shared}")),
            ("audit",format!("SELECT jsonb_build_array(action,target_type) FROM admin_audit_log WHERE id>{audit_base} ORDER BY id"))
        ] {let rows=owner.query(&format!("SELECT v::text FROM ({sql}) AS observation(v)"),&[]).await?;let values=rows.iter().map(|r|serde_json::from_str::<serde_json::Value>(&r.get::<_,String>(0))).collect::<Result<Vec<_>,_>>()?;obs.insert(name.into(),json!(values));}
        obs.insert("notify".into(),json!(tag.drain(&owner).await?));
        // The only generated identifier present in these public projections is
        // the seeded shared mailbox in the chat link and notification accountId.
        let text=serde_json::Value::Object(obs).to_string().replace(&format!("accountId={shared}&"),"accountId=<shared>&").replace(&format!("\\\"accountId\\\": \\\"{shared}\\\""),"\\\"accountId\\\": \\\"<shared>\\\"");
        settle("mail-work-internal",serde_json::from_str(&text)?,recording)
    }.await;
    owner.batch_execute(&format!("BEGIN; SET LOCAL session_replication_role=replica; DELETE FROM admin_audit_log WHERE id>{audit_base}; COMMIT;")).await?;
    owner
        .execute("DELETE FROM chat_channels WHERE id=$1", &[&channel])
        .await?;
    owner
        .execute("DELETE FROM drive_nodes WHERE id=$1", &[&node])
        .await?;
    owner
        .execute(
            "DELETE FROM drive_space_members WHERE space_id=$1",
            &[&space],
        )
        .await?;
    owner
        .execute("DELETE FROM drive_spaces WHERE id=$1", &[&space])
        .await?;
    owner
        .execute("DELETE FROM messages WHERE mailbox_id=$1", &[&shared])
        .await?;
    owner
        .execute("DELETE FROM mailboxes WHERE id=$1", &[&shared])
        .await?;
    owner
        .execute("DELETE FROM tasks WHERE mailbox_id=$1", &[&a.mailbox])
        .await?;
    fixture::remove(&owner, &a).await?;
    result
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mailbox_lifecycle_purges_tick() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("mailbox-lifecycle-purges") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let a = fixture::account(&owner, "mbox4-purge").await?;
    let b = fixture::account(&owner, "mbox4-purge-approver").await?;
    let mut boxes = Vec::new();
    let result=async {
        for i in 1i32..=7 {
            let mailbox:i64=owner.query_one("INSERT INTO mailboxes(domain_id,email,display_name,type,litigation_hold) VALUES ($1,'purge-'||$2::int::text||'-'||$1::bigint::text||'@mbox4.test','Purge','personal',$3) RETURNING id",&[&a.domain,&i,&(i==2)]).await?.get(0);
            boxes.push(mailbox);
            owner.execute("UPDATE mailbox_lifecycle SET access_state='detached',delivery_state='rejecting',binding_state='retained',generation=2,retained_at=now()-interval '2 days',retention_until=now()-interval '1 day' WHERE mailbox_id=$1",&[&mailbox]).await?;
            let request=format!("29520000-0000-4000-8000-{i:012}");
            owner.execute("INSERT INTO mailbox_purge_requests(id,mailbox_id,operation_id,execute_operation_id,lifecycle_generation,preview_digest,requested_by,eligible_at,state,approved_by,reason) VALUES ($1::text::uuid,$2,$1::text::uuid,('29521000-0000-4000-8000-'||lpad($3::int::text,12,'0'))::uuid,1,repeat('a',64),$4,now()-interval '1 day','approved',$5,'mbox4 purge')",&[&request,&mailbox,&i,&a.user,&b.user]).await?;
            match i {
                3=>{owner.execute("UPDATE mailbox_lifecycle SET generation=3 WHERE mailbox_id=$1",&[&mailbox]).await?;}
                4=>{owner.execute("UPDATE mailbox_purge_requests SET eligible_at=now()+interval '1 day' WHERE id=$1::text::uuid",&[&request]).await?;}
                5=>{owner.execute("UPDATE mailbox_purge_requests SET state='claimed',claimed_by='other',attempts=1,lease_until=now()+interval '1 hour' WHERE id=$1::text::uuid",&[&request]).await?;}
                6=>{owner.execute("UPDATE mailbox_purge_requests SET attempts=20 WHERE id=$1::text::uuid",&[&request]).await?;}
                7=>{owner.execute("UPDATE mailbox_purge_requests SET state='failed',claimed_by='expired',attempts=2,lease_until=now()-interval '1 hour' WHERE id=$1::text::uuid",&[&request]).await?;}
                _=>{}
            }
        }
        let audit:i64=owner.query_one("SELECT coalesce(max(id),0) FROM admin_audit_log",&[]).await?.get(0);
        let recording=std::env::var_os("GOFREE_RECORD_DRAIN").is_some();
        if recording {GoTick{package:"internal/mailboxlifecycle",overlay:"mailbox_lifecycle_tick_test.go.txt",test:"TestGoFreeMailboxLifecycleTick",file:"gofree_mailbox_lifecycle_tick_test.go",env:vec![("GOFREE_DRAIN_DSN".into(),db.dsn.clone())],docker:vec![]}.run()?;}
        else {MailboxLifecycle::new(worker_db(&db.dsn)?).tick().await;}
        let obs=observation(&owner,vec![
            ("purges",format!("SELECT jsonb_build_array(id,state,attempts,claimed_by IS NOT NULL,lease_until>now(),blocker_snapshot) FROM mailbox_purge_requests WHERE requested_by={} ORDER BY id",a.user)),
            ("tombstones",format!("SELECT jsonb_build_array(purge_request_id,message_count,blob_count,purged_by={}) FROM mailbox_tombstones WHERE purged_by={} ORDER BY purge_request_id",a.user,a.user)),
            ("operations",format!("SELECT jsonb_build_array(action,result-'mailboxId'-'evidenceDigest') FROM mailbox_lifecycle_operations WHERE actor_user_id={} ORDER BY operation_id",a.user)),
            ("effects",format!("SELECT jsonb_build_array(effect_kind,state,attempts) FROM mailbox_lifecycle_effects WHERE operation_id IN (SELECT operation_id FROM mailbox_lifecycle_operations WHERE actor_user_id={}) ORDER BY operation_id",a.user)),
            ("audit",format!("SELECT jsonb_build_array(action,target_type) FROM admin_audit_log WHERE id>{audit} ORDER BY id")),
            ("remaining",format!("SELECT jsonb_build_array(email,EXISTS(SELECT 1 FROM mailbox_lifecycle l WHERE l.mailbox_id=m.id)) FROM mailboxes m WHERE id=ANY(ARRAY[{}]::bigint[]) ORDER BY email",boxes.iter().map(ToString::to_string).collect::<Vec<_>>().join(",")))
        ]).await?;
        let mut value=serde_json::Value::Object(obs);
        // Fixture ids occur in email only; leave all request ids and business fields intact.
        for row in value["remaining"].as_array_mut().unwrap(){row[0]=json!(row[0].as_str().unwrap().replace(&format!("-{}@",a.domain),"-<domain>@"));}
        settle("mailbox-lifecycle-purges",value,recording)
    }.await;
    owner
        .execute(
            "DELETE FROM mailbox_tombstones WHERE purged_by=$1",
            &[&a.user],
        )
        .await?;
    owner
        .execute(
            "DELETE FROM mailbox_purge_requests WHERE requested_by=$1",
            &[&a.user],
        )
        .await?;
    owner
        .execute(
            "DELETE FROM mailbox_lifecycle_operations WHERE actor_user_id=$1",
            &[&a.user],
        )
        .await?;
    owner
        .execute(
            "DELETE FROM mailbox_lifecycle WHERE mailbox_id=ANY($1)",
            &[&boxes],
        )
        .await?;
    owner
        .execute("DELETE FROM mailboxes WHERE id=ANY($1)", &[&boxes])
        .await?;
    fixture::remove(&owner, &a).await?;
    fixture::remove(&owner, &b).await?;
    result
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mailbox_lifecycle_media_tick() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    for mode in ["success", "not-found", "error"] {
        lifecycle_media(mode).await?;
    }
    Ok(())
}
async fn lifecycle_media(mode: &str) -> Result<(), BoxError> {
    let name = format!("mailbox-lifecycle-media-{mode}");
    let Some(db) = Db::for_case(&name) else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let a = fixture::account(&owner, "mbox4-media").await?;
    let fake = meet_peripherals::Fake::start().await;
    match mode {
        "not-found" | "not-found-horizon" => fake.fail(Some("RemoveParticipant")),
        "error" => fake.fail_with("RemoveParticipant", 403, "permission_denied"),
        "malformed" => fake.fail_with("RemoveParticipant", 200, "malformed"),
        _ => {}
    }
    let result=async {
        let op="29530000-0000-4000-8000-000000000001";
        owner.execute("INSERT INTO mailbox_lifecycle_operations(operation_id,mailbox_id,action,actor_user_id,expected_generation,request_digest,before_digest,after_digest,result) VALUES ($1::text::uuid,$2,'suspend',$3,1,repeat('a',64),repeat('b',64),repeat('c',64),'{}')",&[&op,&a.mailbox,&a.user]).await?;
        owner.execute("INSERT INTO mailbox_lifecycle_effects(operation_id,mailbox_id,effect_kind) VALUES ($1::text::uuid,$2,'evict_media')",&[&op,&a.mailbox]).await?;
        owner.execute("INSERT INTO mailbox_lifecycle_effect_targets(operation_id,room_name,identity,evict_until,completed_at) VALUES ($1::text::uuid,'a-room','u:one',NULL,NULL),($1::text::uuid,'z-room','u:two','2000-01-01',NULL),($1::text::uuid,'completed-room','u:gone',NULL,now())",&[&op]).await?;
        if mode=="complete-fault" {owner.batch_execute("CREATE OR REPLACE FUNCTION mbox4_refuse_complete() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.state='completed' AND NEW.effect_kind='evict_media' THEN RAISE EXCEPTION 'mbox4 completion refused' USING ERRCODE='55000'; END IF; RETURN NEW; END $$; CREATE TRIGGER mbox4_refuse_complete BEFORE UPDATE ON mailbox_lifecycle_effects FOR EACH ROW EXECUTE FUNCTION mbox4_refuse_complete();").await?;}
        let recording=std::env::var_os("GOFREE_RECORD_DRAIN").is_some();
        // Bound without listen: refuses TCP while preventing ephemeral port reuse.
        let refused=tokio::net::TcpSocket::new_v4()?;
        refused.bind("127.0.0.1:0".parse()?)?;
        let addr=if mode=="transport" {refused.local_addr()?}else{fake.addr};
        let url=format!("http://{addr}");
        if recording {GoTick{package:"internal/mailboxlifecycle",overlay:"mailbox_lifecycle_tick_test.go.txt",test:"TestGoFreeMailboxLifecycleTick",file:"gofree_mailbox_lifecycle_tick_test.go",env:vec![("GOFREE_DRAIN_DSN".into(),db.dsn.clone()),("GOFREE_MAIL_LK_URL".into(),url.clone()),("GOFREE_MAIL_HORIZON".into(),if mode.contains("horizon") {"1"}else{"0"}.into())],docker:vec![]}.run()?;}
        else {
            if mode.contains("horizon") {owner.execute("UPDATE mailbox_lifecycle_effect_targets SET evict_until=now()+interval '2 seconds' WHERE operation_id=$1::text::uuid AND room_name='a-room'",&[&op]).await?;}
            MailboxLifecycle::new(worker_db(&db.dsn)?).with_media(&url,meet_peripherals::KEY,meet_peripherals::SECRET).tick().await;}
        let mut obs=observation(&owner,vec![
            ("effects",format!("SELECT jsonb_build_array(state,attempts,last_error,completed_at IS NOT NULL) FROM mailbox_lifecycle_effects WHERE mailbox_id={}",a.mailbox)),
            ("targets",format!("SELECT jsonb_build_array(room_name,identity,completed_at IS NOT NULL) FROM mailbox_lifecycle_effect_targets WHERE operation_id='{op}' ORDER BY room_name"))
        ]).await?;
        for row in obs.get_mut("effects").unwrap().as_array_mut().unwrap() {if let Some(error)=row[2].as_str() {row[2]=json!(error.replace(&url,"<livekit>").replace(&addr.to_string(),"<livekit-address>"));}}
        obs.insert("calls".into(),json!(fake.drain()));
        settle(&name,serde_json::Value::Object(obs),recording)
    }.await;
    if mode == "complete-fault" {
        owner.batch_execute("DROP TRIGGER IF EXISTS mbox4_refuse_complete ON mailbox_lifecycle_effects; DROP FUNCTION IF EXISTS mbox4_refuse_complete();").await?;
    }
    owner
        .execute(
            "DELETE FROM mailbox_lifecycle_operations WHERE actor_user_id=$1",
            &[&a.user],
        )
        .await?;
    fixture::remove(&owner, &a).await?;
    result
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mailbox_lifecycle_media_horizon_tick() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    for mode in ["horizon", "not-found-horizon"] {
        lifecycle_media(mode).await?;
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mailbox_lifecycle_completion_fault_tick() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    lifecycle_media("complete-fault").await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mailbox_lifecycle_media_transport_tick() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    lifecycle_media("transport").await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_work_retry_tick() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("mail-work-retry") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let a = fixture::account(&owner, "mbox4-retry").await?;
    let result=async {
        let event="29540000-0000-4000-8000-000000000001";
        owner.execute("INSERT INTO mail_thread_work_events(id,mailbox_id,thread_id,generation,event_type,actor_user_id,actor_display_snapshot,before_state,after_state,reason,occurred_at) VALUES ($1::text::uuid,$2,'retry',1,'completed',$3,'Actor','{}','{}','oracle','2026-01-02T12:00:00Z')",&[&event,&a.mailbox,&a.user]).await?;
        for (i,attempts) in [(1i32,0i32),(2,9),(3,99),(4,1),(5,1)] {
            let key=format!("mbox4-retry-{i}");
            owner.execute("INSERT INTO mail_work_outbox(event_id,consumer_kind,dedupe_key,payload,attempts) VALUES ($1::text::uuid,'webhook',$2,'{\"eventType\":\"completed\"}',$3)",&[&event,&key,&attempts]).await?;
            if i==4 || i==5 {owner.execute("UPDATE mail_work_outbox SET state='claimed',lease_until=now()+CASE WHEN $2 THEN interval '1 hour' ELSE interval '-1 hour' END WHERE dedupe_key=$1",&[&key,&(i==4)]).await?;}
        }
        let recording=std::env::var_os("GOFREE_RECORD_DRAIN").is_some();
        if recording {GoTick{package:"internal/mailwork",overlay:"mail_work_tick_test.go.txt",test:"TestGoFreeMailWorkTick",file:"gofree_mail_work_tick_test.go",env:vec![("GOFREE_DRAIN_DSN".into(),db.dsn.clone()),("GOFREE_MAIL_TICKS".into(),"2".into())],docker:vec![]}.run()?;}
        else {let worker=MailWork::new(worker_db(&db.dsn)?);worker.tick().await;worker.tick().await;}
        let obs=observation(&owner,vec![("outbox",format!("SELECT jsonb_build_array(dedupe_key,state,attempts,last_error,receipt,lease_until>now(),completed_at IS NOT NULL) FROM mail_work_outbox WHERE event_id='{event}' ORDER BY dedupe_key"))]).await?;
        settle("mail-work-retry",serde_json::Value::Object(obs),recording)
    }.await;
    fixture::remove(&owner, &a).await?;
    result
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_workers_empty_webhook_dispatcher_tick() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("mail-workers-empty-webhooks") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let a = fixture::account(&owner, "mbox4-empty-webhooks").await?;
    let result=async {
        owner.execute("INSERT INTO webhook_subscriptions(user_id,url,secret,event_types,scope) VALUES ($1,'http://127.0.0.1:1','test-secret-only','[\"message.received\"]','organization'),($1,'http://127.0.0.1:1','test-secret-only','[\"mailwork.completed\",\"mailbox.suspended\"]','self')",&[&a.user]).await?;
        let event="29550000-0000-4000-8000-000000000001";
        owner.execute("INSERT INTO mail_thread_work_events(id,mailbox_id,thread_id,generation,event_type,actor_user_id,actor_display_snapshot,before_state,after_state,reason,occurred_at) VALUES ($1::text::uuid,$2,'webhooks',1,'completed',$3,'Actor','{}','{}','oracle','2026-01-02T12:00:00Z')",&[&event,&a.mailbox,&a.user]).await?;
        for (i,kind) in ["claimed","assigned","reassigned","handed_off","completed","sla_breached","unapproved"].iter().enumerate() {
            let payload=json!({"eventType":kind,"mailboxId":a.mailbox,"threadId":"webhooks","generation":1}).to_string();
            owner.execute("INSERT INTO mail_work_outbox(event_id,consumer_kind,dedupe_key,payload) VALUES ($1::text::uuid,'webhook',$2,$3::text::jsonb)",&[&event,&format!("mbox4-empty-{i}"),&payload]).await?;
        }
        let op="29551000-0000-4000-8000-000000000001";
        owner.execute("INSERT INTO mailbox_lifecycle_operations(operation_id,mailbox_id,action,actor_user_id,expected_generation,request_digest,before_digest,after_digest,result) VALUES ($1::text::uuid,$2,'suspend',$3,1,repeat('a',64),repeat('b',64),repeat('c',64),'{}')",&[&op,&a.mailbox,&a.user]).await?;
        owner.execute("INSERT INTO mailbox_lifecycle_effects(operation_id,mailbox_id,effect_kind) VALUES ($1::text::uuid,$2,'lifecycle_webhook')",&[&op,&a.mailbox]).await?;
        owner.execute("INSERT INTO mailbox_lifecycle_outbox(operation_id,event_kind,dedupe_key,payload) VALUES ($1::text::uuid,'mailbox.suspended','mbox4-empty-lifecycle','{\"safe\":true}')",&[&op]).await?;
        let recording=std::env::var_os("GOFREE_RECORD_DRAIN").is_some();
        if recording {
            for (package,overlay,test,file) in [("internal/mailwork","mail_work_tick_test.go.txt","TestGoFreeMailWorkTick","gofree_mail_work_tick_test.go"),("internal/mailboxlifecycle","mailbox_lifecycle_tick_test.go.txt","TestGoFreeMailboxLifecycleTick","gofree_mailbox_lifecycle_tick_test.go")] {
                GoTick{package,overlay,test,file,env:vec![("GOFREE_DRAIN_DSN".into(),db.dsn.clone()),("GOFREE_MAIL_WEBHOOKS".into(),"empty".into())],docker:vec![]}.run()?;
            }
        } else {
            let dispatcher = unguarded(&db.dsn)?;
            MailWork::new(worker_db(&db.dsn)?).with_dispatcher(dispatcher.clone()).tick().await;
            MailboxLifecycle::new(worker_db(&db.dsn)?).with_dispatcher(dispatcher.clone()).tick().await;
            dispatcher.shutdown().await;
        }
        let obs=observation(&owner,vec![
            ("work",format!("SELECT jsonb_build_array(dedupe_key,state,attempts,last_error,receipt-'outboxId') FROM mail_work_outbox WHERE event_id='{event}' ORDER BY dedupe_key")),
            ("lifecycle",format!("SELECT jsonb_build_array(state,attempts,last_error,completed_at IS NOT NULL) FROM mailbox_lifecycle_effects WHERE mailbox_id={}",a.mailbox)),
            ("lifecycle-outbox",format!("SELECT jsonb_build_array(state,attempts,last_error,completed_at IS NOT NULL) FROM mailbox_lifecycle_outbox WHERE operation_id='{op}'")),
            ("deliveries",format!("SELECT to_jsonb(count(*)) FROM webhook_deliveries WHERE subscription_id IN (SELECT id FROM webhook_subscriptions WHERE user_id={})",a.user))
        ]).await?;
        settle("mail-workers-empty-webhooks",serde_json::Value::Object(obs),recording)
    }.await;
    owner
        .execute(
            "DELETE FROM mailbox_lifecycle_operations WHERE actor_user_id=$1",
            &[&a.user],
        )
        .await?;
    fixture::remove(&owner, &a).await?;
    result
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_work_oracle_rejects_omitted_tick() -> Result<(), BoxError> {
    match metric_case(true).await {
        Err(error)
            if error.to_string().contains("/outbox") && error.to_string().contains("/metrics") =>
        {
            println!("MUTANT-REJECTED: mail-work :: omitted tick (queue and metric effects)");
            Ok(())
        }
        Err(error) => Err(error),
        Ok(()) => Err("mail-work oracle accepted an omitted tick".into()),
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lifecycle_oracle_rejects_omitted_tick() -> Result<(), BoxError> {
    match lifecycle_effects_case(true).await {
        Err(error)
            if error.to_string().contains("/effects")
                && error.to_string().contains("/notifies")
                && error.to_string().contains("/audit") =>
        {
            println!("MUTANT-REJECTED: mailbox-lifecycle :: omitted tick (effects, audit and notifications)");
            Ok(())
        }
        Err(error) => Err(error),
        Ok(()) => Err("mailbox-lifecycle oracle accepted an omitted tick".into()),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mailbox_lifecycle_media_malformed_response_tick() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    lifecycle_media("malformed").await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mail_workers_webhook_delivery_tick() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("mail-workers-webhook-delivery") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let a = fixture::account(&owner, "mbox4-webhook-delivery").await?;
    let seen: Seen = Seen::default();
    let hook = hooks::receiver(seen.clone()).await;
    let result = async {
        hooks::clear(&owner).await?;
        let all = r#"["mailwork.claimed","mailwork.assigned","mailwork.handed_off","mailwork.completed","mailwork.sla_breached","mailbox.suspended","mailbox.resumed","mailbox.detached","mailbox.reconnected","mailbox.purge_scheduled","mailbox.purge_cancelled","mailbox.purged"]"#;
        for (path, scope, active, types) in [
            ("/all", "organization", true, all),
            ("/completed", "organization", true, r#"["mailwork.completed"]"#),
            ("/self", "self", true, all),
            ("/inactive", "organization", false, all),
        ] {
            hooks::subscribe(&owner, a.user, hook, path, types, scope, active).await?;
        }
        let kinds = [
            json!({"eventType":"claimed","mailboxId":a.mailbox,"threadId":"t<b>&\u{e9}","generation":1}),
            json!({"eventType":"assigned","mailboxId":a.mailbox,"threadId":"t1","generation":2.5}),
            json!({"eventType":"reassigned","mailboxId":a.mailbox,"threadId":"t2","generation":12345678901234567890u64}),
            json!({"eventType":"handed_off","mailboxId":a.mailbox,"threadId":"t3","secret":"must-not-leak"}),
            json!({"eventType":"completed","mailboxId":a.mailbox,"threadId":"t4","generation":0.0000001}),
            json!({"eventType":"sla_breached","mailboxId":a.mailbox,"threadId":null,"generation":3}),
            json!({"eventType":"unapproved","mailboxId":a.mailbox,"threadId":"t6","generation":1}),
            json!({"mailboxId":a.mailbox,"threadId":"t7"}),
        ];
        for (i, payload) in kinds.iter().enumerate() {
            let event = format!("29590000-0000-4000-8000-{:012}", i + 1);
            owner.execute("INSERT INTO mail_thread_work_events(id,mailbox_id,thread_id,generation,event_type,actor_user_id,actor_display_snapshot,before_state,after_state,reason,occurred_at) VALUES ($1::text::uuid,$2,$3,1,'completed',$4,'Actor','{}','{}','oracle','2026-01-02T12:00:00Z')",&[&event,&a.mailbox,&format!("wh{i}"),&a.user]).await?;
            owner.execute("INSERT INTO mail_work_outbox(event_id,consumer_kind,dedupe_key,payload) VALUES ($1::text::uuid,'webhook',$2,$3::text::jsonb)",&[&event,&format!("mbox-wh-{i}"),&payload.to_string()]).await?;
        }
        let lifecycle = [
            ("suspend", "mailbox.suspended", Some(r#"{"mailboxId":"1","generation":"1","event":"mailbox.suspended"}"#), "2026-01-02T12:00:00.123456Z"),
            ("resume", "mailbox.resumed", Some(r#"{"z":"<tag> & \u00fcn\u00ef","mailboxId":"1","generation":"2","event":"mailbox.resumed"}"#), "2026-01-02T12:00:00Z"),
            ("detach_retain", "mailbox.detached", Some(r#"{"mailboxId":"1","generation":"3","event":"mailbox.detached"}"#), "2026-01-02T12:00:00.5+02:00"),
            ("reconnect", "mailbox.reconnected", None, "2026-01-02T12:00:00Z"),
            ("purge_execute", "mailbox.purged", Some(r#"{"a":{"b":[1,2.5,"x"],"aa":null},"event":"mailbox.purged"}"#), "2026-12-31T23:59:59.000001Z"),
        ];
        for (i, (action, kind, payload, created)) in lifecycle.iter().enumerate() {
            let op = format!("29591000-0000-4000-8000-{:012}", i + 1);
            let generation = i as i64 + 1;
            owner.execute("INSERT INTO mailbox_lifecycle_operations(operation_id,mailbox_id,action,actor_user_id,expected_generation,request_digest,before_digest,after_digest,result) VALUES ($1::text::uuid,$2,$3,$4,$5,repeat('a',64),repeat('b',64),repeat('c',64),'{}')",&[&op,&a.mailbox,action,&a.user,&generation]).await?;
            owner.execute("INSERT INTO mailbox_lifecycle_effects(operation_id,mailbox_id,effect_kind) VALUES ($1::text::uuid,$2,'lifecycle_webhook')",&[&op,&a.mailbox]).await?;
            if let Some(payload) = payload {
                owner.execute("INSERT INTO mailbox_lifecycle_outbox(operation_id,event_kind,dedupe_key,payload,created_at) VALUES ($1::text::uuid,$2,$3,$4::text::jsonb,$5::text::timestamptz)",&[&op,kind,&format!("mbox-wh-lc-{i}"),payload,created]).await?;
            }
        }
        let recording = std::env::var_os("GOFREE_RECORD_DRAIN").is_some();
        if recording {
            for (package, overlay, test, file) in [("internal/mailwork","mail_work_tick_test.go.txt","TestGoFreeMailWorkTick","gofree_mail_work_tick_test.go"),("internal/mailboxlifecycle","mailbox_lifecycle_tick_test.go.txt","TestGoFreeMailboxLifecycleTick","gofree_mailbox_lifecycle_tick_test.go")] {
                GoTick{package,overlay,test,file,env:vec![("GOFREE_DRAIN_DSN".into(),db.dsn.clone()),("GOFREE_MAIL_WEBHOOKS".into(),"deliver".into()),("GOFREE_WEBHOOK_MASTER".into(),hooks::MASTER.into())],docker:vec![]}
                    .run_with(&[("internal/webhook","gofree_unguarded_export.go","webhook_unguarded_export.go.txt")])?;
            }
        } else {
            let dispatcher = unguarded(&db.dsn)?;
            MailWork::new(worker_db(&db.dsn)?).with_dispatcher(dispatcher.clone()).tick().await;
            MailboxLifecycle::new(worker_db(&db.dsn)?).with_dispatcher(dispatcher.clone()).tick().await;
            dispatcher.shutdown().await;
        }
        let mut obs = observation(&owner, vec![
            ("work", "SELECT jsonb_build_array(dedupe_key,state,attempts,last_error,receipt-'outboxId') FROM mail_work_outbox WHERE event_id::text LIKE '29590000%' ORDER BY dedupe_key".to_string()),
            ("lifecycle", format!("SELECT jsonb_build_array(operation_id::text,state,attempts,last_error,completed_at IS NOT NULL) FROM mailbox_lifecycle_effects WHERE mailbox_id={} ORDER BY operation_id", a.mailbox)),
            ("lifecycle-outbox", "SELECT jsonb_build_array(operation_id::text,state,attempts,last_error,completed_at IS NOT NULL) FROM mailbox_lifecycle_outbox WHERE dedupe_key LIKE 'mbox-wh-lc-%' ORDER BY operation_id".to_string()),
        ]).await?;
        // The mailbox id is run-specific: name it in every body that carries it.
        let mailbox = |value: serde_json::Value| {
            let text = value.to_string().replace(&format!("\\\"mailboxId\\\": {}", a.mailbox), "\\\"mailboxId\\\": <mailbox>");
            serde_json::from_str::<serde_json::Value>(&text).unwrap()
        };
        obs.insert("deliveries".into(), mailbox(hooks::deliveries(&owner).await?));
        obs.insert("requests".into(), mailbox(hooks::requests(&seen)));
        settle("mail-workers-webhook-delivery", serde_json::Value::Object(obs), recording)
    }.await;
    let _ = hooks::clear(&owner).await;
    owner.execute("DELETE FROM mailbox_lifecycle_operations WHERE actor_user_id=$1",&[&a.user]).await?;
    fixture::remove(&owner, &a).await?;
    result
}
