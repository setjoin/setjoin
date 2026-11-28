//! Guest mutations: HTTP, complete owned rows, audit and committed publish seam.
use crate::common::{self, BoxError};
use hyper::{Request, Response};
use serde_json::{json, Value};
use setjoin_conformance::{fixture, golden, harness::Db};
use setjoin_gateway::{guests::GuestsRoute, Config, Gateway, RouteTable, TrustedProxies};
use setjoin_pg::ScopedExecutor;
use std::{collections::BTreeMap, sync::Arc};
const TABLES: &[(&str, &str)] = &[
    ("guest_accounts", "user_id"),
    ("users", "id"),
    ("guest_invites", "guest_user_id"),
    ("user_app_entitlements", "user_id"),
    ("identity_auth_link_elevations", "user_id"),
    ("oauth_tokens", "user_id"),
    ("oidc_tokens", "user_id"),
    ("ws_subscriptions", "user_id"),
    ("sessions", "user_id"),
    ("mfa_reauth_step_ups", "user_id"),
    ("webauthn_ceremonies", "user_id"),
    ("session_revocations", "user_id"),
    ("guest_live_eviction_intents", "guest_user_id"),
    ("chat_channel_members", "user_id"),
    ("meeting_participants", "user_id"),
    ("meeting_join_requests", "user_id"),
];
pub(super) struct Fixture<'a> {
    pub(super) a: &'a fixture::Account,
    pub(super) b: &'a fixture::Account,
    pub(super) guest: i64,
    pub(super) email: &'a str,
    pub(super) domain: i64,
    pub(super) profile: i64,
    pub(super) revocations: Vec<i64>,
    pub(super) invite: i64,
    pub(super) invites: Vec<i64>,
    pub(super) approval: i64,
    pub(super) fixed_expiry: bool,
    pub(super) domain_names: [String; 2],
}
pub async fn run(action: &str, kind: &str) -> Result<(), BoxError> {
    run_fault(action, kind, None).await
}
pub async fn run_fault(action: &str, kind: &str, fault: Option<&str>) -> Result<(), BoxError> {
    let mutant = kind.ends_with("-status-mutant");
    let kind = kind.strip_suffix("-status-mutant").unwrap_or(kind);
    let colliding_ids = kind.ends_with("-colliding-ids");
    let kind = kind.strip_suffix("-colliding-ids").unwrap_or(kind);
    let label = kind;
    let kind = kind.strip_suffix("-qualified").unwrap_or(kind);
    let kind = kind.strip_suffix("-inventory").unwrap_or(kind);
    let Some(mut db) = Db::for_case("guests-mutation") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    if kind == "profile-dst" {
        for dsn in std::iter::once(&mut db.dsn).chain(db.app.iter_mut()) {
            dsn.push_str(if dsn.contains('?') {
                "&options=-cTimeZone%3DAmerica%2FNew_York"
            } else {
                "?options=-cTimeZone%3DAmerica%2FNew_York"
            });
        }
    }
    let a = fixture::account(&owner, "guests1-admin").await?;
    let b = fixture::account(&owner, "guests1-other").await?;
    let (guest, email) = super::seed_guest_state(
        &owner,
        &a,
        if action == "enable" {
            "disabled"
        } else {
            "active"
        },
    )
    .await?;
    let foreign_email: String = owner
        .query_one("SELECT email FROM users WHERE id=$1", &[&b.user])
        .await?
        .get(0);
    let invitation = matches!(action, "invite" | "reinvite" | "approval");
    if matches!(action, "invite" | "approval") {
        owner
            .execute("DELETE FROM users WHERE id=$1", &[&guest])
            .await?;
    }
    let approval = if action == "approval" {
        // Independent tables may issue the same numeric ID. Reserve one invite
        // sequence value so the next command's invite equals this approval ID.
        let id = if colliding_ids {
            Some(
                owner
                    .query_one(
                        "SELECT nextval(pg_get_serial_sequence('guest_invites','id')) + 1",
                        &[],
                    )
                    .await?
                    .get::<_, i64>(0),
            )
        } else {
            None
        };
        owner.query_one("INSERT INTO approval_requests(id,consumer_type,requester_user_id,subject,payload,approver_kind,approver_ref,created_at,expires_at,domain_id) VALUES(COALESCE($5::bigint,nextval(pg_get_serial_sequence('approval_requests','id'))),'guest.invite',$1,'Invite guest',jsonb_build_object('invited_email',$2::text),'user',$3,'2026-10-01T12:00:00Z','2099-11-01T12:00:00Z',$4) RETURNING id",&[&a.user,&email,&b.user,&a.domain,&id]).await?.get::<_,i64>(0)
    } else {
        0
    };
    let invite = if action == "revoke" {
        owner
            .execute(
                "UPDATE guest_accounts SET status='invited' WHERE user_id=$1",
                &[&guest],
            )
            .await?;
        owner
            .execute("UPDATE users SET enabled=false WHERE id=$1", &[&guest])
            .await?;
        owner.query_one("SELECT guest_invite_create($1,$2,repeat('a',64),$3,(SELECT email FROM users WHERE id=$1),'2099-11-01T12:00:00Z')",&[&a.user,&guest,&a.domain]).await?.get::<_,i64>(0)
    } else {
        0
    };
    let profile:i64=owner.query_one("INSERT INTO guest_profiles(host_domain_id,name,apps,created_at,updated_at) VALUES($1,'Assigned <profile>',ARRAY['chat'],'2026-10-01T12:00:00Z','2026-10-01T12:00:00Z') RETURNING id",&[&a.domain]).await?.get(0);
    let role:i64=owner.query_one("INSERT INTO admin_role_groups(name,permissions,domain_scope) VALUES($1,ARRAY['guests.view','guests.manage'],$2) RETURNING id",&[&format!("guests1-{}",a.user),&a.domain]).await?.get(0);
    owner
        .execute(
            "INSERT INTO admin_role_assignments(user_id,role_group_id,granted_by) VALUES($1,$2,$1)",
            &[&a.user, &role],
        )
        .await?;
    if kind == "foreign" {
        owner
            .execute(
                "UPDATE admin_role_groups SET domain_scope=$2 WHERE id=$1",
                &[&role, &b.domain],
            )
            .await?;
    }
    if action == "transfer" {
        owner.batch_execute(&format!("BEGIN; UPDATE users SET domain_id={},email='guests1-sponsor@'||(SELECT name FROM domains WHERE id={}) WHERE id={}; UPDATE mailboxes SET domain_id={},email='guests1-sponsor@'||(SELECT name FROM domains WHERE id={}) WHERE id={}; COMMIT;",a.domain,a.domain,b.user,a.domain,a.domain,b.mailbox)).await?;
    }
    let enabled: bool = owner
        .query_one(
            "SELECT enabled FROM feature_toggles WHERE key='feature.guest_accounts'",
            &[],
        )
        .await?
        .get(0);
    owner
        .execute(
            "UPDATE feature_toggles SET enabled=true WHERE key='feature.guest_accounts'",
            &[],
        )
        .await?;
    let audit_start: i64 = owner
        .query_one("SELECT COALESCE(max(id),0) FROM admin_audit_log", &[])
        .await?
        .get(0);
    let receipts = owner
        .query(
            "SELECT operation_id::text FROM rust_operation_receipts WHERE family IN('F10','F11')",
            &[],
        )
        .await?
        .iter()
        .map(|r| r.get::<_, String>(0))
        .collect::<Vec<_>>();
    let prior_config = owner
        .query(
            "SELECT key,value::text FROM system_config WHERE key=ANY($1)",
            &[&vec![
                "authserver.public_url",
                "mail.default_sender",
                "guest.invite_ttl_days",
            ]],
        )
        .await?;
    if invitation {
        owner.batch_execute("INSERT INTO system_config(key,value) VALUES('authserver.public_url','\"https://auth.host.test\"'),('mail.default_sender','\"invite@host.test\"') ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value").await?;
    }
    if invitation {
        if matches!(kind, "bad-public-url" | "profile-bad-url") {
            owner.batch_execute("UPDATE system_config SET value='\"not-a-url\"' WHERE key='authserver.public_url'").await?;
        }
        if matches!(kind, "bad-ttl" | "overflow-ttl") {
            let value = serde_json::to_string(if kind == "bad-ttl" {
                "invalid"
            } else {
                "2147483648"
            })?;
            owner.execute("INSERT INTO system_config(key,value) VALUES('guest.invite_ttl_days',$1::text::jsonb) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value",&[&value]).await?;
        }
        if kind.starts_with("profile") {
            let days = if kind == "profile-overflow" {
                i32::MAX
            } else if kind == "profile-dst" {
                2
            } else {
                10
            };
            owner
                .execute(
                    "UPDATE guest_profiles SET default_expiry_days=$2 WHERE id=$1",
                    &[&profile, &days],
                )
                .await?;
        }
        if kind == "allowlist" {
            owner.execute("INSERT INTO guest_invite_domains(domain,host_domain_id,added_by,added_by_email) VALUES($1,$2,$3,(SELECT email FROM users WHERE id=$3))",&[&format!("guests1-policy-{}.test",a.user),&a.domain,&a.user]).await?;
        }
    }
    let schema = format!("gofree_guests1_notify_{}", a.user);
    let mut worker_dsn = db.dsn.clone();
    if fault == Some("no-notify") {
        owner
            .batch_execute(&format!("CREATE SCHEMA {schema}"))
            .await?;
        for name in [
            "revoke_user_sessions",
            "guest_set_status",
            "rust_guest_status",
        ] {
            let mut source:String=owner.query_one("SELECT pg_get_functiondef(oid) FROM pg_proc WHERE proname=$1 AND pronamespace='public'::regnamespace",&[&name]).await?.get(0);
            source = source.replace(
                &format!("FUNCTION public.{name}("),
                &format!("FUNCTION {schema}.{name}("),
            );
            source = source.replace(
                "SET search_path TO 'pg_catalog', 'public'",
                &format!("SET search_path TO 'pg_catalog', '{schema}', 'public'"),
            );
            if name == "revoke_user_sessions" {
                let needle = "PERFORM app_notify('session_revoke', v_payload::TEXT);";
                if !source.contains(needle) {
                    return Err("notification fixture marker missing".into());
                }
                source = source.replace(needle, "");
            }
            owner.batch_execute(&source).await?;
        }
        worker_dsn.push_str(&format!(
            "{}options=-csearch_path%3D{schema}%2Cpublic",
            if worker_dsn.contains('?') { "&" } else { "?" }
        ));
    }
    let result=async{
  let (s3,captures)=super::mail::endpoint(kind=="delivery-fails").await;let _mail_env=if action=="approval"{Some(super::mail::Environment::new(s3))}else{None};
  let go=common::go_oracle::start_named(&db,s3,None,"gofree-guests1-http").await?;let recording=go.is_some();
  let exec=ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn),4).map_err(|e|e.0)?.with_audit_keys("22".repeat(32),String::new());
  let worker=ScopedExecutor::from_dsn(&worker_dsn,4).map_err(|e|e.0)?.with_audit_keys("22".repeat(32),String::new());
  let approvals=setjoin_gateway::approvals::ApprovalsRoute{exec:exec.clone(),worker_exec:worker.clone(),keys:Arc::new(common::recovery_keys()),issuer:"mailserver".into(),secret:vec![]};
  let adapter=GuestsRoute{exec,worker,keys:Arc::new(common::recovery_keys()),issuer:"mailserver".into(),lifecycle:None,delivery:Some(Arc::new(setjoin_gateway::recovery_worker::S3Store::new(&format!("http://{s3}"),"mailblobs","test-access","test-secret")?))};
  let mut inventory:Value=serde_json::from_str(include_str!("../../route-inventory.json"))?;for route in inventory["routes"].as_array_mut().ok_or("routes")?{if route["family"]=="F11"||(action=="approval"&&route["family"]=="F10"){route["state"]=json!(if recording{"OFF"}else{"ON"});route["upstream"]=json!(if recording{"go-mail"}else{"local-rust"});route["oracle_commands"]=json!([""]);}}
  let gateway=Gateway::new(Config{upstream:go.as_ref().map(|g|format!("http://{}",g.address).parse()).transpose()?,trusted_proxies:TrustedProxies::parse("")?,upstream_header_timeout:setjoin_gateway::proxy::DEFAULT_HEADER_TIMEOUT,edge_limit:None},RouteTable::proxy_all().with(approvals).with(super::probe::Probe{inner:adapter,changed_status:mutant,unfiltered:false}))?.with_inventory(&inventory.to_string())?;
  let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await?;let address=listener.local_addr()?;let server=tokio::spawn(gateway.serve(listener));
  let method=if action=="revoke"{"DELETE"}else if action=="assign"{"PUT"}else{"POST"};let pattern=if action=="approval"{"/me/approvals/{id}/decide".into()}else if action=="revoke"{"/admin/guests/{userId}/invite".into()}else if action=="invite"{"/admin/guests".into()}else{format!("/admin/guests/{{id}}/{}",if action=="revoke"{"invite"}else if action=="assign"{"profile"}else{action})};let path=pattern.replace("{id}",&if kind=="invalid"{"bad".into()}else if action=="approval"{approval.to_string()}else{guest.to_string()}).replace("{userId}",&if kind=="invalid"{"bad".into()}else{guest.to_string()});let path=match kind{"encoded-id"=>path.replace(&format!("/{guest}/"),&format!("/{}/",guest.to_string().bytes().map(|b|format!("%{b:02X}")).collect::<String>())),"encoded-prefix"=>path.replacen("/admin/","/%61dmin/",1),"encoded-slash"=>path.replace(&format!("/{guest}/"),&format!("/{guest}%2Fextra/")),"encoded-mount"=>format!("/%61pi{path}"),_=>path};let body=if action=="approval"{json!({"decision":if kind=="deny"{"deny"}else{"approve"},"comment":"reviewed"}).to_string()}else if action=="invite"{if kind=="invalid"{json!({"email":"bad"}).to_string()}else{if kind.starts_with("profile"){json!({"email":email,"displayName":"Invited <Guest>","profileId":profile}).to_string()}else{json!({"email":if kind=="foreign"{owner.query_one("SELECT email FROM users WHERE id=$1",&[&b.user]).await?.get::<_,String>(0)}else{email.clone()},"displayName":"Invited <Guest>"}).to_string()}}}else if action=="reinvite"{if kind=="null-expiry"{r#"{"expiresAt":"2100-11-01T12:00:00Z","expiresAt":null}"#.into()}else{"{}".into()}}else if action=="revoke"{json!({"expectedInviteId":if kind=="stale"{(invite+1).to_string()}else{invite.to_string()}}).to_string()}else if action=="transfer"{json!({"sponsorUserId":b.user}).to_string()}else if action=="assign"{json!({"profileId":profile}).to_string()}else if action=="extend"{if kind=="invalid"{"{}".into()}else{json!({"expiresAt":match kind{"time-hour"=>"2100-11-01T1:00:00Z","time-comma"=>"2100-11-01T12:00:00,123456789Z","time-zone-hour"=>"2100-11-01T12:00:00+24:00","time-zone-minute"=>"2100-11-01T12:00:00+00:60","time-leap"=>"2100-11-01T12:00:60Z","time-lower-z"=>"2100-11-01T12:00:00z","fractional"=>"2100-11-01T12:00:00.123456789+08:00","submicro-zero"=>"0001-01-01T00:00:00.000000001Z",_=>"2100-11-01T12:00:00Z"}}).to_string()}}else{String::new()};
  let body=match kind{"bad-json"=>"{".into(),"bad-profile"=>json!({"email":email,"profileId":0}).to_string(),"bad-expiry"=>json!({"email":email,"expiresAt":"bad"}).to_string(),"missing-expiry"|"missing-expected"|"missing-profile"=>"{}".into(),"null-profile"=>json!({"profileId":null}).to_string(),"bad-expected"=>json!({"expectedInviteId":"01"}).to_string(),_=>body};
  if kind=="repeat"{let first=request(address,method,&path,&body,a.user).await?;let code=first.status();let data=common::body_bytes(first).await;if code.as_u16()!=(if invitation{202}else if matches!(action,"transfer"|"revoke"){200}else{204}){return Err(format!("initial {action}: {code}: {data:?}").into())}}
  let mut before=snapshot(&owner,guest).await?;let prior_approval=if action=="approval"{owner.query("SELECT to_jsonb(t)::text FROM approval_requests t WHERE id=$1",&[&approval]).await?.iter().map(|r|serde_json::from_str::<Value>(&r.get::<_,String>(0))).collect::<Result<Vec<_>,_>>()?}else{vec![]};let states_before=states(&owner,&[a.mailbox,b.mailbox]).await?;
  let last:i64=owner.query_one("SELECT COALESCE(max(id),0) FROM admin_audit_log",&[]).await?.get(0);
  let mut revoked=db.listen("session_revoke").await?;let mut decided=db.listen("approval_decided").await?;
  let response=request(address,method,&path,&body,if action=="approval"{b.user}else{a.user}).await?;let status=response.status().as_u16();
  let mut headers=serde_json::Map::new();for name in response.headers().keys(){headers.insert(name.to_string(),json!(response.headers().get_all(name).iter().map(|v|v.to_str().unwrap().to_owned()).collect::<Vec<_>>()));}
  let raw=String::from_utf8(common::body_bytes(response).await.to_vec())?;let guest=if matches!(action,"invite"|"approval"){owner.query_opt("SELECT id FROM users WHERE email=$1",&[&email]).await?.map(|r|r.get::<_,i64>(0)).unwrap_or(guest)}else{guest};let mut after=snapshot(&owner,guest).await?;
  let wanted=match kind{"bad-json"|"bad-profile"|"bad-expiry"|"missing-expiry"|"missing-expected"|"bad-expected"|"missing-profile"=>400,"time-leap"|"time-lower-z"=>400,"encoded-slash"=>400,"encoded-mount"=>404,"bad-public-url"|"bad-ttl"|"profile-bad-url"=>500,"allowlist"=>403,"wire-mime"|"profile"|"profile-overflow"|"profile-dst"|"null-expiry"|"overflow-ttl"=>202,_ if action=="approval"=>200,"foreign" if action=="invite"=>409,"foreign" if action=="reinvite"=>404,"delivery-fails"=>503,"success"|"repeat" if invitation=>202,"foreign" if action=="revoke"=>403,"repeat" if action=="revoke"=>404,"stale"=>409,"foreign"=>404,"invalid"=>400,"repeat" if action=="enable"=>422,"submicro-zero"=>422,"repeat" if action=="transfer"=>422,_ if matches!(action,"transfer"|"revoke")=>200,_=>204};
  if recording&&status!=wanted{return Err(format!("Go {action} expected {wanted}, got {status}: {raw}").into())}
  if kind.starts_with("profile")&&status==202{let days:i64=if kind=="profile-overflow"{i64::from(i32::MAX)}else if kind=="profile-dst"{2}else{10};let expected=(days.wrapping_mul(86_400_000_000_000)as f64)/1e9;let actual:f64=owner.query_one("SELECT extract(epoch FROM g.expires_at-u.created_at)::float8 FROM guest_accounts g JOIN users u ON u.id=g.user_id WHERE g.user_id=$1",&[&guest]).await?.get(0);if (actual-expected).abs()>1.0{return Err(format!("profile expiry differs from Go absolute duration: {actual} versus {expected}").into())}}
  if kind=="fractional"&&after["guest_accounts"][0]["expires_at"]!="2100-11-01T04:00:00.123456+00:00"{return Err("expiry failed frozen-Go microsecond truncation".into())}
  let mut audit=owner.query("SELECT to_jsonb(t)::text FROM admin_audit_log t WHERE id>$1 ORDER BY id",&[&last]).await?.iter().map(|r|serde_json::from_str(&r.get::<_,String>(0))).collect::<Result<Vec<Value>,_>>()?;
  let mut notify=vec![];for payload in revoked.drain(&owner).await?{notify.push(json!({"channel":"session_revoke","payload":serde_json::from_str::<Value>(&payload)?}));}
  let invite=if invitation{after["guest_invites"].iter().filter_map(|r|r["id"].as_i64()).max().unwrap_or(0)}else{invite};
  if colliding_ids && (invite <= 0 || invite != approval) { return Err("approval fixture did not collide with its invite ID".into()); }
  let mut f=Fixture{a:&a,b:&b,guest,email:&email,profile,invite,approval,fixed_expiry:kind.starts_with("time-"),invites:after["guest_invites"].iter().filter_map(|r|r["id"].as_i64()).collect(),domain:owner.query_one("SELECT id FROM domains WHERE name='guest.invalid'",&[]).await?.get(0),revocations:vec![],domain_names:[owner.query_one("SELECT name FROM domains WHERE id=$1",&[&a.domain]).await?.get(0),owner.query_one("SELECT name FROM domains WHERE id=$1",&[&b.domain]).await?.get(0)]};
  for rows in [&before["session_revocations"],&after["session_revocations"]]{for row in rows{f.revocations.push(row["id"].as_i64().ok_or("revocation ID")?);}}f.revocations.sort();f.revocations.dedup();
  if action=="approval"{before.insert("approval_requests".into(),prior_approval);after.insert("approval_requests".into(),owner.query("SELECT to_jsonb(t)::text FROM approval_requests t WHERE id=$1",&[&approval]).await?.iter().map(|r|serde_json::from_str::<Value>(&r.get::<_,String>(0))).collect::<Result<Vec<_>,_>>()?);}
  let delivery=if invitation{let (delivery,hash)=super::mail::observe(&owner,&email,guest,&captures,&f.domain_names[0],kind=="wire-mime").await?;for hash in hash{for rows in before.values_mut().chain(after.values_mut()){for row in rows{if row["token_hash"]==hash{row["token_hash"]=json!("<token-sha256>");}}}}Some(delivery)}else{None};
  let mut effects=vec![];for table in TABLES.iter().map(|(name,_)|name.to_string()).chain(if action=="approval"{vec!["approval_requests".to_string()]}else{vec![]}){let mut old=json!(before.remove(&table).ok_or("before")?);let mut new=json!(after.remove(&table).ok_or("after")?);normalize(&mut old,&table,&f)?;normalize(&mut new,&table,&f)?;effects.push(json!({"table":table,"before":old,"after":new}));}
  let mut old=json!(states_before);let mut new=json!(states(&owner,&[a.mailbox,b.mailbox]).await?);normalize(&mut old,"mailbox_state",&f)?;normalize(&mut new,"mailbox_state",&f)?;effects.push(json!({"table":"mailbox_state","before":old,"after":new}));
  for payload in decided.drain(&owner).await?{notify.push(json!({"channel":"approval_decided","payload":serde_json::from_str::<Value>(&payload)?}));}
  for row in &mut audit{normalize(row,"audit",&f)?;}for event in &mut notify{normalize(event,"notify",&f)?;}
  if kind.starts_with("encoded"){if let Ok(v)=serde_json::from_str::<Value>(&raw){if let Some(instance)=v["instance"].as_str(){let decoded=decoded_path(&path);if instance!=decoded.strip_prefix("/api").unwrap_or(&decoded){return Err(format!("wrong decoded Go instance: {instance}").into())}}}}
  let normalized=raw.replace(&decoded_path(&path),&pattern).replace(&email,"guest@outside.test").replace(&path,&pattern).replace(&format!("\"guestUserId\":{guest}"),"\"guestUserId\":\"<guest>\"").replace(&format!("\"sponsorUserId\":{}",b.user),"\"sponsorUserId\":\"<other>\"");if let Some(date)=headers.get_mut("date"){chrono::DateTime::parse_from_rfc2822(date[0].as_str().ok_or("HTTP date")?)?;*date=json!(["<timestamp>"]);}if let Some(length)=headers.get_mut("content-length"){if length[0]!=raw.len().to_string(){return Err("bad wire length".into())}*length=json!([normalized.len().to_string()]);}
  let mut observation=json!({"request":{"method":method,"path":pattern,"external_path":format!("/api{pattern}"),"body":body.replace(&format!("\"expectedInviteId\":\"{}\"",if kind=="stale"{invite+1}else{invite}),"\"expectedInviteId\":\"<invite>\"").replace(&format!("\"profileId\":{profile}"),"\"profileId\":\"<profile>\"").replace(&format!("\"sponsorUserId\":{}",b.user),"\"sponsorUserId\":\"<other>\"")},"response":{"status":status,"headers":headers,"body":normalized},"effects":effects,"audit":audit,"notify":notify});
  if invitation{let response:&mut Value=&mut observation["response"];let body=response["body"].as_str().ok_or("response body")?.to_owned();let mut canonical=body.replace(&format!("\"inviteId\":\"{invite}\""),"\"inviteId\":\"<invite>\"");if let Ok(parsed)=serde_json::from_str::<Value>(&body){if let Some(time)=parsed["expiresAt"].as_str(){chrono::DateTime::parse_from_rfc3339(time)?;let stored=owner.query_one("SELECT to_jsonb(expires_at)#>>'{}' FROM guest_invites WHERE id=$1",&[&invite]).await?.get::<_,String>(0);if chrono::DateTime::parse_from_rfc3339(time)?!=chrono::DateTime::parse_from_rfc3339(&stored.replace(' ',"T"))?{return Err("wire/database expiry mismatch".into())}canonical=canonical.replace(time,"<timestamp>");}}response["body"]=json!(canonical);if response["headers"].get("content-length").is_some(){response["headers"]["content-length"]=json!([canonical.len().to_string()]);}observation["delivery"]=delivery.unwrap();super::mail::replace(&mut observation,&email,"guest@outside.test");super::mail::replace(&mut observation,&foreign_email,"other@host.test");}
  if !recording{super::probe::no_go(address).await?;}server.abort();
  let route=format!("{method} {pattern}");let dir=std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/conformance/guests/goldens");let file=dir.join(format!("guest-{action}-{label}.json"));let row_file=dir.join(format!("guest-{action}-{label}-row-effects.json"));
  if recording{let source=std::env::var("GOFREE_GO_SOURCE")?;super::record(&file,&json!({"format":1,"route":route,"case":label,"go_source":source,"observation":observation}))?;super::record(&row_file,&json!({"format":1,"route":route,"case":format!("{label}-row-effects"),"go_source":source,"effects":observation["effects"]}))?;}
  else{let expected:Value=serde_json::from_slice(&std::fs::read(file)?)?;if mutant{super::probe::rejected(golden::compare(&expected["observation"],&observation).map_err(Into::into),&route)?;}else{golden::compare(&expected["observation"],&observation)?;}let rows:Value=serde_json::from_slice(&std::fs::read(row_file)?)?;golden::compare(&rows["effects"],&observation["effects"])?;eprintln!("GOLDEN-REPLAY: {route} :: {label}");}
  Ok::<_,BoxError>(())
 }.await;
    if fault == Some("no-notify") {
        owner
            .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
            .await?;
    }
    owner
        .batch_execute("BEGIN; SET LOCAL session_replication_role=replica")
        .await?;
    owner
        .execute(
            "DELETE FROM admin_audit_log WHERE id>$1 AND user_id=$2",
            &[&audit_start, &a.user],
        )
        .await?;
    owner.batch_execute("COMMIT").await?;
    owner.execute("DELETE FROM rust_operation_receipts WHERE family IN('F10','F11') AND operation_id::text<>ALL($1)",&[&receipts]).await?;
    if kind == "allowlist" {
        owner
            .execute(
                "DELETE FROM guest_invite_domains WHERE domain=$1",
                &[&format!("guests1-policy-{}.test", a.user)],
            )
            .await?;
    }
    if action == "approval" {
        owner
            .execute("DELETE FROM approval_requests WHERE id=$1", &[&approval])
            .await?;
    }
    owner
        .execute(
            "DELETE FROM outbound_queue WHERE $1=ANY(rcpt_addrs)",
            &[&email],
        )
        .await?;
    owner
        .execute(
            "DELETE FROM users WHERE id=$1 OR email=$2",
            &[&guest, &email],
        )
        .await?;
    owner
        .execute("DELETE FROM guest_profiles WHERE id=$1", &[&profile])
        .await?;
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
    owner
        .execute(
            "UPDATE feature_toggles SET enabled=$1 WHERE key='feature.guest_accounts'",
            &[&enabled],
        )
        .await?;
    if invitation {
        owner
            .execute(
                "DELETE FROM system_config WHERE key=ANY($1)",
                &[&vec![
                    "authserver.public_url",
                    "mail.default_sender",
                    "guest.invite_ttl_days",
                ]],
            )
            .await?;
        for row in prior_config {
            owner
                .execute(
                    "INSERT INTO system_config(key,value) VALUES($1,$2::text::jsonb)",
                    &[&row.get::<_, String>(0), &row.get::<_, String>(1)],
                )
                .await?;
        }
    }
    common::remove_blob_account(&owner, &b).await?;
    common::remove_blob_account(&owner, &a).await?;
    result
}
pub(super) async fn snapshot(
    c: &tokio_postgres::Client,
    guest: i64,
) -> Result<BTreeMap<String, Vec<Value>>, BoxError> {
    let mut result = BTreeMap::new();
    for (table, column) in TABLES {
        let rows=c.query(&format!("SELECT to_jsonb(t)::text FROM {table} t WHERE {column}=$1 ORDER BY to_jsonb(t)::text"),&[&guest]).await?.iter().map(|r|serde_json::from_str(&r.get::<_,String>(0))).collect::<Result<Vec<Value>,_>>()?;
        result.insert((*table).into(), rows);
    }
    Ok(result)
}
async fn states(c: &tokio_postgres::Client, ids: &[i64]) -> Result<Vec<Value>, BoxError> {
    c.query("SELECT jsonb_build_object('mailbox',id,'email',jmap_email_state,'tags',jmap_mailbox_state)::text FROM mailboxes WHERE id=ANY($1) ORDER BY id",&[&ids]).await?.iter().map(|r|serde_json::from_str(&r.get::<_,String>(0)).map_err(Into::into)).collect()
}
async fn request(
    address: std::net::SocketAddr,
    method: &str,
    path: &str,
    body: &str,
    user: i64,
) -> Result<Response<hyper::body::Incoming>, BoxError> {
    Ok(common::send(
        address,
        Request::builder()
            .method(method)
            .uri(if path.starts_with("/%61pi") {
                path.to_owned()
            } else {
                format!("/api{path}")
            })
            .header("host", "mail.test")
            .header("origin", "http://mail.test")
            .header("content-type", "application/json")
            .header("x-request-id", "gofree-guests1-oracle")
            .header(
                "authorization",
                format!("Bearer {}", super::admin_token(user)),
            )
            .body(common::full(body.to_owned()))?,
    )
    .await)
}
pub(super) fn normalize(v: &mut Value, key: &str, f: &Fixture<'_>) -> Result<(), BoxError> {
    match v {
        Value::Object(map) => {
            let audit = map.contains_key("checksum");
            let audit_target = map
                .get("target_type")
                .and_then(Value::as_str)
                .map(str::to_owned);
            let user = map.contains_key("username");
            let approval = map.contains_key("consumer_type") && map.contains_key("approver_ref");
            let invite = map.contains_key("token_hash");
            let revocation = map.contains_key("not_before") && map.contains_key("scope");
            for (k, x) in map {
                if k == "id" && audit {
                    if x.as_i64().is_none_or(|n| n <= 0) {
                        return Err("bad audit ID".into());
                    }
                    *x = json!("<audit>");
                } else if k == "target_id"
                    && audit
                    && audit_target.as_deref() == Some("approval_request")
                {
                    if f.approval <= 0 || *x != f.approval {
                        return Err("unknown audit approval".into());
                    }
                    *x = json!("<approval>");
                } else if k == "target_id"
                    && audit
                    && audit_target.as_deref() == Some("guest_invite")
                {
                    let id = x.as_i64().ok_or("audit invite ID")?;
                    if !f.invites.contains(&id) {
                        return Err("unknown audit invite".into());
                    }
                    *x = json!(if id == f.invite {
                        "<invite>"
                    } else {
                        "<previous-invite>"
                    });
                } else if k == "id" && approval {
                    if *x != f.approval {
                        return Err("unknown approval".into());
                    }
                    *x = json!("<approval>");
                } else if k == "id" && invite {
                    if *x == f.invite {
                        *x = json!("<invite>")
                    } else if f.invites.contains(&x.as_i64().ok_or("invite ID")?) {
                        *x = json!("<previous-invite>")
                    } else {
                        return Err("unknown invite".into());
                    }
                } else if k == "id" && user {
                    if *x != f.guest {
                        return Err("foreign user row".into());
                    }
                    *x = json!("<guest>");
                } else if k == "id" && revocation {
                    revocation_id(x, f)?;
                } else {
                    normalize(x, k, f)?;
                }
            }
        }
        Value::Array(xs) => {
            for x in xs {
                normalize(x, key, f)?;
            }
        }
        Value::Number(_) => {
            if matches!(
                key,
                "user_id"
                    | "requester_user_id"
                    | "decided_by_user_id"
                    | "requester"
                    | "approver_ref"
                    | "guest_user_id"
                    | "guestUserId"
                    | "sponsorUserId"
                    | "target_id"
                    | "request_id"
                    | "created_by"
                    | "updated_by"
                    | "invited_by"
                    | "sponsor_user_id"
            ) {
                *v = if key == "request_id" && *v == f.approval {
                    json!("<approval>")
                } else if *v == f.guest {
                    json!("<guest>")
                } else if *v == f.a.user {
                    json!("<admin>")
                } else if *v == f.b.user {
                    json!("<other>")
                } else {
                    return Err(format!("unexpected {key}: {v}").into());
                };
            } else if matches!(key, "host_domain_id" | "domain_id") {
                *v = if *v == f.a.domain {
                    json!("<domain>")
                } else if *v == f.domain {
                    json!("<guest-domain>")
                } else {
                    return Err("unexpected ownership domain".into());
                };
            } else if key == "mailbox" {
                *v = if *v == f.a.mailbox {
                    json!("<admin-mailbox>")
                } else if *v == f.b.mailbox {
                    json!("<other-mailbox>")
                } else {
                    return Err("unexpected state owner".into());
                };
            } else if matches!(key, "profile_id" | "profileId") {
                if *v != f.profile {
                    return Err("foreign profile assignment".into());
                }
                *v = json!("<profile>");
            } else if key == "sessionRevocationId" {
                revocation_id(v, f)?;
            }
        }
        Value::String(s) => {
            if matches!(
                key,
                "created_at"
                    | "updated_at"
                    | "occurred_at"
                    | "not_before"
                    | "expires_at"
                    | "expiresAt"
                    | "revoked_at"
                    | "used_at"
                    | "decided_at"
                    | "last_attempt_at"
                    | "next_attempt_at"
                    | "transition_at"
                    | "retry_until"
            ) {
                if s != "infinity" {
                    chrono::DateTime::parse_from_rfc3339(s)?;
                }
                if !(f.fixed_expiry && s.starts_with("2100-"))
                    && s != "infinity"
                    && !s.starts_with("2026-10-01T12:00:00")
                    && !s.starts_with("2099-11-01T12:00:00")
                    && !s.starts_with("2100-11-01T12:00:00")
                {
                    *s = "<timestamp>".into();
                }
            } else if key == "checksum" {
                if s.is_empty() {
                    return Err("empty core checksum".into());
                }
                *s = "<checksum>".into();
            } else if key == "replacementInviteId" {
                if s != &f.invite.to_string() {
                    return Err("unbound replacement".into());
                }
                *s = "<invite>".into();
            } else if key == "guestUserId" {
                if s != &f.guest.to_string() {
                    return Err("unknown guest audit".into());
                }
                *s = "<guest>".into();
            } else {
                *s = s
                    .replace(f.email, "guest@outside.test")
                    .replace(&f.domain_names[0], "host.test")
                    .replace(&f.domain_names[1], "other.test");
            }
        }
        _ => {}
    }
    Ok(())
}
fn revocation_id(v: &mut Value, f: &Fixture<'_>) -> Result<(), BoxError> {
    let id = v.as_i64().ok_or("bad revocation ID")?;
    let i = f
        .revocations
        .iter()
        .position(|n| *n == id)
        .ok_or("unobserved revocation ID")?;
    *v = json!(format!("<revocation-{}>", i + 1));
    Ok(())
}

fn decoded_path(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = vec![];
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(byte) = u8::from_str_radix(&value[i + 1..i + 3], 16) {
                out.push(byte);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}
