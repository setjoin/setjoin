use crate::common::{self, BoxError};
use hyper::{Request, Response};
use serde_json::{json, Value};
use setjoin_conformance::{fixture, golden, harness::Db};
use setjoin_gateway::{Config, Gateway, RouteTable, TrustedProxies};
pub mod accounting;
mod faults;
mod session;
mod spec;
mod wire;
struct Probe {
    inner: setjoin_gateway::carddav::CardDavRoute<setjoin_gateway::jmap::jwks::Jwks>,
    mutant: Option<&'static str>,
}
impl setjoin_gateway::Intercept for Probe {
    fn requires_session(&self, r: &Request<setjoin_gateway::Body>) -> bool {
        self.inner.requires_session(r)
    }
    fn matches(&self, r: &Request<setjoin_gateway::Body>) -> bool {
        self.inner.matches(r)
    }
    fn admits_member(
        &self,
        h: hyper::HeaderMap,
        s: &'static str,
    ) -> setjoin_gateway::BoxFuture<bool> {
        self.inner.admits_member(h, s)
    }
    fn handle(
        &self,
        r: Request<setjoin_gateway::Body>,
        c: setjoin_gateway::RequestContext,
    ) -> setjoin_gateway::BoxFuture<Response<setjoin_gateway::Body>> {
        let reply = self.inner.handle(r, c);
        let mutant = self.mutant;
        Box::pin(async move {
            let mut reply = reply.await;
            if mutant == Some("status") {
                *reply.status_mut() = hyper::StatusCode::IM_A_TEAPOT;
            }
            reply
        })
    }
}
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
const BOOK: i64 = 994271;
const OTHER: i64 = 994272;

async fn rows(c: &tokio_postgres::Client, sql: &str) -> Result<Vec<Value>, BoxError> {
    c.query(sql, &[])
        .await?
        .iter()
        .map(|r| serde_json::from_str(&r.get::<_, String>(0)).map_err(Into::into))
        .collect()
}
async fn snapshot(c: &tokio_postgres::Client, a: i64, b: i64) -> Result<Value, BoxError> {
    Ok(json!({
        "books":rows(c,&format!("SELECT (to_jsonb(ab)-'created_at'-'updated_at')::text FROM addressbooks ab WHERE mailbox_id IN ({a},{b}) ORDER BY id")).await?,
        "contacts":rows(c,&format!("SELECT (to_jsonb(c)-'created_at'-'updated_at'-'etag')::text FROM contacts c WHERE addressbook_id IN ({BOOK},{OTHER}) ORDER BY id")).await?,
        "state":rows(c,&format!("SELECT to_jsonb(s)::text FROM jmap_entity_state s WHERE mailbox_id IN ({a},{b}) ORDER BY mailbox_id,datatype")).await?,
        "journal":rows(c,&format!("SELECT (to_jsonb(j)-'id'-'created_at')::text FROM jmap_changes_journal j WHERE mailbox_id IN ({a},{b}) ORDER BY mailbox_id,state_seq,resource_uid")).await?,
        "visibility":rows(c,&format!("SELECT (to_jsonb(j)-'first_seen_at')::text FROM gal_visibility_journal j WHERE mailbox_id IN ({a},{b}) ORDER BY mailbox_id,user_id")).await?
    }))
}
fn normalize(v: &mut Value, ids: &[(i64, String)], domains: &[(String, &str)]) {
    match v {
        Value::Number(n) => {
            if let Some((_, s)) = n.as_i64().and_then(|n| ids.iter().find(|(i, _)| *i == n)) {
                *v = json!(s)
            }
        }
        Value::String(s) => {
            for (domain, label) in domains {
                // Keep Go's physical 75-byte folds visible; only same-length
                // fixture domains may be substituted across a folded line.
                if domain.len() == label.len() && domain.is_ascii() && label.is_ascii() {
                    for at in 1..domain.len() {
                        for newline in ["\r\n ", "&#xD;&#xA; "] {
                            *s = s.replace(
                                &format!("{}{newline}{}", &domain[..at], &domain[at..]),
                                &format!("{}{newline}{}", &label[..at], &label[at..]),
                            );
                        }
                    }
                }
                *s = s.replace(domain, label);
            }
            let mut out = String::new();
            let mut chars = s.chars().peekable();
            while let Some(c) = chars.next() {
                if c.is_ascii_digit() {
                    let mut digits = String::from(c);
                    while chars.peek().is_some_and(char::is_ascii_digit) {
                        digits.push(chars.next().unwrap());
                    }
                    out.push_str(
                        ids.iter()
                            .find(|(n, _)| n.to_string() == digits)
                            .map(|(_, s)| s.as_str())
                            .unwrap_or(&digits),
                    );
                } else {
                    out.push(c)
                }
            }
            *s = out;
        }
        Value::Array(xs) => xs.iter_mut().for_each(|x| normalize(x, ids, domains)),
        Value::Object(m) => m.values_mut().for_each(|x| normalize(x, ids, domains)),
        _ => {}
    }
}
pub async fn run(route: &str, label: &str, mutant: Option<&'static str>) -> Result<(), BoxError> {
    let _lock = SERIAL.lock().await;
    let Some(db) = Db::for_case("cal5-http") else {
        return Ok(());
    };
    let owner = std::sync::Arc::new(db.connect().await?);
    for (table, floor) in [("users", 2_000_000), ("mailboxes", 3_000_000)] {
        owner.batch_execute(&format!("SELECT setval(pg_get_serial_sequence('{table}','id'),greatest({floor},(SELECT last_value FROM {table}_id_seq)))")).await?;
    }
    let a = fixture::account(&owner, "cal5-owner").await?;
    let b = fixture::account(&owner, "cal5-other").await?;
    let audit_level: String = owner
        .query_one("SELECT level FROM audit_policy WHERE id=1", &[])
        .await?
        .get(0);
    let saved=owner.query("SELECT key,enabled FROM feature_toggles WHERE key IN ('feature.carddav','feature.gal_carddav')",&[]).await?;
    let mut blob_owned = false;
    let mut department = None;
    let mut guest_user = None;
    let mut restore = vec![];
    let result=async {
        owner.batch_execute(&format!("UPDATE feature_toggles SET enabled=true WHERE key IN ('feature.carddav','feature.gal_carddav'); DELETE FROM addressbooks WHERE mailbox_id IN ({},{}); INSERT INTO addressbooks(id,mailbox_id,name,description) VALUES({BOOK},{},'CAL5 Owner','Personal & shared'),({OTHER},{},'CAL5 Other','Foreign'); SELECT setval(pg_get_serial_sequence('addressbooks','id'),greatest(995000,(SELECT last_value FROM addressbooks_id_seq)))",a.mailbox,b.mailbox,a.mailbox,b.mailbox)).await?;
        if matches!(route,"get"|"query"|"multiget"|"sync"|"put-update"|"delete") || (route=="propfind" && !matches!(label,"success"|"cross-tenant"|"invalid-input"|"gal-off")) || (route=="put" && matches!(label,"if-none"|"if-match-good")) {
            let uid=if matches!(route,"put"|"put-update"|"delete") {"cal5-write"}else{"cal5-contact"};
            let foreign_uid=if route=="multiget" && label=="cross-tenant" {"cal5-foreign"}else{uid};
            owner.batch_execute(&format!("INSERT INTO contacts(id,addressbook_id,vcard_uid,display_name,first_name,last_name,company,job_title,department,notes,emails,phones,addresses,urls,categories,birthday,anniversary,etag,updated_at) VALUES(2,{BOOK},'{uid}','CAL5 café, planning','Alice','Owner','Setjoin','Engineer','Platform','first\nsecond','[{{\"Type\":\"WORK\",\"Value\":\"alice@example.test\"}}]','[{{\"Type\":\"WORK\",\"Value\":\"+15550100\"}}]','[{{\"Type\":\"HOME\",\"Street\":\"One; Street\",\"City\":\"Paris\",\"Code\":\"75001\"}}]','[{{\"Type\":\"WORK\",\"Value\":\"https://example.test\"}}]',ARRAY['Friends','Work'],'2000-02-29','2020-03-04','cal5-etag','2031-01-02T03:04:05Z'),(3,{OTHER},'{foreign_uid}','Foreign private contact','','','','','','','[]','[]','[]','[]','{{}}',NULL,NULL,'other-etag','2031-01-02T03:04:05Z')")).await?;
        }
        if label=="bad-json" {owner.batch_execute("UPDATE contacts SET emails='[1]'::jsonb WHERE id=2").await?;}
        if label=="photo" || label=="full-profile" {
            owner.execute("INSERT INTO blobs(sha256,minio_ref,size_bytes,content_type) VALUES($1,'gofree-cal5-photo',4,'image/png')",&[&"c5".repeat(32)]).await?;blob_owned=true;
        }
        if route=="get" && label=="fold" {owner.execute("UPDATE contacts SET display_name=$1 WHERE id=2",&[&"漢字é,;".repeat(30)]).await?;}
        if route=="sync" {match label {
            "removed"=>{owner.batch_execute("DELETE FROM contacts WHERE id=2").await?;},
            "updated"=>{owner.batch_execute("UPDATE contacts SET display_name='Updated contact' WHERE id=2").await?;},
            "pruned"=>{owner.execute("DELETE FROM jmap_changes_journal WHERE mailbox_id=$1 AND datatype='ContactCard'",&[&a.mailbox]).await?;},
            "resync"=>{owner.execute("SELECT append_change($1,'ContactCard',bump_entity_state($1,'ContactCard'),NULL,'resync')",&[&a.mailbox]).await?;},_=>{}
        }}
        if label=="gal-off" {owner.batch_execute("UPDATE feature_toggles SET enabled=false WHERE key='feature.gal_carddav'").await?;}
        if route=="entitlement" {
            owner.execute("INSERT INTO user_app_entitlements(user_id,app,enabled) VALUES($1,'contacts',false) ON CONFLICT(user_id,app) DO UPDATE SET enabled=false",&[&a.user]).await?;
            owner.batch_execute("UPDATE audit_policy SET level='full' WHERE id=1").await?;
        }
        if route.starts_with("gal-") || matches!(route,"client-session"|"client-executable") {
            owner.batch_execute(&format!("BEGIN; SET LOCAL session_replication_role=replica; UPDATE users SET first_name='Alice',last_name='Owner',phone='+15550100',job_title='Engineer',manager_id={},ad_upn='alice@upn.example.test',updated_at='2031-01-02T03:04:05Z' WHERE id={}; UPDATE users SET first_name='Bob',last_name='Other',phone='+15550101',job_title='Manager',updated_at='2031-01-02T03:04:06Z' WHERE id={}; COMMIT",b.user,a.user,b.user)).await?;
            if label=="removed" {owner.execute("SELECT gal_visibility_record($1,ARRAY[$2]::bigint[])",&[&a.mailbox,&b.user]).await?;}
            if matches!(label,"cross-tenant"|"hidden"|"hidden-manager"|"removed"|"never-visible") {owner.execute("UPDATE mailboxes SET hidden_from_gal=true WHERE id=$1",&[&b.mailbox]).await?;}
            if label=="disabled" {owner.execute("UPDATE users SET enabled=false WHERE id=$1",&[&b.user]).await?;}
            if matches!(label,"removed"|"never-visible") {owner.batch_execute(&format!("BEGIN; SET LOCAL session_replication_role=replica; UPDATE users SET updated_at='2031-01-02T03:04:06Z' WHERE id={}; COMMIT",b.user)).await?;}
            if label=="guest" {
                let email:String=owner.query_one("SELECT 'cal5-guest-'||gen_random_uuid()::text||'@outside.test'",&[]).await?.get(0);
                let user:i64=owner.query_one("INSERT INTO users(username,email,display_name,domain_id,password_hash) VALUES($1,$1,'CAL5 hidden guest',(SELECT id FROM domains WHERE name='guest.invalid'),'x') RETURNING id",&[&email]).await?.get(0);guest_user=Some(user);
                owner.execute("INSERT INTO guest_accounts(user_id,invited_email,invited_by_email,host_domain_id,status) VALUES($1,$2,'inviter@example.test',$3,'active')",&[&user,&email,&a.domain]).await?;
            }
            if label=="full-profile" {
                let id:i64=owner.query_one("INSERT INTO departments(name,path,ldap_ou) VALUES('CAL5 Platform','gofree_cal5_platform','OU=CAL5 Platform') RETURNING id",&[]).await?.get(0);department=Some(id);
                owner.execute("UPDATE users SET department_id=$2,avatar_sha256=$3 WHERE id=$1",&[&b.user,&id,&"c5".repeat(32)]).await?;
                owner.batch_execute(&format!("BEGIN; SET LOCAL session_replication_role=replica; UPDATE users SET updated_at='2031-01-02T03:04:06Z' WHERE id={}; COMMIT",b.user)).await?;
            }
            owner.execute("INSERT INTO aliases(mailbox_id,domain_id,email) SELECT $1,$2,'alias@'||name FROM domains WHERE id=$2",&[&b.mailbox,&b.domain]).await?;
        }
        if label=="bridge-disabled" {owner.batch_execute("UPDATE feature_toggles SET enabled=false WHERE key='feature.carddav'").await?;}
        restore.extend(faults::install(&owner,route,label).await?);
        let peer=common::fake_upstream(|_|async {Response::new(common::full(""))}).await;
        let go=common::go_oracle::start_named_with_env(&db,peer,"gofree-cal5-http",&[]).await?;
        let recording=go.is_some();
        if recording && mutant.is_some(){return Err("mutants are replay-only".into());}
        restore.extend(install_mutant(&owner,mutant).await?);
        let app=db.app.as_deref().unwrap_or(&db.dsn);
        let cut=match mutant{Some("commit-before")=>Some(common::commit::CommitCut::BeforeCommit),Some("commit-after")=>Some(common::commit::CommitCut::AfterCommit),_=>None};
        let mut commit_wire=if let Some(cut)=cut{Some(common::commit::commit_cut_proxy(app,cut).await)}else{None};
        let wire=if mutant==Some("no-tenant-filter"){Some(wire::no_tenant_filter(app).await?)}else{None};
        let target=wire.as_ref().map(|w|w.dsn.as_str()).or_else(||commit_wire.as_ref().map(|(dsn,_)|dsn.as_str())).unwrap_or(app);
        let table=RouteTable::proxy_all().with(Probe{inner:setjoin_gateway::carddav::CardDavRoute {exec:common::patient_exec(target,if cut.is_some(){1}else{4})?,keys:std::sync::Arc::new(common::recovery_keys()),issuer:"mailserver".into()},mutant}).with_catchall(setjoin_gateway::catchall::CatchallRoute::new());
        let table=if recording {RouteTable::proxy_all()}else{table};
        let mut inventory:Value=serde_json::from_str(include_str!("../../route-inventory.json"))?;
        for row in inventory["routes"].as_array_mut().ok_or("routes")? {if row["path"]=="/carddav/" {row["state"]=json!(if recording {"OFF"}else{"ON"});row["upstream"]=json!(if recording {"go-mail"}else{"local-rust"});}}
        let gateway=Gateway::new(Config{upstream:go.as_ref().map(|g|format!("http://{}",g.address).parse()).transpose()?,trusted_proxies:TrustedProxies::parse("")?,upstream_header_timeout:setjoin_gateway::proxy::DEFAULT_HEADER_TIMEOUT,edge_limit:None},table)?.with_inventory(&inventory.to_string())?;
        let listener = setjoin_conformance::ports::listener().await;let address=listener.local_addr()?;
        drop(listener);
        let executable=if !recording && (route=="client-executable" || label=="bridge-disabled") {Some(session::executable(address,app).await?)}else{None};
        let server=if executable.is_none(){Some(tokio::spawn(gateway.serve(tokio::net::TcpListener::bind(address).await?)))}else{None};
        if matches!(route,"put"|"put-update"|"delete") {owner.batch_execute("SELECT setval(pg_get_serial_sequence('contacts','id'),greatest(9942780,(SELECT last_value FROM contacts_id_seq)))").await?;}

        if matches!(route,"client-session"|"client-executable") {
            let result=session::drive(&db,owner.clone(),&a,&b,address,&common::recovery_token(a.user),recording).await;
            if let Some(server)=server {server.abort();let _=server.await;}drop(executable);return result;
        }
        let spec=spec::spec(route,label,a.user,if label=="guest" && route=="gal-get" {guest_user.unwrap_or(b.user)}else{b.user});
        let send=||{
            let mut request=Request::builder().method(spec.method).uri(&spec.path).header("host","mail.test").header("origin","http://mail.test").header("x-request-id","gofree-cal5-oracle").header("authorization",format!("Bearer {}",common::recovery_token(a.user)));
            for (key,value) in &spec.headers {request=request.header(*key,value);}
            let body=spec.body.clone();
            async move {Ok::<_,BoxError>(common::send(address,request.body(common::full(body))?).await)}
        };
        if spec.repeat {common::body_bytes(send().await?).await;}
        let mut before=snapshot(&owner,a.mailbox,b.mailbox).await?;
        if blob_owned {before["avatar_blob"]=json!(rows(&owner,"SELECT (to_jsonb(b)-'created_at')::text FROM blobs b WHERE minio_ref='gofree-cal5-photo'").await?);}
        let mut notices_a=db.listen(&format!("contact:{}",a.mailbox)).await?;
        let mut notices_b=db.listen(&format!("contact:{}",b.mailbox)).await?;
        let audit_start:i64=owner.query_one("SELECT coalesce(max(id),0) FROM admin_audit_log",&[]).await?.get(0);
        let response=send().await?;
        let status=response.status().as_u16();
        let mut headers=serde_json::Map::new();for k in response.headers().keys() {headers.insert(k.to_string(),json!(response.headers().get_all(k).iter().map(|v|v.to_str().unwrap().to_owned()).collect::<Vec<_>>()));}
        let body=String::from_utf8(common::body_bytes(response).await.to_vec())?;
        let mut after=snapshot(&owner,a.mailbox,b.mailbox).await?;
        if blob_owned {after["avatar_blob"]=json!(rows(&owner,"SELECT (to_jsonb(b)-'created_at')::text FROM blobs b WHERE minio_ref='gofree-cal5-photo'").await?);}
        if let Some(cut)=cut {
            if status!=503 || !body.contains("operation outcome unknown"){return Err("COMMIT loss reported a false success".into());}
            let text=headers.get("x-operation-id").and_then(|v|v[0].as_str()).ok_or("missing operation ID")?;
            if text.len()!=32{return Err("invalid operation ID".into());}let mut raw=[0;16];for (i,b) in raw.iter_mut().enumerate(){*b=u8::from_str_radix(&text[i*2..i*2+2],16)?;}
            let operation=setjoin_contracts::ids::OperationId(raw);
            let (_,task)=commit_wire.take().ok_or("cut proxy missing")?;
            if tokio::time::timeout(std::time::Duration::from_secs(30),task).await???!=cut{return Err("wrong COMMIT barrier".into());}
            let fresh=common::patient_exec(app,1)?;let keys=std::sync::Arc::new(common::recovery_keys());
            use setjoin_calendar::carddav::OutcomeKind;
            let kind=match route{"put"=>OutcomeKind::Create,"put-update"=>OutcomeKind::Update,"delete"=>OutcomeKind::Delete,_=>OutcomeKind::GalSync};
            for (user,expected) in [(a.user,cut==common::commit::CommitCut::AfterCommit),(b.user,false)]{
                let mut h=hyper::HeaderMap::new();h.insert("authorization",format!("Bearer {}",common::recovery_token(user)).parse()?);
                let proof=setjoin_authz::authorize_user_request(&fresh,&keys,"mailserver",&h,"http").await.ok_or("fresh recovery authority unavailable")?;
                let found=setjoin_calendar::carddav::lookup_operation(&fresh,proof.context(),operation,kind).await.map_err(|_|"recovery lookup unavailable")?;
                if found!=expected{return Err("actor-bound outcome mismatch".into());}
                let wrong=if route=="put"{OutcomeKind::Delete}else{OutcomeKind::Create};
                if setjoin_calendar::carddav::lookup_operation(&fresh,proof.context(),operation,wrong).await.map_err(|_|"wrong-kind lookup unavailable")?{return Err("receipt command boundary bypassed".into());}
            }
        }
        if mutant==Some("no-tenant-filter") && (status!=200 || !body.contains("Foreign private contact") || wire.as_ref().is_none_or(|w|w.hits.load(std::sync::atomic::Ordering::SeqCst)==0)){return Err("tenant mutant never reached foreign row".into());}
        if matches!(mutant,Some("no-notify"|"double-bump")) && (status!=201 || after["contacts"].as_array().is_none_or(|r|r.len()!=1)){return Err("effect mutant never published a contact".into());}
        if !recording {
            let metrics=common::send(address,Request::get("/_gateway/metrics").body(common::full(""))?).await;let metrics=String::from_utf8(common::body_bytes(metrics).await.to_vec())?;
            if !metrics.lines().any(|l|l=="setjoin_gateway_proxied_to_go_total 0"){return Err(format!("unexpected Go proxy: {metrics}").into());}
        }
        if let Some(server)=server {server.abort();let _=server.await;}
        let da:String=owner.query_one("SELECT name FROM domains WHERE id=$1",&[&a.domain]).await?.get(0);
        let dbn:String=owner.query_one("SELECT name FROM domains WHERE id=$1",&[&b.domain]).await?.get(0);
        let mut ids=vec![(a.user,"<user-a>".into()),(b.user,"<user-b>".into()),(a.mailbox,"<mailbox-a>".into()),(b.mailbox,"<mailbox-b>".into())];
        let mut replacements=vec![(da,format!("oracle-{}.test","a".repeat(32))),(dbn,format!("oracle-{}.test","b".repeat(32)))];
        if matches!(route,"put"|"put-update"|"delete") {
            for row in owner.query("SELECT id,vcard_uid,etag FROM contacts WHERE addressbook_id IN ($1,$2)",&[&BOOK,&OTHER]).await? {
                let id:i64=row.get(0);let uid:String=row.get(1);let etag:String=row.get(2);
                if id>3 {ids.push((id,format!("<contact:{uid}>")));}
                if (etag.len()==32 || etag.len()==64) && etag.bytes().all(|c|c.is_ascii_hexdigit()) {
                    if matches!(route,"put"|"put-update") && matches!(status,201|204) && uid=="cal5-write" && headers.get("etag").and_then(|v|v[0].as_str())!=Some(format!("\"{etag}\"").as_str()) {return Err("response ETag is not the stored owned contact version".into());}
                    replacements.push((etag,format!("<etag:{uid}>")));
                }
            }
        }
        let mut notify=vec![];
        for (name,listener) in [("a",&mut notices_a),("b",&mut notices_b)] {for payload in listener.drain(&owner).await? {notify.push(json!({"mailbox":name,"payload":serde_json::from_str::<Value>(&payload).unwrap_or(json!(payload))}));}}
        let mut audit=rows(&owner,&format!("SELECT (to_jsonb(l)-'id'-'created_at'-'occurred_at')::text FROM admin_audit_log l WHERE id>{audit_start} ORDER BY id")).await?;
        for row in &mut audit {if let Some(checksum)=row.get_mut("checksum") {
            if !checksum.as_str().is_some_and(|s|s.len()==64 && s.bytes().all(|c|c.is_ascii_hexdigit())){return Err("invalid audit checksum".into());}*checksum=json!("<checksum>");
        }}
        let mut observation=json!({"request":{"method":"*","concrete_method":spec.method,"path":"/carddav/","body":if spec.body.len()>1<<20 {use sha2::Digest;format!("<generated-body bytes={} sha256={:x}>",spec.body.len(),sha2::Sha256::digest(spec.body.as_bytes()))}else{spec.body.clone()}},"response":{"status":status,"headers":headers,"body":body},"effects":[{"table":"f17-carddav","before":before,"after":after}],"audit":audit,"notify":notify});
        normalize(&mut observation,&ids,&replacements.iter().map(|(raw,label)|(raw.clone(),label.as_str())).collect::<Vec<_>>());
        if observation["response"]["headers"].get("date").is_some(){observation["response"]["headers"]["date"]=json!(["<timestamp>"]);}
        if !recording && mutant.is_none() && status!=spec.wanted {return Err(format!("{} must be native: got {status}, expected {}",spec.method,spec.wanted).into());}
        let normalized_length=observation["response"]["body"].as_str().unwrap().len().to_string();
        if let Some(length)=observation["response"]["headers"].get_mut("content-length") {
            if length[0]!=body.len().to_string(){return Err("wrong wire Content-Length".into());}
            *length=json!([normalized_length]);
        }
        let file=std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!("../../tests/conformance/carddav/goldens/{route}-{label}.json"));
        if let Some(cut)=cut {
            if cut==common::commit::CommitCut::BeforeCommit {
                if observation["effects"][0]["before"]!=observation["effects"][0]["after"] || observation["audit"]!=json!([]) || observation["notify"]!=json!([]){return Err("pre-COMMIT cut published effects".into());}
            }else{
                let expected:Value=serde_json::from_slice(&std::fs::read(&file)?)?;let mut expected=expected["observation"].clone();expected.as_object_mut().unwrap().remove("response");let mut actual=observation.clone();actual.as_object_mut().unwrap().remove("response");golden::compare(&expected,&actual)?;
            }
            eprintln!("COMMIT-CUT: CardDAV {route} :: {cut:?} (fresh actor/command lookup, no write replay)");
        }else if recording {golden::record(&file,&json!({"format":1,"route":format!("* /carddav/ {route}"),"case":label,"go_source":std::env::var("GOFREE_GO_SOURCE")?,"observation":observation}))?;}else{
            let expected:Value=common::golden_doc(&file,"observation",&observation);let comparison=golden::compare(&expected["observation"],&observation);
            if let Some(mutant)=mutant {
                if comparison.is_ok(){return Err(format!("mutant survived: {mutant}").into());}
                if mutant=="no-notify" && (expected["observation"]["notify"].as_array().is_none_or(Vec::is_empty) || observation["notify"]!=json!([])){return Err("notification mutant was not discriminated".into());}
                if mutant=="no-audit" && (status!=403 || expected["observation"]["audit"].as_array().is_none_or(Vec::is_empty) || observation["audit"]!=json!([])){return Err("audit mutant was not discriminated".into());}
                eprintln!("MUTANT-REJECTED: * /carddav/ {route} :: {mutant}");eprintln!("MUTANT-REJECTED: * /carddav/ :: {mutant}");
            }else{
                comparison?;
                let row_file=file.with_file_name(format!("{route}-{label}-row-effects.json"));
                if row_file.exists() {
                    let rows:Value=serde_json::from_slice(&std::fs::read(&row_file)?)?;
                    golden::compare(&expected["observation"]["effects"],&rows["effects"])?;
                    golden::compare(&rows["effects"],&observation["effects"])?;
                }
                eprintln!("GOLDEN-REPLAY: * /carddav/ {route} :: {label}");
            }
        }
        Ok::<_,BoxError>(())
    }.await;
    if let Err(error) = &result {
        eprintln!("CardDAV {route}/{label} failed before cleanup: {error}");
        owner.batch_execute("ROLLBACK").await?;
    }
    for definition in restore.into_iter().rev() {
        owner.batch_execute(&definition).await?;
    }
    owner.batch_execute(&format!("DELETE FROM jmap_changes_journal WHERE mailbox_id IN ({},{}); DELETE FROM addressbooks WHERE mailbox_id IN ({},{})",a.mailbox,b.mailbox,a.mailbox,b.mailbox)).await?;
    owner
        .execute(
            "UPDATE audit_policy SET level=$1 WHERE id=1",
            &[&audit_level],
        )
        .await?;
    owner.batch_execute(&format!("BEGIN; SET LOCAL session_replication_role=replica; DELETE FROM admin_audit_log WHERE user_id IN ({},{}); COMMIT",a.user,b.user)).await?;
    for row in saved {
        let key: String = row.get(0);
        let value: bool = row.get(1);
        owner
            .execute(
                "UPDATE feature_toggles SET enabled=$2 WHERE key=$1",
                &[&key, &value],
            )
            .await?;
    }
    if let Some(user) = guest_user {
        owner
            .execute("DELETE FROM guest_accounts WHERE user_id=$1", &[&user])
            .await?;
        owner
            .execute("DELETE FROM users WHERE id=$1", &[&user])
            .await?;
    }
    for account in [&a, &b] {
        common::remove_blob_account(&owner, account).await?;
    }
    if let Some(id) = department {
        owner
            .execute("DELETE FROM departments WHERE id=$1", &[&id])
            .await?;
    }
    if blob_owned {
        owner
            .execute("DELETE FROM blobs WHERE sha256=$1", &[&"c5".repeat(32)])
            .await?;
    }
    result
}

async fn install_mutant(
    c: &tokio_postgres::Client,
    mutant: Option<&str>,
) -> Result<Vec<String>, BoxError> {
    let replacement=match mutant {
        Some("no-notify")=>Some(("app_notify(text,text)","CREATE OR REPLACE FUNCTION app_notify(p_channel text,p_payload text) RETURNS void LANGUAGE plpgsql AS $f$ BEGIN RETURN; END $f$")),
        Some("no-audit")=>Some(("audit_write(bigint,text,text,bigint,jsonb,jsonb,inet,text,text)","CREATE OR REPLACE FUNCTION audit_write(p_actor bigint,p_action text,p_target_type text,p_target_id bigint,p_before jsonb,p_after jsonb,p_ip inet,p_notes text,p_tier text) RETURNS void LANGUAGE plpgsql AS $f$ BEGIN RETURN; END $f$")),
        _=>None,
    };
    let mut restore = vec![];
    if let Some((signature, sql)) = replacement {
        let definition: String = c
            .query_one(
                "SELECT pg_get_functiondef($1::text::regprocedure)",
                &[&signature],
            )
            .await?
            .get(0);
        c.batch_execute(sql).await?;
        restore.push(definition);
    }
    if mutant == Some("double-bump") {
        c.batch_execute("CREATE FUNCTION gofree_cal5_double_bump() RETURNS trigger LANGUAGE plpgsql AS $f$ BEGIN IF NEW.jmap_state>OLD.jmap_state THEN NEW.jmap_state:=NEW.jmap_state+1; END IF; RETURN NEW; END $f$; CREATE TRIGGER gofree_cal5_double_bump BEFORE UPDATE ON addressbooks FOR EACH ROW EXECUTE FUNCTION gofree_cal5_double_bump()").await?;
        restore.push("DROP TRIGGER gofree_cal5_double_bump ON addressbooks; DROP FUNCTION gofree_cal5_double_bump()".into());
    }
    Ok(restore)
}
