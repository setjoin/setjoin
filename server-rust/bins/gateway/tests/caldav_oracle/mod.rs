use crate::common::{self, BoxError};
use hyper::{Request, Response};
use serde_json::{json, Value};
use setjoin_conformance::{fixture, golden, harness::Db};
use setjoin_gateway::{
    Body, BoxFuture, Config, Gateway, Intercept, RequestContext, RouteTable, TrustedProxies,
};
use std::sync::Arc;

mod session;
mod wire;

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
const CAL: i64 = 994261;
const OTHER: i64 = 994262;

struct Probe {
    inner: setjoin_gateway::caldav::CalDavRoute<setjoin_gateway::jmap::jwks::Jwks>,
    mutant: Option<&'static str>,
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
        let mutant = self.mutant;
        Box::pin(async move {
            let mut response = future.await;
            if mutant == Some("status") {
                *response.status_mut() = hyper::StatusCode::IM_A_TEAPOT;
            }
            response
        })
    }
}

struct Spec {
    method: &'static str,
    path: String,
    body: String,
    headers: Vec<(&'static str, String)>,
    repeat: bool,
    wanted: u16,
}
fn spec(route: &str, label: &str) -> Spec {
    if matches!(route, "session" | "executable") {
        return spec("options", "success");
    }
    if route == "entitlement" {
        return Spec {
            method: "OPTIONS",
            path: if label=="cross-tenant" {format!("/caldav/{OTHER}/")} else {"/caldav/".into()},
            body: if label=="invalid-input" {"<invalid".into()} else {String::new()},
            headers: vec![],
            repeat: false,
            wanted: 403,
        };
    }
    if route.ends_with("-limit") {
        let method = match route {
            "propfind-limit" => "PROPFIND",
            "report-limit" => "REPORT",
            "put-limit" => "PUT",
            _ => "MKCALENDAR",
        };
        let cap = if method == "PUT" { 10 << 20 } else { 1 << 20 };
        return Spec {
            method,
            path: if method == "PUT" {
                format!("/caldav/{CAL}/cal4-write.ics")
            } else {
                format!("/caldav/{CAL}/")
            },
            body: "x".repeat(cap + 1),
            headers: vec![],
            repeat: false,
            wanted: 413,
        };
    }
    if route == "get" && label == "encoded" {
        let mut s = spec("get", "success");
        s.path = s.path.replacen("/caldav/", "/%63aldav/", 1);
        s.wanted = 404;
        return s;
    }
    if matches!(route, "query" | "multiget" | "freebusy" | "sync") {
        let name = match route {
            "query" => "calendar-query",
            "multiget" => "calendar-multiget",
            "freebusy" => "free-busy-query",
            _ => "sync-collection",
        };
        let ns = if route == "sync" {
            "DAV:"
        } else {
            "urn:ietf:params:xml:ns:caldav"
        };
        let mut body=format!("<r:{name} xmlns:r=\"{ns}\" xmlns:d=\"DAV:\" xmlns:c=\"urn:ietf:params:xml:ns:caldav\"><d:prop><d:getetag/><c:calendar-data/></d:prop>");
        if route == "freebusy" {
            body.push_str("<c:time-range start=\"20261201T000000Z\" end=\"20261203T000000Z\"/>");
        }
        if route == "multiget" {
            body.push_str(&format!("<d:href>/{CAL}/cal4-event.ics</d:href>"));
        }
        if route == "sync" {
            body.push_str("<d:sync-token></d:sync-token><d:sync-level>1</d:sync-level>");
        }
        body.push_str(&format!("</r:{name}>"));
        if label == "invalid-input" {
            body = format!("<r:{name}");
        }
        let calendar = if label == "cross-tenant" { OTHER } else { CAL };
        let wanted = if label == "invalid-input" || route == "multiget" {
            400
        } else if label == "cross-tenant" && route != "freebusy" {
            404
        } else {
            207
        };
        return Spec {
            method: "REPORT",
            path: format!("/caldav/{calendar}/"),
            body,
            headers: vec![],
            repeat: false,
            wanted,
        };
    }
    if route == "propfind" && matches!(label, "members" | "event" | "length") {
        let path = if label == "members" {
            format!("/caldav/{CAL}/")
        } else {
            format!("/caldav/{CAL}/cal4-event.ics")
        };
        let body = if label == "length" {
            r#"<d:propfind xmlns:d="DAV:"><d:prop><d:getcontentlength/></d:prop></d:propfind>"#
                .to_owned()
        } else {
            r#"<d:propfind xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav"><d:prop><d:resourcetype/><d:displayname/><d:getetag/><d:getcontenttype/><d:getcontentlength/><c:calendar-data/></d:prop></d:propfind>"#.to_owned()
        };
        return Spec {
            method: "PROPFIND",
            path,
            body,
            headers: vec![],
            repeat: false,
            wanted: 207,
        };
    }
    if matches!(route, "get" | "options" | "propfind")
        && matches!(label, "cross-tenant" | "invalid-input")
    {
        let mut s = spec(route, "success");
        if label == "cross-tenant" {
            s.path = if route == "get" {
                format!("/caldav/{OTHER}/cal4-event.ics")
            } else {
                format!("/caldav/{OTHER}/")
            };
        } else {
            s.body = "<propfind".into();
            if route == "get" {
                s.path = "/caldav/not-a-calendar/cal4-event.ics".into();
            }
        }
        if route == "get" {
            s.wanted = 404;
        }
        return s;
    }
    if route == "put" && label != "success" {
        let mut s = spec("put", "success");
        match label {
            "cross-tenant"=>{s.path=format!("/caldav/{OTHER}/cal4-write.ics");s.wanted=404;},
            "invalid-input"=>{s.body="invalid calendar".into();s.wanted=400;},
            "update"=>s.wanted=204,
            "repeat"=>{s.repeat=true;s.wanted=204;},
            "if-none"=>{s.headers.push(("if-none-match","*".into()));s.wanted=412;},
            "if-match"=>{s.headers.push(("if-match","\"wrong\"".into()));s.wanted=412;},
            "if-match-create"=>{s.headers.push(("if-match","*".into()));s.wanted=412;},
            "uid-mismatch"=>{s.body=s.body.replace("UID:cal4-write","UID:other");s.wanted=403;},
            "bad-path"=>{s.path=format!("/caldav/{CAL}/");s.wanted=409;},
            "todo"=>s.body=s.body.replace("VEVENT","VTODO"),
            "journal"=>s.body=s.body.replace("VEVENT","VJOURNAL"),
            "attendees"=>s.body=s.body.replace("END:VEVENT","ATTENDEE;CN=Guest;ROLE=REQ-PARTICIPANT;PARTSTAT=ACCEPTED;RSVP=TRUE:mailto:guest@example.test\r\nEND:VEVENT"),
            "todo-date"=>s.body=s.body.replace("VEVENT","VTODO").replace("END:VTODO","DUE;VALUE=DATE:20310103\r\nEND:VTODO"),
            "recurrence-invalid"|"recurrence-parameters"=>{
                let rid=if label=="recurrence-invalid" {"RECURRENCE-ID:20310103T100000Z,20310104T100000Z"} else {"RECURRENCE-ID;VALUE=DATE-TIME;VALUE=DATE:20310103T100000Z"};
                s.body=s.body.replace("END:VEVENT",&format!("RRULE:FREQ=DAILY;COUNT=3\r\nEND:VEVENT\r\nBEGIN:VEVENT\r\nUID:cal4-write\r\n{rid}\r\nDTSTART:20310103T120000Z\r\nDTEND:20310103T130000Z\r\nSUMMARY:Changed occurrence\r\nEND:VEVENT"));
            },
            "recurring"=>s.body=s.body.replace("END:VEVENT","RRULE:FREQ=DAILY;COUNT=3\r\nEXDATE:20310104T100000Z\r\nEND:VEVENT\r\nBEGIN:VEVENT\r\nUID:cal4-write\r\nRECURRENCE-ID:20310103T100000Z\r\nDTSTART:20310103T120000Z\r\nDTEND:20310103T130000Z\r\nSUMMARY:Changed occurrence\r\nEND:VEVENT"),
            _=>panic!("unknown PUT label {label}"),
        }
        return s;
    }
    if route == "delete" {
        let target = if label == "cross-tenant" { OTHER } else { CAL };
        let path = if label == "invalid-input" {
            format!("/caldav/{CAL}/")
        } else {
            format!("/caldav/{target}/cal4-delete.ics")
        };
        return Spec {
            method: "DELETE",
            path,
            body: String::new(),
            headers: if label == "if-match" {
                vec![("if-match", "\"wrong\"".into())]
            } else {
                vec![]
            },
            repeat: label == "repeat",
            wanted: match label {
                "cross-tenant" | "invalid-input" | "repeat" => 404,
                "if-match" => 412,
                _ => 204,
            },
        };
    }
    if route == "mkcalendar" {
        return Spec {
            method: "MKCALENDAR",
            path: if label == "cross-tenant" {
                format!("/caldav/{OTHER}/new/")
            } else {
                "/caldav/new/".into()
            },
            body: if label == "invalid-input" {
                "<mkcalendar".into()
            } else {
                r#"<c:mkcalendar xmlns:c="urn:ietf:params:xml:ns:caldav" xmlns:d="DAV:"><d:set><d:prop><d:displayname>New CAL4 calendar</d:displayname></d:prop></d:set></c:mkcalendar>"#.into()
            },
            headers: vec![],
            repeat: false,
            wanted: 403,
        };
    }
    if route == "unsupported" || route == "head" {
        return Spec {
            method: if route == "head" { "HEAD" } else { "POST" },
            path: if label == "cross-tenant" {
                format!("/caldav/{OTHER}/outbox/")
            } else {
                "/caldav/outbox/".into()
            },
            body: if label == "invalid-input" {
                "invalid scheduling input".into()
            } else {
                String::new()
            },
            headers: vec![],
            repeat: false,
            wanted: 405,
        };
    }
    match route {
        "put"=> Spec {method:"PUT",path:format!("/caldav/{CAL}/cal4-write.ics"),body:"BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:cal4-write\r\nSUMMARY:CAL4 write\r\nDTSTART:20310102T100000Z\r\nDTEND:20310102T110000Z\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n".into(),headers:vec![("content-type","text/calendar".into())],repeat:false,wanted:201},
        "get" => Spec { method:"GET",path:format!("/caldav/{CAL}/cal4-event.ics"),body:String::new(),headers:vec![],repeat:false,wanted:200 },
        "options" => Spec {
            method: "OPTIONS",
            path: "/caldav/".into(),
            body: String::new(),
            headers: vec![],
            repeat: false,
            wanted: 200,
        },
        "propfind" if matches!(label,"timezone-owned"|"timezone-foreign"|"timezone-cache") => Spec {method:"PROPFIND",path:format!("/caldav/{CAL}/"),body:r#"<d:propfind xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav"><d:prop><c:calendar-timezone/></d:prop></d:propfind>"#.into(),headers:vec![("depth","0".into())],repeat:false,wanted:207},
        "propfind" if label == "properties" => Spec {
            method:"PROPFIND", path:format!("/caldav/{CAL}/"), headers:vec![("depth","0".into())],repeat:false,wanted:207,
            body:r#"<d:propfind xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav"><d:prop><d:resourcetype/><d:displayname/><d:getetag/><d:getcontenttype/><d:getcontentlength/><c:calendar-data/><c:calendar-home-set/><c:calendar-user-address-set/><d:principal-URL/><d:current-user-principal/><d:supported-report-set/><c:supported-calendar-component-set/><c:calendar-timezone/><c:schedule-inbox-URL/><c:schedule-outbox-URL/></d:prop></d:propfind>"#.into()
        },
        "propfind" => Spec {
            method: "PROPFIND",
            path: "/caldav/".into(),
            body: String::new(),
            headers: vec![],
            repeat: false,
            wanted: 207,
        },
        _ => panic!("unknown route {route}"),
    }
}

fn map_strings(v: &mut Value, mask: &dyn Fn(&str) -> String) {
    match v {
        Value::String(s) => *s = mask(s),
        Value::Array(xs) => xs.iter_mut().for_each(|x| map_strings(x, mask)),
        Value::Object(m) => m.values_mut().for_each(|x| map_strings(x, mask)),
        _ => {}
    }
}
async fn rows(c: &tokio_postgres::Client, sql: &str) -> Result<Vec<Value>, BoxError> {
    c.query(sql, &[])
        .await?
        .iter()
        .map(|r| serde_json::from_str(&r.get::<_, String>(0)).map_err(Into::into))
        .collect()
}
async fn snapshot(
    c: &tokio_postgres::Client,
    a: i64,
    b: i64,
    write: bool,
) -> Result<Value, BoxError> {
    let mut value = json!({
        "calendars":rows(c,&format!("SELECT (to_jsonb(c)-'id'-'created_at'-'updated_at')::text FROM calendars c WHERE mailbox_id IN ({a},{b}) ORDER BY mailbox_id,name")).await?,
        "events":rows(c,&format!("SELECT (to_jsonb(e)-'id'-'created_at'-'updated_at'-'etag')::text FROM calendar_events e JOIN calendars c ON c.id=e.calendar_id WHERE c.mailbox_id IN ({a},{b}) ORDER BY c.mailbox_id,e.uid,e.recurrence_override NULLS FIRST")).await?,
        "state":rows(c,&format!("SELECT jsonb_build_object('mailbox',mailbox_id,'datatype',datatype,'state',seq)::text FROM jmap_entity_state WHERE mailbox_id IN ({a},{b}) ORDER BY mailbox_id,datatype")).await?,
        "journal":rows(c,&format!("SELECT (to_jsonb(j)-'id'-'created_at'-'resource_id'-'etag')::text FROM jmap_changes_journal j WHERE mailbox_id IN ({a},{b}) ORDER BY mailbox_id,state_seq,resource_uid")).await?,
        "queue":rows(c,&format!("SELECT (to_jsonb(q)-'id'-'created_at'-'updated_at'-'next_attempt_at')::text FROM outbound_queue q WHERE mailbox_id IN ({a},{b}) ORDER BY id")).await?
    });
    if write {
        value["attendees"]=json!(rows(c,&format!("SELECT (to_jsonb(a)-'id'-'event_id')::text FROM event_attendees a JOIN calendar_events ce ON ce.id=a.event_id JOIN calendars c ON c.id=ce.calendar_id WHERE c.mailbox_id IN ({a},{b}) ORDER BY ce.uid,a.email")).await?);
    }
    Ok(value)
}

pub async fn run(route: &str, label: &str, mutant: Option<&'static str>) -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("cal4-http") else {
        return Ok(());
    };
    let owner = Arc::new(db.connect().await?);
    for (table, floor) in [("users", 2_000_000i64), ("mailboxes", 3_000_000i64)] {
        owner.batch_execute(&format!("SELECT setval(pg_get_serial_sequence('{table}','id'),greatest({floor},(SELECT last_value FROM {table}_id_seq)))")).await?;
    }
    let a = fixture::account(&owner, "cal4-owner").await?;
    let b = fixture::account(&owner, "cal4-other").await?;
    let saved = owner
        .query(
            "SELECT key,enabled FROM feature_toggles WHERE key='feature.caldav'",
            &[],
        )
        .await?;
    owner.batch_execute(&format!("UPDATE feature_toggles SET enabled=true WHERE key='feature.caldav'; DELETE FROM calendars WHERE mailbox_id IN ({},{}); INSERT INTO calendars(id,mailbox_id,name,timezone) VALUES({CAL},{},'CAL4 Owner','UTC'),({OTHER},{},'CAL4 Other','UTC'); SELECT setval(pg_get_serial_sequence('calendars','id'),greatest(995000,(SELECT last_value FROM calendars_id_seq)))",a.mailbox,b.mailbox,a.mailbox,b.mailbox)).await?;
    if matches!(route, "put" | "delete" | "mkcalendar" | "session" | "executable") {
        owner.batch_execute("SELECT setval(pg_get_serial_sequence('calendar_events','id'),greatest(9942700,(SELECT last_value FROM calendar_events_id_seq)))").await?;
    }
    let audit_level: String = owner
        .query_one("SELECT level FROM audit_policy WHERE id=1", &[])
        .await?
        .get(0);
    let s = spec(route, label);
    let mut restore = Vec::new();
    let result=async {
    if route=="entitlement" {
        owner.execute("INSERT INTO user_app_entitlements(user_id,app,enabled) VALUES($1,'calendar',false) ON CONFLICT(user_id,app) DO UPDATE SET enabled=false",&[&a.user]).await?;
        owner.batch_execute("UPDATE audit_policy SET level='full' WHERE id=1").await?;
    }
    if matches!(label, "timezone-owned" | "timezone-foreign" | "timezone-cache") {
        let target = if label == "timezone-foreign" { OTHER } else { CAL };
        let marker = if label != "timezone-foreign" {
            "owned"
        } else {
            "cal4-foreign-private-definition"
        };
        owner.batch_execute(&format!("UPDATE calendars SET timezone='CAL4/Shared' WHERE id={CAL}; INSERT INTO vt_timezone(calendar_id,tzid,standard) VALUES({target},'CAL4/Shared','{{\"cal4\":\"{marker}\"}}')")).await?;
    }
    if matches!(route,"get"|"query"|"multiget"|"freebusy"|"sync") || (route=="propfind" && matches!(label,"members"|"event"|"length")) {
        owner.batch_execute(&format!("INSERT INTO calendar_events(id,calendar_id,uid,title,description,location,start_at,end_at,status,etag) VALUES(2,{CAL},'cal4-event','CAL4 café, planning','first\nsecond','Room; A','2026-12-01T09:00:00Z','2026-12-01T10:00:00Z','confirmed','cal4-etag')")).await?;
    }
    if route=="delete" {
        let target=if label=="cross-tenant" {OTHER} else {CAL};
        owner.batch_execute(&format!("INSERT INTO calendar_events(id,calendar_id,uid,title,start_at,end_at,etag) VALUES(9942690,{target},'cal4-delete','Delete me','2031-01-02T10:00:00Z','2031-01-02T11:00:00Z','cal4-existing')")).await?;
    }
    if route=="put" && matches!(label,"update"|"if-none"|"if-match") {
        owner.batch_execute(&format!("INSERT INTO calendar_events(id,calendar_id,uid,title,start_at,end_at,etag) VALUES(9942690,{CAL},'cal4-write','Existing event','2031-01-02T10:00:00Z','2031-01-02T11:00:00Z','cal4-existing')")).await?;
    }
    if route=="get" && label=="cross-tenant" {
        owner.batch_execute(&format!("INSERT INTO calendar_events(id,calendar_id,uid,title,start_at,end_at,etag) VALUES(3,{OTHER},'cal4-event','Other owner event','2026-12-01T09:00:00Z','2026-12-01T10:00:00Z','other-etag')")).await?;
    }
    if route == "get" {
        let change = match label {
            "todo" => "UPDATE calendar_events SET component_type='VTODO',status='needs-action',priority=2,percent_complete=30,due_at='2026-12-02T12:00:00Z' WHERE id=2".to_owned(),
            "journal" => "UPDATE calendar_events SET component_type='VJOURNAL' WHERE id=2".to_owned(),
            "all-day" => "UPDATE calendar_events SET all_day=true WHERE id=2".to_owned(),
            "timezone" => "UPDATE calendar_events SET timezone='Asia/Kathmandu' WHERE id=2".to_owned(),
            "recurring" => format!("UPDATE calendar_events SET rrule='FREQ=DAILY;COUNT=3',rdate=ARRAY['2026-12-05T09:00:00Z'::timestamptz],exdate=ARRAY['2026-12-03T09:00:00Z'::timestamptz] WHERE id=2; INSERT INTO calendar_events(id,calendar_id,uid,title,start_at,end_at,recurrence_override,etag) VALUES(3,{CAL},'cal4-event','Moved occurrence','2026-12-02T11:00:00Z','2026-12-02T12:00:00Z','2026-12-02T09:00:00Z','cal4-override-etag')"),
            "fold" => format!("UPDATE calendar_events SET title='{}' WHERE id=2", "漢字é,;".repeat(30)),
            _ => String::new(),
        };
        if !change.is_empty() {
            owner.batch_execute(&change).await?;
        }
    }
        let go_peer=common::fake_upstream(|_|async {Response::new(common::full(""))}).await;
        let go=common::go_oracle::start_named_with_env(&db,go_peer,"gofree-cal4-http",&[]).await?;
        let recording=go.is_some();
        if recording && mutant.is_some() {return Err("mutants are replay-only".into());}
        restore=install_mutant(&owner,mutant).await?;
        let app=db.app.as_deref().unwrap_or(&db.dsn);
        let cut=match mutant {Some("commit-before")=>Some(common::commit::CommitCut::BeforeCommit),Some("commit-after")=>Some(common::commit::CommitCut::AfterCommit),_=>None};
        let mut commit_wire=if let Some(cut)=cut {Some(common::commit::commit_cut_proxy(app,cut).await)} else {None};
        let wire=if mutant==Some("no-tenant-filter") {Some(wire::no_tenant_filter(app).await?)} else {None};
        let target=wire.as_ref().map(|w|w.dsn.as_str()).or_else(||commit_wire.as_ref().map(|(dsn,_)|dsn.as_str())).unwrap_or(app);
        let exec=common::patient_exec(target,if cut.is_some(){1}else{4})?;
        let inner=setjoin_gateway::caldav::CalDavRoute::new(exec,Arc::new(common::recovery_keys()),"mailserver".into()).await;
        if !recording && label=="timezone-cache" {
            inner.start_timezone_listener(std::env::var("DB_DIRECT_DSN")?);
            let deadline=tokio::time::Instant::now()+std::time::Duration::from_secs(30);
            while !inner.timezone_listening() {
                if tokio::time::Instant::now()>deadline {return Err("timezone LISTEN unavailable".into());}
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        }
        let adapter=Probe {inner,mutant};
        let mut inventory:Value=serde_json::from_str(include_str!("../../route-inventory.json"))?;
        for row in inventory["routes"].as_array_mut().ok_or("routes")? {
            if row["path"]=="/caldav/" {
                row["state"]=json!(if recording {"OFF"} else {"ON"});
                row["upstream"]=json!(if recording {"go-mail"} else {"local-rust"});
            }
        }
        let gateway=Gateway::new(Config {upstream:go.as_ref().map(|g|format!("http://{}",g.address).parse()).transpose()?,trusted_proxies:TrustedProxies::parse("")?,upstream_header_timeout:setjoin_gateway::proxy::DEFAULT_HEADER_TIMEOUT,edge_limit:None},RouteTable::proxy_all().with(adapter).with_catchall(setjoin_gateway::catchall::CatchallRoute::new()))?.with_inventory(&inventory.to_string())?;
        let listener = setjoin_conformance::ports::listener().await;
        let address=listener.local_addr()?;
        let (executable,server)=if route=="executable" {drop(listener);(Some(session::executable(address,app).await?),None)} else {(None,Some(tokio::spawn(gateway.serve(listener))))};
        let token=common::recovery_token(a.user);
        if matches!(route,"session"|"executable") {
            let result=session::drive(&db,owner.clone(),&a,&b,address,&token,recording).await;
            if let Some(server)=server {server.abort();let _=server.await;}drop(executable);return result;
        }
        let send=|| {
            let mut request=Request::builder().method(s.method).uri(&s.path).header("host","mail.test").header("origin","http://mail.test").header("x-request-id","gofree-cal4-oracle").header("authorization",format!("Bearer {token}"));
            for (k,v) in &s.headers {request=request.header(*k,v);}
            let body=s.body.clone();
            async move {Ok::<_,BoxError>(common::send(address,request.body(common::full(body))?).await)}
        };
        if s.repeat {let first=send().await?; common::body_bytes(first).await;}
        let before=snapshot(&owner,a.mailbox,b.mailbox,matches!(route,"put"|"delete"|"mkcalendar")).await?;
        let audit_start:i64=owner.query_one("SELECT coalesce(max(id),0) FROM admin_audit_log",&[]).await?.get(0);
        let mut notices_a=db.listen(&format!("calendar:{}",a.mailbox)).await?;
        let mut notices_b=db.listen(&format!("calendar:{}",b.mailbox)).await?;
        let response=send().await?;
        let status=response.status().as_u16();
        if status != s.wanted && mutant.is_none() { return Err(format!("{route} must be native: got {status}, expected {}",s.wanted).into()); }
        let mut headers=serde_json::Map::new();
        for k in response.headers().keys() {headers.insert(k.to_string(),json!(response.headers().get_all(k).iter().map(|v|v.to_str().unwrap().to_owned()).collect::<Vec<_>>()));}
        let body=String::from_utf8(common::body_bytes(response).await.to_vec())?;
        if let Some(cut)=cut {
            if status!=503 || !body.contains("operation outcome unknown") {return Err("commit cut reported a false success or wrong outcome".into());}
            let text=headers.get("x-operation-id").and_then(|v|v[0].as_str()).ok_or("missing operation ID")?;
            if text.len()!=32 {return Err("bad operation ID".into());}
            let mut bytes=[0;16];for (i,byte) in bytes.iter_mut().enumerate() {*byte=u8::from_str_radix(&text[i*2..i*2+2],16)?;}
            let op=setjoin_contracts::ids::OperationId(bytes);
            let (_,task)=commit_wire.take().ok_or("missing cut proxy")?;
            let observed=tokio::time::timeout(std::time::Duration::from_secs(30),task).await???;
            if observed!=cut {return Err("wrong COMMIT barrier".into());}
            let fresh=common::patient_exec(app,1)?;let keys=Arc::new(common::recovery_keys());
            for (user,expected) in [(a.user,cut==common::commit::CommitCut::AfterCommit),(b.user,false)] {
                let mut h=hyper::HeaderMap::new();h.insert("authorization",format!("Bearer {}",common::recovery_token(user)).parse()?);
                let auth=setjoin_authz::authorize_user_request(&fresh,&keys,"mailserver",&h,"http").await.ok_or("fresh lookup authority unavailable")?;
                let found=setjoin_calendar::dav::lookup_operation(&fresh,auth.context(),op,setjoin_calendar::dav::Operation::Create).await.map_err(|_|"outcome lookup unavailable")?;
                if found!=expected {return Err("actor-bound COMMIT outcome mismatch".into());}
            }
        }

        let mut cache_responses=vec![];
        if label=="timezone-cache" {
            owner.batch_execute(&format!("BEGIN; SET LOCAL session_replication_role=replica; UPDATE vt_timezone SET standard='{{\"cal4\":\"updated\"}}'::jsonb WHERE calendar_id={CAL} AND tzid='CAL4/Shared'; COMMIT")).await?;
            cache_responses.push(observe_response(send().await?).await?);
            let deadline=tokio::time::Instant::now()+std::time::Duration::from_secs(30);
            loop {
                owner.batch_execute("NOTIFY timezone_changed").await?;
                tokio::time::sleep(std::time::Duration::from_millis(25)).await;
                let response=observe_response(send().await?).await?;
                if response["body"].as_str().is_some_and(|b|b.contains("updated")) {cache_responses.push(response);break;}
                if tokio::time::Instant::now()>deadline {return Err("timezone NOTIFY reload timed out".into());}
            }
        }
        let after=snapshot(&owner,a.mailbox,b.mailbox,matches!(route,"put"|"delete"|"mkcalendar")).await?;
        if mutant==Some("no-tenant-filter") {
            if status!=200 || !body.contains("Other owner event") || wire.as_ref().is_none_or(|w|w.hits.load(std::sync::atomic::Ordering::SeqCst)==0) {return Err("tenant mutant did not reach the foreign resource".into());}
        }
        if matches!(mutant,Some("no-notify"|"double-bump")) && (status!=201 || after["events"].as_array().is_none_or(|a|a.len()!=1)) {return Err("publishing mutant did not create the resource".into());}

        let audit=rows(&owner,&format!("SELECT (to_jsonb(l)-'id'-'created_at'-'occurred_at')::text FROM admin_audit_log l WHERE id>{audit_start} ORDER BY id")).await?;
        let mut audit=audit;
        for row in &mut audit {if let Some(checksum)=row.get_mut("checksum") {
            let valid=checksum.as_str().is_some_and(|s|s.len()==64 && s.bytes().all(|c|c.is_ascii_hexdigit()));
            if !valid {return Err("invalid audit checksum format".into());}
            *checksum=json!("<checksum>");
        }}
        let mut notify=Vec::new();
        for (name,l) in [("a",&mut notices_a),("b",&mut notices_b)] {for payload in l.drain(&owner).await? {notify.push(json!({"mailbox":name,"payload":serde_json::from_str::<Value>(&payload).unwrap_or(json!(payload))}));}}
        let domain_a:String=owner.query_one("SELECT name FROM domains WHERE id=$1",&[&a.domain]).await?.get(0);
        let domain_b:String=owner.query_one("SELECT name FROM domains WHERE id=$1",&[&b.domain]).await?.get(0);
        let mut ids=vec![(a.mailbox,"<mailbox-a>".to_owned()),(b.mailbox,"<mailbox-b>".to_owned()),(a.user,"<user-a>".to_owned()),(b.user,"<user-b>".to_owned())];
        let mut etags=Vec::new();
        if matches!(route,"put"|"delete"|"mkcalendar") {
            for row in owner.query("SELECT ce.id,ce.uid,ce.etag,ce.recurrence_override::text FROM calendar_events ce JOIN calendars c ON c.id=ce.calendar_id WHERE c.mailbox_id IN ($1,$2)",&[&a.mailbox,&b.mailbox]).await? {
                let uid:String=row.get(1);let etag:String=row.get(2);
                let recurrence:Option<String>=row.get(3);let uid=recurrence.map_or_else(||uid.clone(),|r|format!("{uid}@{r}"));
                ids.push((row.get(0),format!("<event:{uid}>")));
                if !etag.is_empty() {etags.push((etag,format!("<etag:{uid}>")));}
            }
        }
        if route=="put" && (label=="recurring" || label.starts_with("recurrence-")) {
            if let Some(value)=headers.get("etag").and_then(|v|v[0].as_str()) {
                let etag=value.trim_matches('"');
                if !etags.iter().any(|(actual,_)|actual==etag) && etag.len()==64 && etag.bytes().all(|c|c.is_ascii_hexdigit()) {etags.push((etag.to_owned(),"<pre-reconcile-etag>".to_owned()));}
            }
        }
        let mask=|text:&str| {
            let mut text=text.replace(&domain_a,"a.test").replace(&domain_b,"b.test");
            for (etag,label) in &etags {text=text.replace(etag,label);}
            let text=regex::Regex::new(r"DTSTAMP:\d{8}T\d{6}Z").unwrap().replace_all(&text,"DTSTAMP:<timestamp>").into_owned();
            let mut out=String::new(); let mut chars=text.chars().peekable();
            while let Some(ch)=chars.next() {
                if ch.is_ascii_digit() {
                    let mut run=String::from(ch);
                    while chars.peek().is_some_and(char::is_ascii_digit) {run.push(chars.next().unwrap());}
                    if let Some((_,label))=run.parse::<i64>().ok().and_then(|n|ids.iter().find(|(id,_)|*id==n)) {out.push_str(label)} else {out.push_str(&run)}
                } else {out.push(ch)}
            }
            out
        };
        let mut observation=json!({"request":{"method":"*","concrete_method":s.method,"path":"/caldav/","external_path":s.path,"body":if s.body.len()>1<<20 {use sha2::Digest;format!("<generated-body bytes={} sha256={:x}>",s.body.len(),sha2::Sha256::digest(s.body.as_bytes()))} else {s.body.clone()}},"response":{"status":status,"headers":headers,"body":mask(&body)},"effects":[{"table":"f17-caldav","before":before,"after":after}],"audit":audit,"notify":notify});
        if !cache_responses.is_empty() {observation["cache_responses"]=json!(cache_responses);}
        fn mask_ids(v:&mut Value, ids:&[(i64,String)]) {
            match v {
                Value::Number(n)=>if let Some((_,label))=n.as_i64().and_then(|n|ids.iter().find(|(id,_)|*id==n)) {*v=json!(label)},
                Value::Array(xs)=>xs.iter_mut().for_each(|v|mask_ids(v,ids)),
                Value::Object(m)=>m.values_mut().for_each(|v|mask_ids(v,ids)), _=>{}
            }
        }
        mask_ids(&mut observation,&ids);
        map_strings(&mut observation,&mask);
        if observation["response"]["headers"].get("date").is_some() {observation["response"]["headers"]["date"]=json!(["<timestamp>"]);}
        if let Some(length)=observation["response"]["headers"].get_mut("content-length") {
            if length[0]!=body.len().to_string() {return Err("wrong wire content-length".into());}
            *length=json!([mask(&body).len().to_string()]);
        }
        if !recording {
            let metrics=common::send(address,Request::get("/_gateway/metrics").body(common::full(""))?).await;
            let metrics=String::from_utf8(common::body_bytes(metrics).await.to_vec())?;
            assert!(metrics.lines().any(|l|l=="setjoin_gateway_proxied_to_go_by_family_total{family=\"F17\"} 0"),"forwarded: {metrics}");
        }
        if let Some(server)=server {server.abort(); let _=server.await;}
        let dir=std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/conformance/caldav/goldens");
        std::fs::create_dir_all(&dir)?;
        let prefix=if route=="entitlement" {"admission-entitlement"} else if route=="put" && (label=="recurring" || label.starts_with("recurrence-")) {"put-recurrence"} else if route=="put" {"put-create"} else {route};
        let file=dir.join(format!("{prefix}-{label}.json"));
        if let Some(cut)=cut {
            if cut==common::commit::CommitCut::BeforeCommit {
                if observation["effects"][0]["before"]!=observation["effects"][0]["after"] || observation["audit"]!=json!([]) || observation["notify"]!=json!([]) {return Err("pre-COMMIT cut published effects".into());}
            } else {
                let expected:Value=serde_json::from_slice(&std::fs::read(file)?)?;
                let mut expected=expected["observation"].clone();expected.as_object_mut().unwrap().remove("response");
                let mut actual=observation.clone();actual.as_object_mut().unwrap().remove("response");
                golden::compare(&expected,&actual)?;
            }
            eprintln!("COMMIT-CUT: CalDAV create :: {cut:?} (fresh actor lookup, no replay)");
        } else if recording {
            golden::record(&file,&json!({"format":1,"route":format!("* /caldav/ {route}"),"case":label,"go_source":std::env::var("GOFREE_GO_SOURCE")?,"observation":observation}))?;
        } else {
            let expected:Value=common::golden_doc(&file,"observation",&observation);
            let compare=golden::compare(&expected["observation"],&observation);
            if let Some(m)=mutant {if compare.is_ok() {return Err(format!("mutant survived {m}").into());}eprintln!("MUTANT-REJECTED: * /caldav/ {route} :: {m}");eprintln!("MUTANT-REJECTED: * /caldav/ :: {m}");} else {compare?;
                if matches!(route,"put"|"delete") {
                    let row:Value=serde_json::from_slice(&std::fs::read(dir.join(format!("{prefix}-{label}-row-effects.json")))?)?;
                    golden::compare(&row["effects"],&observation["effects"])?;
                }
                eprintln!("GOLDEN-REPLAY: * /caldav/ {route} :: {label}");eprintln!("GOLDEN-REPLAY: * /caldav/ :: {label}");}
        }
        Ok::<_,BoxError>(())
    }.await;
    for definition in restore.into_iter().rev() {
        owner.batch_execute(&definition).await?;
    }
    owner.batch_execute(&format!("DELETE FROM jmap_changes_journal WHERE mailbox_id IN ({},{}); DELETE FROM calendars WHERE mailbox_id IN ({},{})",a.mailbox,b.mailbox,a.mailbox,b.mailbox)).await?;
    owner
        .execute(
            "UPDATE audit_policy SET level=$1 WHERE id=1",
            &[&audit_level],
        )
        .await?;
    owner.batch_execute(&format!("BEGIN; SET LOCAL session_replication_role=replica; DELETE FROM admin_audit_log WHERE user_id IN ({},{}); COMMIT",a.user,b.user)).await?;
    for row in saved {
        let key: String = row.get(0);
        let enabled: bool = row.get(1);
        owner
            .execute(
                "UPDATE feature_toggles SET enabled=$2 WHERE key=$1",
                &[&key, &enabled],
            )
            .await?;
    }
    for account in [&a, &b] {
        common::remove_blob_account(&owner, account).await?;
    }
    result
}

async fn observe_response(response: Response<hyper::body::Incoming>) -> Result<Value, BoxError> {
    let status = response.status().as_u16();
    let mut headers = serde_json::Map::new();
    for key in response.headers().keys() {
        headers.insert(
            key.to_string(),
            json!(response
                .headers()
                .get_all(key)
                .iter()
                .map(|v| v.to_str().unwrap().to_owned())
                .collect::<Vec<_>>()),
        );
    }
    let body = String::from_utf8(common::body_bytes(response).await.to_vec())?;
    if headers
        .get("content-length")
        .is_some_and(|v| v[0] != body.len().to_string())
    {
        return Err("invalid extra wire content-length".into());
    }
    if headers.contains_key("date") {
        headers.insert("date".into(), json!(["<timestamp>"]));
    }
    Ok(json!({"status":status,"headers":headers,"body":body}))
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
        c.batch_execute("CREATE FUNCTION gofree_cal4_double_bump() RETURNS trigger LANGUAGE plpgsql AS $f$ BEGIN IF NEW.jmap_state>OLD.jmap_state THEN NEW.jmap_state:=NEW.jmap_state+1; END IF; RETURN NEW; END $f$; CREATE TRIGGER gofree_cal4_double_bump BEFORE UPDATE ON calendars FOR EACH ROW EXECUTE FUNCTION gofree_cal4_double_bump()").await?;
        restore.push("DROP TRIGGER gofree_cal4_double_bump ON calendars; DROP FUNCTION gofree_cal4_double_bump()".into());
    }
    Ok(restore)
}
