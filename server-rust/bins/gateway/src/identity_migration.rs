//! Mailserver-local F21 migration adapter. Owned SQL stays in identity;
//! worker/config composition belongs to this gateway, beside the existing runner.
use crate::{Body,RequestContext};
use hyper::{Method,Request,Response};
use setjoin_authz::AuthContext;
use setjoin_pg::{ScopedExecutor,CommandOutcome};
use serde::de::{DeserializeSeed,MapAccess,Visitor};
use serde_json::json;
use std::fmt;

// Schema-directed serde visitors implement Go's merge semantics: scalar null
// is a no-op, slice null clears, duplicate nested objects merge into the same
// struct, and RawMessage preserves explicit null versus an absent config.
macro_rules! input {
    ($name:ident,$seed:ident { fields {$($field:ident:$ty:ty=$key:literal),* $(,)?}
      lists {$($list:ident:$elem:ty=$listkey:literal),* $(,)?}
      nested {$($nested:ident:$nestedty:ty=>$nestedseed:ident=$nestedkey:literal),* $(,)?}
      raw {$($raw:ident=$rawkey:literal),* $(,)?} }) => {
        #[derive(Default)]
        struct $name { $($field:$ty,)* $($list:Vec<Option<$elem>>,)* $($nested:$nestedty,)* $($raw:Option<Box<serde_json::value::RawValue>>,)* }
        struct $seed<'a>(&'a mut $name);
        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D:serde::Deserializer<'de>>(d:D)->Result<Self,D::Error> {
                let mut value=Self::default();$seed(&mut value).deserialize(d)?;Ok(value)
            }
        }
        impl<'a,'de> DeserializeSeed<'de> for $seed<'a> {
            type Value=();
            fn deserialize<D:serde::Deserializer<'de>>(self,d:D)->Result<(),D::Error> {
                struct Fields<'a>(&'a mut $name);
                impl<'a,'de> Visitor<'de> for Fields<'a> {
                    type Value=();
                    fn expecting(&self,f:&mut fmt::Formatter<'_>)->fmt::Result {f.write_str("a JSON object")}
                    fn visit_unit<E:serde::de::Error>(self)->Result<(),E> {Ok(())}
                    fn visit_map<M:MapAccess<'de>>(self,mut map:M)->Result<(),M::Error> {
                        while let Some(key)=map.next_key::<String>()? {
                            match crate::guests_input::fold(&key).as_str() {
                                $($key=>if let Some(value)=map.next_value::<Option<$ty>>()? {self.0.$field=value;},)*
                                $($listkey=>self.0.$list=map.next_value::<Option<Vec<Option<$elem>>>>()?.unwrap_or_default(),)*
                                $($nestedkey=>map.next_value_seed($nestedseed(&mut self.0.$nested))?,)*
                                $($rawkey=>self.0.$raw=Some(map.next_value()?),)*
                                _=>{let _:serde::de::IgnoredAny=map.next_value()?;}
                            }
                        }
                        Ok(())
                    }
                }
                d.deserialize_any(Fields(self.0))
            }
        }
    };
}
input!(Credentials,CredentialsSeed {fields {username:String="username",password:String="password"} lists {} nested {} raw {}});
input!(ImapInput,ImapSeed {fields {host:String="host",port:i64="port",tls:String="tls_mode"}
    lists {hosts:String="private_hosts",cidrs:String="private_cidrs"} nested {credentials:Credentials=>CredentialsSeed="credentials"} raw {}});
input!(Target,TargetSeed {fields {_source:String="sourceemail",_target:String="targetemail"} lists {} nested {} raw {}});
input!(StartInput,StartSeed {fields {source:String="sourcetype",strategy:String="conflictstrategy"}
    lists {targets:Target="targets"} nested {imap:ImapInput=>ImapSeed="imapconfig"} raw {config="config"}});
input!(EwsInput,EwsSeed {fields {url:String="serverurl",username:String="username",password:String="password",impersonate:String="impersonateas",
    insecure:bool="insecureskipverify",mail:bool="includemail",calendar:bool="includecalendar",contacts:bool="includecontacts"}
    lists {hosts:String="privatehosts",cidrs:String="privatecidrs"} nested {} raw {}});
/// Owner-approved security fix 2026-11-05 (#547): a user's source password never travels in
/// clear on the self-service routes. test-imap refuses `none` (the connector rejects any other
/// unknown mode itself); an IMAP start allows only `tls` or `starttls`, so an omitted mode cannot
/// fall through to `imap.defaults`' (possibly `none`) at run time.
const PLAINTEXT:&str="plaintext IMAP (tls_mode none) is not allowed; use tls or starttls";
const TLS_REQUIRED:&str="tls_mode must be tls or starttls";
fn plaintext(mode:&str)->bool {mode=="none" && !setjoin_contracts::mutants::on("self-service-allows-plaintext-imap")}
fn start_refusal(mode:&str)->Option<&'static str> {
    if plaintext(mode) {return Some(PLAINTEXT);}
    if matches!(mode,"tls"|"starttls") || setjoin_contracts::mutants::on("self-service-allows-empty-tls-mode") {return None;}
    Some(if mode=="none" {PLAINTEXT}else{TLS_REQUIRED})
}
const PRIVATE_POLICY:&str="migration private-network policy is administrator-owned; per-job privateHosts/privateCIDRs are not accepted";

pub(crate) fn matches(r:&Request<Body>)->bool {
    (*r.method()==Method::POST && crate::inventory::path_score("/auth/me/migration/test-imap",r.uri().path()).is_some())
        || (*r.method()==Method::POST && crate::inventory::path_score("/auth/me/migration/upload",r.uri().path()).is_some())
        || (*r.method()==Method::POST && crate::inventory::path_score("/auth/me/migration/pause",r.uri().path()).is_some())
        || (*r.method()==Method::POST && crate::inventory::path_score("/auth/me/migration/cancel",r.uri().path()).is_some())
        || (*r.method()==Method::POST && crate::inventory::path_score("/auth/me/migration/resume",r.uri().path()).is_some())
        || matches!(*r.method(),Method::GET|Method::HEAD|Method::DELETE|Method::POST)
        && crate::inventory::path_score("/auth/me/migration",r.uri().path()).is_some()
}

async fn upload_form(r:&mut Request<Body>)->Result<(Option<Vec<u8>>,Option<Vec<u8>>),()> {
    use http_body_util::BodyExt;
    let boundary=r.headers().get(hyper::header::CONTENT_TYPE).and_then(|v|v.to_str().ok()).and_then(|v|multer::parse_boundary(v).ok()).ok_or(())?;
    let cap=64<<20;
    let mut data=Vec::new();
    while let Some(frame)=r.body_mut().frame().await {
        if let Ok(bytes)=frame.map_err(|_|())?.into_data() {
            if bytes.len()>cap-data.len() {return Err(());}
            data.extend_from_slice(&bytes);
        }
    }
    let stream=futures_util::stream::once(async move {Ok::<_,std::convert::Infallible>(bytes::Bytes::from(data))});
    let mut form=multer::Multipart::new(stream,boundary);
    let (mut ics,mut vcf)=(None,None);
    while let Some(field)=form.next_field().await.map_err(|_|())? {
        let name=field.name().map(str::to_owned);
        let file=field.file_name().is_some_and(|name|!name.is_empty());
        let data=field.bytes().await.map_err(|_|())?.to_vec();
        match (name.as_deref(),file) {
            (Some("ics"),true) if ics.is_none()=>ics=Some(data),
            (Some("vcf"),true) if vcf.is_none()=>vcf=Some(data),
            _=>{}
        }
    }
    Ok((ics,vcf))
}

pub(crate) async fn handle(exec:&ScopedExecutor,actor:&AuthContext,mut r:Request<Body>,c:&RequestContext,id:String,operation:[u8;16],runner:Option<&crate::migration::Runner>)->Response<Body> {
    if r.method()==Method::POST && crate::inventory::path_score("/auth/me/migration/test-imap",r.uri().path()).is_some() {
        let Ok(input)=crate::admin_identity_input::first::<ImapInput>(&mut r,crate::identity_self_service::body_cap()).await else {return crate::mailboxes::bare(400,"invalid JSON body",c,&id);};
        if !input.hosts.is_empty() || !input.cidrs.is_empty() {return crate::mailboxes::bare(400,PRIVATE_POLICY,c,&id);}
        if plaintext(&input.tls) {return crate::mailboxes::bare(400,PLAINTEXT,c,&id);}
        let Some(runner)=runner else {return crate::mailboxes::bare(503,"service unavailable",c,&id);};
        let connector=crate::migration_runner::ImapConnector::new(crate::migration_runner::ImapConfig {
            host:input.host,port:input.port,tls_mode:input.tls,username:input.credentials.username,password:input.credentials.password,
            ..Default::default()
        },runner.orchestrator.dialer());
        let success=matches!(tokio::time::timeout(std::time::Duration::from_secs(30),connector.test_connection()).await,Ok(Ok(())));
        let body=if success {"{\"success\":true}\n".to_owned()}else{
            format!("{}\n",json!({"error":"Could not connect to the source server. Verify the server address and credentials.","success":false}))
        };
        return crate::jmap::reply::response(body,c.identity.proto,id);
    }
    if r.method()==Method::POST && crate::inventory::path_score("/auth/me/migration/upload",r.uri().path()).is_some() {
        let job=crate::admin_identity_input::query(r.uri(),"job_id").and_then(|text|text.parse::<i64>().ok());
        let Some(job)=job else {return crate::mailboxes::bare(400,"invalid job_id",c,&id);};
        if !setjoin_identity::self_service::migration_job_owned(exec,actor,job).await {return crate::mailboxes::bare(404,"migration job not found",c,&id);}
        let Ok((ics,vcf))=upload_form(&mut r).await else {return crate::mailboxes::bare(400,"failed to parse multipart form",c,&id);};
        if ics.is_none() && vcf.is_none() {return crate::mailboxes::bare(400,"no ICS or VCF file provided",c,&id);}
        let Some(runner)=runner else {return crate::mailboxes::bare(503,"service unavailable",c,&id);};
        // Frozen Go ignores StoreUpload errors and acknowledges the input sizes.
        let _=runner.orchestrator.store_upload(job,ics.as_deref(),vcf.as_deref()).await;
        return crate::jmap::reply::response(format!("{{\"ics_size\":{},\"vcf_size\":{}}}\n",ics.as_ref().map_or(0,Vec::len),vcf.as_ref().map_or(0,Vec::len)),c.identity.proto,id);
    }
    if r.method()==Method::POST && crate::inventory::path_score("/auth/me/migration/pause",r.uri().path()).is_some() {
        let Some(job)=setjoin_identity::self_service::migration_pause_job(exec,actor).await else {return crate::mailboxes::bare(404,"no active migration job",c,&id);};
        let Some(runner)=runner else {return crate::mailboxes::bare(503,"service unavailable",c,&id);};
        if runner.orchestrator.pause_job(job).is_err() {return crate::mailboxes::bare(500,"failed to pause job",c,&id);}
        let mut response=crate::jmap::reply::response(String::new(),c.identity.proto,id);
        *response.status_mut()=hyper::StatusCode::ACCEPTED;
        response.headers_mut().remove("content-type");
        return response;
    }
    if r.method()==Method::POST && crate::inventory::path_score("/auth/me/migration/cancel",r.uri().path()).is_some() {
        let Some(job)=setjoin_identity::self_service::migration_cancel_job(exec,actor).await else {return crate::mailboxes::bare(404,"no active migration job",c,&id);};
        let Some(runner)=runner else {return crate::mailboxes::bare(503,"service unavailable",c,&id);};
        if runner.orchestrator.cancel_job(job).is_err() {return crate::mailboxes::bare(500,"failed to cancel job",c,&id);}
        let mut response=crate::jmap::reply::response(String::new(),c.identity.proto,id);
        *response.status_mut()=hyper::StatusCode::NO_CONTENT;
        response.headers_mut().remove("content-type");
        return response;
    }
    if r.method()==Method::POST && crate::inventory::path_score("/auth/me/migration/resume",r.uri().path()).is_some() {
        let Some(job)=setjoin_identity::self_service::migration_paused_job(exec,actor).await else {return crate::mailboxes::bare(404,"no paused migration job",c,&id);};
        let Some(runner)=runner else {return crate::mailboxes::bare(503,"service unavailable",c,&id);};
        if runner.orchestrator.resume_job(job).is_err() {return crate::mailboxes::bare(500,"failed to resume job",c,&id);}
        let mut response=crate::jmap::reply::response(String::new(),c.identity.proto,id);
        *response.status_mut()=hyper::StatusCode::ACCEPTED;
        response.headers_mut().remove("content-type");
        return response;
    }
    if r.method()==Method::POST {
        let fail=|status,message|crate::mailboxes::bare(status,message,c,&id);
        let Ok(input)=crate::admin_identity_input::first::<StartInput>(&mut r,crate::identity_self_service::body_cap()).await else {return fail(400,"invalid JSON body");};
        if !input.targets.is_empty() {return fail(403,"bulk/impersonation migration is an admin operation; use the admin migration API");}
        let source=if input.source.is_empty() {"imap"}else{&input.source};
        let strategy=if input.strategy.is_empty() {"skip"}else{&input.strategy};
        let Some(runner)=runner else {return fail(503,"service unavailable");};
        let mut config=None;
        let mailbox;
        if source=="ews" {
            let Some(raw)=input.config.as_ref() else {return fail(400,"config is required for EWS migration");};
            let Ok(ews)=serde_json::from_str::<EwsInput>(raw.get()) else {return fail(400,"invalid EWS config JSON");};
            if ews.url.is_empty() {return fail(400,"config.serverURL is required for EWS migration");}
            if !ews.impersonate.is_empty() {return fail(400,"impersonation is admin-only; remove impersonateAs from migration config");}
            if !ews.hosts.is_empty() || !ews.cidrs.is_empty() {return fail(400,PRIVATE_POLICY);}
            if ews.username.is_empty() || ews.password.is_empty() {return fail(400,"self-service EWS migration requires your own username and password");}
            let global=setjoin_mailboxes::migration::has_global(exec,"ews").await;
            let value=json!({"use_global_auth":global,"source_type":"ews","self_service":true,"ews":{
                "serverURL":ews.url,"username":ews.username,"password":ews.password,"insecureSkipVerify":ews.insecure,
                "includeMail":ews.mail,"includeCalendar":ews.calendar,"includeContacts":ews.contacts}});
            let Some(sealed)=runner.orchestrator.encryption_key().and_then(|key|setjoin_mailboxes::migration::seal(value.to_string().as_bytes(),&key)) else {return fail(500,"internal error");};
            config=Some(sealed);
            let Some(owned)=setjoin_identity::self_service::migration_mailbox(exec,actor).await else {return fail(400,"no mailbox found for user");};
            mailbox=owned;
        }else if source=="m365" {
            if !setjoin_mailboxes::migration::has_global(exec,"m365").await {return fail(400,"M365 global config not found — admin must configure it first");}
            // Nonempty targets were already refused at ingress. Frozen Go's
            // self-service M365 branch cannot reach job creation.
            return fail(400,"targets[] is required for M365 migration (at least one source email)");
        }else {
            let Some(owned)=setjoin_identity::self_service::migration_mailbox(exec,actor).await else {return fail(400,"no mailbox found for user");};
            mailbox=owned;
            if source.split('|').map(str::trim).any(|kind|kind=="imap") {
                if input.imap.host.is_empty() {return fail(400,"imapConfig.host is required for IMAP migration");}
                if !input.imap.hosts.is_empty() || !input.imap.cidrs.is_empty() {return fail(400,PRIVATE_POLICY);}
                if let Some(why)=start_refusal(&input.imap.tls) {return fail(400,why);}
                let global=setjoin_mailboxes::migration::has_global(exec,"imap").await;
                let value=json!({"use_global_auth":global,"source_type":"imap","self_service":true,"imap":{
                    "host":input.imap.host,"port":input.imap.port,"tls_mode":input.imap.tls,
                    "credentials":{"username":input.imap.credentials.username,"password":input.imap.credentials.password}}});
                let Some(sealed)=runner.orchestrator.encryption_key().and_then(|key|setjoin_mailboxes::migration::seal(value.to_string().as_bytes(),&key)) else {return fail(500,"internal error");};
                config=Some(sealed);
            }
        }
        return match setjoin_identity::self_service::migration_job_insert(exec,actor,source,config.as_deref(),mailbox,strategy,operation).await {
            CommandOutcome::Committed(job)=>{
                if runner.orchestrator.start_job(job).is_err() {return fail(500,"failed to start job");}
                let mut response=crate::jmap::reply::response(format!("{{\"id\":{job},\"status\":\"pending\"}}\n"),c.identity.proto,id);
                *response.status_mut()=hyper::StatusCode::CREATED;
                response
            },
            CommandOutcome::Unknown {operation}=>crate::mailboxes::unknown_outcome(operation,c,&id),
            CommandOutcome::RolledBack(setjoin_pg::Rejection::Statement(error)) if error.sqlstate.as_deref()==Some("23505") && error.message.contains("migration_one_active_per_user")=>fail(409,"an active migration job already exists; cancel it or wait for it to finish"),
            _=>fail(500,"failed to create job"),
        };
    }
    if r.method()==Method::DELETE {
        return match setjoin_identity::self_service::migration_history_delete(exec,actor,operation).await {
            CommandOutcome::Committed(deleted)=>crate::jmap::reply::response(format!("{{\"deleted\":{deleted}}}\n"),c.identity.proto,id),
            CommandOutcome::Unknown {operation}=>crate::mailboxes::unknown_outcome(operation,c,&id),
            _=>crate::mailboxes::bare(500,"delete failed",c,&id),
        };
    }
    let value=setjoin_identity::self_service::migration_status(exec,actor).await.unwrap_or_else(||"{\"status\":\"none\"}\n".into());
    crate::jmap::reply::response(value,c.identity.proto,id)
}
