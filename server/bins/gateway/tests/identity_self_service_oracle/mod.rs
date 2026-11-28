use crate::common::{self, BoxError};
use hyper::{Request, Response};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use setjoin_conformance::{fixture, golden, harness::Db};
use setjoin_gateway::{
    Body, BoxFuture, Config, Gateway, Intercept, RequestContext, RouteTable, TrustedProxies,
};
use std::path::PathBuf;

struct PublicFixture;
impl setjoin_gateway::identity_self_service::HostResolver for PublicFixture {
    fn resolve(&self, _host: String) -> BoxFuture<Option<Vec<std::net::IpAddr>>> {
        Box::pin(async { Some(vec!["93.184.216.34".parse().unwrap()]) })
    }
}

struct Probe {
    inner: setjoin_gateway::identity_self_service::IdentitySelfServiceRoute<
        setjoin_gateway::jmap::jwks::Jwks,
    >,
    mutant: bool,
    mutant_path: String,
}
impl Intercept for Probe {
    fn requires_session(&self, r: &Request<Body>) -> bool {
        self.inner.requires_session(r)
    }
    fn matches(&self, r: &Request<Body>) -> bool {
        self.inner.matches(r)
    }
    fn admits_member(&self, h: hyper::HeaderMap, s: &'static str) -> BoxFuture<bool> {
        self.inner.admits_member(h, s)
    }
    fn handle(&self, r: Request<Body>, c: RequestContext) -> BoxFuture<Response<Body>> {
        let mutant = self.mutant && r.uri().path()==self.mutant_path;
        let future = self.inner.handle(r, c);
        Box::pin(async move {
            let mut response = future.await;
            if mutant {
                *response.status_mut() = hyper::StatusCode::IM_A_TEAPOT;
            }
            response
        })
    }
}

// Generated IDs change the raw byte count. Validate framing before canonicalizing
// only its numeric length for comparison; the recorded headers remain immutable.
fn canonical_framing(observation: &mut Value) {
    if observation["response"]["headers"]
        .get("content-length")
        .is_some()
    {
        observation["response"]["headers"]["content-length"] = json!(["<validated-length>"]);
    }
}

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn normalize(
    text: &str,
    a: &fixture::Account,
    b: &fixture::Account,
    ids: &[(i64, &str)],
) -> String {
    let mut text = text.replace(&format!("?userId={}", b.user), "?userId=<user-b>").replace(&format!("?userId={}",a.user),"?userId=<user-a>");
    text=text.replace(&format!("?userId=%0A{}",a.user),"?userId=%0A<user-a>");
    for (account, label) in [(a, "a"), (b, "b")] {
        for key in ["id","managerId"] {
            text=text.replace(&format!("\"{key}\":\"{}\"",account.user),&format!("\"{key}\":\"<user-{label}>\""));
        }
        for (key, id) in [
            ("user_id", account.user),
            ("owner_user_id", account.user),
            ("granted_by", account.user),
            ("mailbox_id", account.mailbox),
            ("target_mailbox_id", account.mailbox),
        ] {
            for end in [",", "}"] {
                text = text.replace(
                    &format!("\"{key}\":{id}{end}"),
                    &format!("\"{key}\":\"<{label}>\"{end}"),
                );
            }
        }
    }
    for (id, label) in ids {
        if label.starts_with("message-") {
            text=text.replace(&format!("\"messageId\":\"{id}\""),&format!("\"messageId\":\"<{label}>\""));
        }
        for key in ["id","policyId","message_id","job_id"] {
        for sep in [":", ": "] {
            for end in [",", "}"] {
                text = text.replace(
                    &format!("\"{key}\"{sep}{id}{end}"),
                    &format!("\"{key}\"{sep}\"<{label}>\"{end}"),
                );
            }
        }
        }
        text=text.replace(&format!("/migration/upload/{id}/"),&format!("/migration/upload/<{label}>/"));
        let upload_query=regex::Regex::new(&format!(r#"([?&]job_id=){}($|[&\"\\])"#,id)).unwrap();
        text=upload_query.replace_all(&text,|caps:&regex::Captures|format!("{}<{label}>{}",&caps[1],&caps[2])).into_owned();
        let recipient_path=regex::Regex::new(&format!(r#"/smime/recipient-certs/{}($|[/\?\"\\])"#,id)).unwrap();
        text=recipient_path.replace_all(&text,|caps:&regex::Captures|format!("/smime/recipient-certs/<{label}>{}",&caps[1])).into_owned();
        let cert_path=regex::Regex::new(&format!(r#"/smime/certs/{}($|[/\?\"\\])"#,id)).unwrap();
        text=cert_path.replace_all(&text,|caps:&regex::Captures|format!("/smime/certs/<{label}>{}",&caps[1])).into_owned();
        text=text.replace(&format!("/webhooks/{id}"),&format!("/webhooks/<{label}>"));
        text = text.replace(
            &format!("/app-passwords/{id}"),
            &format!("/app-passwords/<{label}>"),
        );
    }
    text=regex::Regex::new(r"oracle-[a-f0-9]{32}\.test").unwrap().replace_all(&text,"fixture.test").into_owned();
    // Only wall-clock timestamps vary. Ordering, flags and hash values remain visible.
    regex::Regex::new(r#"\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|\+00:00)?"#)
        .unwrap()
        .replace_all(&text, |captures: &regex::Captures| {
            if ["2026-10-01","2095-10-01","2020-10-01","2021-10-01"].iter().any(|date|captures[0].starts_with(date)) {
                captures[0].to_owned()
            } else {
                "<timestamp>".to_owned()
            }
        })
        .into_owned()
}

async fn snapshot(
    c: &tokio_postgres::Client,
    a: &fixture::Account,
    b: &fixture::Account,
    action: &str,
) -> Result<Value, BoxError> {
    let rows=c.query("SELECT jsonb_build_object('id',id,'user_id',user_id,'name',name,'label',label,'token_hash',token_hash,'revoked',revoked_at IS NOT NULL,'expires',expires_at IS NOT NULL,'last_used',last_used_at IS NOT NULL)::text FROM app_passwords WHERE user_id=ANY($1) ORDER BY id", &[&vec![a.user,b.user]]).await?;
    let mut value=json!({"app_passwords":rows.iter().map(|r|serde_json::from_str::<Value>(&r.get::<_,String>(0))).collect::<Result<Vec<_>,_>>()?});
    if action.starts_with("migration-") {
        let rows=c.query("SELECT to_jsonb(j)::text FROM migration_jobs j WHERE user_id=ANY($1) ORDER BY id",&[&vec![a.user,b.user]]).await?;
        value["migration_jobs"]=json!(rows.iter().map(|r|serde_json::from_str::<Value>(&r.get::<_,String>(0))).collect::<Result<Vec<_>,_>>()?);
    }
    if action=="migration-delete" {
        let rows=c.query("SELECT to_jsonb(s)::text FROM migration_source_instances s JOIN migration_jobs j ON j.id=s.job_id WHERE j.user_id=ANY($1) ORDER BY s.id",&[&vec![a.user,b.user]]).await?;
        value["migration_source_instances"]=json!(rows.iter().map(|r|serde_json::from_str::<Value>(&r.get::<_,String>(0))).collect::<Result<Vec<_>,_>>()?);
    }
    if action.starts_with("cert-") || action.starts_with("recipient-") {
        for (key,sql) in [
            ("user_smime_certs","SELECT to_jsonb(s)::text FROM user_smime_certs s WHERE user_id=ANY($1) ORDER BY id"),
            ("recipient_smime_certs","SELECT to_jsonb(s)::text FROM recipient_smime_certs s WHERE owner_user_id=ANY($1) ORDER BY id"),
        ] {
            value[key]=json!(c.query(sql,&[&vec![a.user,b.user]]).await?.iter().map(|r|serde_json::from_str::<Value>(&r.get::<_,String>(0))).collect::<Result<Vec<_>,_>>()?);
        }
    }
    if action.starts_with("hook-") {
        let rows=c.query("SELECT to_jsonb(w)::text FROM webhook_subscriptions w WHERE user_id=ANY($1) ORDER BY id",&[&vec![a.user,b.user]]).await?;
        value["webhook_subscriptions"]=json!(rows.iter().map(|r|serde_json::from_str::<Value>(&r.get::<_,String>(0))).collect::<Result<Vec<_>,_>>()?);
    }
    if action=="tips" {
        for (key,sql,owners) in [
            ("preferences","SELECT jsonb_build_object('user_id',id,'external_sender_warning',external_sender_warning)::text FROM users WHERE id=ANY($1) ORDER BY id",vec![a.user,b.user]),
            ("vacation_settings","SELECT to_jsonb(v)::text FROM vacation_settings v WHERE mailbox_id=ANY($1) ORDER BY mailbox_id",vec![a.mailbox,b.mailbox]),
            ("mailbox_delegates","SELECT to_jsonb(d)::text FROM mailbox_delegates d WHERE user_id=ANY($1) ORDER BY mailbox_id,user_id,permission",vec![a.user,b.user]),
        ] {
            value[key]=json!(c.query(sql,&[&owners]).await?.iter().map(|r|serde_json::from_str::<Value>(&r.get::<_,String>(0))).collect::<Result<Vec<_>,_>>()?);
        }
    }
    if action=="receipt" {
        for (key,sql,owners) in [
            ("messages","SELECT jsonb_build_object('message_id',id,'mailbox_id',mailbox_id,'is_read',is_read,'message_header_id',message_id,'subject',subject,'from_addr',from_addr,'received_at',received_at)::text FROM messages WHERE mailbox_id=ANY($1) AND message_id IN ('<idlogin4-receipt-a@source.test>','<idlogin4-receipt-b@source.test>') ORDER BY mailbox_id,id",vec![a.mailbox,b.mailbox]),
            ("mailbox_states","SELECT jsonb_build_object('mailbox_id',id,'jmap_email_state',jmap_email_state)::text FROM mailboxes WHERE id=ANY($1) ORDER BY id",vec![a.mailbox,b.mailbox]),
            ("read_receipts","SELECT (to_jsonb(r)-'id')::text FROM read_receipts r JOIN messages m ON m.id=r.message_id AND m.received_at=r.received_at WHERE m.mailbox_id=ANY($1) ORDER BY r.message_id,r.recipient_email",vec![a.mailbox,b.mailbox]),
            ("outbound_queue","SELECT (to_jsonb(o)-'id')::text FROM outbound_queue o WHERE EXISTS(SELECT 1 FROM messages m WHERE m.mailbox_id=ANY($1) AND o.message_id LIKE '<mdn-'||m.id::text||'-%@mailserver>') ORDER BY o.message_id",vec![a.mailbox,b.mailbox]),
            ("receipt_policies","SELECT (to_jsonb(p)-'id')::text FROM user_notification_prefs p WHERE user_id=ANY($1) ORDER BY user_id,device_fingerprint NULLS FIRST",vec![a.user,b.user]),
        ] {
            value[key]=json!(c.query(sql,&[&owners]).await?.iter().map(|r|serde_json::from_str::<Value>(&r.get::<_,String>(0))).collect::<Result<Vec<_>,_>>()?);
        }
    }
    Ok(value)
}

// Normalize only a validated DB-transaction clock, never arbitrary MIME bytes.
async fn mdn_masks(c:&tokio_postgres::Client,a:&fixture::Account,message:i64,started:std::time::SystemTime,raw:&str)->Result<Vec<(String,String)>,BoxError> {
    let value:Value=serde_json::from_str(raw)?;
    if value["status"]!="sent" {return Err(format!("expected consented MDN: {raw}").into());}
    let mdn=value["mdnMessageId"].as_str().ok_or("missing MDN ID")?;
    let prefix=format!("<mdn-{message}-");
    let clock=mdn.strip_prefix(&prefix).and_then(|s|s.strip_suffix("@mailserver>")).ok_or("MDN ID lost its owned message identity")?;
    let (seconds,fraction)=clock.split_once('.').ok_or("MDN clock is not PostgreSQL epoch text")?;
    let seconds_value=seconds.parse::<u64>()?;
    if seconds!=seconds_value.to_string() || fraction.len()!=6 || !fraction.bytes().all(|b|b.is_ascii_digit()) {return Err("noncanonical MDN clock".into());}
    let nanos=format!("{fraction}000").parse::<u32>()?;
    let when=std::time::UNIX_EPOCH.checked_add(std::time::Duration::new(seconds_value,nanos)).ok_or("MDN clock out of range")?;
    let row=c.query_one("SELECT clock_timestamp(),to_char($1::timestamptz,'Dy, DD Mon YYYY HH24:MI:SS +0000')",&[&when]).await?;
    let finished:std::time::SystemTime=row.get(0);let date:String=row.get(1);
    if when<started || when>finished {return Err("MDN clock outside the request".into());}
    let original=c.query_one("SELECT from_addr,message_id FROM messages WHERE id=$1 AND mailbox_id=$2",&[&message,&a.mailbox]).await?;
    let sender:String=original.get(0);let original_id:String=original.get(1);
    let queued=c.query("SELECT from_addr,rcpt_addrs,raw_ref,status,queued_at=$2::timestamptz AND next_attempt_at=$2::timestamptz FROM outbound_queue WHERE message_id=$1",&[&mdn,&when]).await?;
    if queued.len()!=1 {return Err("MDN did not publish exactly one queue row".into());}
    let queue=&queued[0];let mime:String=queue.get(2);
    if queue.get::<_,String>(0)!="x@test" || queue.get::<_,Vec<String>>(1)!=vec![sender.clone()] || queue.get::<_,String>(3)!="pending" || !queue.get::<_,bool>(4) {return Err("MDN queue identity/status/clock mismatch".into());}
    for field in [format!("From: x@test\r\n"),format!("To: {sender}\r\n"),format!("Message-ID: {mdn}\r\n"),format!("Date: {date}\r\n"),format!("Original-Message-ID: {original_id}\r\n"),format!("Your message was displayed on {date}\r\n")] {
        if !mime.contains(&field) {return Err(format!("MDN omitted validated MIME field {field:?}").into());}
    }
    let receipts=c.query("SELECT r.read_at=$3::timestamptz,r.recipient_email FROM read_receipts r JOIN messages m ON m.id=r.message_id AND m.received_at=r.received_at WHERE r.message_id=$1 AND m.mailbox_id=$2",&[&message,&a.mailbox,&when]).await?;
    if receipts.len()!=1 || !receipts[0].get::<_,bool>(0) || receipts[0].get::<_,String>(1)!="x@test" {return Err("MDN receipt is absent or not atomic with its queue row".into());}
    Ok(vec![(mdn.to_owned(),"<mdn-message-a-<clock>@mailserver>".into()),(date,"<mdn-date>".into())])
}

fn access_token(action:&str,kind:&str,user:i64)->String {
    if action=="org" && kind=="live-deny" {
        common::recovery_token_with(user,json!({"admin":true,"perms":["users.read"]}))
    } else if action=="org" && kind!="no-permission" {
        common::recovery_token_with(user,json!({"perms":["users.read"]}))
    } else { common::recovery_token(user) }
}

async fn hook_masks(c: &tokio_postgres::Client, a: &fixture::Account, raw: &str, started: std::time::SystemTime) -> Result<(i64, Vec<(String,String)>), BoxError> {
    let value: Value = serde_json::from_str(raw)?;
    let secret = value["secret"].as_str().ok_or("missing one-time webhook secret")?;
    if secret.len()!=64 || !secret.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) { return Err("invalid webhook secret format".into()); }
    let id=value["id"].as_i64().ok_or("missing webhook id")?;
    let row=c.query_one("SELECT secret,secret_enc,secret_key_id,created_at >= $2::timestamptz AND updated_at >= $2::timestamptz AND created_at <= clock_timestamp() AND updated_at <= clock_timestamp(),secret_enc::text FROM webhook_subscriptions WHERE id=$1 AND user_id=$3",&[&id,&started,&a.user]).await?;
    let sealed: Vec<u8>=row.try_get(1)?; let key: String=row.try_get(2)?;
    let codec=setjoin_platform::webhook_secret::SecretCodec::new(b"blobs1-test-jwt-secret-for-recording",setjoin_config_secret::CryptoProfile::parse(""));
    if row.try_get::<_,Option<String>>(0)?.is_some() || key!="v1" || !row.try_get::<_,bool>(3)? || codec.open(&sealed,&key)?!=secret { return Err("webhook secret is not sealed under the acknowledged owner/clock/key".into()); }
    let cipher_text:String=row.try_get(4)?;
    Ok((id,vec![(secret.to_owned(),"<hook-secret>".into()),(json!(cipher_text).to_string(),json!("<validated-hook-envelope>").to_string())]))
}

fn cert_upload_body(kind:&str, own:bool) -> Result<String, BoxError> {
    if kind=="invalid-input" {return Ok("{not-multipart".into());}
    let root=PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let dir=root.join("../../tests/conformance/identity-self-service/fixtures");
    let mut cert=if kind=="invalid-cert" {"not a certificate".into()}else{std::fs::read_to_string(dir.join(match kind {"expired"=>"expired.pem","no-email"=>"no-email.pem","sign-only"=>"sign-only.pem","ec"=>"ec.pem",_=>"recipient.pem"}))?};
    if kind=="mislabeled" {cert=cert.replace("CERTIFICATE","OTHER BLOCK");}
    let key=if kind=="invalid-key" {"not a private key".into()}else{std::fs::read_to_string(if kind=="mismatched-key" {dir.join("ec-key.pem")}else{root.join("../../crates/protocols/smtp/oracle/auth-fixture/rsa.pem")})?};
    let label=if kind=="oversize" {"X".repeat(((if own {5}else{2})<<20)+1)}else if matches!(kind,"default-label"|"replace-blank") {" \t ".into()}else{" Desk <&> ".into()};
    let mut body=format!("--gofree-idlogin4\r\nContent-Disposition: form-data; name=\"label\"\r\n\r\n{label}\r\n");
    for (name,text) in [("cert",cert),("key",key)] {
        if (!own && name=="key") || (kind=="missing-cert" && name=="cert") || (kind=="missing-key" && name=="key") {continue;}
        body.push_str(&format!("--gofree-idlogin4\r\nContent-Disposition: form-data; name=\"{name}\"; filename=\"{name}.pem\"\r\nContent-Type: application/x-pem-file\r\n\r\n{text}\r\n"));
    }
    body.push_str("--gofree-idlogin4--\r\n");Ok(body)
}

async fn validate_recipient(c:&tokio_postgres::Client,a:&fixture::Account,started:std::time::SystemTime,kind:&str,prior:Option<std::time::SystemTime>)->Result<i64,BoxError> {
    let mut pem=std::fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/conformance/identity-self-service/fixtures/recipient.pem"))?;
    if kind=="mislabeled" {pem=pem.replace("CERTIFICATE","OTHER BLOCK");}
    let der=setjoin_mail_security::smime::first_pem_bytes(pem.as_bytes()).ok_or("recipient fixture DER")?;
    let fingerprint=format!("{:x}",Sha256::digest(&der));
    let rows=c.query("SELECT id,cert_pem,label,source,first_seen,last_seen,clock_timestamp(),not_before='2026-10-01'::timestamptz AND not_after='2095-10-01'::timestamptz FROM recipient_smime_certs WHERE owner_user_id=$1 AND email='person@example.net' AND fingerprint=$2",&[&a.user,&fingerprint]).await?;
    if rows.len()!=1 {return Err("recipient upsert missing or duplicated owned fingerprint".into());}
    let row=&rows[0];let first:std::time::SystemTime=row.get(4);let last:std::time::SystemTime=row.get(5);let end:std::time::SystemTime=row.get(6);
    let label=if kind=="replace-blank" {"recipient-a"}else{"Desk <&>"};
    if row.get::<_,String>(1)!=pem || row.get::<_,String>(2)!=label || row.get::<_,String>(3)!="imported" || !row.get::<_,bool>(7) || last<started || last>end || prior.map_or(first<started || first>end,|p|first!=p) {return Err("recipient upsert lost PEM/label/source/dates or transaction clocks".into());}
    Ok(row.get(0))
}

struct StoredCert {
    id:i64,
    created:std::time::SystemTime,
    envelope:String,
    masks:Vec<(String,String)>,
}
async fn cert_key_masks(c:&tokio_postgres::Client,a:&fixture::Account,started:std::time::SystemTime,kind:&str,prior:Option<std::time::SystemTime>)->Result<StoredCert,BoxError> {
    let root=PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let expected=std::fs::read_to_string(root.join(if kind=="mismatched-key" {"../../tests/conformance/identity-self-service/fixtures/ec-key.pem"}else{"../../crates/protocols/smtp/oracle/auth-fixture/rsa.pem"}))?;
    let label=match kind {"query-label"=>"Query <&>","default-label"=>"default",_=>"Desk <&>"};
    let root_key="22".repeat(32);
    let row=c.query_one("SELECT id,pgp_sym_decrypt(private_key_enc::bytea,$2),private_key_enc::text,created_at,clock_timestamp(),is_default FROM user_smime_certs WHERE user_id=$1 AND label=$3",&[&a.user,&root_key,&label]).await?;
    let created:std::time::SystemTime=row.try_get(3)?;let finished:std::time::SystemTime=row.try_get(4)?;
    let clock=prior.map_or(created>=started && created<=finished,|old|created==old);
    if row.try_get::<_,String>(1)?!=expected || !clock || row.try_get::<_,bool>(5)?!=(kind!="second-cert") {return Err("S/MIME key/owner/creation clock/default differs from acknowledged upload".into());}
    let cipher:String=row.try_get(2)?;
    Ok(StoredCert {id:row.try_get(0)?,created,envelope:cipher.clone(),masks:vec![(json!(cipher).to_string(),json!("<validated-pgp-key>").to_string())]})
}

const UPLOAD_ICS:&str="BEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n";
const UPLOAD_VCF:&str="BEGIN:VCARD\r\nVERSION:3.0\r\nFN:Fixture\r\nEND:VCARD\r\n";
fn migration_upload_body(kind:&str)->String {
    if matches!(kind,"bad-form"|"cross-tenant") {return "{not multipart".into();}
    if kind=="no-file" {return "--gofree-idlogin4\r\nContent-Disposition: form-data; name=\"ics\"\r\n\r\nnot a file\r\n--gofree-idlogin4--\r\n".into();}
    let mut body=String::new();
    for (name,data) in [("ics",UPLOAD_ICS),("vcf",UPLOAD_VCF)] {
        if (kind=="vcf-only" && name=="ics") || (matches!(kind,"empty-file"|"ics-only"|"oversize") && name=="vcf") {continue;}
        let data=if kind=="empty-file" {String::new()}else if kind=="oversize" {"x".repeat((64<<20)+1)}else{data.to_owned()};
        body.push_str(&format!("--gofree-idlogin4\r\nContent-Disposition: form-data; name=\"{name}\"; filename=\"data.bin\"\r\nContent-Type: application/octet-stream\r\n\r\n{data}\r\n"));
    }
    body.push_str("--gofree-idlogin4--\r\n");body
}
#[derive(Default)]
struct UploadStore {
    attempts:Vec<Value>,
    objects:std::collections::BTreeMap<String,Value>,
    errors:Vec<String>,
}
impl UploadStore {
    fn snapshot(&self)->Result<Value,BoxError> {
        if !self.errors.is_empty() {return Err(self.errors.join("; ").into());}
        Ok(json!({"attempts":self.attempts,"objects":self.objects}))
    }
}

async fn settle_job(c:&tokio_postgres::Client,job:i64,user:i64,runner:Option<&setjoin_gateway::migration::Runner>)->Result<(),BoxError> {
    let deadline=std::time::Instant::now()+std::time::Duration::from_secs(30);
    loop {
        let phase:String=c.query_one("SELECT status FROM migration_jobs WHERE id=$1 AND user_id=$2",&[&job,&user]).await?.get(0);
        if matches!(phase.as_str(),"completed"|"failed"|"cancelled") && runner.is_none_or(|r|!r.orchestrator.is_running(job)) {return Ok(());}
        if std::time::Instant::now()>=deadline {return Err(format!("migration {job} failed to settle: {phase}").into());}
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}

pub async fn run(action: &str, kind: &str) -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let mutant = kind.ends_with("status-mutant");
    let native_auth_denial=kind=="revoked-no-mailbox";
    if native_auth_denial && std::env::var_os("GOFREE_RECORD_GO_BINARY").is_some() {return Err("native admission invariant is not a Go recording case".into());}
    let commit_cut=match kind {
        "commit-before"=>Some(common::commit::CommitCut::BeforeCommit),
        "commit-after"=>Some(common::commit::CommitCut::AfterCommit),
        _=>None,
    };
    if commit_cut.is_some() && std::env::var_os("GOFREE_RECORD_GO_BINARY").is_some() {return Err("commit cuts run natively, never record a fault as Go".into());}
    let label = if mutant { kind.strip_suffix("-status-mutant").filter(|k|!k.is_empty()).unwrap_or("success") } else { kind };
    // `tls-<case>` (#547): the test-imap case recorded with tls_mode "tls", which the route still
    // accepts. It behaves as <case> everywhere but the sent mode and the golden's name.
    let file_label = label;
    let tls_variant = label.starts_with("tls-");
    let label = label.strip_prefix("tls-").unwrap_or(label);
    let Some(db) = Db::for_case("identity-self-service") else {
        return Ok(());
    };
    let c = db.connect().await?;
    let prior_receipts=c.query("SELECT operation_id::text FROM rust_operation_receipts WHERE family='F21' AND command LIKE 'self-service.%'",&[]).await?.iter().map(|r|r.get::<_,String>(0)).collect::<Vec<_>>();
    let privilege_fault=matches!(action,"app-create"|"app-revoke"|"hook-create"|"hook-list"|"hook-delete"|"cert-list"|"cert-upload"|"cert-delete"|"cert-default"|"recipient-list"|"recipient-upload"|"recipient-delete"|"migration-status"|"migration-delete"|"migration-start"|"migration-resume"|"migration-cancel"|"migration-pause"|"migration-upload") && kind=="db-error" || (action=="hook-create" && kind=="count-error") || (action=="cert-delete" && kind=="promote-error") || (action=="cert-default" && kind=="update-error");
    let fault_privilege=match action {"hook-create" if kind=="count-error"=>"SELECT","app-revoke"=>"UPDATE","hook-list"|"cert-list"|"recipient-list"|"migration-status"|"migration-resume"|"migration-cancel"|"migration-pause"|"migration-upload"=>"SELECT","hook-delete"|"recipient-delete"|"migration-delete"=>"DELETE","cert-default"=>if kind=="update-error" {"UPDATE"}else{"SELECT"},"cert-delete"=>if kind=="promote-error" {"UPDATE"}else{"DELETE"},_=>"INSERT"};
    let fault_table=if action.starts_with("migration-") {"migration_jobs"}else if action.starts_with("recipient-") {"recipient_smime_certs"}else if action.starts_with("hook-") {"webhook_subscriptions"}else if action.starts_with("cert-") {"user_smime_certs"}else{"app_passwords"};
    if privilege_fault {
        let granted:bool=c.query_one("SELECT has_table_privilege('setjoin_app',$1,$2)",&[&fault_table,&fault_privilege]).await?.get(0);
        if !granted || db.app.is_none() { return Err("privilege fault needs the configured app role with its original INSERT grant".into()); }
    }
    let a = fixture::account(&c, "idlogin4-a").await?;
    let b = fixture::account(&c, "idlogin4-b").await?;
    let mut policy_ids=Vec::<i64>::new();
    let toggle_fault=(action=="dlp" && kind=="toggle-off") || (action=="tips" && kind=="feature-off");
    let toggle_key=if action=="tips" {"feature.external_sender_warn"}else{"feature.dlp"};
    let toggle_original=if toggle_fault {c.query_opt("SELECT enabled FROM feature_toggles WHERE key=$1",&[&toggle_key]).await?.map(|r|r.get::<_,bool>(0))}else{None};
    let result=async {
        let mut ids=vec![];
        let mut masks=Vec::<(String,String)>::new();
        let mut message_ids=vec![];
        if action.starts_with("migration-") {
            for (account,job_label,status,date) in [(&a,"migration-a","failed","2026-10-01T10:00:00Z"),(&b,"migration-b","cancelled","2026-10-01T11:00:00Z"),(&a,"migration-completed","completed","2026-10-01T12:00:00Z")] {
                let id:i64=c.query_one("INSERT INTO migration_jobs(user_id,source_type,source_config_enc,target_mailbox_id,conflict_strategy,status,progress,error_log,created_at,started_at,completed_at) VALUES($1,'imap',decode('49444c4f47494e342d68696464656e','hex'),$2,'skip',$3,'{\"z\":2,\"a_long\":1}'::jsonb,'[{\"message\":\"finished <&>\",\"code\":7}]'::jsonb,$4::text::timestamptz,$4::text::timestamptz,$4::text::timestamptz) RETURNING id",&[&account.user,&account.mailbox,&status,&date]).await?.get(0);
                ids.push((id,job_label));
            }
        }
        if action=="migration-delete" {
            for (job_label,status,date) in [("migration-paused","paused","2026-10-01T13:00:00Z"),("migration-cancelled","cancelled","2026-10-01T14:00:00Z")] {
                if status=="paused" && label!="success" {continue;}
                let id:i64=c.query_one("INSERT INTO migration_jobs(user_id,source_type,target_mailbox_id,status,created_at) VALUES($1,'ics',$2,$3,$4::text::timestamptz) RETURNING id",&[&a.user,&a.mailbox,&status,&date]).await?.get(0);
                ids.push((id,job_label));
            }
            for (index,job) in [(1,ids[0].0),(2,ids[1].0)] {
                let uuid=format!("49400000-0000-4000-8000-{index:012}");
                c.execute("INSERT INTO migration_source_instances(id,job_id,source_type,source_mailbox_key,selector_digest,created_at,updated_at) VALUES($1::text::uuid,$2,'imap',$3,$4,'2026-10-01','2026-10-01')",&[&uuid,&job,&format!("idlogin4-history-{index}"),&"11".repeat(32)]).await?;
            }
        }
        if action=="migration-delete" && label=="empty" {
            c.execute("DELETE FROM migration_jobs WHERE user_id=$1 AND status IN ('completed','cancelled','failed')",&[&a.user]).await?;
        }
        if action=="migration-status" {
            if label=="empty" {c.execute("DELETE FROM migration_jobs WHERE user_id=$1",&[&a.user]).await?;}
            if label=="completed-only" {c.execute("UPDATE migration_jobs SET status='completed' WHERE user_id=$1",&[&a.user]).await?;}
            if label=="null-dates" {c.execute("UPDATE migration_jobs SET started_at=NULL,completed_at=NULL WHERE user_id=$1",&[&a.user]).await?;}
        }
        if action.starts_with("cert-") {
            let cert=std::fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/conformance/identity-self-service/fixtures/recipient.pem"))?;
            for (account,cert_label) in [(&a,"cert-a"),(&b,"cert-b")] {
                if action=="cert-upload" && account.user==a.user && !matches!(label,"second-cert"|"replace") {continue;}
                let id:i64=c.query_one("INSERT INTO user_smime_certs(user_id,label,cert_pem,is_default,created_at) VALUES($1,$2,$3,true,'2026-10-01T10:00:00Z') RETURNING id",&[&account.user,&cert_label,&cert]).await?.get(0);
                ids.push((id,cert_label));
            }
        }
        if action.starts_with("recipient-") {
            let pem=std::fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/conformance/identity-self-service/fixtures/recipient.pem"))?;
            let der=setjoin_mail_security::smime::first_pem_bytes(pem.as_bytes()).ok_or("recipient fixture DER")?;
            let fingerprint=format!("{:x}",Sha256::digest(&der));
            for (account,cert_label) in [(&a,"recipient-a"),(&b,"recipient-b")] {
                if action=="recipient-upload" && account.user==a.user && !matches!(label,"replace"|"replace-blank") {continue;}
                let id:i64=c.query_one("INSERT INTO recipient_smime_certs(owner_user_id,email,cert_pem,fingerprint,not_before,not_after,source,label,first_seen,last_seen) VALUES($1,'person@example.net',$2,$3,'2026-10-01','2095-10-01','harvested',$4,'2026-10-01T10:00:00Z','2026-10-01T11:00:00Z') RETURNING id",&[&account.user,&pem,&fingerprint,&cert_label]).await?.get(0);
                ids.push((id,cert_label));
            }
        }
        if (action=="cert-delete" && label!="no-survivor") || action=="cert-default" {
            let id:i64=c.query_one("INSERT INTO user_smime_certs(user_id,label,cert_pem,is_default,created_at) SELECT $1,'survivor',cert_pem,false,'2026-10-01T11:00:00Z' FROM user_smime_certs WHERE user_id=$1 LIMIT 1 RETURNING id",&[&a.user]).await?.get(0);
            ids.push((id,"cert-survivor"));
        }
        if action.starts_with("hook-") {
            for (account,label) in [(&a,"hook-a"),(&b,"hook-b")] {
                let id:i64=c.query_one("INSERT INTO webhook_subscriptions(user_id,url,secret,event_types,scope,created_at,updated_at) VALUES($1,$2,'fixture-secret-not-returned','[\"mail.received\"]'::jsonb,'self','2026-10-01T10:00:00Z','2026-10-01T10:00:00Z') RETURNING id",&[&account.user,&format!("https://example.net/{label}")]).await?.get(0);
                ids.push((id,label));
            }
        }
        if action=="hook-create" && label=="cap" {
            // hook-a already exists: 19 more bring the caller to Go's cap of 20.
            for n in 0..19 {
                let url=format!("https://example.net/hook-cap-{n}");
                let id:i64=c.query_one("INSERT INTO webhook_subscriptions(user_id,url,secret,event_types,scope,created_at,updated_at) VALUES($1,$2,'fixture-secret-not-returned','[\"mail.received\"]'::jsonb,'self','2026-10-01T10:00:00Z','2026-10-01T10:00:00Z') RETURNING id",&[&a.user,&url]).await?.get(0);
                ids.push((id,"hook-cap"));
            }
        }
        if action=="cert-upload" && label=="replace" {
            c.execute("UPDATE user_smime_certs SET label='Desk <&>' WHERE user_id=$1",&[&a.user]).await?;
        }
        if action=="cert-list" {
            if label=="empty" { c.execute("DELETE FROM user_smime_certs WHERE user_id=$1",&[&a.user]).await?; }
            if label=="invalid-cert" { c.execute("UPDATE user_smime_certs SET cert_pem='invalid stored PEM' WHERE user_id=$1",&[&a.user]).await?; }
            if label=="long-label" { c.execute("UPDATE user_smime_certs SET label=$2 WHERE user_id=$1",&[&a.user,&"<&>".repeat(800)]).await?; }
        }
        if action=="recipient-list" {
            if label=="empty" {c.execute("DELETE FROM recipient_smime_certs WHERE owner_user_id=$1",&[&a.user]).await?;}
            if matches!(label,"sign-only"|"ec"|"invalid-cert") {
                let pem=if label=="invalid-cert" {"invalid stored certificate".into()} else {std::fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!("../../tests/conformance/identity-self-service/fixtures/{label}.pem")))?};
                c.execute("UPDATE recipient_smime_certs SET cert_pem=$2 WHERE owner_user_id=$1",&[&a.user,&pem]).await?;
            }
            if label=="no-dates" {c.execute("UPDATE recipient_smime_certs SET not_before=NULL,not_after='0001-01-01' WHERE owner_user_id=$1",&[&a.user]).await?;}
            if label=="empty-label" {c.execute("UPDATE recipient_smime_certs SET label=NULL WHERE owner_user_id=$1",&[&a.user]).await?;}
        }
        if action=="receipt" {
            for (account,which,label) in [(&a,"a","message-a"),(&b,"b","message-b")] {
                let header=format!("<idlogin4-receipt-{which}@source.test>");
                let message:i64=c.query_one("INSERT INTO messages(mailbox_id,folder_id,message_id,subject,from_addr,size_bytes,thread_id,raw_ref,received_at,is_read) VALUES($1,$2,$3,'IDLOGIN4 receipt','sender@source.test',10,$3,'receipt-original','2026-10-01T10:00:00Z',false) RETURNING id",&[&account.mailbox,&account.inbox,&header]).await?.get(0);
                message_ids.push(message);ids.push((message,label));
            }
        }
        if action.starts_with("app-") || action=="dlp" {
        for (account,label) in [(&a,"app-a"),(&b,"app-b")] {
            let id:i64=c.query_one("INSERT INTO app_passwords(user_id,name,label,token_hash,created_at) VALUES($1,$2,'fixture',$3,'2026-10-01T10:00:00Z') RETURNING id", &[&account.user,&label,&format!("seed-{label}")]).await?.get(0);
            ids.push((id,label));
        }
        }
        if action=="app-list" && label=="timestamps" {
            c.execute("UPDATE app_passwords SET created_at='2026-10-01T10:00:00.123400Z',last_used_at='2026-10-01T10:15:00.450000Z',expires_at='2026-10-01T12:00:00Z' WHERE id=$1 AND user_id=$2",&[&ids[0].0,&a.user]).await?;
        }
        if action=="app-create" && label=="cap" {
            for label in ["cap-0","cap-1","cap-2","cap-3","cap-4","cap-5","cap-6","cap-7","cap-8"] {
                let id:i64=c.query_one("INSERT INTO app_passwords(user_id,name,label,token_hash,created_at) VALUES($1,$2,'fixture',$3,'2026-10-01T10:00:00Z') RETURNING id",&[&a.user,&label,&format!("seed-{label}")]).await?.get(0);
                ids.push((id,label));
            }
        }
        if action=="org" && matches!(label,"managers"|"reports") {
            c.execute("UPDATE users SET domain_id=$1 WHERE id=$2",&[&a.domain,&b.user]).await?;
            c.execute("UPDATE mailboxes SET domain_id=$1 WHERE id=$2 AND user_id=$3",&[&a.domain,&b.mailbox,&b.user]).await?;
            let (manager,report)=if label=="reports" {(a.user,b.user)}else{(b.user,a.user)};
            c.execute("UPDATE users SET manager_id=$1 WHERE id=$2",&[&manager,&report]).await?;
        }
        if action=="org" && label=="unicode-profile" {
            c.execute("UPDATE users SET display_name=$1,first_name='Ada',last_name='L',job_title='Engineer' WHERE id=$2",&[&"Lead <&> 中文\u{2028}line",&a.user]).await?;
        }
        if action=="dlp" && matches!(label,"violation"|"foreign-policy"|"db-error") {
            let domain=if label=="foreign-policy" {b.domain}else{a.domain};
            let regex=if label=="db-error" {"["}else{"Hello"};
            let id:i64=c.query_one("INSERT INTO dlp_policies(domain_id,name,priority,regex_patterns) VALUES($1,'IDLOGIN4 policy',-999,$2) RETURNING id",&[&domain,&vec![regex]]).await?.get(0);
            policy_ids.push(id);ids.push((id,"dlp-policy"));
        }
        if toggle_fault { c.execute("INSERT INTO feature_toggles(key,enabled) VALUES($1,false) ON CONFLICT(key) DO UPDATE SET enabled=false",&[&toggle_key]).await?; }
        if action=="receipt" && matches!(label,"policy-never"|"policy-always") {
            let policy=if label=="policy-never" {"never"}else{"always"};
            c.execute("DELETE FROM user_notification_prefs WHERE user_id=$1 AND device_fingerprint IS NULL",&[&a.user]).await?;
            c.execute("INSERT INTO user_notification_prefs(user_id,read_receipt_policy) VALUES($1,$2)",&[&a.user,&policy]).await?;
        }
        if action=="tips" && label=="preference-off" {
            c.execute("UPDATE users SET external_sender_warning=false WHERE id=$1",&[&a.user]).await?;
        }
        if action=="tips" && matches!(label,"ooo"|"ooo-indefinite") {
            let indefinite=label=="ooo-indefinite";
            c.execute("INSERT INTO vacation_settings(mailbox_id,enabled,subject,body_text,end_date) VALUES($1,true,'IDLOGIN4 private subject','IDLOGIN4 private reply',CASE WHEN $2 THEN NULL::date ELSE '2099-12-31'::date END) ON CONFLICT(mailbox_id) DO UPDATE SET enabled=true,subject=excluded.subject,body_text=excluded.body_text,end_date=excluded.end_date",&[&a.mailbox,&indefinite]).await?;
        }
        if action=="tips" && matches!(label,"delegate"|"wrong-delegate") {
            let delegate=if label=="delegate" {a.user}else{b.user};
            c.execute("INSERT INTO mailbox_delegates(mailbox_id,user_id,permission,granted_by) VALUES($1,$2,'send_as',$3)",&[&b.mailbox,&delegate,&b.user]).await?;
        }
        let imap=if action=="migration-test-imap" {
            let bind=if std::env::var_os("GOFREE_RECORD_GO_BINARY").is_some() {"11.249.49.1:0"}else{"127.0.0.1:0"};
            let fake=crate::fake_imap::FakeImap::start(bind,"owned-user","owned-password",vec![]).await?;
            masks.push((format!("\"port\":{}",fake.address.port()),"\"port\":\"<imap-port>\"".into()));
            Some(fake)
        }else{None};
        let pattern=match action {"migration-test-imap"=>"/auth/me/migration/test-imap","migration-upload"=>"/auth/me/migration/upload","migration-pause"=>"/auth/me/migration/pause","migration-cancel"=>"/auth/me/migration/cancel","migration-resume"=>"/auth/me/migration/resume","migration-status"|"migration-delete"|"migration-start"=>"/auth/me/migration","recipient-list"|"recipient-upload"=>"/auth/me/smime/recipient-certs","recipient-delete"=>"/auth/me/smime/recipient-certs/{id}","app-revoke"=>"/auth/me/app-passwords/{id}","dlp"=>"/auth/me/dlp-check","org"=>"/auth/me/org-chart","tips"=>"/auth/me/mailtips","receipt"=>"/auth/me/read-receipt","hook-list"|"hook-create"=>"/auth/me/webhooks","hook-delete"=>"/auth/me/webhooks/{id}","cert-list"|"cert-upload"=>"/auth/me/smime/certs","cert-delete"=>"/auth/me/smime/certs/{id}","cert-default"=>"/auth/me/smime/certs/{id}/default",_=>"/auth/me/app-passwords"};
        let (method,path,mut body)=match action {
            "migration-test-imap"=>("POST",pattern.into(),match label {
                "invalid-input"=>r#"{"port":"wrong"}"#.into(),
                "null-body"=>"null".into(),
                "folded-body"=>format!(r#"{{"HOST":"11.249.49.1","port":{},"TLS_MODE":"none","credentials":{{"USERNAME":"owned-user"}},"CREDENTIALS":{{"PASSWORD":"owned-password"}},"private_hosts":["caller"],"PRIVATE_HOSTS":null}} trailing ignored"#,imap.as_ref().unwrap().address.port()),
                _=>{
                    let mut input=json!({"host":match label {"loopback"=>"127.0.0.1","link-local"=>"169.254.169.254","ipv6-loopback"=>"::1","no-host"=>"",_=>"11.249.49.1"},"port":imap.as_ref().unwrap().address.port(),"tls_mode":if tls_variant {"tls"}else{"none"},"credentials":{"username":"owned-user","password":if label=="bad-password" {"wrong-password"}else{"owned-password"}}});
                    if label=="private-policy" {input["private_hosts"]=json!(["11.249.49.1"]);}
                    if label=="private-cidr" {input["private_cidrs"]=json!(["0.0.0.0/0"]);}
                    if label=="cross-tenant" {input["user_id"]=json!(b.user);input["mailbox_id"]=json!(b.mailbox);}
                    input.to_string()
                }
            }),
            "migration-upload"=>("POST",format!("{pattern}?job_id={}",match label {"invalid-input"=>"bad".into(),"cross-tenant"=>ids[1].0.to_string(),"missing"=>"9223372036854775807".into(),"overflow"=>"9223372036854775808".into(),_=>ids[0].0.to_string()}),migration_upload_body(label)),
            "migration-cancel"|"migration-pause"=>("POST",pattern.into(),if label=="invalid-input" {"{not-json".into()}else if label=="cross-tenant" {json!({"user_id":b.user,"job_id":ids[1].0}).to_string()}else{String::new()}),
            "migration-resume"=>("POST",pattern.into(),if label=="invalid-input" {"{not-json".into()}else{String::new()}),
            "migration-start"=>("POST",pattern.into(),match label {
                "invalid-input"=>"{not-json".into(),
                "cross-tenant"=>json!({"sourceType":"ics","targets":[{"sourceEmail":"source@example.net","targetEmail":c.query_one("SELECT email FROM users WHERE id=$1",&[&b.user]).await?.get::<_,String>(0)}]}).to_string(),
                "folded-imap"=>r#"{"SourceType":"imap","IMAPCONFIG":{"HOST":"127.0.0.1","CREDENTIALS":{"USERNAME":"owned-user"},"private_hosts":["private-source"]},"imapConfig":{"tls_mode":"none","credentials":{"password":"owned-password"},"private_hosts":null}}"#.into(),
                "imap"|"private-policy"|"no-host"=>json!({"sourceType":"imap","imapConfig":{"host":if label=="no-host" {""}else{"127.0.0.1"},"tls_mode":"none","credentials":{"username":"owned-user","password":"owned-password"},"private_hosts":if label=="private-policy" {vec!["private-source"]}else{vec![]}}}).to_string(),
                "ews-no-config"=>r#"{"sourceType":"ews"}"#.into(),
                "ews-null-config"=>r#"{"sourceType":"ews","config":null}"#.into(),
                "ews-bad-config"=>r#"{"sourceType":"ews","config":[]}"#.into(),
                "ews"|"ews-missing-creds"|"ews-impersonation"=>json!({"sourceType":"ews","config":{"serverURL":"https://127.0.0.1/EWS","username":"owned-user","password":if label=="ews-missing-creds" {""}else{"owned-password"},"impersonateAs":if label=="ews-impersonation" {"foreign@example.net"}else{""}}}).to_string(),
                "m365"=>r#"{"sourceType":"m365"}"#.into(),
                "invalid-strategy"=>r#"{"sourceType":"ics","conflictStrategy":"invalid"}"#.into(),
                "unknown-source"=>r#"{"sourceType":"unknown"}"#.into(),
                _=>r#"{"sourceType":"ics"}"#.into(),
            }),
            "migration-delete"=>("DELETE",if label=="cross-tenant" {format!("{pattern}?userId={}",b.user)}else{pattern.into()},if label=="invalid-input" {"{not-json".into()}else{String::new()}),
            "migration-status"=>("GET",if label=="cross-tenant" {format!("{pattern}?userId={}",b.user)}else{pattern.into()},if label=="invalid-input" {"{not-json".into()}else{String::new()}),
            "recipient-delete"=>("DELETE",format!("/auth/me/smime/recipient-certs/{}",match label {"invalid-input"=>"bad".into(),"overflow"=>"9223372036854775808".into(),"missing"=>"9223372036854775807".into(),"cross-tenant"=>ids[1].0.to_string(),_=>ids[0].0.to_string()}),String::new()),
            "recipient-upload"=>("POST",if label=="cross-tenant" {format!("{pattern}?userId={}",b.user)}else{pattern.into()},cert_upload_body(label,false)?),
            "recipient-list"=>("GET",if label=="cross-tenant" {format!("{pattern}?userId={}",b.user)}else{pattern.into()},if label=="invalid-input" {"{not-json".into()}else{String::new()}),
            "cert-default"=>("POST",format!("/auth/me/smime/certs/{}/default",match label {"invalid-input"=>"bad".into(),"overflow"=>"9223372036854775808".into(),"missing"=>"9223372036854775807".into(),"cross-tenant"=>ids[1].0.to_string(),_=>ids[2].0.to_string()}),String::new()),
            "cert-delete"=>("DELETE",format!("/auth/me/smime/certs/{}",match label {"invalid-input"=>"bad".into(),"overflow"=>"9223372036854775808".into(),"missing"=>"9223372036854775807".into(),"cross-tenant"=>ids[1].0.to_string(),"non-default"=>ids[2].0.to_string(),_=>ids[0].0.to_string()}),String::new()),
            "cert-upload"=>("POST",match label {"cross-tenant"=>format!("{pattern}?userId={}",b.user),"query-label"=>format!("{pattern}?label=Query%20%3C%26%3E"),"bad-query"=>format!("{pattern}?label=%zz"),_=>pattern.to_owned()},cert_upload_body(label,true)?),
            "cert-list"=>("GET",if label=="cross-tenant" {format!("{pattern}?userId={}",b.user)}else{pattern.to_owned()},if label=="invalid-input" {"{not-json".into()}else{String::new()}),
            "hook-delete"=>("DELETE",format!("/auth/me/webhooks/{}",match label {"invalid-input"=>"bad".to_owned(),"overflow"=>"9223372036854775808".to_owned(),"cross-tenant"=>ids[1].0.to_string(),_=>ids[0].0.to_string()}),String::new()),
            "hook-list"=>("GET",if label=="cross-tenant" {format!("{pattern}?userId={}",b.user)}else{pattern.to_owned()},if label=="invalid-input" {"{not-json".into()}else{String::new()}),
            "hook-create"=>("POST",pattern.to_owned(),match label {
                "invalid-input"=>r#"{"url":"https://example.net/new-hook","eventTypes":"wrong"}"#.into(),
                "null-body"=>"null".into(),
                "null-events"=>r#"{"url":"https://example.net/new-hook","eventTypes":["mail.received"],"eventTypes":null}"#.into(),
                "folded-body"=>r#"{"URL":"https://example.net/new-hook","EVENTTYPES":["mail.received"],"Scope":null} trailing ignored"#.into(),
                _=>json!({"url":if label=="unsafe-url" {"http://127.0.0.1/internal"}else{"https://example.net/new-hook"},"eventTypes":match label {"unknown-event"=>vec!["unknown"],"duplicate-event"=>vec!["mail.received","mail.received"],_=>vec!["mail.received"]},"scope":if label=="bad-scope" {"organization"}else{"self"},"userId":b.user,"user_id":b.user,"mailbox_id":b.mailbox}).to_string(),
            }),
            "app-list"=>("GET", if label=="cross-tenant" { format!("/auth/me/app-passwords?userId={}",b.user) } else {if label=="encoded-path" {"/auth/m%65/app-passwords"} else {"/auth/me/app-passwords"}.to_owned()}, if label=="invalid-input"{"{not-json".to_owned()}else{String::new()}),
            "app-create"=>("POST","/auth/me/app-passwords".to_owned(), match label {
                "invalid-input"=>"{}".to_owned(),
                "control-escapes"=>json!({"name":"Desk\u{0008}\u{000c} literal\\b","label":"desk"}).to_string(),
                "cross-tenant"=>json!({"name":"Desktop <&>","label":"desk","user_id":b.user,"mailbox_id":b.mailbox}).to_string(),
                _=>r#"{"name":"Desktop <&>","label":"desk"}"#.to_owned(),
            }),
            "app-revoke"=>("DELETE",format!("/auth/me/app-passwords/{}",match label {"invalid-input"=>"bad".to_owned(),"cross-tenant"=>ids[1].0.to_string(),_=>ids[0].0.to_string()}),String::new()),
            "dlp"=>("POST",pattern.to_owned(),match label {
                "invalid-input"|"toggle-off"=>r#"{"recipients":"wrong"}"#.to_owned(),
                "cross-tenant"=>json!({"recipients":["outside@example.net"],"subject":"Hello","bodyText":"Plain draft","user_id":b.user,"mailbox_id":b.mailbox}).to_string(),
                _=>r#"{"recipients":["outside@example.net"],"subject":"Hello","bodyText":"Plain draft"}"#.to_owned(),
            }),
            "org"=>("GET",match label {
                "cross-tenant"=>format!("{pattern}?userId={}",b.user),
                "invalid-input"=>format!("{pattern}?userId=bad"),
                "newline-id"=>format!("{pattern}?userId=%0A{}",a.user),
                "no-permission"|"live-deny"=>format!("{pattern}?userId={}",a.user),
                "prefix-id"=>format!("{pattern}?userId={}tail",a.user),
                _=>pattern.to_owned(),
            },String::new()),
            "tips"=>("GET",match label {
                "cross-tenant"|"delegate"|"wrong-delegate"=>{
                    let email:String=c.query_one("SELECT email FROM mailboxes WHERE id=$1 AND user_id=$2",&[&b.mailbox,&b.user]).await?.get(0);
                    format!("{pattern}?userId={}&from={email}",b.user)
                },
                "invalid-input"=>format!("{pattern}?recipients=%zz"),
                "large-audience"=>format!("{pattern}?recipients={}",(0..26).map(|i|format!("rcpt{i:02}@EXAMPLE.NET")).collect::<Vec<_>>().join(",")),
                "ooo"|"ooo-indefinite"=>{
                    let email:String=c.query_one("SELECT email FROM mailboxes WHERE id=$1 AND user_id=$2",&[&a.mailbox,&a.user]).await?.get(0);
                    format!("{pattern}?recipients={email}")
                },
                "self-from"=>format!("{pattern}?from=x@test"),
                _=>format!("{pattern}?recipients=outside@EXAMPLE.NET"),
            },if label=="invalid-input" {"{not-json".into()}else{String::new()}),
            "receipt"=>("POST",pattern.to_owned(),match label {
                "invalid-body"=>r#"{"messageId":12}"#.into(),
                "null-body"=>"null".into(),
                _=>json!({"messageId":match label {"cross-tenant"=>message_ids[1].to_string(),"invalid-input"=>"bad".to_owned(),"overflow"=>"9223372036854775808".to_owned(),_=>message_ids[0].to_string()},"consent":matches!(label,"send"|"repeat"|"policy-never")}).to_string(),
            }),
            _=>return Err(format!("unknown action {action}").into()),
        };
        if action=="hook-create" {
            if label=="success" {
                body=r#"{"url":"https://example.net/new-hook","eventTypes":["mail.received"],"scope":"self"}"#.into();
            } else if std::env::var_os("GOFREE_RECORD_GO_BINARY").is_none() {
                // Preserve the unknown userId JSON key literally from Go's wire
                // recording. The recognized fixture identities user_id/mailbox_id
                // still name the live foreign account and are normalized below.
                let file=PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!("../../tests/conformance/identity-self-service/goldens/{action}-{label}.json"));
                if file.exists() {
                    let capture:Value=serde_json::from_slice(&std::fs::read(file)?)?;
                    if let Some(original)=capture["observation"]["request"]["body"].as_str().and_then(|text|serde_json::from_str::<Value>(text).ok()).and_then(|v|v["userId"].as_i64()) {
                        body=body.replace(&format!("\"userId\":{}",b.user),&format!("\"userId\":{original}"));
                    }
                }
            }
        }
        let content_type=if matches!(action,"cert-upload"|"recipient-upload"|"migration-upload") {"multipart/form-data; boundary=gofree-idlogin4"}else{"application/json"};
        let gated=matches!(action,"migration-cancel"|"migration-pause") && matches!(label,"success"|"invalid-input"|"repeat");
        let uploading=action=="migration-upload";
        let denied_suffix=match label {"store-error"=>"/ics","store-vcf-error"=>"/vcf",_=>""};
        let upload_store=std::sync::Arc::new(std::sync::Mutex::new(UploadStore::default()));
        let reached=std::sync::Arc::new(tokio::sync::Notify::new());
        let released=std::sync::Arc::new(tokio::sync::Notify::new());
        let s3=common::fake_upstream({
            let reached=reached.clone();let released=released.clone();let upload_store=upload_store.clone();
            move |r| {let reached=reached.clone();let released=released.clone();let upload_store=upload_store.clone();async move {
                if (gated || uploading) && r.uri().query().is_some_and(|q|q.starts_with("location")) {
                    return Response::new(common::full("<LocationConstraint xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">us-east-1</LocationConstraint>"));
                }
                if uploading && r.method()==hyper::Method::PUT {
                    use http_body_util::BodyExt;
                    let (parts,body)=r.into_parts();
                    let request=hyper::Request::from_parts(parts,());
                    let denied=!denied_suffix.is_empty() && request.uri().path().ends_with(denied_suffix);
                    let result=match body.collect().await {
                        Ok(body)=>common::s3::observe(&request,&body.to_bytes()),
                        Err(error)=>Err(error.to_string()),
                    };
                    let mut state=upload_store.lock().unwrap();
                    match result {
                        Ok(observed)=>{
                            let uri=observed["uri"].as_str().unwrap().to_owned();
                            if !denied {state.objects.insert(uri,observed["body"].clone());}
                            state.attempts.push(json!({"method":observed["method"],"uri":observed["uri"],"body":observed["body"],"signature_valid":true}));
                        }
                        Err(error)=>state.errors.push(error),
                    }
                    if denied {return Response::builder().status(403).body(common::full("<Error><Code>AccessDenied</Code><Message>fixture denied</Message></Error>")).unwrap();}
                    return Response::builder().header("etag","\"d41d8cd98f00b204e9800998ecf8427e\"").body(common::full("")).unwrap();
                }
                if gated && r.method()==hyper::Method::GET && r.uri().path().contains("/migration/upload/") {
                    reached.notify_one();released.notified().await;
                }
                Response::new(common::full(""))
            }}
        }).await;
        let startup_sentinel=if std::env::var_os("GOFREE_RECORD_GO_BINARY").is_some() && (matches!(action,"migration-pause"|"migration-upload"|"migration-test-imap") || label=="no-mailbox") {
            Some(c.query_one("INSERT INTO migration_jobs(user_id,source_type,target_mailbox_id,status) VALUES($1,'ics',$2,'paused') RETURNING id",&[&b.user,&b.mailbox]).await?.get::<_,i64>(0))
        }else{None};
        let go=common::go_oracle::start_named(&db,s3,None,"gofree-idlogin4").await?;
        if let Some(job)=startup_sentinel {
            let deadline=std::time::Instant::now()+std::time::Duration::from_secs(30);
            loop {
                let phase:String=c.query_one("SELECT status FROM migration_jobs WHERE id=$1 AND user_id=$2",&[&job,&b.user]).await?.get(0);
                if phase=="failed" {break;}
                if std::time::Instant::now()>=deadline {return Err("Go startup recovery sentinel did not settle".into());}
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            c.execute("DELETE FROM migration_jobs WHERE id=$1 AND user_id=$2",&[&job,&b.user]).await?;
        }

        let recording=go.is_some();
        if native_auth_denial {
            c.execute("INSERT INTO session_revocations(user_id,scope,reason,not_before,expires_at) VALUES($1,'all','idlogin4 fixture',now()+interval '1 hour',now()+interval '2 hours')",&[&a.user]).await?;
        }
        if action=="migration-start" {
            if label=="no-primary" {
                let error=c.execute("UPDATE mailboxes SET is_primary=false WHERE id=$1 AND user_id=$2",&[&a.mailbox,&a.user]).await.err().ok_or("primary invariant accepted an impossible no-primary fixture")?;
                if error.code().map(|v|v.code())!=Some("BZ014") {return Err(error.into());}
                if !c.query_one("SELECT is_primary FROM mailboxes WHERE id=$1 AND user_id=$2",&[&a.mailbox,&a.user]).await?.get::<_,bool>(0) {return Err("rejected no-primary mutation changed the mailbox".into());}
            }
            if matches!(label,"no-mailbox"|"revoked-no-mailbox") {c.execute("UPDATE mailboxes SET user_id=NULL,is_primary=false WHERE id=$1 AND user_id=$2",&[&a.mailbox,&a.user]).await?;}
        }

        if action.starts_with("migration-") && action!="migration-start" && matches!(label,"no-mailbox"|"revoked-no-mailbox") {
            c.execute("UPDATE mailboxes SET user_id=NULL,is_primary=false WHERE id=$1 AND user_id=$2",&[&a.mailbox,&a.user]).await?;
        }

        if action=="migration-delete" {
            if label=="success" && !recording {
                // The first immutable Go capture includes startup recovery of
                // its pre-seeded paused row. Run the existing native startup
                // seam too, rather than changing that capture or HTTP effects.
                let expected=ids.iter().find(|(_,name)|*name=="migration-paused").ok_or("paused startup fixture")?.0;
                let row=c.query_one("SELECT migration_recover_stuck()::text",&[]).await?;
                let recovered:Value=serde_json::from_str(&row.get::<_,String>(0))?;
                if recovered["ids"]!=json!([expected]) {return Err("startup recovery touched an unexpected fixture job".into());}
            } else if label!="success" {
                // New command cases start from post-startup active state.
                let id:i64=c.query_one("INSERT INTO migration_jobs(user_id,source_type,target_mailbox_id,status,created_at) VALUES($1,'ics',$2,'paused','2026-10-01T13:00:00Z') RETURNING id",&[&a.user,&a.mailbox]).await?.get(0);
                ids.push((id,"migration-paused"));
            }
        }
        if action=="migration-resume" {
            for (account,name) in [(&a,"migration-resume-a"),(&b,"migration-resume-b")] {
                if account.user==a.user && matches!(label,"cross-tenant"|"empty") {continue;}
                let job:i64=c.query_one("INSERT INTO migration_jobs(user_id,source_type,target_mailbox_id,status,created_at) VALUES($1,'ics',$2,'paused','2026-10-01T13:00:00Z') RETURNING id",&[&account.user,&account.mailbox]).await?.get(0);
                ids.push((job,name));
            }
        }
        if matches!(action,"migration-cancel"|"migration-pause") {
            let phase=if action=="migration-pause" {"fetching"}else{"paused"};
            let job:i64=c.query_one("INSERT INTO migration_jobs(user_id,source_type,target_mailbox_id,status,created_at) VALUES($1,'ics',$2,$3,'2026-10-01T13:00:00Z') RETURNING id",&[&b.user,&b.mailbox,&phase]).await?.get(0);
            ids.push((job,"migration-control-b"));
            if action=="migration-cancel" && label=="stale" && !recording {
                // This immutable Go capture includes startup recovery between
                // its B and A seed inserts. Reproduce only that fixture event.
                let row=c.query_one("SELECT migration_recover_stuck()::text",&[]).await?;
                let recovered:Value=serde_json::from_str(&row.get::<_,String>(0))?;
                if recovered["ids"]!=json!([job]) {return Err("control startup recovery touched an unexpected job".into());}
            }
            if matches!(label,"stale"|"db-error") {
                let job:i64=c.query_one("INSERT INTO migration_jobs(user_id,source_type,target_mailbox_id,status,created_at) VALUES($1,'ics',$2,$3,'2026-10-01T13:00:00Z') RETURNING id",&[&a.user,&a.mailbox,&phase]).await?.get(0);
                ids.push((job,"migration-control-a"));
            }
        }
        if action=="migration-start" && label=="cap" {
            let active:i64=c.query_one("INSERT INTO migration_jobs(user_id,source_type,target_mailbox_id,status,created_at) VALUES($1,'ics',$2,'pending','2026-10-01T13:00:00Z') RETURNING id",&[&a.user,&a.mailbox]).await?.get(0);
            ids.push((active,"migration-active"));
        }
        let mut inventory:Value=serde_json::from_str(include_str!("../../route-inventory.json"))?;
        for r in inventory["routes"].as_array_mut().ok_or("routes")? {
            if r["sources"].as_array().is_some_and(|xs|xs.iter().any(|x|x.as_str().is_some_and(|s|s.starts_with("mailserver/")))) && r["path"] .as_str().unwrap_or("").starts_with("/auth/me/") {
                r["state"]=json!(if recording{"OFF"}else{"ON"});
                r["upstream"]=json!(if recording{"go-mail"}else{"local-rust"});
                r["oracle_commands"]=json!([""]);
            }
        }
        let mut cut_task=None;
        let request_dsn=if let Some(cut)=commit_cut {
            let (dsn,task)=common::commit::commit_cut_proxy(db.app.as_deref().unwrap_or(&db.dsn),cut).await;
            cut_task=Some(task); dsn
        }else{db.app.as_deref().unwrap_or(&db.dsn).to_owned()};
        let dialer=if let Some(fake)=&imap {
            let local=fake.address;
            setjoin_gateway::migration_runner::Dialer::custom(
                |host|Box::pin(async move {host.parse::<std::net::IpAddr>().map(|ip|vec![ip]).map_err(|error|error.to_string())}),
                move |origin|Box::pin(async move {
                    if origin.port()!=local.port() {return Err("unexpected fixture origin".into());}
                    let stream=tokio::net::TcpStream::connect(local).await.map_err(|error|error.to_string())?;
                    Ok(Box::new(stream) as Box<dyn setjoin_gateway::migration_runner::imap::Io>)
                }),
            )
        }else{setjoin_gateway::migration_runner::Dialer::system()};
        let migration_runner=if matches!(action,"migration-start"|"migration-resume"|"migration-cancel"|"migration-pause"|"migration-upload"|"migration-test-imap") && !recording {
            Some(setjoin_gateway::migration::Runner {
                orchestrator:setjoin_gateway::migration_runner::Orchestrator::new(setjoin_gateway::migration_runner::Config {
                    db:setjoin_pg::workers::WorkerDatabase::new(&db.dsn)?.with_audit_keys("22".repeat(32),String::new()),
                    store:std::sync::Arc::new(setjoin_gateway::recovery_worker::S3Store::new(&format!("http://{s3}"),"mailblobs","test-access","test-secret")?),
                    root:"22".repeat(32),dialer,dispatcher:None,
                }),
                worker:common::patient_exec(&db.dsn,4)?.with_audit_keys("22".repeat(32),String::new()),
            })
        }else{None};
        let routes=RouteTable::proxy_all().with(Probe {inner:setjoin_gateway::identity_self_service::IdentitySelfServiceRoute {
            exec:common::patient_exec(&request_dsn,4)?.with_audit_keys("22".repeat(32),String::new()),
            worker:common::patient_exec(&db.dsn,4)?,
            keys:std::sync::Arc::new(common::recovery_keys()),
            issuer:"mailserver".into(),
            webhook_codec:setjoin_platform::webhook_secret::SecretCodec::new(b"blobs1-test-jwt-secret-for-recording",setjoin_config_secret::CryptoProfile::parse("")),
            migration_runner:migration_runner.clone(),
            // The recorded cases register example.net; the registration-time DNS check (#547)
            // sees a fixed public address instead of the host's resolver.
            webhook_resolver:std::sync::Arc::new(PublicFixture),
        },mutant,mutant_path:path.split('?').next().unwrap_or(&path).to_owned()});
        let gateway=Gateway::new(Config{upstream:go.as_ref().map(|g|format!("http://{}",g.address).parse()).transpose()?,trusted_proxies:TrustedProxies::parse("")?,upstream_header_timeout:setjoin_gateway::proxy::DEFAULT_HEADER_TIMEOUT,edge_limit:None},routes)?.with_inventory(&inventory.to_string())?;
        let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address=listener.local_addr()?;
        let server=tokio::spawn(gateway.serve(listener));
        let control_job=if gated {
            let token=access_token("migration-start",label,a.user);
            let response=common::send(address,Request::builder().method("POST").uri("/auth/me/migration").header("host","mail.test").header("origin","http://mail.test").header("authorization",format!("Bearer {token}")).body(common::full(r#"{"sourceType":"ics"}"#))?).await;
            if response.status()!=201 {return Err("control fixture migration not admitted".into());}
            let value:Value=serde_json::from_slice(&common::body_bytes(response).await)?;
            let job=value["id"].as_i64().ok_or("control fixture job id")?;
            ids.push((job,"migration-control-a"));
            tokio::time::timeout(std::time::Duration::from_secs(10),reached.notified()).await.map_err(|_|"migration never reached its object-store boundary")?;
            Some(job)
        }else{None};
        if privilege_fault { c.batch_execute(&format!("REVOKE {fault_privilege} ON {fault_table} FROM setjoin_app")).await?; }
        let mut prior_cert_created=if action=="cert-upload" && label=="replace" {Some(c.query_one("SELECT created_at FROM user_smime_certs WHERE user_id=$1 AND label='Desk <&>'",&[&a.user]).await?.get::<_,std::time::SystemTime>(0))}else{None};
        let mut prior_cert_envelope=None;
        if action=="cert-upload" && label=="repeat" {
            let first_start:std::time::SystemTime=c.query_one("SELECT clock_timestamp()",&[]).await?.get(0);
            let token=access_token(action,label,a.user);
            let response=common::send(address,Request::builder().method(method).uri(&path).header("host","mail.test").header("origin","http://mail.test").header("content-type",content_type).header("authorization",format!("Bearer {token}")).body(common::full(body.clone()))?).await;
            if response.status()!=200 {return Err("first repeated certificate upload failed".into());}
            let stored=cert_key_masks(&c,&a,first_start,label,None).await?;
            prior_cert_created=Some(stored.created);prior_cert_envelope=Some(stored.envelope);masks.extend(stored.masks);ids.push((stored.id,"cert-first"));
        }
        let mut first_hook_secret=None;
        if action=="hook-create" && label=="repeat" {
            let first_start:std::time::SystemTime=c.query_one("SELECT clock_timestamp()",&[]).await?.get(0);
            let token=access_token(action,label,a.user);
            let response=common::send(address,Request::builder().method(method).uri(&path).header("host","mail.test").header("origin","http://mail.test").header("content-type",content_type).header("x-request-id","gofree-idlogin4").header("authorization",format!("Bearer {token}")).body(common::full(body.clone()))?).await;
            if response.status()!=201 {return Err("first repeated webhook creation failed".into());}
            let raw=String::from_utf8(common::body_bytes(response).await.to_vec())?;
            let value:Value=serde_json::from_str(&raw)?;
            first_hook_secret=Some(value["secret"].as_str().ok_or("missing first webhook secret")?.to_owned());
            let (created,validated)=hook_masks(&c,&a,&raw,first_start).await?;
            ids.push((created,"hook-first"));masks.extend(validated);
        }
        let mut first_hash=None;
        if action=="app-create" && label=="repeat" {
            let first_start:std::time::SystemTime=c.query_one("SELECT clock_timestamp()",&[]).await?.get(0);
            let token=access_token(action,label,a.user);
            let response=common::send(address,Request::builder().method(method).uri(&path).header("host","mail.test").header("origin","http://mail.test").header("content-type",content_type).header("x-request-id","gofree-idlogin4").header("authorization",format!("Bearer {token}")).body(common::full(body.clone()))?).await;
            let status=response.status().as_u16();
            let raw=String::from_utf8(common::body_bytes(response).await.to_vec())?;
            if status!=201 { return Err(format!("first repeated creation: {status} {raw}").into()); }
            let value:Value=serde_json::from_str(&raw)?;
            let secret=value["token"].as_str().ok_or("missing first token")?;
            if secret.len()!=72 || !secret.starts_with("mail-ap-") || !secret.as_bytes()[8..].iter().all(|b|b.is_ascii_digit() || (b'a'..=b'f').contains(b)) { return Err("invalid first token".into()); }
            let hash=format!("{:x}",Sha256::digest(secret.as_bytes()));
            let row=c.query_one("SELECT id,created_at >= $2::timestamptz AND created_at<=clock_timestamp() FROM app_passwords WHERE user_id=$1 AND token_hash=$3",&[&a.user,&first_start,&hash]).await?;
            if !row.get::<_,bool>(1) {return Err("first creation timestamp outside request".into());}
            ids.push((row.get::<_,i64>(0),"app-first")); first_hash=Some(hash);
        }
        if matches!(action,"cert-delete"|"cert-default"|"recipient-delete") && label=="repeat" {
            let token=access_token(action,label,a.user);
            let response=common::send(address,Request::builder().method(method).uri(&path).header("host","mail.test").header("origin","http://mail.test").header("authorization",format!("Bearer {token}")).body(common::full(""))?).await;
            if response.status()!=200 {return Err("first repeated owned certificate delete failed".into());}
            let _=common::body_bytes(response).await;
        }
        if action=="hook-delete" && label=="repeat" {
            let token=access_token(action,label,a.user);
            let response=common::send(address,Request::builder().method(method).uri(&path).header("host","mail.test").header("origin","http://mail.test").header("authorization",format!("Bearer {token}")).body(common::full(""))?).await;
            if response.status()!=204 || !common::body_bytes(response).await.is_empty() {return Err("first repeated webhook delete failed".into());}
        }
        if action=="app-revoke" && label=="repeat" {
            let token=access_token(action,label,a.user);
            let response=common::send(address,Request::builder().method(method).uri(&path).header("host","mail.test").header("origin","http://mail.test").header("authorization",format!("Bearer {token}")).body(common::full(""))?).await;
            if response.status()!=204 {return Err("first revoke did not succeed".into());}
            if !common::body_bytes(response).await.is_empty() {return Err("revoke returned a body".into());}
        }
        if action=="receipt" && label=="repeat" {
            let first_start:std::time::SystemTime=c.query_one("SELECT clock_timestamp()",&[]).await?.get(0);
            let token=access_token(action,label,a.user);
            let response=common::send(address,Request::builder().method(method).uri(&path).header("host","mail.test").header("origin","http://mail.test").header("content-type",content_type).header("x-request-id","gofree-idlogin4").header("authorization",format!("Bearer {token}")).body(common::full(body.clone()))?).await;
            if response.status()!=200 {return Err("first repeated MDN failed".into());}
            let raw=String::from_utf8(common::body_bytes(response).await.to_vec())?;
            masks.extend(mdn_masks(&c,&a,message_ids[0],first_start,&raw).await?);
        }
        if action=="recipient-upload" && label=="repeat" {
            let first_start:std::time::SystemTime=c.query_one("SELECT clock_timestamp()",&[]).await?.get(0);
            let token=access_token(action,label,a.user);
            let response=common::send(address,Request::builder().method(method).uri(&path).header("host","mail.test").header("origin","http://mail.test").header("content-type",content_type).header("authorization",format!("Bearer {token}")).body(common::full(body.clone()))?).await;
            if response.status()!=200 {return Err("first recipient import failed".into());}
            let _=common::body_bytes(response).await;
            ids.push((validate_recipient(&c,&a,first_start,label,None).await?,"recipient-first"));
        }
        if uploading && label=="repeat" {
            let token=access_token(action,label,a.user);
            let response=common::send(address,Request::builder().method("POST").uri(&path).header("host","mail.test").header("origin","http://mail.test").header("content-type",content_type).header("authorization",format!("Bearer {token}")).body(common::full(body.clone()))?).await;
            if response.status()!=200 {return Err("first file upload failed".into());}
            let _=common::body_bytes(response).await;
            if upload_store.lock().unwrap().objects.len()!=2 {return Err("first upload did not persist two objects".into());}
        }
        if matches!(action,"migration-cancel"|"migration-pause") && label=="repeat" {
            let token=access_token(action,label,a.user);
            let response=common::send(address,Request::builder().method("POST").uri(&path).header("host","mail.test").header("origin","http://mail.test").header("authorization",format!("Bearer {token}")).body(common::full(""))?).await;
            if response.status().as_u16()!=if action=="migration-pause" {202}else{204} {return Err("first migration control was not admitted".into());}
            let _=common::body_bytes(response).await;
            released.notify_one();
            settle_job(&c,control_job.ok_or("live repeat job")?,a.user,migration_runner.as_ref()).await?;
        }
        if action=="migration-resume" && label=="repeat" {
            let token=access_token(action,label,a.user);
            let response=common::send(address,Request::builder().method("POST").uri(&path).header("host","mail.test").header("origin","http://mail.test").header("authorization",format!("Bearer {token}")).body(common::full(""))?).await;
            if response.status()!=202 {return Err("first resume was not admitted".into());}
            let _=common::body_bytes(response).await;
            let job=ids.iter().find(|(_,name)|*name=="migration-resume-a").ok_or("paused repeat fixture")?.0;
            settle_job(&c,job,a.user,migration_runner.as_ref()).await?;
        }
        if action=="migration-delete" && label=="repeat" {
            let token=access_token(action,label,a.user);
            let response=common::send(address,Request::builder().method(method).uri(&path).header("host","mail.test").header("origin","http://mail.test").header("authorization",format!("Bearer {token}")).body(common::full(""))?).await;
            if response.status()!=200 || common::body_bytes(response).await.as_ref()!=b"{\"deleted\":3}\n" {return Err("first history deletion did not remove exactly three owned terminal jobs".into());}
        }
        if action=="migration-start" && label=="repeat" {
            let first_start:std::time::SystemTime=c.query_one("SELECT clock_timestamp()",&[]).await?.get(0);
            let token=access_token(action,label,a.user);
            let response=common::send(address,Request::builder().method(method).uri(&path).header("host","mail.test").header("origin","http://mail.test").header("content-type",content_type).header("authorization",format!("Bearer {token}")).body(common::full(body.clone()))?).await;
            if response.status()!=201 {return Err("first repeated migration admission failed".into());}
            let value:Value=serde_json::from_slice(&common::body_bytes(response).await)?;
            let job=value["id"].as_i64().ok_or("first job id")?;
            let deadline=std::time::Instant::now()+std::time::Duration::from_secs(30);
            loop {
                let row=c.query_one("SELECT status,target_mailbox_id,source_type,created_at >= $3::timestamptz AND created_at <= clock_timestamp() FROM migration_jobs WHERE id=$1 AND user_id=$2",&[&job,&a.user,&first_start]).await?;
                if row.get::<_,i64>(1)!=a.mailbox || row.get::<_,String>(2)!="ics" || !row.get::<_,bool>(3) {return Err("first migration lost owner/source/clock".into());}
                if matches!(row.get::<_,String>(0).as_str(),"completed"|"failed"|"cancelled") {break;}
                if std::time::Instant::now()>=deadline {return Err("first migration did not settle before repeat".into());}
                tokio::time::sleep(std::time::Duration::from_millis(25)).await;
            }
            if let Some(runner)=&migration_runner {
                while runner.orchestrator.is_running(job) {
                    if std::time::Instant::now()>=deadline {return Err("first migration task retained".into());}
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            }
            ids.push((job,"migration-first"));
        }
        let recipient_prior=if action=="recipient-upload" {c.query_opt("SELECT first_seen FROM recipient_smime_certs WHERE owner_user_id=$1",&[&a.user]).await?.map(|r|r.get::<_,std::time::SystemTime>(0))}else{None};
        let mut before=snapshot(&c,&a,&b,action).await?;
        if uploading {before["storage"]=upload_store.lock().unwrap().snapshot()?;}
        if imap.is_some() {before["imap_commands"]=json!([]);}
        let org_before=if action=="org" {Some(c.query_one("SELECT jsonb_agg(jsonb_build_object('id',id,'display_name',display_name,'first_name',first_name,'last_name',last_name,'job_title',job_title,'manager_id',manager_id,'department_id',department_id,'avatar_sha256',avatar_sha256) ORDER BY id)::text FROM users WHERE id=ANY($1)",&[&vec![a.user,b.user]]).await?.get::<_,String>(0))}else{None};
        let dlp_before=if action=="dlp" {Some(c.query_one("SELECT COALESCE(jsonb_agg(to_jsonb(v) ORDER BY id),'[]'::jsonb)::text FROM dlp_violations v WHERE mailbox_id=ANY($1)",&[&vec![a.mailbox,b.mailbox]]).await?.get::<_,String>(0))}else{None};
        let started:std::time::SystemTime=c.query_one("SELECT clock_timestamp()",&[]).await?.get(0);
        let audit_start:i64=c.query_one("SELECT COALESCE(max(id),0) FROM admin_audit_log",&[]).await?.get(0);
        let mut config=db.listen("config_changed").await?;
        let mut state=db.listen("state_change").await?;
        let mut critical=db.listen("critical_events").await?;
        let token=access_token(action,label,a.user);
        let request_body=body.clone();
        let mut wire_body=body.into_bytes();
        if matches!(action,"cert-upload"|"recipient-upload") && label=="invalid-utf8" {
            let at=wire_body.windows(4).position(|v|v==b"Desk").ok_or("UTF8 label marker")?;
            wire_body[at]=0xff;
        }
        let response=common::send(address,Request::builder().method(method).uri(&path).header("host","mail.test").header("origin","http://mail.test").header("content-type",content_type).header("x-request-id","gofree-idlogin4").header("authorization",format!("Bearer {token}")).body(common::full(wire_body.clone()))?).await;
        let status=response.status().as_u16();
        let mut headers=serde_json::Map::new();
        for key in response.headers().keys().filter(|k| k.as_str()!="date") {
            headers.insert(key.to_string(),json!(response.headers().get_all(key).iter().map(|v|v.to_str().unwrap()).collect::<Vec<_>>()));
        }
        let mut raw=String::from_utf8(common::body_bytes(response).await.to_vec())?;
        if let Some(length)=headers.get("content-length").and_then(|x|x[0].as_str()) {
            if length.parse::<usize>()? != raw.len() { return Err("incorrect HTTP Content-Length".into()); }
        }
        if let Some(job)=control_job {
            released.notify_one();
            settle_job(&c,job,a.user,migration_runner.as_ref()).await?;
        }
        if action=="migration-status" && (raw.contains("source_config_enc") || raw.contains("IDLOGIN4-hidden")) {return Err("migration status leaked source configuration".into());}
        if action=="migration-resume" && (status==202 || mutant) {
            let job=ids.iter().find(|(_,name)|*name=="migration-resume-a").ok_or("owned paused fixture")?.0;
            settle_job(&c,job,a.user,migration_runner.as_ref()).await?;
        }
        if action=="migration-start" && (status==201 || mutant) {
            let response:Value=serde_json::from_str(&raw)?;
            let job=response["id"].as_i64().ok_or("started migration omitted id")?;
            if response["status"]!="pending" {return Err("start did not project pending admission".into());}
            let deadline=std::time::Instant::now()+std::time::Duration::from_secs(30);
            loop {
                let row=c.query_one("SELECT status,target_mailbox_id,source_type,conflict_strategy,created_at >= $3::timestamptz AND created_at <= clock_timestamp() FROM migration_jobs WHERE id=$1 AND user_id=$2",&[&job,&a.user,&started]).await?;
                if row.get::<_,i64>(1)!=a.mailbox || row.get::<_,String>(2)!=match label {"imap"|"folded-imap"=>"imap","ews"=>"ews","unknown-source"=>"unknown",_=>"ics"} || row.get::<_,String>(3)!="skip" || !row.get::<_,bool>(4) {return Err("started job lost actor mailbox/source/strategy/clock".into());}
                if let Some(bytes)=c.query_one("SELECT source_config_enc FROM migration_jobs WHERE id=$1 AND user_id=$2",&[&job,&a.user]).await?.get::<_,Option<Vec<u8>>>(0) {
                    let codec=setjoin_mailboxes::migration::derive_key(&"22".repeat(32),"migration").ok_or("migration fixture root")?;
                    let opened=setjoin_mailboxes::migration::open(&bytes,&codec).ok_or("invalid migration envelope")?;
                    let config:Value=serde_json::from_slice(&opened)?;
                    let source=if label=="ews" {"ews"}else{"imap"};
                    if config["self_service"]!=true || config["source_type"]!=source || config["use_global_auth"]!=false {return Err("migration config lost verified self-service provenance".into());}
                    let inner=&config[source];
                    if source=="imap" {
                        if inner["host"]!="127.0.0.1" || inner["tls_mode"]!="none" || inner["credentials"]["username"]!="owned-user" || inner["credentials"]["password"]!="owned-password" {return Err("IMAP sealed config differs from submitted credentials".into());}
                    }else if inner["serverURL"]!="https://127.0.0.1/EWS" || inner["username"]!="owned-user" || inner["password"]!="owned-password" {return Err("EWS sealed config differs from submitted credentials".into());}
                    let text=format!("\\x{}",bytes.iter().map(|b|format!("{b:02x}")).collect::<String>());
                    masks.push((json!(text).to_string(),json!("<validated-migration-envelope>").to_string()));
                }
                let phase:String=row.get(0);
                if matches!(phase.as_str(),"completed"|"failed"|"cancelled") {break;}
                if std::time::Instant::now()>=deadline {return Err(format!("started migration never settled: {phase}").into());}
                tokio::time::sleep(std::time::Duration::from_millis(25)).await;
            }
            if let Some(runner)=&migration_runner {
                while runner.orchestrator.is_running(job) {
                    if std::time::Instant::now()>=deadline {return Err("settled migration retained an active task".into());}
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            }
            ids.push((job,"migration-created"));
        }
        let mut after=snapshot(&c,&a,&b,action).await?;
        if let Some(fake)=&imap {
            let commands:Vec<_>=fake.state.commands.lock().unwrap().iter().filter_map(|command|command.split_whitespace().next().map(str::to_uppercase)).filter(|command|matches!(command.as_str(),"LOGIN"|"LIST"|"LOGOUT")).collect();
            if raw.contains("plaintext IMAP (tls_mode none) is not allowed") {
                // Owner-approved security fix (#547): refused before any dial.
                if !commands.is_empty() {return Err("a refused plaintext IMAP request reached the source".into());}
            } else if status==200 || mutant {
                let expected=!tls_variant && matches!(label,"success"|"cross-tenant"|"no-mailbox"|"folded-body");
                if serde_json::from_str::<Value>(&raw)?["success"]!=expected {return Err(format!("IMAP success result differs for {label}: {raw}").into());}
                let expected_commands=if expected {vec!["LOGIN","LIST","LOGOUT"]}else if label=="bad-password" {vec!["LOGIN"]}else{vec![]};
                if commands!=expected_commands {return Err("IMAP failure reached an unexpected protocol boundary".into());}
            }
            if status==200 && serde_json::from_str::<Value>(&raw)?["success"]==true && commands!=["LOGIN","LIST","LOGOUT"] {return Err("successful connection test did not authenticate/list/logout".into());}
            after["imap_commands"]=json!(commands);
        }
        if uploading {
            let stored=upload_store.lock().unwrap();
            after["storage"]=stored.snapshot()?;
            if status==200 || mutant {
                let files:Vec<_>=[("ics",UPLOAD_ICS),("vcf",UPLOAD_VCF)].into_iter().filter(|(name,_)|label!="empty-file" && !(label=="ics-only" && *name=="vcf") && !(label=="vcf-only" && *name=="ics")).collect();
                let mut expected=std::collections::BTreeMap::new();
                let attempts=if label=="store-error" {1}else{files.len()*if label=="repeat" {2}else{1}};
                if stored.attempts.len()!=attempts {return Err("wrong number of signed upload attempts".into());}
                for (name,data) in files {
                    if label=="store-error" || label=="store-vcf-error" && name=="vcf" {continue;}
                    expected.insert(format!("/mailblobs/migration/upload/{}/{name}",ids[0].0),json!({"length":data.len(),"sha256":format!("{:x}",Sha256::digest(data.as_bytes()))}));
                }
                if stored.objects!=expected {return Err("uploaded object owner/key/bytes differ".into());}
            }else if !stored.objects.is_empty() || !stored.attempts.is_empty() {return Err("rejected upload reached object storage".into());}
        }
        if action=="recipient-upload" && (status==200 || mutant) {
            ids.push((validate_recipient(&c,&a,started,label,recipient_prior).await?,"recipient-created"));
        }
        if action=="cert-upload" && (status==200 || mutant) {
            let stored=cert_key_masks(&c,&a,started,label,prior_cert_created).await?;
            if prior_cert_envelope.as_deref()==Some(stored.envelope.as_str()) {return Err("re-upload did not refresh the PGP envelope".into());}
            ids.push((stored.id,"cert-created"));masks.extend(stored.masks);
        }
        if action=="hook-create" && (status==201 || (mutant && label=="success")) {
            if let Some(first)=&first_hook_secret {
                let value:Value=serde_json::from_str(&raw)?;
                if value["secret"].as_str()==Some(first.as_str()) {return Err("repeated webhook creation reused a signing secret".into());}
            }
            let (created, validated)=hook_masks(&c,&a,&raw,started).await?;
            ids.push((created,"hook-created"));masks.extend(validated);
        }
        if action=="cert-delete" && commit_cut.is_none() {
            let actual:i64=c.query_one("SELECT count(*)::bigint FROM rust_operation_receipts WHERE family='F21' AND command='self-service.cert.delete' AND operation_id::text<>ALL($1::text[])",&[&prior_receipts]).await?.get(0);
            let expected=if recording {0}else if label=="repeat" || status==200 || mutant {1}else{0};
            if actual!=expected {return Err("owned certificate deletion receipt count mismatch".into());}
        }
        if action=="migration-start" {
            let actual:i64=c.query_one("SELECT count(*)::bigint FROM rust_operation_receipts WHERE family='F21' AND command='self-service.migration.start' AND operation_id::text<>ALL($1::text[])",&[&prior_receipts]).await?.get(0);
            let expected=if recording || (status!=201 && !mutant) {0}else if label=="repeat" {2}else{1};
            if actual!=expected {return Err("migration admission receipt count mismatch".into());}
        }
        if action=="migration-delete" {
            let actual:i64=c.query_one("SELECT count(*)::bigint FROM rust_operation_receipts WHERE family='F21' AND command='self-service.migration.delete' AND operation_id::text<>ALL($1::text[])",&[&prior_receipts]).await?.get(0);
            let expected=if recording || (status!=200 && !mutant) {0}else if label=="repeat" {2}else{1};
            if actual!=expected {return Err("migration history receipt count mismatch".into());}
        }
        if action=="recipient-delete" {
            let actual:i64=c.query_one("SELECT count(*)::bigint FROM rust_operation_receipts WHERE family='F21' AND command='self-service.recipient.delete' AND operation_id::text<>ALL($1::text[])",&[&prior_receipts]).await?.get(0);
            let expected=if recording {0}else if label=="repeat" || status==200 || mutant {1}else{0};
            if actual!=expected {return Err("recipient deletion receipt count mismatch".into());}
        }
        if action=="recipient-upload" {
            let actual:i64=c.query_one("SELECT count(*)::bigint FROM rust_operation_receipts WHERE family='F21' AND command='self-service.recipient.store' AND operation_id::text<>ALL($1::text[])",&[&prior_receipts]).await?.get(0);
            let expected=if recording || (status!=200 && !mutant) {0}else if label=="repeat" {2}else{1};
            if actual!=expected {return Err("recipient import receipt count mismatch".into());}
        }
        if action=="cert-default" {
            let actual:i64=c.query_one("SELECT count(*)::bigint FROM rust_operation_receipts WHERE family='F21' AND command='self-service.cert.default' AND operation_id::text<>ALL($1::text[])",&[&prior_receipts]).await?.get(0);
            let expected=if recording || (status!=200 && !mutant) {0}else if label=="repeat" {2}else{1};
            if actual!=expected {return Err("default certificate receipt count mismatch".into());}
        }
        if action=="cert-upload" {
            let actual:i64=c.query_one("SELECT count(*)::bigint FROM rust_operation_receipts WHERE family='F21' AND command='self-service.cert.store' AND operation_id::text<>ALL($1::text[])",&[&prior_receipts]).await?.get(0);
            let expected=if recording || (status!=200 && !mutant) {0}else if label=="repeat" {2}else{1};
            if actual!=expected {return Err("certificate acknowledgement receipt count mismatch".into());}
        }
        if action=="hook-create" {
            let actual:i64=c.query_one("SELECT count(*)::bigint FROM rust_operation_receipts WHERE family='F21' AND command='self-service.webhook.create' AND operation_id::text<>ALL($1::text[])",&[&prior_receipts]).await?.get(0);
            let expected=if recording || (status!=201 && !(mutant && label=="success")) {0}else if label=="repeat" {2}else{1};
            if actual!=expected {return Err("webhook acknowledgement receipt count mismatch".into());}
        }
        if action=="receipt" && matches!(label,"send"|"policy-always") {
            if status!=200 {return Err(format!("consented MDN failed: {status} {raw}").into());}
            masks.extend(mdn_masks(&c,&a,message_ids[0],started,&raw).await?);
        }
        if action=="receipt" && label=="repeat" && (status!=200 || serde_json::from_str::<Value>(&raw)?["status"]!="already_sent") {return Err("MDN repeat was not deduplicated".into());}
        if action=="receipt" {
            let actual:i64=c.query_one("SELECT count(*)::bigint FROM rust_operation_receipts WHERE family='F21' AND command='self-service.read-receipt' AND operation_id::text<>ALL($1::text[])",&[&prior_receipts]).await?.get(0);
            let expected=if recording || (status!=200 && !mutant) {0}else if label=="repeat" {2}else{1};
            if actual!=expected {return Err("MDN acknowledgement receipt count mismatch".into());}
        }

        if let Some(before)=org_before {
            let after:String=c.query_one("SELECT jsonb_agg(jsonb_build_object('id',id,'display_name',display_name,'first_name',first_name,'last_name',last_name,'job_title',job_title,'manager_id',manager_id,'department_id',department_id,'avatar_sha256',avatar_sha256) ORDER BY id)::text FROM users WHERE id=ANY($1)",&[&vec![a.user,b.user]]).await?.get(0);
            if before!=after {return Err("org-chart query changed an owned profile".into());}
        }
        if let Some(before)=dlp_before {
            let after:String=c.query_one("SELECT COALESCE(jsonb_agg(to_jsonb(v) ORDER BY id),'[]'::jsonb)::text FROM dlp_violations v WHERE mailbox_id=ANY($1)",&[&vec![a.mailbox,b.mailbox]]).await?.get(0);
            if before!=after {return Err("compose advisory persisted a DLP violation".into());}
        }
        if action=="tips" && raw.contains("IDLOGIN4 private") {return Err("OOO advisory leaked private reply content".into());}
        if action=="app-create" && (status==201 || mutant) {
            let value:Value=serde_json::from_str(&raw)?;
            let secret=value["token"].as_str().ok_or("missing one-time token")?;
            if secret.len()!=72 || !secret.starts_with("mail-ap-") || !secret.as_bytes()[8..].iter().all(|b|b.is_ascii_digit() || (b'a'..=b'f').contains(b)) { return Err("invalid app-password token format".into()); }
            let hash=Sha256::digest(secret.as_bytes()).iter().map(|b|format!("{b:02x}")).collect::<String>();
            let mut count=0;
            for row in after["app_passwords"].as_array_mut().ok_or("app rows")? {
                if row["token_hash"].as_str()==Some(hash.as_str()) {
                    if row["user_id"].as_i64()!=Some(a.user) { return Err("app password persisted under caller-owned identity field".into()); }
                    ids.push((row["id"].as_i64().ok_or("created app id")?,"app-created"));
                    row["token_hash"]=json!("<returned-token-hash>"); count+=1;
                }
            }
            if count!=1 { return Err("returned credential does not match exactly one owned persisted SHA-256 hash".into()); }
            let timely:bool=c.query_one("SELECT created_at >= $2::timestamptz AND created_at<=clock_timestamp() FROM app_passwords WHERE user_id=$1 AND token_hash=$3",&[&a.user,&started,&hash]).await?.get(0);
            if !timely { return Err("app password creation time is outside the request".into()); }
            raw=raw.replace(secret,"<app-token>");
        }
        if let Some(hash)=first_hash {
            for snapshot in [&mut before,&mut after] {
                for row in snapshot["app_passwords"].as_array_mut().ok_or("app rows")? {
                    if row["token_hash"].as_str()==Some(hash.as_str()) { row["token_hash"]=json!("<first-token-hash>"); }
                }
            }
        }
        if action=="app-create" && commit_cut.is_none() && !mutant {
            let actual:i64=c.query_one("SELECT count(*)::bigint FROM rust_operation_receipts WHERE family='F21' AND command='self-service.app.create' AND operation_id::text<>ALL($1::text[])",&[&prior_receipts]).await?.get(0);
            let expected=if recording || status!=201 {0}else if label=="repeat"{2}else{1};
            if actual!=expected { return Err("publishing receipt did not match the acknowledged transaction count".into()); }
        }
        let audit:Vec<Value>=c.query("SELECT to_jsonb(a)::text FROM admin_audit_log a WHERE id>$1 ORDER BY id",&[&audit_start]).await?.iter().map(|r|serde_json::from_str(&r.get::<_,String>(0))).collect::<Result<_,_>>()?;
        let notify=json!({"config_changed":config.drain(&c).await?,"state_change":state.drain(&c).await?,"critical_events":critical.drain(&c).await?});
        let observation={
            let norm=|text:&str| {let mut text=text.to_owned();for (from,to) in &masks {text=text.replace(from,to);}normalize(&text,&a,&b,&ids)};
            let request_body=if uploading && label=="oversize" {json!({"bytes":wire_body.len(),"sha256":format!("{:x}",Sha256::digest(&wire_body))})}else{json!(norm(&request_body))};
            let mut request=json!({"method":method,"path":norm(&path),"body":request_body});
            if label=="repeat" { request["repeat"]=json!(true); }
            if action=="migration-start" && label=="no-primary" {request["fixture_constraint"]=json!("no-primary mutation refused BZ014; original primary retained");}
            if matches!(action,"cert-upload"|"recipient-upload") { request["content_type"]=json!(content_type); }
            if matches!(action,"cert-upload"|"recipient-upload") && matches!(label,"oversize"|"invalid-utf8") {request["body"]=json!({"bytes":wire_body.len(),"sha256":format!("{:x}",Sha256::digest(&wire_body))});}
            json!({"request":request,"audit":audit,"notify":notify,"response":{"status":status,"headers":headers,"body":norm(&raw)},"effects":[{"before":serde_json::from_str::<Value>(&norm(&before.to_string()))?,"after":serde_json::from_str::<Value>(&norm(&after.to_string()))?}]})
        };
        if !recording {
            let metrics=common::send(address,Request::get("/_gateway/metrics").body(common::full(""))?).await;
            if !String::from_utf8(common::body_bytes(metrics).await.to_vec())?.lines().any(|l|l=="setjoin_gateway_proxied_to_go_by_family_total{family=\"F21\"} 0") { server.abort(); return Err(format!("native request forwarded to Go: {status} {raw}").into()); }
        }
        server.abort(); let _=server.await;
        if native_auth_denial {
            if status!=401 || before!=after || !audit.is_empty() || notify.as_object().is_none_or(|m|m.values().any(|v|v.as_array().is_none_or(|a|!a.is_empty()))) {return Err("revoked mailbox-less identity reached user authority or published effects".into());}
            eprintln!("NATIVE-AUTH: revoked mailbox-less member denied");return Ok(());
        }
        let dir=PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/conformance/identity-self-service/goldens");
        std::fs::create_dir_all(&dir)?;
        let file=dir.join(format!("{action}-{file_label}.json"));
        if let Some(cut)=commit_cut {
            let observed=tokio::time::timeout(std::time::Duration::from_secs(30),cut_task.take().ok_or("wire proxy")?).await???;
            if observed!=cut {return Err("wrong COMMIT boundary cut".into());}
            if status!=503 || raw.contains("mail-ap-") || raw.contains("\"token\"") {return Err(format!("uncertain commit released success/credentials: {status} {raw}").into());}
            let operation=headers.get("x-operation-id").and_then(|v|v[0].as_str()).ok_or("unknown outcome omitted operation ID")?;
            if operation.len()!=32 || !operation.bytes().all(|b|b.is_ascii_hexdigit()) {return Err("invalid operation ID".into());}
            let committed=cut==common::commit::CommitCut::AfterCommit;
            let receipt_sql="SELECT EXISTS(SELECT 1 FROM rust_operation_receipts WHERE operation_id=substr(encode(digest($1::text || ':' || $2::text,'sha256'),'hex'),1,32)::uuid AND family='F21' AND command=$3)";
            let command=if action=="cert-delete" {"self-service.cert.delete"}else{"self-service.app.create"};
            let actor=a.user.to_string(); let foreign=b.user.to_string();
            let owned:bool=c.query_one(receipt_sql,&[&operation,&actor,&command]).await?.get(0);
            let other:bool=c.query_one(receipt_sql,&[&operation,&foreign,&command]).await?.get(0);
            if owned!=committed || other {return Err("commit receipt is absent, non-atomic or visible under another actor".into());}
            let expected:Value=serde_json::from_slice(&std::fs::read(dir.join(format!("{action}-success.json")))?)?;
            let mut cut_after=after.clone();
            if committed && action=="app-create" {
                let mut found=0;
                for row in cut_after["app_passwords"].as_array_mut().ok_or("app rows")? {
                    if row["name"]=="Desktop <&>" {
                        if row["user_id"].as_i64()!=Some(a.user) {return Err("cut committed foreign app owner".into());}
                        let hash=row["token_hash"].as_str().ok_or("cut hash")?;
                        if hash.len()!=64 || !hash.bytes().all(|b|b.is_ascii_hexdigit()) {return Err("cut stored invalid digest".into());}
                        ids.push((row["id"].as_i64().ok_or("cut app id")?,"app-created"));
                        row["token_hash"]=json!("<returned-token-hash>"); found+=1;
                    }
                }
                if found!=1 {return Err("committed cut did not create exactly one app password".into());}
            }
            let normalized:Value=serde_json::from_str(&normalize(&cut_after.to_string(),&a,&b,&ids))?;
            golden::compare(&expected["observation"]["effects"][0][if committed{"after"}else{"before"}],&normalized)?;
            golden::compare(&expected["observation"]["audit"],&observation["audit"])?;
            golden::compare(&expected["observation"]["notify"],&observation["notify"])?;
            eprintln!("COMMIT-CUT: {action} :: {label}");
            return Ok(());
        }

        if recording {
            if mutant { return Err("never record a planted mutant".into()); }
            let wanted=match action {"migration-test-imap"=>if matches!(label,"invalid-input"|"private-policy"|"private-cidr") {400}else{200},"migration-upload"=>match label {"cross-tenant"|"db-error"|"missing"=>404,"invalid-input"|"overflow"|"bad-form"|"no-file"|"oversize"=>400,_=>200},"migration-pause"=>match label {"cross-tenant"|"empty"|"db-error"|"repeat"|"no-mailbox"=>404,"stale"=>500,_=>202},"migration-cancel"=>match label {"cross-tenant"|"empty"|"db-error"|"repeat"|"no-mailbox"=>404,"stale"=>500,_=>204},"migration-resume"=>if matches!(label,"cross-tenant"|"empty"|"db-error"|"repeat") {404}else{202},"migration-start"=>match label {"cross-tenant"=>403,"invalid-input"|"m365"|"no-host"|"ews-no-config"|"ews-null-config"|"ews-bad-config"|"ews-missing-creds"|"ews-impersonation"|"private-policy"|"no-mailbox"=>400,"cap"=>409,"invalid-strategy"|"db-error"=>500,_=>201},"migration-delete" if label=="db-error"=>500,"recipient-delete" if matches!(label,"invalid-input"|"overflow")=>400,"recipient-delete" if matches!(label,"cross-tenant"|"missing"|"repeat")=>404,"recipient-delete" if label=="db-error"=>500,"recipient-upload" if matches!(label,"invalid-input"|"missing-cert"|"invalid-cert"|"expired"|"no-email"|"sign-only"|"ec"|"oversize")=>400,"recipient-upload" if matches!(label,"db-error"|"invalid-utf8")=>500,"cert-default" if matches!(label,"invalid-input"|"overflow")=>400,"cert-default" if matches!(label,"cross-tenant"|"missing")=>404,"cert-default" if matches!(label,"db-error"|"update-error")=>500,"cert-delete" if matches!(label,"invalid-input"|"overflow")=>400,"cert-delete" if matches!(label,"cross-tenant"|"repeat"|"db-error"|"promote-error"|"missing")=>500,"cert-upload" if matches!(label,"invalid-input"|"missing-cert"|"missing-key"|"invalid-cert"|"invalid-key"|"oversize"|"bad-query")=>400,"cert-upload" if matches!(label,"db-error"|"invalid-utf8")=>500,"hook-delete"=>if label=="success" {204}else{404},"hook-create"=>match label {"invalid-input"|"null-body"|"null-events"|"bad-scope"|"unknown-event"|"duplicate-event"|"unsafe-url"=>400,"cap"=>409,"count-error"=>503,"db-error"=>500,_=>201},"app-create"=>match label {"invalid-input"=>400,"cap"=>409,"db-error"=>500,_=>201},"app-revoke"=>match label {"invalid-input"=>400,"cross-tenant"|"repeat"=>404,"db-error"=>500,_=>204},"dlp" if label=="invalid-input"=>400,"org" if matches!(label,"invalid-input"|"newline-id")=>400,"org" if matches!(label,"cross-tenant"|"no-permission"|"live-deny")=>403,"receipt" if matches!(label,"invalid-input"|"invalid-body"|"null-body")=>400,"receipt" if matches!(label,"cross-tenant"|"overflow")=>500,_=>200};
            if status != wanted { return Err(format!("frozen Go success: {status} {raw}").into()); }
            use std::io::Write;
            let doc=json!({"format":1,"route":format!("{method} {pattern}"),"case":file_label,"go_source":std::env::var("GOFREE_GO_SOURCE")?,"observation":observation});
            let mut output=std::fs::OpenOptions::new().write(true).create_new(true).open(&file)?;
            writeln!(output,"{}",serde_json::to_string_pretty(&doc)?)?;
            if matches!(action,"app-create"|"app-revoke"|"receipt"|"hook-create"|"hook-delete"|"cert-upload"|"cert-delete"|"cert-default"|"recipient-upload"|"recipient-delete"|"migration-delete"|"migration-start"|"migration-resume"|"migration-cancel"|"migration-pause"|"migration-upload") {
                let companion=json!({"format":1,"route":doc["route"],"case":format!("{label}-row-effects"),"go_source":doc["go_source"],"effects":doc["observation"]["effects"]});
                let rows=file.with_file_name(format!("{action}-{label}-rows.json"));
                let mut output=std::fs::OpenOptions::new().write(true).create_new(true).open(rows)?;
                writeln!(output,"{}",serde_json::to_string_pretty(&companion)?)?;
            }
        }else{
            let expected:Value=serde_json::from_slice(&std::fs::read(&file).map_err(|e|format!("missing Go recording {}: native response {status}: {raw}; {e}",file.display()))?)?;
            let projected=dir.parent().ok_or("corpus parent")?.join("qualified").join(file.file_name().ok_or("golden filename")?);
            if projected.exists() {
                let qualified:Value=serde_json::from_slice(&std::fs::read(projected)?)?;
                let mut derived=expected.clone();
                let request=&mut derived["observation"]["request"];
                request["wire_path"]=request["path"].clone();
                request["path"]=expected["route"].as_str().ok_or("route")?.split_once(' ').ok_or("route pattern")?.1.into();
                let channels=derived["observation"]["notify"].as_object().ok_or("notification channels")?;
                let notifications=channels.iter().flat_map(|(channel,payloads)|payloads.as_array().into_iter().flatten().map(move|payload|json!({"channel":channel,"payload":payload}))).collect::<Vec<_>>();
                derived["observation"]["notify"]=json!(notifications);
                golden::compare(&qualified,&derived)?;
            }
            let mut rows_doc:Option<Value>=None;
            if matches!(action,"app-create"|"app-revoke"|"receipt"|"hook-create"|"hook-delete"|"cert-upload"|"cert-delete"|"cert-default"|"recipient-upload"|"recipient-delete"|"migration-delete"|"migration-start"|"migration-resume"|"migration-cancel"|"migration-pause"|"migration-upload") {
                // A golden pinned in divergences.json (an owner-approved security fix, #547) is
                // compared with its reviewed expectation. Both documents are fetched before any
                // comparison so a regenerating run (SECFIX3_WRITE_SECURITY) writes every file.
                rows_doc=Some(common::golden_doc(&file.with_file_name(format!("{action}-{label}-rows.json")),"effects",&observation["effects"]));
            }
            let mut wanted_observation=common::golden_doc(&file,"observation",&observation)["observation"].clone();
            if let Some(rows)=&rows_doc {golden::compare(&rows["effects"],&observation["effects"])?;}
            canonical_framing(&mut wanted_observation);
            let mut compared=observation;
            canonical_framing(&mut compared);
            let result=golden::compare(&wanted_observation,&compared);
            if mutant {
                let error=result.err().ok_or("status mutant survived")?;
                if !error.contains("/response/status") { return Err(format!("mutant failed for wrong reason: {error}").into()); }
                eprintln!("MUTANT-REJECTED: {} :: status",expected["route"].as_str().ok_or("route")?);
            }else{result?;eprintln!("GOLDEN-REPLAY: {} :: {file_label}",expected["route"].as_str().ok_or("route")?);}
        }
        Ok::<_,BoxError>(())
    }.await;
    if toggle_fault {
        if let Some(enabled)=toggle_original {c.execute("UPDATE feature_toggles SET enabled=$1 WHERE key=$2",&[&enabled,&toggle_key]).await?;}
        else {c.execute("DELETE FROM feature_toggles WHERE key=$1",&[&toggle_key]).await?;}
    }
    c.execute("DELETE FROM dlp_policies WHERE id=ANY($1)",&[&policy_ids]).await?;
    if privilege_fault { c.batch_execute(&format!("GRANT {fault_privilege} ON {fault_table} TO setjoin_app")).await?; }
    c.execute("DELETE FROM rust_operation_receipts WHERE family='F21' AND command LIKE 'self-service.%' AND operation_id::text<>ALL($1::text[])",&[&prior_receipts]).await?;
    if action=="receipt" {
        c.execute("DELETE FROM outbound_queue o WHERE EXISTS(SELECT 1 FROM messages m WHERE m.mailbox_id=ANY($1) AND o.message_id LIKE '<mdn-'||m.id::text||'-%@mailserver>')",&[&vec![a.mailbox,b.mailbox]]).await?;
        c.execute("DELETE FROM read_receipts r USING messages m WHERE m.id=r.message_id AND m.received_at=r.received_at AND m.mailbox_id=ANY($1)",&[&vec![a.mailbox,b.mailbox]]).await?;
    }
    c.execute(
        "DELETE FROM app_passwords WHERE user_id=ANY($1)",
        &[&vec![a.user, b.user]],
    )
    .await?;
    if action=="org" && matches!(label,"managers"|"reports") {
        c.execute("UPDATE users SET manager_id=NULL WHERE id=ANY($1)",&[&vec![a.user,b.user]]).await?;
        c.execute("UPDATE users SET domain_id=$1 WHERE id=$2",&[&b.domain,&b.user]).await?;
        c.execute("UPDATE mailboxes SET domain_id=$1 WHERE id=$2 AND user_id=$3",&[&b.domain,&b.mailbox,&b.user]).await?;
    }
    if action.starts_with("cert-") || action.starts_with("recipient-") {
        c.execute("DELETE FROM user_smime_certs WHERE user_id=ANY($1)",&[&vec![a.user,b.user]]).await?;
        c.execute("DELETE FROM recipient_smime_certs WHERE owner_user_id=ANY($1)",&[&vec![a.user,b.user]]).await?;
    }
    if action.starts_with("hook-") {
        c.execute("DELETE FROM webhook_subscriptions WHERE user_id=ANY($1)",&[&vec![a.user,b.user]]).await?;
    }
    fixture::remove(&c, &a).await?;
    fixture::remove(&c, &b).await?;
    result
}
