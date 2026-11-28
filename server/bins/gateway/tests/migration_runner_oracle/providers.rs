//! Additional #446 fixtures. A real CA and an isolated DNS server keep Go offline.
use super::*;
use hickory_resolver::proto::{
    op::Message,
    rr::{rdata::A, RData, Record, RecordType},
};
use std::{net::Ipv4Addr, path::PathBuf};
#[path = "../common/fake_microsoft.rs"]
pub mod fake;
const DNS: &str = "127.0.0.86:53";
pub struct Providers {
    pub peer: fake::Peer,
    dns: tokio::task::JoinHandle<()>,
    pub files: PathBuf,
    enabled: Option<bool>,
}
impl Drop for Providers {
    fn drop(&mut self) {
        self.dns.abort();
        let _ = std::fs::remove_dir_all(&self.files);
    }
}
impl Providers {
    pub async fn start(recording: bool, label: &str) -> Result<Self, BoxError> {
        let bind = if recording {
            format!("{}:443", plan::PUBLIC)
        } else {
            "127.0.0.87:443".into()
        };
        let scenario = if label.ends_with("negotiate") {
            "negotiate"
        } else if label.ends_with("contacts-only") || label == "ews-contacts-legacy" {
            "contacts-only"
        } else if label == "verify-failure" {
            "empty-users"
        } else if label.ends_with("http-error") {
            "http-error"
        } else if label.starts_with("m365-") && label.ends_with("calendar-failure") {
            "empty-contacts"
        } else if label.starts_with("m365-") && !label.ends_with("contact-failure") {
            "mail-only"
        } else {
            "success"
        };
        let peer = fake::Peer::start(&bind, scenario).await?;
        let socket = tokio::net::UdpSocket::bind(DNS).await?;
        let ip: Ipv4Addr = if recording {
            plan::PUBLIC.parse()?
        } else {
            Ipv4Addr::new(127, 0, 0, 87)
        };
        let dns = tokio::spawn(async move {
            let mut buf = [0; 65535];
            while let Ok((n, addr)) = socket.recv_from(&mut buf).await {
                let Ok(request) = Message::from_vec(&buf[..n]) else {
                    continue;
                };
                let mut reply = Message::response(request.metadata.id, request.metadata.op_code);
                reply.metadata.authoritative = true;
                reply.metadata.recursion_available = true;
                reply.metadata.recursion_desired = request.metadata.recursion_desired;
                reply.edns = request.edns.clone();
                for q in request.queries {
                    if q.query_type() == RecordType::A {
                        reply.answers.push(Record::from_rdata(
                            q.name().clone(),
                            0,
                            RData::A(A(
                                if recording
                                    && q.name().to_string().trim_end_matches('.') == plan::HOST
                                {
                                    Ipv4Addr::new(172, 17, 0, 1)
                                } else {
                                    ip
                                },
                            )),
                        ));
                    }
                    reply.queries.push(q);
                }
                if let Ok(bytes) = reply.to_vec() {
                    let _ = socket.send_to(&bytes, addr).await;
                }
            }
        });
        let files = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../../test-results")
            .join(format!("gofree-mbox7-providers-{}", std::process::id()));
        std::fs::create_dir_all(files.parent().unwrap())?;
        std::fs::create_dir(&files)?;
        let files = files.canonicalize()?;
        std::fs::write(files.join("ca.pem"), &peer.ca)?;
        std::fs::write(
            files.join("resolv.conf"),
            "nameserver 127.0.0.86\noptions timeout:1 attempts:1 ndots:1\n",
        )?;
        Ok(Self {
            peer,
            dns,
            files,
            enabled: None,
        })
    }
    pub async fn seed(
        &mut self,
        c: &tokio_postgres::Client,
        fx: &Fx,
        action: &str,
        label: &str,
    ) -> Result<(), BoxError> {
        let enabled=c.query_opt("SELECT enabled FROM feature_toggles WHERE key='feature.mail_migration_source_identity'",&[]).await?.map(|r|r.get::<_,bool>(0));
        self.enabled = enabled;
        c.execute("INSERT INTO feature_toggles(key,enabled) VALUES ('feature.mail_migration_source_identity',$1) ON CONFLICT(key) DO UPDATE SET enabled=EXCLUDED.enabled",&[&!label.ends_with("legacy")]).await?;
        for mailbox in [fx.a.mailbox, fx.b.mailbox] {
            c.execute("INSERT INTO calendars(mailbox_id,name,is_default) SELECT $1,'Migration',true WHERE NOT EXISTS(SELECT 1 FROM calendars WHERE mailbox_id=$1 AND is_default)",&[&mailbox]).await?;
            c.execute("INSERT INTO addressbooks(mailbox_id,name,is_default) SELECT $1,'Migration',true WHERE NOT EXISTS(SELECT 1 FROM addressbooks WHERE mailbox_id=$1 AND is_default)",&[&mailbox]).await?;
        }
        for (key, value) in [
            (
                "ews.global",
                json!({"serverURL":"https://ews.mbox7.test/EWS","username":"service","password":"pw","authMode":"impersonation","insecureSkipVerify":false}),
            ),
            (
                "m365.app",
                json!({"client_id":"client","client_secret":"secret","tenant_id":"tenant","cloud":if label.contains("china"){"china"}else{"global"},"source_email":"source@example.test"}),
            ),
        ] {
            if label == "no-config" && key == "m365.app" {
                continue;
            }
            let key_bytes =
                setjoin_mailboxes::migration::derive_key(&plan::root(), "system").unwrap();
            let wrapped = setjoin_mailboxes::migration::wrapper(
                &setjoin_mailboxes::migration::seal(value.to_string().as_bytes(), &key_bytes)
                    .unwrap(),
            );
            c.execute("INSERT INTO system_config(key,value,encrypted) VALUES($1,$2::text::jsonb,true) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value,encrypted=true",&[&key,&wrapped]).await?;
        }
        if label == "bad-config" {
            c.execute(
                "UPDATE system_config SET value='{}' WHERE key='m365.app'",
                &[],
            )
            .await?;
        }
        if action == "callback" && label != "fabricated" {
            let actor = if label == "other-actor" {
                fx.b.user
            } else {
                fx.a.user
            };
            c.execute("INSERT INTO m365_consent_states(actor_user_id,state_token,cloud,issued_at,expires_at) VALUES($1,'fixture-state','global',now()-interval '20 minutes',now()+CASE WHEN $2 THEN interval '-1 second' ELSE interval '10 minutes' END)",&[&actor,&(label=="expired")]).await?;
        }
        Ok(())
    }
    pub async fn restore(&self, c: &tokio_postgres::Client) -> Result<(), BoxError> {
        if let Some(enabled) = self.enabled {
            c.execute("UPDATE feature_toggles SET enabled=$1 WHERE key='feature.mail_migration_source_identity'",&[&enabled]).await?;
        } else {
            c.execute(
                "DELETE FROM feature_toggles WHERE key='feature.mail_migration_source_identity'",
                &[],
            )
            .await?;
        }
        Ok(())
    }
    pub async fn go(
        &self,
        db: &Db,
        s3: std::net::SocketAddr,
    ) -> Result<Option<common::go_oracle::GoOracle>, BoxError> {
        std::env::set_var("GOFREE_ORACLE_RESOLV_CONF", self.files.join("resolv.conf"));
        let relative = self
            .files
            .strip_prefix(
                PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("../../..")
                    .canonicalize()?,
            )
            .unwrap_or(&self.files);
        // /src is mounted read-only in the oracle container.
        let ca = format!("/src/{}", relative.display());
        let result = common::go_oracle::start_named_with_env(
            db,
            s3,
            "gofree-mbox7-providers",
            &[
                ("SSL_CERT_FILE", format!("{ca}/ca.pem")),
                ("GODEBUG", "netdns=go".into()),
            ],
        )
        .await;
        std::env::remove_var("GOFREE_ORACLE_RESOLV_CONF");
        result
    }
    pub async fn upload_job(
        &self,
        c: &tokio_postgres::Client,
        fx: &Fx,
        s3: &fake_s3::DriveS3,
        label: &str,
    ) -> Result<(), BoxError> {
        use setjoin_gateway::recovery_worker::{ObjectStore, S3Store};
        let phase = if label.contains("compound") {
            "imap|ics|vcf"
        } else if label.contains("ics") {
            "ics"
        } else {
            "vcf"
        };
        let strategy = if label.ends_with("overwrite") {
            "overwrite"
        } else if label.ends_with("rename") {
            "rename"
        } else {
            "skip"
        };
        c.execute(
            "UPDATE migration_jobs SET source_type=$1,conflict_strategy=$2 WHERE id=$3",
            &[&phase, &strategy, &fx.pending],
        )
        .await?;
        if label.ends_with("overwrite") || label.ends_with("rename") {
            if phase == "ics" {
                c.execute("INSERT INTO calendar_events(calendar_id,uid,title,start_at,end_at) SELECT id,'m7-event','Existing event','2026-11-07 10:00Z','2026-11-07 11:00Z' FROM calendars WHERE mailbox_id=$1 AND is_default",&[&fx.b.mailbox]).await?;
            } else {
                c.execute("INSERT INTO contacts(addressbook_id,vcard_uid,display_name) SELECT id,'m7-contact','Existing contact' FROM addressbooks WHERE mailbox_id=$1 AND is_default",&[&fx.b.mailbox]).await?;
            }
        }
        if !label.ends_with("missing") {
            let store = S3Store::new(
                &format!("http://{}", s3.addr),
                "mailblobs",
                "test-access",
                "test-secret",
            )?;
            for (suffix, data) in [("ics", fake::ICS), ("vcf", fake::VCF)] {
                if phase.contains(suffix) {
                    store
                        .put(
                            &format!("migration/upload/{}/{suffix}", fx.pending),
                            data.as_bytes(),
                            "application/octet-stream",
                        )
                        .await?;
                }
            }
        }
        Ok(())
    }
    pub async fn control_job(
        &self,
        c: &tokio_postgres::Client,
        fx: &Fx,
        source: &str,
    ) -> Result<(), BoxError> {
        let config = json!({"use_global_auth":true,"self_service":false,"source_type":source,"ews":{"impersonateAs":"source@example.test"},"m365":{"source_email":"source@example.test"}});
        let key = setjoin_mailboxes::migration::derive_key(&plan::root(), "migration").unwrap();
        let sealed =
            setjoin_mailboxes::migration::seal(config.to_string().as_bytes(), &key).unwrap();
        c.execute(
            "UPDATE migration_jobs SET source_type=$1,source_config_enc=$2 WHERE id=$3",
            &[&source, &sealed, &fx.j2],
        )
        .await?;
        Ok(())
    }
}
pub async fn snapshot(c: &tokio_postgres::Client, fx: &Fx) -> Result<Value, BoxError> {
    let boxes = format!("({},{})", fx.a.mailbox, fx.b.mailbox);
    let users = format!("({},{})", fx.a.user, fx.b.user);
    let mut config = json!(null);
    if let Some(row) = c
        .query_opt(
            "SELECT value::text,encrypted FROM system_config WHERE key='m365.app'",
            &[],
        )
        .await?
    {
        config = match setjoin_mailboxes::migration::unseal(&row.get::<_, String>(0), &plan::root())
        {
            setjoin_mailboxes::migration::Unsealed::Plain(v) => v,
            _ => json!("<sealed>"),
        };
    }
    let mut out = json!({
        "events":rows(c,&format!("SELECT ((to_jsonb(e)-'id'-'created_at'-'updated_at'-'jmap_state'-'etag'-'calendar_id')||jsonb_build_object('mailbox',c.mailbox_id))::text FROM calendar_events e JOIN calendars c ON c.id=e.calendar_id WHERE c.mailbox_id IN {boxes} ORDER BY uid")).await?,
        "contacts":rows(c,&format!("SELECT ((to_jsonb(c)-'id'-'created_at'-'updated_at'-'jmap_state'-'etag'-'addressbook_id')||jsonb_build_object('mailbox',a.mailbox_id))::text FROM contacts c JOIN addressbooks a ON a.id=c.addressbook_id WHERE a.mailbox_id IN {boxes} ORDER BY vcard_uid")).await?,
        "instances":rows(c,&format!("SELECT jsonb_build_object('job_id',job_id,'type',source_type,'key',source_mailbox_key,'digest',selector_digest,'generation',generation)::text FROM migration_source_instances WHERE job_id IN(SELECT id FROM migration_jobs WHERE user_id IN {users}) ORDER BY job_id")).await?,
        "source_objects":rows(c,&format!("SELECT (to_jsonb(o)-'source_instance_id'-'applied_operation_id'-'applied_at'-'target_id')::text FROM migration_source_objects o JOIN migration_source_instances i ON i.id=o.source_instance_id WHERE i.job_id IN(SELECT id FROM migration_jobs WHERE user_id IN {users}) ORDER BY object_type,source_object_id")).await?,
        "operations":rows(c,&format!("SELECT (to_jsonb(o)-'operation_id'-'source_instance_id'-'target_id'-'created_at'-'completed_at')::text FROM migration_object_operations o WHERE job_id IN(SELECT id FROM migration_jobs WHERE user_id IN {users}) ORDER BY job_id,object_type,source_object_id,source_version")).await?,
        "checkpoints":rows(c,&format!("SELECT (to_jsonb(c)-'committed_at')::text FROM migration_checkpoints c WHERE job_id IN(SELECT id FROM migration_jobs WHERE user_id IN {users}) ORDER BY job_id,scope_key,cursor_kind")).await?,
        "states":rows(c,&format!("SELECT jsonb_build_object('mailbox',id,'calendar',(SELECT jsonb_agg(c.jmap_state ORDER BY c.id) FROM calendars c WHERE c.mailbox_id=mailboxes.id),'contact',(SELECT jsonb_agg(a.jmap_state ORDER BY a.id) FROM addressbooks a WHERE a.mailbox_id=mailboxes.id),'email',jmap_email_state,'thread',jmap_thread_state)::text FROM mailboxes WHERE id IN {boxes} ORDER BY id")).await?,
        "consents":rows(c,&format!("SELECT jsonb_build_object('actor',actor_user_id,'cloud',cloud,'spent',consumed_at IS NOT NULL,'expired',expires_at<now())::text FROM m365_consent_states WHERE actor_user_id IN {users} ORDER BY actor_user_id")).await?,
        "m365_config":config
    });
    let relations=rows(c,&format!("SELECT jsonb_build_object('source',o.source_object_id,'uid',c.vcard_uid,'mailbox',a.mailbox_id)::text FROM migration_source_objects o JOIN migration_source_instances i ON i.id=o.source_instance_id LEFT JOIN contacts c ON o.target_kind='contact' AND c.id=o.target_id LEFT JOIN addressbooks a ON a.id=c.addressbook_id WHERE o.object_type='contact' AND i.job_id IN(SELECT id FROM migration_jobs WHERE user_id IN {users}) ORDER BY o.source_object_id")).await?;
    if !relations.is_empty() {
        out["contact_targets"] = json!(relations);
    }
    Ok(out)
}

pub async fn ids(
    c: &tokio_postgres::Client,
    fx: &Fx,
) -> Result<Vec<(&'static str, i64, String)>, BoxError> {
    let boxes = vec![fx.a.mailbox, fx.b.mailbox];
    let mut ids = vec![];
    for (query,key,prefix)in[("SELECT e.id FROM calendar_events e JOIN calendars c ON c.id=e.calendar_id WHERE c.mailbox_id=ANY($1) ORDER BY uid","event_id","event"),("SELECT c.id FROM contacts c JOIN addressbooks a ON a.id=c.addressbook_id WHERE a.mailbox_id=ANY($1) ORDER BY vcard_uid","contact_id","contact"),("SELECT id FROM calendars WHERE mailbox_id=ANY($1) ORDER BY mailbox_id,id","calendar_id","calendar")]{
        for (n,row)in c.query(query,&[&boxes]).await?.iter().enumerate(){ids.push((key,row.get(0),format!("<{prefix}-{n}>")));}
    }
    for (n,row)in c.query("SELECT id FROM messages WHERE mailbox_id=ANY($1) AND raw_ref NOT LIKE 'raw-%' ORDER BY subject,raw_ref,id",&[&boxes]).await?.iter().enumerate(){let id:i64=row.get(0);for key in ["message_id","message"]{ids.push((key,id,format!("<message-new-{n}>")));}}
    for row in c
        .query(
            "SELECT id,mailbox_id,name FROM tags WHERE mailbox_id=ANY($1) ORDER BY mailbox_id,name",
            &[&boxes],
        )
        .await?
    {
        let id: i64 = row.get(0);
        let mailbox: i64 = row.get(1);
        let name: String = row.get(2);
        ids.push((
            "tag_id",
            id,
            format!(
                "<tag-{}-{name}>",
                if mailbox == fx.a.mailbox { "a" } else { "b" }
            ),
        ));
    }
    for (key, id, name) in [
        ("actor", fx.a.user, "<user-a>"),
        ("actor", fx.b.user, "<user-b>"),
    ] {
        ids.push((key, id, name.into()));
    }
    Ok(ids)
}
pub fn requests(peer: &fake::Peer) -> Value {
    // SOAP formatting and SDK transport headers are not the provider contract.
    // Compare the selected resource, authentication identity and immutable-ID preference.
    let requests:Vec<Value>=peer.seen.lock().unwrap().iter().map(|v|{
        let uri=v["path"].as_str().unwrap();let (path,query)=uri.split_once('?').unwrap_or((uri,""));
        let mut query:Vec<_>=url::form_urlencoded::parse(query.as_bytes()).map(|(k,v)|(k.into_owned(),v.into_owned())).collect();query.sort();
        let mut authorization=v["authorization"].clone();
        if let Some((scheme,token))=v["authorization"].as_str().and_then(|s|s.split_once(' ')).filter(|(s,_)|matches!(*s,"NTLM"|"Negotiate")){
            use base64::{engine::general_purpose::STANDARD,Engine};
            let bytes=STANDARD.decode(token).unwrap();
            let kind=bytes.get(8..12).and_then(|b|b.try_into().ok()).map(u32::from_le_bytes);
            authorization=json!({"scheme":scheme,"type":match kind{Some(1)=>"negotiate",Some(3)=>"authenticate",_=>"invalid"}});
        }
        json!({"path":path,"query":query,"operation":v["operation"],"authorization":authorization,"prefer":v["prefer"],"anchor":v["anchor"]})
    }).collect();
    json!(requests)
}
