use crate::common::BoxError;
use setjoin_conformance::fixture::{self, Account};
use tokio_postgres::Client;
pub struct Fx {
    pub a: Account,
    pub b: Account,
    role: i64,
    saved: String,
    toggle: String,
    a_domain: String,
    b_domain: String,
}
pub struct Plan {
    pub method: &'static str,
    pub pattern: &'static str,
    pub path: String,
    pub query: String,
    pub body: String,
    pub recorded_body: String,
    pub repeat: bool,
    pub head: bool,
}
impl Fx {
    pub async fn build(c: &Client, label: &str, action: &str) -> Result<Self, BoxError> {
        let a = fixture::account(c, "dev3-admin").await?;
        let b = fixture::account(c, "dev3-other").await?;
        let a_domain = c
            .query_one("SELECT name FROM domains WHERE id=$1", &[&a.domain])
            .await?
            .get(0);
        let b_domain = c
            .query_one("SELECT name FROM domains WHERE id=$1", &[&b.domain])
            .await?
            .get(0);
        let perm = if label == "denied" {
            "users.read"
        } else if action == "pending" {
            "mam.read"
        } else if matches!(action, "approve" | "deny" | "revoke" | "wipe") {
            "mam.write"
        } else {
            "mail.offline_policy"
        };
        let domain = matches!(label, "foreign" | "rls-scoped").then_some(a.domain);
        let role=c.query_one("INSERT INTO admin_role_groups(name,permissions,domain_scope) VALUES($1,ARRAY[$2::text],$3) RETURNING id",&[&format!("dev3-role-{}",a.user),&perm,&domain]).await?.get(0);
        c.execute(
            "INSERT INTO admin_role_assignments(user_id,role_group_id,granted_by) VALUES($1,$2,$1)",
            &[&a.user, &role],
        )
        .await?;
        let saved = c
            .query_one(
                "SELECT COALESCE(jsonb_agg(to_jsonb(p)),'[]'::jsonb)::text FROM offline_policies p",
                &[],
            )
            .await?
            .get(0);
        let toggle=c.query_one("SELECT COALESCE(jsonb_agg(to_jsonb(t)),'[]'::jsonb)::text FROM feature_toggles t WHERE key='feature.offline_mail'",&[]).await?.get(0);
        c.batch_execute("DELETE FROM offline_policies").await?;
        Ok(Self {
            a,
            b,
            role,
            saved,
            toggle,
            a_domain,
            b_domain,
        })
    }
    pub async fn seed(&self, c: &Client, action: &str, label: &str) -> Result<(), BoxError> {
        c.batch_execute("INSERT INTO offline_policies(id,name,scope_type,enabled,max_offline_days,require_approval,wipe_on_logout,priority,created_at,updated_at) VALUES(985001,'Global <offline> & policy','global',true,30,true,'admin_default',5,'2026-01-01','2026-01-01');").await?;
        if action == "delete" {
            c.batch_execute("INSERT INTO offline_policies(id,name,scope_type,enabled,priority,created_at,updated_at) VALUES(985002,'Fallback','global',true,0,'2026-01-01','2026-01-01')").await?;
        }
        if action == "create" {
            c.batch_execute(
                "SELECT setval(pg_get_serial_sequence('offline_policies','id'),985100,false)",
            )
            .await?;
        }
        if matches!(
            action,
            "preview" | "approve" | "deny" | "revoke" | "wipe" | "ack"
        ) {
            c.execute("INSERT INTO devices(id,user_id,fingerprint,hmac_secret) VALUES(985010,$1,'dev3-own','secret')",&[&self.a.user]).await?;
            c.execute("INSERT INTO user_devices(id,user_id,device_id,device_name,platform,fingerprint_hash,offline_approval) VALUES(986001,$1,985010,'Own desktop','desktop','fingerprint','pending')",&[&self.a.user]).await?;
        }
        if matches!(action, "revoke" | "wipe") {
            c.batch_execute("UPDATE user_devices SET offline_approval='approved' WHERE id=986001")
                .await?;
        }
        if action == "ack" {
            c.batch_execute("UPDATE user_devices SET wipe_requested=true,wipe_type='selective',wipe_at='2026-01-01' WHERE id=986001").await?;
        }
        if action == "size" {
            c.execute("UPDATE messages SET body_text='é',body_html='<p>hi</p>',size_bytes=999999 WHERE mailbox_id=$1",&[&self.a.mailbox]).await?;
            c.execute(
                "UPDATE messages SET body_text='private other-user body' WHERE mailbox_id=$1",
                &[&self.b.mailbox],
            )
            .await?;
            let mb:i64=c.query_one("INSERT INTO mailboxes(user_id,domain_id,email,display_name,type,is_primary) VALUES($1,$2,'dev3-secondary@offline.test','Secondary','personal',false) RETURNING id",&[&self.a.user,&self.a.domain]).await?.get(0);
            let inbox: i64 = c
                .query_one(
                    "SELECT id FROM tags WHERE mailbox_id=$1 AND name='Inbox'",
                    &[&mb],
                )
                .await?
                .get(0);
            let message = fixture::message(c, mb, inbox, &[inbox], true).await?;
            c.execute(
                "UPDATE messages SET body_text='extra' WHERE id=$1",
                &[&message],
            )
            .await?;
        }
        if action == "pending" && matches!(label, "populated" | "foreign") {
            c.execute("INSERT INTO devices(id,user_id,fingerprint,hmac_secret) VALUES(985010,$1,'dev3-own','secret')",&[&self.a.user]).await?;
            c.execute("INSERT INTO user_devices(id,user_id,device_id,device_name,platform,fingerprint_hash,offline_approval,last_seen_at) VALUES(986001,$1,985010,'Own desktop','desktop','fingerprint','pending','2026-01-02')",&[&self.a.user]).await?;
        }
        if matches!(label, "foreign" | "spoofed-owner")
            && matches!(
                action,
                "preview" | "pending" | "approve" | "deny" | "revoke" | "wipe" | "ack"
            )
        {
            c.execute("INSERT INTO devices(id,user_id,fingerprint,hmac_secret) VALUES(985011,$1,'dev3-other','secret')",&[&self.b.user]).await?;
            c.execute("INSERT INTO user_devices(id,user_id,device_id,device_name,platform,fingerprint_hash,offline_approval,last_seen_at) VALUES(986002,$1,985011,'Other desktop','desktop','other-fingerprint','pending','2026-01-03')",&[&self.b.user]).await?;
            if matches!(action, "revoke" | "wipe") {
                c.batch_execute(
                    "UPDATE user_devices SET offline_approval='approved' WHERE id=986002",
                )
                .await?;
            }
            if action == "ack" {
                c.batch_execute("UPDATE user_devices SET wipe_requested=true,wipe_type='selective',wipe_at='2026-01-01' WHERE id=986002").await?;
            }
        }
        if label.starts_with("large") && action == "policies" {
            c.batch_execute("INSERT INTO offline_policies(id,name,scope_type,enabled,max_offline_days,require_approval,wipe_on_logout,priority,created_at,updated_at) SELECT 985010+n,'Large policy '||n,'global',true,30,true,'admin_default',10+n,'2026-01-01','2026-01-01' FROM generate_series(1,6)n").await?;
        }
        if label == "empty" && action == "policies" {
            c.batch_execute("DELETE FROM offline_policies").await?;
        }
        if label == "last-global" && action == "delete" {
            c.batch_execute("DELETE FROM offline_policies WHERE id=985002")
                .await?;
        }
        if label == "approved" && matches!(action, "approve" | "deny") {
            c.batch_execute("UPDATE user_devices SET offline_approval='approved' WHERE id=986001")
                .await?;
        }
        if label == "pending" && matches!(action, "revoke" | "wipe") {
            c.batch_execute("UPDATE user_devices SET offline_approval='pending' WHERE id=986001")
                .await?;
        }
        if action == "size" {
            if label == "empty" {
                c.execute("DELETE FROM messages WHERE mailbox_id IN(SELECT id FROM mailboxes WHERE user_id=$1)",&[&self.a.user]).await?;
            }
            if label == "deleted" {
                c.execute(
                    "UPDATE messages SET is_deleted=true WHERE id=$1",
                    &[&self.a.two_labels],
                )
                .await?;
            }
            if label == "windows" {
                c.execute(
                    "DELETE FROM message_tags WHERE message_id IN($1,$2)",
                    &[&self.a.two_labels, &self.a.inbox_only],
                )
                .await?;
                c.execute(
                    "UPDATE messages SET received_at=now()-interval '8 days' WHERE id=$1",
                    &[&self.a.two_labels],
                )
                .await?;
                c.execute(
                    "UPDATE messages SET received_at=now()-interval '100 days' WHERE id=$1",
                    &[&self.a.inbox_only],
                )
                .await?;
            }
        }
        Ok(())
    }
    pub async fn remove(&self, c: &Client) -> Result<(), BoxError> {
        c.batch_execute("DELETE FROM offline_policies; DELETE FROM feature_toggles WHERE key='feature.offline_mail'").await?;
        c.execute("INSERT INTO offline_policies SELECT * FROM jsonb_populate_recordset(NULL::offline_policies,$1::text::jsonb)",&[&self.saved]).await?;
        c.execute("INSERT INTO feature_toggles SELECT * FROM jsonb_populate_recordset(NULL::feature_toggles,$1::text::jsonb)",&[&self.toggle]).await?;
        c.execute(
            "DELETE FROM admin_role_assignments WHERE role_group_id=$1",
            &[&self.role],
        )
        .await?;
        c.execute("DELETE FROM admin_role_groups WHERE id=$1", &[&self.role])
            .await?;
        c.execute(
            "DELETE FROM user_devices WHERE user_id IN($1,$2)",
            &[&self.a.user, &self.b.user],
        )
        .await?;
        c.execute("DELETE FROM messages WHERE mailbox_id IN(SELECT id FROM mailboxes WHERE user_id=$1 AND id<>$2)",&[&self.a.user,&self.a.mailbox]).await?;
        c.execute(
            "DELETE FROM mailboxes WHERE user_id=$1 AND id<>$2",
            &[&self.a.user, &self.a.mailbox],
        )
        .await?;
        fixture::remove(c, &self.a).await?;
        fixture::remove(c, &self.b).await?;
        Ok(())
    }
    pub fn ids(&self) -> Vec<(&'static str, i64, String)> {
        vec![
            ("user_id", self.a.user, "<admin>".into()),
            ("user_id", self.b.user, "<other>".into()),
            ("actor_id", self.a.user, "<admin>".into()),
            ("mailboxId", self.a.mailbox, "<admin-mailbox>".into()),
            ("offline_approval_by", self.a.user, "<admin>".into()),
        ]
    }
    pub fn names(&self, text: &str) -> String {
        text.replace(&self.a_domain, "host-a.test")
            .replace(&self.b_domain, "host-b.test")
    }
}
pub fn plan(action: &str, label: &str, fx: &Fx) -> Plan {
    let (method, pattern) = match action {
        "policies" => ("GET", "/admin/offline/policies"),
        "policy" => ("GET", "/admin/offline/policies/{id}"),
        "enabled" => ("GET", "/admin/offline/enabled"),
        "pending" => ("GET", "/admin/offline/devices/pending"),
        "create" => ("POST", "/admin/offline/policies"),
        "update" => ("PUT", "/admin/offline/policies/{id}"),
        "delete" => ("DELETE", "/admin/offline/policies/{id}"),
        "toggle" => ("PUT", "/admin/offline/enabled"),
        "preview" => ("POST", "/admin/offline/policy-preview"),
        "approve" => ("POST", "/admin/offline/devices/{id}/approve"),
        "deny" => ("POST", "/admin/offline/devices/{id}/deny"),
        "revoke" => ("POST", "/admin/offline/devices/{id}/revoke"),
        "wipe" => ("POST", "/admin/offline/devices/{id}/wipe"),
        "size" => ("GET", "/offline/size-estimate"),
        "ack" => ("POST", "/offline/wipe-ack"),
        _ => unreachable!(),
    };
    let device = matches!(action, "approve" | "deny" | "revoke" | "wipe");
    let policy_body = r#"{"name":"New <policy> & value","scope_type":"global","enabled":true,"max_offline_days":60,"require_approval":false,"priority":8}"#;
    let mut body = match action {
        "create" | "update" => policy_body.into(),
        "toggle" => r#"{"enabled":true}"#.into(),
        "preview" => format!(r#"{{"targetUserId":"{}","deviceId":"986001"}}"#, fx.a.user),
        "ack" => r#"{"device_id":985010}"#.into(),
        _ => String::new(),
    };
    let mut target = if device {
        "986001".to_owned()
    } else {
        "985001".to_owned()
    };
    let mut query = String::new();
    match label{
 "foreign"=>{
   if device{target="986002".into();}
   if action=="preview"{body=format!(r#"{{"targetUserId":"{}","deviceId":"986002"}}"#,fx.b.user);}
   if action=="ack"{body=r#"{"device_id":985011}"#.into();}
   if action=="size"{query=format!("?user_id={}&mailbox_id={}",fx.b.user,fx.b.mailbox);}
 },
 "invalid"=>{if pattern.contains("{id}"){target="bad".into();}else if method=="GET"{query="?window=bad&user_id=bad&limit=bad".into();}else{body="{".into();}},
 "missing"=>{target="9999999".into();if action=="ack"{body=r#"{"device_id":9999999}"#.into();}if action=="preview"{body=format!(r#"{{"targetUserId":"{}","deviceId":"9999999"}}"#,fx.a.user);}},
 "zero-id"=>{target="0".into();if action=="ack"{body=r#"{"device_id":0}"#.into();}},
 "negative-id"=>{target="-1".into();if action=="ack"{body=r#"{"device_id":-1}"#.into();}},
 "plus-id"=>target=format!("+{target}"),
 "null"=>body="null".into(),"empty-body"=>body=String::new(),"empty-object"=>body="{}".into(),
 "trailing"=>body.push_str(" trailing"),"second-object"=>body.push_str(" {}"),
 "unknown-field"=>body=body.replacen('{',"{\"unexpected\":true,",1),
 "unbounded"=>body=format!("{{\"enabled\":true,\"padding\":\"{}\"}}","A".repeat(17<<20)),
 "typed"=>body=if action=="ack"{r#"{"device_id":"985010"}"#.into()}else if action=="preview"{r#"{"targetUserId":1,"deviceId":"986001"}"#.into()}else{body.replace("true","\"true\"")},
 "case-keys"=>body=if action=="preview"{body.replace("targetUserId","TARGETUSERID").replace("deviceId","DEVICEID")}else{body.replace("enabled","ENABLED").replace("device_id","DEVICE_ID")},
 "duplicate-null"=>body=if action=="toggle"{r#"{"enabled":true,"enabled":null}"#.into()}else{body.replacen("\"enabled\":true","\"enabled\":true,\"enabled\":null",1)},
 "partial-qos"=>body=body.replacen('{',"{\"background_sync_allowed\":false,",1),
 "qos"=>body=body.replacen('{',"{\"background_sync_allowed\":false,\"automatic_network_max\":\"any\",\"attachment_prefetch_max\":\"always\",\"opportunistic_requires_charging\":false,\"connectivity_sync_mode\":\"observe\",",1),
 "bad-scope"=>body=body.replace("\"global\"","\"bad\""),
 "no-name"=>body=body.replace("New <policy> & value",""),
 "negative-days"=>body=body.replace(":60",":-1"),"int32-overflow"=>body=body.replace(":60",":2147483648"),
 "fraction"=>body=body.replace(":60",":1.5"),
 "too-large"=>body=format!("{}{}",body," ".repeat(16400)),
 "bad-target"=>body=body.replace(&fx.a.user.to_string(),"bad"),
 "bad-device"=>body=body.replace("986001","0"),
 "spoofed-owner"=>body=r#"{"device_id":985011,"user_id":9999999,"mailbox_id":9999999,"domain_scope":0}"#.into(),
 _=>{}
 }
    let recorded_body = if label == "unbounded" {
        String::new()
    } else {
        body.replace(
            &format!("\"targetUserId\":\"{}\"", fx.a.user),
            "\"targetUserId\":\"<admin>\"",
        )
        .replace(
            &format!("\"targetUserId\":\"{}\"", fx.b.user),
            "\"targetUserId\":\"<other>\"",
        )
    };
    Plan {
        method,
        pattern,
        path: pattern.replace("{id}", &target),
        query,
        body,
        recorded_body,
        repeat: label == "repeat",
        head: label == "head" || label == "large-head",
    }
}
