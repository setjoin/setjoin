//! approval-notify system worker. Only its explicit worker DSN can cross tenants.
use std::future::Future;
use tokio_postgres::{types::Type, NoTls};
type Error = Box<dyn std::error::Error + Send + Sync>;
pub struct ApprovalNotify {
    dsn: String,
    secret: Vec<u8>,
    base: String,
}
impl ApprovalNotify {
    pub fn new(dsn: String, secret: Vec<u8>, base: String) -> Self {
        Self { dsn, secret, base }
    }
    /// One committed approval_created event, matching Go's best-effort fan-out.
    pub async fn tick(&self, payload: &str) -> Result<(), Error> {
        if self.secret.is_empty() || self.base.is_empty() {
            return Ok(());
        }
        let Ok(event) = serde_json::from_str::<Event>(payload) else {
            return Ok(());
        };
        let request = event.request_id;
        let consumer = event.consumer_type;
        if consumer == "rbac.jit_activation" {
            return Ok(());
        }
        let (client, connection) = tokio_postgres::connect(&self.dsn, NoTls).await?;
        let driver = tokio::spawn(connection);
        let rows=client.query_typed("SELECT approver_kind,approver_ref,subject,floor(extract(epoch FROM expires_at))::bigint,to_char(expires_at AT TIME ZONE 'UTC','Dy, DD Mon YYYY HH24:MI:SS')||' UTC' FROM approval_requests WHERE id=$1",&[(&request,Type::INT8)]).await?;
        let Some(row) = rows.first() else {
            return Ok(());
        };
        let kind: String = row.get(0);
        let approver: i64 = row.get(1);
        let subject: String = row.get(2);
        let expiry: i64 = row.get(3);
        let expiration: String = row.get(4);
        let users=match kind.as_str(){"user"=>vec![approver],"role_group"=>client.query_typed("SELECT user_id FROM admin_role_assignments WHERE role_group_id=$1 AND (expires_at IS NULL OR expires_at>now()) AND admin_assignment_active(eligible,activated_until)",&[(&approver,Type::INT8)]).await?.iter().map(|r|r.get::<_,i64>(0)).collect(),_=>return Ok(())};
        for user in users {
            let rows=client.query_typed("SELECT COALESCE(mb.email,u.email) FROM mailboxes mb JOIN users u ON u.id=mb.user_id WHERE mb.user_id=$1 AND mb.is_primary=true LIMIT 1",&[(&user,Type::INT8)]).await?;
            let Some(email) = rows.first().map(|r| r.get::<_, String>(0)) else {
                continue;
            };
            let approve = format!(
                "{}/approvals/email/{}",
                self.base,
                crate::email::sign(request, user, "approve", expiry, &self.secret)
            );
            let deny = format!(
                "{}/approvals/email/{}",
                self.base,
                crate::email::sign(request, user, "deny", expiry, &self.secret)
            );
            let text=format!("You have an approval request pending action.\n\nRequest: {subject}\n\nApprove: {approve}\n\nDeny: {deny}\n\nThis link expires at {expiration}.");
            let escaped = subject
                .replace('&', "&amp;")
                .replace('<', "&lt;")
                .replace('>', "&gt;")
                .replace('"', "&#34;")
                .replace('\'', "&#39;");
            let mut html = String::new();
            let args = [
                escaped.as_str(),
                approve.as_str(),
                deny.as_str(),
                expiration.as_str(),
            ];
            let mut parts = include_str!("notification.html").split("%s");
            html.push_str(parts.next().unwrap_or(""));
            for arg in args {
                html.push_str(arg);
                html.push_str(parts.next().unwrap_or(""));
            }
            let domain = email
                .rsplit_once('@')
                .filter(|(_, d)| !d.is_empty())
                .map(|(_, d)| d)
                .unwrap_or(&email);
            let from = format!("noreply@{domain}");
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos();
            let message = format!("approval-{request}-{user}-{nanos}@setjoin");
            let raw = format!("system:approval-notify:{request}:{user}");
            let to = serde_json::json!([{"email":email,"name":""}]).to_string();
            let size = (text.len() + html.len()) as i64;
            let title = format!("Approval required: {subject}");
            // Go's entire delivery transaction is this canonical reducer call. Do not retry an unknown commit.
            if client.query_typed("SELECT deliver($1,$2,$3,'SetJoin Approvals',$4,$5::text::jsonb,'[]'::jsonb,'[]'::jsonb,$6,'','',$7,$8,$9,FALSE,clock_timestamp(),'none','none','none',0::real,'{}'::jsonb)",&[(&raw,Type::TEXT),(&message,Type::TEXT),(&from,Type::TEXT),(&email,Type::TEXT),(&to,Type::TEXT),(&title,Type::TEXT),(&text,Type::TEXT),(&html,Type::TEXT),(&size,Type::INT8)]).await.is_err(){eprintln!("approval notify: delivery failed");}
        }
        drop(client);
        driver.await??;
        Ok(())
    }
    /// Direct LISTEN; cancellation closes the owned connection, reconnects after loss.
    pub async fn run_until(self, direct: String, stop: impl Future<Output = ()>) {
        tokio::pin!(stop);
        loop {
            let listener = tokio::select! {_=&mut stop=>return,result=setjoin_pg::workers::DirectListener::connect(&direct,"approval_created")=>result};
            match listener {
                Ok(mut listener) => loop {
                    let event = tokio::select! {_=&mut stop=>{let _=listener.close().await;return},event=listener.recv()=>event};
                    let Some(event) = event else {
                        let _ = listener.close().await;
                        break;
                    };
                    tokio::select! {_=&mut stop=>{let _=listener.close().await;return},result=self.tick(event.payload())=>{if result.is_err(){eprintln!("approval notify: event failed");}}}
                },
                Err(_) => eprintln!("approval notify: listener disconnected"),
            }
            tokio::select! {_=&mut stop=>return,_=tokio::time::sleep(std::time::Duration::from_secs(1))=>{}}
        }
    }
}

#[derive(Default)]
struct Event {
    request_id: i64,
    consumer_type: String,
}
impl<'de> serde::Deserialize<'de> for Event {
    fn deserialize<D: serde::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        struct Fields;
        impl<'de> serde::de::Visitor<'de> for Fields {
            type Value = Event;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("approval_created object")
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Event, E> {
                Ok(Event::default())
            }
            fn visit_map<M: serde::de::MapAccess<'de>>(
                self,
                mut fields: M,
            ) -> Result<Event, M::Error> {
                let mut event = Event::default();
                while let Some(key) = fields.next_key::<String>()? {
                    let folded = key
                        .chars()
                        .map(|c| match c {
                            'ſ' => 's',
                            'K' => 'k',
                            _ => c.to_ascii_lowercase(),
                        })
                        .collect::<String>();
                    match folded.as_str() {
                        "request_id" => {
                            if let Some(id) = fields.next_value::<Option<i64>>()? {
                                event.request_id = id;
                            }
                        }
                        "consumer_type" => {
                            if let Some(value) = fields.next_value::<Option<String>>()? {
                                event.consumer_type = value;
                            }
                        }
                        _ => {
                            let _: serde::de::IgnoredAny = fields.next_value()?;
                        }
                    }
                }
                Ok(event)
            }
        }
        decoder.deserialize_any(Fields)
    }
}
