//! Best-effort session aggregation; report submission belongs to #323.
use crate::mail_auth::{Dns, DnsType};
use setjoin_pg::{workers::WorkerDatabase, Type};
use std::sync::Arc;

pub(super) struct Reporter {
    db: WorkerDatabase,
    dns: Arc<dyn Dns>,
}
impl Reporter {
    pub fn new(db: WorkerDatabase, dns: Arc<dyn Dns>) -> Self {
        Self { db, dns }
    }
    pub async fn discover(&self, domain: &str) -> String {
        if let Ok(records) = self
            .dns
            .lookup(DnsType::Txt, &format!("_smtp._tls.{domain}"))
            .await
        {
            for txt in records {
                let txt = txt.trim();
                if txt.starts_with("v=TLSRPTv1") {
                    for part in txt.split(';') {
                        if let Some(uri) = part.trim().strip_prefix("rua=") {
                            return uri.trim().into();
                        }
                    }
                }
            }
        }
        String::new()
    }
    pub async fn record(&self, domain: &str, host: &str, uri: &str, error: Option<&str>) {
        let result = match error {
            None => "success",
            Some(s) if s.contains("starttls") || s.contains("STARTTLS") => "starttls-not-supported",
            Some(s) if s.contains("certificate") || s.contains("x509") => "certificate-expired",
            Some(s) if s.contains("tls") || s.contains("TLS") || s.contains("handshake") => {
                "validation-failure"
            }
            Some(s) if s.contains("connect") || s.contains("dial") => "tcp-connection-refused",
            Some(_) => "validation-failure",
        };
        let date = chrono::Utc::now().date_naive().to_string();
        let failure = error.unwrap_or("");
        if let Ok(connection) = self.db.connect_session().await {
            let _=connection.query("INSERT INTO tls_rpt_sessions(policy_domain,mx_host,mx_ip,result,failure_reason,report_uri,report_date,session_count) VALUES($1,$2,'',$3,$4,$5,$6::date,1) ON CONFLICT(policy_domain,mx_host,mx_ip,result,report_date) DO UPDATE SET session_count=tls_rpt_sessions.session_count+1",&[(&domain,Type::TEXT),(&host,Type::TEXT),(&result,Type::TEXT),(&failure,Type::TEXT),(&uri,Type::TEXT),(&date,Type::TEXT)]).await;
        }
    }
}
