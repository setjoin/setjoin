//! Reducer-backed inbound storage after configured mail authentication and ARC.
//! #526 ports the enabled security pipeline. The baseline corpus retains its
//! frozen-Go all-disabled configuration alongside the enabled recordings.
use futures_util::future::BoxFuture;
use serde_json::{json, Value};
use setjoin_mime as mime;
use setjoin_pg::{workers::WorkerDatabase, Type};
use sha2::{Digest, Sha256};
use std::sync::Arc;

#[derive(Clone, Default)]
pub struct DeliveryFeatures {
    pub rules: bool,
    pub vacation: bool,
    pub journaling: bool,
    pub retention: bool,
    pub full_text_search: bool,
    pub audit: bool,
    pub external_first_time: bool,
}
/// Shared gateway Dispatcher adapter. Only reducer-derived subjects may reach it.
pub trait DeliveryEvents: Send + Sync {
    fn received<'a>(
        &'a self,
        user: i64,
        mailbox: i64,
        from: &'a str,
        to: &'a str,
    ) -> BoxFuture<'a, ()>;
}
pub trait RawBlobs: Send + Sync {
    fn put<'a>(&'a self, key: &'a str, data: &'a [u8]) -> BoxFuture<'a, Result<(), String>>;
}
#[derive(Clone)]
pub(crate) struct Delivery {
    pub auth: Option<crate::mail_auth::MailAuth>,
    pub flags: Option<Arc<dyn crate::submission::Flags>>,
    pub spam_batch: Option<Arc<tokio::sync::Mutex<setjoin_spam::Batch>>>,
    pub inbound: Arc<crate::inbound::Pipeline>,
    pub recipients: Vec<String>,
    pub spf: &'static str,
    pub db: Option<WorkerDatabase>,
    pub features: DeliveryFeatures,
    pub events: Option<Arc<dyn DeliveryEvents>>,
    pub blobs: Option<Arc<dyn RawBlobs>>,
}
impl Delivery {
    pub async fn receive(
        &self,
        from: &[u8],
        to: &str,
        helo: &str,
        ip: &str,
        data: &[u8],
    ) -> Result<Accepted, Failure> {
        let db = self
            .db
            .as_ref()
            .ok_or("SMTP worker database is not configured")?;
        let dkim = if let Some(auth) = &self.auth {
            auth.delivery_dkim(data).await
        } else {
            Default::default()
        };
        let (sender_name, sender) = mime::parse_from(&mime::extract_header(data, "From"));
        let sender = mime::go_lossy(&sender);
        let sender_name = mime::go_lossy(&sender_name);
        let dmarc = if let Some(auth) = &self.auth {
            auth.delivery_dmarc(
                db,
                &sender,
                &mime::go_lossy(&mime::extract_header(data, "Message-Id")),
                self.spf,
                &mime::go_lossy(from),
                &dkim,
            )
            .await
        } else {
            Default::default()
        };
        if dmarc.reject {
            return Err(Failure::DmarcRejected);
        }
        let sealed = if let Some(auth) = &self.auth {
            auth.delivery_arc(
                db,
                data,
                &sender,
                &mime::go_lossy(from),
                self.spf,
                dmarc.result,
                helo,
                ip,
                to,
            )
            .await
        } else {
            None
        };
        let data = sealed.as_deref().unwrap_or(data);
        let now = chrono::Utc::now();
        let trace = format!(
            "Received: from {helo} ({ip} [{ip}]) by mailserver\r\n\tvia SMTP; {}\r\n",
            now.format("%a, %d %b %Y %H:%M:%S %z")
        );
        let mut message = trace.into_bytes();
        if !from.is_empty() && from != b"<>" {
            message.extend_from_slice(b"Return-Path: <");
            message.extend_from_slice(from);
            message.extend_from_slice(b">\r\n");
        }
        message.extend_from_slice(data);
        let trace_end = message.len() - data.len();
        let h = |name| mime::go_lossy(&mime::extract_header(&message, name));
        let mut message_id = h("Message-Id");
        if message_id.is_empty() {
            use ring::rand::SecureRandom;
            let mut id = [0u8; 16];
            ring::rand::SystemRandom::new()
                .fill(&mut id)
                .map_err(|_| "randomness unavailable")?;
            message_id = format!("<{}@mailserver>", hex(&id))
        }
        let conn = db.connect_session().await.map_err(|e| e.to_string())?;
        let enabled = |key: &str| self.flags.as_ref().is_some_and(|f| f.enabled(key));
        let smime = if enabled("feature.smime_verify") && !crate::mutants::on("inbound-no-smime") {
            self.inbound.smime(&conn, to, &sender, &message, true).await
        } else {
            None
        };
        let mutate_body = smime.as_ref().is_none_or(|s| s.status != "valid")
            || crate::mutants::on("inbound-smime-mutate-valid");
        let (phish, evidence) = self
            .inbound
            .phish(&conn, self.flags.as_deref(), &sender_name, &sender)
            .await;
        if phish == crate::inbound::Verdict::Reject {
            return Ok(Accepted::PhishDrop);
        }
        let warned = (mutate_body
            && phish == crate::inbound::Verdict::Warn
            && !crate::mutants::on("inbound-no-phish-warning"))
        .then(|| crate::inbound::inject(data, &evidence));
        let data = warned.as_deref().unwrap_or(data);
        // Go preserves envelope bytes until PostgreSQL rejects invalid UTF-8.
        // JSON-encoded MIME fields instead use Go's replacement-rune behavior.
        let from = std::str::from_utf8(from).map_err(|_| "invalid SMTP envelope encoding")?;
        let list_id = h("List-Id");
        let mut external = false;
        let mut spoof = false;
        if enabled("feature.external_sender_warn")
            && !crate::mutants::on("inbound-no-sender-warning")
        {
            external = if let Some((_, domain)) =
                sender.rsplit_once('@').filter(|(_, d)| !d.is_empty())
            {
                conn.query("SELECT NOT EXISTS(SELECT 1 FROM domains WHERE is_local=TRUE AND lower(name)=lower($1))", &[(&domain, Type::TEXT)]).await
                    .ok().and_then(|r| r.first().map(|r| r.get::<_, bool>(0))).unwrap_or(false)
            } else {
                true
            };
            if external && !sender_name.is_empty() && enabled("feature.external_sender_name_spoof")
            {
                spoof = conn
                    .query(
                        "SELECT EXISTS(SELECT 1 FROM users WHERE lower(display_name)=lower($1))",
                        &[(&sender_name, Type::TEXT)],
                    )
                    .await
                    .ok()
                    .and_then(|r| r.first().map(|r| r.get::<_, bool>(0)))
                    .unwrap_or(false);
            }
        }
        let (mut spam_score, mut spam_symbols) = (0.0f64, Vec::<String>::new());
        let mut rbl = Vec::new();
        if enabled("feature.rbl") && !crate::mutants::on("inbound-no-rbl") {
            if let (Some(auth), Ok(ip)) = (&self.auth, ip.parse::<std::net::IpAddr>()) {
                let reverse = match ip.to_canonical() {
                    std::net::IpAddr::V4(ip) => ip
                        .octets()
                        .iter()
                        .rev()
                        .map(u8::to_string)
                        .collect::<Vec<_>>()
                        .join("."),
                    std::net::IpAddr::V6(ip) => ip
                        .octets()
                        .iter()
                        .rev()
                        .flat_map(|b| [format!("{:x}", b & 15), format!("{:x}", b >> 4)])
                        .collect::<Vec<_>>()
                        .join("."),
                };
                for provider in [
                    "zen.spamhaus.org",
                    "bl.spamcop.net",
                    "b.barracudacentral.org",
                ] {
                    if auth
                        .dns
                        .lookup(
                            crate::mail_auth::DnsType::Ip,
                            &format!("{reverse}.{provider}"),
                        )
                        .await
                        .is_ok()
                    {
                        rbl.push(provider);
                    }
                }
            }
        }
        if enabled("feature.spam_scoring") && !crate::mutants::on("inbound-no-spam-score") {
            spam_score += rbl.len() as f64 * 2.0;
            spam_symbols.extend(rbl.into_iter().map(|p| format!("RBL_{p}")));
            if mime::extract_header(data, "Message-Id").is_empty() {
                spam_score += 1.0;
                spam_symbols.push("MISSING_MID".into());
            }
            if mime::extract_header(data, "Date").is_empty() {
                spam_score += 0.5;
                spam_symbols.push("MISSING_DATE".into());
            }
            if mime::extract_body_text(data).is_empty() && !mime::extract_body_html(data).is_empty()
            {
                spam_score += 1.0;
                spam_symbols.push("HTML_ONLY".into());
            }
            let subject = mime::go_lossy(&mime::to_lower(&mime::extract_header(data, "Subject")));
            if [
                "viagra",
                "cialis",
                "lottery",
                "winner",
                "million",
                "urgent",
                "click here",
                "act now",
            ]
            .iter()
            .any(|k| subject.contains(k))
            {
                spam_score += 1.5;
                spam_symbols.push("SUSPICIOUS_SUBJECT".into());
            }
            // Frozen Go lowercases the subject before counting uppercase ASCII;
            // its ALL_CAPS rule can never fire.
        }
        if enabled("feature.spam_ml_detectors") && !crate::mutants::on("inbound-no-ml-detectors") {
            let (score, symbols) = crate::inbound::scoring::detectors(
                data,
                from,
                &sender,
                &self.recipients,
                self.spf == "pass",
                dkim.result == "pass",
            );
            spam_score += score;
            spam_symbols.extend(symbols);
        }
        let mut condemned = if enabled("feature.clamav") && !crate::mutants::on("inbound-no-av") {
            if let Some(clamd) = &self.inbound.clamav {
                clamd
                    .scan(data)
                    .await
                    .unwrap_or_else(|_| b"ClamAV:unavailable".to_vec())
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };
        if condemned.is_empty()
            && crate::inbound::risky(data)
            && !crate::mutants::on("inbound-no-sandbox")
        {
            if let (Some(cape), Some((_, domain))) = (&self.inbound.sandbox, to.rsplit_once('@')) {
                let rows = conn
                    .query(
                        "SELECT sandbox_enabled,sandbox_action FROM domains WHERE name=$1",
                        &[(&domain, Type::TEXT)],
                    )
                    .await;
                if let Ok(rows) = rows {
                    if let Some(row) = rows.first().filter(|row| row.get::<_, bool>(0)) {
                        if let Some((malicious, name)) = cape.analyze(data).await {
                            if malicious && row.get::<_, String>(1) == "reject" {
                                return Err(Failure::Other);
                            }
                            condemned = format!(
                                "Sandbox:{}{name}",
                                if malicious { "" } else { "Suspicious:" }
                            )
                            .into_bytes();
                        }
                    }
                }
            }
        }
        let mut linked = None;
        if (mutate_body || crate::mutants::on("inbound-link-ignore-signature"))
            && enabled("feature.link_protect_rewrite")
            && !crate::mutants::on("inbound-no-link")
        {
            if let Some(links) = self
                .inbound
                .config
                .links
                .as_ref()
                .filter(|k| !k.key.is_empty())
            {
                let mailbox = conn.query("SELECT m.id FROM mailboxes m JOIN aliases a ON a.mailbox_id=m.id WHERE a.email=lower($1) AND m.enabled=TRUE LIMIT 1", &[(&to,Type::TEXT)]).await.ok().and_then(|r|r.first().map(|r|r.get::<_,i64>(0))).unwrap_or(0);
                match links.rewrite(
                    data,
                    &self.inbound.config.internal_domains,
                    &message_id,
                    mailbox,
                ) {
                    Ok((bytes, count)) if count > 0 => linked = Some(bytes),
                    Err(_)
                        if condemned.is_empty()
                            && !crate::mutants::on("inbound-no-mime-condemnation") =>
                    {
                        condemned = b"MIME:unparseable".to_vec()
                    }
                    _ => {}
                }
            }
        }
        // Go refreshes body extraction after a successful rewrite, while its
        // parsed envelope/header snapshot remains the pristine original.
        let rewritten_message = linked.as_ref().map(|bytes| {
            let mut rebuilt = message[..trace_end].to_vec();
            rebuilt.extend_from_slice(bytes);
            rebuilt
        });
        let body_message = rewritten_message.as_deref().unwrap_or(&message);
        let data = linked.as_deref().unwrap_or(data);
        let raw_ref = format!("inbound/{}", hex(&Sha256::digest(data)));
        let mut params = json!({
         "p_raw_ref":raw_ref,"p_message_id":message_id,"p_from_addr":sender,"p_from_name":sender_name,"p_rcpt_addr":to,
         "p_to_addrs":serde_json::from_str::<Value>(&mime::parse_address_list(&mime::extract_header(&message,"To"))).unwrap(),
         "p_cc_addrs":serde_json::from_str::<Value>(&mime::parse_address_list(&mime::extract_header(&message,"Cc"))).unwrap(),
         "p_bcc_addrs":serde_json::from_str::<Value>(&mime::parse_address_list(&mime::extract_header(&message,"Bcc"))).unwrap(),
         "p_subject":h("Subject"),"p_in_reply_to":h("In-Reply-To"),"p_references_hdr":h("References"),
         "p_body_text":mime::go_lossy(&mime::extract_body_text(body_message)),"p_body_html":mime::go_lossy(&mime::extract_body_html(body_message)),
         "p_size_bytes":data.len(),"p_has_attachments":message.windows(31).any(|w|w==b"Content-Disposition: attachment"),"p_sent_at":now.to_rfc3339(),
         "p_spf_result":self.spf,"p_dkim_result":dkim.result,"p_dmarc_result":dmarc.result,"p_spam_score":spam_score,"p_spam_headers":if spam_symbols.is_empty(){Value::Null}else{json!(spam_symbols)},
         "p_vote_response":h("X-Mailserver-Vote-Response"),"p_crypto_type":crypto_type(&h("Content-Type")),
         "p_is_external":external,"p_sender_display_name":sender_name,"p_is_name_spoof":spoof,"p_depth":0,
         "p_list_id":if list_id.is_empty(){Value::Null}else{json!(list_id)},
         "p_smime_status":null,"p_smime_signer_email":null,"p_smime_signer_cn":null,"p_smime_issuer_cn":null
        });
        if let Some(smime) = &smime {
            params["p_smime_status"] = json!(smime.status);
            for (key, value) in [
                ("p_smime_signer_email", &smime.email),
                ("p_smime_signer_cn", &smime.cn),
                ("p_smime_issuer_cn", &smime.issuer),
            ] {
                if !value.is_empty() {
                    params[key] = json!(value);
                }
            }
        }
        // Frozen Go resolves a per-user sender list through aliases only. A mailbox
        // without an alias (including catch-all resolution) skips these checks.
        let users = conn.query(
            "SELECT m.user_id FROM mailboxes m JOIN aliases a ON a.mailbox_id=m.id WHERE a.email=lower($1) AND m.enabled=TRUE LIMIT 1",
            &[(&to, Type::TEXT)],
        ).await;
        if let Ok(rows) = users {
            if let Some(user) = rows.first().and_then(|row| row.get::<_, Option<i64>>(0)) {
                let mut listed = false;
                for (kind, symbol) in [("blocked", "USER_BLOCKED"), ("safe", "USER_SAFE")] {
                    let entries = conn.query(
                        "SELECT EXISTS(SELECT 1 FROM user_sender_list WHERE user_id=$1 AND sender=$2 AND list_type=$3)",
                        &[(&user, Type::INT8), (&sender, Type::TEXT), (&kind, Type::TEXT)],
                    ).await;
                    if entries.ok().is_some_and(|rows| rows[0].get::<_, bool>(0)) {
                        listed = true;
                        let score = params["p_spam_score"].as_f64().unwrap_or(0.0);
                        params["p_spam_score"] = json!(if kind == "blocked" {
                            score.max(10.0)
                        } else {
                            score.min(1.0)
                        });
                        append_symbol(&mut params, symbol);
                        break;
                    }
                }
                if !listed && enabled("feature.ml_spam") && !crate::mutants::on("inbound-no-ftrl") {
                    if let Some(batch) = &self.spam_batch {
                        if let Ok(score) = batch
                            .lock()
                            .await
                            .score(user, data, enabled("feature.spam_model_batch_load"))
                            .await
                        {
                            if score > 0.7 {
                                params["p_spam_score"] =
                                    json!(params["p_spam_score"].as_f64().unwrap_or(0.0).max(7.0));
                                append_symbol(&mut params, "FTRL_SPAM");
                            }
                        }
                    }
                }
            }
        }
        if dmarc.quarantine {
            let score = params["p_spam_score"].as_f64().unwrap_or(0.0).max(10.0);
            params["p_spam_score"] = json!(score);
            params["p_dmarc_result"] = json!("fail");
        }
        if let Some(blobs) = &self.blobs {
            blobs.put(&raw_ref, data).await?
        }
        conn.batch("BEGIN").await?;
        let features = &self.features;
        for (name, enabled) in [
            ("app.skip_rules", features.rules),
            ("app.skip_vacation", features.vacation),
            ("app.skip_journaling", features.journaling),
            ("app.skip_retention", features.retention),
            ("app.skip_fts", features.full_text_search),
            ("app.skip_audit", features.audit),
            (
                "app.skip_external_sender_first_time",
                features.external_first_time,
            ),
        ] {
            if !enabled || name == "app.skip_fts" {
                let value = if enabled { "false" } else { "true" };
                conn.query(
                    "SELECT set_config($1,$2,true)",
                    &[(&name, Type::TEXT), (&value, Type::TEXT)],
                )
                .await?;
            }
        }
        // Go's encoding/json emits integral float64 scores without `.0`.
        // The verbatim moderation replay payload exposes that representation.
        let score = params["p_spam_score"].as_f64().unwrap_or(0.0);
        if score.fract() == 0.0 && score.abs() < (1u64 << 53) as f64 {
            params["p_spam_score"] = json!(score as i64);
        }
        let params = params.to_string();
        let moderation =
            enabled("approval.group_moderation") && !crate::mutants::on("inbound-no-moderation");
        let condemned = if crate::mutants::on("inbound-no-condemnation") {
            Vec::new()
        } else {
            condemned
        };
        let rows = if !condemned.is_empty() || moderation {
            conn.query_detailed("SELECT message_id,subject_user_id,subject_mailbox_id,publication_enrolled,outcome FROM rust_smtp_inbound_security($1::jsonb,$2,$3,$4,convert_from($5::bytea,'UTF8'))",&[(&params,Type::TEXT),(&from,Type::TEXT),(&to,Type::TEXT),(&moderation,Type::BOOL),(&condemned,Type::BYTEA)]).await.map_err(Failure::Database)?
        } else {
            conn.query_detailed("SELECT message_id,subject_user_id,subject_mailbox_id,publication_enrolled,'delivered'::text FROM smtp_inbound_deliver($1::jsonb,$2,$3)",&[(&params,Type::TEXT),(&from,Type::TEXT),(&to,Type::TEXT)]).await.map_err(Failure::Database)?
        };
        match rows[0].get::<_, String>(4).as_str() {
            "rejected" => {
                conn.batch("ROLLBACK").await?;
                return Err(Failure::GroupRejected);
            }
            "deferred" => {
                conn.batch("ROLLBACK").await?;
                return Err(Failure::Other);
            }
            _ => {}
        }
        // Never acknowledge a lost commit. Connection drop rolls back pre-commit errors.
        conn.batch("COMMIT").await?;
        let row = &rows[0];
        if row.get::<_, Option<i64>>(0).is_some() && !row.get::<_, bool>(3) {
            if let (Some(events), Some(user), Some(mailbox)) = (
                &self.events,
                row.get::<_, Option<i64>>(1),
                row.get::<_, Option<i64>>(2),
            ) {
                events.received(user, mailbox, from, to).await;
            }
        }
        if row.get::<_,Option<i64>>(0).is_some() {
            crate::inbound::imip::process(&self.inbound,&conn, body_message, crate::inbound::imip::Transport {envelope:from,from:&sender,spf:self.spf=="pass",dkim:&dkim,recipients:&self.recipients,to}).await;
        }
        Ok(Accepted::Normal)
    }
}
fn append_symbol(params: &mut Value, symbol: &str) {
    let mut symbols = params["p_spam_headers"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    symbols.push(json!(symbol));
    params["p_spam_headers"] = json!(symbols);
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn crypto_type(ct: &str) -> &'static str {
    let ct = ct.to_lowercase();
    if ct.contains("application/pkcs7-mime") {
        if ct.contains("smime-type=signed-data") {
            return "smime-signed";
        }
        return "smime-encrypted";
    }
    for (needle, kind) in [
        ("application/pkcs7-signature", "smime-signed"),
        ("application/pgp-encrypted", "pgp-encrypted"),
        ("application/pgp-signature", "pgp-signed"),
    ] {
        if ct.contains(needle) {
            return kind;
        }
    }
    "none"
}
pub(crate) enum Accepted {
    Normal,
    PhishDrop,
}
pub(crate) enum Failure {
    GroupRejected,
    DmarcAntiPhishRejected,
    AntiPhishRejected,
    DmarcRejected,
    Database(setjoin_pg::StatementFailure),
    Other,
}
impl From<String> for Failure {
    fn from(_: String) -> Self {
        Self::Other
    }
}
impl From<&str> for Failure {
    fn from(_: &str) -> Self {
        Self::Other
    }
}
pub(crate) fn failure(error: &Failure) -> &'static str {
    match error {
        Failure::GroupRejected => {
            "550 5.7.1 Message rejected: sender not permitted to post to this group\r\n"
        }
        Failure::DmarcAntiPhishRejected | Failure::AntiPhishRejected => {
            "550 Message rejected per anti-phishing policy\r\n"
        }
        Failure::DmarcRejected => "550 Message rejected per DMARC policy\r\n",
        Failure::Database(error) => crate::reducer_reply::project(error),
        Failure::Other => crate::reducer_reply::TEMPORARY,
    }
}
