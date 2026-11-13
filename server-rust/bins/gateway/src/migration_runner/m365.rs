//! Frozen Graph/OAuth source session (#446). No Microsoft SDK is required at runtime.
use super::{
    ews::{bounded, empty},
    Batch, Change, Checkpoint, ItemKind,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};

pub type M365Config = setjoin_mailboxes::migration::M365;
pub struct M365Connector {
    cfg: M365Config,
    client: reqwest::Client,
    token: Option<(String, Instant)>,
    links: BTreeMap<String, String>,
    categories: Option<Vec<String>>,
    category: usize,
}
fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k).and_then(Value::as_str).unwrap_or("")
}
fn path(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes())
        .collect::<String>()
        .replace('+', "%20")
        .replace("%3A", ":")
        .replace("%40", "@")
        .replace("%26", "&")
        .replace("%3D", "=")
        .replace("%2B", "+")
        .replace("%24", "$")
}
fn form(s: &str) -> String {
    url::form_urlencoded::Serializer::new(String::new())
        .append_pair("", s)
        .finish()
        .trim_start_matches('=')
        .into()
}
impl M365Connector {
    pub fn new(cfg: M365Config) -> Result<Self, String> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(60))
            .build()
            .map_err(|e| e.to_string())?;
        Ok(Self::with_client(cfg, client))
    }
    pub fn with_client(cfg: M365Config, client: reqwest::Client) -> Self {
        Self {
            cfg,
            client,
            token: None,
            links: BTreeMap::new(),
            categories: None,
            category: 0,
        }
    }
    fn auth_base(&self) -> &'static str {
        if self.cfg.cloud == "china" {
            "https://login.chinacloudapi.cn"
        } else {
            "https://login.microsoftonline.com"
        }
    }
    fn graph_base(&self) -> &'static str {
        if self.cfg.cloud == "china" {
            "https://microsoftgraph.chinacloudapi.cn"
        } else {
            "https://graph.microsoft.com"
        }
    }
    async fn access_token(&mut self) -> Result<String, String> {
        if let Some((token, until)) = &self.token {
            if *until > Instant::now() + Duration::from_secs(10) {
                return Ok(token.clone());
            }
        }
        let url = format!(
            "{}/{}/oauth2/v2.0/token",
            self.auth_base(),
            self.cfg.tenant_id
        );
        let scope = format!("{}/.default", self.graph_base());
        let mut last = String::new();
        // oauth2/clientcredentials discovers the server's client authentication style.
        for in_body in [false, true] {
            let mut pairs = vec![
                ("grant_type", "client_credentials"),
                ("scope", scope.as_str()),
            ];
            if in_body {
                pairs.extend([
                    ("client_id", self.cfg.client_id.as_str()),
                    ("client_secret", self.cfg.client_secret.as_str()),
                ]);
            }
            let body = url::form_urlencoded::Serializer::new(String::new())
                .extend_pairs(pairs)
                .finish();
            let mut request = self
                .client
                .post(&url)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(body);
            if !in_body {
                request = request.header(
                    "authorization",
                    format!(
                        "Basic {}",
                        STANDARD.encode(format!(
                            "{}:{}",
                            form(&self.cfg.client_id),
                            form(&self.cfg.client_secret)
                        ))
                    ),
                );
            }
            let response = request.send().await.map_err(|e| e.to_string())?;
            let status = response.status();
            let text = String::from_utf8_lossy(
                &bounded(response, 1 << 20, "oauth2: token response exceeds limit").await?,
            )
            .into_owned();
            if !status.is_success() {
                last = format!(
                    "oauth2: cannot fetch token: {} {}\nResponse: {text}",
                    status.as_u16(),
                    status.canonical_reason().unwrap_or("")
                );
                continue;
            }
            let v: Value = serde_json::from_str(&text)
                .map_err(|e| format!("oauth2: cannot parse json: {e}"))?;
            let token = s(&v, "access_token");
            if token.is_empty() {
                return Err("oauth2: server response missing access_token".into());
            }
            let expires = v["expires_in"]
                .as_u64()
                .or_else(|| v["expires_in"].as_str().and_then(|s| s.parse().ok()))
                .unwrap_or(3600);
            self.token = Some((
                token.into(),
                Instant::now() + Duration::from_secs(expires.min(315360000)),
            ));
            return Ok(token.into());
        }
        Err(last)
    }
    pub async fn test_connection(&mut self) -> Result<(), String> {
        let bytes = self
            .get(
                &format!("{}/v1.0/users?$top=1", self.graph_base()),
                "application/json",
                false,
            )
            .await
            .map_err(|e| {
                format!(
                    "graph test connection: {}",
                    e.strip_prefix("Graph token: ")
                        .map(|e| format!("m365 token: {e}"))
                        .unwrap_or(e)
                )
            })?;
        let page: Value =
            serde_json::from_slice(&bytes).map_err(|e| format!("graph test connection: {e}"))?;
        if page["value"].as_array().is_none_or(Vec::is_empty) {
            return Err("no users found in tenant — verify permissions".into());
        }
        Ok(())
    }
    async fn user(&mut self) -> Result<String, String> {
        if !self.cfg.source_user_id.trim().is_empty() {
            return Ok(self.cfg.source_user_id.trim().into());
        }
        let selector = self.cfg.source_email.trim();
        if selector.is_empty() {
            return Err("M365 source mailbox selector is required".into());
        }
        let url = format!(
            "{}/v1.0/users/{}?$select=id,mail,userPrincipalName",
            self.graph_base(),
            url::form_urlencoded::byte_serialize(selector.as_bytes())
                .collect::<String>()
                .replace('+', "%20")
        );
        let bytes = self
            .get(&url, "application/json", false)
            .await
            .map_err(|e| {
                format!(
                    "resolve M365 source mailbox {}: {e}",
                    super::imap::go_quote(&self.cfg.source_email)
                )
            })?;
        let value: Value = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
        let user = s(&value, "id");
        if user.is_empty() {
            return Err("resolved M365 source mailbox has no immutable user id".into());
        }
        self.cfg.source_user_id = user.into();
        Ok(user.into())
    }
    pub async fn identity(&mut self) -> Result<(String, String), String> {
        use sha2::{Digest, Sha256};
        let user = self.user().await?;
        let selector = self.cfg.source_email.trim().to_lowercase();
        let selector = if selector.is_empty() {
            &user
        } else {
            &selector
        };
        Ok((
            format!("m365:{user}"),
            super::imap::hex(&Sha256::digest(format!("m365\0{selector}"))),
        ))
    }
    pub fn restore(
        &mut self,
        legacy: &BTreeMap<String, String>,
        durable: &[(String, String, Value)],
    ) -> Result<(), String> {
        for (scope, link) in legacy {
            if !link.is_empty() {
                self.pinned(link, true).map_err(|e| {
                    format!(
                        "restore M365 checkpoint {}: {e}",
                        super::imap::go_quote(scope)
                    )
                })?;
            }
        }
        self.links = legacy.clone();
        for (scope, kind, v) in durable {
            if kind != "m365_delta_link" {
                return Err(format!(
                    "restore source checkpoint {}: kind {} is not \"m365_delta_link\"",
                    super::imap::go_quote(scope),
                    super::imap::go_quote(kind)
                ));
            }
            let value = v.as_str().filter(|s| !s.is_empty()).ok_or_else(|| {
                format!(
                    "restore M365 checkpoint {}: invalid delta link",
                    super::imap::go_quote(scope)
                )
            })?;
            self.pinned(value, true).map_err(|e| {
                format!(
                    "restore M365 checkpoint {}: {e}",
                    super::imap::go_quote(scope)
                )
            })?;
            self.links.insert(scope.clone(), value.into());
        }
        Ok(())
    }
    /// #536 (owner-approved divergence from frozen Go, which sent the bearer token to any
    /// `@odata.nextLink`): every Graph request, continuation and restored delta link must be
    /// https, on the Graph host of the configured cloud, on the default port, without userinfo.
    fn pinned(&self, link: &str, restoring: bool) -> Result<(), String> {
        if setjoin_contracts::mutants::on(if restoring {
            "m365-restore-any-origin"
        } else {
            "m365-bearer-any-origin"
        }) {
            return Ok(());
        }
        let base = url::Url::parse(self.graph_base()).map_err(|e| e.to_string())?;
        let refuse = |why: &str| {
            Err(format!(
                "refusing Graph link: {why} (links must stay on https://{})",
                base.host_str().unwrap_or_default()
            ))
        };
        let Ok(parsed) = url::Url::parse(link) else {
            return refuse("not an absolute URL");
        };
        if parsed.scheme() != "https" {
            return refuse("scheme is not https");
        }
        // Mutant `m365-cross-cloud`: accept either cloud's Graph host.
        let other_cloud = setjoin_contracts::mutants::on("m365-cross-cloud")
            && matches!(
                parsed.host_str(),
                Some("graph.microsoft.com" | "microsoftgraph.chinacloudapi.cn")
            );
        if parsed.host_str() != base.host_str() && !other_cloud {
            return refuse("host is not the Graph host");
        }
        if parsed.port().is_some() {
            return refuse("port is not the default port");
        }
        if !parsed.username().is_empty() || parsed.password().is_some() {
            return refuse("link carries userinfo");
        }
        Ok(())
    }
    async fn get(&mut self, url: &str, accept: &str, immutable: bool) -> Result<Vec<u8>, String> {
        self.pinned(url, false)?;
        for attempt in 0..5 {
            let token = self
                .access_token()
                .await
                .map_err(|e| format!("Graph token: {e}"))?;
            let mut req = self
                .client
                .get(url)
                .bearer_auth(token)
                .header("accept", accept);
            if immutable {
                req = req.header("Prefer", "IdType=\"ImmutableId\"");
            }
            let response = match req.send().await {
                Ok(r) => r,
                Err(e) => {
                    if attempt == 4 {
                        return Err(e.to_string());
                    }
                    tokio::time::sleep(Duration::from_secs(1 << attempt)).await;
                    continue;
                }
            };
            let status = response.status().as_u16();
            let delay = response
                .headers()
                .get("retry-after")
                .and_then(|s| s.to_str().ok())
                .map(|s| s.to_owned());
            let max = if accept == "text/plain" {
                50 << 20
            } else {
                64 << 20
            };
            let body = bounded(
                response,
                max,
                &format!("Graph response exceeds {max}-byte limit"),
            )
            .await?;
            if (200..300).contains(&status) {
                return Ok(body);
            }
            if !matches!(status, 429 | 503 | 504) {
                return Err(format!(
                    "Graph returned {status}: {}",
                    String::from_utf8_lossy(&body[..body.len().min(500)]).trim()
                ));
            }
            if attempt == 4 {
                return Err(format!(
                    "Graph retry budget exhausted after status {status}"
                ));
            }
            let delay = delay
                .as_deref()
                .and_then(|s| {
                    s.trim()
                        .parse::<u64>()
                        .ok()
                        .map(Duration::from_secs)
                        .or_else(|| {
                            httpdate::parse_http_date(s).ok().map(|t| {
                                t.duration_since(std::time::SystemTime::now())
                                    .unwrap_or_default()
                            })
                        })
                })
                .unwrap_or(Duration::from_secs(1 << attempt))
                .min(Duration::from_secs(30));
            tokio::time::sleep(delay).await;
        }
        unreachable!()
    }
    async fn initialize(&mut self) -> Result<(), String> {
        if self.links.is_empty() {
            let user = path(&self.user().await?);
            let base = format!("{}/v1.0/users/{user}", self.graph_base());
            for folder in ["deleteditems", "drafts", "inbox", "junkemail", "sentitems"] {
                self.links.insert(format!("messages:{folder}"),format!("{base}/mailFolders/{folder}/messages/delta?$select=id,changeKey,parentFolderId&$top=100"));
            }
            self.links.insert(
                "events".into(),
                format!("{base}/events?$select=id,changeKey,subject,iCalUId&$top=100"),
            );
            let select="id,changeKey,displayName,givenName,surname,companyName,jobTitle,businessPhones,mobilePhone,homePhones,emailAddresses";
            if self.cfg.cloud == "china" {
                self.links.insert(
                    "contacts".into(),
                    format!("{base}/contacts?$select={select}&$top=100"),
                );
            } else {
                let mut link = format!("{base}/contactFolders?$select=id&$top=100");
                let mut folders = vec![];
                while !link.is_empty() {
                    let raw = self
                        .get(&link, "application/json", false)
                        .await
                        .map_err(|e| format!("list contact folders: {e}"))?;
                    let page: Value = serde_json::from_slice(&raw)
                        .map_err(|e| format!("parse contact folders: {e}"))?;
                    for item in page["value"].as_array().into_iter().flatten() {
                        let id = s(item, "id");
                        if id.is_empty() {
                            return Err("contact folder omitted immutable id".into());
                        }
                        folders.push(id.to_owned());
                    }
                    link = s(&page, "@odata.nextLink").into();
                }
                folders.sort();
                for folder in folders {
                    self.links.insert(
                        format!("contacts:{folder}"),
                        format!(
                            "{base}/contactFolders/{}/contacts/delta?$select={select}&$top=100",
                            path(&folder)
                        ),
                    );
                }
            }
        }
        self.categories = Some(self.links.keys().cloned().collect());
        Ok(())
    }
    pub async fn next_batch(&mut self) -> Result<Option<Batch>, String> {
        if self.categories.is_none() {
            self.initialize().await?;
        }
        let Some(category) = self
            .categories
            .as_ref()
            .and_then(|c| c.get(self.category))
            .cloned()
        else {
            return Ok(None);
        };
        let link = self.links.get(&category).cloned().unwrap_or_default();
        if link.is_empty() {
            self.category += 1;
            return Box::pin(self.next_batch()).await;
        }
        let raw = self
            .get(&link, "application/json", true)
            .await
            .map_err(|e| format!("delta request: {e}"))?;
        let page: Value =
            serde_json::from_slice(&raw).map_err(|e| format!("parse delta response: {e}"))?;
        let values = page["value"].as_array().cloned().unwrap_or_default();
        if values.len() > 100 {
            return Err(format!(
                "M365 page contains {} items; maximum is 100",
                values.len()
            ));
        }
        let mut items = vec![];
        for v in values {
            let id = s(&v, "id");
            if id.is_empty() {
                return Err(format!("delta {category} object omitted immutable id"));
            }
            let kind = if category.starts_with("messages") {
                ItemKind::Mail
            } else if category == "events" {
                ItemKind::Calendar
            } else if category.starts_with("contacts") {
                ItemKind::Contact
            } else {
                return Err(format!(
                    "unknown M365 delta category {}",
                    super::imap::go_quote(&category)
                ));
            };
            let mut item = empty(kind);
            item.object_id = id.into();
            item.version = s(&v, "changeKey").into();
            if v.get("@removed").is_some() {
                item.change = Change::Delete;
            }
            if kind == ItemKind::Mail {
                item.folder_id = s(&v, "parentFolderId").into();
                if item.folder_id.is_empty() {
                    item.folder_id = category.trim_start_matches("messages:").into();
                }
                if item.change != Change::Delete {
                    let user = path(&self.user().await?);
                    let url = format!(
                        "{}/v1.0/users/{user}/messages/{}/$value",
                        self.graph_base(),
                        path(id)
                    );
                    item.raw = self.get(&url, "text/plain", true).await.map_err(|e| {
                        format!("download delta message {}: {e}", super::imap::go_quote(id))
                    })?;
                    let tag = match category.trim_start_matches("messages:") {
                        "inbox" => "Inbox",
                        "sentitems" => "Sent",
                        "drafts" => "Drafts",
                        "deleteditems" => "Trash",
                        "junkemail" => "Spam",
                        _ => match s(&v, "parentFolderId") {
                            "sentitems" => "sent",
                            "drafts" => "drafts",
                            "deleteditems" => "trash",
                            "junkemail" => "spam",
                            _ => "inbox",
                        },
                    };
                    item.tags = vec![tag.into()];
                    item.folder_path = vec![tag.into()];
                }
            } else if item.change != Change::Delete {
                if kind == ItemKind::Calendar {
                    item.ics = event_ics(&v);
                } else {
                    item.vcf = contact_vcf(&v);
                }
            }
            items.push(item);
        }
        let next = s(&page, "@odata.nextLink");
        let delta = s(&page, "@odata.deltaLink");
        for link in [next, delta].into_iter().filter(|l| !l.is_empty()) {
            self.pinned(link, false)
                .map_err(|e| format!("delta response: {e}"))?;
        }
        let ordinary = next.is_empty()
            && delta.is_empty()
            && (category == "events" || (self.cfg.cloud == "china" && category == "contacts"));
        let checkpoint = if !delta.is_empty() {
            delta
        } else if !next.is_empty() {
            next
        } else if ordinary {
            &link
        } else {
            return Err(format!(
                "M365 delta page {} omitted continuation",
                super::imap::go_quote(&category)
            ));
        };
        let checkpoint = checkpoint.to_owned();
        self.links.insert(category.clone(), checkpoint.clone());
        if !delta.is_empty() || ordinary {
            self.category += 1;
        }
        Ok(Some(Batch {
            items,
            checkpoint: Checkpoint::Delta {
                scope: category.clone(),
                legacy_scope: category.clone(),
                kind: "m365_delta_link",
                value: json!(checkpoint),
                legacy: json!({"delta":{category:checkpoint}}),
            },
        }))
    }
}
fn escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace(';', "\\;")
        .replace(',', "\\,")
        .replace('\n', "\\n")
        .replace('\r', "")
}
fn datetime(v: &Value) -> String {
    let input = s(v, "dateTime");
    let parsed = chrono::NaiveDateTime::parse_from_str(input, "%Y-%m-%dT%H:%M:%S%.f");
    let Ok(t) = parsed else {
        return String::new();
    };
    let time = t.format("%Y%m%dT%H%M%S");
    let zone = s(v, "timeZone");
    if zone.is_empty() || zone == "UTC" {
        format!("{time}Z")
    } else {
        format!("TZID={zone}:{time}")
    }
}
fn event_ics(v: &Value) -> String {
    let mut lines = vec![
        "BEGIN:VCALENDAR".into(),
        "VERSION:2.0".into(),
        "PRODID:-//Mailserver//Migration//EN".into(),
        "BEGIN:VEVENT".into(),
    ];
    let uid = if s(v, "iCalUId").is_empty() {
        s(v, "id")
    } else {
        s(v, "iCalUId")
    };
    if !uid.is_empty() {
        lines.push(format!("UID:{uid}"));
    }
    if v["subject"].is_string() {
        lines.push(format!("SUMMARY:{}", escape(s(v, "subject"))));
    }
    for (key, prop) in [("start", "DTSTART"), ("end", "DTEND")] {
        let dt = datetime(&v[key]);
        if !dt.is_empty() {
            lines.push(format!("{prop}:{dt}"));
        }
    }
    for (key, field, prop) in [
        ("body", "content", "DESCRIPTION"),
        ("location", "displayName", "LOCATION"),
    ] {
        let value = s(&v[key], field);
        if !value.is_empty() {
            lines.push(format!("{prop}:{}", escape(value)));
        }
    }
    lines.extend(["END:VEVENT".into(), "END:VCALENDAR".into(), String::new()]);
    lines.join("\r\n")
}
fn contact_vcf(v: &Value) -> String {
    let mut lines = vec!["BEGIN:VCARD".into(), "VERSION:3.0".into()];
    if !s(v, "displayName").is_empty() {
        lines.push(format!("FN:{}", escape(s(v, "displayName"))));
    }
    if v["givenName"].is_string() {
        lines.push(format!(
            "N:{};{};;;",
            escape(s(v, "surname")),
            escape(s(v, "givenName"))
        ));
    }
    for value in v["emailAddresses"].as_array().into_iter().flatten() {
        if !s(value, "address").is_empty() {
            lines.push(format!("EMAIL:{}", escape(s(value, "address"))));
        }
    }
    for value in v["businessPhones"].as_array().into_iter().flatten() {
        if let Some(s) = value.as_str().filter(|s| !s.is_empty()) {
            lines.push(format!("TEL;TYPE=WORK:{}", escape(s)));
        }
    }
    if !s(v, "jobTitle").is_empty() {
        lines.push(format!("TITLE:{}", escape(s(v, "jobTitle"))));
    }
    lines.extend(["END:VCARD".into(), String::new()]);
    lines.join("\r\n")
}
