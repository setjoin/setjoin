//! Exchange Web Services: bounded SOAP pages and NTLMv2 over HTTP/1.1 (#446).
use super::{Batch, Change, Checkpoint, ItemKind, SourceItem};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
    time::Duration,
};

#[derive(Clone, Default)]
pub struct EwsConfig {
    pub server_url: String,
    pub username: String,
    pub password: String,
    pub impersonate_as: String,
    pub insecure_skip_verify: bool,
    pub private_hosts: Vec<String>,
    pub private_cidrs: Vec<String>,
}
struct PolicyResolver {
    hosts: Vec<String>,
    cidrs: Vec<String>,
}
impl reqwest::dns::Resolve for PolicyResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let (host, hosts, cidrs) = (
            name.as_str().to_owned(),
            self.hosts.clone(),
            self.cidrs.clone(),
        );
        Box::pin(async move {
            let addresses: Vec<_> = tokio::net::lookup_host((host.as_str(), 0)).await?.collect();
            if addresses.is_empty()
                || addresses.iter().any(|a| {
                    !setjoin_mailboxes::private_policy::dial_allowed(&hosts, &cidrs, &host, a.ip())
                })
            {
                return Err(std::io::Error::other(super::UNSAFE).into());
            }
            Ok(Box::new(addresses.into_iter()) as reqwest::dns::Addrs)
        })
    }
}
#[derive(Clone)]
struct Folder {
    id: String,
    name: String,
    kind: ItemKind,
}
pub struct EwsConnector {
    cfg: EwsConfig,
    client: reqwest::Client,
    folders: Option<Vec<Folder>>,
    folder: usize,
    states: BTreeMap<String, String>,
    legacy: BTreeMap<String, String>,
    reset: bool,
}
impl EwsConnector {
    fn validate(cfg: &EwsConfig) -> Result<(), String> {
        setjoin_mailboxes::private_policy::compile_private_policy(
            &cfg.private_hosts,
            &cfg.private_cidrs,
        )
        .map_err(|e| format!("invalid EWS source policy: {e}"))?;
        setjoin_mailboxes::private_policy::validate_ews_url(&cfg.server_url, &cfg.private_hosts)
            .map_err(|e| format!("invalid EWS server URL: {e}"))
    }
    pub fn new(cfg: EwsConfig) -> Result<Self, String> {
        Self::validate(&cfg)?;
        let client = reqwest::Client::builder()
            .no_proxy()
            .http1_only()
            .pool_max_idle_per_host(1)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(300))
            .connect_timeout(Duration::from_secs(10))
            .danger_accept_invalid_certs(cfg.insecure_skip_verify)
            .dns_resolver(Arc::new(PolicyResolver {
                hosts: cfg.private_hosts.clone(),
                cidrs: cfg.private_cidrs.clone(),
            }))
            .build()
            .map_err(|e| e.to_string())?;
        Self::with_client(cfg, client)
    }
    /// Inject a trusted transport (the oracle supplies its private CA and DNS).
    pub fn with_client(cfg: EwsConfig, client: reqwest::Client) -> Result<Self, String> {
        Self::validate(&cfg)?;
        Ok(Self {
            cfg,
            client,
            folders: None,
            folder: 0,
            states: BTreeMap::new(),
            legacy: BTreeMap::new(),
            reset: false,
        })
    }
    pub fn identity(&self) -> Result<(String, String), String> {
        use sha2::{Digest, Sha256};
        let mut selector = self.cfg.impersonate_as.trim();
        if selector.is_empty() {
            selector = self.cfg.username.trim();
        }
        if selector.is_empty() {
            return Err("EWS source mailbox selector is required".into());
        }
        let digest = super::imap::hex(&Sha256::digest(format!(
            "ews\0{}\0{}",
            self.cfg.server_url.to_lowercase(),
            selector.to_lowercase()
        )));
        Ok((format!("ews:{digest}"), digest))
    }
    pub fn restore(
        &mut self,
        legacy: &BTreeMap<String, String>,
        durable: &[(String, String, Value)],
    ) -> Result<(), String> {
        self.legacy = legacy.clone();
        for (scope, kind, v) in durable {
            if kind != "ews_sync_state" {
                return Err(format!(
                    "restore source checkpoint {}: kind {} is not \"ews_sync_state\"",
                    super::imap::go_quote(scope),
                    super::imap::go_quote(kind)
                ));
            }
            let value = v.as_str().filter(|s| !s.is_empty()).ok_or_else(|| {
                format!(
                    "restore EWS checkpoint {}: invalid sync state",
                    super::imap::go_quote(scope)
                )
            })?;
            self.states.insert(scope.clone(), value.into());
        }
        Ok(())
    }
    fn envelope(&self, body: &str) -> String {
        let impersonation = if self.cfg.impersonate_as.is_empty() {
            String::new()
        } else {
            format!("<t:ExchangeImpersonation><t:ConnectingSID><t:PrimarySmtpAddress>{}</t:PrimarySmtpAddress></t:ConnectingSID></t:ExchangeImpersonation>",escape(&self.cfg.impersonate_as))
        };
        format!("<?xml version=\"1.0\" encoding=\"utf-8\"?><soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:t=\"http://schemas.microsoft.com/exchange/services/2006/types\" xmlns:m=\"http://schemas.microsoft.com/exchange/services/2006/messages\"><soap:Header><t:RequestServerVersion Version=\"Exchange2016\"/>{impersonation}</soap:Header><soap:Body>{body}</soap:Body></soap:Envelope>")
    }
    fn folder_body(name: &str) -> String {
        format!("<m:GetFolder><m:FolderShape><t:BaseShape>Default</t:BaseShape></m:FolderShape><m:FolderIds><t:DistinguishedFolderId Id=\"{name}\"/></m:FolderIds></m:GetFolder>")
    }
    pub async fn test_connection(&self) -> Result<(), String> {
        self.soap(&Self::folder_body("inbox")).await.map(|_| ())
    }
    async fn send(&self, body: &str, authorization: &str) -> Result<reqwest::Response, String> {
        let mut request = self
            .client
            .post(&self.cfg.server_url)
            .header("content-type", "text/xml; charset=utf-8")
            .body(self.envelope(body));
        if !authorization.is_empty() {
            request = request.header("authorization", authorization);
        }
        if !self.cfg.impersonate_as.is_empty() {
            request = request.header("X-AnchorMailbox", &self.cfg.impersonate_as);
        }
        request
            .send()
            .await
            .map_err(|e| format!("ews request: {e}"))
    }
    async fn soap(&self, body: &str) -> Result<String, String> {
        let mut response = self.send(body, "").await?;
        if response.status() == reqwest::StatusCode::UNAUTHORIZED {
            let has_scheme = |scheme: &str| {
                response
                    .headers()
                    .get_all("www-authenticate")
                    .iter()
                    .any(|v| {
                        v.to_str()
                            .unwrap_or("")
                            .split(',')
                            .any(|s| s.trim().starts_with(scheme))
                    })
            };
            let scheme = if has_scheme("Negotiate") {
                Some("Negotiate")
            } else if has_scheme("NTLM") {
                Some("NTLM")
            } else {
                None
            };
            if let Some(scheme) = scheme {
                let _ = bounded(response, 16 << 20, "EWS response exceeds 16 MiB limit").await?;
                use negotiate_auth::{Entropy, Handshake, Identity, Scheme};
                let mut nonce = [0u8; 8];
                ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut nonce)
                    .map_err(|_| "random")?;
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_err(|e| e.to_string())?;
                let entropy = Entropy::from_unix_time(nonce, now);
                let mut handshake = Handshake::new(
                    Scheme::Ntlm,
                    Identity::new(&self.cfg.username, self.cfg.password.clone()),
                    entropy.clone(),
                );
                let initial = handshake.initial().map_err(|e| e.to_string())?;
                let token = initial
                    .strip_prefix("NTLM ")
                    .ok_or("NTLM negotiate token missing")?;
                let challenge = self.send(body, &format!("{scheme} {token}")).await?;
                let header = challenge
                    .headers()
                    .get_all("www-authenticate")
                    .iter()
                    .filter_map(|v| v.to_str().ok())
                    .flat_map(|v| v.split(','))
                    .find_map(|v| v.trim().strip_prefix(&format!("{scheme} ")))
                    .ok_or("NTLM challenge missing")?
                    .to_owned();
                let _ = bounded(challenge, 16 << 20, "EWS response exceeds 16 MiB limit").await?;
                let bytes = STANDARD.decode(&header).map_err(|e| e.to_string())?;
                // Go infers the challenge target for an unqualified account name.
                if !self.cfg.username.contains(['\\', '@']) {
                    if let Some(domain) = challenge_target(&bytes) {
                        handshake = Handshake::new(
                            Scheme::Ntlm,
                            Identity::with_domain(
                                domain,
                                &self.cfg.username,
                                self.cfg.password.clone(),
                            ),
                            entropy,
                        );
                        handshake.initial().map_err(|e| e.to_string())?;
                    }
                }
                let reply = handshake
                    .advance(&format!("NTLM {header}"))
                    .map_err(|e| e.to_string())?;
                let reply = reply
                    .strip_prefix("NTLM ")
                    .ok_or("NTLM authentication token missing")?;
                response = self.send(body, &format!("{scheme} {reply}")).await?;
            }
        }
        let status = response.status().as_u16();
        let bytes = bounded(response, 16 << 20, "EWS response exceeds 16 MiB limit").await?;
        if status >= 400 {
            return Err(format!("EWS HTTP {status}"));
        }
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }
    pub async fn next_batch(&mut self) -> Result<Option<Batch>, String> {
        if self.folders.is_none() {
            let mut folders = vec![];
            for (name, kind) in [
                ("inbox", ItemKind::Mail),
                ("sentitems", ItemKind::Mail),
                ("drafts", ItemKind::Mail),
                ("deleteditems", ItemKind::Mail),
                ("junkemail", ItemKind::Mail),
                ("calendar", ItemKind::Calendar),
                ("contacts", ItemKind::Contact),
            ] {
                if let Ok(body) = self.soap(&Self::folder_body(name)).await {
                    if let Some(at) = body.find("<t:FolderId") {
                        let id = raw_attr(&body[at..], "Id"); // Go's folder parser does not unescape.
                        if !id.is_empty() {
                            folders.push(Folder {
                                id,
                                name: name.into(),
                                kind,
                            });
                        }
                    }
                }
            }
            for f in &folders {
                if let Some(legacy) = self.legacy.get(&f.name) {
                    if folders
                        .iter()
                        .any(|other| other.id != f.id && other.name == f.name)
                    {
                        return Err(format!(
                            "EWS legacy checkpoint display name {} is ambiguous",
                            super::imap::go_quote(&f.name)
                        ));
                    }
                    if self
                        .states
                        .get(&f.id)
                        .is_some_and(|s| !s.is_empty() && s != legacy)
                    {
                        return Err(format!(
                            "EWS durable and legacy checkpoints disagree for folder {}",
                            super::imap::go_quote(&f.id)
                        ));
                    }
                    self.states.insert(f.id.clone(), legacy.clone());
                }
            }
            self.folders = Some(folders);
        }
        let Some(folder) = self
            .folders
            .as_ref()
            .and_then(|f| f.get(self.folder))
            .cloned()
        else {
            return Ok(None);
        };
        loop {
            let state = self.states.get(&folder.id).cloned().unwrap_or_default();
            let body=format!("<m:SyncFolderItems><m:ItemShape><t:BaseShape>IdOnly</t:BaseShape><t:IncludeMimeContent>true</t:IncludeMimeContent></m:ItemShape><m:SyncFolderId><t:FolderId Id=\"{}\"/></m:SyncFolderId><m:SyncState>{state}</m:SyncState><m:MaxChangesReturned>100</m:MaxChangesReturned></m:SyncFolderItems>",folder.id);
            let response = self
                .soap(&body)
                .await
                .map_err(|e| format!("SyncFolderItems {}: {e}", folder.id))?;
            if response.contains("ErrorInvalidSyncStateData")
                || response.contains("ErrorInvalidWatermark")
            {
                if !state.is_empty() && !self.reset {
                    self.states.remove(&folder.id);
                    self.reset = true;
                    continue;
                }
                return Err(format!(
                    "parse SyncFolderItems {}: EWS SyncState is invalid or expired",
                    folder.id
                ));
            }
            if response.contains("ResponseClass=\"Error\"") {
                return Err(format!(
                    "parse SyncFolderItems {}: EWS SyncFolderItems returned an error response",
                    folder.id
                ));
            }
            let state = element(&response, "m:SyncState").unwrap_or_default();
            if state.is_empty() {
                return Err(format!("SyncFolderItems {} omitted SyncState", folder.id));
            }
            let mut changes = vec![];
            let mut remaining = response.as_str();
            while let Some((at, tag)) = ["Create", "Update", "Delete"]
                .iter()
                .filter_map(|tag| remaining.find(&format!("<t:{tag}>")).map(|at| (at, *tag)))
                .min_by_key(|x| x.0)
            {
                let close = format!("</t:{tag}>");
                let Some(end) = remaining[at..].find(&close) else {
                    break;
                };
                let block = &remaining[at..at + end + close.len()];
                let id = attr(block, "Id");
                if id.is_empty() {
                    return Err(format!(
                        "SyncFolderItems {} returned change without ItemId",
                        folder.id
                    ));
                }
                changes.push((id, attr(block, "ChangeKey"), tag == "Delete"));
                remaining = &remaining[at + end + close.len()..];
            }
            let fetch: Vec<_> = changes
                .iter()
                .filter(|c| !c.2)
                .map(|c| c.0.as_str())
                .collect();
            let mut fetched = HashMap::new();
            for ids in fetch.chunks(50) {
                let xml = ids
                    .iter()
                    .map(|id| format!("<t:ItemId Id=\"{id}\"/>"))
                    .collect::<String>();
                let body=format!("<m:GetItem><m:ItemShape><t:BaseShape>IdOnly</t:BaseShape><t:IncludeMimeContent>true</t:IncludeMimeContent></m:ItemShape><m:ItemIds>{xml}</m:ItemIds></m:GetItem>");
                let response = self
                    .soap(&body)
                    .await
                    .map_err(|e| format!("GetItem delta {}: {e}", folder.id))?;
                let items = parse_items(&response, folder.kind);
                if items.len() != ids.len() {
                    return Err(format!(
                        "GetItem delta {} returned {} of {} items",
                        folder.id,
                        items.len(),
                        ids.len()
                    ));
                }
                for mut item in items {
                    item.folder_id = folder.id.clone();
                    item.folder_path = vec![folder.name.clone()];
                    item.tags = vec![match folder.id.as_str() {
                        "sentitems" => "Sent",
                        "drafts" => "Drafts",
                        "deleteditems" => "Trash",
                        "junkemail" => "Spam",
                        _ => "",
                    }
                    .into()];
                    fetched.insert(item.object_id.clone(), item);
                }
            }
            let mut items = vec![];
            for (id, version, delete) in changes {
                if delete {
                    items.push(SourceItem {
                        kind: folder.kind,
                        change: Change::Delete,
                        object_id: id,
                        version,
                        folder_id: folder.id.clone(),
                        folder_path: vec![folder.name.clone()],
                        ..empty(folder.kind)
                    });
                } else {
                    items.push(
                        fetched.get(&id).cloned().ok_or_else(|| {
                            format!("GetItem delta {} omitted item {id}", folder.id)
                        })?,
                    );
                }
            }
            self.states.insert(folder.id.clone(), state.clone());
            if response.contains("IncludesLastItemInRange=\"true\"")
                || response.contains("<m:IncludesLastItemInRange>true</m:IncludesLastItemInRange>")
            {
                self.folder += 1;
                self.reset = false;
            }
            return Ok(Some(Batch {
                items,
                checkpoint: Checkpoint::Delta {
                    scope: folder.id.clone(),
                    legacy_scope: folder.name.clone(),
                    kind: "ews_sync_state",
                    value: json!(state),
                    legacy: json!({"delta":{folder.name:state}}),
                },
            }));
        }
    }
}
pub(super) async fn bounded(
    mut response: reqwest::Response,
    max: usize,
    message: &str,
) -> Result<Vec<u8>, String> {
    if response.content_length().is_some_and(|n| n > max as u64) {
        return Err(message.into());
    }
    let mut out = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| format!("ews read body: {e}"))?
    {
        if chunk.len() > max.saturating_sub(out.len()) {
            return Err(message.into());
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}
fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&#34;")
        .replace('\'', "&#39;")
}
fn raw_attr(block: &str, name: &str) -> String {
    let needle = format!("{name}=\"");
    block
        .find(&needle)
        .and_then(|at| {
            block[at + needle.len()..]
                .split_once('"')
                .map(|(s, _)| s.to_owned())
        })
        .unwrap_or_default()
}
fn attr(block: &str, name: &str) -> String {
    html_escape::decode_html_entities(&raw_attr(block, name)).into_owned()
}
fn element(block: &str, name: &str) -> Option<String> {
    let start = block.find(&format!("<{name}>"))? + name.len() + 2;
    let end = block[start..].find(&format!("</{name}>"))?;
    Some(block[start..start + end].into())
}
pub(super) fn empty(kind: ItemKind) -> SourceItem {
    SourceItem {
        kind,
        change: Change::Upsert,
        object_id: String::new(),
        version: String::new(),
        folder_id: String::new(),
        raw: vec![],
        ics: String::new(),
        vcf: String::new(),
        folder_path: vec![],
        tags: vec![],
        uid: 0,
        uid_validity: 0,
    }
}
fn parse_items(mut response: &str, kind: ItemKind) -> Vec<SourceItem> {
    let tags: &[&str] = match kind {
        ItemKind::Mail => &[
            "Message",
            "MeetingMessage",
            "MeetingRequest",
            "MeetingResponse",
            "MeetingCancellation",
            "PostItem",
        ],
        ItemKind::Calendar => &["CalendarItem"],
        ItemKind::Contact => &["Contact"],
    };
    let mut items = vec![];
    while let Some((at, tag)) = tags
        .iter()
        .filter_map(|tag| response.find(&format!("<t:{tag}")).map(|at| (at, *tag)))
        .min_by_key(|x| x.0)
    {
        let close = format!("</t:{tag}>");
        let Some(end) = response[at..].find(&close) else {
            break;
        };
        let block = &response[at..at + end + close.len()];
        let id = attr(block, "Id");
        if let Some(at) = block.find("<t:MimeContent").filter(|_| !id.is_empty()) {
            if let Some((_, rest)) = block[at..].split_once('>') {
                if let Some((payload, _)) = rest.split_once("</t:MimeContent>") {
                    let unescaped = html_escape::decode_html_entities(payload);
                    let compact: String = unescaped
                        .chars()
                        .filter(|c| !matches!(c, ' ' | '\n' | '\r' | '\t'))
                        .collect();
                    let raw = STANDARD.decode(&compact).unwrap_or_else(|_| {
                        html_escape::decode_html_entities(&compact)
                            .as_bytes()
                            .to_vec()
                    });
                    let mut item = empty(kind);
                    item.object_id = id;
                    item.version = attr(block, "ChangeKey");
                    match kind {
                        ItemKind::Mail => item.raw = raw,
                        ItemKind::Calendar => item.ics = String::from_utf8_lossy(&raw).into_owned(),
                        ItemKind::Contact => item.vcf = String::from_utf8_lossy(&raw).into_owned(),
                    };
                    items.push(item);
                }
            }
        }
        response = &response[at + end + close.len()..];
    }
    items
}

fn challenge_target(bytes: &[u8]) -> Option<String> {
    if bytes.get(..12)? != b"NTLMSSP\0\x02\0\0\0" {
        return None;
    }
    let length = u16::from_le_bytes(bytes.get(12..14)?.try_into().ok()?) as usize;
    let offset = u32::from_le_bytes(bytes.get(16..20)?.try_into().ok()?) as usize;
    if length % 2 != 0 {
        return None;
    }
    let value = bytes.get(offset..offset.checked_add(length)?)?;
    let value = String::from_utf16(
        &value
            .chunks_exact(2)
            .map(|p| u16::from_le_bytes([p[0], p[1]]))
            .collect::<Vec<_>>(),
    )
    .ok()?;
    Some(value)
}
