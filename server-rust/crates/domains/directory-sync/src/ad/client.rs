//! Active Directory wire client mirroring `mailserver/internal/ad/client.go`.
//!
//! Transport is implicit TLS on port 636 (the legacy handler path has no other
//! mode); servers come from `ad_sync_ldap_host` or from DNS SRV discovery of
//! `_ldap._tcp.<domain>`, and a bind never happens on a plain connection.
use crate::ldap::client::{first_value, normalize_dn, search_paged, ClientError, LdapClient};
use crate::ldap::filter;
use ldap3::{Ldap, Scope, SearchEntry, SearchOptions};
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

const TIMEOUT: Duration = Duration::from_secs(30);
const MANAGER_LOOKUP_CHUNK: usize = 100;
/// Backstop against a directory whose paging cookie never empties.
const MAX_SEARCH_PAGES: usize = 1000;
const SUBJECT_ATTRIBUTE: &str = "objectGUID";
const CONSISTENCY_GUID: &str = "msDS-ConsistencyGuid";
const DEFAULT_FILTER: &str = "(&(objectClass=user)(objectCategory=person))";

/// Attributes requested for every user entry (Go `userSearchRequest`); the first
/// is the subject attribute, `objectGUID` unless a catalog source says otherwise.
const USER_ATTRS: [&str; 13] = [
    "mail",
    "displayName",
    "givenName",
    "sn",
    "sAMAccountName",
    "userPrincipalName",
    "userAccountControl",
    "department",
    "title",
    "manager",
    "telephoneNumber",
    "proxyAddresses",
    "uSNChanged",
];

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AdUser {
    pub dn: String,
    pub object_guid: String,
    pub email: String,
    pub display_name: String,
    pub first_name: String,
    pub last_name: String,
    pub sam_account_name: String,
    pub upn: String,
    pub disabled: bool,
    pub department: String,
    pub title: String,
    pub manager_dn: String,
    pub manager_subject: String,
    pub phone: String,
    pub proxy_addresses: Vec<String>,
    pub usn_changed: i64,
}

/// DNS SRV lookup of `_ldap._tcp.<domain>`: the targets in connection order,
/// without port (Go always dials 636). The system resolver is the production
/// implementation; tests inject their own.
pub trait SrvResolver: Send + Sync {
    fn lookup<'a>(
        &'a self,
        domain: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<String>, String>> + Send + 'a>>;
}

type Lookup = Pin<Box<dyn Future<Output = Result<Vec<String>, String>> + Send>>;

async fn srv_targets(
    resolver: hickory_resolver::TokioResolver,
    domain: String,
) -> Result<Vec<String>, String> {
    let name = format!("_ldap._tcp.{domain}");
    let lookup = resolver.srv_lookup(name).await.map_err(|e| e.to_string())?;
    let mut records: Vec<(u16, u16, String)> = lookup
        .answers()
        .iter()
        .filter_map(|record| match &record.data {
            hickory_resolver::proto::rr::RData::SRV(srv) => {
                Some((srv.priority, srv.weight, srv.target.to_utf8()))
            }
            _ => None,
        })
        .collect();
    // RFC 2782 order: lowest priority first, heavier weight first within one.
    records.sort_by(|a, b| a.0.cmp(&b.0).then(b.1.cmp(&a.1)));
    Ok(records.into_iter().map(|(_, _, target)| target).collect())
}

/// The system resolver (`/etc/resolv.conf`), as Go's `net.LookupSRV`.
pub struct SystemResolver;

impl SrvResolver for SystemResolver {
    fn lookup<'a>(
        &'a self,
        domain: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<String>, String>> + Send + 'a>> {
        let domain = domain.to_owned();
        Box::pin(async move {
            let resolver = hickory_resolver::TokioResolver::builder_tokio()
                .map_err(|e| e.to_string())?
                .build()
                .map_err(|e| e.to_string())?;
            srv_targets(resolver, domain).await
        })
    }
}

/// A resolver that asks exactly one name server (UDP), for tests and for a
/// fixed-resolver deployment.
pub struct NameServerResolver(pub std::net::SocketAddr);

impl SrvResolver for NameServerResolver {
    fn lookup<'a>(
        &'a self,
        domain: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<String>, String>> + Send + 'a>> {
        let (addr, domain) = (self.0, domain.to_owned());
        let lookup: Lookup = Box::pin(async move {
            use hickory_resolver::config::{NameServerConfig, ResolverConfig};
            use hickory_resolver::net::runtime::TokioRuntimeProvider;
            let mut server = NameServerConfig::udp(addr.ip());
            for connection in &mut server.connections {
                connection.port = addr.port();
            }
            let resolver = hickory_resolver::Resolver::builder_with_config(
                ResolverConfig::from_name_servers(vec![server]),
                TokioRuntimeProvider::default(),
            )
            .build()
            .map_err(|e| e.to_string())?;
            srv_targets(resolver, domain).await
        });
        lookup
    }
}

/// Go `fmt.Sscanf(s, "%d", &n)` into an `int64`: optional leading spaces and
/// sign, then digits; trailing text is ignored, no digits or overflow fail.
pub fn sscanf_d(raw: &str) -> Option<i64> {
    let trimmed = raw.trim_start_matches([' ', '\t', '\r']);
    let (sign, rest) = match trimmed.as_bytes().first() {
        Some(b'-') => (-1i128, &trimmed[1..]),
        Some(b'+') => (1i128, &trimmed[1..]),
        _ => (1i128, trimmed),
    };
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    if digits.is_empty() {
        return None;
    }
    let value = digits.parse::<i128>().ok()? * sign;
    i64::try_from(value).ok()
}

/// Go `guidToString`: Active Directory's mixed-endian 16-byte GUID as text.
pub fn guid_to_string(guid: &[u8]) -> String {
    if guid.len() != 16 {
        return String::new();
    }
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{}",
        guid[3],
        guid[2],
        guid[1],
        guid[0],
        guid[5],
        guid[4],
        guid[7],
        guid[6],
        guid[8],
        guid[9],
        guid[10..16]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    )
}

/// Go `ldaputil.DomainToBaseDN`.
pub fn domain_to_base_dn(domain: &str) -> String {
    domain
        .split('.')
        .map(|part| format!("DC={part}"))
        .collect::<Vec<_>>()
        .join(",")
}

#[derive(Clone, Debug)]
pub struct AdClient {
    base_dn: String,
    bind_dn: String,
    password: String,
    hosts: Vec<String>,
    /// Always 636 for the legacy path; the endpoint's port for a catalog source.
    port: i64,
    /// Implicit TLS (`ldaps`) unless a catalog source asks for `starttls`.
    implicit_tls: bool,
    subject_attribute: String,
    user_filter: String,
}

/// The non-secret runtime shape of one catalog AD source (Go `ad.ClientConfig`).
#[derive(Clone, Debug, Default)]
pub struct ClientConfig {
    pub host: String,
    pub port: i64,
    pub transport: String,
    pub base_dn: String,
    pub bind_dn: String,
    pub password: String,
    pub subject_attribute: String,
    pub user_filter: String,
}

impl AdClient {
    /// Go `NewClient`: an override host skips discovery; otherwise SRV targets
    /// become `host:636`. A failed lookup is an error (no client).
    pub async fn new(
        domain: &str,
        bind_dn: &str,
        password: &str,
        override_host: &str,
        resolver: &dyn SrvResolver,
    ) -> Result<Self, String> {
        let hosts = if override_host.is_empty() {
            resolver
                .lookup(domain)
                .await
                .map_err(|e| {
                    format!(
                        "AD discovery failed for {domain}: SRV lookup for _ldap._tcp.{domain}: {e}"
                    )
                })?
                .into_iter()
                .map(|target| target.trim_end_matches('.').to_owned())
                .collect()
        } else {
            vec![override_host.to_owned()]
        };
        Ok(Self {
            base_dn: domain_to_base_dn(domain),
            bind_dn: bind_dn.into(),
            password: password.into(),
            hosts,
            port: 636,
            implicit_tls: true,
            subject_attribute: SUBJECT_ATTRIBUTE.into(),
            user_filter: String::new(),
        })
    }

    /// Go `NewConfiguredClient`: the exact endpoint, TLS mode, base DN and
    /// operator-approved immutable anchor of a catalog source, no discovery.
    pub fn configured(cfg: &ClientConfig) -> Result<Self, String> {
        if cfg.host.trim().is_empty() || !(1..=65535).contains(&cfg.port) {
            return Err("AD endpoint is invalid".into());
        }
        if cfg.base_dn.trim().is_empty() {
            return Err("AD base DN is required".into());
        }
        if cfg.transport != "ldaps" && cfg.transport != "starttls" {
            return Err("AD transport must be ldaps or starttls".into());
        }
        if cfg.subject_attribute != SUBJECT_ATTRIBUTE && cfg.subject_attribute != CONSISTENCY_GUID {
            return Err("AD immutable subject attribute is invalid".into());
        }
        if !cfg.user_filter.is_empty() && filter::compile(&cfg.user_filter).is_none() {
            return Err("AD user filter is invalid".into());
        }
        Ok(Self {
            base_dn: cfg.base_dn.clone(),
            bind_dn: cfg.bind_dn.clone(),
            password: cfg.password.clone(),
            hosts: vec![cfg.host.clone()],
            port: cfg.port,
            implicit_tls: cfg.transport == "ldaps",
            subject_attribute: cfg.subject_attribute.clone(),
            user_filter: cfg.user_filter.clone(),
        })
    }

    pub fn hosts(&self) -> &[String] {
        &self.hosts
    }

    fn endpoint(&self, host: &str) -> LdapClient {
        LdapClient::new(
            host,
            self.port,
            self.implicit_tls,
            &self.bind_dn,
            &self.password,
            &self.base_dn,
        )
    }

    /// Go `connect`: the first reachable server wins.
    pub async fn connect(&self) -> Result<(Ldap, LdapClient), ClientError> {
        for host in &self.hosts {
            let endpoint = self.endpoint(host);
            match endpoint.connect().await {
                Ok(ldap) => return Ok((ldap, endpoint)),
                Err(e) => {
                    eprintln!("setjoin-gateway: ad-sync: AD connection failed host={host}: {e}")
                }
            }
        }
        Err(ClientError::Connect("all AD servers unreachable".into()))
    }

    /// Search every user changed at or after `cursor`, with manager anchors
    /// resolved; also the highest `uSNChanged` seen.
    pub async fn search_users(
        &self,
        ldap: &mut Ldap,
        cursor: i64,
    ) -> Result<(Vec<AdUser>, i64), ClientError> {
        let base = if self.user_filter.is_empty() {
            DEFAULT_FILTER
        } else {
            &self.user_filter
        };
        let filter = format!("(&{base}(uSNChanged>={cursor}))");
        let attrs: Vec<String> = std::iter::once(self.subject_attribute.as_str())
            .chain(USER_ATTRS)
            .map(str::to_owned)
            .collect();
        let mut users = vec![];
        let mut max_usn = 0i64;
        let entries = search_pages(ldap, &self.base_dn, &filter, attrs).await?;
        for entry in &entries {
            let (user, include) = user_from_entry(entry, &self.subject_attribute)?;
            if !include {
                continue;
            }
            max_usn = max_usn.max(user.usn_changed);
            users.push(user);
        }
        self.resolve_manager_subjects(ldap, &mut users).await?;
        Ok((users, max_usn))
    }

    async fn resolve_manager_subjects(
        &self,
        ldap: &mut Ldap,
        users: &mut [AdUser],
    ) -> Result<(), ClientError> {
        let (mut by_dn, missing) = known_manager_subjects(users);
        for chunk in missing.chunks(MANAGER_LOOKUP_CHUNK) {
            let parts: String = chunk
                .iter()
                .map(|dn| format!("(distinguishedName={})", filter::escape(dn)))
                .collect();
            let text = format!("(|{parts})");
            let canonical = filter::compile(&text)
                .ok_or_else(|| ClientError::Search("AD manager anchor lookup: filter".into()))?;
            let (entries, status) = ldap
                .with_timeout(TIMEOUT)
                .with_search_options(SearchOptions::new().timelimit(30))
                .search(
                    &self.base_dn,
                    Scope::Subtree,
                    &canonical,
                    vec![self.subject_attribute.clone()],
                )
                .await
                .map_err(|e| ClientError::Search(format!("AD manager anchor lookup: {e}")))
                .map(|r| (r.0, r.1))?;
            if status.rc != 0 {
                return Err(ClientError::Search(format!(
                    "AD manager anchor lookup: LDAP Result Code {} {:?}",
                    status.rc, status.text
                )));
            }
            for entry in entries {
                let entry = SearchEntry::construct(entry);
                let subject = immutable_subject(&entry, &self.subject_attribute);
                if !subject.is_empty() {
                    by_dn.insert(normalize_dn(&entry.dn), subject);
                }
            }
        }
        for user in users.iter_mut() {
            if user.manager_subject.is_empty() {
                user.manager_subject = by_dn
                    .get(&normalize_dn(&user.manager_dn))
                    .cloned()
                    .unwrap_or_default();
            }
        }
        Ok(())
    }
}

/// The paged loop of `SearchUsers`, bounded by `MAX_SEARCH_PAGES` requests.
async fn search_pages(
    ldap: &mut Ldap,
    base_dn: &str,
    filter_text: &str,
    attrs: Vec<String>,
) -> Result<Vec<SearchEntry>, ClientError> {
    // ldap3 pages inside one streaming search; the page bound is enforced by
    // counting entries per request (500 each) against the backstop.
    let entries = search_paged(ldap, base_dn, filter_text, attrs, 500, Some(30))
        .await
        .map_err(|e| ClientError::Search(format!("AD search: {e}")))?;
    if entries.len() > MAX_SEARCH_PAGES * 500 {
        return Err(ClientError::Search(format!(
            "AD search exceeded {MAX_SEARCH_PAGES} pages (paging cookie never emptied)"
        )));
    }
    Ok(entries)
}

/// First raw value of an attribute (text or binary), case-insensitive name.
fn raw_value(entry: &SearchEntry, name: &str) -> Vec<u8> {
    if let Some((_, values)) = entry
        .bin_attrs
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
    {
        if let Some(first) = values.first() {
            return first.clone();
        }
    }
    entry
        .attrs
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .and_then(|(_, v)| v.first())
        .map(|v| v.as_bytes().to_vec())
        .unwrap_or_default()
}

fn all_values(entry: &SearchEntry, name: &str) -> Vec<String> {
    entry
        .attrs
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.clone())
        .unwrap_or_default()
}

/// Go `immutableSubject`: `objectGUID` as GUID text, `msDS-ConsistencyGuid` as
/// base64, anything else empty.
fn immutable_subject(entry: &SearchEntry, attribute: &str) -> String {
    use base64::Engine;
    let raw = raw_value(entry, attribute);
    match attribute {
        SUBJECT_ATTRIBUTE => guid_to_string(&raw),
        CONSISTENCY_GUID if raw.is_empty() => String::new(),
        CONSISTENCY_GUID => base64::engine::general_purpose::STANDARD.encode(raw),
        _ => String::new(),
    }
}

/// Go `userFromEntry`; `include` is false for an unparsable `uSNChanged`
/// (skipped silently) and an unparsable `userAccountControl` is an error.
fn user_from_entry(entry: &SearchEntry, attribute: &str) -> Result<(AdUser, bool), ClientError> {
    let get = |name: &str| first_value(entry, name);
    let mut user = AdUser {
        dn: entry.dn.clone(),
        object_guid: immutable_subject(entry, attribute),
        email: get("mail"),
        display_name: get("displayName"),
        first_name: get("givenName"),
        last_name: get("sn"),
        sam_account_name: get("sAMAccountName"),
        upn: get("userPrincipalName"),
        department: get("department"),
        title: get("title"),
        manager_dn: get("manager"),
        phone: get("telephoneNumber"),
        proxy_addresses: all_values(entry, "proxyAddresses"),
        ..Default::default()
    };
    let uac = get("userAccountControl");
    if !uac.is_empty() {
        let value = sscanf_d(&uac).ok_or_else(|| {
            ClientError::Search(format!("AD: invalid userAccountControl {uac:?}"))
        })?;
        user.disabled = value & 2 != 0;
    }
    let usn = get("uSNChanged");
    if !usn.is_empty() {
        match sscanf_d(&usn) {
            Some(n) => user.usn_changed = n,
            None => return Ok((AdUser::default(), false)),
        }
    }
    Ok((user, true))
}

/// Go `knownManagerSubjects`: page-local `normalized dn -> guid` and the
/// manager DNs still unknown (first spelling kept, deduplicated).
pub fn known_manager_subjects(users: &mut [AdUser]) -> (HashMap<String, String>, Vec<String>) {
    let mut by_dn = HashMap::new();
    for user in users.iter() {
        if !user.dn.is_empty() && !user.object_guid.is_empty() {
            by_dn.insert(normalize_dn(&user.dn), user.object_guid.clone());
        }
    }
    let mut missing = vec![];
    let mut seen = std::collections::HashSet::new();
    for user in users.iter_mut() {
        let manager = normalize_dn(&user.manager_dn);
        if manager.is_empty() {
            continue;
        }
        if let Some(subject) = by_dn.get(&manager).filter(|s| !s.is_empty()) {
            user.manager_subject = subject.clone();
            continue;
        }
        if seen.insert(manager) {
            missing.push(user.manager_dn.clone());
        }
    }
    (by_dn, missing)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sscanf_matches_go() {
        assert_eq!(sscanf_d("514"), Some(514));
        assert_eq!(sscanf_d("  12abc"), Some(12));
        assert_eq!(sscanf_d("-7"), Some(-7));
        assert_eq!(sscanf_d("+7"), Some(7));
        assert_eq!(sscanf_d("abc"), None);
        assert_eq!(sscanf_d("-"), None);
        assert_eq!(sscanf_d("99999999999999999999"), None);
        assert_eq!(sscanf_d("0x10"), Some(0));
    }

    #[test]
    fn guid_is_mixed_endian() {
        let raw = [
            0x33, 0x22, 0x11, 0x00, 0x55, 0x44, 0x77, 0x66, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        assert_eq!(guid_to_string(&raw), "00112233-4455-6677-8899-aabbccddeeff");
        assert_eq!(guid_to_string(&raw[..15]), "");
    }

    #[test]
    fn base_dn_from_domain() {
        assert_eq!(
            domain_to_base_dn("corp.example.test"),
            "DC=corp,DC=example,DC=test"
        );
    }
}
