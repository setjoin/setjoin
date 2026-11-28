//! LDAP wire client for the sync engines, mirroring `mailserver/internal/ldapsync/client.go`.
//!
//! Transport is implicit TLS (`ldaps`) or `STARTTLS`; a bind never happens on a
//! plain connection. Server certificates are verified against the platform
//! roots (`SSL_CERT_FILE` honoured) for the configured host, as Go's
//! `crypto/tls` does.
use super::filter;
use ldap3::adapters::{Adapter, EntriesOnly, PagedResults};
use ldap3::{Ldap, LdapConnAsync, LdapConnSettings, Scope, SearchEntry, SearchOptions};
use std::collections::HashMap;
use std::time::Duration;

const TIMEOUT: Duration = Duration::from_secs(30);
const MANAGER_LOOKUP_CHUNK: usize = 100;
pub const MAX_DISCOVERY_ATTRIBUTES: usize = 16;

/// Attributes requested for every user entry (Go `ldapUserAttrs`).
pub const USER_ATTRS: [&str; 14] = [
    "dn",
    "mail",
    "displayName",
    "givenName",
    "sn",
    "title",
    "telephoneNumber",
    "department",
    "userPrincipalName",
    "modifyTimestamp",
    "manager",
    "nsAccountLock",
    "pwdAccountLockedTime",
    "userAccountControl",
];

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LdapUser {
    pub dn: String,
    pub manager_dn: String,
    pub manager_subject: String,
    pub email: String,
    pub display_name: String,
    pub first_name: String,
    pub last_name: String,
    pub title: String,
    pub phone: String,
    pub department: String,
    pub upn: String,
    pub disabled: bool,
    pub modify_stamp: String,
    pub immutable_subject: String,
}

/// Go's `ConnClass`: how the console words a failed connection test.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnClass {
    Network,
    BindAuth,
}

#[derive(Debug)]
pub struct ConnError {
    pub class: ConnClass,
    pub message: String,
}
impl std::fmt::Display for ConnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

/// Failure of one client step; `InvalidCredentials` is LDAP result code 49.
#[derive(Debug)]
pub enum ClientError {
    Connect(String),
    Bind {
        invalid_credentials: bool,
        message: String,
    },
    Search(String),
}
impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Connect(m) | Self::Search(m) => f.write_str(m),
            Self::Bind { message, .. } => f.write_str(message),
        }
    }
}
impl std::error::Error for ClientError {}

#[derive(Clone, Debug)]
pub struct LdapClient {
    host: String,
    port: i64,
    starttls: bool,
    bind_dn: String,
    password: String,
    base_dn: String,
    subject_attribute: String,
}

/// Go `ldapAttributeName`: `^[A-Za-z][A-Za-z0-9-]{0,63}$`.
pub fn valid_attribute_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 64
        && bytes[0].is_ascii_alphabetic()
        && bytes[1..]
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'-')
}

/// Go `ldaputil.NormalizeDN`: lower-case and trim whitespace.
pub fn normalize_dn(dn: &str) -> String {
    dn.trim_matches(|c: char| c.is_whitespace()).to_lowercase()
}

/// Lock state across directory families (Go `entryDisabled`).
pub fn entry_disabled(ns_account_lock: &str, pwd_locked: &str, uac: &str) -> bool {
    if ns_account_lock == "TRUE" || !pwd_locked.is_empty() {
        return true;
    }
    parse_int64(uac).is_some_and(|v| v & 0x2 != 0)
}

/// `strconv.ParseInt(s, 10, 64)`: optional sign, digits only, in range.
fn parse_int64(s: &str) -> Option<i64> {
    let digits = s.strip_prefix(['+', '-']).unwrap_or(s);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse::<i64>()
        .ok()
        .or_else(|| s.strip_prefix('+')?.parse().ok())
}

impl LdapClient {
    pub fn new(
        host: &str,
        port: i64,
        use_tls: bool,
        bind_dn: &str,
        password: &str,
        base_dn: &str,
    ) -> Self {
        Self {
            host: host.into(),
            port,
            starttls: !use_tls,
            bind_dn: bind_dn.into(),
            password: password.into(),
            base_dn: base_dn.into(),
            subject_attribute: String::new(),
        }
    }

    /// Operator-approved immutable anchor; empty keeps normalized sync closed.
    pub fn set_subject_attribute(&mut self, attribute: &str) -> Result<(), String> {
        if attribute.is_empty() {
            self.subject_attribute.clear();
            return Ok(());
        }
        if !valid_attribute_name(attribute) {
            return Err(format!("invalid LDAP subject attribute {attribute:?}"));
        }
        self.subject_attribute = attribute.into();
        Ok(())
    }
    pub fn subject_attribute(&self) -> &str {
        &self.subject_attribute
    }
    pub fn base_dn(&self) -> &str {
        &self.base_dn
    }

    pub async fn connect(&self) -> Result<Ldap, ClientError> {
        if !(1..=65535).contains(&self.port) {
            return Err(ClientError::Connect(format!(
                "invalid LDAP port {}",
                self.port
            )));
        }
        let settings = LdapConnSettings::new()
            .set_conn_timeout(TIMEOUT)
            .set_starttls(self.starttls);
        let scheme = if self.starttls { "ldap" } else { "ldaps" };
        let host = if self.host.contains(':') && !self.host.starts_with('[') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        let url = format!("{scheme}://{host}:{}", self.port);
        let (conn, ldap) = LdapConnAsync::with_settings(settings, &url)
            .await
            .map_err(|e| ClientError::Connect(e.to_string()))?;
        ldap3::drive!(conn);
        Ok(ldap)
    }

    /// Bind as the service account. An empty password is refused client-side,
    /// as go-ldap refuses an unauthenticated bind.
    pub async fn bind(&self, ldap: &mut Ldap) -> Result<(), ClientError> {
        if self.password.is_empty() {
            return Err(ClientError::Bind {
                invalid_credentials: false,
                message: "ldap: empty password not allowed by the client".into(),
            });
        }
        let result = ldap
            .with_timeout(TIMEOUT)
            .simple_bind(&self.bind_dn, &self.password)
            .await
            .map_err(|e| ClientError::Bind {
                invalid_credentials: false,
                message: e.to_string(),
            })?;
        if result.rc != 0 {
            return Err(ClientError::Bind {
                invalid_credentials: result.rc == 49,
                message: format!("LDAP Result Code {} {:?}", result.rc, result.text),
            });
        }
        Ok(())
    }

    fn attrs(&self) -> Vec<String> {
        let mut attrs: Vec<String> = USER_ATTRS.iter().map(|s| (*s).to_owned()).collect();
        if !self.subject_attribute.is_empty() {
            attrs.push(self.subject_attribute.clone());
        }
        attrs
    }

    /// Paged subtree search for user entries, then manager anchor resolution.
    pub async fn search_users(
        &self,
        ldap: &mut Ldap,
        filter_text: &str,
        page_size: u32,
    ) -> Result<Vec<LdapUser>, ClientError> {
        let text = if filter_text.is_empty() {
            "(objectClass=person)"
        } else {
            filter_text
        };
        let page = if page_size == 0 { 500 } else { page_size };
        let entries = self
            .paged(ldap, text, self.attrs(), page)
            .await
            .map_err(|e| ClientError::Search(format!("LDAP search: {e}")))?;
        let mut users: Vec<LdapUser> = entries.iter().map(|e| self.user_from_entry(e)).collect();
        self.resolve_manager_subjects(ldap, &mut users).await?;
        Ok(users)
    }

    async fn paged(
        &self,
        ldap: &mut Ldap,
        filter_text: &str,
        attrs: Vec<String>,
        page: u32,
    ) -> Result<Vec<SearchEntry>, String> {
        search_paged(ldap, &self.base_dn, filter_text, attrs, page, None).await
    }

    fn user_from_entry(&self, entry: &SearchEntry) -> LdapUser {
        let get = |name: &str| first_value(entry, name);
        LdapUser {
            dn: entry.dn.clone(),
            manager_dn: get("manager"),
            email: get("mail"),
            display_name: get("displayName"),
            first_name: get("givenName"),
            last_name: get("sn"),
            title: get("title"),
            phone: get("telephoneNumber"),
            department: get("department"),
            upn: get("userPrincipalName"),
            modify_stamp: get("modifyTimestamp"),
            immutable_subject: get(&self.subject_attribute),
            disabled: entry_disabled(
                &get("nsAccountLock"),
                &get("pwdAccountLockedTime"),
                &get("userAccountControl"),
            ),
            manager_subject: String::new(),
        }
    }

    async fn resolve_manager_subjects(
        &self,
        ldap: &mut Ldap,
        users: &mut [LdapUser],
    ) -> Result<(), ClientError> {
        if self.subject_attribute.is_empty() {
            return Ok(());
        }
        let (mut by_dn, missing) = known_manager_subjects(users);
        for chunk in missing.chunks(MANAGER_LOOKUP_CHUNK) {
            let parts: String = chunk
                .iter()
                .map(|dn| format!("(distinguishedName={})", filter::escape(dn)))
                .collect();
            let text = format!("(|{parts})");
            let canonical = filter::compile(&text)
                .ok_or_else(|| ClientError::Search("LDAP manager anchor lookup: filter".into()))?;
            let result = ldap
                .with_timeout(TIMEOUT)
                .with_search_options(SearchOptions::new().timelimit(30))
                .search(
                    &self.base_dn,
                    Scope::Subtree,
                    &canonical,
                    vec![self.subject_attribute.clone()],
                )
                .await
                .map_err(|e| ClientError::Search(format!("LDAP manager anchor lookup: {e}")))?;
            let (entries, status) = (result.0, result.1);
            if status.rc != 0 {
                return Err(ClientError::Search(format!(
                    "LDAP manager anchor lookup: LDAP Result Code {} {:?}",
                    status.rc, status.text
                )));
            }
            for entry in entries {
                let entry = SearchEntry::construct(entry);
                let subject = first_value(&entry, &self.subject_attribute);
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

    /// Aggregate uniqueness evidence for candidate immutable attributes.
    pub async fn discover_immutable_attributes(
        &self,
        ldap: &mut Ldap,
        filter_text: &str,
        candidates: &[String],
    ) -> Result<Vec<AnchorDiscovery>, String> {
        if candidates.is_empty() || candidates.len() > MAX_DISCOVERY_ATTRIBUTES {
            return Err(format!(
                "LDAP anchor discovery requires 1..{MAX_DISCOVERY_ATTRIBUTES} attributes"
            ));
        }
        let mut seen = std::collections::HashSet::new();
        for attribute in candidates {
            if !valid_attribute_name(attribute) {
                return Err(format!("invalid LDAP subject attribute {attribute:?}"));
            }
            if !seen.insert(attribute.as_str()) {
                return Err(format!("duplicate LDAP subject attribute {attribute:?}"));
            }
        }
        let text = if filter_text.is_empty() {
            "(objectClass=person)"
        } else {
            filter_text
        };
        let entries = self
            .paged(ldap, text, candidates.to_vec(), 500)
            .await
            .map_err(|e| format!("LDAP immutable-anchor discovery: {e}"))?;
        Ok(discovery_facts(&entries, candidates))
    }
}

/// One paged subtree search (RFC 2696) collecting every entry. `time_limit`
/// is the server-side limit in seconds (AD sets 30, LDAP leaves it unset).
pub(crate) async fn search_paged(
    ldap: &mut Ldap,
    base_dn: &str,
    filter_text: &str,
    attrs: Vec<String>,
    page: u32,
    time_limit: Option<i32>,
) -> Result<Vec<SearchEntry>, String> {
    let canonical =
        filter::compile(filter_text).ok_or("LDAP Result Code 201 \"Filter Compile Error\"")?;
    let adapters: Vec<Box<dyn Adapter<'_, _, _>>> = vec![
        Box::new(EntriesOnly::new()),
        Box::new(PagedResults::new(page as i32)),
    ];
    let handle = match time_limit {
        Some(seconds) => ldap
            .with_timeout(TIMEOUT)
            .with_search_options(SearchOptions::new().timelimit(seconds)),
        None => ldap.with_timeout(TIMEOUT),
    };
    let mut stream = handle
        .streaming_search_with(adapters, base_dn, Scope::Subtree, &canonical, attrs)
        .await
        .map_err(|e| e.to_string())?;
    let mut out = vec![];
    while let Some(entry) = stream.next().await.map_err(|e| e.to_string())? {
        out.push(SearchEntry::construct(entry));
    }
    let done = stream.finish().await;
    if done.rc != 0 {
        return Err(format!("LDAP Result Code {} {:?}", done.rc, done.text));
    }
    Ok(out)
}

pub(crate) fn first_value(entry: &SearchEntry, name: &str) -> String {
    if name.is_empty() {
        return String::new();
    }
    entry
        .attrs
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .and_then(|(_, v)| v.first().cloned())
        .unwrap_or_default()
}

/// Known `normalized dn -> subject` from the page, and the manager DNs still unknown.
pub fn known_manager_subjects(users: &mut [LdapUser]) -> (HashMap<String, String>, Vec<String>) {
    let mut by_dn = HashMap::new();
    for user in users.iter() {
        if !user.dn.is_empty() && !user.immutable_subject.is_empty() {
            by_dn.insert(normalize_dn(&user.dn), user.immutable_subject.clone());
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnchorDiscovery {
    pub attribute: String,
    pub entries: usize,
    pub present: usize,
    pub unique: usize,
    pub duplicates: usize,
    pub ready: bool,
}

fn discovery_facts(entries: &[SearchEntry], candidates: &[String]) -> Vec<AnchorDiscovery> {
    candidates
        .iter()
        .map(|attribute| {
            let mut fact = AnchorDiscovery {
                attribute: attribute.clone(),
                entries: entries.len(),
                present: 0,
                unique: 0,
                duplicates: 0,
                ready: false,
            };
            let mut values: HashMap<String, usize> = HashMap::new();
            for entry in entries {
                let value = first_value(entry, attribute);
                if value.is_empty() {
                    continue;
                }
                fact.present += 1;
                *values.entry(value).or_default() += 1;
            }
            fact.unique = values.len();
            fact.duplicates = values.values().filter(|c| **c > 1).sum();
            fact.ready = fact.entries > 0
                && fact.present == fact.entries
                && fact.unique == fact.entries
                && fact.duplicates == 0;
            fact
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_states() {
        assert!(entry_disabled("TRUE", "", ""));
        assert!(!entry_disabled("true", "", ""));
        assert!(entry_disabled("", "000001010000Z", ""));
        assert!(entry_disabled("", "", "514"));
        assert!(!entry_disabled("", "", "512"));
        assert!(entry_disabled("", "", "+2"));
        assert!(!entry_disabled("", "", "0x2"));
    }

    #[test]
    fn attribute_names() {
        assert!(valid_attribute_name("entryUUID"));
        assert!(valid_attribute_name("a-b9"));
        assert!(!valid_attribute_name(""));
        assert!(!valid_attribute_name("9a"));
        assert!(!valid_attribute_name("a_b"));
        assert!(!valid_attribute_name(&"a".repeat(65)));
    }

    #[test]
    fn dn_normalization() {
        assert_eq!(normalize_dn("  CN=A,DC=X \t"), "cn=a,dc=x");
    }
}
