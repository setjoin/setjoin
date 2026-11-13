//! Adapter from the injectable [`Dns`] trait to `mail-auth`'s TXT cache.
//!
//! `mail-auth` owns DKIM/ARC parsing, canonicalization, signature checks and
//! expiry (owner-approved security fix 2026-11-05, #492/#493). It resolves keys
//! through a `ResolverCache`; every name it can ask for is fetched through
//! [`Dns`] first and the cache answers *every* query (an unfetched name is a
//! temporary DNS error), so `mail-auth`'s own network resolver is never used.
use super::{Dns, DnsError, DnsType};
use mail_auth::{
    common::{parse::TxtRecordParser, verify::DomainKey},
    hickory_resolver::proto::op::ResponseCode,
    Error, MessageAuthenticator, ResolverCache, Txt,
};
use std::{borrow::Borrow, collections::HashMap, hash::Hash, sync::Mutex, sync::OnceLock};

#[derive(Default)]
pub(crate) struct TxtCache(Mutex<HashMap<Box<str>, Txt>>);

impl ResolverCache<Box<str>, Txt> for TxtCache {
    fn get<Q>(&self, name: &Q) -> Option<Txt>
    where
        Box<str>: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        Some(
            self.0
                .lock()
                .expect("txt cache")
                .get(name)
                .cloned()
                .unwrap_or_else(|| Txt::Error(Error::DnsError("name was not prefetched".into()))),
        )
    }
    fn remove<Q>(&self, name: &Q) -> Option<Txt>
    where
        Box<str>: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.0.lock().expect("txt cache").remove(name)
    }
    fn insert(&self, key: Box<str>, value: Txt, _: std::time::Instant) {
        self.0.lock().expect("txt cache").insert(key, value);
    }
}

impl TxtCache {
    /// Resolve a DKIM/ARC key record (`selector._domainkey.domain.`) through `dns`.
    pub(crate) async fn fetch_key(&self, dns: &dyn Dns, fqdn: &str) {
        if self.0.lock().expect("txt cache").contains_key(fqdn) {
            return;
        }
        let name = fqdn.trim_end_matches('.');
        let value: Txt = match dns.lookup(DnsType::Txt, name).await {
            Ok(records) => {
                let mut parsed: mail_auth::Result<DomainKey> = Err(Error::InvalidRecordType);
                for record in &records {
                    parsed = DomainKey::parse(record.as_bytes());
                    if parsed.is_ok() {
                        break;
                    }
                }
                parsed.into()
            }
            Err(DnsError::NotFound) => Txt::Error(Error::DnsRecordNotFound(ResponseCode::NXDomain)),
            Err(DnsError::Temporary) => Txt::Error(Error::DnsError("temporary failure".into())),
        };
        self.insert(
            fqdn.into(),
            value,
            std::time::Instant::now() + std::time::Duration::from_secs(60),
        );
    }
}

/// Never used for I/O: the [`TxtCache`] is total. Building it performs no lookup.
pub(crate) fn authenticator() -> &'static MessageAuthenticator {
    static AUTH: OnceLock<MessageAuthenticator> = OnceLock::new();
    AUTH.get_or_init(|| {
        MessageAuthenticator::new_cloudflare().expect("resolver configuration is static")
    })
}
