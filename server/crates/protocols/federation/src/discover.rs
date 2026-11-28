//! Peer discovery: DNS SRV `_setjoin-im._tcp.<domain>` (MX-shaped, no central
//! directory). The resolver is an injectable seam; the system resolver is the
//! production implementation.

use crate::{db::BoxFut, error::FedError, stream::PeerEndpoint};
use std::{
    collections::hash_map::RandomState,
    hash::{BuildHasher, Hasher},
    net::SocketAddr,
};

pub const SRV_SERVICE: &str = "setjoin-im";
pub const SRV_PROTO: &str = "tcp";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Srv {
    pub target: String,
    pub port: u16,
    pub priority: u16,
    pub weight: u16,
}

pub trait Resolver: Send + Sync {
    fn lookup_srv<'a>(
        &'a self,
        service: &'a str,
        proto: &'a str,
        name: &'a str,
    ) -> BoxFut<'a, Result<Vec<Srv>, String>>;
}

fn rand_u64() -> u64 {
    RandomState::new().build_hasher().finish()
}

/// Go's `net.LookupSRV` order: by priority, weighted-random within one.
pub fn order_srv(mut records: Vec<Srv>) -> Vec<Srv> {
    records.sort_by_key(|r| r.priority);
    let mut out = Vec::with_capacity(records.len());
    let mut i = 0;
    while i < records.len() {
        let mut j = i;
        while j < records.len() && records[j].priority == records[i].priority {
            j += 1;
        }
        let mut group: Vec<Srv> = records[i..j].to_vec();
        // Zero weights first (RFC 2782), then repeated weighted picks.
        group.sort_by_key(|r| r.weight != 0);
        while !group.is_empty() {
            let sum: u64 = group.iter().map(|r| u64::from(r.weight)).sum();
            let pick = if sum == 0 {
                0
            } else {
                let mut n = rand_u64() % (sum + 1);
                let mut idx = 0;
                for (k, r) in group.iter().enumerate() {
                    idx = k;
                    if n <= u64::from(r.weight) {
                        break;
                    }
                    n -= u64::from(r.weight);
                }
                idx
            };
            out.push(group.remove(pick));
        }
        i = j;
    }
    out
}

async fn srv_lookup(
    resolver: hickory_resolver::TokioResolver,
    name: String,
) -> Result<Vec<Srv>, String> {
    let lookup = resolver.srv_lookup(name).await.map_err(|e| e.to_string())?;
    Ok(lookup
        .answers()
        .iter()
        .filter_map(|record| match &record.data {
            hickory_resolver::proto::rr::RData::SRV(srv) => Some(Srv {
                target: srv.target.to_utf8(),
                port: srv.port,
                priority: srv.priority,
                weight: srv.weight,
            }),
            _ => None,
        })
        .collect())
}

/// The system resolver (`/etc/resolv.conf`), as Go's default resolver.
pub struct SystemResolver;

impl Resolver for SystemResolver {
    fn lookup_srv<'a>(
        &'a self,
        service: &'a str,
        proto: &'a str,
        name: &'a str,
    ) -> BoxFut<'a, Result<Vec<Srv>, String>> {
        Box::pin(async move {
            let resolver = hickory_resolver::TokioResolver::builder_tokio()
                .map_err(|e| e.to_string())?
                .build()
                .map_err(|e| e.to_string())?;
            srv_lookup(resolver, format!("_{service}._{proto}.{name}")).await
        })
    }
}

/// Asks exactly one name server over UDP (tests, fixed-resolver deployments).
pub struct NameServerResolver(pub SocketAddr);

impl Resolver for NameServerResolver {
    fn lookup_srv<'a>(
        &'a self,
        service: &'a str,
        proto: &'a str,
        name: &'a str,
    ) -> BoxFut<'a, Result<Vec<Srv>, String>> {
        let addr = self.0;
        Box::pin(async move {
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
            srv_lookup(resolver, format!("_{service}._{proto}.{name}")).await
        })
    }
}

/// A fixed answer, for tests and the harness.
pub struct StaticResolver(pub Vec<(String, Srv)>);

impl Resolver for StaticResolver {
    fn lookup_srv<'a>(
        &'a self,
        _service: &'a str,
        _proto: &'a str,
        name: &'a str,
    ) -> BoxFut<'a, Result<Vec<Srv>, String>> {
        Box::pin(async move {
            Ok(self
                .0
                .iter()
                .filter(|(d, _)| d == name)
                .map(|(_, s)| s.clone())
                .collect())
        })
    }
}

/// `ResolvePeer`: the best SRV record's endpoint.
pub async fn resolve_peer(r: &dyn Resolver, domain: &str) -> Result<PeerEndpoint, FedError> {
    let addrs = r
        .lookup_srv(SRV_SERVICE, SRV_PROTO, domain)
        .await
        .map_err(|e| FedError::other(format!("federation: SRV lookup for {domain}: {e}")))?;
    if addrs.is_empty() {
        return Err(FedError::other(format!(
            "federation: no SRV records for _{SRV_SERVICE}._{SRV_PROTO}.{domain}"
        )));
    }
    let best = order_srv(addrs).remove(0);
    Ok(PeerEndpoint {
        domain: domain.to_string(),
        target: best
            .target
            .strip_suffix('.')
            .unwrap_or(&best.target)
            .to_string(),
        port: best.port,
    })
}
