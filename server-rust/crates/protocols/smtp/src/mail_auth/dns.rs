use futures_util::future::BoxFuture;
use hickory_resolver::{proto::rr::RData, TokioResolver};
use std::{net::IpAddr, time::Duration};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DnsType {
    Txt,
    Ip,
    Mx,
    Ptr,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DnsError {
    NotFound,
    Temporary,
}
/// The same four resolver operations used by frozen Go. TXT chunks are joined
/// within a resource record; separate records must remain separate.
pub trait Dns: Send + Sync {
    fn lookup<'a>(
        &'a self,
        kind: DnsType,
        name: &'a str,
    ) -> BoxFuture<'a, Result<Vec<String>, DnsError>>;
}
pub struct SystemDns {
    resolver: TokioResolver,
}
impl SystemDns {
    pub fn from_resolver(resolver: TokioResolver) -> Self {
        Self { resolver }
    }
    pub fn new() -> Result<Self, String> {
        let resolver = TokioResolver::builder_tokio()
            .map_err(|e| e.to_string())?
            .build()
            .map_err(|e| e.to_string())?;
        Ok(Self { resolver })
    }
}
impl Dns for SystemDns {
    fn lookup<'a>(
        &'a self,
        kind: DnsType,
        name: &'a str,
    ) -> BoxFuture<'a, Result<Vec<String>, DnsError>> {
        Box::pin(async move {
            let lookup = async {
                let name = format!("{}.", name.trim_end_matches('.'));
                match kind {
                    DnsType::Txt => self.resolver.txt_lookup(name).await.map(|v| {
                        v.answers()
                            .iter()
                            .filter_map(|r| {
                                if let RData::TXT(t) = &r.data {
                                    Some(setjoin_mime::go_lossy(
                                        &t.txt_data
                                            .iter()
                                            .flat_map(|c| c.iter().copied())
                                            .collect::<Vec<_>>(),
                                    ))
                                } else {
                                    None
                                }
                            })
                            .collect()
                    }),
                    DnsType::Ip => self
                        .resolver
                        .lookup_ip(name)
                        .await
                        .map(|v| v.iter().map(|ip| ip.to_canonical().to_string()).collect()),
                    DnsType::Mx => self.resolver.mx_lookup(name).await.map(|v| {
                        let mut mx: Vec<_> = v
                            .answers()
                            .iter()
                            .filter_map(|r| {
                                if let RData::MX(mx) = &r.data {
                                    Some((mx.preference, mx.exchange.to_utf8()))
                                } else {
                                    None
                                }
                            })
                            .collect();
                        mx.sort_by_key(|(preference, _)| *preference);
                        mx.into_iter().map(|(_, host)| host).collect()
                    }),
                    DnsType::Ptr => {
                        let ip: IpAddr = name
                            .trim_end_matches('.')
                            .parse()
                            .map_err(|_| DnsError::NotFound)?;
                        self.resolver.reverse_lookup(ip).await.map(|v| {
                            v.answers()
                                .iter()
                                .filter_map(|r| {
                                    if let RData::PTR(n) = &r.data {
                                        Some(n.to_utf8())
                                    } else {
                                        None
                                    }
                                })
                                .collect()
                        })
                    }
                }
                .map_err(|e| {
                    if e.is_no_records_found() {
                        DnsError::NotFound
                    } else {
                        DnsError::Temporary
                    }
                })
            };
            tokio::time::timeout(Duration::from_secs(5), lookup)
                .await
                .unwrap_or(Err(DnsError::Temporary))
        })
    }
}
