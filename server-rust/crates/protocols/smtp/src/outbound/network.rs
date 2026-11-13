//! Production DNS/socket operations; queue and protocol choices stay upstream.
use super::Network;
use crate::mail_auth::{Dns, DnsType, SystemDns};
use futures_util::future::BoxFuture;
use tokio::net::TcpStream;
pub struct SystemNetwork {
    dns: SystemDns,
}
impl SystemNetwork {
    pub fn new() -> Result<Self, String> {
        Ok(Self {
            dns: SystemDns::new()?,
        })
    }
    pub async fn local_hostname(&self) -> String {
        if let Ok(mut addresses) = tokio::net::lookup_host(("localhost", 0)).await {
            if let Some(address) = addresses.next() {
                if let Ok(hosts) = std::fs::read_to_string("/etc/hosts") {
                    for line in hosts.lines() {
                        let mut fields = line
                            .split('#')
                            .next()
                            .unwrap_or_default()
                            .split_whitespace();
                        if fields
                            .next()
                            .and_then(|ip| ip.parse::<std::net::IpAddr>().ok())
                            == Some(address.ip())
                        {
                            if let Some(name) = fields.next() {
                                return name.trim_end_matches('.').into();
                            }
                        }
                    }
                }
                if let Ok(names) = self
                    .dns
                    .lookup(DnsType::Ptr, &address.ip().to_string())
                    .await
                {
                    if let Some(name) = names.first() {
                        return name.trim_end_matches('.').into();
                    }
                }
            }
        }
        "mailserver.local".into()
    }
}
impl Network for SystemNetwork {
    fn mx<'a>(&'a self, domain: &'a str) -> BoxFuture<'a, Result<Vec<String>, String>> {
        Box::pin(async move {
            self.dns
                .lookup(DnsType::Mx, domain)
                .await
                .map_err(|e| format!("{e:?}"))
        })
    }
    fn connect<'a>(&'a self, host: &'a str) -> BoxFuture<'a, Result<TcpStream, String>> {
        Box::pin(async move {
            let host = host.trim_end_matches('.');
            let addresses = tokio::net::lookup_host((host, 25))
                .await
                .map_err(|e| format!("dial tcp: {e}"))?;
            let mut last = None;
            for address in addresses {
                match TcpStream::connect(address).await {
                    Ok(socket) => return Ok(socket),
                    Err(error) => {
                        let detail = match error.kind() {
                            std::io::ErrorKind::ConnectionRefused => {
                                "connect: connection refused".into()
                            }
                            std::io::ErrorKind::TimedOut => "i/o timeout".into(),
                            _ => error.to_string(),
                        };
                        last = Some(format!("dial tcp {address}: {detail}"));
                    }
                }
            }
            Err(last.unwrap_or_else(|| format!("dial tcp: lookup {host}: no such host")))
        })
    }
}
