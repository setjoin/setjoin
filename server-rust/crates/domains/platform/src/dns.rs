//! Platform slice `terms-remaining`, group `dns`: record generation and DNS health
//! (`/admin/dns/records`, `/admin/dns/verify`), Go's `DNSHandler`.
//!
//! Generation is reads plus fixed text. Verification asks a resolver for MX and TXT records;
//! Go uses the process resolver (`net.LookupMX`), so the production resolver reads
//! `/etc/resolv.conf` and a fixed name server is available for tests. Lookup failures render
//! Go's `DNSError` text (`lookup <name> on <server>: <reason>`).
use super::{done, s};
use setjoin_pg::{ScopedExecutor, StatementFailure, Type};
use std::net::SocketAddr;

/// Where lookups go.
#[derive(Clone, Debug)]
pub enum Resolver {
    /// `/etc/resolv.conf`, as Go's resolver.
    System,
    /// One UDP name server.
    Server(SocketAddr),
}

/// Go's `net.isDomainName`.
fn is_domain_name(name: &str) -> bool {
    if name == "." {
        return true;
    }
    let b = name.as_bytes();
    let l = b.len();
    if l == 0 || l > 254 || (l == 254 && b[l - 1] != b'.') {
        return false;
    }
    let (mut last, mut non_numeric, mut part) = (b'.', false, 0usize);
    for &c in b {
        match c {
            b'a'..=b'z' | b'A'..=b'Z' | b'_' => {
                non_numeric = true;
                part += 1;
            }
            b'0'..=b'9' => part += 1,
            b'-' => {
                if last == b'.' {
                    return false;
                }
                part += 1;
                non_numeric = true;
            }
            b'.' => {
                if last == b'.' || last == b'-' || part > 63 || part == 0 {
                    return false;
                }
                part = 0;
            }
            _ => return false,
        }
        last = c;
    }
    !(last == b'-' || part > 63) && non_numeric
}

impl Resolver {
    fn server_text(&self) -> String {
        match self {
            Resolver::Server(addr) => addr.to_string(),
            Resolver::System => std::fs::read_to_string("/etc/resolv.conf")
                .ok()
                .and_then(|text| {
                    text.lines()
                        .filter_map(|l| l.trim().strip_prefix("nameserver"))
                        .map(|rest| rest.trim().to_owned())
                        .next()
                })
                .map(|ip| {
                    if ip.contains(':') {
                        format!("[{ip}]:53")
                    } else {
                        format!("{ip}:53")
                    }
                })
                .unwrap_or_default(),
        }
    }

    async fn ask(
        &self,
        name: &str,
        kind: hickory_resolver::proto::rr::RecordType,
    ) -> Result<hickory_resolver::lookup::Lookup, String> {
        use hickory_resolver::config::{NameServerConfig, ResolverConfig};
        use hickory_resolver::net::runtime::TokioRuntimeProvider;
        let failed = |reason: &str| {
            let server = self.server_text();
            if server.is_empty() {
                format!("lookup {name}: {reason}")
            } else {
                format!("lookup {name} on {server}: {reason}")
            }
        };
        if !is_domain_name(name) {
            return Err(format!("lookup {name}: no such host"));
        }
        let resolver = match self {
            Resolver::System => hickory_resolver::TokioResolver::builder_tokio()
                .map_err(|_| failed("server misbehaving"))?
                .build()
                .map_err(|_| failed("server misbehaving"))?,
            Resolver::Server(addr) => {
                let mut server = NameServerConfig::udp(addr.ip());
                for connection in &mut server.connections {
                    connection.port = addr.port();
                }
                hickory_resolver::Resolver::builder_with_config(
                    ResolverConfig::from_name_servers(vec![server]),
                    TokioRuntimeProvider::default(),
                )
                .build()
                .map_err(|_| failed("server misbehaving"))?
            }
        };
        let absolute = if name.ends_with('.') {
            name.to_owned()
        } else {
            format!("{name}.")
        };
        match resolver.lookup(absolute, kind).await {
            Ok(found) if !found.answers().is_empty() => Ok(found),
            Ok(_) => Err(failed("no such host")),
            Err(e) if e.is_no_records_found() => Err(failed("no such host")),
            Err(hickory_resolver::net::NetError::Timeout) => Err(failed("i/o timeout")),
            Err(_) => Err(failed("server misbehaving")),
        }
    }

    /// `net.LookupMX`: records by ascending preference, hosts with their trailing dot.
    pub async fn mx(&self, name: &str) -> Result<Vec<String>, String> {
        let found = self
            .ask(name, hickory_resolver::proto::rr::RecordType::MX)
            .await?;
        let mut hosts: Vec<(u16, String)> = found
            .answers()
            .iter()
            .filter_map(|r| match &r.data {
                hickory_resolver::proto::rr::RData::MX(mx) => {
                    Some((mx.preference, mx.exchange.to_utf8()))
                }
                _ => None,
            })
            .collect();
        if hosts.is_empty() {
            return Err(format!("lookup {name}: no such host"));
        }
        hosts.sort_by_key(|(p, _)| *p);
        Ok(hosts.into_iter().map(|(_, h)| h).collect())
    }

    /// `net.LookupTXT`: one string per record, its character strings concatenated.
    pub async fn txt(&self, name: &str) -> Result<Vec<String>, String> {
        let found = self
            .ask(name, hickory_resolver::proto::rr::RecordType::TXT)
            .await?;
        let out: Vec<String> = found
            .answers()
            .iter()
            .filter_map(|r| match &r.data {
                hickory_resolver::proto::rr::RData::TXT(txt) => Some(
                    txt.txt_data
                        .iter()
                        .map(|part| String::from_utf8_lossy(part).into_owned())
                        .collect::<String>(),
                ),
                _ => None,
            })
            .collect();
        if out.is_empty() {
            return Err(format!("lookup {name}: no such host"));
        }
        Ok(out)
    }
}

/// The scope name of a domain-scoped principal; `None` when the domain row is gone.
pub async fn scope_name(
    exec: &ScopedExecutor,
    domain_scope: i64,
) -> Result<Option<String>, StatementFailure> {
    let rows = exec
        .read(
            "SELECT name FROM domains WHERE id = $1",
            &[(&domain_scope, Type::INT8)],
        )
        .await?;
    Ok(rows.first().and_then(|r| r.try_get::<_, String>(0).ok()))
}

/// First selector row of `domain_signing_keys`, or every one.
async fn selectors(exec: &ScopedExecutor, domain: &str, one: bool) -> Option<Vec<String>> {
    let sql = if one {
        "SELECT selector FROM domain_signing_keys WHERE domain = $1 LIMIT 1"
    } else {
        "SELECT selector FROM domain_signing_keys WHERE domain = $1"
    };
    let rows = exec.read(sql, &[(&domain, Type::TEXT)]).await.ok()?;
    Some(
        rows.iter()
            .filter_map(|r| r.try_get::<_, String>(0).ok())
            .collect(),
    )
}

/// `GET /admin/dns/records`.
pub async fn records(exec: &ScopedExecutor, domain: &str) -> String {
    let host = exec
        .read(
            "SELECT value->>'value' FROM system_config WHERE key = 'gateway_hostname'",
            &[],
        )
        .await
        .ok()
        .and_then(|rows| rows.first().and_then(|r| r.try_get::<_, String>(0).ok()))
        .unwrap_or_default();
    let host = if host.is_empty() {
        format!("mail.{domain}")
    } else {
        host
    };
    let stamp = exec
        .read(
            "SELECT to_char(now() AT TIME ZONE 'UTC','YYYYMMDD\"T\"HH24MISS\"Z\"')",
            &[],
        )
        .await
        .ok()
        .and_then(|rows| rows.first().and_then(|r| r.try_get::<_, String>(0).ok()))
        .unwrap_or_default();
    let mut dkim: Vec<String> = selectors(exec, domain, false)
        .await
        .unwrap_or_default()
        .iter()
        .map(|sel| {
            format!(
                "{{\"selector\":{},\"record\":{}}}",
                s(sel),
                s(&format!(
                    "{sel}._domainkey.{domain} IN TXT \"v=DKIM1; k=rsa; p=<public-key>\""
                ))
            )
        })
        .collect();
    if dkim.is_empty() {
        dkim.push(format!(
            "{{\"selector\":\"default\",\"record\":{}}}",
            s(&format!(
                "default._domainkey.{domain} IN TXT \"v=DKIM1; k=rsa; p=<public-key>\""
            ))
        ));
    }
    done(format!(
        "{{\"domain\":{},\"mx\":{},\"spf\":{},\"dkim\":[{}],\"dmarc\":{},\"mtasts\":{},\"tlsa\":{},\"reverseDns\":{},\"recommendedA\":{}}}",
        s(domain),
        s(&format!("{domain} IN MX 10 {host}.")),
        s(&format!("{domain} IN TXT \"v=spf1 mx ~all\"")),
        dkim.join(","),
        s(&format!("_dmarc.{domain} IN TXT \"v=DMARC1; p=quarantine; rua=mailto:dmarc@{domain}; pct=100\"")),
        s(&format!("_mta-sts.{domain} IN TXT \"v=STSv1; id={stamp}\"")),
        s(&format!("_25._tcp.{host} IN TLSA 3 1 1 (<sha256-hex-of-server-cert>)")),
        s(&format!("<your-server-ip>.in-addr.arpa IN PTR {host}.")),
        s(&format!("{host} IN A <your-server-ip>")),
    ))
}

struct Check {
    kind: &'static str,
    name: String,
    status: &'static str,
    value: String,
    expected: String,
}
impl Check {
    fn render(&self) -> String {
        let mut out = format!(
            "{{\"type\":\"{}\",\"name\":{},\"status\":\"{}\"",
            self.kind,
            s(&self.name),
            self.status
        );
        if !self.value.is_empty() {
            out += &format!(",\"value\":{}", s(&self.value));
        }
        if !self.expected.is_empty() {
            out += &format!(",\"expected\":{}", s(&self.expected));
        }
        out + "}"
    }
}

/// The first TXT record containing `marker`, as a passing check; else a failing one.
async fn txt_check(
    resolver: &Resolver,
    kind: &'static str,
    name: String,
    marker: &str,
    expected: &str,
    checks: &mut Vec<Check>,
) -> bool {
    if let Ok(records) = resolver.txt(&name).await {
        if let Some(found) = records.into_iter().find(|t| t.contains(marker)) {
            checks.push(Check {
                kind,
                name,
                status: "pass",
                value: found,
                expected: String::new(),
            });
            return true;
        }
    }
    checks.push(Check {
        kind,
        name,
        status: "fail",
        value: String::new(),
        expected: expected.into(),
    });
    false
}

/// `GET /admin/dns/verify`.
pub async fn verify(exec: &ScopedExecutor, resolver: &Resolver, domain: &str) -> String {
    let mut checks = Vec::new();
    let mut all = true;
    match resolver.mx(domain).await {
        Ok(hosts) => checks.push(Check {
            kind: "MX",
            name: domain.into(),
            status: "pass",
            value: hosts.first().cloned().unwrap_or_default(),
            expected: String::new(),
        }),
        Err(e) => {
            checks.push(Check {
                kind: "MX",
                name: domain.into(),
                status: "fail",
                value: e,
                expected: String::new(),
            });
            all = false;
        }
    }
    all &= txt_check(
        resolver,
        "SPF",
        domain.into(),
        "v=spf1",
        "v=spf1 ...",
        &mut checks,
    )
    .await;
    all &= txt_check(
        resolver,
        "DMARC",
        format!("_dmarc.{domain}"),
        "v=DMARC1",
        "v=DMARC1; ...",
        &mut checks,
    )
    .await;
    if let Some(selector) = selectors(exec, domain, true)
        .await
        .and_then(|v| v.into_iter().next())
    {
        all &= txt_check(
            resolver,
            "DKIM",
            format!("{selector}._domainkey.{domain}"),
            "v=DKIM1",
            "v=DKIM1; ...",
            &mut checks,
        )
        .await;
    }
    done(format!(
        "{{\"domain\":{},\"checks\":{},\"allPass\":{all}}}",
        s(domain),
        if checks.is_empty() {
            "null".to_owned()
        } else {
            format!(
                "[{}]",
                checks
                    .iter()
                    .map(Check::render)
                    .collect::<Vec<_>>()
                    .join(",")
            )
        }
    ))
}
