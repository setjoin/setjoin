//! SPF evaluation (RFC 7208) over [`Dns`]. Owner-approved security fixes
//! 2026-11-05 (#493): a DNS failure or an exhausted lookup budget is
//! `temperror`/`permerror` rather than a silent non-match; unknown mechanisms and
//! malformed `ip4`/`ip6`/CIDR syntax are `permerror`; `ip4` never matches an IPv6
//! client (nor `ip6` an IPv4 one) while a bare IPv6 address matches exactly;
//! `a/24`, `mx//64` dual-CIDR forms are honoured; `include` of a domain without a
//! policy is `permerror`; and `redirect=` applies only after every mechanism failed
//! to match.
use super::{Dns, DnsError, DnsType};
use futures_util::future::BoxFuture;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const MAX_TERMS: usize = 10;
const MAX_VOID: usize = 2;
const MAX_NAMES: usize = 10;

#[derive(Default)]
struct Budget {
    terms: usize,
    voids: usize,
}
impl Budget {
    /// One DNS-querying term (a, mx, ptr, exists, include, redirect).
    fn term(&mut self) -> Result<(), &'static str> {
        self.terms += 1;
        if self.terms > MAX_TERMS && !crate::mutants::on("spf-errors-are-non-matches") {
            return Err("permerror");
        }
        Ok(())
    }
    fn void(&mut self) -> Result<(), &'static str> {
        self.voids += 1;
        if self.voids > MAX_VOID && !crate::mutants::on("spf-errors-are-non-matches") {
            return Err("permerror");
        }
        Ok(())
    }
}

pub async fn check(
    dns: &dyn Dns,
    domain: &str,
    ip: &str,
    sender: &str,
    helo: &str,
) -> &'static str {
    depth(dns, domain, ip, sender, helo, 0, &mut Budget::default()).await
}
/// A matching DNS answer, or the error verdict for the whole evaluation.
type Hit = Result<bool, &'static str>;
fn lookup_error(error: DnsError, budget: &mut Budget) -> Hit {
    match error {
        DnsError::NotFound => budget.void().map(|()| false),
        DnsError::Temporary if crate::mutants::on("spf-errors-are-non-matches") => Ok(false),
        DnsError::Temporary => Err("temperror"),
    }
}
struct Cidr {
    v4: u8,
    v6: u8,
}
fn dual_cidr(spec: &str) -> Option<Cidr> {
    let mut cidr = Cidr { v4: 32, v6: 128 };
    let (v4, v6) = match spec.split_once("//") {
        Some((v4, v6)) => (v4, Some(v6)),
        None => (spec, None),
    };
    if let Some(v4) = v4.strip_prefix('/') {
        cidr.v4 = v4.parse().ok().filter(|n| *n <= 32)?;
    } else if !v4.is_empty() {
        return None;
    }
    if let Some(v6) = v6 {
        cidr.v6 = v6.parse().ok().filter(|n| *n <= 128)?;
    }
    Some(cidr)
}
fn in_prefix(a: IpAddr, b: IpAddr, cidr: &Cidr) -> bool {
    match (a, b) {
        (IpAddr::V4(a), IpAddr::V4(b)) => {
            let mask = u32::MAX.checked_shl(32 - u32::from(cidr.v4)).unwrap_or(0);
            u32::from(a) & mask == u32::from(b) & mask
        }
        (IpAddr::V6(a), IpAddr::V6(b)) => {
            let mask = u128::MAX.checked_shl(128 - u32::from(cidr.v6)).unwrap_or(0);
            u128::from(a) & mask == u128::from(b) & mask
        }
        _ => false,
    }
}
fn client(ip: &str) -> Option<IpAddr> {
    ip.parse::<IpAddr>().ok().map(|v| v.to_canonical())
}
/// `ip4:`/`ip6:` operand. `Err` is a syntax error (`permerror`).
fn network(address: &str, v4: bool, ip: Option<IpAddr>) -> Hit {
    let (host, prefix) = match address.split_once('/') {
        Some((host, prefix)) => (host, Some(prefix)),
        None => (address, None),
    };
    let (network, max) =
        if v4 && !(crate::mutants::on("spf-ip4-accepts-ipv6") && host.contains(':')) {
            let parsed: Ipv4Addr = host.parse().map_err(|_| "permerror")?;
            (IpAddr::V4(parsed), 32)
        } else {
            let parsed: Ipv6Addr = host.parse().map_err(|_| "permerror")?;
            (IpAddr::V6(parsed), 128)
        };
    let prefix = match prefix {
        Some(text) => text
            .parse::<u8>()
            .ok()
            .filter(|n| *n <= max)
            .ok_or("permerror")?,
        None => max,
    };
    let Some(ip) = ip else { return Ok(false) };
    let cidr = Cidr {
        v4: prefix.min(32),
        v6: prefix,
    };
    // A family mismatch never matches: IPv4-mapped clients were canonicalized.
    Ok(in_prefix(ip, network, &cidr))
}
fn depth<'a>(
    dns: &'a dyn Dns,
    domain: &'a str,
    ip: &'a str,
    sender: &'a str,
    helo: &'a str,
    level: usize,
    budget: &'a mut Budget,
) -> BoxFuture<'a, &'static str> {
    Box::pin(async move {
        if level > MAX_TERMS {
            return "permerror";
        }
        let domain = domain.to_lowercase();
        let domain = domain.strip_prefix('@').unwrap_or(&domain);
        if domain.is_empty() {
            return "none";
        }
        let txt = match dns.lookup(DnsType::Txt, domain).await {
            Ok(txt) => txt,
            Err(DnsError::NotFound) => return "none",
            Err(_) => return "temperror",
        };
        let mut records = txt.iter().filter(|v| {
            let lower = v.to_lowercase();
            lower == "v=spf1" || lower.starts_with("v=spf1 ")
        });
        let Some(record) = records.next() else {
            return "none";
        };
        if records.next().is_some() {
            return "permerror";
        }
        let address = client(ip);
        let mut redirect = None;
        for term in record.split_whitespace().skip(1) {
            let (qualifier, rest) = match term.as_bytes()[0] {
                b'+' | b'-' | b'~' | b'?' => (term.as_bytes()[0], &term[1..]),
                _ => (b'+', term),
            };
            let lowered = rest.to_lowercase();
            let name_end = lowered.find([':', '/', '=']).unwrap_or(lowered.len());
            let (name, tail) = lowered.split_at(name_end);
            if let Some(value) = tail.strip_prefix('=') {
                // Modifiers: redirect is applied last, exp and unknown ones are ignored.
                if name == "redirect" && redirect.is_none() {
                    redirect = Some(macros(value, domain, sender, helo, ip));
                }
                continue;
            }
            let spec = tail.strip_prefix(':');
            let (target, cidr_text) = match spec {
                Some(spec) => match spec.find('/') {
                    Some(i) => (Some(&spec[..i]), &spec[i..]),
                    None => (Some(spec), ""),
                },
                None => (None, tail),
            };
            let target = target.map(|t| macros(t, domain, sender, helo, ip));
            let matched: Hit = match name {
                "all" => Ok(true),
                "ip4" | "ip6" => match (spec, name) {
                    (Some(operand), name) => network(operand, name == "ip4", address),
                    (None, _) => Err("permerror"),
                },
                "include" => match target {
                    Some(host) if !host.is_empty() => {
                        if let Err(e) = budget.term() {
                            return e;
                        }
                        match depth(dns, &host, ip, sender, helo, level + 1, budget).await {
                            "pass" => Ok(true),
                            "fail" | "softfail" | "neutral" => Ok(false),
                            "temperror" => Err("temperror"),
                            _ => Err("permerror"),
                        }
                    }
                    _ => Err("permerror"),
                },
                "a" | "mx" => match dual_cidr(cidr_text) {
                    None => Err("permerror"),
                    Some(cidr) => {
                        if let Err(e) = budget.term() {
                            return e;
                        }
                        let host = target.unwrap_or_else(|| domain.to_owned());
                        if name == "a" {
                            addresses(dns, &host, address, &cidr, budget).await
                        } else {
                            mx(dns, &host, address, &cidr, budget).await
                        }
                    }
                },
                "ptr" => {
                    if !cidr_text.is_empty() {
                        Err("permerror")
                    } else if let Err(e) = budget.term() {
                        return e;
                    } else {
                        let host = target.unwrap_or_else(|| domain.to_owned());
                        Ok(ptr(dns, &host, address).await)
                    }
                }
                "exists" => match target {
                    Some(host) if !host.is_empty() => {
                        if let Err(e) = budget.term() {
                            return e;
                        }
                        match dns.lookup(DnsType::Ip, &host).await {
                            Ok(values) => Ok(!values.is_empty()),
                            Err(error) => lookup_error(error, budget),
                        }
                    }
                    _ => Err("permerror"),
                },
                _ if crate::mutants::on("spf-unknown-mechanism-ignored") => Ok(false),
                _ => Err("permerror"),
            };
            match matched {
                Err(verdict) => return verdict,
                Ok(true) => {
                    return match qualifier {
                        b'-' => "fail",
                        b'~' => "softfail",
                        b'?' => "neutral",
                        _ => "pass",
                    }
                }
                Ok(false) => {}
            }
        }
        if let Some(target) = redirect {
            if let Err(e) = budget.term() {
                return e;
            }
            return match depth(dns, &target, ip, sender, helo, level + 1, budget).await {
                "none" => "permerror",
                verdict => verdict,
            };
        }
        "neutral"
    })
}
async fn addresses(
    dns: &dyn Dns,
    host: &str,
    client: Option<IpAddr>,
    cidr: &Cidr,
    budget: &mut Budget,
) -> Hit {
    let Some(client) = client else {
        return Ok(false);
    };
    match dns.lookup(DnsType::Ip, host).await {
        Ok(values) => Ok(values
            .iter()
            .filter_map(|v| self::client(v))
            .any(|v| in_prefix(client, v, cidr))),
        Err(error) => lookup_error(error, budget),
    }
}
async fn mx(
    dns: &dyn Dns,
    host: &str,
    client: Option<IpAddr>,
    cidr: &Cidr,
    budget: &mut Budget,
) -> Hit {
    let hosts = match dns.lookup(DnsType::Mx, host).await {
        Ok(hosts) => hosts,
        Err(error) => return lookup_error(error, budget),
    };
    if hosts.len() > MAX_NAMES {
        return Err("permerror");
    }
    for exchange in hosts {
        if addresses(dns, &exchange, client, cidr, budget).await? {
            return Ok(true);
        }
    }
    Ok(false)
}
async fn ptr(dns: &dyn Dns, domain: &str, client: Option<IpAddr>) -> bool {
    let Some(client) = client else { return false };
    let Ok(hosts) = dns.lookup(DnsType::Ptr, &client.to_string()).await else {
        return false;
    };
    let cidr = Cidr { v4: 32, v6: 128 };
    for host in hosts.into_iter().take(MAX_NAMES) {
        let host = host.strip_suffix('.').unwrap_or(&host);
        let lower = host.to_lowercase();
        if (domain.is_empty() || lower == domain || lower.ends_with(&format!(".{domain}")))
            && matches!(
                addresses(dns, host, Some(client), &cidr, &mut Budget::default()).await,
                Ok(true)
            )
        {
            return true;
        }
    }
    false
}
fn macros(input: &str, current: &str, sender: &str, helo: &str, ip: &str) -> String {
    let (local, origin) = sender.rsplit_once('@').unwrap_or(("", ""));
    // One pass, like strings.NewReplacer: replacements never expand themselves.
    let mut out = String::new();
    let mut rest = input;
    while let Some(i) = rest.find("%{") {
        out.push_str(&rest[..i]);
        rest = &rest[i..];
        let replacement = if rest.as_bytes().get(3) == Some(&b'}') {
            match rest.as_bytes()[2].to_ascii_lowercase() {
                b's' => Some(sender),
                b'l' => Some(local),
                b'o' => Some(origin),
                b'd' | b'p' => Some(current),
                b'i' => Some(ip),
                b'v' => Some("in-addr"),
                b'h' => Some(helo),
                _ => None,
            }
        } else {
            None
        };
        if let Some(value) = replacement {
            out.push_str(value);
            rest = &rest[4..]
        } else {
            out.push_str("%{");
            rest = &rest[2..]
        }
    }
    out.push_str(rest);
    out
}
