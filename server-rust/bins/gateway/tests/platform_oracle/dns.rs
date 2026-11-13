//! Group `dns` cases for the `terms-remaining` oracle: `/admin/dns/*`. Go resolves through a
//! mounted `resolv.conf` that names a fake zone server on 127.0.0.77:53 (the run needs root,
//! as the AD oracle does); Rust asks the same server. The zone answers MX and TXT.
use super::terms::Case;
use std::collections::HashMap;
use std::net::SocketAddr;
use tokio::net::UdpSocket;

/// Go queries `domain_signing_keys.domain`, a column that does not exist (the table keys on
/// `domain_id`), so its selector reads always fail; the effects are the table's rows anyway.
const EFFECTS: &str = "SELECT to_jsonb(s)::text FROM domain_signing_keys s ORDER BY id";
pub const ADDRESS: &str = "127.0.0.77:53";

/// A record of the fake zone: `(type, rdata)`.
type Record = (u16, Vec<u8>);

fn name_bytes(name: &str) -> Vec<u8> {
    let mut out = vec![];
    for label in name
        .trim_end_matches('.')
        .split('.')
        .filter(|l| !l.is_empty())
    {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out
}
fn mx(preference: u16, host: &str) -> Record {
    let mut data = preference.to_be_bytes().to_vec();
    data.extend(name_bytes(host));
    (15, data)
}
fn txt(parts: &[&str]) -> Record {
    let mut data = vec![];
    for part in parts {
        data.push(part.len() as u8);
        data.extend_from_slice(part.as_bytes());
    }
    (16, data)
}

fn zone() -> HashMap<String, Vec<Record>> {
    let mut z: HashMap<String, Vec<Record>> = HashMap::new();
    let mut add = |name: &str, record: Record| z.entry(name.to_owned()).or_default().push(record);
    // A complete domain.
    add("ok.test", mx(20, "backup.ok.test."));
    add("ok.test", mx(10, "mx1.ok.test."));
    add("ok.test", txt(&["google-site-verification=abc"]));
    add("ok.test", txt(&["v=spf1 mx ", "~all"]));
    add("_dmarc.ok.test", txt(&["v=DMARC1; p=none"]));
    add("sel1._domainkey.ok.test", txt(&["v=DKIM1; k=rsa; p=AAAA"]));
    // MX only.
    add("mxonly.test", mx(5, "mail.mxonly.test."));
    // Present name without the asked types (NODATA).
    add("nodata.test", txt(&["unrelated"]));
    // SPF-looking text that is not SPF, DMARC without the version tag.
    add("weak.test", mx(10, "mx.weak.test."));
    add("weak.test", txt(&["spf1 not really"]));
    add("_dmarc.weak.test", txt(&["p=reject"]));
    add("sel1._domainkey.weak.test", txt(&["k=rsa; p=AAAA"]));
    // Equal-preference free MX list with the lowest last.
    add("order.test", mx(30, "c.order.test."));
    add("order.test", mx(10, "a.order.test."));
    add("order.test", mx(20, "b.order.test."));
    // The scoped admin's own domain.
    add("host-a.test", mx(10, "mx.host-a.test."));
    add("host-a.test", txt(&["v=spf1 -all"]));
    z
}

/// The fake zone server: UDP on `ADDRESS`; names ending `servfail.test` answer SERVFAIL.
pub struct Zone {
    task: tokio::task::JoinHandle<()>,
    #[allow(dead_code)]
    pub log: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
}
impl Drop for Zone {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Zone {
    pub async fn start() -> Result<Self, std::io::Error> {
        let socket = UdpSocket::bind(ADDRESS.parse::<SocketAddr>().expect("address")).await?;
        let zone = zone();
        let log = std::sync::Arc::new(std::sync::Mutex::new(vec![]));
        let seen = log.clone();
        let task = tokio::spawn(async move {
            let mut buffer = [0u8; 512];
            loop {
                let Ok((n, peer)) = socket.recv_from(&mut buffer).await else {
                    return;
                };
                let packet = &buffer[..n];
                if packet.len() < 12 {
                    continue;
                }
                let (mut at, mut name) = (12usize, String::new());
                while let Some(&len) = packet.get(at) {
                    at += 1;
                    if len == 0 {
                        break;
                    }
                    name.push_str(
                        &String::from_utf8_lossy(&packet[at..at + len as usize]).to_lowercase(),
                    );
                    name.push('.');
                    at += len as usize;
                }
                let name = name.trim_end_matches('.').to_owned();
                let qtype = u16::from_be_bytes([packet[at], packet[at + 1]]);
                let question = &packet[12..at + 4];
                seen.lock()
                    .expect("log")
                    .push(format!("type={qtype} name={name}"));
                let answers: Vec<&Record> = zone
                    .get(&name)
                    .map(|rs| rs.iter().filter(|r| r.0 == qtype).collect())
                    .unwrap_or_default();
                let rcode: u8 = if name.ends_with("servfail.test") {
                    2
                } else if zone.contains_key(&name) {
                    0
                } else {
                    3
                };
                let mut out = vec![packet[0], packet[1], 0x84 | (packet[2] & 1), rcode];
                out.extend_from_slice(&[0, 1]);
                out.extend_from_slice(&(answers.len() as u16).to_be_bytes());
                out.extend_from_slice(&[0, 0, 0, 0]);
                out.extend_from_slice(question);
                for (kind, data) in answers {
                    out.extend_from_slice(&[0xC0, 0x0C]);
                    out.extend_from_slice(&kind.to_be_bytes());
                    out.extend_from_slice(&[0, 1, 0, 0, 0, 60]);
                    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
                    out.extend_from_slice(data);
                }
                let _ = socket.send_to(&out, peer).await;
            }
        });
        Ok(Self { task, log })
    }
}

fn base(pattern: &'static str, perm: &'static str) -> Case {
    Case {
        method: "GET",
        pattern,
        fill: vec![],
        query: "?domain=ok.test".into(),
        perm,
        body: String::new(),
        headers: vec![],
        seed: vec![
            "UPDATE domains SET name='host-a.test' WHERE id={a_domain}; UPDATE domains SET name='host-b.test' WHERE id={b_domain}".into(),
            "DELETE FROM system_config WHERE key='gateway_hostname'".into(),
        ],
        cleanup: vec!["DELETE FROM domain_signing_keys WHERE selector LIKE 'plat5%' OR selector IN ('sel1','sel2','absent')".into(), "DELETE FROM system_config WHERE key='gateway_hostname'".into()],
        effects: EFFECTS,
        table: "domain_signing_keys",
        channels: vec![],
        status: 200,
        replace: vec![],
        unshift: vec![],
    }
}

/// A signing key of the named domain (the recorded Go never sees it: see `EFFECTS`).
fn selector(domain: &str, selector: &str) -> String {
    format!("INSERT INTO domain_signing_keys(domain_id,selector,public_key_pem,private_key_pem,created_at) SELECT id,'{selector}','y','x','2026-10-01 10:00:00+00' FROM domains WHERE name='{domain}'")
}

pub fn specs(action: &str, label: &str) -> Option<Case> {
    let mut c = match action {
        "dns-records" => base("/admin/dns/records", "domains.read"),
        "dns-verify" => base("/admin/dns/verify", "domains.read"),
        _ => return None,
    };
    let verify = action == "dns-verify";
    match label {
        "success" | "denied" | "scoped-other" | "scoped-own" => {
            c.seed.push(selector("ok.test", "sel1"));
            if label == "scoped-own" {
                c.query = "?domain=HOST-A.test".into();
            }
        }
        "no-selector" => {}
        "multi-selector" => {
            c.seed.push(selector("ok.test", "sel1"));
            c.seed.push(selector("ok.test", "sel2"));
        }
        "missing-domain" => c.query = String::new(),
        "empty-domain" => c.query = "?domain=".into(),
        "blank-domain" => c.query = "?domain=%20%20".into(),
        "padded-domain" => c.query = "?domain=%20ok.test%20".into(),
        "uppercase-domain" => c.query = "?domain=OK.Test".into(),
        "escaped-domain" => c.query = "?domain=a%3Cb%3E%26c.test".into(),
        "repeated-domain" => c.query = "?domain=ok.test&domain=mxonly.test".into(),
        "gateway-host" => {
            c.seed.push("INSERT INTO system_config(key,value,description,updated_at) VALUES ('gateway_hostname','{\"value\":\"mx.custom.test\"}','d','2026-10-01 10:00:00+00')".into());
        }
        "gateway-host-empty" => {
            c.seed.push("INSERT INTO system_config(key,value,description,updated_at) VALUES ('gateway_hostname','{\"value\":\"\"}','d','2026-10-01 10:00:00+00')".into());
        }
        "gateway-host-plain" => {
            c.seed.push("INSERT INTO system_config(key,value,description,updated_at) VALUES ('gateway_hostname','\"mx.plain.test\"','d','2026-10-01 10:00:00+00')".into());
        }
        "mx-only" if verify => c.query = "?domain=mxonly.test".into(),
        "nxdomain" if verify => c.query = "?domain=nothere.test".into(),
        "nodata" if verify => c.query = "?domain=nodata.test".into(),
        "servfail" if verify => c.query = "?domain=servfail.test".into(),
        "weak-records" if verify => {
            c.query = "?domain=weak.test".into();
            c.seed.push(selector("weak.test", "sel1"));
        }
        "mx-order" if verify => c.query = "?domain=order.test".into(),
        "dkim-missing" if verify => {
            c.seed.push(selector("ok.test", "absent"));
        }
        "invalid-name" if verify => c.query = "?domain=bad%20name".into(),
        "underscore-name" if verify => c.query = "?domain=_x.ok.test".into(),
        "numeric-name" if verify => c.query = "?domain=12345".into(),
        "long-label" if verify => c.query = format!("?domain={}.test", "a".repeat(64)),
        _ => return None,
    }
    let scoped_label = label == "scoped-own" || label == "scoped-other";
    if scoped_label && label == "scoped-other" {
        c.query = "?domain=ok.test".into();
    }
    c.status = if label == "denied" { 403 } else { 0 };
    Some(c)
}
