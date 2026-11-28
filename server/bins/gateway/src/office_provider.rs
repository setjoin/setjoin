//! Office's peripheral HTTPS protocol. Every DNS answer is checked and pinned
//! before connecting; neither proxy environment nor redirects can widen policy.
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};
const UNSAFE: &str = "URL is not allowed (must be http/https to a public host)";
#[derive(Clone, Default)]
struct Policy {
    hosts: Vec<String>,
    nets: Vec<ipnet::IpNet>,
}
impl Policy {
    fn compile(target: &Value) -> Result<Self, String> {
        let mut p = Self::default();
        for h in target["privateAllowHosts"].as_array().into_iter().flatten() {
            let raw = h.as_str().ok_or("invalid private-policy hostname")?;
            let host = raw.trim().trim_end_matches('.').to_lowercase();
            if host.is_empty()
                || host.contains(['/', ':', '@', '[', ']'])
                || host.parse::<IpAddr>().is_ok()
            {
                return Err(format!("invalid private-policy hostname {raw:?}"));
            }
            p.hosts.push(host);
        }
        for n in target["privateAllowCidrs"].as_array().into_iter().flatten() {
            let raw = n.as_str().ok_or("invalid private-policy CIDR")?;
            let net = raw
                .trim()
                .parse::<ipnet::IpNet>()
                .map_err(|_| format!("invalid private-policy CIDR {raw:?}"))?;
            if !private(net.network()) || !private(net.broadcast()) {
                return Err(format!("invalid private-policy CIDR {raw:?}"));
            }
            p.nets.push(net);
        }
        if p.hosts.is_empty() != p.nets.is_empty() {
            return Err("private-policy hosts and CIDRs must be configured together".into());
        }
        Ok(p)
    }
    fn host_allowed(&self, h: &str) -> bool {
        self.hosts
            .iter()
            .any(|v| v == &h.trim_end_matches('.').to_lowercase())
    }
    fn allows(&self, host: &str, ip: IpAddr) -> bool {
        !blocked(ip)
            || (self.host_allowed(host)
                && private(ip)
                && !permanent(ip)
                && self.nets.iter().any(|n| n.contains(&ip)))
    }
}
fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v) => v.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        _ => ip,
    }
}
fn private(ip: IpAddr) -> bool {
    match canonical(ip) {
        IpAddr::V4(v) => v.is_private(),
        IpAddr::V6(v) => (v.segments()[0] & 0xfe00) == 0xfc00,
    }
}
fn permanent(ip: IpAddr) -> bool {
    let ip = canonical(ip);
    if ip.is_loopback() || ip.is_multicast() || ip.is_unspecified() {
        return true;
    }
    match ip {
        IpAddr::V4(v) => {
            let a = v.octets();
            if a[0] == 169 && a[1] == 254 {
                return true;
            }
        }
        IpAddr::V6(v) => {
            if v.segments()[0] & 0xffc0 == 0xfe80 {
                return true;
            }
        }
    }
    [
        "0.0.0.0/8",
        "100.64.0.0/10",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "192.31.196.0/24",
        "192.52.193.0/24",
        "192.88.99.0/24",
        "192.175.48.0/24",
        "198.18.0.0/15",
        "240.0.0.0/4",
        "100::/64",
        "2001:db8::/32",
        "64:ff9b::/96",
    ]
    .iter()
    .any(|n| {
        n.parse::<ipnet::IpNet>()
            .expect("static CIDR")
            .contains(&ip)
    })
}
fn blocked(ip: IpAddr) -> bool {
    private(ip) || permanent(ip)
}
fn url(raw: &str, policy: &Policy, proof: bool) -> Result<reqwest::Url, String> {
    let u = reqwest::Url::parse(raw).map_err(|_| UNSAFE.to_owned())?;
    let h = u.host_str().ok_or(UNSAFE)?;
    if u.scheme() != "https"
        || !u.username().is_empty()
        || u.password().is_some()
        || (proof && u.fragment().is_some())
    {
        return Err(UNSAFE.into());
    }
    if h.trim_matches(['[', ']'])
        .parse::<IpAddr>()
        .is_ok_and(blocked)
        || (!policy.host_allowed(h) && h.to_lowercase().ends_with(".local"))
    {
        return Err(UNSAFE.into());
    }
    Ok(u)
}
fn same_origin(first: &reqwest::Url, next: &reqwest::Url) -> bool {
    first.scheme() == "https"
        && next.scheme() == "https"
        && first.host_str() == next.host_str()
        && first.port() == next.port()
        && next.username().is_empty()
        && next.password().is_none()
}
async fn fetch(raw: &str, method: reqwest::Method, policy: &Policy) -> Result<Vec<u8>, String> {
    tokio::time::timeout(Duration::from_secs(12), async {
        let target = url(raw, policy, false)?;
        let host = target.host_str().ok_or(UNSAFE)?.trim_matches(['[', ']']);
        let addresses: Vec<SocketAddr> =
            tokio::net::lookup_host((host, target.port_or_known_default().ok_or(UNSAFE)?))
                .await
                .map_err(|_| UNSAFE)?
                .collect();
        if addresses.is_empty() || addresses.iter().any(|a| !policy.allows(host, a.ip())) {
            return Err(UNSAFE.into());
        }
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(12))
            .resolve_to_addrs(host, &addresses)
            .build()
            .map_err(|e| e.to_string())?;
        qualification_response(
            client
                .request(method.clone(), target)
                .header("accept", "application/xml,text/xml,*/*;q=0.1")
                .send()
                .await
                .map_err(|e| e.to_string())?,
            method,
        )
        .await
    })
    .await
    .map_err(|_| "request timed out".to_owned())?
}
#[derive(Deserialize)]
struct Discovery {
    #[serde(rename = "proof-key", default)]
    key: KeyAttributes,
}
#[derive(Deserialize, Default)]
struct KeyAttributes {
    #[serde(rename = "@modulus", default)]
    modulus: String,
    #[serde(rename = "@exponent", default)]
    exponent: String,
    #[serde(rename = "@oldmodulus", default)]
    old_modulus: String,
    #[serde(rename = "@oldexponent", default)]
    old_exponent: String,
}
#[derive(Clone)]
struct PublicKey {
    modulus: Vec<u8>,
    exponent: Vec<u8>,
}
fn key(modulus: &str, exponent: &str) -> Result<PublicKey, String> {
    let m = STANDARD
        .decode(modulus.replace(['\r', '\n'], ""))
        .map_err(|_| "invalid WOPI proof modulus")?;
    if m.is_empty() {
        return Err("invalid WOPI proof modulus".into());
    }
    if m.len() < 256 {
        return Err(format!(
            "WOPI proof modulus of {} bits is below the 2048-bit floor",
            m.len() * 8
        ));
    }
    let e = STANDARD
        .decode(exponent.replace(['\r', '\n'], ""))
        .map_err(|_| "invalid WOPI proof exponent")?;
    if e.is_empty() || e.len() > 4 {
        return Err("invalid WOPI proof exponent".into());
    }
    let n = e.iter().fold(0u32, |n, b| (n << 8) | u32::from(*b));
    if !(3..=i32::MAX as u32).contains(&n) {
        return Err("invalid WOPI proof exponent value".into());
    }
    Ok(PublicKey {
        modulus: m,
        exponent: e,
    })
}
fn discovery(bytes: &[u8]) -> Result<Discovery, String> {
    quick_xml::de::from_reader(bytes).map_err(|e| format!("discovery XML: {e}"))
}
/// Frozen Go's qualification checks; a successful synthetic save remains a
/// reducer-owned prerequisite, never an assertion accepted from the caller.
pub async fn qualify(target: &Value) -> Result<(Value, String), String> {
    qualify_with_client(target, None).await
}
/// An injected TLS client is the outbound fake-provider seam. Native callers
/// leave it unset and always use DNS-answer pinning above.
pub async fn qualify_with_client(
    target: &Value,
    client: Option<&reqwest::Client>,
) -> Result<(Value, String), String> {
    let policy =
        Policy::compile(target).map_err(|e| format!("compile private target policy: {e}"))?;
    for (name, field) in [
        ("proof discovery", "proofDiscoveryUrl"),
        ("editor", "editorUrl"),
        ("WOPI public base", "wopiPublicBaseUrl"),
    ] {
        url(target[field].as_str().unwrap_or(""), &policy, false)
            .map_err(|e| format!("{name} URL: {e}"))?;
    }
    let discovery_url = target["proofDiscoveryUrl"].as_str().unwrap_or("");
    let editor = target["editorUrl"].as_str().unwrap_or("");
    let first = reqwest::Url::parse(discovery_url).map_err(|e| e.to_string())?;
    let second = reqwest::Url::parse(editor).map_err(|e| e.to_string())?;
    if !same_origin(&first, &second) {
        return Err("editor and WOPI discovery must use the same HTTPS origin".into());
    }
    let bytes = qualification_fetch(discovery_url, reqwest::Method::GET, &policy, client)
        .await
        .map_err(|e| format!("discovery: {e}"))?;
    let doc = discovery(&bytes)?;
    key(&doc.key.modulus, &doc.key.exponent).map_err(|e| format!("proof key: {e}"))?;
    qualification_fetch(editor, reqwest::Method::HEAD, &policy, client)
        .await
        .map_err(|e| format!("editor: {e}"))?;
    Ok((
        serde_json::json!({"discovery":"pass","proof":"pass","editor":"pass","wopiSave":"pass","discoveryBytes":bytes.len()}),
        format!("{:x}", Sha256::digest(bytes)),
    ))
}

#[derive(Clone)]
struct ProofKeys {
    current: PublicKey,
    old: Option<PublicKey>,
    at: std::time::Instant,
}
/// Process-local proof-key cache. The executable uses the guarded native
/// transport; tests may pin the address of their own TLS fake provider.
#[derive(Default)]
pub struct ProofVerifier {
    cache: tokio::sync::Mutex<std::collections::HashMap<String, ProofKeys>>,
    address: Option<SocketAddr>,
}
impl ProofVerifier {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn with_address(address: SocketAddr) -> Self {
        Self {
            address: Some(address),
            ..Self::default()
        }
    }
    async fn keys(&self, raw: &str) -> Result<ProofKeys, String> {
        url(raw, &Policy::default(), true)?;
        if let Some(keys) = self
            .cache
            .lock()
            .await
            .get(raw)
            .filter(|k| k.at.elapsed() < Duration::from_secs(12 * 3600))
            .cloned()
        {
            return Ok(keys);
        }
        let bytes = proof_fetch(raw, self.address).await?;
        let doc = discovery(&bytes)?;
        let current = key(&doc.key.modulus, &doc.key.exponent)?;
        let old = if !doc.key.old_modulus.is_empty() && !doc.key.old_exponent.is_empty() {
            Some(key(&doc.key.old_modulus, &doc.key.old_exponent)?)
        } else {
            None
        };
        let keys = ProofKeys {
            current,
            old,
            at: std::time::Instant::now(),
        };
        self.cache.lock().await.insert(raw.into(), keys.clone());
        Ok(keys)
    }
    pub async fn verify<B>(
        &self,
        r: &hyper::Request<B>,
        token: &str,
        discovery: &str,
        public_base: &str,
    ) -> bool {
        const EPOCH: u64 = 621355968000000000;
        let raw = r
            .headers()
            .get("x-wopi-timestamp")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if raw.is_empty() || !raw.bytes().all(|b| b.is_ascii_digit()) {
            return false;
        }
        let Ok(timestamp) = raw.parse::<u64>() else {
            return false;
        };
        let Some(ticks) = timestamp.checked_sub(EPOCH) else {
            return false;
        };
        if ticks > i64::MAX as u64 / 100 {
            return false;
        }
        let Ok(now) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) else {
            return false;
        };
        let ns = u128::from(ticks) * 100;
        if now.as_nanos().abs_diff(ns) > 20 * 60 * 1_000_000_000 {
            return false;
        }
        let Ok(keys) = self.keys(discovery).await else {
            return false;
        };
        let uri = r.uri().path_and_query().map_or("", |v| v.as_str());
        let uri = uri.strip_prefix("/api").unwrap_or(uri);
        let request_url = format!("{}{uri}", public_base.trim_end_matches('/'));
        // Go uses Unicode's simple uppercase mapping, never multi-character folds.
        let upper: String = request_url.chars().map(simple_uppercase).collect();
        let mut payload = Vec::new();
        for part in [token.as_bytes(), upper.as_bytes()] {
            let Ok(n) = u32::try_from(part.len()) else {
                return false;
            };
            payload.extend_from_slice(&n.to_be_bytes());
            payload.extend_from_slice(part);
        }
        payload.extend_from_slice(&8u32.to_be_bytes());
        payload.extend_from_slice(&timestamp.to_be_bytes());
        let proof = r
            .headers()
            .get("x-wopi-proof")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let old = r
            .headers()
            .get("x-wopi-proofold")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        fn signature(key: &PublicKey, raw: &str, payload: &[u8]) -> bool {
            let Ok(signature) = STANDARD.decode(raw.replace(['\r', '\n'], "")) else {
                return false;
            };
            ring::signature::RsaPublicKeyComponents {
                n: &key.modulus,
                e: &key.exponent,
            }
            .verify(
                &ring::signature::RSA_PKCS1_2048_8192_SHA256,
                payload,
                &signature,
            )
            .is_ok()
        }
        signature(&keys.current, proof, &payload)
            || signature(&keys.current, old, &payload)
            || keys
                .old
                .as_ref()
                .is_some_and(|key| signature(key, proof, &payload))
    }
}

async fn qualification_fetch(
    raw: &str,
    method: reqwest::Method,
    policy: &Policy,
    client: Option<&reqwest::Client>,
) -> Result<Vec<u8>, String> {
    let Some(client) = client else {
        return fetch(raw, method, policy).await;
    };
    qualification_response(
        client
            .request(method.clone(), raw)
            .header("accept", "application/xml,text/xml,*/*;q=0.1")
            .send()
            .await
            .map_err(|e| e.to_string())?,
        method,
    )
    .await
}
async fn qualification_response(
    mut response: reqwest::Response,
    method: reqwest::Method,
) -> Result<Vec<u8>, String> {
    let status = response.status().as_u16();
    if (method == reqwest::Method::GET && status != 200)
        || (method == reqwest::Method::HEAD && !(200..500).contains(&status))
    {
        return Err(format!("unexpected HTTP status {status}"));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|e| e.to_string())? {
        if bytes.len() + chunk.len() > 2 << 20 {
            return Err("response exceeds 2 MiB".into());
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

/// Runtime proof discovery uses a bare HTTP request: reqwest's implicit
/// Accept: */* changes the frozen provider request. DNS is checked once and
/// only the checked sockets are dialed. The optional address is a trusted
/// fake-provider seam, never deployment or request configuration.
async fn proof_fetch(raw: &str, pinned: Option<SocketAddr>) -> Result<Vec<u8>, String> {
    use http_body_util::BodyExt;
    use tokio_rustls::rustls::{self, pki_types::ServerName};
    tokio::time::timeout(Duration::from_secs(5), async {
        let original = url(raw, &Policy::default(), true)?;
        let mut target = original.clone();
        let mut roots = rustls::RootCertStore::empty();
        for cert in rustls_native_certs::load_native_certs().certs {
            let _ = roots.add(cert);
        }
        let tls = tokio_rustls::TlsConnector::from(std::sync::Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        ));
        for redirects in 0..10 {
            let host = target.host_str().ok_or(UNSAFE)?.trim_matches(['[', ']']);
            let addresses = if let Some(address) = pinned {
                vec![address]
            } else {
                let addresses: Vec<_> =
                    tokio::net::lookup_host((host, target.port_or_known_default().ok_or(UNSAFE)?))
                        .await
                        .map_err(|_| UNSAFE)?
                        .collect();
                if addresses.is_empty() || addresses.iter().any(|a| blocked(a.ip())) {
                    return Err(UNSAFE.into());
                }
                addresses
            };
            let stream = tokio::net::TcpStream::connect(addresses.as_slice())
                .await
                .map_err(|e| e.to_string())?;
            let stream = tls
                .connect(
                    ServerName::try_from(host.to_owned()).map_err(|e| e.to_string())?,
                    stream,
                )
                .await
                .map_err(|e| e.to_string())?;
            let (mut sender, connection) =
                hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream))
                    .await
                    .map_err(|e| e.to_string())?;
            let connection = tokio::spawn(async move {
                let _ = connection.await;
            });
            // Dropping this guard also closes a timed-out or redirected connection.
            struct Connection(tokio::task::JoinHandle<()>);
            impl Drop for Connection {
                fn drop(&mut self) {
                    self.0.abort();
                }
            }
            let _connection = Connection(connection);
            let uri: hyper::Uri = target.as_str().parse().map_err(|_| UNSAFE)?;
            let host = uri.authority().ok_or(UNSAFE)?.as_str();
            let request = hyper::Request::builder()
                .uri(uri.path_and_query().map_or("/", |v| v.as_str()))
                .header("host", host)
                .header("user-agent", "Go-http-client/1.1")
                .header("accept-encoding", "gzip")
                .body(http_body_util::Empty::<bytes::Bytes>::new())
                .map_err(|e| e.to_string())?;
            let mut response = sender
                .send_request(request)
                .await
                .map_err(|e| e.to_string())?;
            if matches!(response.status().as_u16(), 301 | 302 | 303 | 307 | 308) {
                let next = target
                    .join(
                        response
                            .headers()
                            .get("location")
                            .and_then(|v| v.to_str().ok())
                            .ok_or("WOPI discovery redirect left its HTTPS origin")?,
                    )
                    .map_err(|e| e.to_string())?;
                if redirects >= 9 || !same_origin(&original, &next) {
                    return Err("WOPI discovery redirect left its HTTPS origin".into());
                }
                target = next;
                continue;
            }
            if response.status() != 200 {
                return Err(format!(
                    "unexpected HTTP status {}",
                    response.status().as_u16()
                ));
            }
            let gzip = response
                .headers()
                .get("content-encoding")
                .is_some_and(|v| v == "gzip");
            let mut bytes = Vec::new();
            while let Some(frame) = response.body_mut().frame().await {
                let frame = frame.map_err(|e| e.to_string())?;
                if let Ok(data) = frame.into_data() {
                    let n = data.len().min((2 << 20) - bytes.len());
                    bytes.extend_from_slice(&data[..n]);
                    if bytes.len() == 2 << 20 {
                        break;
                    }
                }
            }
            if gzip {
                use std::io::Read;
                let mut decoded = Vec::new();
                flate2::read::GzDecoder::new(bytes.as_slice())
                    .take(2 << 20)
                    .read_to_end(&mut decoded)
                    .map_err(|e| e.to_string())?;
                return Ok(decoded);
            }
            return Ok(bytes);
        }
        Err("WOPI discovery redirect left its HTTPS origin".into())
    })
    .await
    .map_err(|_| "request timed out".to_owned())?
}

// Unicode simple mappings that have a different multi-character full mapping.
// Other full expansions (for example ß) have no simple uppercase equivalent.
fn simple_uppercase(c: char) -> char {
    match c as u32 {
        0x1f80..=0x1f87 | 0x1f90..=0x1f97 | 0x1fa0..=0x1fa7 => {
            char::from_u32(c as u32 + 8).unwrap()
        }
        0x1fb3 => 'ᾼ',
        0x1fc3 => 'ῌ',
        0x1ff3 => 'ῼ',
        _ => {
            let mut upper = c.to_uppercase();
            let first = upper.next().unwrap();
            if upper.next().is_some() {
                c
            } else {
                first
            }
        }
    }
}
