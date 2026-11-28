//! In-process fake LDAP directory (RFC 4511 subset) shared by the frozen-Go
//! recorder and the Rust replay (#380). It speaks BER over implicit TLS
//! (`ldaps`) or plain TCP with the `StartTLS` extended operation, supports
//! simple bind, subtree search with filters and the paged-results control, and
//! records every operation it receives so the wire interaction becomes part of
//! the oracle observation. Test support only; never linked into a gateway.
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;

/// Test CA that signs `SERVER_CERT` (127.0.0.1 and localhost). Mount or point
/// `SSL_CERT_FILE` at it so both clients verify the server normally.
pub const CA_PEM: &str = include_str!("../directory-sync/ldap-fixture/ca.pem");
const SERVER_CERT: &str = include_str!("../directory-sync/ldap-fixture/server.pem");
const SERVER_KEY: &str = include_str!("../directory-sync/ldap-fixture/server.p8");

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Transport {
    Ldaps,
    StartTls,
}

#[derive(Clone, Debug, Default)]
pub struct Entry {
    pub dn: String,
    pub attrs: Vec<(String, Vec<String>)>,
    /// Binary attribute values (an Active Directory `objectGUID`).
    pub bin: Vec<(String, Vec<u8>)>,
}

impl Entry {
    pub fn new(dn: &str, attrs: &[(&str, &str)]) -> Self {
        let mut out = Entry {
            dn: dn.into(),
            attrs: vec![],
            bin: vec![],
        };
        for (name, value) in attrs {
            match out
                .attrs
                .iter_mut()
                .find(|(n, _)| n.eq_ignore_ascii_case(name))
            {
                Some((_, values)) => values.push((*value).into()),
                None => out.attrs.push(((*name).into(), vec![(*value).into()])),
            }
        }
        out
    }
    /// Add one binary-valued attribute.
    pub fn with_bin(mut self, name: &str, value: &[u8]) -> Self {
        self.bin.push((name.into(), value.to_vec()));
        self
    }
    fn values(&self, name: &str) -> Vec<&str> {
        if name.eq_ignore_ascii_case("distinguishedName") || name.eq_ignore_ascii_case("dn") {
            return vec![&self.dn];
        }
        self.attrs
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case(name))
            .flat_map(|(_, v)| v.iter().map(String::as_str))
            .collect()
    }
}

#[derive(Default)]
struct State {
    entries: Vec<Entry>,
    bind_dn: String,
    bind_password: String,
    fail_search: bool,
    log: Vec<String>,
}

/// Running fake directory. Dropping it stops accepting connections.
pub struct FakeLdap {
    pub addr: SocketAddr,
    state: Arc<Mutex<State>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for FakeLdap {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl FakeLdap {
    pub async fn start(transport: Transport) -> std::io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        Self::on(listener, transport)
    }
    pub fn on(listener: TcpListener, transport: Transport) -> std::io::Result<Self> {
        let addr = listener.local_addr()?;
        let state = Arc::new(Mutex::new(State::default()));
        let acceptor = acceptor();
        let shared = state.clone();
        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let (state, acceptor) = (shared.clone(), acceptor.clone());
                tokio::spawn(async move {
                    let _ = serve(stream, transport, acceptor, state).await;
                });
            }
        });
        Ok(Self { addr, state, task })
    }
    pub fn set_credentials(&self, dn: &str, password: &str) {
        let mut s = self.state.lock().unwrap();
        s.bind_dn = dn.into();
        s.bind_password = password.into();
    }
    pub fn set_entries(&self, entries: Vec<Entry>) {
        self.state.lock().unwrap().entries = entries;
    }
    pub fn fail_search(&self, fail: bool) {
        self.state.lock().unwrap().fail_search = fail;
    }
    /// Operations received so far, one line each (bind DN, search parameters).
    pub fn log(&self) -> Vec<String> {
        self.state.lock().unwrap().log.clone()
    }
    pub fn clear_log(&self) {
        self.state.lock().unwrap().log.clear();
    }
}

fn acceptor() -> TlsAcceptor {
    let certs: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(SERVER_CERT.as_bytes())
            .collect::<Result<_, _>>()
            .expect("fixture certificate");
    let key = PrivateKeyDer::from_pem_slice(SERVER_KEY.as_bytes()).expect("fixture key");
    let config = ServerConfig::builder_with_provider(Arc::new(
        tokio_rustls::rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("protocol versions")
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .expect("fixture identity");
    TlsAcceptor::from(Arc::new(config))
}

trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

async fn serve(
    stream: TcpStream,
    transport: Transport,
    acceptor: TlsAcceptor,
    state: Arc<Mutex<State>>,
) -> std::io::Result<()> {
    match transport {
        Transport::Ldaps => {
            let tls = acceptor.accept(stream).await?;
            session(Box::new(tls), None, state).await
        }
        Transport::StartTls => session(Box::new(stream), Some(acceptor), state).await,
    }
}

// ---- BER -----------------------------------------------------------------

fn len_bytes(n: usize) -> Vec<u8> {
    if n < 0x80 {
        vec![n as u8]
    } else if n < 0x100 {
        vec![0x81, n as u8]
    } else if n < 0x10000 {
        vec![0x82, (n >> 8) as u8, n as u8]
    } else {
        vec![0x83, (n >> 16) as u8, (n >> 8) as u8, n as u8]
    }
}
fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend(len_bytes(body.len()));
    out.extend_from_slice(body);
    out
}
fn int(tag: u8, mut n: i64) -> Vec<u8> {
    let mut bytes = vec![];
    loop {
        bytes.push(n as u8);
        n >>= 8;
        if (n == 0 && bytes.last().unwrap() & 0x80 == 0)
            || (n == -1 && bytes.last().unwrap() & 0x80 != 0)
        {
            break;
        }
    }
    bytes.reverse();
    tlv(tag, &bytes)
}
fn octets(s: &str) -> Vec<u8> {
    tlv(0x04, s.as_bytes())
}

/// One decoded TLV: tag, value, rest.
fn take(buf: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let tag = *buf.first()?;
    let first = *buf.get(1)?;
    let (len, off) = if first < 0x80 {
        (first as usize, 2)
    } else {
        let n = (first & 0x7f) as usize;
        let mut len = 0usize;
        for b in buf.get(2..2 + n)? {
            len = (len << 8) | *b as usize;
        }
        (len, 2 + n)
    };
    Some((tag, buf.get(off..off + len)?, buf.get(off + len..)?))
}
fn decode_int(v: &[u8]) -> i64 {
    let mut n: i64 = if v.first().is_some_and(|b| b & 0x80 != 0) {
        -1
    } else {
        0
    };
    for b in v {
        n = (n << 8) | *b as i64;
    }
    n
}
fn text(v: &[u8]) -> String {
    String::from_utf8_lossy(v).into_owned()
}

async fn read_message<R: AsyncRead + Unpin>(r: &mut R) -> std::io::Result<Vec<u8>> {
    let mut head = vec![0u8; 2];
    r.read_exact(&mut head).await?;
    if head[1] >= 0x80 {
        let n = (head[1] & 0x7f) as usize;
        let mut extra = vec![0u8; n];
        r.read_exact(&mut extra).await?;
        head.extend(extra);
    }
    let (_, _, _) = (0, 0, 0);
    let first = head[1];
    let len = if first < 0x80 {
        first as usize
    } else {
        head[2..].iter().fold(0usize, |l, b| (l << 8) | *b as usize)
    };
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).await?;
    head.extend(body);
    Ok(head)
}

// ---- filter ----------------------------------------------------------------

/// Parsed search filter in RFC 4515 text form and as an evaluator.
fn filter_text(f: &[u8]) -> String {
    let Some((tag, v, _)) = take(f) else {
        return "?".into();
    };
    let pair = |v: &[u8]| {
        let (_, a, rest) = take(v).unwrap_or((0, b"", b""));
        let (_, b, _) = take(rest).unwrap_or((0, b"", b""));
        (text(a), text(b))
    };
    let children = |mut v: &[u8]| {
        let mut out = String::new();
        while let Some((_, _, rest)) = take(v) {
            out += &filter_text(v);
            v = rest;
        }
        out
    };
    match tag {
        0xa0 => format!("(&{})", children(v)),
        0xa1 => format!("(|{})", children(v)),
        0xa2 => format!("(!{})", filter_text(v)),
        0xa3 => {
            let (a, b) = pair(v);
            format!("({a}={})", escape(&b))
        }
        0xa5 => {
            let (a, b) = pair(v);
            format!("({a}>={})", escape(&b))
        }
        0xa6 => {
            let (a, b) = pair(v);
            format!("({a}<={})", escape(&b))
        }
        0x87 => format!("({}=*)", text(v)),
        0xa4 => {
            let (a, parts) = take(v).map(|(_, a, r)| (text(a), r)).unwrap_or_default();
            let (_, seq, _) = take(parts).unwrap_or((0, b"", b""));
            let mut out = String::new();
            let mut rest = seq;
            while let Some((t, p, r)) = take(rest) {
                if t == 0x80 {
                    out += &escape(&text(p));
                    out += "*";
                } else if t == 0x81 {
                    out += &format!("*{}*", escape(&text(p)));
                } else {
                    out += &format!("*{}", escape(&text(p)));
                }
                rest = r;
            }
            format!("({a}={})", out.replace("**", "*"))
        }
        _ => "(?)".into(),
    }
}
fn escape(s: &str) -> String {
    s.replace('\\', "\\5c")
        .replace('*', "\\2a")
        .replace('(', "\\28")
        .replace(')', "\\29")
}

/// Integer-syntax attributes (AD `uSNChanged`) compare numerically; everything
/// else (generalized time) compares as text.
fn order(a: &str, b: &str) -> std::cmp::Ordering {
    match (a.parse::<i64>(), b.parse::<i64>()) {
        (Ok(x), Ok(y)) => x.cmp(&y),
        _ => a.cmp(b),
    }
}

fn matches(f: &[u8], entry: &Entry) -> bool {
    let Some((tag, v, _)) = take(f) else {
        return false;
    };
    let pair = |v: &[u8]| {
        let (_, a, rest) = take(v).unwrap_or((0, b"", b""));
        let (_, b, _) = take(rest).unwrap_or((0, b"", b""));
        (text(a), text(b))
    };
    match tag {
        0xa0 | 0xa1 => {
            let mut results = vec![];
            let mut rest = v;
            while let Some((_, _, r)) = take(rest) {
                results.push(matches(rest, entry));
                rest = r;
            }
            if tag == 0xa0 {
                results.iter().all(|x| *x)
            } else {
                results.iter().any(|x| *x)
            }
        }
        0xa2 => !matches(v, entry),
        0xa3 => {
            let (a, b) = pair(v);
            entry.values(&a).iter().any(|x| x.eq_ignore_ascii_case(&b))
        }
        0xa5 => {
            let (a, b) = pair(v);
            entry.values(&a).iter().any(|x| order(x, &b).is_ge())
        }
        0xa6 => {
            let (a, b) = pair(v);
            entry.values(&a).iter().any(|x| order(x, &b).is_le())
        }
        0x87 => !entry.values(&text(v)).is_empty(),
        0xa4 => {
            let (a, parts) = take(v).map(|(_, a, r)| (text(a), r)).unwrap_or_default();
            let (_, seq, _) = take(parts).unwrap_or((0, b"", b""));
            let mut needles = vec![];
            let mut rest = seq;
            while let Some((t, p, r)) = take(rest) {
                needles.push((t, text(p).to_lowercase()));
                rest = r;
            }
            entry.values(&a).iter().any(|x| {
                let x = x.to_lowercase();
                needles.iter().all(|(t, n)| match t {
                    0x80 => x.starts_with(n),
                    0x82 => x.ends_with(n),
                    _ => x.contains(n),
                })
            })
        }
        _ => false,
    }
}

// ---- session ---------------------------------------------------------------

fn result(tag: u8, id: i64, code: i64, diagnostic: &str, extra: &[u8], controls: &[u8]) -> Vec<u8> {
    let mut body = int(0x0a, code);
    body.extend(octets(""));
    body.extend(octets(diagnostic));
    body.extend_from_slice(extra);
    let mut message = int(0x02, id);
    message.extend(tlv(tag, &body));
    message.extend_from_slice(controls);
    tlv(0x30, &message)
}

async fn session(
    mut io: Box<dyn Io>,
    mut upgrade: Option<TlsAcceptor>,
    state: Arc<Mutex<State>>,
) -> std::io::Result<()> {
    let mut bound = false;
    // Paged-search cursors keyed by cookie.
    let mut cursors: HashMap<Vec<u8>, usize> = HashMap::new();
    let mut next_cookie = 1u64;
    loop {
        let raw = read_message(&mut io).await?;
        let (_, message, _) = take(&raw).ok_or(std::io::ErrorKind::InvalidData)?;
        let (_, id, rest) = take(message).ok_or(std::io::ErrorKind::InvalidData)?;
        let id = decode_int(id);
        let (op, body, controls) = take(rest).ok_or(std::io::ErrorKind::InvalidData)?;
        match op {
            0x60 => {
                let (_, _version, rest) = take(body).ok_or(std::io::ErrorKind::InvalidData)?;
                let (_, name, rest) = take(rest).ok_or(std::io::ErrorKind::InvalidData)?;
                let (_, password, _) = take(rest).ok_or(std::io::ErrorKind::InvalidData)?;
                let (name, password) = (text(name), text(password));
                let (ok, shown) = {
                    let mut s = state.lock().unwrap();
                    let ok = name == s.bind_dn && password == s.bind_password;
                    let shown = format!(
                        "bind dn={name} password={}",
                        if ok { "ok" } else { "wrong" }
                    );
                    s.log.push(shown.clone());
                    (ok, shown)
                };
                let _ = shown;
                bound = ok;
                let reply = if ok {
                    result(0x61, id, 0, "", &[], &[])
                } else {
                    result(0x61, id, 49, "invalid credentials", &[], &[])
                };
                io.write_all(&reply).await?;
            }
            0x77 => {
                let (_, oid, _) = take(body).ok_or(std::io::ErrorKind::InvalidData)?;
                if oid == b"1.3.6.1.4.1.1466.20037" {
                    state.lock().unwrap().log.push("starttls".into());
                    match upgrade.take() {
                        Some(acceptor) => {
                            io.write_all(&result(0x78, id, 0, "", &[], &[])).await?;
                            io.flush().await?;
                            io = Box::new(acceptor.accept(io).await?);
                        }
                        None => {
                            io.write_all(&result(0x78, id, 2, "already secured", &[], &[]))
                                .await?;
                        }
                    }
                } else {
                    io.write_all(&result(0x78, id, 2, "unsupported", &[], &[]))
                        .await?;
                }
            }
            0x63 => {
                let (_, base, rest) = take(body).ok_or(std::io::ErrorKind::InvalidData)?;
                let (_, scope, rest) = take(rest).ok_or(std::io::ErrorKind::InvalidData)?;
                let (_, _deref, rest) = take(rest).ok_or(std::io::ErrorKind::InvalidData)?;
                let (_, size_limit, rest) = take(rest).ok_or(std::io::ErrorKind::InvalidData)?;
                let (_, _time, rest) = take(rest).ok_or(std::io::ErrorKind::InvalidData)?;
                let (_, _types_only, rest) = take(rest).ok_or(std::io::ErrorKind::InvalidData)?;
                let filter = rest;
                let (_, _, rest) = take(filter).ok_or(std::io::ErrorKind::InvalidData)?;
                let (_, attributes, _) = take(rest).ok_or(std::io::ErrorKind::InvalidData)?;
                let mut wanted = vec![];
                let mut rest = attributes;
                while let Some((_, a, r)) = take(rest) {
                    wanted.push(text(a));
                    rest = r;
                }
                // Paged-results control 1.2.840.113556.1.4.319.
                let mut paging: Option<(usize, Vec<u8>)> = None;
                if let Some((0xa0, list, _)) = take(controls) {
                    let mut rest = list;
                    while let Some((_, control, r)) = take(rest) {
                        let (_, oid, c) = take(control).unwrap_or((0, b"", b""));
                        if oid == b"1.2.840.113556.1.4.319" {
                            let mut c = c;
                            if let Some((0x01, _, after)) = take(c) {
                                c = after;
                            }
                            if let Some((_, value, _)) = take(c) {
                                if let Some((_, seq, _)) = take(value) {
                                    let (_, size, cookie) = take(seq).unwrap_or((0, b"", b""));
                                    let (_, cookie, _) = take(cookie).unwrap_or((0, b"", b""));
                                    paging = Some((decode_int(size) as usize, cookie.to_vec()));
                                }
                            }
                        }
                        rest = r;
                    }
                }
                let (fail, entries, shown) = {
                    let mut s = state.lock().unwrap();
                    let shown = format!(
                        "search base={} scope={} sizeLimit={} filter={} attrs={} page={}",
                        text(base),
                        decode_int(scope),
                        decode_int(size_limit),
                        filter_text(filter),
                        wanted.join(","),
                        paging.as_ref().map_or(0, |p| p.0),
                    );
                    s.log.push(shown.clone());
                    (s.fail_search, s.entries.clone(), shown)
                };
                let _ = shown;
                if !bound {
                    io.write_all(&result(0x65, id, 50, "bind required", &[], &[]))
                        .await?;
                    continue;
                }
                if fail {
                    io.write_all(&result(0x65, id, 1, "operations error", &[], &[]))
                        .await?;
                    continue;
                }
                let hits: Vec<&Entry> = entries.iter().filter(|e| matches(filter, e)).collect();
                let (start, size) = match &paging {
                    Some((size, cookie)) => (
                        cursors.remove(cookie).unwrap_or(0),
                        if *size == 0 { usize::MAX } else { *size },
                    ),
                    None => (0, usize::MAX),
                };
                let end = start.saturating_add(size).min(hits.len());
                for entry in &hits[start.min(hits.len())..end] {
                    let mut attrs = vec![];
                    for (name, values) in &entry.attrs {
                        if !wanted.is_empty()
                            && !wanted.iter().any(|w| w.eq_ignore_ascii_case(name))
                        {
                            continue;
                        }
                        let set: Vec<u8> = values.iter().flat_map(|v| octets(v)).collect();
                        let mut one = octets(name);
                        one.extend(tlv(0x31, &set));
                        attrs.extend(tlv(0x30, &one));
                    }
                    for (name, value) in &entry.bin {
                        if !wanted.is_empty()
                            && !wanted.iter().any(|w| w.eq_ignore_ascii_case(name))
                        {
                            continue;
                        }
                        let mut one = octets(name);
                        one.extend(tlv(0x31, &tlv(0x04, value)));
                        attrs.extend(tlv(0x30, &one));
                    }
                    let mut body = octets(&entry.dn);
                    body.extend(tlv(0x30, &attrs));
                    let mut message = int(0x02, id);
                    message.extend(tlv(0x64, &body));
                    io.write_all(&tlv(0x30, &message)).await?;
                }
                let mut control = vec![];
                if paging.is_some() {
                    let cookie = if end < hits.len() {
                        let key = next_cookie.to_be_bytes().to_vec();
                        next_cookie += 1;
                        cursors.insert(key.clone(), end);
                        key
                    } else {
                        vec![]
                    };
                    let mut value = int(0x02, 0);
                    value.extend(tlv(0x04, &cookie));
                    let mut c = octets("1.2.840.113556.1.4.319");
                    c.extend(tlv(0x04, &tlv(0x30, &value)));
                    control = tlv(0xa0, &tlv(0x30, &c));
                }
                io.write_all(&result(0x65, id, 0, "", &[], &control))
                    .await?;
            }
            0x42 => return Ok(()),
            _ => {
                io.write_all(&result(0x65, id, 2, "protocol error", &[], &[]))
                    .await?;
            }
        }
        io.flush().await?;
    }
}
