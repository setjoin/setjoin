//! Pure-Rust TLS 1.2/1.3 live resumption, key rotation, and Go-envelope interchange tests
//! against the immutable frozen-Go recordings in `tests/conformance/tlsfront/`.
use aes::cipher::{KeyIvInit, StreamCipher};
use base64::{engine::general_purpose::STANDARD, Engine};
use rustls::{
    client::{ClientSessionMemoryCache, Resumption},
    pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer, ServerName},
    server::ProducesTickets,
    sign::{CertifiedKey, SingleCertAndKey},
    ClientConfig, HandshakeKind, RootCertStore, ServerConfig,
};
use serde_json::{json, Value};
use setjoin_tls::{state, tickets::Tickets, Frontend};
use sha2::{Digest, Sha512};
use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct Work(PathBuf);
impl Work {
    fn new(case: &str) -> Self {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../..")
            .canonicalize()
            .unwrap();
        let dir = root
            .join("test-results/gofree-tlsfront")
            .join(format!("{case}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let saved: Value = serde_json::from_slice(
            &std::fs::read(
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../../tests/conformance/tlsfront/tls13-resumed.json"),
            )
            .unwrap(),
        )
        .unwrap();
        std::fs::write(
            dir.join("cert.pem"),
            saved["certificate_pem"].as_str().unwrap(),
        )
        .unwrap();
        std::fs::write(
            dir.join("key.pem"),
            saved["public_test_key_pem"].as_str().unwrap(),
        )
        .unwrap();
        Self(dir)
    }

    fn rust(&self) -> Arc<Frontend> {
        let frontend = Frontend::from_env_with_aes(
            &|name| match name {
                "TLS_CERT_FILE" => Some(self.0.join("cert.pem").display().to_string()),
                "TLS_KEY_FILE" => Some(self.0.join("key.pem").display().to_string()),
                _ => None,
            },
            true,
        )
        .unwrap()
        .unwrap();
        frontend.set_ticket_keys([7; 32], None);
        frontend
    }

    fn roots(&self) -> RootCertStore {
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from_pem_file(self.0.join("cert.pem")).unwrap())
            .unwrap();
        roots
    }

    fn certified_key(&self) -> Arc<CertifiedKey> {
        let certs: Vec<_> = CertificateDer::pem_file_iter(self.0.join("cert.pem"))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        let key = PrivateKeyDer::from_pem_file(self.0.join("key.pem")).unwrap();
        Arc::new(
            CertifiedKey::from_der(certs, key, &rustls::crypto::ring::default_provider()).unwrap(),
        )
    }
}

impl Drop for Work {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn recording_path(version: u16) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
        "../../tests/conformance/tlsfront/tls{}-resumed.json",
        if version == 0x304 { 13 } else { 12 }
    ))
}

fn client_config(
    work: &Work,
    version: u16,
    store: Arc<ClientSessionMemoryCache>,
) -> Arc<ClientConfig> {
    let versions: &[&rustls::SupportedProtocolVersion] = match version {
        0x304 => &[&rustls::version::TLS13],
        0x303 => &[&rustls::version::TLS12],
        _ => panic!("unsupported TLS version {version:#x}"),
    };
    let mut cfg =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(versions)
            .unwrap()
            .with_root_certificates(work.roots())
            .with_no_client_auth();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    cfg.resumption = Resumption::store(store);
    Arc::new(cfg)
}

/// Extract the Subject CommonName from a DER X.509 certificate (OID 2.5.4.3).
fn leaf_cn(der: &[u8]) -> String {
    const OID_CN: &[u8] = &[0x06, 0x03, 0x55, 0x04, 0x03];
    let pos = der
        .windows(OID_CN.len())
        .rposition(|w| w == OID_CN)
        .expect("leaf certificate missing CommonName OID");
    let rest = &der[pos + OID_CN.len()..];
    assert!(rest.len() >= 2, "truncated CommonName TLV");
    assert!(
        matches!(rest[0], 0x0c | 0x13 | 0x16),
        "unexpected CommonName ASN.1 tag {:#x}",
        rest[0]
    );
    let len = rest[1] as usize;
    assert!(len < 128 && rest.len() >= 2 + len);
    std::str::from_utf8(&rest[2..2 + len]).unwrap().to_owned()
}

async fn rust_server(frontend: Arc<Frontend>) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut tls = frontend.accept(stream).await.unwrap();
        tls.write_all(b"ok\n").await.unwrap();
        tls.shutdown().await.unwrap();
    });
    (addr, task)
}

async fn probe(addr: &str, cfg: Arc<ClientConfig>) -> Value {
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut tls = tokio_rustls::TlsConnector::from(cfg)
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
        .unwrap();
    let mut body = Vec::new();
    tls.read_to_end(&mut body).await.unwrap();
    let conn = tls.get_ref().1;
    let certs = conn.peer_certificates().unwrap_or_default();
    let subject = certs
        .first()
        .map(|der| leaf_cn(der.as_ref()))
        .unwrap_or_default();
    json!({
        "alpn": String::from_utf8_lossy(conn.alpn_protocol().unwrap_or_default()),
        "body": String::from_utf8(body).unwrap(),
        "chain": certs.len(),
        "cipher": u16::from(conn.negotiated_cipher_suite().unwrap().suite()),
        "resumed": conn.handshake_kind() == Some(HandshakeKind::Resumed),
        "subject": subject,
        "version": u16::from(conn.protocol_version().unwrap()),
    })
}

/// Seal plaintext in Go 1.26 crypto/tls' ticket envelope: IV(16) || AES-128-CTR || HMAC-SHA256(32).
fn seal_go_envelope(key: [u8; 32], iv: [u8; 16], plain: &[u8]) -> Vec<u8> {
    let expanded = Sha512::digest(key);
    let mut ticket = iv.to_vec();
    ticket.extend_from_slice(plain);
    ctr::Ctr128BE::<aes::Aes128>::new_from_slices(&expanded[16..32], &iv)
        .unwrap()
        .apply_keystream(&mut ticket[16..]);
    let mac = ring::hmac::sign(
        &ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &expanded[32..48]),
        &ticket,
    );
    ticket.extend_from_slice(mac.as_ref());
    ticket
}

/// Independent Go 1.26 crypto/tls.Config.DecryptTicket + SessionState parser.
fn decrypt_and_parse_go_ticket(ticket: &[u8], keys: &[[u8; 32]]) -> Option<Vec<u8>> {
    if ticket.len() < 48 {
        return None;
    }
    let split = ticket.len() - 32;
    let (authenticated, tag) = ticket.split_at(split);
    for key in keys {
        let expanded = Sha512::digest(key);
        if ring::hmac::verify(
            &ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &expanded[32..48]),
            authenticated,
            tag,
        )
        .is_err()
        {
            continue;
        }
        let mut plain = authenticated[16..].to_vec();
        ctr::Ctr128BE::<aes::Aes128>::new_from_slices(&expanded[16..32], &authenticated[..16])
            .ok()?
            .apply_keystream(&mut plain);
        if validate_go_session_state(&plain) {
            return Some(plain);
        }
        return None;
    }
    None
}

/// Validate Go 1.26 crypto/tls.ParseSessionState server-side wire layout strictly.
fn validate_go_session_state(plain: &[u8]) -> bool {
    fn take<'a>(s: &mut &'a [u8], n: usize) -> Option<&'a [u8]> {
        let (h, t) = s.split_at_checked(n)?;
        *s = t;
        Some(h)
    }
    fn take_vec<'a>(s: &mut &'a [u8], len_bytes: usize) -> Option<&'a [u8]> {
        let mut len = 0usize;
        for &b in take(s, len_bytes)? {
            len = (len << 8) | (b as usize);
        }
        take(s, len)
    }
    let mut rest = plain;
    let Some(version) = take(&mut rest, 2) else {
        return false;
    };
    if !matches!(version, [3, 3] | [3, 4]) {
        return false;
    }
    // isClient: 1 = server-side SessionState in Go crypto/tls
    if take(&mut rest, 1) != Some(&[1][..]) {
        return false;
    }
    let Some(_cipher) = take(&mut rest, 2) else {
        return false;
    };
    let Some(_created_at) = take(&mut rest, 8) else {
        return false;
    };
    let Some(secret) = take_vec(&mut rest, 1) else {
        return false;
    };
    if secret.is_empty() {
        return false;
    }
    let Some(mut extra) = take_vec(&mut rest, 3) else {
        return false;
    };
    while !extra.is_empty() {
        if take_vec(&mut extra, 3).is_none() {
            return false;
        }
    }
    let Some(ems) = take(&mut rest, 1) else {
        return false;
    };
    if ems[0] > 1 {
        return false;
    }
    let Some(early_data) = take(&mut rest, 1) else {
        return false;
    };
    if early_data[0] != 0 {
        return false;
    }
    let Some(mut peer_certs) = take_vec(&mut rest, 3) else {
        return false;
    };
    while !peer_certs.is_empty() {
        if take_vec(&mut peer_certs, 3).is_none() || take_vec(&mut peer_certs, 2).is_none() {
            return false;
        }
    }
    if take_vec(&mut rest, 3).is_none() {
        return false;
    }
    if version == [3, 3] && take(&mut rest, 2).is_none() {
        return false;
    }
    rest.is_empty()
}

/// Extract the plaintext ticket offered by a rustls client in its ClientHello.
fn extract_client_hello_ticket(record: &[u8], version: u16) -> Option<Vec<u8>> {
    if record.len() < 9 || record[0] != 0x16 || record[5] != 0x01 {
        return None;
    }
    let hs_len = ((record[6] as usize) << 16) | ((record[7] as usize) << 8) | (record[8] as usize);
    let mut s = record.get(9..9 + hs_len)?;
    // client_version (2) + random (32)
    s = s.get(34..)?;
    // session_id
    let sid_len = *s.first()? as usize;
    s = s.get(1 + sid_len..)?;
    // cipher_suites
    let cs_len = u16::from_be_bytes([*s.first()?, *s.get(1)?]) as usize;
    s = s.get(2 + cs_len..)?;
    // compression_methods
    let comp_len = *s.first()? as usize;
    s = s.get(1 + comp_len..)?;
    // extensions
    let ext_total = u16::from_be_bytes([*s.first()?, *s.get(1)?]) as usize;
    let mut exts = s.get(2..2 + ext_total)?;
    let target_ext = if version == 0x304 {
        0x0029u16
    } else {
        0x0023u16
    };
    while exts.len() >= 4 {
        let ext_type = u16::from_be_bytes([exts[0], exts[1]]);
        let ext_len = u16::from_be_bytes([exts[2], exts[3]]) as usize;
        let ext_body = exts.get(4..4 + ext_len)?;
        exts = &exts[4 + ext_len..];
        if ext_type == target_ext {
            if version == 0x304 {
                if ext_body.len() < 4 {
                    return None;
                }
                let id_len = u16::from_be_bytes([ext_body[2], ext_body[3]]) as usize;
                return Some(ext_body.get(4..4 + id_len)?.to_vec());
            } else {
                return Some(ext_body.to_vec());
            }
        }
    }
    None
}

/// Transparent TCP relay that captures the ClientHello ticket without altering a single byte.
async fn spawn_ticket_spy(
    target: String,
    version: u16,
) -> (
    String,
    Arc<Mutex<Option<Vec<u8>>>>,
    tokio::task::JoinHandle<()>,
) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let captured = Arc::new(Mutex::new(None));
    let slot = captured.clone();
    let task = tokio::spawn(async move {
        let (mut client, _) = listener.accept().await.unwrap();
        let mut server = tokio::net::TcpStream::connect(target).await.unwrap();
        let mut header = [0u8; 5];
        client.read_exact(&mut header).await.unwrap();
        let rec_len = u16::from_be_bytes([header[3], header[4]]) as usize;
        let mut record = Vec::with_capacity(5 + rec_len);
        record.extend_from_slice(&header);
        record.resize(5 + rec_len, 0);
        client.read_exact(&mut record[5..]).await.unwrap();
        *slot.lock().unwrap() = extract_client_hello_ticket(&record, version);
        server.write_all(&record).await.unwrap();
        let _ = tokio::io::copy_bidirectional(&mut client, &mut server).await;
    });
    (addr, captured, task)
}

/// Test-only ticket minter that emits a Go-format ticket with configurable age and MAC tamper,
/// so a real rustls client sends that exact ticket in its own ClientHello (preserving transcript hash).
#[derive(Debug)]
struct ControlledGoTicketer {
    key: [u8; 32],
    age: u64,
    tamper: bool,
}

impl ProducesTickets for ControlledGoTicketer {
    fn enabled(&self) -> bool {
        true
    }
    fn lifetime(&self) -> u32 {
        7 * 24 * 3600
    }
    fn encrypt(&self, plain: &[u8]) -> Option<Vec<u8>> {
        let mut go_plain = state::for_go(plain)?;
        let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
        go_plain[5..13].copy_from_slice(&now.saturating_sub(self.age).to_be_bytes());
        let mut ticket = seal_go_envelope(self.key, [91; 16], &go_plain);
        if self.tamper {
            *ticket.last_mut()? ^= 1;
        }
        Some(ticket)
    }
    fn decrypt(&self, _cipher: &[u8]) -> Option<Vec<u8>> {
        None
    }
}

async fn controlled_issuer(
    work: &Work,
    key: [u8; 32],
    age: u64,
    tamper: bool,
) -> (String, tokio::task::JoinHandle<()>) {
    let mut provider = rustls::crypto::ring::default_provider();
    provider.cipher_suites = vec![rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256];
    let mut cfg = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(SingleCertAndKey::from(work.certified_key())));
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    cfg.send_tls13_tickets = 1;
    cfg.ticketer = Arc::new(ControlledGoTicketer { key, age, tamper });
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut tls = acceptor.accept(stream).await.unwrap();
        tls.write_all(b"ok\n").await.unwrap();
        tls.shutdown().await.unwrap();
    });
    (addr, task)
}

fn retarget_go_ticket(recorded: &Value, age: u64, tamper: bool) -> (Vec<u8>, Vec<u8>) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut plain = STANDARD
        .decode(recorded["server_state"]["plain"].as_str().unwrap())
        .unwrap();
    assert_eq!(plain[0], 3);
    assert_eq!(plain[2], 1);
    plain[5..13].copy_from_slice(&now.saturating_sub(age).to_be_bytes());
    let mut ticket = seal_go_envelope([7; 32], [91; 16], &plain);
    if tamper {
        *ticket.last_mut().unwrap() ^= 1;
    }
    (ticket, plain)
}

async fn verify_go_to_rust_session(version: u16) {
    let work = Work::new(&format!("go-to-rust-{version}"));
    let recorded: Value = serde_json::from_slice(
        &std::fs::read(recording_path(version)).expect("recorded frozen-Go fixture missing"),
    )
    .unwrap();

    // 1. Exact Go-recorded wire envelope opens bit-for-bit identically through Tickets::open.
    let original_ticket = STANDARD
        .decode(recorded["server_state"]["ticket"].as_str().unwrap())
        .unwrap();
    let original_plain = STANDARD
        .decode(recorded["server_state"]["plain"].as_str().unwrap())
        .unwrap();
    let tickets = Tickets::new().unwrap();
    tickets.set([7; 32], None);
    let opened_original = tickets
        .open(&original_ticket)
        .expect("Tickets::open must decrypt immutable frozen-Go ticket");
    assert_eq!(opened_original, original_plain);

    // 2. Retargeted Go-recorded SessionState translates cleanly via state::for_rustls
    //    and round-trips back to Go's prefix/secret via state::for_go.
    let (retargeted_ticket, retargeted_plain) = retarget_go_ticket(&recorded, 0, false);
    let opened = tickets
        .open(&retargeted_ticket)
        .expect("Tickets::open must decrypt retargeted Go ticket");
    assert_eq!(opened, retargeted_plain);
    let cipher = recorded["observation"][1]["cipher"].as_u64().unwrap() as u16;
    let rustls_state = state::for_rustls(&opened, Some("localhost"), Some(cipher))
        .expect("state::for_rustls must accept Go SessionState");
    let roundtrip_go =
        state::for_go(&rustls_state).expect("state::for_go must re-encode translated SessionState");
    assert_eq!(&roundtrip_go[..5], &retargeted_plain[..5]);
    assert_eq!(&roundtrip_go[5..13], &retargeted_plain[5..13]);
    let secret_len = retargeted_plain[13] as usize;
    assert_eq!(roundtrip_go[13] as usize, secret_len);
    assert_eq!(
        &roundtrip_go[14..14 + secret_len],
        &retargeted_plain[14..14 + secret_len]
    );

    // 3. Live over-the-wire TLS full + resumed handshakes against setjoin_tls::Frontend.
    let store = Arc::new(ClientSessionMemoryCache::new(8));
    let cfg = client_config(&work, version, store);
    let (addr1, s1) = rust_server(work.rust()).await;
    let full = probe(&addr1, cfg.clone()).await;
    s1.await.unwrap();
    assert_eq!(full, recorded["observation"][0]);

    let (addr2, s2) = rust_server(work.rust()).await;
    let resumed = probe(&addr2, cfg).await;
    s2.await.unwrap();
    assert_eq!(resumed, recorded["observation"][1]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn go_issued_tls13_ticket_resumes_on_rust() {
    verify_go_to_rust_session(0x304).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn go_issued_tls12_ticket_resumes_on_rust() {
    verify_go_to_rust_session(0x303).await;
}

async fn check_native_format(version: u16) {
    let work = Work::new(&format!("rust-to-go-format-{version}"));
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
        "../../tests/conformance/tlsfront/tls{}-session-metadata.json",
        if version == 0x304 { 13 } else { 12 }
    ));

    // Handshake 1: Frontend issues a real encrypted session ticket over TLS.
    let store = Arc::new(ClientSessionMemoryCache::new(8));
    let cfg = client_config(&work, version, store);
    let (addr1, s1) = rust_server(work.rust()).await;
    let full = probe(&addr1, cfg.clone()).await;
    s1.await.unwrap();
    assert_eq!(full["resumed"], false);

    // Handshake 2: Spy captures the exact wire ticket from ClientHello while verifying resumption.
    let (addr2, s2) = rust_server(work.rust()).await;
    let (spy_addr, captured, spy) = spawn_ticket_spy(addr2, version).await;
    let resumed = probe(&spy_addr, cfg).await;
    spy.await.unwrap();
    s2.await.unwrap();
    assert_eq!(resumed["resumed"], true);

    let wire_ticket = captured
        .lock()
        .unwrap()
        .clone()
        .expect("ClientHello did not carry Frontend-issued ticket");

    // Independent Go 1.26 crypto/tls.Config.DecryptTicket verification.
    let plain = decrypt_and_parse_go_ticket(&wire_ticket, &[[7; 32]]);
    let actual = match plain {
        Some(plain) => json!({
            "accepted": true,
            "prefix": STANDARD.encode(&plain[..5]),
            "secret_bytes": plain[13],
        }),
        None => json!({"accepted": false}),
    };
    let recorded: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    assert_eq!(actual, recorded["observation"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rust_issued_ticket_is_go_compatible_encrypted_session_state() {
    check_native_format(0x304).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rust_issued_tls12_ticket_is_go_compatible() {
    check_native_format(0x303).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ticket_rotation_and_rejections_match_recorded_go() {
    let work = Work::new("ticket-generations");
    let session: Value =
        serde_json::from_slice(&std::fs::read(recording_path(0x304)).unwrap()).unwrap();
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/conformance/tlsfront/ticket-generations.json");
    let recorded: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();

    // Positive control: controlled Go-format issuer with age=0, tamper=false resumes on Frontend.
    {
        let store = Arc::new(ClientSessionMemoryCache::new(8));
        let cfg = client_config(&work, 0x304, store);
        let (issuer_addr, issuer) = controlled_issuer(&work, [7; 32], 0, false).await;
        let first = probe(&issuer_addr, cfg.clone()).await;
        issuer.await.unwrap();
        assert_eq!(first["resumed"], false);
        let (addr, server) = rust_server(work.rust()).await;
        let second = probe(&addr, cfg).await;
        server.await.unwrap();
        assert_eq!(
            second["resumed"], true,
            "positive control ticket must resume on Frontend"
        );
    }

    let cases = [
        ("current", 7, None, 0, false),
        ("previous", 9, Some(7), 0, false),
        ("older-rejected", 9, Some(8), 0, false),
        ("bad-mac", 7, None, 0, true),
        ("expired", 7, None, 8 * 86400, false),
    ];

    for (index, (case, current, previous, age, tamper)) in cases.into_iter().enumerate() {
        let expected = &recorded["observation"][index]["observation"];

        // (a) Direct Go-envelope check against immutable recorded Go SessionState.
        let (go_ticket, _) = retarget_go_ticket(&session, age, tamper);
        let ring = Tickets::new().unwrap();
        ring.set([current; 32], previous.map(|p| [p; 32]));
        let accepted = ring
            .open(&go_ticket)
            .and_then(|plain| state::for_rustls(&plain, Some("localhost"), Some(0x1301)))
            .is_some();
        assert_eq!(
            accepted,
            expected["resumed"].as_bool().unwrap(),
            "Go-envelope check for {case}"
        );

        // (b) Live over-the-wire TLS 1.3 resumption against setjoin_tls::Frontend.
        let store = Arc::new(ClientSessionMemoryCache::new(8));
        let cfg = client_config(&work, 0x304, store);
        if age == 0 && !tamper {
            let (addr1, s1) = rust_server(work.rust()).await;
            let first = probe(&addr1, cfg.clone()).await;
            s1.await.unwrap();
            assert_eq!(first["resumed"], false);
        } else {
            let (issuer_addr, issuer) = controlled_issuer(&work, [7; 32], age, tamper).await;
            let first = probe(&issuer_addr, cfg.clone()).await;
            issuer.await.unwrap();
            assert_eq!(first["resumed"], false);
        }

        let frontend = work.rust();
        frontend.set_ticket_keys([current; 32], previous.map(|p| [p; 32]));
        let (addr2, s2) = rust_server(frontend).await;
        let actual = probe(&addr2, cfg).await;
        s2.await.unwrap();
        assert_eq!(&actual, expected, "{case}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ticket_key_mutant_is_rejected_by_the_oracle() {
    let work = Work::new("ticket-mutant");
    let recorded: Value =
        serde_json::from_slice(&std::fs::read(recording_path(0x304)).unwrap()).unwrap();

    // Direct Go-envelope check: wrong key must fail Tickets::open.
    let (go_ticket, _) = retarget_go_ticket(&recorded, 0, false);
    let wrong_ring = Tickets::new().unwrap();
    wrong_ring.set([8; 32], None);
    assert!(wrong_ring.open(&go_ticket).is_none());

    // Live over-the-wire check: Frontend with wrong key must fall back to a full handshake.
    let store = Arc::new(ClientSessionMemoryCache::new(8));
    let cfg = client_config(&work, 0x304, store);
    let (addr1, s1) = rust_server(work.rust()).await;
    let first = probe(&addr1, cfg.clone()).await;
    s1.await.unwrap();
    assert_eq!(first["resumed"], false);

    let frontend = work.rust();
    frontend.set_ticket_keys([8; 32], None);
    let (addr2, s2) = rust_server(frontend).await;
    let actual = probe(&addr2, cfg).await;
    s2.await.unwrap();
    assert_ne!(
        actual, recorded["observation"][1],
        "oracle accepted a broken ticket-key consumer"
    );
    assert_eq!(actual["resumed"], false);
}
