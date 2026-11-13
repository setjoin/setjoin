//! Secure-behaviour tests for the owner-approved security fixes of 2026-11-05
//! (#492, #493, #488): mail authentication and the inbound listener. Each bug
//! restored by a mutant (`scripts/test-smtp-secfix-mutants.py`) must fail one of
//! these. The recorded frozen-Go corpora stay immutable; the cases they lock a bug
//! in are listed in `oracle/divergences.json`.
#[path = "support/auth_blobs.rs"]
mod auth_blobs;
#[path = "support/auth_dns.rs"]
mod auth_dns;
use base64::Engine;
use serde_json::{json, Value};
use setjoin_conformance::harness::Db;
use setjoin_smtp::mail_auth::{Features, MailAuth};
use std::{sync::Arc, time::Duration};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    sync::watch,
};

const RSA_PEM: &str = include_str!("../oracle/auth-fixture/rsa.pem");
const RSA_PUB: &str = include_str!("../oracle/auth-fixture/rsa.pub.pem");
const ED_PEM: &str = include_str!("../oracle/auth-fixture/ed25519.pem");
const ED_PUB: &str = include_str!("../oracle/auth-fixture/ed25519.pub.pem");

fn pem_body(pem: &str) -> Vec<u8> {
    let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    base64::engine::general_purpose::STANDARD
        .decode(body)
        .unwrap()
}
fn rsa_record() -> String {
    format!(
        "v=DKIM1; k=rsa; p={}",
        base64::engine::general_purpose::STANDARD.encode(pem_body(RSA_PUB))
    )
}
fn ed_record() -> String {
    let spki = pem_body(ED_PUB);
    format!(
        "v=DKIM1; k=ed25519; p={}",
        base64::engine::general_purpose::STANDARD.encode(&spki[spki.len() - 32..])
    )
}
const MESSAGE: &[u8] = b"From: Alice <alice@signer.test>\r\nTo: bob@dest.test\r\nSubject: signed\r\nDate: Thu, 05 Nov 2026 10:00:00 +0000\r\nMessage-Id: <s@signer.test>\r\n\r\nline one\r\nline two\r\n";

trait ReplaceFrom {
    fn replace_from(self, from: &str, to: &str) -> Vec<u8>;
}
impl ReplaceFrom for Vec<u8> {
    fn replace_from(self, from: &str, to: &str) -> Vec<u8> {
        String::from_utf8(self)
            .unwrap()
            .replace(from, to)
            .into_bytes()
    }
}
async fn seed_signer(owner: &tokio_postgres::Client, rows: &[(&str, &str, &str)]) {
    owner
        .batch_execute(
            "DELETE FROM domain_signing_keys WHERE selector LIKE 'sf2%'; DELETE FROM domains WHERE name IN ('signer.test','arcsign.test')",
        )
        .await
        .unwrap();
    owner
        .batch_execute(
            "INSERT INTO domains(name,is_local) VALUES ('signer.test',true),('arcsign.test',true)",
        )
        .await
        .unwrap();
    for (domain, selector, algorithm) in rows {
        let pem = if *algorithm == "rsa-sha256" {
            RSA_PEM
        } else {
            ED_PEM
        };
        owner
            .execute(
                "INSERT INTO domain_signing_keys(domain_id,selector,algorithm,public_key_pem,private_key_pem) \
                 SELECT id,$2,$3,'unused',$4 FROM domains WHERE name=$1",
                &[domain, selector, algorithm, &pem],
            )
            .await
            .unwrap();
    }
}
async fn drop_signer(owner: &tokio_postgres::Client) {
    owner
        .batch_execute(
            "DELETE FROM domain_signing_keys WHERE selector LIKE 'sf2%'; DELETE FROM domains WHERE name IN ('signer.test','arcsign.test')",
        )
        .await
        .unwrap();
}
fn auth(dns: Value) -> MailAuth {
    MailAuth::new(Features::default(), Arc::new(auth_dns::FixtureDns(dns)))
}

#[tokio::test]
async fn outbound_signing_emits_a_complete_verifiable_dkim_signature() {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("secfix2-signing") else {
        return;
    };
    let owner = db.connect().await.unwrap();
    let worker = setjoin_pg::workers::WorkerDatabase::new(&db.dsn).unwrap();
    for (algorithm, selector, record) in [
        ("rsa-sha256", "sf2rsa", rsa_record()),
        ("ed25519-sha256", "sf2ed", ed_record()),
    ] {
        seed_signer(&owner, &[("signer.test", selector, algorithm)]).await;
        let signed =
            setjoin_smtp::mail_auth::sign_outbound(&worker, "alice@signer.test", MESSAGE, false)
                .await;
        assert!(
            signed.starts_with(b"DKIM-Signature: "),
            "{algorithm}: header needs its field name: {}",
            String::from_utf8_lossy(&signed[..60.min(signed.len())])
        );
        assert!(signed.ends_with(MESSAGE), "{algorithm}: message untouched");
        let dns = json!({format!("txt:{selector}._domainkey.signer.test"): [record]});
        let verified = auth(dns.clone()).verify_dkim(&signed).await;
        assert_eq!(
            (verified.result, verified.domain.as_str()),
            ("pass", "signer.test"),
            "{algorithm}"
        );
        // Any change to a signed header or the body breaks it.
        let mut tampered = signed.clone();
        let at = tampered.windows(8).position(|w| w == b"line one").unwrap();
        tampered[at] = b'L';
        assert_eq!(auth(dns).verify_dkim(&tampered).await.result, "fail");
    }
    // A signature asserts authorship: a foreign From is never signed, and neither is a
    // rule-forward, even one whose (spoofed) From is the signing domain itself.
    seed_signer(&owner, &[("signer.test", "sf2rsa", "rsa-sha256")]).await;
    let foreign = MESSAGE
        .to_vec()
        .replace_from("alice@signer.test", "x@other.test");
    let spoofed = MESSAGE;
    for (name, raw, forwarded) in [
        (
            "forwarded message with another domain's From",
            foreign.as_slice(),
            true,
        ),
        (
            "non-forward whose From is another domain",
            foreign.as_slice(),
            false,
        ),
        (
            "forward carrying a spoofed signing-domain From",
            spoofed,
            true,
        ),
    ] {
        let out = setjoin_smtp::mail_auth::sign_outbound(
            &worker,
            "noreply-forward@signer.test",
            raw,
            forwarded,
        )
        .await;
        assert_eq!(out, raw, "{name} must leave unsigned");
    }
    let out =
        setjoin_smtp::mail_auth::sign_outbound(&worker, "alice@signer.test", MESSAGE, false).await;
    assert!(
        out.starts_with(b"DKIM-Signature: "),
        "control: own-domain message is signed"
    );
    // No key for the sender's domain: unsigned, unchanged.
    seed_signer(&owner, &[]).await;
    let plain =
        setjoin_smtp::mail_auth::sign_outbound(&worker, "alice@signer.test", MESSAGE, false).await;
    assert_eq!(plain, MESSAGE);
    // Inactive keys never sign.
    seed_signer(&owner, &[("signer.test", "sf2rsa", "rsa-sha256")]).await;
    owner
        .batch_execute("UPDATE domain_signing_keys SET active=false WHERE selector='sf2rsa'")
        .await
        .unwrap();
    let inactive =
        setjoin_smtp::mail_auth::sign_outbound(&worker, "alice@signer.test", MESSAGE, false).await;
    assert_eq!(inactive, MESSAGE);
    drop_signer(&owner).await;
}

#[tokio::test]
async fn dkim_honours_signature_expiry() {
    use mail_auth::{
        common::crypto::{RsaKey, Sha256},
        dkim::DkimSigner,
    };
    use rustls_pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    let der = pem_body(&RSA_PEM.replace("RSA PRIVATE KEY", "PRIVATE KEY"));
    let key = RsaKey::<Sha256>::from_key_der(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        der.as_slice(),
    )))
    .or_else(|_| {
        RsaKey::<Sha256>::from_key_der(PrivateKeyDer::Pkcs1(
            rustls_pki_types::PrivatePkcs1KeyDer::from(der.as_slice()),
        ))
    })
    .unwrap();
    let signature = DkimSigner::from_key(key)
        .domain("signer.test")
        .selector("sf2exp")
        .headers(["From", "To", "Subject"])
        .expiration(1)
        .sign(MESSAGE)
        .unwrap();
    use mail_auth::common::headers::HeaderWriter;
    let mut signed = signature.to_header().into_bytes();
    signed.extend_from_slice(MESSAGE);
    let auth = auth(json!({"txt:sf2exp._domainkey.signer.test": [rsa_record()]}));
    assert_eq!(auth.verify_dkim(&signed).await.result, "pass", "fresh");
    tokio::time::sleep(Duration::from_millis(2300)).await;
    assert_eq!(
        auth.verify_dkim(&signed).await.result,
        "fail",
        "an expired signature (x=) must not pass"
    );
}

#[tokio::test]
async fn spf_errors_and_syntax_are_not_silent_non_matches() {
    let table: &[(&str, Value, &str, &str)] = &[
        (
            "dns failure on an a: lookup is temperror",
            json!({"txt:s.test":["v=spf1 a:h.test -all"],"ip:h.test":"servfail"}),
            "192.0.2.1",
            "temperror",
        ),
        (
            "an unknown mechanism is permerror",
            json!({"txt:s.test":["v=spf1 bogus:x -all"]}),
            "192.0.2.1",
            "permerror",
        ),
        (
            "ip4 with an IPv6 operand is permerror",
            json!({"txt:s.test":["v=spf1 ip4:2001:db8::1 -all"]}),
            "2001:db8::1",
            "permerror",
        ),
        (
            "a bare IPv6 mechanism matches exactly",
            json!({"txt:s.test":["v=spf1 ip6:2001:db8::1 -all"]}),
            "2001:db8::1",
            "pass",
        ),
        (
            "a/24 dual-cidr is honoured",
            json!({"txt:s.test":["v=spf1 a:h.test/24 -all"],"ip:h.test":["192.0.2.1"]}),
            "192.0.2.200",
            "pass",
        ),
        (
            "ip4 never matches an IPv6 client",
            json!({"txt:s.test":["v=spf1 ip4:0.0.0.0/0 -all"]}),
            "2001:db8::1",
            "fail",
        ),
        (
            "include of a domain with no policy is permerror",
            json!({"txt:s.test":["v=spf1 include:none.test -all"]}),
            "192.0.2.1",
            "permerror",
        ),
        (
            "redirect applies only after the mechanisms",
            json!({"txt:s.test":["v=spf1 redirect=o.test ip4:192.0.2.9"],"txt:o.test":["v=spf1 -all"]}),
            "192.0.2.9",
            "pass",
        ),
        (
            "more than ten DNS terms is permerror",
            {
                let mut dns = json!({"txt:s.test": [format!(
                    "v=spf1 {} -all",
                    (0..12).map(|i| format!("a:h{i}.test")).collect::<Vec<_>>().join(" ")
                )]});
                for i in 0..12 {
                    dns[format!("ip:h{i}.test")] = json!(["198.51.100.1"]);
                }
                dns
            },
            "192.0.2.1",
            "permerror",
        ),
    ];
    for (name, dns, ip, want) in table {
        let got = auth(dns.clone())
            .check_spf("s.test", ip, "u@s.test", "helo.test")
            .await;
        assert_eq!(got, *want, "{name}");
    }
}

// ---- live inbound sessions ----

struct Live {
    addr: std::net::SocketAddr,
    stop: watch::Sender<bool>,
    task: tokio::task::JoinHandle<std::io::Result<()>>,
    blobs: Arc<auth_blobs::Blobs>,
}
impl Live {
    async fn finish(self) {
        let _ = self.stop.send(true);
        let _ = self.task.await;
    }
}
async fn start(dsn: &str, dns: Value, features: Features) -> Live {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop, rx) = watch::channel(false);
    let blobs = Arc::new(auth_blobs::Blobs::default());
    let server = setjoin_smtp::Server::new()
        .with_database(setjoin_pg::workers::WorkerDatabase::new(dsn).unwrap())
        .with_mail_auth(MailAuth::new(features, Arc::new(auth_dns::FixtureDns(dns))))
        .with_blob_store(blobs.clone());
    let task = tokio::spawn(Arc::new(server).serve(listener, rx));
    Live {
        addr,
        stop,
        task,
        blobs,
    }
}
/// Send each step and read `lines` reply lines; returns every reply.
async fn talk(addr: std::net::SocketAddr, steps: &[(Vec<u8>, usize)]) -> Vec<String> {
    let mut socket = BufReader::new(TcpStream::connect(addr).await.unwrap());
    let mut replies = Vec::new();
    let read = async |socket: &mut BufReader<TcpStream>, lines: usize| {
        let mut reply = String::new();
        for _ in 0..lines {
            let mut line = String::new();
            tokio::time::timeout(Duration::from_secs(10), socket.read_line(&mut line))
                .await
                .expect("reply timed out")
                .unwrap();
            reply.push_str(&line);
        }
        reply
    };
    replies.push(read(&mut socket, 1).await);
    for (send, lines) in steps {
        socket.get_mut().write_all(send).await.unwrap();
        replies.push(read(&mut socket, *lines).await);
    }
    replies
}
fn envelope(mail_from: &str, rcpt: &str, body: &[u8]) -> Vec<(Vec<u8>, usize)> {
    let mut data = body.to_vec();
    data.extend_from_slice(b".\r\n");
    vec![
        (b"EHLO peer.test\r\n".to_vec(), 5),
        (format!("MAIL FROM:<{mail_from}>\r\n").into_bytes(), 1),
        (format!("RCPT TO:<{rcpt}>\r\n").into_bytes(), 1),
        (b"DATA\r\n".to_vec(), 1),
        (data, 1),
        (b"QUIT\r\n".to_vec(), 1),
    ]
}
async fn fresh(db: &Db) -> tokio_postgres::Client {
    let owner = db.connect().await.unwrap();
    for sql in [
        include_str!("../oracle/auth-cleanup.sql"),
        include_str!("../oracle/cleanup.sql"),
        include_str!("../oracle/seed.sql"),
    ] {
        owner.batch_execute(sql).await.unwrap();
    }
    owner
}
async fn finish(owner: &tokio_postgres::Client) {
    for sql in [
        include_str!("../oracle/auth-cleanup.sql"),
        include_str!("../oracle/cleanup.sql"),
    ] {
        owner.batch_execute(sql).await.unwrap();
    }
}
fn message(from: &str, subject: &str) -> Vec<u8> {
    format!("From: {from}\r\nTo: alice@smtp1.test\r\nSubject: {subject}\r\nMessage-Id: <{subject}@sf2.test>\r\n\r\nbody\r\n").into_bytes()
}

#[tokio::test]
async fn dmarc_uses_the_public_suffix_list_relaxed_default_subdomain_policy_and_one_record() {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("secfix2-dmarc") else {
        return;
    };
    let owner = fresh(&db).await;
    let spf_ok = "v=spf1 ip4:127.0.0.1 -all";
    let cases: Vec<(&str, Value, &str, &str, &str)> = vec![
        (
            "organizational domain follows the public suffix list",
            json!({"txt:_dmarc.victim.co.uk":["v=DMARC1; p=reject"],"txt:attacker.co.uk":[spf_ok]}),
            "x@attacker.co.uk",
            "x@victim.co.uk",
            "550",
        ),
        (
            "omitted aspf is relaxed",
            json!({"txt:_dmarc.example.test":["v=DMARC1; p=reject"],"txt:mail.example.test":[spf_ok]}),
            "b@mail.example.test",
            "x@example.test",
            "250",
        ),
        (
            "sp= governs a subdomain",
            json!({"txt:_dmarc.example.test":["v=DMARC1; p=none; sp=reject"]}),
            "x@elsewhere.test",
            "x@sub.example.test",
            "550",
        ),
        (
            "several DMARC records are not concatenated",
            json!({"txt:_dmarc.example.test":["v=DMARC1; p=none;","v=DMARC1; p=reject"]}),
            "x@elsewhere.test",
            "x@example.test",
            "250",
        ),
    ];
    for (name, dns, mail_from, from, want) in cases {
        let live = start(
            &db.dsn,
            dns,
            Features {
                spf: true,
                dmarc: true,
                ..Default::default()
            },
        )
        .await;
        let replies = talk(
            live.addr,
            &envelope(mail_from, "alice@smtp1.test", &message(from, "dmarc")),
        )
        .await;
        live.finish().await;
        assert!(
            replies[5].starts_with(want),
            "{name}: DATA reply {:?}",
            replies[5]
        );
        owner
            .batch_execute(include_str!("../oracle/cleanup.sql"))
            .await
            .unwrap();
        owner
            .batch_execute(include_str!("../oracle/seed.sql"))
            .await
            .unwrap();
    }
    finish(&owner).await;
}

fn arc_headers(raw: &str) -> Vec<String> {
    raw.lines()
        .filter(|l| l.starts_with("ARC-Seal:"))
        .map(str::to_owned)
        .collect()
}
const FORGED: &str = "ARC-Seal: i=1; a=rsa-sha256; d=forged.test; s=s; cv=none; b=AAAA\r\nARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=forged.test; s=s; h=from; bh=AAAA; b=AAAA\r\nARC-Authentication-Results: i=1; forged.test; spf=pass\r\n";

#[tokio::test]
async fn arc_seal_authenticates_the_incoming_chain_and_uses_the_receiving_domain() {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("secfix2-arc") else {
        return;
    };
    let owner = fresh(&db).await;
    // Only the receiving domain (smtp1.test, the recipient's) may seal.
    let reset = async |owner: &tokio_postgres::Client| {
        for sql in [
            include_str!("../oracle/cleanup.sql"),
            include_str!("../oracle/seed.sql"),
        ] {
            owner.batch_execute(sql).await.unwrap();
        }
        seed_signer(owner, &[("smtp1.test", "sf2arc", "rsa-sha256")]).await;
    };
    reset(&owner).await;
    let dns = json!({"txt:sf2arc._domainkey.smtp1.test":[rsa_record()]});
    let features = Features {
        spf: true,
        dkim: true,
        dmarc: true,
        arc: true,
    };
    // The author is a remote, attacker-chosen domain with no key here.
    let from = "sender@remote.test";
    let stored = |live: &Live| -> String {
        let blobs = live.blobs.0.lock().unwrap();
        let encoded = blobs.values().next().expect("one stored message").clone();
        String::from_utf8(
            base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .unwrap(),
        )
        .unwrap()
    };
    // A forged chain (no verifiable signature) is sealed cv=fail, never cv=pass.
    let live = start(&db.dsn, dns.clone(), features).await;
    let mut forged = FORGED.as_bytes().to_vec();
    forged.extend(message(from, "forged"));
    let replies = talk(live.addr, &envelope(from, "alice@smtp1.test", &forged)).await;
    assert!(replies[5].starts_with("250"), "{replies:?}");
    let sealed = stored(&live);
    live.finish().await;
    let seals = arc_headers(&sealed);
    assert_eq!(seals.len(), 2, "forged set plus ours:\n{sealed}");
    assert!(
        seals[0].contains("i=2") && seals[0].contains("cv=fail"),
        "{seals:?}"
    );
    assert!(
        seals[0].contains("d=smtp1.test"),
        "sealed by the receiving domain: {seals:?}"
    );
    reset(&owner).await;
    // No incoming chain: our set is i=1 cv=none.
    let live = start(&db.dsn, dns.clone(), features).await;
    let replies = talk(
        live.addr,
        &envelope(from, "alice@smtp1.test", &message(from, "first")),
    )
    .await;
    assert!(replies[5].starts_with("250"), "{replies:?}");
    let first = stored(&live);
    live.finish().await;
    let seals = arc_headers(&first);
    assert_eq!(seals.len(), 1, "{first}");
    assert!(
        seals[0].contains("i=1") && seals[0].contains("cv=none"),
        "{seals:?}"
    );
    reset(&owner).await;
    // A genuinely sealed message verifies at the next hop: i=2 cv=pass.
    let live = start(&db.dsn, dns.clone(), features).await;
    let replies = talk(
        live.addr,
        &envelope(from, "alice@smtp1.test", first.as_bytes()),
    )
    .await;
    assert!(replies[5].starts_with("250"), "{replies:?}");
    let second = stored(&live);
    live.finish().await;
    let seals = arc_headers(&second);
    assert_eq!(seals.len(), 2, "{second}");
    assert!(
        seals[0].contains("i=2") && seals[0].contains("cv=pass"),
        "{seals:?}"
    );
    // A key that exists only for the (attacker-chosen) From domain is never used:
    // the receiving domain has none, so nothing is sealed.
    reset(&owner).await;
    owner
        .batch_execute("DELETE FROM domain_signing_keys WHERE selector='sf2arc'")
        .await
        .unwrap();
    seed_signer(&owner, &[("arcsign.test", "sf2arc", "rsa-sha256")]).await;
    let live = start(
        &db.dsn,
        json!({"txt:sf2arc._domainkey.arcsign.test":[rsa_record()]}),
        features,
    )
    .await;
    let spoofed = "x@arcsign.test";
    let replies = talk(
        live.addr,
        &envelope(spoofed, "alice@smtp1.test", &message(spoofed, "foreign")),
    )
    .await;
    assert!(replies[5].starts_with("250"), "{replies:?}");
    let unsealed = stored(&live);
    live.finish().await;
    assert!(
        arc_headers(&unsealed).is_empty(),
        "no receiving-domain key: unsealed\n{unsealed}"
    );
    drop_signer(&owner).await;
    finish(&owner).await;
}

// ---- #488 ----

#[tokio::test]
async fn a_stalled_implicit_tls_refusal_cannot_stall_the_accept_loop() {
    use tokio_rustls::rustls::{
        pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer, ServerName},
        ClientConfig, RootCertStore, ServerConfig,
    };
    let cert = CertificateDer::pem_slice_iter(include_bytes!(
        "../../../../tests/conformance/directory-sync/ldap-fixture/server.pem"
    ))
    .collect::<Result<Vec<_>, _>>()
    .unwrap();
    let key = PrivateKeyDer::from_pem_slice(include_bytes!(
        "../../../../tests/conformance/directory-sync/ldap-fixture/server.p8"
    ))
    .unwrap();
    let tls = Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert, key)
            .unwrap(),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop, rx) = watch::channel(false);
    // Zero slots: every connection is refused (after the implicit-TLS handshake).
    let server = setjoin_smtp::Server::new()
        .with_tls(tls)
        .with_max_connections(0);
    let task = tokio::spawn(Arc::new(server).serve(listener, rx));
    // A client that connects and never starts the handshake.
    let _stalled = TcpStream::connect(addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    let mut roots = RootCertStore::empty();
    roots
        .add(
            CertificateDer::from_pem_slice(include_bytes!(
                "../../../../tests/conformance/directory-sync/ldap-fixture/ca.pem"
            ))
            .unwrap(),
        )
        .unwrap();
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let attempt = async {
        let socket = TcpStream::connect(addr).await.unwrap();
        let tls = tokio_rustls::TlsConnector::from(Arc::new(config))
            .connect(ServerName::try_from("localhost").unwrap(), socket)
            .await
            .unwrap();
        let mut line = String::new();
        BufReader::new(tls).read_line(&mut line).await.unwrap();
        line
    };
    let line = tokio::time::timeout(Duration::from_secs(3), attempt)
        .await
        .expect("a stalled refusal froze the accept loop");
    assert!(line.starts_with("421"), "{line}");
    let _ = stop.send(true);
    let _ = task.await;
}

async fn delivered(owner: &tokio_postgres::Client) -> i64 {
    owner
        .query_one(
            "SELECT count(*) FROM messages WHERE mailbox_id BETWEEN 9348021 AND 9348023",
            &[],
        )
        .await
        .unwrap()
        .get(0)
}

#[tokio::test]
async fn mail_is_never_acknowledged_without_a_delivered_recipient() {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("secfix2-ack") else {
        return;
    };
    let owner = fresh(&db).await;
    let live = start(&db.dsn, json!({}), Features::default()).await;
    // Every RCPT refused: DATA must not be offered (frozen Go answered 250).
    let replies = talk(
        live.addr,
        &[
            (b"EHLO peer.test\r\n".to_vec(), 5),
            (b"MAIL FROM:<s@remote.test>\r\n".to_vec(), 1),
            (b"RCPT TO:<nobody@smtp1.test>\r\n".to_vec(), 1),
            (b"DATA\r\n".to_vec(), 1),
            (b"QUIT\r\n".to_vec(), 1),
        ],
    )
    .await;
    assert!(replies[3].starts_with("550"), "{replies:?}");
    assert!(
        replies[4].starts_with("554"),
        "DATA without recipients: {replies:?}"
    );
    // The terminator never arrives (client half-closes): no delivery, no 250.
    let mut socket = BufReader::new(TcpStream::connect(live.addr).await.unwrap());
    let mut line = String::new();
    socket.read_line(&mut line).await.unwrap();
    for (send, lines) in [
        ("EHLO peer.test\r\n", 5),
        ("MAIL FROM:<s@remote.test>\r\n", 1),
        ("RCPT TO:<alice@smtp1.test>\r\n", 1),
        ("DATA\r\n", 1),
    ] {
        socket.get_mut().write_all(send.as_bytes()).await.unwrap();
        for _ in 0..lines {
            line.clear();
            socket.read_line(&mut line).await.unwrap();
        }
    }
    socket
        .get_mut()
        .write_all(b"From: s@remote.test\r\nSubject: cut\r\n\r\ntruncated bo")
        .await
        .unwrap();
    socket.get_mut().shutdown().await.unwrap();
    line.clear();
    tokio::time::timeout(Duration::from_secs(5), socket.read_line(&mut line))
        .await
        .unwrap()
        .unwrap();
    assert!(
        line.starts_with("451"),
        "a truncated DATA must be tempfailed, got {line:?}"
    );
    assert_eq!(delivered(&owner).await, 0, "nothing may be delivered");
    live.finish().await;
    finish(&owner).await;
}

#[tokio::test]
async fn a_recipient_lookup_outage_is_a_temporary_failure() {
    // The worker database cannot be reached: neither "exists" nor "no such user".
    let live = start(
        "postgres://nobody:none@127.0.0.1:1/none",
        json!({}),
        Features::default(),
    )
    .await;
    let replies = talk(
        live.addr,
        &[
            (b"EHLO peer.test\r\n".to_vec(), 5),
            (b"MAIL FROM:<s@remote.test>\r\n".to_vec(), 1),
            (b"RCPT TO:<alice@smtp1.test>\r\n".to_vec(), 1),
            (b"QUIT\r\n".to_vec(), 1),
        ],
    )
    .await;
    live.finish().await;
    assert!(
        replies[3].starts_with("451"),
        "an outage must be retried, not bounced: {replies:?}"
    );
}

/// The cases share one database and fixed fixtures: libtest's threads must take turns.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
