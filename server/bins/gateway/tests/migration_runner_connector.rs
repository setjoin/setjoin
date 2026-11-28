//! The IMAP connector of the migration runner (#431) against a scripted source:
//! folder discovery and tags, UID pages of 100, resume by UIDVALIDITY, login
//! errors and the SSRF policy at dial time.
#[path = "common/fake_imap.rs"]
mod fake_imap;
use fake_imap::{folder, message, FakeImap};
use setjoin_gateway::migration_runner::{Batch, Checkpoint, Dialer, ImapConfig, ImapConnector};
use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};

/// `imap.test` resolves to a private address; connections go to the loopback fake.
fn dialer(target: SocketAddr, answer: &'static str) -> Dialer {
    Dialer::custom(
        move |_| Box::pin(async move { Ok(vec![answer.parse::<IpAddr>().unwrap()]) }),
        move |_| {
            Box::pin(async move {
                let s = tokio::net::TcpStream::connect(target)
                    .await
                    .map_err(|e| e.to_string())?;
                Ok(Box::new(s) as Box<dyn setjoin_gateway::migration_runner::imap::Io>)
            })
        },
    )
}

fn config(port: u16, password: &str) -> ImapConfig {
    ImapConfig {
        host: "imap.test".into(),
        port: port as i64,
        tls_mode: "none".into(),
        private_hosts: vec!["imap.test".into()],
        private_cidrs: vec!["10.0.0.0/8".into()],
        username: "alice".into(),
        password: password.into(),
    }
}

async fn all(c: &mut ImapConnector) -> Result<Vec<Batch>, String> {
    let mut out = vec![];
    while let Some(b) = c.next_batch().await? {
        out.push(b);
    }
    Ok(out)
}

#[tokio::test]
async fn pages_folders_and_tags() {
    let many: Vec<_> = (1..=205).map(|u| message(u, "bulk", "x")).collect();
    let server = FakeImap::start(
        "127.0.0.1:0",
        "alice",
        "pw",
        vec![
            folder(
                "INBOX",
                &[],
                77,
                vec![message(1, "hi", "hello"), message(2, "yo", "again")],
            ),
            folder("Sent", &["\\Sent"], 5, vec![message(4, "out", "o")]),
            folder("Work/Projects", &[], 9, many),
            folder("Empty", &[], 3, vec![]),
        ],
    )
    .await
    .unwrap();
    let port = server.address.port();
    let mut c = ImapConnector::new(config(port, "pw"), dialer(server.address, "10.1.2.3"));
    let batches = all(&mut c).await.unwrap();
    let shape: Vec<(String, usize, u32)> = batches
        .iter()
        .map(|b| match &b.checkpoint {
            Checkpoint::Imap { folder, uid, .. } => (folder.clone(), b.items.len(), *uid),
            _ => panic!("imap checkpoints only"),
        })
        .collect();
    assert_eq!(
        shape,
        [
            ("INBOX".into(), 2, 2),
            ("Sent".into(), 1, 4),
            ("Work/Projects".into(), 100, 100),
            ("Work/Projects".into(), 100, 200),
            ("Work/Projects".into(), 5, 205),
        ]
    );
    let first = &batches[0].items[0];
    assert_eq!(first.object_id, "imap:INBOX:77:1");
    assert_eq!(first.tags, ["Inbox"]);
    assert_eq!(first.version.len(), 64);
    assert_eq!(batches[1].items[0].tags, ["Sent"]);
    assert_eq!(batches[2].items[0].tags, ["Projects"]);
    assert_eq!(batches[2].items[0].folder_path, ["Work", "Projects"]);
}

#[tokio::test]
async fn resumes_only_within_the_same_uid_validity() {
    let server = FakeImap::start(
        "127.0.0.1:0",
        "alice",
        "pw",
        vec![folder(
            "INBOX",
            &[],
            77,
            (1..=5).map(|u| message(u, "m", "b")).collect(),
        )],
    )
    .await
    .unwrap();
    let port = server.address.port();
    let resume = |validity: u64| {
        let mut c = ImapConnector::new(config(port, "pw"), dialer(server.address, "10.1.2.3"));
        c.restore(
            &BTreeMap::new(),
            &[(
                "INBOX".into(),
                "imap_uid".into(),
                serde_json::json!({"uid": 3, "uidValidity": validity}),
            )],
        )
        .unwrap();
        c
    };
    let same = all(&mut resume(77)).await.unwrap();
    assert_eq!(
        same[0].items.iter().map(|i| i.uid).collect::<Vec<_>>(),
        [4, 5]
    );
    let changed = all(&mut resume(78)).await.unwrap();
    assert_eq!(
        changed[0].items.len(),
        5,
        "a new UIDVALIDITY restarts the folder"
    );
    // Legacy resume (no validity) also restarts: Go requires the stored generation.
    let mut legacy = ImapConnector::new(config(port, "pw"), dialer(server.address, "10.1.2.3"));
    legacy
        .restore(&BTreeMap::from([("INBOX".to_owned(), 3)]), &[])
        .unwrap();
    assert_eq!(all(&mut legacy).await.unwrap()[0].items.len(), 5);
}

#[tokio::test]
async fn login_failure_carries_the_server_text() {
    let server = FakeImap::start("127.0.0.1:0", "alice", "pw", vec![])
        .await
        .unwrap();
    let mut c = ImapConnector::new(
        config(server.address.port(), "wrong"),
        dialer(server.address, "10.1.2.3"),
    );
    assert_eq!(
        c.next_batch().await.err().unwrap(),
        "imap login: Authentication failed."
    );
    assert_eq!(
        ImapConnector::new(
            config(server.address.port(), "wrong"),
            dialer(server.address, "10.1.2.3")
        )
        .test_connection()
        .await
        .unwrap_err(),
        "imap login: Authentication failed."
    );
}

#[tokio::test]
async fn dial_policy_refuses_unlisted_and_permanently_blocked_addresses() {
    let server = FakeImap::start("127.0.0.1:0", "alice", "pw", vec![])
        .await
        .unwrap();
    let port = server.address.port();
    let unsafe_text =
        "IMAP destination is not allowed: URL is not allowed (must be http/https to a public host)";
    // A private answer for a host the policy does not name.
    let mut cfg = config(port, "pw");
    cfg.private_hosts = vec![];
    cfg.private_cidrs = vec![];
    for answer in ["10.1.2.3", "127.0.0.1", "169.254.169.254", "100.64.0.1"] {
        let err = ImapConnector::new(cfg.clone(), dialer(server.address, answer))
            .test_connection()
            .await
            .unwrap_err();
        assert_eq!(err, unsafe_text, "{answer}");
    }
    // Loopback stays refused even when named and listed.
    let mut listed = config(port, "pw");
    listed.private_cidrs = vec!["10.0.0.0/8".into()];
    let err = ImapConnector::new(listed, dialer(server.address, "127.0.0.1"))
        .test_connection()
        .await
        .unwrap_err();
    assert_eq!(err, unsafe_text);
    // An answer outside the listed CIDR is refused too.
    let err = ImapConnector::new(config(port, "pw"), dialer(server.address, "192.168.1.1"))
        .test_connection()
        .await
        .unwrap_err();
    assert_eq!(err, unsafe_text);
    // A public answer needs no policy.
    let mut open = config(port, "pw");
    open.private_hosts = vec![];
    open.private_cidrs = vec![];
    ImapConnector::new(open, dialer(server.address, "93.184.216.34"))
        .test_connection()
        .await
        .unwrap();
}

#[tokio::test]
async fn mixed_public_and_private_dns_answers_are_refused_before_dial() {
    let server=FakeImap::start("127.0.0.1:0","alice","pw",vec![]).await.unwrap();
    let local=server.address;
    let attempts=std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let observed=attempts.clone();
    let dialer=Dialer::custom(
        |_|Box::pin(async {Ok(vec!["93.184.216.34".parse().unwrap(),"127.0.0.1".parse().unwrap()])}),
        move |_| {
            observed.fetch_add(1,std::sync::atomic::Ordering::SeqCst);
            Box::pin(async move {
                let stream=tokio::net::TcpStream::connect(local).await.map_err(|error|error.to_string())?;
                Ok(Box::new(stream) as Box<dyn setjoin_gateway::migration_runner::imap::Io>)
            })
        },
    );
    let connector=ImapConnector::new(ImapConfig {
        host:"mixed-source.test".into(),port:local.port() as i64,tls_mode:"none".into(),
        username:"alice".into(),password:"pw".into(),..Default::default()
    },dialer);
    assert_eq!(connector.test_connection().await.unwrap_err(),"IMAP destination is not allowed: URL is not allowed (must be http/https to a public host)");
    assert_eq!(attempts.load(std::sync::atomic::Ordering::SeqCst),0);
}
