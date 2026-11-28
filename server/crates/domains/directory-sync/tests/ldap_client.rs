//! The wire client against the in-process fake directory: both transports,
//! paging, manager anchors, bind classes and discovery.
use setjoin_conformance::ldap_fake::{Entry, FakeLdap, Transport, CA_PEM};
use setjoin_directory_sync::ldap::{ClientError, LdapClient};

/// Written once per process: parallel cases re-truncating one shared file let a
/// concurrent handshake read it empty (`UnknownIssuer`).
fn trust() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let path = std::env::temp_dir().join(format!(
            "setjoin-ldap-fixture-ca-{}.pem",
            std::process::id()
        ));
        std::fs::write(&path, CA_PEM).unwrap();
        std::env::set_var("SSL_CERT_FILE", path);
    });
}

fn people(n: usize) -> Vec<Entry> {
    (0..n)
        .map(|i| {
            Entry::new(
                &format!("uid=u{i:03},ou=people,dc=example,dc=test"),
                &[
                    ("objectClass", "person"),
                    ("mail", &format!("u{i:03}@example.test")),
                    ("entryUUID", &format!("uuid-{i:03}")),
                    ("manager", "uid=u000,ou=people,dc=example,dc=test"),
                    ("modifyTimestamp", &format!("202601010000{:02}Z", i % 60)),
                ],
            )
        })
        .collect()
}

async fn run(transport: Transport) {
    trust();
    let server = FakeLdap::start(transport).await.unwrap();
    server.set_credentials("cn=svc,dc=example,dc=test", "pw");
    server.set_entries(people(7));
    let mut client = LdapClient::new(
        "127.0.0.1",
        server.addr.port() as i64,
        transport == Transport::Ldaps,
        "cn=svc,dc=example,dc=test",
        "pw",
        "dc=example,dc=test",
    );
    client.set_subject_attribute("entryUUID").unwrap();
    let mut ldap = client.connect().await.unwrap();
    client.bind(&mut ldap).await.unwrap();
    let users = client.search_users(&mut ldap, "", 3).await.unwrap();
    assert_eq!(users.len(), 7);
    assert_eq!(users[1].immutable_subject, "uuid-001");
    assert_eq!(users[1].manager_subject, "uuid-000");
    let log = server.log();
    // Three pages of size 3 for seven entries.
    assert_eq!(
        log.iter()
            .filter(|l| l.contains("filter=(objectClass=person)"))
            .count(),
        3,
        "{log:?}"
    );
}

#[tokio::test]
async fn ldaps_paged_search_with_manager_subjects() {
    run(Transport::Ldaps).await;
}

#[tokio::test]
async fn starttls_paged_search_with_manager_subjects() {
    run(Transport::StartTls).await;
}

#[tokio::test]
async fn wrong_password_is_invalid_credentials_and_empty_password_never_dials_bind() {
    trust();
    let server = FakeLdap::start(Transport::Ldaps).await.unwrap();
    server.set_credentials("cn=svc,dc=example,dc=test", "pw");
    let wrong = LdapClient::new(
        "127.0.0.1",
        server.addr.port() as i64,
        true,
        "cn=svc,dc=example,dc=test",
        "no",
        "dc=x",
    );
    let mut ldap = wrong.connect().await.unwrap();
    assert!(matches!(
        wrong.bind(&mut ldap).await,
        Err(ClientError::Bind {
            invalid_credentials: true,
            ..
        })
    ));
    let empty = LdapClient::new(
        "127.0.0.1",
        server.addr.port() as i64,
        true,
        "cn=svc,dc=example,dc=test",
        "",
        "dc=x",
    );
    assert!(matches!(
        empty.bind(&mut ldap).await,
        Err(ClientError::Bind {
            invalid_credentials: false,
            ..
        })
    ));
    assert_eq!(server.log().len(), 1);
}

#[tokio::test]
async fn untrusted_host_name_fails_closed() {
    trust();
    let server = FakeLdap::start(Transport::Ldaps).await.unwrap();
    // The fixture certificate names 127.0.0.1 and localhost only.
    let client = LdapClient::new(
        "127.0.0.2",
        server.addr.port() as i64,
        true,
        "x",
        "y",
        "dc=x",
    );
    assert!(client.connect().await.is_err());
}

#[tokio::test]
async fn discovery_reports_uniqueness() {
    trust();
    let server = FakeLdap::start(Transport::Ldaps).await.unwrap();
    server.set_credentials("cn=svc", "pw");
    let mut entries = people(3);
    entries[2].attrs.retain(|(n, _)| n != "entryUUID");
    entries[2]
        .attrs
        .push(("entryUUID".into(), vec!["uuid-000".into()]));
    server.set_entries(entries);
    let client = LdapClient::new(
        "127.0.0.1",
        server.addr.port() as i64,
        true,
        "cn=svc",
        "pw",
        "dc=example,dc=test",
    );
    let mut ldap = client.connect().await.unwrap();
    client.bind(&mut ldap).await.unwrap();
    let facts = client
        .discover_immutable_attributes(&mut ldap, "", &["entryUUID".into(), "mail".into()])
        .await
        .unwrap();
    assert_eq!(
        (facts[0].unique, facts[0].duplicates, facts[0].ready),
        (2, 2, false)
    );
    assert!(facts[1].ready);
}
