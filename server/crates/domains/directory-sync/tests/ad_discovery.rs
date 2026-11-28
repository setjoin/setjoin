//! AD domain controller discovery (#381): SRV order, trailing dots, the override host,
//! and a failed lookup, against the in-process fake DNS server (random loopback port).
use setjoin_conformance::dns_fake::FakeDns;
use setjoin_directory_sync::ad::{AdClient, NameServerResolver};

async fn dns() -> FakeDns {
    FakeDns::start(
        "127.0.0.1:0".parse().unwrap(),
        vec![(
            "_ldap._tcp.corp.example.test".into(),
            vec![
                (20, 5, 636, "later.example.test.".into()),
                (10, 1, 636, "light.example.test.".into()),
                (10, 9, 636, "heavy.example.test.".into()),
            ],
        )],
    )
    .await
    .expect("fake dns")
}

#[tokio::test]
async fn srv_targets_follow_priority_then_weight_without_the_trailing_dot() {
    let server = dns().await;
    let resolver = NameServerResolver(server.addr);
    let client = AdClient::new("corp.example.test", "CN=svc", "pw", "", &resolver)
        .await
        .expect("discovered");
    assert_eq!(
        client.hosts(),
        [
            "heavy.example.test",
            "light.example.test",
            "later.example.test"
        ]
    );
    assert!(server
        .log()
        .iter()
        .any(|l| l == "dns type=33 name=_ldap._tcp.corp.example.test"));
}

#[tokio::test]
async fn an_override_host_skips_discovery() {
    let server = dns().await;
    let resolver = NameServerResolver(server.addr);
    let client = AdClient::new(
        "corp.example.test",
        "CN=svc",
        "pw",
        "dc1.example.test",
        &resolver,
    )
    .await
    .expect("override");
    assert_eq!(client.hosts(), ["dc1.example.test"]);
    assert!(server.log().is_empty(), "no DNS query for an override host");
}

#[tokio::test]
async fn an_unknown_domain_is_a_discovery_error() {
    let server = dns().await;
    let resolver = NameServerResolver(server.addr);
    let error = AdClient::new("missing.example.test", "CN=svc", "pw", "", &resolver)
        .await
        .expect_err("NXDOMAIN");
    assert!(
        error.starts_with("AD discovery failed for missing.example.test: SRV lookup for _ldap._tcp.missing.example.test"),
        "{error}"
    );
}
