//! OpenLDAP clients from the existing test-ldap image exercise the Rust socket.
use setjoin_conformance::harness::Db;
use setjoin_ldap::Server;
use std::{process::Command, sync::Arc};
use tokio::{net::TcpListener, sync::watch};
use tokio_rustls::rustls::{
    pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer},
    ServerConfig,
};

/// Pinned in `.github/ci/images.lock` and preloaded by the lane (`scripts/build-interop-images.sh`
/// on a dev host); the test never builds, tags or removes images (#141).
const IMAGE: &str = "setjoin-interop-ldap:local";

#[tokio::test]
async fn test_ldap_container_clients() {
    use futures_util::FutureExt;
    let Some(db) = Db::for_case("ldap-openldap-interop") else {
        return;
    };
    let owner = db.connect().await.unwrap();
    owner
        .batch_execute(include_str!("../oracle/cleanup.sql"))
        .await
        .unwrap();
    owner
        .batch_execute(include_str!("../oracle/seed.sql"))
        .await
        .unwrap();
    owner
        .execute(
            "UPDATE users SET password_hash=$1 WHERE email LIKE '%@ldap1.test'",
            &[&include_str!("../oracle/password-hash.txt")],
        )
        .await
        .unwrap();
    let cert = CertificateDer::pem_slice_iter(include_bytes!(
        "../../../../tests/conformance/directory-sync/ldap-fixture/server.pem"
    ))
    .collect::<Result<Vec<_>, _>>()
    .unwrap();
    let key = PrivateKeyDer::from_pem_slice(include_bytes!(
        "../../../../tests/conformance/directory-sync/ldap-fixture/server.p8"
    ))
    .unwrap();
    let tls = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert, key)
        .unwrap();
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = l.local_addr().unwrap();
    let (stop, rx) = watch::channel(false);
    let server = fixture_server(
        setjoin_pg::ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn), 4).unwrap(),
        "ldap1.test",
    )
    .with_tls(Arc::new(tls));
    let task = tokio::spawn(Arc::new(server).serve(l, rx));
    let outcome = std::panic::AssertUnwindSafe(async {
        let ca = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../tests/conformance/directory-sync/ldap-fixture/ca.pem")
            .canonicalize()
            .unwrap();
        for (case, password, filter, expected_status, needle) in [
            (
                "alias",
                "LDAP1-correct-password!",
                "(mail=bob-alias@ldap1.test)",
                0,
                Some("mail: bob@ldap1.test"),
            ),
            (
                "hidden",
                "LDAP1-correct-password!",
                "(mail=hidden@ldap1.test)",
                0,
                None,
            ),
            ("bad-password", "wrong", "(objectClass=*)", 49, None),
        ] {
            let name = format!("gofree-ldap1-openldap-{}-{case}", std::process::id());
            let mount = format!("{}:/ldap1-ca.pem:ro", ca.display());
            let image_name = IMAGE.to_string();
            let output = tokio::task::spawn_blocking(move || {
                Command::new("docker")
                    .args([
                        "run",
                        "--pull",
                        "never",
                        "--rm",
                        "--name",
                        &name,
                        "--label",
                        "org.setjoin.task=gofree-ldap1",
                        "--network",
                        "host",
                        "-v",
                        &mount,
                        "-e",
                        "LDAPTLS_CACERT=/ldap1-ca.pem",
                        "--entrypoint",
                        "timeout",
                        &image_name,
                        "15",
                        "ldapsearch",
                        "-LLL",
                        "-x",
                        "-H",
                        &format!("ldaps://{address}"),
                        "-D",
                        "alice@ldap1.test",
                        "-w",
                        password,
                        "-b",
                        "ou=People,dc=ldap1,dc=test",
                        filter,
                        "cn",
                        "mail",
                    ])
                    .output()
            })
            .await
            .unwrap()
            .unwrap();
            assert_eq!(
                output.status.code(),
                Some(expected_status),
                "{case}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let out = String::from_utf8(output.stdout).unwrap();
            if let Some(needle) = needle {
                assert!(out.contains(needle), "{case}: {out}")
            } else {
                assert!(
                    !out.contains("dn:"),
                    "{case}: unexpected directory result {out}"
                )
            }
        }
    })
    .catch_unwind()
    .await;
    stop.send(true).unwrap();
    task.await.unwrap().unwrap();
    owner
        .batch_execute(include_str!("../oracle/cleanup.sql"))
        .await
        .unwrap();
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic)
    }
}

// Only the legacy protocol oracle uses an allow-all policy. Production serve
// still requires explicit Enforced wiring, including for anonymous operations.
struct FixtureGate;
impl setjoin_threat::ThreatGate for FixtureGate {
    fn intercept<'a>(
        &'a self,
        _: &'a setjoin_threat::ConnectionMeta,
    ) -> futures_util::future::BoxFuture<'a, (setjoin_threat::ThreatAction, std::time::Duration)>
    {
        Box::pin(async {
            (
                setjoin_threat::ThreatAction::Allow,
                std::time::Duration::ZERO,
            )
        })
    }
    fn record_result<'a>(
        &'a self,
        _: &'a setjoin_threat::ConnectionMeta,
        _: bool,
        _: i64,
    ) -> futures_util::future::BoxFuture<'a, ()> {
        Box::pin(async {})
    }
    fn evaluate_post_auth<'a>(
        &'a self,
        _: &'a mut setjoin_threat::ConnectionMeta,
    ) -> futures_util::future::BoxFuture<'a, (setjoin_threat::ThreatAction, String)> {
        Box::pin(async { (setjoin_threat::ThreatAction::Allow, String::new()) })
    }
}
fn fixture_server(db: setjoin_pg::ScopedExecutor, domain: impl Into<String>) -> Server {
    Server::new(db, domain).with_threat_gate(Arc::new(FixtureGate))
}
