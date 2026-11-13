//! Containerised independent SMTP client against the real listener/database.
#[path = "support/auth_dns.rs"]
mod auth_dns;
use std::{
    process::{Command, Stdio},
    sync::Arc,
};
use tokio::{net::TcpListener, sync::watch};
use tokio_rustls::rustls::{
    pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer},
    ServerConfig,
};
struct Image(String);
impl Drop for Image {
    fn drop(&mut self) {
        if Command::new("docker")
            .args(["image", "inspect", &self.0])
            .output()
            .unwrap()
            .status
            .success()
        {
            let out = Command::new("docker")
                .args(["image", "rm", &self.0])
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "remove owned image {}: {}",
                self.0,
                String::from_utf8_lossy(&out.stderr)
            );
        }
    }
}
fn build(args: &[&str]) {
    let out = Command::new("docker")
        .args(args)
        .output()
        .expect("Docker required for interop");
    assert!(
        out.status.success(),
        "docker build: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_smtp_container_clients() {
    let Some(db) = setjoin_conformance::harness::Db::for_case("smtp1-container") else {
        return;
    };
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let pid = std::process::id();
    let base = Image(format!("gofree-smtp6-interop-base-{pid}"));
    let image = Image(format!("gofree-smtp6-interop-client-{pid}"));
    eprintln!(
        "owned images: {}, {}; --rm client gofree-smtp6-interop-{pid}",
        base.0, image.0
    );
    build(&[
        "build",
        "--label",
        "org.setjoin.task=gofree-smtp6",
        "-q",
        "-t",
        &base.0,
        root.join("../../../../mailserver/deploy/docker/test-smtp")
            .to_str()
            .unwrap(),
    ]);
    let mut child = Command::new("docker")
        .args([
            "build",
            "--label",
            "org.setjoin.task=gofree-smtp6",
            "-q",
            "-t",
            &image.0,
            "-",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    use std::io::Write;
    writeln!(
        child.stdin.take().unwrap(),
        "FROM {}\nRUN apk add --no-cache python3",
        base.0
    )
    .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "Python layer: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let owner = db.connect().await.unwrap();
    owner
        .batch_execute(include_str!("../oracle/cleanup.sql"))
        .await
        .unwrap();
    owner
        .batch_execute(include_str!("../oracle/seed.sql"))
        .await
        .unwrap();
    let (stop, rx) = watch::channel(false);
    let mut tasks = Vec::new();
    let mut ports = Vec::new();
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
    let vectors: serde_json::Value =
        serde_json::from_str(include_str!("../oracle/dkim-vectors-go.json")).unwrap();
    let mut dns = vectors
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["name"] == "rsa-pass")
        .unwrap()["dns"]
        .clone();
    dns["txt:remote.test"] = serde_json::json!(["v=spf1 +all"]);
    dns["txt:_dmarc.remote.test"] = serde_json::json!(["v=DMARC1; p=reject"]);
    dns["txt:dkim.smtp2.test"] = serde_json::json!(["v=spf1 -all"]);
    dns["txt:_dmarc.dkim.smtp2.test"] = serde_json::json!(["v=DMARC1; p=reject"]);
    for implicit in [false, true] {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        ports.push(l.local_addr().unwrap().port());
        let server = setjoin_smtp::Server::new()
            .with_database(setjoin_pg::workers::WorkerDatabase::new(&db.dsn).unwrap())
            .with_mail_auth(setjoin_smtp::mail_auth::MailAuth::new(
                setjoin_smtp::mail_auth::Features {
                    spf: true,
                    dkim: true,
                    dmarc: true,
                    arc: true,
                },
                Arc::new(auth_dns::FixtureDns(dns.clone())),
            ));
        let server = if implicit {
            server.with_tls(tls.clone())
        } else {
            server
        };
        tasks.push(tokio::spawn(Arc::new(server).serve(l, rx.clone())));
    }
    let image_name = image.0.clone();
    let script = format!(
        "{}:/smtp2-client.py:ro",
        root.join("tests/interop_client.py").display()
    );
    let ca = format!(
        "{}:/smtp2-ca.pem:ro",
        root.join("../../../tests/conformance/directory-sync/ldap-fixture/ca.pem")
            .canonicalize()
            .unwrap()
            .display()
    );
    // A message signed now with the active-schema signing path (security fix
    // 2026-11-05, #492/#493): Go's recorded signature is nonstandard and expired.
    let signed_path = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("smtp2-dkim.json");
    {
        use base64::Engine;
        let plain = b"From: Alice <sender@dkim.smtp2.test>\r\nTo: alice@smtp1.test\r\nSubject: DKIM fixture\r\nDate: Thu, 10 Sep 2026 10:00:00 +0000\r\nMessage-Id: <smtp2-interop-dkim@remote.test>\r\n\r\nbody line\r\nsecond line\r\n";
        let key = setjoin_smtp::mail_auth::Loaded::new(
            "dkim.smtp2.test",
            "sel",
            "rsa-sha256",
            include_str!("../oracle/auth-fixture/rsa.pem"),
        )
        .unwrap();
        let mut raw = key.dkim_header(plain).unwrap().into_bytes();
        raw.extend_from_slice(plain);
        std::fs::write(
            &signed_path,
            serde_json::json!([{"name":"rsa-pass","raw_base64":base64::engine::general_purpose::STANDARD.encode(raw)}]).to_string(),
        )
        .unwrap();
    }
    let signed_fixture = format!("{}:/smtp2-dkim.json:ro", signed_path.display());
    let out = tokio::task::spawn_blocking(move || {
        Command::new("docker")
            .args([
                "run",
                "--rm",
                "--name",
                &format!("gofree-smtp6-interop-{pid}"),
                "--label",
                "org.setjoin.task=gofree-smtp6",
                "--network",
                "host",
                "-v",
                &script,
                "-v",
                &ca,
                "-v",
                &signed_fixture,
                "--entrypoint",
                "timeout",
                &image_name,
                "30",
                "python3",
                "/smtp2-client.py",
                &ports[0].to_string(),
                &ports[1].to_string(),
            ])
            .output()
    })
    .await
    .unwrap()
    .unwrap();
    stop.send(true).unwrap();
    for task in tasks {
        task.await.unwrap().unwrap();
    }
    let rows=owner.query("SELECT message_id,body_text,spf_result,dkim_result,dmarc_result FROM messages WHERE mailbox_id=9348021 ORDER BY message_id",&[]).await.unwrap();
    owner
        .batch_execute(include_str!("../oracle/cleanup.sql"))
        .await
        .unwrap();
    assert!(
        out.status.success(),
        "SMTP container: {}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        rows.len(),
        4,
        "three client deliveries and a real Postfix MTA delivery"
    );
    for row in rows {
        let signed = row.get::<_, String>(0) == "<smtp2-interop-dkim@remote.test>";
        assert_eq!(
            row.get::<_, String>(1),
            if signed {
                "body line\nsecond line"
            } else {
                ".dot-stuffed line\nhello"
            }
        );
        assert_eq!(
            row.get::<_, String>(2),
            if signed { "fail" } else { "pass" }
        );
        assert_eq!(
            row.get::<_, String>(3),
            if signed { "pass" } else { "none" }
        );
        assert_eq!(row.get::<_, String>(4), "pass");
    }
}
