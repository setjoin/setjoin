//! Native HTTPS policy client: real TLS peer, status, compression and body bounds.
use crate::common::boot::Child;
use crate::common::boot::CommandBootExt;
mod common;
use setjoin_gateway::smtp_outbound::HttpPolicyFetch;
use setjoin_smtp::outbound::PolicyFetch;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

#[tokio::test]
async fn policy_https_client_preserves_status_and_limits_decoded_body() {
    use tokio_rustls::rustls::{
        pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer},
        ServerConfig,
    };
    let cert = CertificateDer::pem_slice_iter(include_bytes!(
        "../../../tests/conformance/directory-sync/ldap-fixture/server.pem"
    ))
    .collect::<Result<Vec<_>, _>>()
    .unwrap();
    let key = PrivateKeyDer::from_pem_slice(include_bytes!(
        "../../../tests/conformance/directory-sync/ldap-fixture/server.p8"
    ))
    .unwrap();
    let tls = Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert, key)
            .unwrap(),
    );
    let plain = b"version: STSv1\nmode: enforce\nmx: localhost\n".to_vec();
    let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    std::io::Write::write_all(&mut gzip, &vec![b'x'; 131072]).unwrap();
    let compressed = gzip.finish().unwrap();
    for (status, encoding, body, expected) in [
        (200, "", plain.clone(), Some(plain)),
        (200, "", vec![b'y'; 131072], Some(vec![b'y'; 65536])),
        (200, "gzip", compressed, Some(vec![b'x'; 65536])),
        (200, "gzip", b"invalid gzip".to_vec(), None),
        (404, "", b"missing".to_vec(), None),
        (302, "", b"redirect".to_vec(), None),
    ] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let tls = tls.clone();
        let peer = tokio::spawn(async move {
            let stream = tokio_rustls::TlsAcceptor::from(tls)
                .accept(listener.accept().await.unwrap().0)
                .await
                .unwrap();
            let mut stream = BufReader::new(stream);
            let mut line = String::new();
            stream.read_line(&mut line).await.unwrap();
            assert_eq!(line, "GET /policy HTTP/1.1\r\n");
            let mut headers = String::new();
            loop {
                line.clear();
                stream.read_line(&mut line).await.unwrap();
                if line == "\r\n" {
                    break;
                }
                headers.push_str(&line);
            }
            assert!(headers
                .to_ascii_lowercase()
                .contains("accept-encoding: gzip"));
            let mut response = format!(
                "HTTP/1.1 {status} Fixture\r\nContent-Length: {}\r\nConnection: close\r\n",
                body.len()
            );
            if !encoding.is_empty() {
                response += &format!("Content-Encoding: {encoding}\r\n");
            }
            if status == 302 {
                response += "Location: https://127.0.0.1:1/must-not-follow\r\n";
            }
            response += "\r\n";
            stream.write_all(response.as_bytes()).await.unwrap();
            let _ = stream.write_all(&body).await;
        });
        let ca = reqwest::Certificate::from_pem(include_bytes!(
            "../../../tests/conformance/directory-sync/ldap-fixture/ca.pem"
        ))
        .unwrap();
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .add_root_certificate(ca)
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap();
        let actual = HttpPolicyFetch::with_client_for_tests(client)
            .get(&format!("https://{address}/policy"))
            .await;
        peer.await.unwrap();
        match expected {
            Some(body) => assert_eq!(actual.unwrap(), body),
            None => assert!(actual.is_err()),
        }
    }
    assert!(
        HttpPolicyFetch::new()
            .get("https://127.0.0.1/policy")
            .await
            .is_err(),
        "production client must reject private targets"
    );
    assert!(
        HttpPolicyFetch::new()
            .get("http://example.test/policy")
            .await
            .is_err(),
        "policy fetch requires HTTPS"
    );
}

#[tokio::test]
async fn production_worker_rejects_a_missing_authoritative_feature_registry() {
    use futures_util::FutureExt;
    use std::{
        os::unix::process::CommandExt,
        process::{Command, Stdio},
    };
    struct Owned(Child);
    impl Drop for Owned {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let Some(db) = setjoin_conformance::harness::Db::for_case("smtp4-feature-startup") else {
        return;
    };
    let owner = db.connect().await.unwrap();
    owner
        .batch_execute(
            "ALTER TABLE feature_toggle_registry_state RENAME TO gofree_smtp4_registry_backup",
        )
        .await
        .unwrap();
    let result = std::panic::AssertUnwindSafe(async {
        let mut child = Owned(
            Command::new(env!("CARGO_BIN_EXE_setjoin-gateway"))
                .arg0("gofree-smtp4-missing-feature-registry")
                .env_clear()
                .env("GATEWAY_LISTEN", "127.0.0.1:0")
                .env("GATEWAY_AUTH_UPSTREAM", "http://127.0.0.1:1")
                .env("RUST_WORKERS_ON", "outbound-mail")
                .env("GO_WORKERS_OFF", "outbound-mail")
                .env("DB_DSN", &db.dsn)
                .env("DB_WORKER_DSN", &db.dsn)
                .env("DB_DIRECT_DSN", &db.dsn)
                .env("S3_ENDPOINT", "http://127.0.0.1:1")
                .env("S3_BUCKET", "mail")
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn_boot()
                .unwrap(),
        );
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                assert_eq!(
                    status.code(),
                    Some(0),
                    "frozen Go returns normally on toggle init failure"
                );
                let mut stderr = String::new();
                std::io::Read::read_to_string(child.0.stderr.as_mut().unwrap(), &mut stderr)
                    .unwrap();
                assert!(
                    stderr.contains("toggle init failed")
                        && stderr.contains("registry")
                        && !stderr.contains("server boot checks completed"),
                    "{stderr}"
                );
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "worker accepted a missing feature registry"
            );
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .catch_unwind()
    .await;
    owner
        .batch_execute(
            "ALTER TABLE gofree_smtp4_registry_backup RENAME TO feature_toggle_registry_state",
        )
        .await
        .unwrap();
    if let Err(error) = result {
        std::panic::resume_unwind(error)
    }
}
