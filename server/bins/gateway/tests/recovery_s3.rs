use http_body_util::Full;
use hyper::{body::Bytes, service::service_fn, Request, Response};
use hyper_util::rt::TokioIo;
use setjoin_gateway::recovery_worker::{ObjectStore, S3Store};
use std::{
    convert::Infallible,
    sync::{Arc, Mutex},
};
use tokio::net::TcpListener;

#[tokio::test]
async fn deletes_the_exact_object_using_the_bucket_region() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let seen = Arc::new(Mutex::new(Vec::new()));
    let observed = seen.clone();
    let server = tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let observed = observed.clone();
            tokio::spawn(async move {
                let service = service_fn(move |req: Request<hyper::body::Incoming>| {
                    let observed = observed.clone();
                    async move {
                        let method = req.method().to_string();
                        let uri = req.uri().to_string();
                        let auth = req
                            .headers()
                            .get("authorization")
                            .unwrap()
                            .to_str()
                            .unwrap()
                            .to_owned();
                        observed
                            .lock()
                            .unwrap()
                            .push((method.clone(), uri.clone(), auth));
                        let (status, body) = if method == "GET" {
                            (200, "<LocationConstraint>eu-central-1</LocationConstraint>")
                        } else {
                            (204, "")
                        };
                        let response = Response::builder()
                            .status(status)
                            .body(Full::new(Bytes::from(body)))
                            .unwrap();
                        Ok::<_, Infallible>(response)
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    let store = S3Store::new(&endpoint, "mailblobs", "test-access", "test-secret").unwrap();
    store.remove("recovery-quarantine/a/b").await.unwrap();
    server.abort();
    let requests = seen.lock().unwrap();
    assert_eq!(requests.len(), 2);
    // minio-go bucket-cache.go sets location="" with url.Values.Encode.
    assert_eq!(
        (&requests[0].0[..], &requests[0].1[..]),
        ("GET", "/mailblobs/?location=")
    );
    assert_eq!(
        (&requests[1].0[..], &requests[1].1[..]),
        ("DELETE", "/mailblobs/recovery-quarantine/a/b")
    );
    assert!(
        requests[1].2.contains("/eu-central-1/s3/aws4_request"),
        "{}",
        requests[1].2
    );
}

#[tokio::test]
async fn denied_location_with_region_header_still_deletes_in_that_region() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let auth = Arc::new(Mutex::new(String::new()));
    let observed = auth.clone();
    let server = tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let observed = observed.clone();
            tokio::spawn(async move {
                let service = service_fn(move |req: Request<hyper::body::Incoming>| {
                    let observed = observed.clone();
                    async move {
                        let response = if req.method() == hyper::Method::GET {
                            Response::builder()
                                .status(403)
                                .header("x-amz-bucket-region", "us-west-2")
                        } else {
                            *observed.lock().unwrap() = req
                                .headers()
                                .get("authorization")
                                .unwrap()
                                .to_str()
                                .unwrap()
                                .to_owned();
                            Response::builder().status(204)
                        };
                        Ok::<_, Infallible>(response.body(Full::new(Bytes::new())).unwrap())
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    let store = S3Store::new(&endpoint, "mailblobs", "test-access", "test-secret").unwrap();
    let result = store.remove("recovery-quarantine/a/b").await;
    server.abort();
    assert!(result.is_ok(), "{result:?}");
    assert!(auth.lock().unwrap().contains("/us-west-2/s3/aws4_request"));
}

#[test]
fn refuses_plaintext_for_non_loopback_object_stores() {
    assert!(S3Store::new(
        "http://storage.example.test:9000",
        "mailblobs",
        "key",
        "secret"
    )
    .is_err());
    assert!(S3Store::new("http://127.0.0.1:9000", "mailblobs", "key", "secret").is_ok());
}

#[tokio::test]
async fn trusts_private_ca_from_the_system_certificate_file() {
    const CHILD: &str = "GOFREE_BLOBS1_TLS_TEST_CHILD";
    if std::env::var_os(CHILD).is_none() {
        use std::os::unix::process::CommandExt;
        let cert_file = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/recovery_tls/ca.pem"
        );
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .arg0("gofree-blobs1-recovery-tls")
            .env(CHILD, "1")
            .env("SSL_CERT_FILE", cert_file)
            .env("SSL_CERT_DIR", "/nonexistent-gofree-blobs1")
            .args([
                "--exact",
                "trusts_private_ca_from_the_system_certificate_file",
                "--nocapture",
            ])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }

    use tokio_rustls::rustls::{
        self,
        pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    };
    let _ = rustls::crypto::ring::default_provider().install_default();
    let cert = CertificateDer::from(include_bytes!("fixtures/recovery_tls/server.der").to_vec());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        include_bytes!("fixtures/recovery_tls/server-key.der").to_vec(),
    ));
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("https://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(stream) = acceptor.accept(stream).await else {
                    return;
                };
                let service = service_fn(|req: Request<hyper::body::Incoming>| async move {
                    let (status, body) = if req.method() == hyper::Method::GET {
                        (200, "<LocationConstraint>us-east-1</LocationConstraint>")
                    } else {
                        (204, "")
                    };
                    Ok::<_, Infallible>(
                        Response::builder()
                            .status(status)
                            .body(Full::new(Bytes::from(body)))
                            .unwrap(),
                    )
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    let store = S3Store::new(&endpoint, "mailblobs", "test-access", "test-secret").unwrap();
    let result = store.remove("recovery-quarantine/a/b").await;
    server.abort();
    assert!(result.is_ok(), "private CA should be trusted: {result:?}");
}

#[tokio::test]
async fn missing_or_partial_credentials_match_gos_anonymous_requests() {
    use http_body_util::BodyExt;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let requests = Arc::new(Mutex::new(Vec::new()));
    let observed = requests.clone();
    let server = tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let observed = observed.clone();
            tokio::spawn(async move {
                let service = service_fn(move |mut request: Request<hyper::body::Incoming>| {
                    let observed = observed.clone();
                    async move {
                        let body = request.body_mut().collect().await.unwrap().to_bytes();
                        observed.lock().unwrap().push(serde_json::json!({"method":request.method().as_str(),"uri":request.uri().to_string(),"body":std::str::from_utf8(&body).unwrap(),"authorization":request.headers().contains_key("authorization"),"date":request.headers().contains_key("x-amz-date"),"sha256":request.headers().contains_key("x-amz-content-sha256")}));
                        let response = if request.uri().query() == Some("location=") {
                            Response::new(Full::new(Bytes::from(
                                "<LocationConstraint>eu-central-1</LocationConstraint>",
                            )))
                        } else {
                            Response::builder()
                                .status(204)
                                .body(Full::new(Bytes::new()))
                                .unwrap()
                        };
                        Ok::<_, Infallible>(response)
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    for (access, secret) in [("", ""), ("test-access", ""), ("", "test-secret")] {
        let store = S3Store::new(&endpoint, "mailblobs", access, secret)
            .expect("Go accepts anonymous credentials");
        store.remove("recovery-quarantine/a/b").await.unwrap();
    }
    server.abort();
    let expected: serde_json::Value =
        serde_json::from_str(include_str!("golden/go-recovery-anonymous-http.json")).unwrap();
    assert_eq!(serde_json::json!(*requests.lock().unwrap()), expected);
}
