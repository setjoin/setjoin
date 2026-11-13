//! #305: the :80 listener against frozen Go. Go's real HTTP-01 token responder
//! (`internal/acme` overlay) and its real `httpsRedirectHandler` (`cmd/mailserverd` overlay) answer
//! a request list once; the Rust listener must answer the same status, content type, Location and
//! body, with the token store checked first and everything else redirected.
//!
//! Record: `GOFREE_RECORD_HTTP80=1` + `GOFREE_GO_SOURCE`. Replay needs no Go.
mod drain_oracle;
use drain_oracle::{repo_root, BoxError, GoTick};
use serde_json::{json, Value};
use setjoin_acme::Http01Store;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn golden(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/conformance/acme/goldens")
        .join(format!("{name}.json"))
}

fn run_go(package: &str, overlay: &str, test: &str, file: &str) -> Result<Value, BoxError> {
    if std::env::var_os("GOFREE_ORACLE_CONTAINER_PREFIX").is_none() {
        std::env::set_var("GOFREE_ORACLE_CONTAINER_PREFIX", "gofree-plat7-http80");
    }
    let out = repo_root()?.join(format!("test-results/gofree-plat7-acme/{test}.json"));
    std::fs::create_dir_all(out.parent().unwrap())?;
    GoTick {
        package,
        overlay,
        test,
        file,
        env: vec![(
            "GOFREE_HTTP80_OUT".into(),
            format!("/src/test-results/gofree-plat7-acme/{test}.json"),
        )],
        docker: vec![],
    }
    .run()?;
    Ok(serde_json::from_slice(&std::fs::read(out)?)?)
}

async fn raw(
    addr: std::net::SocketAddr,
    method: &str,
    target: &str,
) -> Result<(u16, std::collections::BTreeMap<String, String>, String), BoxError> {
    let mut s = tokio::net::TcpStream::connect(addr).await?;
    s.write_all(
        format!(
            "{method} {target} HTTP/1.1\r\nHost: mail.example.test\r\nConnection: close\r\n\r\n"
        )
        .as_bytes(),
    )
    .await?;
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).await?;
    let text = String::from_utf8_lossy(&buf).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").ok_or("no head")?;
    let mut lines = head.lines();
    let status = lines
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()?;
    let headers = lines
        .filter_map(|l| l.split_once(": "))
        .map(|(k, v)| (k.to_lowercase(), v.to_owned()))
        .collect();
    Ok((status, headers, body.to_owned()))
}

#[tokio::test(flavor = "multi_thread")]
async fn http80_matches_recorded_go() -> Result<(), BoxError> {
    if std::env::var_os("GOFREE_RECORD_HTTP80").is_some() {
        let tokens = run_go(
            "internal/acme",
            "../acme/http01_handler_test.go.txt",
            "TestGoFreeHTTP01Handler",
            "gofree_http01_handler_test.go",
        )?;
        let redirects = run_go(
            "cmd/mailserverd",
            "../acme/redirect_test.go.txt",
            "TestGoFreeHTTPSRedirect",
            "gofree_redirect_test.go",
        )?;
        let source = std::env::var("GOFREE_GO_SOURCE")?;
        for (name, observation) in [
            ("acme-http80-token-responder", tokens),
            ("acme-http80-https-redirect", redirects),
        ] {
            let _ = std::fs::remove_file(golden(name));
            setjoin_conformance::golden::record(
                &golden(name),
                &json!({"format":1,"case":name,"go_source":source,"observation":observation}),
            )?;
        }
        return Ok(());
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let store = Http01Store::default();
    store.present("tok-1", "tok-1.thumbprint");
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(setjoin_gateway::acme::serve_http80(
        listener,
        store,
        "mail.example.test".into(),
        async move {
            let _ = stopped.await;
        },
    ));
    // Token responder: Go's `next` was a teapot; in Rust `next` is the redirect (Go's composition).
    let tokens: Value =
        serde_json::from_slice(&std::fs::read(golden("acme-http80-token-responder"))?)?;
    for row in tokens["observation"].as_array().unwrap() {
        let (status, headers, body) = raw(
            addr,
            row["method"].as_str().unwrap(),
            row["path"].as_str().unwrap(),
        )
        .await?;
        if row["status"] == 418 {
            assert_eq!(status, 301, "{row}: a non-challenge request is redirected");
        } else {
            assert_eq!(json!(status), row["status"], "{row}");
            assert_eq!(
                headers.get("content-type").cloned().unwrap_or_default(),
                row["content_type"].as_str().unwrap(),
                "{row}"
            );
            assert_eq!(json!(body), row["body"], "{row}");
        }
    }
    let redirects: Value =
        serde_json::from_slice(&std::fs::read(golden("acme-http80-https-redirect"))?)?;
    for row in redirects["observation"].as_array().unwrap() {
        let (status, headers, body) = raw(
            addr,
            row["method"].as_str().unwrap(),
            row["path"].as_str().unwrap(),
        )
        .await?;
        assert_eq!(json!(status), row["status"], "{row}");
        assert_eq!(
            headers.get("location").cloned().unwrap_or_default(),
            row["location"].as_str().unwrap(),
            "{row}"
        );
        assert_eq!(
            headers.get("content-type").cloned().unwrap_or_default(),
            row["content_type"].as_str().unwrap(),
            "{row}"
        );
        assert_eq!(json!(body), row["body"], "{row}");
    }
    let _ = stop.send(());
    let _ = server.await;
    println!("GOLDEN-REPLAY: acme :80 :: http80");
    Ok(())
}
