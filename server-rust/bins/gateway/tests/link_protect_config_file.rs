//! #357: `jwt.secret` from the `SETJOIN_CONFIG` YAML verifies link-protect tokens in the
//! executable gateway, no click reaches Go, and the secret never appears in its logs.
//! The click names mailbox -1 (D-357e-1) and an unparsable URL, so the answer (the warn
//! page) needs neither DNS nor an audit row.
mod common;
use common::boot::CommandBootExt;
use common::BoxError;
use hmac::{Hmac, Mac};
use hyper::Request;
use setjoin_conformance::harness::Db;
use sha2::Sha256;
use std::process::{Command, Stdio};
use std::time::Duration;

const SECRET: &str = "yaml-only-link-protect-secret-0123456789";

fn sign(url: &str, mailbox: i64, secret: &str) -> String {
    use base64::{engine::general_purpose::URL_SAFE, Engine};
    let payload = format!(
        "{{\"u\":{},\"m\":\"\",\"b\":{mailbox},\"e\":4102444800}}",
        serde_json::to_string(url).unwrap()
    );
    let b64 = URL_SAFE.encode(payload);
    let key = setjoin_gateway::link_protect::TokenKeys::derive(secret.as_bytes(), 1);
    let mut mac = Hmac::<Sha256>::new_from_slice(&key).unwrap();
    mac.update(b64.as_bytes());
    format!("{b64}.{}", URL_SAFE.encode(mac.finalize().into_bytes())).replace('=', "%3D")
}

#[tokio::test]
async fn yaml_jwt_secret_verifies_clicks_natively_and_is_never_logged() -> Result<(), BoxError> {
    let Some(db) = Db::for_case("link-protect-config-file") else {
        return Ok(());
    };
    let dir = std::env::temp_dir().join(format!("gofree-357e-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    let yaml = dir.join("setjoin.yaml");
    std::fs::write(&yaml, format!("jwt:\n  secret: {SECRET}\n"))?;
    let log_path = dir.join("gateway.log");
    let log = std::fs::File::create(&log_path)?;
    let jwks = common::fake_upstream(|_| async {
        hyper::Response::builder()
            .header("content-type", "application/json")
            .body(common::full(
                include_bytes!("../../../tests/conformance/jmap/test-jwks.json").as_slice(),
            ))
            .unwrap()
    })
    .await;
    let address = setjoin_conformance::ports::address();
    let mut command = Command::new(env!("CARGO_BIN_EXE_setjoin-gateway"));
    command.env_clear();
    for (key, value) in [
        ("GATEWAY_LISTEN", address.to_string()),
        ("GATEWAY_AUTH_UPSTREAM", format!("http://{jwks}")),
        ("DB_DSN", db.app.as_deref().unwrap_or(&db.dsn).to_owned()),
        ("DB_WORKER_DSN", db.dsn.clone()),
        ("DB_DIRECT_DSN", db.direct.clone()),
        ("DB_ENCRYPTION_KEY", "22".repeat(32)),
        (
            "AUTHSERVER_JWKS_URL",
            format!("http://{jwks}/.well-known/jwks.json"),
        ),
        ("CORE_RATE_LIMIT", "100000".into()),
        ("SETJOIN_CONFIG", yaml.display().to_string()),
    ] {
        command.env(key, value);
    }
    if let Ok(path) = std::env::var("LLVM_PROFILE_FILE") {
        command.env("LLVM_PROFILE_FILE", path);
    }
    let mut child = command
        .stdout(Stdio::from(log.try_clone()?))
        .stderr(Stdio::from(log))
        .spawn_boot()?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    while tokio::net::TcpStream::connect(address).await.is_err() {
        if let Some(status) = child.try_wait()? {
            return Err(format!(
                "gateway exited: {status}: {}",
                std::fs::read_to_string(&log_path)?
            )
            .into());
        }
        if tokio::time::Instant::now() > deadline {
            return Err("gateway startup timeout".into());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let click = |token: String| {
        Request::get(format!("/link-protect?token={token}"))
            .header("host", "mail.test")
            .body(common::full(""))
            .unwrap()
    };
    let good = common::send(address, click(sign("http://[bad/", -1, SECRET))).await;
    let status = good.status().as_u16();
    let body = String::from_utf8(common::body_bytes_unchecked(good).await.to_vec())?;
    assert_eq!(status, 200, "{body}");
    assert!(body.contains("<title>Warning"), "{body}");
    let wrong = common::send(
        address,
        click(sign(
            "http://[bad/",
            -1,
            "some-other-secret-some-other-secret",
        )),
    )
    .await;
    assert_eq!(wrong.status().as_u16(), 400);
    let metrics = common::send(
        address,
        Request::get("/_gateway/metrics").body(common::full(""))?,
    )
    .await;
    let metrics = String::from_utf8(common::body_bytes_unchecked(metrics).await.to_vec())?;
    assert!(
        metrics
            .lines()
            .any(|l| l == "setjoin_gateway_proxied_to_go_total 0"),
        "{metrics}"
    );
    drop(child);
    let logged = std::fs::read_to_string(&log_path)?;
    assert!(
        !logged.contains(SECRET),
        "the YAML JWT secret appeared in the gateway's logs"
    );
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}
