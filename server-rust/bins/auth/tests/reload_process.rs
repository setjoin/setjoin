//! Standalone process seam: SIGHUP and HTTP share one live internal-key generation.
mod common;
use std::{
    os::unix::process::CommandExt,
    process::{Child, Command, Stdio},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
struct Owned(Child);
impl Drop for Owned {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
struct ConfigFile(std::path::PathBuf);
impl Drop for ConfigFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}
async fn status(addr: std::net::SocketAddr, key: &str) -> Result<u16, String> {
    status_at(addr, key, "/auth/introspect").await
}
async fn status_at(addr: std::net::SocketAddr, key: &str, path: &str) -> Result<u16, String> {
    Ok(response_at(addr, key, path).await?["status"]
        .as_u64()
        .unwrap() as u16)
}
async fn response_at(
    addr: std::net::SocketAddr,
    key: &str,
    path: &str,
) -> Result<serde_json::Value, String> {
    let mut stream = tokio::net::TcpStream::connect(addr)
        .await
        .map_err(|e| e.to_string())?;
    let body = r#"{"token":"unknown"}"#;
    stream.write_all(format!("POST {path} HTTP/1.1\r\nHost: auth.test\r\nAuthorization: Bearer {key}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).as_bytes()).await.map_err(|e|e.to_string())?;
    let mut raw = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(3),
        stream.read_to_end(&mut raw),
    )
    .await
    .map_err(|e| e.to_string())?
    .map_err(|e| e.to_string())?;
    let raw = String::from_utf8(raw).map_err(|e| e.to_string())?;
    let (head, body) = raw.split_once("\r\n\r\n").ok_or("missing response body")?;
    let status: u16 = head
        .split_whitespace()
        .nth(1)
        .ok_or("no status")?
        .parse()
        .map_err(|_| "bad status")?;
    let mut headers = serde_json::Map::new();
    for line in head.lines().skip(1) {
        if let Some((k, v)) = line.split_once(':') {
            let k = k.to_ascii_lowercase();
            if matches!(k.as_str(), "content-type" | "x-content-type-options") {
                headers.insert(k, serde_json::json!(v.trim()));
            }
        }
    }
    Ok(serde_json::json!({"status":status,"headers":headers,"body":body}))
}
#[tokio::test]
async fn sighup_rearms_the_internal_key_without_rotating_signing_keys() {
    run(false).await;
}
#[tokio::test]
async fn sighup_does_not_mount_boot_disabled_internal_routes() {
    run(true).await;
}
async fn run(empty: bool) {
    let db = setjoin_conformance::harness::Db::for_case("IDLOGIN3-SIGHUP").unwrap();
    let c = db.connect().await.unwrap();
    c.query_one(
        "SELECT pg_advisory_lock(hashtextextended('gofree-idlogin1-oracle',0))",
        &[],
    )
    .await
    .unwrap();
    common::signing_key(&c).await;
    let f: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tests/conformance/identity-login/keys.json"
    ))
    .unwrap();
    let file = ConfigFile(std::env::temp_dir().join(format!(
        "gofree-idlogin3-sighup-{}.yaml",
        uuid::Uuid::new_v4()
    )));
    std::fs::write(
        &file.0,
        if empty {
            "internal:\n  api_key: \"\"\n"
        } else {
            "internal:\n  api_key: old-internal-key\n"
        },
    )
    .unwrap();
    let listener = setjoin_conformance::ports::std_listener();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let mut child = Owned(
        Command::new(env!("CARGO_BIN_EXE_setjoin-auth"))
            .arg0(format!("{}-auth-reload", std::env::var("GOFREE_RESOURCE_PREFIX").unwrap_or_else(|_| "gofree-idlogin3".into())))
            .env("DB_DSN", db.app.as_deref().unwrap_or(&db.dsn))
            .env("JWT_SECRET", f["secret"].as_str().unwrap())
            .env("JWT_SIGNING_ALG", "HS256")
            .env("SETJOIN_CONFIG", &file.0)
            .env("LISTEN_ADDR", addr.to_string())
            .env("CRYPTO_ALGORITHM_PROFILE", "standard")
            .env_remove("INTERNAL_API_KEY")
            .env_remove("TLS_CERT")
            .env_remove("TLS_KEY")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let result = async {
        let mut ready = false;
        for _ in 0..500 {
            if status(addr, "old-internal-key").await == Ok(if empty{401}else{200}) {
                ready = true;
                break;
            }
            if child.0.try_wait().map_err(|e| e.to_string())?.is_some() {
                return Err("auth exited before readiness".to_owned());
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        if !ready {
            return Err("auth readiness deadline".to_owned());
        }
        let mut before=Vec::new();if empty {for path in ["/auth/scim/disable","/admin/reload"]{before.push(serde_json::json!({"path":path,"response":response_at(addr,"new-internal-key",path).await?}));}}
        std::fs::write(&file.0, "internal:\n  api_key: new-internal-key\n")
            .map_err(|e| e.to_string())?;
        if !Command::new("kill")
            .args(["-HUP", &child.0.id().to_string()])
            .status()
            .map_err(|e| e.to_string())?
            .success()
        {
            return Err("could not signal owned auth child".to_owned());
        }
        let mut rearmed = false;
        for _ in 0..250 {
            if status(addr, "new-internal-key").await == Ok(200) {
                rearmed = true;
                break;
            }
            if child.0.try_wait().map_err(|e| e.to_string())?.is_some() {
                return Err("auth exited on SIGHUP".to_owned());
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        if !rearmed {
            return Err("SIGHUP never rearmed new key".to_owned());
        }
        if status(addr, "old-internal-key").await != Ok(401) {
            return Err("old internal key remains accepted".to_owned());
        }
        if empty {let mut after=Vec::new();for path in ["/auth/scim/disable","/admin/reload"]{after.push(serde_json::json!({"path":path,"response":response_at(addr,"new-internal-key",path).await?}));}
        let expected:serde_json::Value=serde_json::from_str(&std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/conformance/identity-token/goldens/operator-boot-empty.json")).map_err(|e|e.to_string())?).map_err(|e|e.to_string())?;
        let actual=serde_json::json!({"format":1,"go_source":"d431c0ecdbb362809c3fdba781a395712612bf61","before":before,"after":after});setjoin_conformance::golden::compare(&expected,&actual)?;
        }
        let kid: String = c
            .query_one("SELECT kid FROM signing_keys WHERE status='active'", &[])
            .await
            .map_err(|e| e.to_string())?
            .get(0);
        if kid != f["kid"].as_str().unwrap() {
            return Err("SIGHUP rotated signing keys".to_owned());
        }
        Ok(())
    }
    .await;
    if child.0.try_wait().unwrap().is_none() {
        let _ = Command::new("kill")
            .args(["-TERM", &child.0.id().to_string()])
            .status();
        for _ in 0..100 {
            if child.0.try_wait().unwrap().is_some() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    }
    drop(child);
    drop(file);
    assert!(result.is_ok(), "{result:?}");
}
