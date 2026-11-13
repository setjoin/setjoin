//! Frozen startup reseal seam: AES/SM4 interoperability and all-or-nothing refusal.
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use serde_json::{json, Value};
use setjoin_conformance::{golden, harness::Db};
type Err = Box<dyn std::error::Error + Send + Sync>;
const KEYS: [&str; 3] = [
    "oidc_provider_idfed2_secret_a_config",
    "oidc_provider_idfed2_secret_b_config",
    "oidc_provider_idfed2_secret_c_config",
];
#[tokio::test]
async fn startup_secret_reseal_matches_go() {
    let db = Db::for_case("IDFED2-secrets").expect("assigned DB required");
    let c = db.connect().await.unwrap();
    c.query_one(
        "SELECT pg_advisory_lock(hashtextextended('gofree-idlogin1-oracle',0))",
        &[],
    )
    .await
    .unwrap();
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../tests/conformance/identity-login/keys.json"
    ))
    .unwrap();
    let master = fixture["secret"].as_str().unwrap().as_bytes();
    let result=async{
        let mut cases=Vec::new();
        for kind in ["plain","repeat","wrong-key","bad-type","smx"]{
            if kind!="repeat"{
                cleanup(&c).await?;
                seed(&c,KEYS[0],json!({"name":"idfed2-secret","enabled":false,"client_secret":"synthetic-rp-secret","extra":{"keep":true}}),false).await?;
                seed(&c,KEYS[2],json!({"client_secret":"","enabled":false}),false).await?;
            }
            if kind=="wrong-key"{
                let sealed=setjoin_config_secret::seal_column(b"wrong-key-secret",b"another synthetic master key 340",setjoin_config_secret::CryptoProfile::Standard)?;
                seed(&c,KEYS[1],json!({"client_secret":URL_SAFE_NO_PAD.encode(sealed)}),true).await?;
            }
            if kind=="bad-type"{seed(&c,KEYS[1],json!({"client_secret":42}),false).await?;}
            let (before,exact_before)=snapshot(&c,master).await?;
            let profile=if kind=="smx"{setjoin_config_secret::CryptoProfile::Smx}else{setjoin_config_secret::CryptoProfile::Standard};
            let outcome=setjoin_identity::rp::reseal(&db.dsn,master,profile).await;
            let (after,exact_after)=snapshot(&c,master).await?;
            cases.push(json!({"case":kind,"count":outcome.as_ref().copied().unwrap_or(0),"error":outcome.is_err(),"unchanged":exact_before==exact_after,"before":before,"after":after}));
        }
        let actual=json!({"format":1,"go_source":"61e9cff379b4087b970c7637ab8af5c4c252af67","seam":"ResealOIDCProviderClientSecrets","cases":cases});
        let path=std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/conformance/identity-rp/secret-go.json");
        let expected:Value=serde_json::from_slice(&std::fs::read(path)?)?;golden::compare(&expected,&actual)?;Ok::<(),Err>(())
    }.await;
    cleanup(&c).await.unwrap();
    result.unwrap();
}
async fn cleanup(c: &tokio_postgres::Client) -> Result<(), Err> {
    c.execute(
        "DELETE FROM system_config WHERE key=ANY($1::text[])",
        &[&KEYS.to_vec()],
    )
    .await?;
    Ok(())
}
async fn seed(
    c: &tokio_postgres::Client,
    key: &str,
    value: Value,
    encrypted: bool,
) -> Result<(), Err> {
    c.execute("INSERT INTO system_config(key,value,encrypted) VALUES($1,$2::text::jsonb,$3) ON CONFLICT(key) DO UPDATE SET value=excluded.value,encrypted=excluded.encrypted",&[&key,&value.to_string(),&encrypted]).await?;
    Ok(())
}
async fn snapshot(
    c: &tokio_postgres::Client,
    master: &[u8],
) -> Result<(Vec<Value>, Vec<(String, String, bool)>), Err> {
    let rows=c.query("SELECT key,value::text,encrypted FROM system_config WHERE key=ANY($1::text[]) ORDER BY key",&[&KEYS.to_vec()]).await?;
    let mut out = Vec::new();
    let mut exact = Vec::new();
    for r in rows {
        let key: String = r.get(0);
        let raw: String = r.get(1);
        let encrypted: bool = r.get(2);
        let mut value: Value = serde_json::from_str(&raw)?;
        exact.push((key.clone(), raw, encrypted));
        if let Some(raw) = value["client_secret"].as_str() {
            if let Ok(bytes) = URL_SAFE_NO_PAD
                .decode(raw)
                .or_else(|_| STANDARD.decode(raw))
            {
                if bytes.starts_with(b"EK01") {
                    let plain = setjoin_config_secret::open_column(&bytes, master)
                        .ok()
                        .and_then(|b| String::from_utf8(b).ok());
                    value["client_secret"] =
                        json!({"envelope":true,"opened":plain,"algorithm":bytes.get(4)});
                }
            }
        }
        out.push(json!({"key":key,"value":value,"encrypted":encrypted}));
    }
    Ok((out, exact))
}

struct Process(Option<std::process::Child>);
impl Drop for Process {
    fn drop(&mut self) {
        if let Some(child) = &mut self.0 {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}
#[tokio::test]
async fn disabled_rp_warns_about_bad_secret_and_keeps_serving() {
    use std::os::unix::process::CommandExt;
    use std::process::Stdio;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let db = Db::for_case("IDFED2-secret-startup").expect("assigned DB required");
    let c = db.connect().await.unwrap();
    c.query_one(
        "SELECT pg_advisory_lock(hashtextextended('gofree-idlogin1-oracle',0))",
        &[],
    )
    .await
    .unwrap();
    cleanup(&c).await.unwrap();
    seed(
        &c,
        KEYS[1],
        json!({"client_secret":42,"enabled":false}),
        false,
    )
    .await
    .unwrap();
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../tests/conformance/identity-login/keys.json"
    ))
    .unwrap();
    let addr = setjoin_conformance::ports::address();
    let mut child = Process(Some(
        std::process::Command::new(env!("CARGO_BIN_EXE_setjoin-auth"))
            .arg0("gofree-idfed2-disabled-rp-startup")
            .env_remove("SETJOIN_CONFIG")
            .env_remove("RUST_WORKERS_ON")
            .env_remove("GO_WORKERS_OFF")
            .env_remove("DB_ENCRYPTION_KEY")
            .env_remove("AUDIT_HMAC_KEY")
            .env("DB_DSN", &db.dsn)
            .env("JWT_SECRET", fixture["secret"].as_str().unwrap())
            .env("OIDC_ENABLED", "false")
            .env("OIDC_PROVIDER_ENABLED", "false")
            .env("CRYPTO_ALGORITHM_PROFILE", "standard")
            .env("LISTEN_ADDR", addr.to_string())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    ));
    let result = async {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(15);
        loop {
            if child.0.as_mut().unwrap().try_wait()?.is_some() {
                return Err("auth stopped instead of retaining the healthy provider subset".into());
            }
            if let Ok(mut stream) = tokio::net::TcpStream::connect(addr).await {
                stream
                    .write_all(
                        b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
                    )
                    .await?;
                let mut reply = String::new();
                tokio::time::timeout(
                    std::time::Duration::from_secs(3),
                    stream.read_to_string(&mut reply),
                )
                .await??;
                if reply.starts_with("HTTP/1.1 200") {
                    return Ok::<(), Err>(());
                }
                return Err(format!("health unavailable after reseal warning: {reply}").into());
            }
            if tokio::time::Instant::now() > deadline {
                return Err("auth did not listen after reseal warning".into());
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    }
    .await;
    let _ = child.0.as_mut().unwrap().kill();
    let output = child.0.take().unwrap().wait_with_output().unwrap();
    cleanup(&c).await.unwrap();
    result.unwrap();
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("plaintext providers will fail closed"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
