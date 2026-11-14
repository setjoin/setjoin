//! #358 DELETE gate, gateway half: the real executable with GATEWAY_UPSTREAM unset
//! (GATEWAY_AUTH_UPSTREAM is the dead :1 the binary requires; its hops are counted).
//! A Go hop is a rise in setjoin_gateway_proxied_to_go_total. Every (cell, shape)
//! has a reviewed outcome, `Native(status)` or `Hop(owner)`, reviewed against
//! drive_native.rs:93-126 and the CalDAV/CardDAV authorize-None forward. Member
//! bearer controls prove each route is served natively. A mismatch is a finding:
//! never copy observed output into EXPECT. The guard pins the Hop cells.
use crate::common::boot::Child;
use crate::common::boot::CommandBootExt;
mod common;
use base64::Engine;
use common::{body_bytes, full, send, BoxError};
use hyper::Request;
use serde_json::json;
use setjoin_conformance::{fixture, harness::Db};
use std::collections::BTreeMap;
use std::process::{Command, Stdio};
use std::time::Duration;

const SECRET: &str = "delete-gate-gateway-jwt-secret-0123456789";
const PASSWORD: &str = "Password1!";
// SPNEGO cannot be minted without a KDC (#355 adds the fixture): a well-formed header shape.
const NEGOTIATE: &str =
    "Negotiate YIIBhgYGKwYBBQUCoIIBejCCAXagGDAWBgkqhkiC9xIBAgIGCSqGSIb3EgECAg==";
const CELLS: &[(&str, &[(&str, bool)])] = &[
    ("default", &[]),
    ("guest-program-off", &[("feature.guest_accounts", false)]),
    (
        "conditional-access",
        &[("feature.conditional_access", true)],
    ),
    (
        "device-trust",
        &[("feature.device_trust_enforcement", true)],
    ),
    ("token-binding", &[("feature.token_binding", true)]),
];
const SHAPES: [&str; 10] = [
    "caldav-basic",
    "caldav-negotiate",
    "caldav-member",
    "carddav-basic",
    "carddav-negotiate",
    "carddav-member",
    "drive-basic",
    "drive-negotiate",
    "drive-guest",
    "drive-member",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Outcome {
    Hop(&'static str),
    Native(u16),
}
use Outcome::{Hop, Native};

const ALL: &[&str] = &[
    "default",
    "guest-program-off",
    "conditional-access",
    "device-trust",
    "token-binding",
];
/// Reviewed outcomes. Hop cells only shrink (guard: MATRIX_HOPS = 35).
const EXPECT: &[(&[&str], &str, Outcome)] = &[
    (ALL, "caldav-basic", Hop("#355 DAV Basic (caldav.rs:74)")),
    (
        ALL,
        "caldav-negotiate",
        Hop("#355 DAV Negotiate (caldav.rs:74)"),
    ),
    (ALL, "caldav-member", Native(207)),
    (ALL, "carddav-basic", Hop("#355 DAV Basic (carddav.rs:48)")),
    (
        ALL,
        "carddav-negotiate",
        Hop("#355 DAV Negotiate (carddav.rs:48)"),
    ),
    (ALL, "carddav-member", Native(207)),
    (
        ALL,
        "drive-basic",
        Hop("#355 native-token Basic (drive_native.rs:117)"),
    ),
    (
        ALL,
        "drive-negotiate",
        Hop("#355 native-token Negotiate (drive_native.rs:121)"),
    ),
    (
        ALL,
        "drive-guest",
        Hop("#353 guest program admission (drive_native.rs:125)"),
    ),
    (ALL, "drive-member", Native(200)),
];

struct Process {
    child: Child,
    address: std::net::SocketAddr,
    log: std::path::PathBuf,
}
impl Drop for Process {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            unsafe {
                libc::kill(self.child.id() as i32, libc::SIGTERM);
            }
            for _ in 0..50 {
                if self.child.try_wait().ok().flatten().is_some() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            if self.child.try_wait().ok().flatten().is_none() {
                let _ = self.child.kill();
            }
        }
        let _ = self.child.wait();
        if !std::thread::panicking() {
            let _ = std::fs::remove_file(&self.log);
        }
    }
}
impl Process {
    async fn start(db: &Db) -> Result<Self, BoxError> {
        use std::os::unix::process::CommandExt;
        let listener = setjoin_conformance::ports::listener().await;
        let address = listener.local_addr()?;
        drop(listener);
        let jwks = common::fake_upstream(|_| async {
            hyper::Response::builder()
                .header("content-type", "application/json")
                .body(full(
                    include_bytes!("../../../tests/conformance/jmap/test-jwks.json").as_slice(),
                ))
                .unwrap()
        })
        .await;
        let log =
            std::env::temp_dir().join(format!("gofree-delete-gate-gateway-{}.log", address.port()));
        let output = std::fs::File::create(&log)?;
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_setjoin-gateway"));
        cmd.arg0("gofree-delete-gate-gateway").env_clear();
        for (key, value) in [
            ("GATEWAY_LISTEN", address.to_string()),
            ("GATEWAY_AUTH_UPSTREAM", "http://127.0.0.1:1".into()),
            ("DB_DSN", db.app.as_deref().unwrap_or(&db.dsn).into()),
            ("DB_WORKER_DSN", db.dsn.clone()),
            ("DB_OWNER_DSN", db.dsn.clone()),
            ("DB_DIRECT_DSN", db.direct.clone()),
            ("DB_ENCRYPTION_KEY", "22".repeat(32)),
            (
                "AUTHSERVER_JWKS_URL",
                format!("http://{jwks}/.well-known/jwks.json"),
            ),
            ("JWT_SECRET", SECRET.into()),
            ("CORE_RATE_LIMIT", "100000".into()),
            ("ADMIN_RATE_LIMIT", "100000".into()),
            ("S3_ENDPOINT", "http://127.0.0.1:1".into()),
            ("S3_ACCESS_KEY", "test-access".into()),
            ("S3_SECRET_KEY", "test-secret".into()),
            ("S3_BUCKET", "mailblobs".into()),
            ("S3_SECURE", "false".into()),
        ] {
            cmd.env(key, value);
        }
        let child = cmd
            .stdout(Stdio::from(output.try_clone()?))
            .stderr(Stdio::from(output))
            .spawn_boot()?;
        let mut process = Self {
            child,
            address,
            log,
        };
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(status) = process.child.try_wait()? {
                return Err(format!(
                    "gateway exited {status}: {}",
                    std::fs::read_to_string(&process.log)?
                )
                .into());
            }
            if tokio::net::TcpStream::connect(address).await.is_ok() {
                return Ok(process);
            }
            if tokio::time::Instant::now() > deadline {
                return Err("gateway startup timed out".into());
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
}
async fn go_hops(address: std::net::SocketAddr) -> Result<u64, BoxError> {
    let r = send(
        address,
        Request::builder()
            .uri("/_gateway/metrics")
            .body(full(""))
            .unwrap(),
    )
    .await;
    let text = String::from_utf8(body_bytes(r).await.to_vec())?;
    Ok(text
        .lines()
        .find_map(|l| l.strip_prefix("setjoin_gateway_proxied_to_go_total "))
        .ok_or("proxied_to_go_total missing")?
        .trim()
        .parse()?)
}
/// Shaped like tests/drive_native_token.rs:344 (jti, fam, nbf, amr, acr).
fn token(user: i64, email: &str, guest: bool) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let mut c = json!({"uid":user,"email":email,"typ":"access","jti":format!("delete-gate-{user}"),
        "fam":"35800000-0000-4000-8000-000000000001","iss":"mailserver","aud":["mailserver-gateway"],
        "iat":now,"nbf":now,"exp":now+3600,"amr":["pwd"],"acr":"aal1"});
    if guest {
        c["acct"] = json!("guest");
    }
    setjoin_authz::legacy_jwt::sign_hs256(SECRET.as_bytes(), &c.to_string())
}
fn expected() -> BTreeMap<(&'static str, &'static str), Outcome> {
    let mut out = BTreeMap::new();
    for (cells, shape, outcome) in EXPECT {
        assert!(SHAPES.contains(shape), "EXPECT names unknown shape {shape}");
        for cell in *cells {
            assert!(
                CELLS.iter().any(|(n, _)| n == cell),
                "EXPECT names unknown cell {cell}"
            );
            assert!(
                out.insert((*cell, *shape), *outcome).is_none(),
                "EXPECT lists {cell}/{shape} twice"
            );
        }
    }
    for (cell, _) in CELLS {
        for shape in SHAPES {
            assert!(
                out.contains_key(&(*cell, shape)),
                "EXPECT has no outcome for {cell}/{shape}"
            );
        }
    }
    out
}

#[tokio::test]
async fn gateway_matrix_matches_reviewed_outcomes() -> Result<(), BoxError> {
    let expect = expected();
    let db = Db::for_case("delete-gate-gateway").expect("assigned DB required");
    let c = db.connect().await?;
    c.query_one(
        "SELECT pg_advisory_lock(hashtextextended('gofree-delete-gate',0))",
        &[],
    )
    .await?;
    let member = fixture::account(&c, "delete-gate-member").await?;
    let target = fixture::account(&c, "delete-gate-target").await?;
    c.execute(
        "UPDATE users SET password_hash=$1,mfa_exempt=true WHERE id=$2",
        &[&bcrypt::hash(PASSWORD, 4)?, &member.user],
    )
    .await?;
    let member_email: String = c
        .query_one("SELECT email FROM users WHERE id=$1", &[&member.user])
        .await?
        .get(0);
    let guest_email: String = c
        .query_one(
            "SELECT 'delete-gate-guest-'||replace(gen_random_uuid()::text,'-','')||'@example.test'",
            &[],
        )
        .await?
        .get(0);
    let guest: i64 = c
        .query_one(
            "INSERT INTO users(username,domain_id,email,display_name,password_hash) VALUES($1,(SELECT id FROM domains WHERE name='guest.invalid'),$1,'delete gate guest','x') RETURNING id",
            &[&guest_email],
        )
        .await?
        .get(0);
    c.execute(
        "INSERT INTO guest_accounts(user_id,invited_email,invited_by_email,host_domain_id,status) VALUES($1,$2,'inviter@example.test',$3,'active')",
        &[&guest, &guest_email, &member.domain],
    )
    .await?;
    let mut keys: Vec<&str> = vec!["feature.drive"];
    keys.extend(CELLS.iter().flat_map(|(_, t)| t.iter().map(|(k, _)| *k)));
    let mut saved: Vec<(String, Option<bool>)> = Vec::new();
    for key in &keys {
        let v: Option<bool> = c
            .query_opt("SELECT enabled FROM feature_toggles WHERE key=$1", &[key])
            .await?
            .map(|r| r.get(0));
        saved.push((key.to_string(), v));
    }
    let basic = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{member_email}:{PASSWORD}"))
    );
    let member_bearer = format!("Bearer {}", token(member.user, &member_email, false));
    let guest_bearer = format!("Bearer {}", token(guest, &guest_email, true));
    let mint = json!({"user_id": target.user, "lifetime": 99999999}).to_string();
    let upsert = "INSERT INTO feature_toggles(key,enabled) VALUES($1,$2) ON CONFLICT(key) DO UPDATE SET enabled=$2";
    let outcome: Result<Vec<String>, BoxError> = async {
        let mut problems = Vec::new();
        for (cell, toggles) in CELLS {
            for (key, v) in &saved {
                match v {
                    Some(on) => {
                        c.execute(upsert, &[key, on]).await?;
                    }
                    None => {
                        c.execute("DELETE FROM feature_toggles WHERE key=$1", &[key]).await?;
                    }
                }
            }
            c.execute(upsert, &[&"feature.drive", &true]).await?;
            for (key, on) in *toggles {
                c.execute(upsert, &[key, on]).await?;
            }
            let process = Process::start(&db).await?;
            for shape in SHAPES {
                let (method, path, auth, payload): (&str, &str, &str, String) = match shape {
                    "caldav-basic" => ("PROPFIND", "/caldav/", basic.as_str(), String::new()),
                    "caldav-negotiate" => ("PROPFIND", "/caldav/", NEGOTIATE, String::new()),
                    "caldav-member" => ("PROPFIND", "/caldav/", member_bearer.as_str(), String::new()),
                    "carddav-basic" => ("PROPFIND", "/carddav/", basic.as_str(), String::new()),
                    "carddav-negotiate" => ("PROPFIND", "/carddav/", NEGOTIATE, String::new()),
                    "carddav-member" => ("PROPFIND", "/carddav/", member_bearer.as_str(), String::new()),
                    "drive-basic" => ("POST", "/api/drive/native-token", basic.as_str(), mint.clone()),
                    "drive-negotiate" => ("POST", "/api/drive/native-token", NEGOTIATE, mint.clone()),
                    "drive-guest" => ("POST", "/api/drive/native-token", guest_bearer.as_str(), mint.clone()),
                    "drive-member" => ("POST", "/api/drive/native-token", member_bearer.as_str(), mint.clone()),
                    other => return Err(format!("unknown shape {other}").into()),
                };
                let want = expect[&(*cell, shape)];
                let before = go_hops(process.address).await?;
                let mut request = Request::builder()
                    .method(hyper::Method::from_bytes(method.as_bytes()).unwrap())
                    .uri(path)
                    .header("host", "mail.delete-gate.test")
                    .header("authorization", auth)
                    .header("x-request-id", "delete-gate");
                request = if method == "POST" {
                    request.header("content-type", "application/json")
                } else {
                    request.header("depth", "0")
                };
                let response = send(process.address, request.body(full(payload)).unwrap()).await;
                let status = response.status().as_u16();
                let raw = String::from_utf8_lossy(&body_bytes(response).await).into_owned();
                let hops = go_hops(process.address).await? - before;
                let ok = match want {
                    Hop(_) => hops == 1,
                    Native(code) => hops == 0 && status == code,
                };
                if !ok {
                    problems.push(format!(
                        "cell {cell} shape {shape}: expected {want:?}, got status {status} with {hops} Go hop(s): {}",
                        raw.chars().take(200).collect::<String>()
                    ));
                }
            }
            drop(process);
        }
        Ok(problems)
    }
    .await;
    for (key, v) in &saved {
        match v {
            Some(on) => {
                c.execute(upsert, &[key, on]).await?;
            }
            None => {
                c.execute("DELETE FROM feature_toggles WHERE key=$1", &[key])
                    .await?;
            }
        }
    }
    c.execute("DELETE FROM guest_accounts WHERE user_id=$1", &[&guest])
        .await?;
    c.execute("DELETE FROM users WHERE id=$1", &[&guest])
        .await?;
    fixture::remove(&c, &target).await?;
    fixture::remove(&c, &member).await?;
    let problems = outcome?;
    eprintln!(
        "DELETE-GATE-MATRIX gateway cells={} shapes={} mismatches={}",
        CELLS.len(),
        SHAPES.len(),
        problems.len()
    );
    assert!(
        problems.is_empty(),
        "{}\nA mismatch is a finding: read the forward site named in EXPECT, then fix the code or get \
         the EXPECT change reviewed. Never copy this output into EXPECT.",
        problems.join("\n")
    );
    Ok(())
}
