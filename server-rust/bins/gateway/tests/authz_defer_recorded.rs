//! #406: terminal admission answers through the real front-door HTTP seam.
use crate::common::boot::CommandBootExt;
use crate::common::boot::Child;
mod common;
use common::{body_bytes, full, send};
use hyper::Request;
use setjoin_gateway::jmap::limit::{EdgeLimit, Limiter};
use setjoin_gateway::{Config, Gateway, RouteTable, TrustedProxies};
use std::time::Duration;
use tokio::net::TcpListener;

/// The cases share one database, fixed addresses and ids: libtest's threads must take turns.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[tokio::test]
async fn csrf_failure_is_a_native_problem_without_go() {
    let _serial = SERIAL.lock().await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let gateway = Gateway::new(
        Config {
            upstream: None,
            upstream_header_timeout: Duration::from_secs(2),
            trusted_proxies: TrustedProxies::parse("").unwrap(),
            edge_limit: Some(EdgeLimit::for_front_door(Limiter::new(600, 60))),
        },
        RouteTable::proxy_all(),
    )
    .unwrap();
    let task = tokio::spawn(gateway.serve(listener));
    let response = send(
        address,
        Request::builder()
            .method("POST")
            .uri("/api/admin/users")
            .header("host", "mail.example.test")
            .header("origin", "https://evil.example")
            .header("x-request-id", "authzdefer-csrf")
            .body(full("{}"))
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), 403);
    assert_eq!(body_bytes(response).await,
        "{\"detail\":\"CSRF validation failed\",\"status\":403,\"title\":\"csrf_failed\",\"type\":\"about:blank\"}\n");
    task.abort();
    let _ = task.await;
}

use common::BoxError;
use serde_json::json;
use setjoin_conformance::harness::Db;
use std::process::{Command, Stdio};

const SECRET: &str = "blobs1-test-jwt-secret-for-recording";
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
        Self::start_with(db, &[]).await
    }
    async fn start_with(db: &Db, extra: &[(&str, String)]) -> Result<Self, BoxError> {
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
            std::env::temp_dir().join(format!("gofree-authzdefer-gateway-{}.log", address.port()));
        let output = std::fs::File::create(&log)?;
        if let Ok(ledger) = std::env::var("GOFREE_RESOURCE_LEDGER") {
            use std::io::Write;
            writeln!(
                std::fs::OpenOptions::new().append(true).open(ledger)?,
                "Plan owned gofree-authzdefer-gateway at {address}; log {}; own DB only",
                log.display()
            )?;
        }
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_setjoin-gateway"));
        cmd.arg0("gofree-authzdefer-gateway").env_clear();
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
            ("S3_ENDPOINT", "http://127.0.0.1:1".into()),
            ("S3_ACCESS_KEY", "test-access".into()),
            ("S3_SECRET_KEY", "test-secret".into()),
            ("S3_BUCKET", "mailblobs".into()),
            ("S3_SECURE", "false".into()),
            ("ADMIN_RATE_LIMIT", "100000".into()),
        ] {
            cmd.env(key, value);
        }
        for (key, value) in extra {
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

#[tokio::test]
async fn expired_token_is_rejected_by_the_native_executable() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let db = Db::for_case("authzdefer-expired").expect("assigned DB required");
    let process = Process::start(&db).await?;
    let token = setjoin_authz::legacy_jwt::sign_hs256(SECRET.as_bytes(),
        &json!({"uid":1,"typ":"access","iss":"mailserver","aud":["mailserver-gateway"],"iat":1,"exp":2}).to_string());
    let response = send(
        process.address,
        Request::builder()
            .method("POST")
            .uri("/jmap")
            .header("host", "mail.test")
            .header("authorization", format!("Bearer {token}"))
            .header("x-request-id", "gofree-t5-golden")
            .body(full("{}"))
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), 401);
    let go: serde_json::Value =
        serde_json::from_str(include_str!("golden/go-auth-responses.json"))?;
    assert_eq!(
        body_bytes(response).await,
        go["expired"]["body"].as_str().unwrap().as_bytes()
    );
    Ok(())
}

const FAMILIES: &[(&str, &str, &str)] = &[
    ("F01", "GET", "/api/admin/departments"),
    ("F02", "GET", "/api/admin/ad/config"),
    ("F03", "GET", "/api/admin/conditional-access/policies"),
    ("F04", "GET", "/api/admin/audit"),
    ("F05", "GET", "/api/admin/mailboxes"),
    ("F06", "GET", "/api/admin/anti-phish"),
    ("F07", "GET", "/api/admin/mdm/devices"),
    ("F08", "GET", "/api/admin/alerts"),
    ("F09", "GET", "/api/settings/rules-list"),
    ("F10", "GET", "/api/me/approvals"),
    ("F11", "GET", "/api/admin/guests"),
    ("F12", "GET", "/api/chat/channels/browse"),
    ("F13", "GET", "/api/meet"),
    ("F14", "GET", "/api/drive/nodes"),
    ("F15", "GET", "/api/admin/office"),
    ("F16", "GET", "/api/recovery/incidents"),
    ("F17", "GET", "/api/booking/pages"),
    ("F18", "POST", "/jmap"),
    ("F19", "GET", "/api/settings/imap"),
    ("F20", "POST", "/api/assist/complete"),
    ("F22", "GET", "/api/openapi.full.json"),
];

async fn observe(response: hyper::Response<hyper::body::Incoming>) -> serde_json::Value {
    let status = response.status().as_u16();
    let headers: serde_json::Map<String, serde_json::Value> = response
        .headers()
        .iter()
        .filter(|(k, _)| {
            !matches!(
                k.as_str(),
                "date" | "content-length" | "transfer-encoding" | "connection"
            )
        })
        .map(|(k, v)| (k.to_string(), json!(v.to_str().unwrap())))
        .collect();
    let bytes = body_bytes(response).await;
    json!({"status":status,"headers":headers,"body":String::from_utf8(bytes.to_vec()).unwrap()})
}

async fn assert_zero_proxy(address: std::net::SocketAddr) -> Result<(), BoxError> {
    let metrics = send(
        address,
        Request::builder()
            .uri("/_gateway/metrics")
            .body(full(""))
            .unwrap(),
    )
    .await;
    let text = String::from_utf8(body_bytes(metrics).await.to_vec())?;
    assert!(
        text.contains("setjoin_gateway_proxied_to_go_total 0\n"),
        "{text}"
    );
    Ok(())
}

#[tokio::test]
async fn invalid_tokens_match_frozen_go_across_merged_families() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let db = Db::for_case("authzdefer-invalid-families").expect("assigned DB required");
    let record = std::env::var_os("GOFREE_RECORD_GO_BINARY").is_some();
    let s3 = common::fake_upstream(|_| async { hyper::Response::new(full("")) }).await;
    let go = common::go_oracle::start_named(&db, s3, None, "gofree-authzdefer-oracle").await?;
    let native = if record {
        None
    } else {
        Some(Process::start(&db).await?)
    };
    // Recording still traverses the actual Rust front door, configured as a
    // transparent transport; native replay has GATEWAY_UPSTREAM unset.
    let address = if let Some(go) = &go {
        common::gateway(go.address, "", RouteTable::proxy_all()).await
    } else {
        native.as_ref().unwrap().address
    };
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/conformance/authz-defer/invalid.json");
    let expected: serde_json::Value = if record {
        json!({})
    } else {
        serde_json::from_slice::<serde_json::Value>(&std::fs::read(&path)?)?["cases"].clone()
    };
    let mut observed = serde_json::Map::new();
    let mut mismatches = Vec::new();
    for &(family, method, uri) in FAMILIES {
        for kind in ["expired", "wrong-audience"] {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs();
            let mut claims = json!({"uid":1,"typ":"access","iss":"mailserver","aud":["mailserver-gateway"],"iat":now-10,"exp":now+600});
            if kind == "expired" {
                claims["exp"] = json!(2);
            } else {
                claims["aud"] = json!(["other"]);
            }
            let token =
                setjoin_authz::legacy_jwt::sign_hs256(SECRET.as_bytes(), &claims.to_string());
            let response = send(
                address,
                Request::builder()
                    .method(method)
                    .uri(uri)
                    .header("host", "mail.test")
                    .header("authorization", format!("Bearer {token}"))
                    .header("x-request-id", "authzdefer-oracle")
                    .body(full("{}"))
                    .unwrap(),
            )
            .await;
            let value = observe(response).await;
            let key = format!("{family}-{kind}");
            if !record && value != expected[&key] {
                mismatches.push(format!(
                    "{key}: actual {value}; expected {}",
                    expected[&key]
                ));
            }
            observed.insert(key, value);
        }
    }
    if record {
        assert!(!path.exists(), "immutable corpus already exists");
        std::fs::write(
            path,
            serde_json::to_vec_pretty(
                &json!({"go_source":std::env::var("GOFREE_GO_SOURCE")?,"cases":observed}),
            )?,
        )?;
    } else {
        assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
        let metrics = send(
            address,
            Request::builder()
                .uri("/_gateway/metrics")
                .body(full(""))
                .unwrap(),
        )
        .await;
        let metrics = String::from_utf8(body_bytes(metrics).await.to_vec())?;
        assert!(
            metrics.contains("setjoin_gateway_proxied_to_go_total 0\n"),
            "{metrics}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn guest_claim_without_satellite_matches_go_across_families() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let db = Db::for_case("authzdefer-guest-mismatch").expect("assigned DB required");
    let record = std::env::var_os("GOFREE_RECORD_GO_BINARY").is_some();
    let s3 = common::fake_upstream(|_| async { hyper::Response::new(full("")) }).await;
    let go = common::go_oracle::start_named(&db, s3, None, "gofree-authzdefer-oracle").await?;
    let native = if record {
        None
    } else {
        Some(Process::start(&db).await?)
    };
    let address = if let Some(go) = &go {
        common::gateway(go.address, "", RouteTable::proxy_all()).await
    } else {
        native.as_ref().unwrap().address
    };
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/conformance/authz-defer/guest-mismatch.json");
    let expected: serde_json::Value = if record {
        json!({})
    } else {
        serde_json::from_slice::<serde_json::Value>(&std::fs::read(&path)?)?["cases"].clone()
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let claims = json!({"uid":9000000000i64,"typ":"access","acct":"guest","iss":"mailserver","aud":["mailserver-gateway"],"iat":now-10,"exp":now+600});
    let token = setjoin_authz::legacy_jwt::sign_hs256(SECRET.as_bytes(), &claims.to_string());
    let mut observed = serde_json::Map::new();
    let mut mismatches = Vec::new();
    for &(family, method, uri) in FAMILIES {
        let response = send(
            address,
            Request::builder()
                .method(method)
                .uri(uri)
                .header("host", "mail.test")
                .header("authorization", format!("Bearer {token}"))
                .header("x-request-id", "authzdefer-oracle")
                .body(full("{}"))
                .unwrap(),
        )
        .await;
        let value = observe(response).await;
        if !record && value != expected[family] {
            mismatches.push(format!("{family}: {value}; expected {}", expected[family]));
        }
        observed.insert(family.into(), value);
    }
    if record {
        assert!(!path.exists(), "immutable corpus already exists");
        std::fs::write(
            path,
            serde_json::to_vec_pretty(
                &json!({"go_source":std::env::var("GOFREE_GO_SOURCE")?,"cases":observed}),
            )?,
        )?;
    } else {
        assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
        assert_zero_proxy(address).await?;
    }
    Ok(())
}

struct GuestFixture {
    user: i64,
    domain: i64,
}
impl GuestFixture {
    async fn seed(c: &tokio_postgres::Client) -> Result<Self, BoxError> {
        let domain:i64=c.query_one("INSERT INTO domains(name,is_local) VALUES('authzdefer-'||gen_random_uuid()::text||'.test',true) RETURNING id",&[]).await?.get(0);
        let user:i64=c.query_one("INSERT INTO users(username,domain_id,email,display_name,password_hash) VALUES('authzdefer-'||gen_random_uuid()::text,(SELECT id FROM domains WHERE name='guest.invalid'),'authzdefer-guest@example.test','authzdefer guest','x') RETURNING id",&[]).await?.get(0);
        c.execute("INSERT INTO guest_accounts(user_id,invited_email,invited_by_email,host_domain_id,status) VALUES($1,'authzdefer-guest@example.test','inviter@example.test',$2,'active')",&[&user,&domain]).await?;
        Ok(Self { user, domain })
    }
    async fn cleanup(&self, c: &tokio_postgres::Client) -> Result<(), BoxError> {
        c.execute("DELETE FROM guest_accounts WHERE user_id=$1", &[&self.user])
            .await?;
        c.execute("DELETE FROM users WHERE id=$1", &[&self.user])
            .await?;
        c.execute("DELETE FROM domains WHERE id=$1", &[&self.domain])
            .await?;
        Ok(())
    }
    fn token(&self, claimed: bool) -> String {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut c = json!({"uid":self.user,"email":"authzdefer-guest@example.test","typ":"access","iss":"mailserver","aud":["mailserver-gateway"],"iat":now-10,"exp":now+600});
        if claimed {
            c["acct"] = json!("guest");
        }
        setjoin_authz::legacy_jwt::sign_hs256(SECRET.as_bytes(), &c.to_string())
    }
}

#[tokio::test]
async fn active_guests_are_hidden_on_every_family_when_program_is_off() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let db = Db::for_case("authzdefer-guest-off").expect("assigned DB required");
    let c = db.connect().await?;
    let fixture = GuestFixture::seed(&c).await?;
    let saved: bool = c
        .query_one(
            "SELECT enabled FROM feature_toggles WHERE key='feature.guest_accounts'",
            &[],
        )
        .await?
        .get(0);
    c.execute(
        "UPDATE feature_toggles SET enabled=false WHERE key='feature.guest_accounts'",
        &[],
    )
    .await?;
    use futures_util::FutureExt;
    let result = std::panic::AssertUnwindSafe(async {
        let record = std::env::var_os("GOFREE_RECORD_GO_BINARY").is_some();
        let s3 = common::fake_upstream(|_| async { hyper::Response::new(full("")) }).await;
        let go = common::go_oracle::start_named(&db, s3, None, "gofree-authzdefer-oracle").await?;
        let native = if record {
            None
        } else {
            Some(Process::start(&db).await?)
        };
        let address = if let Some(go) = &go {
            common::gateway(go.address, "", RouteTable::proxy_all()).await
        } else {
            native.as_ref().unwrap().address
        };
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/conformance/authz-defer/guest-off.json");
        let expected = if record {
            json!({})
        } else {
            serde_json::from_slice::<serde_json::Value>(&std::fs::read(&path)?)?["cases"].clone()
        };
        let mut observed = serde_json::Map::new();
        let mut mismatches = Vec::new();
        for &(family, method, uri) in FAMILIES.iter().chain(
            [
                ("public", "GET", "/api/openapi.json"),
                ("rtc", "GET", "/rtc"),
            ]
            .iter(),
        ) {
            for claimed in [false, true] {
                let token = fixture.token(claimed);
                let response = send(
                    address,
                    Request::builder()
                        .method(method)
                        .uri(uri)
                        .header("host", "mail.test")
                        .header("authorization", format!("Bearer {token}"))
                        .header("x-request-id", "authzdefer-oracle")
                        .body(full("{}"))
                        .unwrap(),
                )
                .await;
                let value = observe(response).await;
                let key = format!("{family}-claimed-{claimed}");
                if !record && value != expected[&key] {
                    mismatches.push(format!("{key}: {value}; expected {}", expected[&key]));
                }
                observed.insert(key, value);
            }
        }
        if record {
            assert!(!path.exists());
            std::fs::write(
                path,
                serde_json::to_vec_pretty(
                    &json!({"go_source":std::env::var("GOFREE_GO_SOURCE")?,"cases":observed}),
                )?,
            )?;
        } else {
            assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
            assert_zero_proxy(address).await?;
        }
        Ok::<_, BoxError>(())
    })
    .catch_unwind()
    .await;
    c.execute(
        "UPDATE feature_toggles SET enabled=$1 WHERE key='feature.guest_accounts'",
        &[&saved],
    )
    .await?;
    fixture.cleanup(&c).await?;
    match result {
        Ok(value) => value,
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

#[tokio::test]
async fn active_guests_follow_the_go_allowlist_when_program_is_on() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let db = Db::for_case("authzdefer-guest-on").expect("assigned DB required");
    let c = db.connect().await?;
    let fixture = GuestFixture::seed(&c).await?;
    let saved: bool = c
        .query_one(
            "SELECT enabled FROM feature_toggles WHERE key='feature.guest_accounts'",
            &[],
        )
        .await?
        .get(0);
    c.execute(
        "UPDATE feature_toggles SET enabled=true WHERE key='feature.guest_accounts'",
        &[],
    )
    .await?;
    use futures_util::FutureExt;
    let result = std::panic::AssertUnwindSafe(async {
        let record = std::env::var_os("GOFREE_RECORD_GO_BINARY").is_some();
        let s3 = common::fake_upstream(|_| async { hyper::Response::new(full("")) }).await;
        let go = common::go_oracle::start_named(&db, s3, None, "gofree-authzdefer-oracle").await?;
        let native = if record {
            None
        } else {
            Some(Process::start(&db).await?)
        };
        let address = if let Some(go) = &go {
            common::gateway(go.address, "", RouteTable::proxy_all()).await
        } else {
            native.as_ref().unwrap().address
        };
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/conformance/authz-defer/guest-on.json");
        let expected = if record {
            json!({})
        } else {
            serde_json::from_slice::<serde_json::Value>(&std::fs::read(&path)?)?["cases"].clone()
        };
        let mut observed = serde_json::Map::new();
        let mut mismatches = Vec::new();
        for &(family, method, uri) in FAMILIES
            .iter()
            .filter(|(f, _, _)| !matches!(*f, "F12" | "F13" | "F14"))
            .chain([("public", "GET", "/api/openapi.json")].iter())
        {
            for claimed in [false, true] {
                let token = fixture.token(claimed);
                let response = send(
                    address,
                    Request::builder()
                        .method(method)
                        .uri(uri)
                        .header("host", "mail.test")
                        .header("authorization", format!("Bearer {token}"))
                        .header("x-request-id", "authzdefer-oracle")
                        .body(full("{}"))
                        .unwrap(),
                )
                .await;
                let value = observe(response).await;
                let key = format!("{family}-claimed-{claimed}");
                if !record && value != expected[&key] {
                    mismatches.push(format!("{key}: {value}; expected {}", expected[&key]));
                }
                observed.insert(key, value);
            }
        }
        if record {
            assert!(!path.exists());
            std::fs::write(
                path,
                serde_json::to_vec_pretty(
                    &json!({"go_source":std::env::var("GOFREE_GO_SOURCE")?,"cases":observed}),
                )?,
            )?;
        } else {
            assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
            assert_zero_proxy(address).await?;
        }
        Ok::<_, BoxError>(())
    })
    .catch_unwind()
    .await;
    c.execute(
        "UPDATE feature_toggles SET enabled=$1 WHERE key='feature.guest_accounts'",
        &[&saved],
    )
    .await?;
    fixture.cleanup(&c).await?;
    match result {
        Ok(value) => value,
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

#[tokio::test]
async fn guest_jmap_session_never_resolves_a_mailbox() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let db = Db::for_case("authzdefer-guest-session").expect("assigned DB required");
    let c = db.connect().await?;
    let fixture = GuestFixture::seed(&c).await?;
    let saved: bool = c
        .query_one(
            "SELECT enabled FROM feature_toggles WHERE key='feature.guest_accounts'",
            &[],
        )
        .await?
        .get(0);
    c.execute(
        "UPDATE feature_toggles SET enabled=true WHERE key='feature.guest_accounts'",
        &[],
    )
    .await?;
    use futures_util::FutureExt;
    let result = std::panic::AssertUnwindSafe(async {
        let record = std::env::var_os("GOFREE_RECORD_GO_BINARY").is_some();
        let s3 = common::fake_upstream(|_| async { hyper::Response::new(full("")) }).await;
        let go = common::go_oracle::start_named(&db, s3, None, "gofree-authzdefer-oracle").await?;
        let native = if record {
            None
        } else {
            Some(Process::start(&db).await?)
        };
        let address = if let Some(go) = &go {
            common::gateway(go.address, "", RouteTable::proxy_all()).await
        } else {
            native.as_ref().unwrap().address
        };
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/conformance/authz-defer/guest-session.json");
        let expected = if record {
            json!({})
        } else {
            serde_json::from_slice::<serde_json::Value>(&std::fs::read(&path)?)?["cases"].clone()
        };
        let mut observed = serde_json::Map::new();
        let mut mismatches = Vec::new();
        for &(family, method, uri) in [("jmap-session", "GET", "/.well-known/jmap")].iter() {
            for claimed in [false, true] {
                let token = fixture.token(claimed);
                let response = send(
                    address,
                    Request::builder()
                        .method(method)
                        .uri(uri)
                        .header("host", "mail.test")
                        .header("authorization", format!("Bearer {token}"))
                        .header("x-request-id", "authzdefer-oracle")
                        .body(full("{}"))
                        .unwrap(),
                )
                .await;
                let value = observe(response).await;
                let key = format!("{family}-claimed-{claimed}");
                if !record && value != expected[&key] {
                    mismatches.push(format!("{key}: {value}; expected {}", expected[&key]));
                }
                observed.insert(key, value);
            }
        }
        if record {
            assert!(!path.exists());
            std::fs::write(
                path,
                serde_json::to_vec_pretty(
                    &json!({"go_source":std::env::var("GOFREE_GO_SOURCE")?,"cases":observed}),
                )?,
            )?;
        } else {
            assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
            assert_zero_proxy(address).await?;
        }
        Ok::<_, BoxError>(())
    })
    .catch_unwind()
    .await;
    c.execute(
        "UPDATE feature_toggles SET enabled=$1 WHERE key='feature.guest_accounts'",
        &[&saved],
    )
    .await?;
    fixture.cleanup(&c).await?;
    match result {
        Ok(value) => value,
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

#[tokio::test]
async fn guest_user_domains_do_not_invent_mailbox_authority() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let db = Db::for_case("authzdefer-guest-domains").expect("assigned DB required");
    let c = db.connect().await?;
    let fixture = GuestFixture::seed(&c).await?;
    let keys = vec![
        "feature.guest_accounts",
        "feature.chat",
        "feature.meet",
        "feature.drive",
    ];
    let saved = c
        .query(
            "SELECT key,enabled FROM feature_toggles WHERE key=ANY($1)",
            &[&keys],
        )
        .await?;
    c.execute(
        "UPDATE feature_toggles SET enabled=true WHERE key=ANY($1)",
        &[&keys],
    )
    .await?;
    c.execute("INSERT INTO user_app_entitlements(user_id,app,enabled) SELECT $1,app,true FROM unnest(ARRAY['chat','meet','drive']) app",&[&fixture.user]).await?;
    use futures_util::FutureExt;
    let result = std::panic::AssertUnwindSafe(async {
        let record = std::env::var_os("GOFREE_RECORD_GO_BINARY").is_some();
        let s3 = common::fake_upstream(|_| async { hyper::Response::new(full("")) }).await;
        let livekit = vec![
            ("LIVEKIT_API_KEY", "authzdefer".into()),
            ("LIVEKIT_API_SECRET", "authzdefer-secret".into()),
            ("LIVEKIT_URL", "ws://127.0.0.1:1".into()),
        ];
        let go =
            common::go_oracle::start_named_with_env(&db, s3, "gofree-authzdefer-oracle", &livekit)
                .await?;
        let native = if record {
            None
        } else {
            Some(Process::start_with(&db, &livekit).await?)
        };
        let address = if let Some(go) = &go {
            common::gateway(go.address, "", RouteTable::proxy_all()).await
        } else {
            native.as_ref().unwrap().address
        };
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/conformance/authz-defer/guest-domains.json");
        let expected = if record {
            json!({})
        } else {
            serde_json::from_slice::<serde_json::Value>(&std::fs::read(&path)?)?["cases"].clone()
        };
        let mut observed = serde_json::Map::new();
        let mut mismatches = Vec::new();
        for &(family, method, uri) in [
            ("chat-read", "GET", "/api/chat/conversations"),
            ("chat-create", "POST", "/api/chat/channels"),
            ("meet-read", "GET", "/api/meet"),
            ("meet-create", "POST", "/api/meet"),
            ("drive-read", "GET", "/api/drive/versions/0/preview"),
        ]
        .iter()
        {
            for claimed in [false, true] {
                let token = fixture.token(claimed);
                let response = send(
                    address,
                    Request::builder()
                        .method(method)
                        .uri(uri)
                        .header("host", "mail.test")
                        .header("authorization", format!("Bearer {token}"))
                        .header("x-request-id", "authzdefer-oracle")
                        .body(full(if family == "chat-create" {
                            "{\"name\":\"authzdefer denied\",\"kind\":\"channel\"}"
                        } else if family == "meet-create" {
                            "{\"title\":\"authzdefer denied\"}"
                        } else {
                            "{}"
                        }))
                        .unwrap(),
                )
                .await;
                let value = observe(response).await;
                let key = format!("{family}-claimed-{claimed}");
                if !record && value != expected[&key] {
                    mismatches.push(format!("{key}: {value}; expected {}", expected[&key]));
                }
                observed.insert(key, value);
            }
        }
        if record {
            assert!(!path.exists());
            std::fs::write(
                path,
                serde_json::to_vec_pretty(
                    &json!({"go_source":std::env::var("GOFREE_GO_SOURCE")?,"cases":observed}),
                )?,
            )?;
        } else {
            assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
            assert_zero_proxy(address).await?;
        }
        Ok::<_, BoxError>(())
    })
    .catch_unwind()
    .await;
    for row in saved {
        let key: String = row.get(0);
        let enabled: bool = row.get(1);
        c.execute(
            "UPDATE feature_toggles SET enabled=$1 WHERE key=$2",
            &[&enabled, &key],
        )
        .await?;
    }
    fixture.cleanup(&c).await?;
    match result {
        Ok(value) => value,
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

fn member_token(user: i64, admin: bool, permissions: &[&str], domain: Option<i64>) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut claims = json!({"uid":user,"email":"authzdefer-actor@example.test","admin":admin,"perms":permissions,"typ":"access","iss":"mailserver","aud":["mailserver-gateway"],"iat":now-10,"exp":now+600});
    if let Some(domain) = domain {
        claims["domain"] = json!(domain);
    }
    setjoin_authz::legacy_jwt::sign_hs256(SECRET.as_bytes(), &claims.to_string())
}

async fn audit_rows(
    c: &tokio_postgres::Client,
    after: i64,
    actor: i64,
) -> Result<serde_json::Value, BoxError> {
    let rows=c.query("SELECT jsonb_build_object('user_id',user_id,'ip',host(ip),'action',action,'target_type',target_type,'target_id',target_id,'before_state',before_state,'after_state',after_state,'notes',notes)::text FROM admin_audit_log WHERE id>$1 ORDER BY id",&[&after]).await?;
    let mut out = vec![];
    for row in rows {
        let mut value: serde_json::Value = serde_json::from_str(row.get(0))?;
        if value["user_id"] == json!(actor) {
            value["user_id"] = json!("<actor>");
        }
        out.push(value);
    }
    Ok(json!(out))
}

#[tokio::test]
async fn full_spec_uses_live_grants_and_records_go_console_denials() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    use futures_util::FutureExt;
    use setjoin_conformance::fixture;
    let db = Db::for_case("authzdefer-full-spec").expect("assigned DB required");
    let c = db.connect().await?;
    let actor = fixture::account(&c, "authzdefer-audit").await?;
    let role:i64=c.query_one("INSERT INTO admin_role_groups(name,permissions) VALUES('authzdefer-'||gen_random_uuid()::text,ARRAY['system.config']) RETURNING id",&[]).await?.get(0);
    let first: i64 = c
        .query_one("SELECT coalesce(max(id),0) FROM admin_audit_log", &[])
        .await?
        .get(0);
    let result=std::panic::AssertUnwindSafe(async{
        let record=std::env::var_os("GOFREE_RECORD_GO_BINARY").is_some();
        let s3=common::fake_upstream(|_|async{hyper::Response::new(full(""))}).await;
        let go=common::go_oracle::start_named(&db,s3,None,"gofree-authzdefer-oracle").await?;
        let native=if record{None}else{Some(Process::start(&db).await?)};
        let address=if let Some(go)=&go{common::gateway(go.address,"",RouteTable::proxy_all()).await}else{native.as_ref().unwrap().address};
        let path=std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/conformance/authz-defer/full-spec.json");
        let expected=if record{json!({})}else{serde_json::from_slice::<serde_json::Value>(&std::fs::read(&path)?)?["cases"].clone()};
        let mut observed=serde_json::Map::new();let mut mismatches=Vec::new();
        for kind in ["no-grant","stale-signed-admin","signed-member","signed-scoped-member","live-admin"]{
            if kind=="live-admin"{c.execute("INSERT INTO admin_role_assignments(user_id,role_group_id,granted_by) VALUES($1,$2,$1)",&[&actor.user,&role]).await?;}
            let admin=matches!(kind,"stale-signed-admin"|"live-admin");
            let perms=if matches!(kind,"stale-signed-admin"|"signed-member"|"signed-scoped-member"){&["system.config"][..]}else{&[][..]};
            let token=member_token(actor.user,admin,perms,(kind=="signed-scoped-member").then_some(actor.domain));
            for format in ["yaml","json"]{
                let last:i64=c.query_one("SELECT coalesce(max(id),0) FROM admin_audit_log",&[]).await?.get(0);
                let response=send(address,Request::builder().uri(format!("/api/openapi.full.{format}"))
                    .header("host","mail.test").header("authorization",format!("Bearer {token}"))
                    .header("x-request-id","authzdefer-oracle").body(full("")).unwrap()).await;
                let mut value=observe(response).await;
                if value["status"]==200{
                    use sha2::{Digest,Sha256};
                    let hash=format!("{:x}",Sha256::digest(value["body"].as_str().unwrap().as_bytes()));
                    value.as_object_mut().unwrap().remove("body");value["body_sha256"]=json!(hash);
                }
                let value=json!({"response":value,"audit":audit_rows(&c,last,actor.user).await?});
                let key=format!("{kind}-{format}");
                if !record && value!=expected[&key]{mismatches.push(format!("{key}: {value}; expected {}",expected[&key]));}
                observed.insert(key,value);
            }
        }
        if record{assert!(!path.exists());std::fs::write(path,serde_json::to_vec_pretty(&json!({"go_source":std::env::var("GOFREE_GO_SOURCE")?,"cases":observed}))?)?;}
        else{assert!(mismatches.is_empty(),"{}",mismatches.join("\n"));assert_zero_proxy(address).await?;}
        Ok::<_,BoxError>(())
    }).catch_unwind().await;
    c.execute(
        "DELETE FROM admin_role_assignments WHERE user_id=$1 AND role_group_id=$2",
        &[&actor.user, &role],
    )
    .await?;
    c.execute("DELETE FROM admin_role_groups WHERE id=$1", &[&role])
        .await?;
    c.batch_execute(&format!("BEGIN;SET LOCAL session_replication_role=replica;DELETE FROM admin_audit_log WHERE id>{first} AND before_state->>'actor'='authzdefer-actor@example.test';COMMIT;")).await?;
    fixture::remove(&c, &actor).await?;
    match result {
        Ok(value) => value,
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

#[tokio::test]
async fn meet_entitlement_denials_write_go_app_blocked_audits() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    use futures_util::FutureExt;
    use setjoin_conformance::fixture;
    let db = Db::for_case("authzdefer-meet-denial").expect("assigned DB required");
    let c = db.connect().await?;
    let actor = fixture::account(&c, "authzdefer-meet").await?;
    let saved: bool = c
        .query_one(
            "SELECT enabled FROM feature_toggles WHERE key='feature.meet'",
            &[],
        )
        .await?
        .get(0);
    let level: String = c
        .query_one("SELECT level FROM audit_policy WHERE id=1", &[])
        .await?
        .get(0);
    c.execute(
        "UPDATE feature_toggles SET enabled=true WHERE key='feature.meet'",
        &[],
    )
    .await?;
    c.execute(
        "INSERT INTO user_app_entitlements(user_id,app,enabled) VALUES($1,'meet',false)",
        &[&actor.user],
    )
    .await?;
    let result=std::panic::AssertUnwindSafe(async{
        let record=std::env::var_os("GOFREE_RECORD_GO_BINARY").is_some();
        let s3=common::fake_upstream(|_|async{hyper::Response::new(full(""))}).await;
        let go=common::go_oracle::start_named(&db,s3,None,"gofree-authzdefer-oracle").await?;
        let native=if record{None}else{Some(Process::start(&db).await?)};
        let address=if let Some(go)=&go{common::gateway(go.address,"",RouteTable::proxy_all()).await}else{native.as_ref().unwrap().address};
        let path=std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/conformance/authz-defer/meet-denial.json");
        let expected=if record{json!({})}else{serde_json::from_slice::<serde_json::Value>(&std::fs::read(&path)?)?["cases"].clone()};
        let token=member_token(actor.user,false,&[],None);
        let mut observed=serde_json::Map::new();let mut mismatches=Vec::new();
        for policy in ["full","lean"]{
            c.execute("UPDATE audit_policy SET level=$1 WHERE id=1",&[&policy]).await?;
            for (name,method,uri) in [("list","GET","/api/meet"),("create","POST","/api/meet"),("get","GET","/api/meet/0")]{
                for repeat in 0..2{
                    let last:i64=c.query_one("SELECT coalesce(max(id),0) FROM admin_audit_log",&[]).await?.get(0);
                    let response=send(address,Request::builder().method(method).uri(uri).header("host","mail.test")
                        .header("authorization",format!("Bearer {token}")).header("x-request-id","authzdefer-oracle")
                        .body(full("{\"title\":\"must not create\"}")).unwrap()).await;
                    let value=json!({"response":observe(response).await,"audit":audit_rows(&c,last,actor.user).await?});
                    let key=format!("{policy}-{name}-{repeat}");
                    if !record&&value!=expected[&key]{mismatches.push(format!("{key}: {value}; expected {}",expected[&key]));}
                    observed.insert(key,value);
                }
            }
        }
        if record{assert!(!path.exists());std::fs::write(path,serde_json::to_vec_pretty(&json!({"go_source":std::env::var("GOFREE_GO_SOURCE")?,"cases":observed}))?)?;}
        else{assert!(mismatches.is_empty(),"{}",mismatches.join("\n"));assert_zero_proxy(address).await?;}
        Ok::<_,BoxError>(())
    }).catch_unwind().await;
    c.execute(
        "UPDATE feature_toggles SET enabled=$1 WHERE key='feature.meet'",
        &[&saved],
    )
    .await?;
    c.execute("UPDATE audit_policy SET level=$1 WHERE id=1", &[&level])
        .await?;
    c.batch_execute(&format!("BEGIN;SET LOCAL session_replication_role=replica;DELETE FROM admin_audit_log WHERE user_id={};COMMIT;",actor.user)).await?;
    fixture::remove(&c, &actor).await?;
    match result {
        Ok(value) => value,
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

#[tokio::test]
async fn invalid_jwt_spends_route_budget_after_the_guest_belt() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let db = Db::for_case("authzdefer-jwt-route-budget").expect("assigned DB required");
    let record = std::env::var_os("GOFREE_RECORD_GO_BINARY").is_some();
    let s3 = common::fake_upstream(|_| async { hyper::Response::new(full("")) }).await;
    let extra = vec![
        ("ADMIN_RATE_LIMIT", "1".into()),
        // The guest-belt membership check forwards (and spends no budget) when it overruns its
        // 1 s bound; a loaded host took 1 s per request here and all three came back 401. The
        // bound is the product's, so the test widens it rather than the product changing.
        ("SETJOIN_AUTHZ_PRECHECK_TIMEOUT_MS", "30000".into()),
    ];
    let go = common::go_oracle::start_named_with_env(&db, s3, "gofree-authzdefer-oracle", &extra)
        .await?;
    let native = if record {
        None
    } else {
        Some(Process::start_with(&db, &extra).await?)
    };
    let address = if let Some(go) = &go {
        common::gateway(go.address, "", RouteTable::proxy_all()).await
    } else {
        native.as_ref().unwrap().address
    };
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/conformance/authz-defer/jwt-route-budget.json");
    let token=setjoin_authz::legacy_jwt::sign_hs256(SECRET.as_bytes(),&json!({"uid":1,"typ":"access","iss":"mailserver","aud":["mailserver-gateway"],"iat":1,"exp":2}).to_string());
    // Three requests must share Go's epoch-minute bucket even on a busy host.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let remaining = 60 - now % 60;
    if remaining < 10 {
        tokio::time::sleep(Duration::from_secs(remaining + 1)).await;
    }
    let mut values = vec![];
    for _ in 0..3 {
        values.push(
            observe(
                send(
                    address,
                    Request::builder()
                        .uri("/api/admin/departments")
                        .header("host", "mail.test")
                        .header("authorization", format!("Bearer {token}"))
                        .header("x-request-id", "authzdefer-oracle")
                        .body(full(""))
                        .unwrap(),
                )
                .await,
            )
            .await,
        );
    }
    if record {
        assert!(!path.exists());
        std::fs::write(
            path,
            serde_json::to_vec_pretty(
                &json!({"go_source":std::env::var("GOFREE_GO_SOURCE")?,"responses":values}),
            )?,
        )?;
    } else {
        let expected: serde_json::Value = serde_json::from_slice(&std::fs::read(path)?)?;
        assert_eq!(json!(values), expected["responses"]);
        assert_zero_proxy(address).await?;
    }
    Ok(())
}

#[tokio::test]
async fn denylisted_sessions_match_go_across_families() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    use futures_util::FutureExt;
    use setjoin_conformance::fixture;
    let db = Db::for_case("authzdefer-denylist").expect("assigned DB required");
    let c = db.connect().await?;
    let actor = fixture::account(&c, "authzdefer-denylist").await?;
    c.execute("INSERT INTO session_revocations(user_id,scope,not_before,reason,expires_at) VALUES($1,'all',now(),'authzdefer oracle',now()+interval '1 hour')",&[&actor.user]).await?;
    let result = std::panic::AssertUnwindSafe(async {
        let record = std::env::var_os("GOFREE_RECORD_GO_BINARY").is_some();
        let s3 = common::fake_upstream(|_| async { hyper::Response::new(full("")) }).await;
        let go = common::go_oracle::start_named(&db, s3, None, "gofree-authzdefer-oracle").await?;
        let native = if record {
            None
        } else {
            Some(Process::start(&db).await?)
        };
        let address = if let Some(go) = &go {
            common::gateway(go.address, "", RouteTable::proxy_all()).await
        } else {
            native.as_ref().unwrap().address
        };
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/conformance/authz-defer/denylist.json");
        let expected = if record {
            json!({})
        } else {
            serde_json::from_slice::<serde_json::Value>(&std::fs::read(&path)?)?["cases"].clone()
        };
        let token = member_token(actor.user, false, &[], None);
        let mut observed = serde_json::Map::new();
        let mut mismatches = Vec::new();
        for (family, method, uri) in FAMILIES {
            let value = observe(
                send(
                    address,
                    Request::builder()
                        .method(*method)
                        .uri(*uri)
                        .header("host", "mail.test")
                        .header("authorization", format!("Bearer {token}"))
                        .header("x-request-id", "authzdefer-oracle")
                        .body(full("{}"))
                        .unwrap(),
                )
                .await,
            )
            .await;
            if !record && value != expected[*family] {
                mismatches.push(format!("{family}: {value}; expected {}", expected[*family]));
            }
            observed.insert((*family).into(), value);
        }
        if record {
            assert!(!path.exists());
            std::fs::write(
                path,
                serde_json::to_vec_pretty(
                    &json!({"go_source":std::env::var("GOFREE_GO_SOURCE")?,"cases":observed}),
                )?,
            )?;
        } else {
            assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
            assert_zero_proxy(address).await?;
        }
        Ok::<_, BoxError>(())
    })
    .catch_unwind()
    .await;
    c.execute(
        "DELETE FROM session_revocations WHERE user_id=$1",
        &[&actor.user],
    )
    .await?;
    fixture::remove(&c, &actor).await?;
    match result {
        Ok(value) => value,
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

fn check_corpus(
    name: &str,
    record: bool,
    cases: serde_json::Map<String, serde_json::Value>,
) -> Result<(), BoxError> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/conformance/authz-defer")
        .join(format!("{name}.json"));
    if record {
        assert!(
            !path.exists(),
            "immutable corpus already exists: {}",
            path.display()
        );
        std::fs::write(
            path,
            serde_json::to_vec_pretty(
                &json!({"go_source":std::env::var("GOFREE_GO_SOURCE")?,"cases":cases}),
            )?,
        )?;
    } else {
        let mut expected: serde_json::Value = serde_json::from_slice(&std::fs::read(&path)?)?;
        if name == "authority-error" {
            // Owner-approved security fix 2026-11-05 (#484): a failed authority lookup drops the
            // signed grants, so the frozen-Go baseline is replaced by a reviewed expectation.
            let doc = json!({"go_source":expected["go_source"],"cases":cases});
            expected = common::security_expected(path.parent().unwrap(), &path, &doc);
        }
        assert_eq!(json!(cases), expected["cases"]);
    }
    Ok(())
}

#[tokio::test]
async fn slow_guest_probe_answers_go_503_and_recovers() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    use futures_util::FutureExt;
    let db = Db::for_case("authzdefer-db-slow").expect("assigned DB required");
    let c = db.connect().await?;
    let record = std::env::var_os("GOFREE_RECORD_GO_BINARY").is_some();
    let s3 = common::fake_upstream(|_| async { hyper::Response::new(full("")) }).await;
    let extra = vec![
        (
            "DB_WORKER_DSN",
            format!("{}?options=-cstatement_timeout%3D1100", db.dsn),
        ),
        ("SETJOIN_AUTHZ_PRECHECK_TIMEOUT_MS", "1000".into()),
    ];
    let go = common::go_oracle::start_named_with_env(&db, s3, "gofree-authzdefer-oracle", &extra)
        .await?;
    let native = if record {
        None
    } else {
        Some(Process::start_with(&db, &extra).await?)
    };
    let address = if let Some(go) = &go {
        common::gateway(go.address, "", RouteTable::proxy_all()).await
    } else {
        native.as_ref().unwrap().address
    };
    let token = member_token(9000000000, false, &[], None);
    c.batch_execute("BEGIN;LOCK TABLE guest_accounts IN ACCESS EXCLUSIVE MODE")
        .await?;
    let result = std::panic::AssertUnwindSafe(async {
        let mut cases = serde_json::Map::new();
        for (family, method, uri) in FAMILIES {
            let started = std::time::Instant::now();
            let value = observe(
                send(
                    address,
                    Request::builder()
                        .method(*method)
                        .uri(*uri)
                        .header("host", "mail.test")
                        .header("authorization", format!("Bearer {token}"))
                        .header("x-request-id", "authzdefer-oracle")
                        .body(full("{}"))
                        .unwrap(),
                )
                .await,
            )
            .await;
            assert!(
                started.elapsed() < Duration::from_secs(5),
                "unbounded guest probe"
            );
            cases.insert((*family).into(), value);
        }
        Ok::<_, BoxError>(cases)
    })
    .catch_unwind()
    .await;
    c.batch_execute("ROLLBACK").await?;
    let mut cases = match result {
        Ok(value) => value?,
        Err(panic) => std::panic::resume_unwind(panic),
    };
    // The guest-mismatch outcome proves the same process can query after cancellation.
    let token = GuestFixture {
        user: 9000000000,
        domain: 0,
    }
    .token(true);
    cases.insert(
        "recovered".into(),
        observe(
            send(
                address,
                Request::builder()
                    .uri("/api/settings/imap")
                    .header("host", "mail.test")
                    .header("authorization", format!("Bearer {token}"))
                    .header("x-request-id", "authzdefer-oracle")
                    .body(full(""))
                    .unwrap(),
            )
            .await,
        )
        .await,
    );
    check_corpus("db-slow", record, cases)?;
    if !record {
        assert_zero_proxy(address).await?;
    }
    Ok(())
}

struct SecretFile(std::path::PathBuf);
impl SecretFile {
    fn sm2() -> Result<Self, BoxError> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let path = std::env::temp_dir().join(format!(
            "gofree-authzdefer-sm2-{}-{}.pem",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos()
        ));
        if let Ok(ledger) = std::env::var("GOFREE_RESOURCE_LEDGER") {
            writeln!(
                std::fs::OpenOptions::new().append(true).open(ledger)?,
                "Plan owned fixture SM2 PEM {} (delete on drop)",
                path.display()
            )?;
        }
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/conformance/identity-login/keys.json"
        ))?;
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&path)?;
        file.write_all(fixture["sm2_pem"].as_str().unwrap().as_bytes())?;
        Ok(Self(path))
    }
}
impl Drop for SecretFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[tokio::test]
async fn hs256_and_sm2_profiles_match_go_across_families() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    use futures_util::FutureExt;
    use setjoin_conformance::fixture;
    let db = Db::for_case("authzdefer-profiles").expect("assigned DB required");
    let c = db.connect().await?;
    let actor = fixture::account(&c, "authzdefer-profiles").await?;
    let result=std::panic::AssertUnwindSafe(async{
        let record=std::env::var_os("GOFREE_RECORD_GO_BINARY").is_some();
        let key=SecretFile::sm2()?;let pem=std::fs::read_to_string(&key.0)?;
        let mut cases=serde_json::Map::new();
        for profile in ["standard","hybrid","smx"]{
            let s3=common::fake_upstream(|_|async{hyper::Response::new(full(""))}).await;
            let go_extra=vec![("CRYPTO_ALGORITHM_PROFILE",profile.into()),("SM2_PRIVATE_KEY_FILE","/run/authzdefer-sm2.pem".into()),
                ("--volume",format!("{}:/run/authzdefer-sm2.pem:ro",key.0.display()))];
            let go=common::go_oracle::start_named_with_env(&db,s3,"gofree-authzdefer-oracle",&go_extra).await?;
            let native_extra=vec![("CRYPTO_ALGORITHM_PROFILE",profile.into()),("SM2_PRIVATE_KEY_FILE",key.0.to_string_lossy().into_owned())];
            let native=if record{None}else{Some(Process::start_with(&db,&native_extra).await?)};
            let address=if let Some(go)=&go{common::gateway(go.address,"",RouteTable::proxy_all()).await}else{native.as_ref().unwrap().address};
            for alg in ["hs256","sm2"]{
                let now=std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();
                let mut claims=json!({"uid":9000000000i64,"acct":"guest","typ":"access","iss":"mailserver","aud":["mailserver-gateway"],"iat":now-10,"exp":now+600});
                let sign=|claims:&serde_json::Value|->Result<String,BoxError>{Ok(if alg=="hs256"{setjoin_authz::legacy_jwt::sign_hs256(SECRET.as_bytes(),&claims.to_string())}else{setjoin_authz::legacy_jwt::sign_sm2(&pem,&claims.to_string())?})};
                let token=sign(&claims)?;
                for (family,method,uri) in FAMILIES{
                    cases.insert(format!("{profile}-{alg}-{family}"),observe(send(address,Request::builder().method(*method).uri(*uri)
                        .header("host","mail.test").header("authorization",format!("Bearer {token}"))
                        .header("x-request-id","authzdefer-oracle").body(full("{}")).unwrap()).await).await);
                }
                claims["uid"]=json!(actor.user);claims.as_object_mut().unwrap().remove("acct");
                let token=sign(&claims)?;
                cases.insert(format!("{profile}-{alg}-member"),observe(send(address,Request::builder().uri("/api/settings/imap")
                    .header("host","mail.test").header("authorization",format!("Bearer {token}"))
                    .header("x-request-id","authzdefer-oracle").body(full("")).unwrap()).await).await);
            }
            if !record{assert_zero_proxy(address).await?;}
        }
        check_corpus("profiles",record,cases)
    }).catch_unwind().await;
    fixture::remove(&c, &actor).await?;
    match result {
        Ok(value) => value,
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

#[tokio::test]
async fn jwks_down_matches_go_without_an_upstream() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use p256::ecdsa::{signature::Signer, Signature, SigningKey};
    let db = Db::for_case("authzdefer-jwks-down").expect("assigned DB required");
    let record = std::env::var_os("GOFREE_RECORD_GO_BINARY").is_some();
    let extra = vec![(
        "AUTHSERVER_JWKS_URL",
        "http://127.0.0.1:1/.well-known/jwks.json".into(),
    )];
    let s3 = common::fake_upstream(|_| async { hyper::Response::new(full("")) }).await;
    let go = common::go_oracle::start_named_with_env(&db, s3, "gofree-authzdefer-oracle", &extra)
        .await?;
    let native = if record {
        None
    } else {
        Some(Process::start_with(&db, &extra).await?)
    };
    let address = if let Some(go) = &go {
        common::gateway(go.address, "", RouteTable::proxy_all()).await
    } else {
        native.as_ref().unwrap().address
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let claims = json!({"uid":1,"typ":"access","iss":"mailserver","aud":["mailserver-gateway"],"iat":now-10,"exp":now+600});
    let unsigned = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(r#"{"alg":"ES256","kid":"unavailable-key","typ":"JWT"}"#),
        URL_SAFE_NO_PAD.encode(claims.to_string())
    );
    let signature: Signature = SigningKey::from_slice(&[0x11; 32])?.sign(unsigned.as_bytes());
    let token = format!(
        "{unsigned}.{}",
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    );
    let mut cases = serde_json::Map::new();
    for (family, method, uri) in FAMILIES {
        cases.insert(
            (*family).into(),
            observe(
                send(
                    address,
                    Request::builder()
                        .method(*method)
                        .uri(*uri)
                        .header("host", "mail.test")
                        .header("authorization", format!("Bearer {token}"))
                        .header("x-request-id", "authzdefer-oracle")
                        .body(full("{}"))
                        .unwrap(),
                )
                .await,
            )
            .await,
        );
    }
    check_corpus("jwks-down", record, cases)?;
    if !record {
        assert_zero_proxy(address).await?;
    }
    Ok(())
}

#[tokio::test]
async fn absent_registry_refuses_startup_as_go_does() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    use futures_util::FutureExt;
    let db = Db::for_case("authzdefer-registry-absent").expect("assigned DB required");
    let c = db.connect().await?;
    let saved: String = c
        .query_one(
            "SELECT row_to_json(s)::text FROM feature_toggle_registry_state s WHERE singleton",
            &[],
        )
        .await?
        .get(0);
    c.execute(
        "DELETE FROM feature_toggle_registry_state WHERE singleton",
        &[],
    )
    .await?;
    let result = std::panic::AssertUnwindSafe(async {
        let record = std::env::var_os("GOFREE_RECORD_GO_BINARY").is_some();
        let message = if record {
            let s3 = common::fake_upstream(|_| async { hyper::Response::new(full("")) }).await;
            let started =
                common::go_oracle::start_named(&db, s3, None, "gofree-authzdefer-oracle").await;
            let error = match started {
                Err(e) => e.to_string(),
                Ok(_) => panic!("Go served without the registry"),
            };
            std::fs::read_to_string(
                error
                    .split("see ")
                    .nth(1)
                    .ok_or("missing oracle error log")?,
            )?
        } else {
            match Process::start(&db).await {
                Err(e) => e.to_string(),
                Ok(_) => panic!("native gateway served without the registry"),
            }
        };
        assert!(
            message.contains("registry"),
            "unexpected startup error: {message}"
        );
        let mut cases = serde_json::Map::new();
        cases.insert(
            "startup".into(),
            json!({"listening":false,"reason":"registry unavailable"}),
        );
        check_corpus("registry-absent", record, cases)
    })
    .catch_unwind()
    .await;
    c.execute("INSERT INTO feature_toggle_registry_state SELECT * FROM json_populate_record(NULL::feature_toggle_registry_state,$1::text::json)",&[&saved]).await?;
    match result {
        Ok(value) => value,
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

#[tokio::test]
async fn cold_denylist_with_cae_matches_go() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    use futures_util::FutureExt;
    use setjoin_conformance::fixture;
    let db = Db::for_case("authzdefer-cold-denylist").expect("assigned DB required");
    let c = db.connect().await?;
    let actor = fixture::account(&c, "authzdefer-cold").await?;
    let saved: bool = c
        .query_one(
            "SELECT enabled FROM feature_toggles WHERE key='feature.cae_runtime'",
            &[],
        )
        .await?
        .get(0);
    assert!(c
        .query_one(
            "SELECT has_table_privilege('setjoin_app','session_revocations','SELECT')",
            &[]
        )
        .await?
        .get::<_, bool>(0));
    c.batch_execute("REVOKE SELECT ON session_revocations FROM setjoin_app")
        .await?;
    c.execute(
        "UPDATE feature_toggles SET enabled=true WHERE key='feature.cae_runtime'",
        &[],
    )
    .await?;
    let result = std::panic::AssertUnwindSafe(async {
        let record = std::env::var_os("GOFREE_RECORD_GO_BINARY").is_some();
        let extra = vec![
            ("DB_WORKER_DSN", db.app.clone().ok_or("app DSN required")?),
            ("RUST_WORKERS_ON", "session-denylist-refresh".into()),
        ];
        let s3 = common::fake_upstream(|_| async { hyper::Response::new(full("")) }).await;
        let go =
            common::go_oracle::start_named_with_env(&db, s3, "gofree-authzdefer-oracle", &extra)
                .await?;
        let native = if record {
            None
        } else {
            Some(Process::start_with(&db, &extra).await?)
        };
        let address = if let Some(go) = &go {
            common::gateway(go.address, "", RouteTable::proxy_all()).await
        } else {
            native.as_ref().unwrap().address
        };
        let token = member_token(actor.user, false, &[], None);
        let mut cases = serde_json::Map::new();
        for (family, method, uri) in FAMILIES {
            cases.insert(
                (*family).into(),
                observe(
                    send(
                        address,
                        Request::builder()
                            .method(*method)
                            .uri(*uri)
                            .header("host", "mail.test")
                            .header("authorization", format!("Bearer {token}"))
                            .header("x-request-id", "authzdefer-oracle")
                            .body(full("{}"))
                            .unwrap(),
                    )
                    .await,
                )
                .await,
            );
        }
        check_corpus("denylist-cold", record, cases)?;
        if !record {
            assert_zero_proxy(address).await?;
        }
        Ok::<_, BoxError>(())
    })
    .catch_unwind()
    .await;
    c.batch_execute("GRANT SELECT ON session_revocations TO setjoin_app")
        .await?;
    c.execute(
        "UPDATE feature_toggles SET enabled=$1 WHERE key='feature.cae_runtime'",
        &[&saved],
    )
    .await?;
    fixture::remove(&c, &actor).await?;
    match result {
        Ok(value) => value,
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

#[tokio::test]
async fn csrf_ordering_and_origin_shapes_match_go() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    use futures_util::FutureExt;
    use setjoin_conformance::fixture;
    let db = Db::for_case("authzdefer-csrf-matrix").expect("assigned DB required");
    let c = db.connect().await?;
    let actor = fixture::account(&c, "authzdefer-csrf").await?;
    let result=std::panic::AssertUnwindSafe(async{
        let record=std::env::var_os("GOFREE_RECORD_GO_BINARY").is_some();
        let s3=common::fake_upstream(|_|async{hyper::Response::new(full(""))}).await;
        let go=common::go_oracle::start_named(&db,s3,None,"gofree-authzdefer-oracle").await?;
        let native=if record{None}else{Some(Process::start(&db).await?)};
        let address=if let Some(go)=&go{common::gateway(go.address,"",RouteTable::proxy_all()).await}else{native.as_ref().unwrap().address};
        let expired=setjoin_authz::legacy_jwt::sign_hs256(SECRET.as_bytes(),&json!({"uid":1,"typ":"access","iss":"mailserver","aud":["mailserver-gateway"],"iat":1,"exp":2}).to_string());
        let mut cases=serde_json::Map::new();
        for (family,_,uri) in FAMILIES{
            cases.insert(format!("{family}-cross-origin"),observe(send(address,Request::builder().method("POST").uri(*uri)
                .header("host","mail.test").header("origin","http://foreign.test")
                .header("authorization",format!("Bearer {expired}"))
                .header("x-request-id","authzdefer-oracle").body(full("{}")).unwrap()).await).await);
        }
        for (name,host,headers) in [
            ("userinfo","mail.test",vec![("origin","http://reader:secret@mail.test")]),
            ("referer-userinfo","mail.test",vec![("referer","http://reader@mail.test/path?q=1")]),
            ("referer-cross-site","mail.test",vec![("referer","http://mail.test/path"),("sec-fetch-site","cross-site")]),
            ("origin-wins","mail.test",vec![("origin","http://mail.test"),("sec-fetch-site","cross-site")]),
            ("opaque","mail.test",vec![("origin","null")]),
            ("ipv6-mixed-port","[::1]",vec![("origin","http://[::1]:80")]),
            ("invalid-port","mail.test",vec![("origin","http://mail.test:bad")]),
        ]{
            let mut req=Request::builder().method("POST").uri("/jmap").header("host",host)
                .header("authorization",format!("Bearer {expired}")).header("x-request-id","authzdefer-oracle");
            for (key,value) in headers{req=req.header(key,value);}
            cases.insert(name.into(),observe(send(address,req.body(full("{}")).unwrap()).await).await);
        }
        let token=member_token(actor.user,false,&[],None);
        cases.insert("safe-get-cross-origin".into(),observe(send(address,Request::builder().uri("/api/settings/imap")
            .header("host","mail.test").header("origin","http://foreign.test")
            .header("authorization",format!("Bearer {token}"))
            .header("x-request-id","authzdefer-oracle").body(full("")).unwrap()).await).await);
        check_corpus("csrf",record,cases)?;
        if !record{assert_zero_proxy(address).await?;}
        Ok::<_,BoxError>(())
    }).catch_unwind().await;
    fixture::remove(&c, &actor).await?;
    match result {
        Ok(value) => value,
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

#[tokio::test]
async fn authority_read_failure_preserves_go_signed_permission_behavior() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    use futures_util::FutureExt;
    use setjoin_conformance::fixture;
    let db = Db::for_case("authzdefer-authority-error").expect("assigned DB required");
    let c = db.connect().await?;
    let actor = fixture::account(&c, "authzdefer-authority-error").await?;
    assert!(c
        .query_one(
            "SELECT has_table_privilege('setjoin_app','admin_role_assignments','SELECT')",
            &[]
        )
        .await?
        .get::<_, bool>(0));
    let first: i64 = c
        .query_one("SELECT coalesce(max(id),0) FROM admin_audit_log", &[])
        .await?
        .get(0);
    let result = std::panic::AssertUnwindSafe(async {
        let record = std::env::var_os("GOFREE_RECORD_GO_BINARY").is_some();
        let s3 = common::fake_upstream(|_| async { hyper::Response::new(full("")) }).await;
        let go = common::go_oracle::start_named(&db, s3, None, "gofree-authzdefer-oracle").await?;
        let native = if record {
            None
        } else {
            Some(Process::start(&db).await?)
        };
        let address = if let Some(go) = &go {
            common::gateway(go.address, "", RouteTable::proxy_all()).await
        } else {
            native.as_ref().unwrap().address
        };
        c.batch_execute("REVOKE SELECT ON admin_role_assignments FROM setjoin_app")
            .await?;
        let mut cases = serde_json::Map::new();
        for (name, perms) in [
            ("signed-grant", vec!["system.config"]),
            ("no-signed-grant", vec![]),
        ] {
            let last: i64 = c
                .query_one("SELECT coalesce(max(id),0) FROM admin_audit_log", &[])
                .await?
                .get(0);
            let token = member_token(actor.user, true, &perms, None);
            let mut response = observe(
                send(
                    address,
                    Request::builder()
                        .uri("/api/openapi.full.json")
                        .header("host", "mail.test")
                        .header("authorization", format!("Bearer {token}"))
                        .header("x-request-id", "authzdefer-oracle")
                        .body(full(""))
                        .unwrap(),
                )
                .await,
            )
            .await;
            if response["status"] == 200 {
                use sha2::{Digest, Sha256};
                let hash = format!(
                    "{:x}",
                    Sha256::digest(response["body"].as_str().unwrap().as_bytes())
                );
                response.as_object_mut().unwrap().remove("body");
                response["body_sha256"] = json!(hash);
            }
            cases.insert(
                name.into(),
                json!({"response":response,"audit":audit_rows(&c,last,actor.user).await?}),
            );
        }
        check_corpus("authority-error", record, cases)?;
        if !record {
            assert_zero_proxy(address).await?;
        }
        Ok::<_, BoxError>(())
    })
    .catch_unwind()
    .await;
    c.batch_execute("GRANT SELECT ON admin_role_assignments TO setjoin_app")
        .await?;
    c.batch_execute(&format!("BEGIN;SET LOCAL session_replication_role=replica;DELETE FROM admin_audit_log WHERE id>{first} AND before_state->>'actor'='authzdefer-actor@example.test';COMMIT;")).await?;
    fixture::remove(&c, &actor).await?;
    match result {
        Ok(value) => value,
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

#[tokio::test]
async fn smx_requires_an_sm2_key_at_startup_as_go_does() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let db = Db::for_case("authzdefer-smx-key-absent").expect("assigned DB required");
    let record = std::env::var_os("GOFREE_RECORD_GO_BINARY").is_some();
    let extra = vec![("CRYPTO_ALGORITHM_PROFILE", "smx".into())];
    let message = if record {
        let s3 = common::fake_upstream(|_| async { hyper::Response::new(full("")) }).await;
        let started =
            common::go_oracle::start_named_with_env(&db, s3, "gofree-authzdefer-oracle", &extra)
                .await;
        let error = match started {
            Err(e) => e.to_string(),
            Ok(_) => panic!("Go served smx without an SM2 key"),
        };
        std::fs::read_to_string(
            error
                .split("see ")
                .nth(1)
                .ok_or("missing oracle error log")?,
        )?
    } else {
        match Process::start_with(&db, &extra).await {
            Err(e) => e.to_string(),
            Ok(_) => panic!("native gateway served smx without an SM2 key"),
        }
    };
    assert!(
        message.to_ascii_lowercase().contains("sm2"),
        "unexpected startup failure: {message}"
    );
    let mut cases = serde_json::Map::new();
    cases.insert(
        "startup".into(),
        json!({"listening":false,"reason":"SM2 key required"}),
    );
    check_corpus("smx-key-absent", record, cases)
}

#[tokio::test]
async fn guest_belt_matches_go_across_auth_spa_and_redirect_boundaries() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    use futures_util::FutureExt;
    let db = Db::for_case("authzdefer-dispatch-belt").expect("assigned DB required");
    let c = db.connect().await?;
    let first_health: i64 = c
        .query_one("SELECT coalesce(max(id),0) FROM health_history", &[])
        .await?
        .get(0);
    let guest = GuestFixture::seed(&c).await?;
    let saved: bool = c
        .query_one(
            "SELECT enabled FROM feature_toggles WHERE key='feature.guest_accounts'",
            &[],
        )
        .await?
        .get(0);
    let result = std::panic::AssertUnwindSafe(async {
        let record = std::env::var_os("GOFREE_RECORD_GO_BINARY").is_some();
        let mut cases = serde_json::Map::new();
        for enabled in [false, true] {
            c.execute("UPDATE feature_toggles SET enabled=$1 WHERE key='feature.guest_accounts'", &[&enabled]).await?;
            let s3 = common::fake_upstream(|_| async {hyper::Response::new(full(""))}).await;
            let go = common::go_oracle::start_named(&db, s3, None, "gofree-authzdefer-oracle").await?;
            let native = if record {None} else {Some(Process::start(&db).await?)};
            let address = if let Some(go) = &go {oracle_gateway(go.address).await?} else {native.as_ref().unwrap().address};
            let expired = setjoin_authz::legacy_jwt::sign_hs256(SECRET.as_bytes(), &json!({"uid":1,"typ":"access","iss":"mailserver","aud":["mailserver-gateway"],"iat":1,"exp":2}).to_string());
            for (name, method, uri, token) in [
                ("api-expired", "GET", "/api/not-a-real-route", expired.clone()),
                ("alias-expired", "POST", "/drive/spaces", expired.clone()),
                ("chat-unknown-expired", "GET", "/api/chat/missing_route", expired.clone()),
                ("api-method-expired", "PUT", "/api/admin/departments", expired.clone()),
                ("auth-inactive", "GET", "/auth/me", GuestFixture{user:9000000000,domain:0}.token(true)),
                ("auth-unlisted-guest", "GET", "/auth/me/org-chart", guest.token(true)),
                ("auth-unlisted-member-claim", "GET", "/auth/me/org-chart", guest.token(false)),
                ("unknown-api", "GET", "/api/not-a-real-route", guest.token(true)),
                ("spa-inactive", "GET", "/unregistered-spa-path", GuestFixture{user:9000000000,domain:0}.token(true)),
                ("bare-get-inactive", "GET", "/drive/spaces", GuestFixture{user:9000000000,domain:0}.token(true)),
                ("canonical-inactive", "GET", "/api/admin//departments", GuestFixture{user:9000000000,domain:0}.token(true)),
                ("bare-post", "POST", "/drive/spaces", guest.token(true)),
            ] {
                cases.insert(format!("{enabled}-{name}"), observe(send(address, Request::builder().method(method).uri(uri)
                    .header("host", "mail.test").header("authorization", format!("Bearer {token}"))
                    .header("x-request-id", "authzdefer-oracle").body(full("{}")).unwrap()).await).await);
            }
            for (state, status, expired) in [("disabled", "disabled", false), ("expired", "active", true)] {
                c.execute("UPDATE guest_accounts SET status=$2,expires_at=CASE WHEN $3 THEN now()-interval '1 hour' ELSE NULL END WHERE user_id=$1", &[&guest.user, &status, &expired]).await?;
                for claimed in [false,true] {
                    let token=guest.token(claimed);
                    cases.insert(format!("{enabled}-{state}-{claimed}"), observe(send(address, Request::builder().uri("/auth/me")
                        .header("host","mail.test").header("authorization",format!("Bearer {token}"))
                        .header("x-request-id","authzdefer-oracle").body(full("")).unwrap()).await).await);
                }
            }
            c.execute("UPDATE guest_accounts SET status='active',expires_at=NULL WHERE user_id=$1", &[&guest.user]).await?;
            if !record {assert_zero_proxy(address).await?;}
        }
        check_corpus("guest-dispatch", record, cases)
    }).catch_unwind().await;
    c.execute(
        "UPDATE feature_toggles SET enabled=$1 WHERE key='feature.guest_accounts'",
        &[&saved],
    )
    .await?;
    c.execute(
        "DELETE FROM health_history WHERE id>$1 AND check_name='minio_connectivity'",
        &[&first_health],
    )
    .await?;
    guest.cleanup(&c).await?;
    match result {
        Ok(value) => value,
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

async fn oracle_gateway(upstream: std::net::SocketAddr) -> Result<std::net::SocketAddr, BoxError> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let uri: hyper::Uri = format!("http://{upstream}").parse()?;
    let gateway = Gateway::new(
        Config {
            upstream: Some(uri.clone()),
            upstream_header_timeout: Duration::from_secs(10),
            trusted_proxies: TrustedProxies::parse("")?,
            edge_limit: None,
        },
        RouteTable::proxy_all(),
    )?
    .with_auth_upstream(uri.clone())?
    .with_rust_auth_upstream(uri)?;
    tokio::spawn(gateway.serve(listener));
    Ok(address)
}
