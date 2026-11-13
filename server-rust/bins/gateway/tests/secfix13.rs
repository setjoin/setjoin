//! Owner-approved security fixes of 2026-11-05 for the self-service routes (#547 items 5-8):
//! no inherited private-network allowlist, no plaintext IMAP, capped JSON bodies, and DNS
//! resolution at webhook registration. Each test states the secure behaviour at the real front
//! door; the mutants (feature `oracle-mutants`, `SETJOIN_SECFIX3_MUTANT`,
//! scripts/test-secfix13-mutants.py) restore frozen Go's behaviour and must make them fail.
mod common;
#[allow(dead_code)]
#[path = "common/fake_imap.rs"]
mod fake_imap;
use common::BoxError;
use hyper::Request;
use serde_json::{json, Value};
use setjoin_conformance::{fixture, harness::Db};
use setjoin_gateway::identity_self_service::{HostResolver, IdentitySelfServiceRoute};
use setjoin_gateway::{BoxFuture, Config, Gateway, RouteTable, TrustedProxies};
use std::sync::Arc;

struct World {
    owner: tokio_postgres::Client,
    dsn: String,
    app_dsn: String,
    a: fixture::Account,
    saved_defaults: Option<(String, bool)>,
}
async fn world(case: &str) -> Result<Option<World>, BoxError> {
    let Some(db) = Db::for_case(case) else { return Ok(None) };
    let owner = db.connect().await?;
    cleanup_leftovers(&owner).await?;
    let a = fixture::account(&owner, "secfix13-a").await?;
    let saved_defaults = owner
        .query_opt("SELECT value::text,encrypted FROM system_config WHERE key='imap.defaults'", &[])
        .await?
        .map(|r| (r.get::<_, String>(0), r.get::<_, bool>(1)));
    // A failed run (a restored-bug mutant) skips `finish`: what it left is not the original.
    let saved_defaults = match saved_defaults {
        Some((text, _)) if text.contains("secfix13.test") => {
            owner.execute("DELETE FROM system_config WHERE key='imap.defaults'", &[]).await?;
            None
        }
        other => other,
    };
    Ok(Some(World { owner, app_dsn: db.app.clone().unwrap_or_else(|| db.dsn.clone()), dsn: db.dsn.clone(), a, saved_defaults }))
}
async fn cleanup_leftovers(owner: &tokio_postgres::Client) -> Result<(), BoxError> {
    for row in owner
        .query("SELECT u.id,u.domain_id,m.id FROM users u JOIN mailboxes m ON m.user_id=u.id AND m.is_primary WHERE u.username LIKE 'secfix13-a@oracle-%'", &[])
        .await?
    {
        let a = fixture::Account { user: row.get(0), domain: row.get(1), mailbox: row.get(2), inbox: 0, label: 0, two_labels: 0, inbox_only: 0 };
        wipe(owner, a.user).await?;
        fixture::remove(owner, &a).await?;
    }
    Ok(())
}
async fn wipe(owner: &tokio_postgres::Client, user: i64) -> Result<(), BoxError> {
    for sql in [
        "DELETE FROM webhook_subscriptions WHERE user_id=$1",
        "DELETE FROM app_passwords WHERE user_id=$1",
        "DELETE FROM migration_jobs WHERE user_id=$1",
    ] {
        owner.execute(sql, &[&user]).await?;
    }
    Ok(())
}
impl World {
    async fn finish(self) -> Result<(), BoxError> {
        wipe(&self.owner, self.a.user).await?;
        match &self.saved_defaults {
            Some((value, enc)) => {
                self.owner
                    .execute("INSERT INTO system_config(key,value,encrypted) VALUES('imap.defaults',$1::text::jsonb,$2) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value,encrypted=EXCLUDED.encrypted", &[value, enc])
                    .await?
            }
            None => self.owner.execute("DELETE FROM system_config WHERE key='imap.defaults'", &[]).await?,
        };
        fixture::remove(&self.owner, &self.a).await?;
        Ok(())
    }
    fn exec(&self) -> Result<setjoin_pg::ScopedExecutor, BoxError> {
        Ok(common::patient_exec(&self.app_dsn, 4)?.with_audit_keys("22".repeat(32), String::new()))
    }
    /// The real front door with only the self-service route mounted.
    async fn serve(
        &self,
        runner: Option<setjoin_gateway::migration::Runner>,
        resolver: Arc<dyn HostResolver>,
    ) -> Result<(std::net::SocketAddr, tokio::task::JoinHandle<()>), BoxError> {
        let route = IdentitySelfServiceRoute {
            exec: self.exec()?,
            worker: common::patient_exec(&self.dsn, 4)?,
            keys: Arc::new(common::recovery_keys()),
            issuer: "mailserver".into(),
            webhook_codec: setjoin_platform::webhook_secret::SecretCodec::new(
                b"blobs1-test-jwt-secret-for-recording",
                setjoin_config_secret::CryptoProfile::parse(""),
            ),
            migration_runner: runner,
            webhook_resolver: resolver,
        };
        let mut inventory: Value = serde_json::from_str(include_str!("../route-inventory.json"))?;
        for r in inventory["routes"].as_array_mut().ok_or("routes")? {
            let mailserver = r["sources"].as_array().is_some_and(|xs| xs.iter().any(|x| x.as_str().is_some_and(|s| s.starts_with("mailserver/"))));
            if mailserver && r["path"].as_str().unwrap_or("").starts_with("/auth/me/") {
                r["state"] = json!("ON");
                r["upstream"] = json!("local-rust");
                r["oracle_commands"] = json!([""]);
            }
        }
        let gateway = Gateway::new(
            Config {
                upstream: None,
                trusted_proxies: TrustedProxies::parse("")?,
                upstream_header_timeout: setjoin_gateway::proxy::DEFAULT_HEADER_TIMEOUT,
                edge_limit: None,
            },
            RouteTable::proxy_all().with(route),
        )?
        .with_inventory(&inventory.to_string())?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        Ok((address, tokio::spawn(gateway.serve(listener))))
    }
    async fn call(&self, addr: std::net::SocketAddr, method: &str, path: &str, body: String) -> Result<(u16, String), BoxError> {
        let token = common::recovery_token(self.a.user);
        let response = common::send(
            addr,
            Request::builder()
                .method(method)
                .uri(path)
                .header("host", "mail.test")
                .header("origin", "http://mail.test")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {token}"))
                .body(common::full(body))?,
        )
        .await;
        let status = response.status().as_u16();
        Ok((status, String::from_utf8(common::body_bytes(response).await.to_vec())?))
    }
}

/// Resolves a fixed table; an unknown name does not resolve.
struct Table(Vec<(&'static str, Vec<&'static str>)>);
impl HostResolver for Table {
    fn resolve(&self, host: String) -> BoxFuture<Option<Vec<std::net::IpAddr>>> {
        let found = self.0.iter().find(|(name, _)| *name == host).map(|(_, ips)| ips.iter().map(|ip| ip.parse().unwrap()).collect());
        Box::pin(async move { found })
    }
}

fn padded(prefix: &str, to: usize) -> String {
    // A valid JSON object whose last member is `pad`, `to` bytes long in all.
    let used = prefix.len() + 9;
    format!("{prefix}\"pad\":\"{}\"}}", "a".repeat(to.saturating_sub(used)))
}

/// #547 item 8: a webhook URL whose NAME resolves to a non-public address is refused at
/// registration (frozen Go checked literal IPs only; delivery-time PublicOnly stays).
/// The cases share one database, fixed fixtures and reducers: libtest's threads must take turns.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[tokio::test]
async fn webhook_registration_resolves_the_host_and_refuses_non_public_answers() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(w) = world("secfix13-webhook-dns").await? else { return Ok(()) };
    let result = async {
        let resolver = Arc::new(Table(vec![
            ("public.hooks.test", vec!["93.184.216.34"]),
            ("internal.hooks.test", vec!["10.0.0.5"]),
            ("loopback.hooks.test", vec!["127.0.0.1"]),
            ("metadata.hooks.test", vec!["169.254.169.254"]),
            ("mapped.hooks.test", vec!["::ffff:10.0.0.5"]),
            ("mixed.hooks.test", vec!["93.184.216.34", "10.0.0.5"]),
        ]));
        let (addr, server) = w.serve(None, resolver).await?;
        let register = |url: &str| json!({"url": url, "eventTypes": ["mail.received"]}).to_string();
        for url in [
            "https://internal.hooks.test/x",
            "https://loopback.hooks.test/x",
            "https://metadata.hooks.test/x",
            "https://mapped.hooks.test/x",
            "https://mixed.hooks.test/x",
            "https://unresolvable.hooks.test/x",
            "http://127.0.0.1/x",
        ] {
            let (status, text) = w.call(addr, "POST", "/auth/me/webhooks", register(url)).await?;
            assert_eq!(status, 400, "{url} must be refused at registration: {text}");
        }
        let stored: i64 = w.owner.query_one("SELECT count(*) FROM webhook_subscriptions WHERE user_id=$1", &[&w.a.user]).await?.get(0);
        assert_eq!(stored, 0, "a refused registration stores nothing");
        for url in ["https://public.hooks.test/x", "http://93.184.216.34/x"] {
            let (status, text) = w.call(addr, "POST", "/auth/me/webhooks", register(url)).await?;
            assert_eq!(status, 201, "control: {url} is public: {text}");
        }
        server.abort();
        Ok::<_, BoxError>(())
    }
    .await;
    w.finish().await?;
    result
}

/// #547 item 7: test-imap, migration start, webhook, app-password and read-receipt bodies are
/// capped at 1 MiB (Go decoded without a cap).
#[tokio::test]
async fn self_service_json_bodies_are_capped_at_one_mebibyte() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(w) = world("secfix13-body-cap").await? else { return Ok(()) };
    let result = async {
        let (addr, server) = w.serve(None, Arc::new(Table(vec![("public.hooks.test", vec!["93.184.216.34"])]))).await?;
        let big = 1 << 20;
        let cases: [(&str, &str, &str); 5] = [
            ("POST", "/auth/me/webhooks", r#"{"url":"https://public.hooks.test/x","eventTypes":["mail.received"],"#),
            ("POST", "/auth/me/app-passwords", r#"{"name":"cap","#),
            ("POST", "/auth/me/read-receipt", r#"{"messageId":"1","consent":true,"#),
            ("POST", "/auth/me/migration/test-imap", r#"{"host":"imap.example.net","port":993,"tls_mode":"tls","#),
            ("POST", "/auth/me/migration", r#"{"sourceType":"imap","imapConfig":{"host":"imap.example.net","tls_mode":"tls"},"#),
        ];
        for (method, path, prefix) in cases {
            let (status, text) = w.call(addr, method, path, padded(prefix, big + 1)).await?;
            assert_eq!(status, 400, "{path}: a body over 1 MiB must be refused, got {status}: {text}");
        }
        for (_, path, _) in cases {
            let stored: i64 = w.owner.query_one(
                "SELECT (SELECT count(*) FROM webhook_subscriptions WHERE user_id=$1)+(SELECT count(*) FROM app_passwords WHERE user_id=$1)+(SELECT count(*) FROM migration_jobs WHERE user_id=$1)",
                &[&w.a.user],
            ).await?.get(0);
            assert_eq!(stored, 0, "{path}: an oversize body must create nothing");
        }
        // Control: the same request just under the cap is read (and, here, created).
        let (status, text) = w.call(addr, "POST", "/auth/me/app-passwords", padded(r#"{"name":"cap","#, big - 64)).await?;
        assert_eq!(status, 201, "control: a body under the cap is accepted: {text}");
        let (status, text) = w.call(addr, "POST", "/auth/me/webhooks", padded(r#"{"url":"https://public.hooks.test/x","eventTypes":["mail.received"],"#, big - 64)).await?;
        assert_eq!(status, 201, "control: a webhook body under the cap is accepted: {text}");
        server.abort();
        Ok::<_, BoxError>(())
    }
    .await;
    w.finish().await?;
    result
}

fn orchestrator(
    w: &World,
    dialer: setjoin_gateway::migration_runner::Dialer,
) -> Result<setjoin_gateway::migration::Runner, BoxError> {
    use setjoin_gateway::migration_runner::{Config as RunnerConfig, Orchestrator};
    Ok(setjoin_gateway::migration::Runner {
        orchestrator: Orchestrator::new(RunnerConfig {
            db: setjoin_pg::workers::WorkerDatabase::new(&w.dsn)?.with_audit_keys("22".repeat(32), String::new()),
            store: Arc::new(setjoin_gateway::recovery_worker::S3Store::new("http://127.0.0.1:1", "mailblobs", "test-access", "test-secret")?),
            root: "22".repeat(32),
            dialer,
            dispatcher: None,
        }),
        worker: common::patient_exec(&w.dsn, 4)?.with_audit_keys("22".repeat(32), String::new()),
    })
}

/// #547 item 6: plaintext IMAP (`tls_mode` none) is refused on test-imap and on IMAP start.
#[tokio::test]
async fn self_service_imap_refuses_plaintext_tls_mode() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(w) = world("secfix13-plaintext").await? else { return Ok(()) };
    let result = async {
        let table = Arc::new(Table(vec![]));
        // test-imap without a runner answers 503 once it passes validation (the control).
        let (addr, server) = w.serve(None, table.clone()).await?;
        for mode in ["none"] {
            let body = json!({"host": "imap.example.net", "port": 143, "tls_mode": mode, "credentials": {"username": "u", "password": "p"}}).to_string();
            let (status, text) = w.call(addr, "POST", "/auth/me/migration/test-imap", body).await?;
            assert_eq!(status, 400, "tls_mode {mode} must be refused: {text}");
            assert!(text.contains("plaintext IMAP"), "{text}");
        }
        for mode in ["tls", "starttls"] {
            let body = json!({"host": "imap.example.net", "port": 993, "tls_mode": mode, "credentials": {"username": "u", "password": "p"}}).to_string();
            let (status, text) = w.call(addr, "POST", "/auth/me/migration/test-imap", body).await?;
            assert_eq!(status, 503, "control: {mode} passes validation and reaches the runner check: {text}");
        }
        server.abort();
        // Start needs a runner. An already active job makes an accepted request answer 409, so
        // nothing is started here and the refusal is observable as 400.
        let runner = orchestrator(&w, setjoin_gateway::migration_runner::Dialer::system())?;
        let (addr, server) = w.serve(Some(runner), table).await?;
        w.owner.execute("INSERT INTO migration_jobs(user_id,source_type,target_mailbox_id,status) VALUES($1,'ics',$2,'pending')", &[&w.a.user, &w.a.mailbox]).await?;
        let start = |mode: &str| json!({"sourceType": "imap", "imapConfig": {"host": "imap.example.net", "port": 143, "tls_mode": mode, "credentials": {"username": "u", "password": "p"}}}).to_string();
        let (status, text) = w.call(addr, "POST", "/auth/me/migration", start("none")).await?;
        assert_eq!(status, 400, "an IMAP start with tls_mode none must be refused: {text}");
        assert!(text.contains("plaintext IMAP"), "{text}");
        // An omitted or unknown mode would fall through to imap.defaults at run time: refused too.
        let omitted = json!({"sourceType": "imap", "imapConfig": {"host": "imap.example.net", "port": 143, "credentials": {"username": "u", "password": "p"}}}).to_string();
        for body in [omitted, start(""), start("bogus")] {
            let (status, text) = w.call(addr, "POST", "/auth/me/migration", body).await?;
            assert_eq!(status, 400, "an IMAP start must name tls or starttls: {text}");
            assert!(text.contains("tls_mode must be tls or starttls"), "{text}");
        }
        let (status, text) = w.call(addr, "POST", "/auth/me/migration", start("starttls")).await?;
        assert_eq!(status, 409, "control: starttls is accepted up to the one-active-job rule: {text}");
        let jobs: i64 = w.owner.query_one("SELECT count(*) FROM migration_jobs WHERE user_id=$1", &[&w.a.user]).await?.get(0);
        assert_eq!(jobs, 1, "a refused start creates no job");
        server.abort();
        Ok::<_, BoxError>(())
    }
    .await;
    w.finish().await?;
    result
}

/// #547 item 5: a self-service job that merges the administrator's `imap.defaults` must not
/// inherit the administrator's private-network allowlist (the user names the host). The same job
/// created by an administrator (`self_service: false`) still does.
#[tokio::test]
async fn self_service_migration_never_inherits_the_admin_private_allowlist() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(w) = world("secfix13-allowlist").await? else { return Ok(()) };
    let result = async {
        let imap = fake_imap::FakeImap::start("127.0.0.1:0", "alice", "pw", vec![fake_imap::folder("INBOX", &[], 1, vec![])]).await?;
        let target = imap.address;
        let host = "internal-imap.secfix13.test";
        w.owner.execute(
            "INSERT INTO system_config(key,value,encrypted) VALUES('imap.defaults',$1::text::jsonb,false) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value,encrypted=false",
            &[&json!({"host": host, "port": target.port(), "tls_mode": "none", "private_hosts": [host], "private_cidrs": ["10.0.0.0/24"]}).to_string()],
        ).await?;
        // The administrator's host resolves to a private address; the dial goes to the fake.
        let dialer = setjoin_gateway::migration_runner::Dialer::custom(
            |_| Box::pin(async { Ok(vec!["10.0.0.9".parse::<std::net::IpAddr>().unwrap()]) }),
            move |origin| {
                Box::pin(async move {
                    if origin.port() != target.port() {
                        return Err("unexpected fixture origin".into());
                    }
                    let stream = tokio::net::TcpStream::connect(target).await.map_err(|e| e.to_string())?;
                    Ok(Box::new(stream) as Box<dyn setjoin_gateway::migration_runner::imap::Io>)
                })
            },
        );
        let runner = orchestrator(&w, dialer)?;
        let key = setjoin_mailboxes::migration::derive_key(&"22".repeat(32), "migration").ok_or("key")?;
        let seen = &imap;
        let run = |self_service: bool| {
            let runner = &runner;
            let w = &w;
            async move {
                let config = json!({"use_global_auth": true, "source_type": "imap", "self_service": self_service,
                    "imap": {"host": host, "port": target.port(), "tls_mode": if self_service {"starttls"} else {"none"}, "credentials": {"username": "alice", "password": "pw"}}});
                let sealed = setjoin_mailboxes::migration::seal(config.to_string().as_bytes(), &key).ok_or("seal")?;
                w.owner.execute("DELETE FROM migration_jobs WHERE user_id=$1", &[&w.a.user]).await?;
                let job: i64 = w.owner.query_one(
                    "INSERT INTO migration_jobs(user_id,source_type,target_mailbox_id,status,source_config_enc) VALUES($1,'imap',$2,'pending',$3) RETURNING id",
                    &[&w.a.user, &w.a.mailbox, &sealed],
                ).await?.get(0);
                runner.orchestrator.start_job(job).map_err(|e| BoxError::from(format!("{e:?}")))?;
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
                loop {
                    let row = w.owner.query_one("SELECT status,error_log::text FROM migration_jobs WHERE id=$1", &[&job]).await?;
                    let status: String = row.get(0);
                    // A job that reached the source and is waiting on it is the observable bug.
                    if matches!(status.as_str(), "completed" | "failed" | "cancelled") || !seen.state.commands.lock().unwrap().is_empty() {
                        return Ok::<_, BoxError>((status, row.get::<_, String>(1)));
                    }
                    if std::time::Instant::now() > deadline {
                        return Err(format!("job never settled: {status}").into());
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            }
        };
        let contacted = || imap.state.commands.lock().unwrap().len();
        let (status, log) = run(true).await?;
        assert_eq!(contacted(), 0, "a self-service job reached the administrator's private host: {status} {log}");
        assert_eq!(status, "failed", "{log}");
        assert!(log.contains("destination is not allowed"), "the private-network policy is what failed the job: {log}");
        let (status, log) = run(false).await?;
        assert!(contacted() > 0, "control: an administrator-created job inherits the allowlist and connects: {status} {log}");
        server_done(&imap);
        Ok::<_, BoxError>(())
    }
    .await;
    w.finish().await?;
    result
}
fn server_done(_: &fake_imap::FakeImap) {}

/// Runs one pending IMAP job of the fixture user through the orchestrator and returns its final
/// status and error log.
async fn run_job(
    w: &World,
    runner: &setjoin_gateway::migration::Runner,
    config: Value,
) -> Result<(String, String), BoxError> {
    let key = setjoin_mailboxes::migration::derive_key(&"22".repeat(32), "migration").ok_or("key")?;
    let sealed = setjoin_mailboxes::migration::seal(config.to_string().as_bytes(), &key).ok_or("seal")?;
    w.owner.execute("DELETE FROM migration_jobs WHERE user_id=$1", &[&w.a.user]).await?;
    let job: i64 = w.owner.query_one(
        "INSERT INTO migration_jobs(user_id,source_type,target_mailbox_id,status,source_config_enc) VALUES($1,'imap',$2,'pending',$3) RETURNING id",
        &[&w.a.user, &w.a.mailbox, &sealed],
    ).await?.get(0);
    runner.orchestrator.start_job(job).map_err(|e| BoxError::from(format!("{e:?}")))?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        let row = w.owner.query_one("SELECT status,error_log::text FROM migration_jobs WHERE id=$1", &[&job]).await?;
        let status: String = row.get(0);
        if matches!(status.as_str(), "completed" | "failed" | "cancelled") {
            return Ok((status, row.get::<_, String>(1)));
        }
        if std::time::Instant::now() > deadline {
            return Err(format!("job never settled: {status}").into());
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}

/// #547 item 6 (review fix): once defaults are merged, a job that is not administrator-created
/// never runs in clear. An omitted tls_mode inherits the administrator's `none`, and a job created
/// before the route refused `none` carries it; the runner refuses both. An administrator-created
/// job (`self_service: false`) keeps the administrator's choice.
#[tokio::test]
async fn self_service_jobs_never_run_plaintext_imap() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(w) = world("secfix13-runner-plaintext").await? else { return Ok(()) };
    let result = async {
        let imap = fake_imap::FakeImap::start("127.0.0.1:0", "alice", "pw", vec![fake_imap::folder("INBOX", &[], 1, vec![])]).await?;
        let target = imap.address;
        let host = "plain-imap.secfix13.test";
        // Defaults say `none`; no private allowlist is involved (the host resolves publicly).
        w.owner.execute(
            "INSERT INTO system_config(key,value,encrypted) VALUES('imap.defaults',$1::text::jsonb,false) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value,encrypted=false",
            &[&json!({"host": host, "port": target.port(), "tls_mode": "none"}).to_string()],
        ).await?;
        let dialer = setjoin_gateway::migration_runner::Dialer::custom(
            |_| Box::pin(async { Ok(vec!["93.184.216.34".parse::<std::net::IpAddr>().unwrap()]) }),
            move |origin| {
                Box::pin(async move {
                    if origin.port() != target.port() {
                        return Err("unexpected fixture origin".into());
                    }
                    let stream = tokio::net::TcpStream::connect(target).await.map_err(|e| e.to_string())?;
                    Ok(Box::new(stream) as Box<dyn setjoin_gateway::migration_runner::imap::Io>)
                })
            },
        );
        let runner = orchestrator(&w, dialer)?;
        let contacted = || imap.state.commands.lock().unwrap().len();
        let job = |self_service: bool, tls: Option<&str>| {
            let mut imap = json!({"host": host, "port": target.port(), "credentials": {"username": "alice", "password": "pw"}});
            if let Some(tls) = tls {
                imap["tls_mode"] = json!(tls);
            }
            json!({"use_global_auth": true, "source_type": "imap", "self_service": self_service, "imap": imap})
        };
        for (what, config) in [
            ("omitted mode inheriting the defaults' none", job(true, None)),
            ("explicit none created before the route refused it", job(true, Some("none"))),
        ] {
            let (status, log) = run_job(&w, &runner, config).await?;
            assert_eq!(contacted(), 0, "{what}: the source was contacted in clear: {status} {log}");
            assert_eq!(status, "failed", "{what}: {log}");
            assert!(log.contains("plaintext IMAP"), "{what}: the plaintext refusal is what failed the job: {log}");
        }
        let (status, log) = run_job(&w, &runner, job(false, None)).await?;
        assert!(contacted() > 0, "control: an administrator-created job keeps the administrator's mode: {status} {log}");
        Ok::<_, BoxError>(())
    }
    .await;
    w.finish().await?;
    result
}
