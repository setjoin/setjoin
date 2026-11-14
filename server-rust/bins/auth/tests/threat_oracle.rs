//! #349a native HTTP threat admission oracle. Recorded cases (`go_off_*`,
//! `go_threat_*`, `go_geo_*`, `go_tarpit_*`) drive the auth listener directly:
//! frozen Go authserverd while recording (GOFREE_RECORD_UPSTREAM, preset
//! GOFREE_RECORD_AUTH_PRESET), the native server with no Go upstream on replay.
//! Approved security divergences replay against Rust contracts with the Go
//! golden kept as evidence. `native_*` cases pin Rust-only invariants. Corpus:
//! tests/conformance/identity-threat (README has the dispatch inputs).
#[allow(dead_code)]
mod common;
use base64::Engine as _;
use http_body_util::BodyExt;
use hyper::Request;
use serde_json::{json, Value};
use setjoin_auth::{body, AuthServer, Config};
use setjoin_conformance::{fixture, golden, harness::Db};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio_postgres::Client;

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
type Err = Box<dyn std::error::Error + Send + Sync>;

const PASSWORD: &str = "Password1!";
const WRONG: &str = "Wrong-password-1!";
const AGENT: &str = "GOFREE349A oracle";
const HOST: &str = "auth.gofree349a.test";
const ORIGIN: &str = "http://auth.gofree349a.test";
const MARK: &str = "GOFREE349A";
const NOBODY: &str = "nobody-349a@gofree349a.test";
const VICTIM: &str = "victim-349a@gofree349a.test";
const DECOY: &str = "decoy@gofree349a.test";
const US_IP: &str = "203.0.113.5";
const OWNER: &str = "auth shape awaits its owner ticket\n";
/// Public fixture string from scripts/gofree-record.sh (never a real secret).
const CAPTCHA_FIXTURE: &str = "gofree-record-fixture-captcha-secret-not-a-secret";
const ENC: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const SEED_1: &str = "gofree349a-seed-1";
const SEED_2: &str = "gofree349a-seed-2";
const SEED_3: &str = "gofree349a-seed-3";
const SPRAY: [&str; 3] = [SEED_1, SEED_2, SEED_3];
const REPEAT3: [&str; 3] = [SEED_1, SEED_1, SEED_1];
const REPEAT2: [&str; 2] = [SEED_1, SEED_1];
const LOGIN: &str = "/auth/login";
const REFRESH: &str = "/auth/refresh";
const RESET: &str = "/auth/forgot-password/reset";
const BEGIN: &str = "/auth/forgot-password/begin";
const VERIFY: &str = "/auth/forgot-password/verify";
const FLAGS: [&str; 5] = [
    "feature.rate_limit",
    "feature.conditional_access",
    "feature.device_trust_enforcement",
    "feature.token_binding",
    "feature.forgot_password",
];
const EFFECTS: &str = "SELECT jsonb_build_object(
 'attempts', coalesce((SELECT jsonb_agg(jsonb_build_object('source_ip',host(source_ip),'username',target_username,'protocol',protocol,'outcome',outcome,'country',coalesce(geo_country,''),'fingerprint',coalesce(device_fingerprint,'')) ORDER BY occurred_at, id) FROM auth_attempts WHERE source_ip = ANY($1::text[]::inet[]) AND occurred_at >= $2::text::timestamptz AND target_username NOT LIKE 'gofree349a-seed%'),'[]'::jsonb),
 'lockouts', coalesce((SELECT jsonb_agg(jsonb_build_object('key',lockout_key,'failed_count',failed_count,'level',escalation_level,'locked',locked_until>now()) ORDER BY lockout_key) FROM auth_lockouts WHERE lockout_key = ANY($3::text[])),'[]'::jsonb),
 'rate', coalesce((SELECT jsonb_agg(jsonb_build_object('key',key,'count',count) ORDER BY key) FROM rate_limit_counters WHERE key = ANY($4::text[])),'[]'::jsonb),
 'devices', coalesce((SELECT jsonb_agg(jsonb_build_object('hash',device_hash,'agent',user_agent,'prefix',ip_prefix,'country',coalesce(country,''),'count',auth_count) ORDER BY id) FROM device_registry WHERE user_id=$5),'[]'::jsonb),
 'audit', coalesce((SELECT jsonb_agg(jsonb_build_object('event',event_type,'source_ip',host(source_ip),'user',user_id IS NOT NULL,'metadata',metadata) ORDER BY occurred_at, id) FROM audit_log WHERE source_ip = ANY($1::text[]::inet[]) AND event_type IN ('device_new','device_country_changed','spray_detected') AND occurred_at >= $2::text::timestamptz),'[]'::jsonb)
)::text";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Preset {
    Off,
    Threat,
    Geo,
    Tarpit,
}

impl Preset {
    fn of(name: &str) -> Preset {
        if name.starts_with("threat-") {
            Preset::Threat
        } else if name.starts_with("geo-") {
            Preset::Geo
        } else if name.starts_with("tarpit-") {
            Preset::Tarpit
        } else {
            Preset::Off
        }
    }

    fn name(self) -> &'static str {
        match self {
            Preset::Off => "off",
            Preset::Threat => "threat",
            Preset::Geo => "geo",
            Preset::Tarpit => "tarpit",
        }
    }

    /// The Go env scripts/gofree-record.sh writes for this preset.
    fn env(self) -> Vec<(&'static str, &'static str)> {
        if self == Preset::Off {
            return [
                "THREAT_FEED_ENABLED",
                "GEO_BLOCK_ENABLED",
                "SPRAY_DETECT_ENABLED",
                "CAPTCHA_ENABLED",
                "TARPIT_ENABLED",
            ]
            .into_iter()
            .map(|k| (k, "false"))
            .collect();
        }
        let tarpit = self == Preset::Tarpit;
        let mut env = vec![
            ("THREAT_FEED_ENABLED", "true"),
            ("GEO_BLOCK_ENABLED", if tarpit { "false" } else { "true" }),
            ("SPRAY_DETECT_ENABLED", "true"),
            ("CAPTCHA_ENABLED", if tarpit { "false" } else { "true" }),
            ("TARPIT_ENABLED", "true"),
            ("CAPTCHA_SECRET", CAPTCHA_FIXTURE),
            ("GEO_BLOCK_COUNTRIES", "US"),
            ("THREAT_RATE_LIMIT_PER_MIN", "3"),
            ("THREAT_CAPTCHA_THRESHOLD", "3"),
            ("THREAT_CAPTCHA_WINDOW_MINS", "5"),
            ("THREAT_SPRAY_MAX_USERS", "3"),
            ("THREAT_SPRAY_WINDOW_SECS", "300"),
            ("THREAT_SPRAY_LOCKOUT_MINS", "5"),
        ];
        if tarpit {
            env.push(("THREAT_TARPIT_THRESHOLD", "2"));
        }
        env
    }

    /// us.mmdb resolves every address to US (one-node tree).
    fn geoip(self) -> bool {
        matches!(self, Preset::Geo | Preset::Tarpit)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Source {
    Case,
    Proxy,
}

#[derive(Clone, Copy)]
enum Payload {
    LoginGood,
    LoginBad,
    RefreshJwtEmail,
    RefreshPrevious,
    ResetBad,
    Oversize,
    BeginUnknown,
    BeginActor,
    VerifyBad,
}

#[derive(Clone, Copy)]
enum Extra {
    None,
    CrossSite,
    Xff,
    CaptchaBogus,
    CaptchaDerived,
    CaptchaFixture,
    CaptchaWrong,
    CaptchaExpired,
}

enum Setup {
    None,
    IpRule(&'static str),
    RateCounter(i32),
    LockoutArm,
    Totp,
    ForceChange,
    Escalated,
    Feed,
    SeedFailures(&'static [&'static str]),
}

/// Rust-side half of an approved divergence, checked on replay.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Check {
    None,
    BeginKeepsLockout,
    RefreshKeysVerifiedOnly,
    FailedTokenCounted,
}

struct Step {
    source: Source,
    path: &'static str,
    payload: Payload,
    extra: Extra,
}

struct Contract {
    statuses: Vec<(u16, Option<&'static str>)>,
    attempts: Vec<&'static str>,
    delay: Option<(&'static str, Duration)>,
}

struct Plan {
    rate: bool,
    setup: Setup,
    steps: Vec<Step>,
    /// Go-derived contract; checked while recording, and on replay when `native` is None.
    go: Contract,
    /// Rust's contract where an approved divergence changes the response: replay
    /// keeps the Go golden as evidence only.
    native: Option<Contract>,
    /// JSON pointers removed from both sides before comparing (divergent effects).
    strip: &'static [&'static str],
    check: Check,
}

fn contract(status: u16, reason: Option<&'static str>, attempts: &[&'static str]) -> Contract {
    Contract {
        statuses: vec![(status, reason)],
        attempts: attempts.to_vec(),
        delay: None,
    }
}

/// A token that fails verification or its claim still runs the tarpit (V2-1):
/// 3 failures, threshold 3: 500*3+500 ms. A verified, claimed token skips it.
fn tarpitted() -> Contract {
    Contract {
        statuses: vec![(429, Some("tarpit_applied"))],
        attempts: vec![],
        delay: Some(("2s", Duration::from_secs(2))),
    }
}

#[allow(clippy::too_many_arguments)]
fn single(
    rate: bool,
    setup: Setup,
    path: &'static str,
    payload: Payload,
    extra: Extra,
    status: u16,
    reason: Option<&'static str>,
    attempts: &[&'static str],
) -> Plan {
    Plan {
        rate,
        setup,
        steps: vec![Step {
            source: Source::Case,
            path,
            payload,
            extra,
        }],
        go: contract(status, reason, attempts),
        native: None,
        strip: &[],
        check: Check::None,
    }
}

fn plan(name: &str) -> Result<Plan, Err> {
    use Extra as E;
    use Payload as P;
    Ok(match name {
        "off-login-unmounted-ip-block" => single(
            false,
            Setup::IpRule("block"),
            LOGIN,
            P::LoginBad,
            E::CaptchaBogus,
            401,
            None,
            &[],
        ),
        "off-refresh-unmounted-ip-block" => single(
            false,
            Setup::IpRule("block"),
            REFRESH,
            P::RefreshJwtEmail,
            E::None,
            401,
            None,
            &[],
        ),
        "off-login-ip-block" => single(
            true,
            Setup::IpRule("block"),
            LOGIN,
            P::LoginBad,
            E::None,
            403,
            Some("ip_blocked"),
            &[],
        ),
        "off-login-ip-allow" => single(
            true,
            Setup::IpRule("allow"),
            LOGIN,
            P::LoginBad,
            E::None,
            401,
            None,
            &["failure"],
        ),
        "off-login-rate-limited" => single(
            true,
            Setup::RateCounter(20),
            LOGIN,
            P::LoginBad,
            E::None,
            429,
            Some("rate_limited"),
            &["rate_limited"],
        ),
        "off-login-success" => single(
            true,
            Setup::None,
            LOGIN,
            P::LoginGood,
            E::None,
            200,
            None,
            &["success"],
        ),
        "off-login-failure" => single(
            true,
            Setup::None,
            LOGIN,
            P::LoginBad,
            E::None,
            401,
            None,
            &["failure"],
        ),
        "off-login-csrf" => single(
            true,
            Setup::None,
            LOGIN,
            P::LoginGood,
            E::CrossSite,
            403,
            None,
            &["failure"],
        ),
        "off-login-mfa-pending" => single(
            true,
            Setup::Totp,
            LOGIN,
            P::LoginGood,
            E::None,
            202,
            None,
            &[],
        ),
        "off-login-force-change" => single(
            true,
            Setup::ForceChange,
            LOGIN,
            P::LoginGood,
            E::None,
            403,
            None,
            &[],
        ),
        "off-login-lockout" => {
            let mut plan = single(
                true,
                Setup::LockoutArm,
                LOGIN,
                P::LoginGood,
                E::None,
                403,
                Some("lockout"),
                &["lockout"],
            );
            plan.go.delay = Some(("15s", Duration::from_secs(15)));
            plan
        }
        "off-login-captcha-bogus" => Plan {
            strip: &["/observation/effects/rate"],
            check: Check::FailedTokenCounted,
            ..single(
                true,
                Setup::None,
                LOGIN,
                P::LoginGood,
                E::CaptchaBogus,
                403,
                Some("captcha"),
                &["captcha_needed"],
            )
        },
        "off-refresh-jwt-email" => Plan {
            strip: &[
                "/observation/effects/attempts",
                "/observation/effects/lockouts",
            ],
            check: Check::RefreshKeysVerifiedOnly,
            ..single(
                true,
                Setup::None,
                REFRESH,
                P::RefreshJwtEmail,
                E::None,
                401,
                None,
                &["failure"],
            )
        },
        "off-refresh-success" => Plan {
            steps: vec![
                Step {
                    source: Source::Case,
                    path: LOGIN,
                    payload: P::LoginGood,
                    extra: E::None,
                },
                Step {
                    source: Source::Case,
                    path: REFRESH,
                    payload: P::RefreshPrevious,
                    extra: E::None,
                },
            ],
            go: Contract {
                statuses: vec![(200, None), (200, None)],
                attempts: vec!["success", "success"],
                delay: None,
            },
            ..single(
                true,
                Setup::None,
                LOGIN,
                P::LoginGood,
                E::None,
                200,
                None,
                &[],
            )
        },
        "off-reset-ip-block" => single(
            false,
            Setup::IpRule("block"),
            RESET,
            P::ResetBad,
            E::None,
            403,
            Some("ip_blocked"),
            &[],
        ),
        "off-reset-invalid-token" => single(
            false,
            Setup::None,
            RESET,
            P::ResetBad,
            E::None,
            401,
            None,
            &["failure"],
        ),
        "off-reset-csrf" => single(
            false,
            Setup::None,
            RESET,
            P::ResetBad,
            E::CrossSite,
            403,
            None,
            &["failure"],
        ),
        "off-reset-oversize" => single(
            false,
            Setup::None,
            RESET,
            P::Oversize,
            E::None,
            413,
            Some("body_too_large"),
            &[],
        ),
        "off-begin-decoy" => single(
            false,
            Setup::None,
            BEGIN,
            P::BeginUnknown,
            E::None,
            200,
            None,
            &["success"],
        ),
        "off-begin-ip-block" => single(
            false,
            Setup::IpRule("block"),
            BEGIN,
            P::BeginUnknown,
            E::None,
            403,
            Some("ip_blocked"),
            &[],
        ),
        "off-begin-captcha-bogus" => single(
            false,
            Setup::None,
            BEGIN,
            P::BeginUnknown,
            E::CaptchaBogus,
            403,
            Some("captcha"),
            &["captcha_needed"],
        ),
        "off-begin-captcha-derived" => single(
            false,
            Setup::None,
            BEGIN,
            P::BeginUnknown,
            E::CaptchaDerived,
            200,
            None,
            &["success"],
        ),
        "off-begin-lockout-divergence" => Plan {
            strip: &["/observation/effects/lockouts"],
            check: Check::BeginKeepsLockout,
            ..single(
                false,
                Setup::Escalated,
                BEGIN,
                P::BeginActor,
                E::None,
                200,
                None,
                &["success"],
            )
        },
        "off-verify-invalid-code" => single(
            false,
            Setup::None,
            VERIFY,
            P::VerifyBad,
            E::None,
            401,
            None,
            &["failure"],
        ),
        "threat-login-feed" => single(
            true,
            Setup::Feed,
            LOGIN,
            P::LoginBad,
            E::None,
            403,
            Some("threat_blocked"),
            &["threat_blocked"],
        ),
        "threat-login-trusted-xff" => Plan {
            steps: vec![Step {
                source: Source::Proxy,
                path: LOGIN,
                payload: P::LoginBad,
                extra: E::Xff,
            }],
            ..single(
                true,
                Setup::None,
                LOGIN,
                P::LoginBad,
                E::Xff,
                401,
                None,
                &["failure"],
            )
        },
        "threat-login-spoofed-xff" => single(
            true,
            Setup::None,
            LOGIN,
            P::LoginBad,
            E::Xff,
            401,
            None,
            &["failure"],
        ),
        "threat-login-spray" => single(
            true,
            Setup::SeedFailures(&SPRAY),
            LOGIN,
            P::LoginBad,
            E::None,
            403,
            Some("spray_detected"),
            &["spray_detected"],
        ),
        "threat-login-captcha-needed" => single(
            true,
            Setup::SeedFailures(&REPEAT3),
            LOGIN,
            P::LoginBad,
            E::None,
            403,
            Some("captcha"),
            &["captcha_needed"],
        ),
        "threat-login-captcha-solved" => single(
            true,
            Setup::SeedFailures(&REPEAT3),
            LOGIN,
            P::LoginGood,
            E::CaptchaFixture,
            200,
            None,
            &["success"],
        ),
        "threat-login-captcha-wrong" => Plan {
            native: Some(tarpitted()),
            ..single(
                true,
                Setup::SeedFailures(&REPEAT3),
                LOGIN,
                P::LoginGood,
                E::CaptchaWrong,
                403,
                Some("captcha"),
                &["captcha_needed"],
            )
        },
        "threat-login-captcha-expired" => Plan {
            native: Some(tarpitted()),
            ..single(
                true,
                Setup::SeedFailures(&REPEAT3),
                LOGIN,
                P::LoginGood,
                E::CaptchaExpired,
                403,
                Some("captcha"),
                &["captcha_needed"],
            )
        },
        "threat-login-rate-limited" => single(
            true,
            Setup::RateCounter(3),
            LOGIN,
            P::LoginBad,
            E::None,
            429,
            Some("rate_limited"),
            &["rate_limited"],
        ),
        "geo-login-trusted-xff" => Plan {
            steps: vec![Step {
                source: Source::Proxy,
                path: LOGIN,
                payload: P::LoginBad,
                extra: E::Xff,
            }],
            ..single(
                true,
                Setup::None,
                LOGIN,
                P::LoginBad,
                E::Xff,
                403,
                Some("geo_blocked"),
                &["geo_blocked"],
            )
        },
        "geo-login-ip-block-first" => single(
            true,
            Setup::IpRule("block"),
            LOGIN,
            P::LoginBad,
            E::None,
            403,
            Some("ip_blocked"),
            &[],
        ),
        "tarpit-login-threshold" => {
            let mut plan = single(
                true,
                Setup::SeedFailures(&REPEAT2),
                LOGIN,
                P::LoginBad,
                E::None,
                429,
                Some("tarpit_applied"),
                &[],
            );
            plan.go.delay = Some(("1.5s", Duration::from_millis(1500)));
            plan
        }
        "tarpit-login-high-risk" => {
            let mut plan = single(
                true,
                Setup::None,
                LOGIN,
                P::LoginBad,
                E::None,
                429,
                Some("tarpit_applied"),
                &[],
            );
            plan.go.delay = Some(("500ms", Duration::from_millis(500)));
            plan
        }
        _ => return Err(format!("no plan for {name}").into()),
    })
}

struct Fx {
    a: fixture::Account,
    email: String,
}

struct Reply {
    status: u16,
    headers: Value,
    body: String,
    elapsed: Duration,
}

struct Server {
    stop: Option<oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<()>,
    addr: SocketAddr,
}

impl Server {
    async fn close(mut self) {
        if let Some(tx) = self.stop.take() {
            let _ = tx.send(());
        }
        let _ = (&mut self.task).await;
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn keys() -> Value {
    serde_json::from_str(include_str!(
        "../../../tests/conformance/identity-login/keys.json"
    ))
    .expect("keys fixture")
}

fn fixture_secret() -> String {
    keys()["secret"].as_str().unwrap_or_default().to_owned()
}

fn mmdb() -> String {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/conformance/authzgates/us.mmdb")
        .to_string_lossy()
        .into_owned()
}

fn corpus() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/conformance/identity-threat")
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn mac_token(secret: &[u8], message: &str, exp: i64) -> String {
    use base64::engine::general_purpose::URL_SAFE;
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret);
    let mac = ring::hmac::sign(&key, message.as_bytes());
    URL_SAFE.encode(format!("{exp}.{}", URL_SAFE.encode(mac.as_ref())))
}

/// Independent Go captchaToken encoder (recording only).
fn go_captcha(secret: &[u8], answer: &str, exp: i64) -> String {
    mac_token(secret, &format!("{answer}|{exp}"), exp)
}

/// Independent encoder of the #349 bound token.
fn bound_captcha(
    secret: &[u8],
    answer: &str,
    exp: i64,
    ip: &str,
    route: &str,
    username: &str,
) -> String {
    mac_token(
        secret,
        &format!("{answer}|{exp}|{ip}|{route}|{username}"),
        exp,
    )
}

struct Len(usize);
impl ring::hkdf::KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}

/// Go's CAPTCHA_SECRET default for JWT_SECRET (salt = purpose, empty info).
fn derived_secret(jwt_secret: &str) -> Vec<u8> {
    let prk = ring::hkdf::Salt::new(ring::hkdf::HKDF_SHA256, b"mailserver-captcha-token-v1")
        .extract(jwt_secret.as_bytes());
    let mut out = vec![0u8; 32];
    prk.expand(&[], Len(32))
        .and_then(|okm| okm.fill(&mut out))
        .expect("HKDF-SHA256");
    out
}

fn fake_refresh(email: &str) -> String {
    format!(
        "h.{}.s",
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(json!({ "email": email }).to_string())
    )
}

fn rust_config(db: &Db, preset: Preset, upstream: Option<String>) -> Result<Config, Err> {
    let secret = fixture_secret();
    let mut cfg = Config::for_secret(secret.clone());
    cfg.signing_alg = "ES256".into();
    cfg.dsn = db.dsn.clone();
    cfg.go_upstream = upstream;
    let env = preset.env();
    let lookup = |name: &str, _: &str| {
        env.iter()
            .find(|(k, _)| *k == name)
            .map(|(_, v)| (*v).to_owned())
    };
    cfg.threat = Config::threat_from_lookup(
        &lookup,
        &secret,
        setjoin_config_secret::CryptoProfile::Standard,
    )?;
    if preset != Preset::Off {
        cfg.client_proxy = "127.0.0.1".into();
    }
    if preset.geoip() {
        cfg.geoip_path = mmdb();
    }
    Ok(cfg)
}

async fn gated_server(
    cfg: Config,
    exec_dsn: &str,
    request_dsn: &str,
    worker_dsn: &str,
) -> Result<Arc<AuthServer>, Err> {
    let exec = setjoin_pg::ScopedExecutor::from_dsn(exec_dsn, 4).map_err(|e| e.0)?;
    Ok(Arc::new(
        AuthServer::load(exec, cfg)
            .await?
            .with_threat_gate_dsns(request_dsn, worker_dsn)
            .await?,
    ))
}

async fn native_server(db: &Db, cfg: Config) -> Result<Arc<AuthServer>, Err> {
    gated_server(cfg, db.app.as_deref().unwrap_or(&db.dsn), &db.dsn, &db.dsn).await
}

async fn serve(server: Arc<AuthServer>) -> Result<Server, Err> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let (tx, rx) = oneshot::channel::<()>();
    let task = tokio::spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        tokio::pin!(rx);
        loop {
            tokio::select! {
                _ = &mut rx => break,
                accepted = listener.accept() => {
                    let Ok((stream, peer)) = accepted else { break };
                    let server = server.clone();
                    connections.spawn(async move {
                        let service = hyper::service::service_fn(move |mut req: Request<hyper::body::Incoming>| {
                            let server = server.clone();
                            req.extensions_mut().insert(setjoin_auth::ConnectionMeta { peer, tls: false });
                            async move {
                                Ok::<_, std::convert::Infallible>(
                                    server.handle(req.map(|b| b.map_err(std::io::Error::other).boxed())).await,
                                )
                            }
                        });
                        let _ = hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
                            .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                            .await;
                    });
                }
            }
        }
        connections.abort_all();
        while connections.join_next().await.is_some() {}
    });
    Ok(Server {
        stop: Some(tx),
        task,
        addr,
    })
}

/// A Go-upstream stand-in that records every forwarded body and answers 418.
struct Spy {
    server: Server,
    hits: Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
}

async fn spy() -> Result<Spy, Err> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let hits = Arc::new(std::sync::Mutex::new(Vec::new()));
    let seen = hits.clone();
    let (tx, rx) = oneshot::channel::<()>();
    let task = tokio::spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        tokio::pin!(rx);
        loop {
            tokio::select! {
                _ = &mut rx => break,
                accepted = listener.accept() => {
                    let Ok((stream, _)) = accepted else { break };
                    let seen = seen.clone();
                    connections.spawn(async move {
                        let service = hyper::service::service_fn(move |r: Request<hyper::body::Incoming>| {
                            let seen = seen.clone();
                            async move {
                                let b = r.into_body().collect().await.map(|b| b.to_bytes().to_vec()).unwrap_or_default();
                                seen.lock().unwrap().push(b);
                                Ok::<_, std::convert::Infallible>(
                                    hyper::Response::builder().status(418).body(body("go\n")).unwrap(),
                                )
                            }
                        });
                        let _ = hyper::server::conn::http1::Builder::new()
                            .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                            .await;
                    });
                }
            }
        }
        connections.abort_all();
        while connections.join_next().await.is_some() {}
    });
    Ok(Spy {
        server: Server {
            stop: Some(tx),
            task,
            addr,
        },
        hits,
    })
}

/// A TCP proxy to the fixture Postgres that can be cut: every live connection
/// drops and new ones are refused (F5 pool faults).
struct Cuttable {
    cut: tokio::sync::watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
}

impl Cuttable {
    fn cut(&self) {
        let _ = self.cut.send(true);
    }
}

impl Drop for Cuttable {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn cuttable(dsn: &str) -> Result<(String, Cuttable), Err> {
    let cfg: tokio_postgres::Config = dsn.parse()?;
    let host = match cfg.get_hosts().first() {
        Some(tokio_postgres::config::Host::Tcp(h)) => h.clone(),
        _ => return Err("TCP fixture DSN required".into()),
    };
    let port = *cfg.get_ports().first().unwrap_or(&5432);
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let mut proxied = format!("host=127.0.0.1 port={}", listener.local_addr()?.port());
    {
        let mut add = |key: &str, value: &str| {
            proxied.push_str(&format!(
                " {key}='{}'",
                value.replace('\\', "\\\\").replace('\'', "\\'")
            ));
        };
        if let Some(v) = cfg.get_user() {
            add("user", v);
        }
        if let Some(v) = cfg.get_password() {
            add("password", std::str::from_utf8(v)?);
        }
        if let Some(v) = cfg.get_dbname() {
            add("dbname", v);
        }
        if let Some(v) = cfg.get_options() {
            add("options", v);
        }
    }
    let (cut, mut watch) = tokio::sync::watch::channel(false);
    let task = tokio::spawn(async move {
        let mut links = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                _ = watch.changed() => break,
                accepted = listener.accept() => {
                    let Ok((mut client, _)) = accepted else { break };
                    let (host, mut stop) = (host.clone(), watch.clone());
                    links.spawn(async move {
                        let Ok(mut server) = tokio::net::TcpStream::connect((host.as_str(), port)).await else {
                            return;
                        };
                        tokio::select! {
                            _ = stop.changed() => {}
                            _ = tokio::io::copy_bidirectional(&mut client, &mut server) => {}
                        }
                    });
                }
            }
        }
        // Dropping the listener refuses new connections; aborting drops live ones.
        links.abort_all();
        while links.join_next().await.is_some() {}
    });
    Ok((proxied, Cuttable { cut, task }))
}

async fn send(
    addr: SocketAddr,
    from: Ipv4Addr,
    path: &str,
    payload: Vec<u8>,
    headers: &[(String, String)],
) -> Result<Reply, Err> {
    let mut http = hyper_util::client::legacy::connect::HttpConnector::new();
    http.set_local_address(Some(IpAddr::V4(from)));
    let client: hyper_util::client::legacy::Client<_, setjoin_auth::Body> =
        hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
            .build(http);
    let mut req = Request::builder()
        .method("POST")
        .uri(format!("http://{addr}{path}"))
        .header("host", HOST)
        .header("user-agent", AGENT)
        .header("content-type", "application/json");
    for (k, v) in headers {
        req = req.header(k.as_str(), v.as_str());
    }
    let started = Instant::now();
    let resp = client.request(req.body(body(payload))?).await?;
    let status = resp.status().as_u16();
    let mut hs = serde_json::Map::new();
    for name in [
        "content-type",
        "cache-control",
        "x-threat-reason",
        "x-threat-delay",
        "set-cookie",
        "www-authenticate",
        "x-content-type-options",
    ] {
        if let Some(v) = resp.headers().get(name) {
            hs.insert(name.into(), json!(v.to_str()?));
        }
    }
    let raw = String::from_utf8(resp.into_body().collect().await?.to_bytes().to_vec())?;
    Ok(Reply {
        status,
        headers: Value::Object(hs),
        body: raw,
        elapsed: started.elapsed(),
    })
}

fn origin() -> Vec<(String, String)> {
    vec![("origin".to_owned(), ORIGIN.to_owned())]
}

fn payload(kind: Payload, email: &str, previous: Option<&Reply>) -> Result<Vec<u8>, Err> {
    Ok(match kind {
        Payload::LoginGood => json!({"email": email, "password": PASSWORD}).to_string().into_bytes(),
        Payload::LoginBad => json!({"email": email, "password": WRONG}).to_string().into_bytes(),
        Payload::RefreshJwtEmail => json!({"refresh_token": fake_refresh(email)}).to_string().into_bytes(),
        Payload::RefreshPrevious => {
            let prior: Value = serde_json::from_str(&previous.ok_or("refresh needs a prior login")?.body)?;
            let token = prior["refresh_token"].as_str().ok_or("prior login issued no refresh token")?;
            json!({ "refresh_token": token }).to_string().into_bytes()
        }
        Payload::ResetBad => json!({"email": email, "reset_token": "not-a-reset-token", "new_password": "NewPassword2!"}).to_string().into_bytes(),
        Payload::Oversize => vec![b'x'; (1 << 20) + 1],
        Payload::BeginUnknown => json!({ "email": NOBODY }).to_string().into_bytes(),
        Payload::BeginActor => json!({ "email": email }).to_string().into_bytes(),
        Payload::VerifyBad => json!({"email": email, "code": "000000"}).to_string().into_bytes(),
    })
}

/// The username the route's handler decodes from `payload` (captcha binding).
fn payload_username(kind: Payload, email: &str) -> String {
    match kind {
        Payload::BeginUnknown => NOBODY.to_owned(),
        Payload::RefreshJwtEmail | Payload::RefreshPrevious | Payload::Oversize => String::new(),
        _ => email.to_owned(),
    }
}

/// Recording mints Go-format tokens; replay mints #349 bound tokens.
struct Mint {
    go: bool,
    ip: String,
    route: &'static str,
    username: String,
}

fn captcha_headers(
    h: &mut Vec<(String, String)>,
    secret: &[u8],
    answer: &str,
    sent: &str,
    exp: i64,
    mint: &Mint,
) {
    let token = if mint.go {
        go_captcha(secret, answer, exp)
    } else {
        bound_captcha(secret, answer, exp, &mint.ip, mint.route, &mint.username)
    };
    h.push(("x-captcha-token".into(), token));
    h.push(("x-captcha-answer".into(), sent.into()));
}

fn extra_headers(extra: Extra, now: i64, mint: &Mint) -> Vec<(String, String)> {
    let mut h = origin();
    match extra {
        Extra::None => {}
        Extra::CrossSite => {
            h[0].1 = "https://evil.example".into();
            h.push(("sec-fetch-site".into(), "cross-site".into()));
        }
        Extra::Xff => h.push(("x-forwarded-for".into(), US_IP.into())),
        Extra::CaptchaBogus => {
            h.push(("x-captcha-token".into(), "bogus-token".into()));
            h.push(("x-captcha-answer".into(), "1".into()));
        }
        Extra::CaptchaDerived => captcha_headers(
            &mut h,
            &derived_secret(&fixture_secret()),
            "7",
            "7",
            now + 120,
            mint,
        ),
        Extra::CaptchaFixture => captcha_headers(
            &mut h,
            CAPTCHA_FIXTURE.as_bytes(),
            "7",
            "7",
            now + 120,
            mint,
        ),
        Extra::CaptchaWrong => captcha_headers(
            &mut h,
            CAPTCHA_FIXTURE.as_bytes(),
            "7",
            "8",
            now + 120,
            mint,
        ),
        Extra::CaptchaExpired => {
            captcha_headers(&mut h, CAPTCHA_FIXTURE.as_bytes(), "7", "7", now - 60, mint)
        }
    }
    h
}

fn keys_for(ips: &[String], users: &[String]) -> Vec<String> {
    let mut keys: Vec<String> = ips.iter().map(|ip| format!("ip:{ip}")).collect();
    for user in users {
        let user = user.to_lowercase();
        keys.push(format!("user:{user}"));
        for ip in ips {
            keys.push(format!("ip_user:{ip}:{user}"));
        }
    }
    keys
}

async fn clear_state(c: &Client, ips: &[String], email: &str) -> Result<(), Err> {
    let keys = keys_for(
        ips,
        &[
            email.to_owned(),
            NOBODY.to_owned(),
            VICTIM.to_owned(),
            DECOY.to_owned(),
        ],
    );
    let rates: Vec<String> = ips.iter().map(|ip| format!("auth:http:{ip}")).collect();
    c.execute("DELETE FROM ip_rules WHERE description=$1", &[&MARK])
        .await?;
    c.execute("DELETE FROM threat_feed_blocks WHERE source=$1", &[&MARK])
        .await?;
    c.execute(
        "DELETE FROM rate_limit_counters WHERE key=ANY($1::text[])",
        &[&rates],
    )
    .await?;
    c.execute(
        "DELETE FROM auth_lockouts WHERE lockout_key=ANY($1::text[])",
        &[&keys],
    )
    .await?;
    c.execute(
        "DELETE FROM auth_attempts WHERE source_ip=ANY($1::text[]::inet[])",
        &[&ips.to_vec()],
    )
    .await?;
    Ok(())
}

async fn save_flags(c: &Client) -> Result<String, Err> {
    Ok(c
        .query_one(
            "SELECT coalesce(jsonb_agg(to_jsonb(t)),'[]')::text FROM feature_toggles t WHERE key=ANY($1::text[])",
            &[&FLAGS.to_vec()],
        )
        .await?
        .get(0))
}

async fn restore_flags(c: &Client, saved: &str) -> Result<(), Err> {
    c.execute(
        "DELETE FROM feature_toggles WHERE key=ANY($1::text[])",
        &[&FLAGS.to_vec()],
    )
    .await?;
    c.execute(
        "INSERT INTO feature_toggles SELECT * FROM jsonb_populate_recordset(NULL::feature_toggles,$1::text::jsonb)",
        &[&saved],
    )
    .await?;
    Ok(())
}

async fn set_flags(c: &Client, rate: bool, recording: bool) -> Result<(), Err> {
    c.execute(
        "INSERT INTO feature_toggles(key,enabled) VALUES('feature.rate_limit',$1),('feature.conditional_access',false),('feature.device_trust_enforcement',false),('feature.token_binding',false),('feature.forgot_password',true) ON CONFLICT(key) DO UPDATE SET enabled=EXCLUDED.enabled",
        &[&rate],
    )
    .await?;
    if recording {
        // Frozen Go reloads feature_toggles from its LISTEN; let it settle.
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    Ok(())
}

async fn seed(c: &Client) -> Result<Fx, Err> {
    let a = fixture::account(c, "gofree349a").await?;
    c.execute(
        "UPDATE users SET password_hash=$1,mfa_exempt=true,totp_enabled=false,push_mfa_enabled=false,must_change_password=false WHERE id=$2",
        &[&bcrypt::hash(PASSWORD, 4)?, &a.user],
    )
    .await?;
    let email: String = c
        .query_one("SELECT email FROM users WHERE id=$1", &[&a.user])
        .await?
        .get(0);
    Ok(Fx { a, email })
}

async fn cleanup(c: &Client, fx: &Fx, ips: &[String]) -> Result<(), Err> {
    clear_state(c, ips, &fx.email).await?;
    c.execute(
        "DELETE FROM device_registry WHERE user_id=$1",
        &[&fx.a.user],
    )
    .await?;
    for table in ["auth_event_log", "login_events", "sessions", "oauth_tokens"] {
        c.execute(
            &format!("DELETE FROM {table} WHERE user_id=$1"),
            &[&fx.a.user],
        )
        .await?;
    }
    c.execute(
        "DELETE FROM auth_event_log WHERE email=ANY($1::text[])",
        &[&vec![fx.email.clone(), NOBODY.to_owned(), DECOY.to_owned()]],
    )
    .await?;
    c.execute(
        "DELETE FROM auth_lockouts WHERE lockout_key LIKE 'recovery_user:' || $1::bigint::text",
        &[&fx.a.user],
    )
    .await?;
    c.batch_execute(&format!(
        "BEGIN;SET LOCAL session_replication_role=replica;DELETE FROM admin_audit_log WHERE user_id={};COMMIT",
        fx.a.user
    ))
    .await?;
    fixture::remove(c, &fx.a).await?;
    Ok(())
}

async fn setup(c: &Client, setup: &Setup, ip: &str, fx: &Fx) -> Result<(), Err> {
    match setup {
        Setup::None => {}
        Setup::IpRule(action) => {
            c.execute(
                "INSERT INTO ip_rules(cidr,action,description) VALUES($1::text::inet,$2,$3)",
                &[&format!("{ip}/32"), action, &MARK],
            )
            .await?;
        }
        Setup::RateCounter(n) => {
            c.execute(
                "INSERT INTO rate_limit_counters(key,count,window_start) VALUES($1,$2,now()) ON CONFLICT(key) DO UPDATE SET count=EXCLUDED.count,window_start=now()",
                &[&format!("auth:http:{ip}"), n],
            )
            .await?;
        }
        Setup::LockoutArm => {
            c.execute("SELECT lockout_arm($1,5)", &[&format!("ip:{ip}")])
                .await?;
        }
        Setup::Totp => {
            c.execute(
                "UPDATE users SET totp_enabled=true WHERE id=$1",
                &[&fx.a.user],
            )
            .await?;
        }
        Setup::ForceChange => {
            c.execute(
                "UPDATE users SET must_change_password=true WHERE id=$1",
                &[&fx.a.user],
            )
            .await?;
        }
        Setup::Escalated => {
            for key in keys_for(&[ip.to_owned()], &[fx.email.clone()]) {
                c.execute("SELECT lockout_escalate($1)", &[&key]).await?;
            }
        }
        Setup::Feed => {
            c.execute(
                "INSERT INTO threat_feed_blocks(cidr,source) VALUES($1::text::inet,$2)",
                &[&format!("{ip}/32"), &MARK],
            )
            .await?;
        }
        Setup::SeedFailures(users) => {
            for user in users.iter() {
                c.execute(
                    "INSERT INTO auth_attempts(source_ip,target_username,protocol,outcome) VALUES($1::text::inet,$2,'http','failure')",
                    &[&ip, user],
                )
                .await?;
            }
        }
    }
    Ok(())
}

fn masks(replies: &[Reply], email: &str) -> Vec<(String, String)> {
    let mut out = vec![(fake_refresh(email), "<jwt-email-token>".to_owned())];
    for reply in replies {
        let Ok(Value::Object(doc)) = serde_json::from_str::<Value>(&reply.body) else {
            continue;
        };
        for key in [
            "access_token",
            "refresh_token",
            "mfa_token",
            "force_token",
            "captcha_token",
            "reset_token",
        ] {
            if let Some(v) = doc
                .get(key)
                .and_then(Value::as_str)
                .filter(|v| !v.is_empty())
            {
                out.push((v.to_owned(), format!("<{key}>")));
            }
        }
        if let Some(prompt) = doc.get("captcha_prompt").and_then(Value::as_str) {
            let operands = prompt
                .strip_prefix("What is ")
                .and_then(|p| p.strip_suffix('?'))
                .and_then(|p| p.split_once(" + "));
            if let Some((a, b)) = operands {
                let operand = |s: &str| s.parse::<u32>().is_ok_and(|n| (1..=20).contains(&n));
                if operand(a) && operand(b) {
                    out.push((prompt.to_owned(), "What is <a> + <b>?".to_owned()));
                }
            }
        }
    }
    out.push((email.to_owned(), "<actor>".to_owned()));
    out
}

fn apply(text: &str, masks: &[(String, String)]) -> String {
    masks.iter().fold(text.to_owned(), |t, (from, to)| {
        t.replace(from.as_str(), to)
    })
}

fn strip(doc: &mut Value, pointer: &str) {
    if let Some((parent, key)) = pointer.rsplit_once('/') {
        if let Some(Value::Object(map)) = doc.pointer_mut(parent) {
            map.remove(key);
        }
    }
}

fn step_doc(
    step: &Step,
    payload: &[u8],
    headers: &[(String, String)],
    reply: &Reply,
    masks: &[(String, String)],
) -> Result<Value, Err> {
    let shown: serde_json::Map<String, Value> = headers
        .iter()
        .map(|(k, v)| {
            let v = if k == "x-captcha-token" {
                "<captcha-token>".to_owned()
            } else {
                apply(v, masks)
            };
            (k.clone(), Value::String(v))
        })
        .collect();
    let body = if payload.len() > 4096 {
        format!("<{} bytes>", payload.len())
    } else {
        apply(&String::from_utf8_lossy(payload), masks)
    };
    let response_headers: Value = serde_json::from_str(&apply(&reply.headers.to_string(), masks))?;
    Ok(json!({
        "request": {
            "method": "POST",
            "path": step.path,
            "source": if step.source == Source::Proxy { "trusted-proxy" } else { "case" },
            "headers": shown,
            "body": body,
        },
        "response": {
            "status": reply.status,
            "headers": response_headers,
            "body": apply(&reply.body, masks),
        },
    }))
}

type Sent = Vec<(Vec<u8>, Vec<(String, String)>)>;

async fn drive(
    target: SocketAddr,
    ip: Ipv4Addr,
    plan: &Plan,
    email: &str,
    recording: bool,
) -> Result<(Vec<Reply>, Sent), Err> {
    let now = unix_now();
    let mut replies: Vec<Reply> = Vec::new();
    let mut sent = Vec::new();
    for step in &plan.steps {
        let from = if step.source == Source::Proxy {
            Ipv4Addr::LOCALHOST
        } else {
            ip
        };
        let payload = payload(step.payload, email, replies.last())?;
        let mint = Mint {
            go: recording,
            ip: ip.to_string(),
            route: step.path,
            username: payload_username(step.payload, email),
        };
        let headers = extra_headers(step.extra, now, &mint);
        let reply = send(target, from, step.path, payload.clone(), &headers).await?;
        sent.push((payload, headers));
        replies.push(reply);
    }
    Ok((replies, sent))
}

fn check_contract(
    name: &str,
    contract: &Contract,
    replies: &[Reply],
    effects: &Value,
) -> Result<(), Err> {
    for (i, ((status, reason), reply)) in contract.statuses.iter().zip(replies).enumerate() {
        let got = reply.headers.get("x-threat-reason").and_then(Value::as_str);
        if reply.status != *status || got != *reason || reply.body == OWNER {
            return Err(format!(
                "{name} step {i}: expected {status} {reason:?}, got {} {got:?}: {}",
                reply.status, reply.body
            )
            .into());
        }
    }
    let outcomes: Vec<&str> = effects["attempts"]
        .as_array()
        .ok_or("attempts missing")?
        .iter()
        .filter_map(|a| a["outcome"].as_str())
        .collect();
    if outcomes != contract.attempts {
        return Err(format!(
            "{name}: attempt rows {outcomes:?}, expected {:?}",
            contract.attempts
        )
        .into());
    }
    if let Some((header, min)) = contract.delay {
        let last = replies.last().ok_or("no reply")?;
        let got = last.headers.get("x-threat-delay").and_then(Value::as_str);
        if got != Some(header) || last.elapsed < min || last.elapsed > min + Duration::from_secs(5)
        {
            return Err(format!(
                "{name}: delay header {got:?} after {:?}, expected {header} slept",
                last.elapsed
            )
            .into());
        }
    }
    Ok(())
}

fn len(v: &Value) -> usize {
    v.as_array().map_or(0, Vec::len)
}

/// Rust half of an approved divergence (replay only).
fn native_check(name: &str, check: Check, effects: &Value) -> Result<(), Err> {
    let ok = match check {
        Check::None => true,
        Check::BeginKeepsLockout => len(&effects["lockouts"]) == 3,
        Check::RefreshKeysVerifiedOnly => {
            len(&effects["lockouts"]) == 0 && effects["attempts"][0]["username"] == ""
        }
        Check::FailedTokenCounted => len(&effects["rate"]) == 1 && effects["rate"][0]["count"] == 1,
    };
    if ok {
        Ok(())
    } else {
        Err(format!("{name}: divergence not observed in Rust effects {effects}").into())
    }
}

/// Go half of an approved divergence: the golden must show the Go behaviour.
fn go_check(name: &str, check: Check, effects: &Value) -> Result<(), Err> {
    let ok = match check {
        Check::None => true,
        Check::BeginKeepsLockout => len(&effects["lockouts"]) == 0,
        Check::RefreshKeysVerifiedOnly => len(&effects["lockouts"]) == 3,
        Check::FailedTokenCounted => len(&effects["rate"]) == 0,
    };
    if ok {
        Ok(())
    } else {
        Err(format!("{name}: the Go golden no longer shows the divergence evidence").into())
    }
}

#[allow(clippy::too_many_arguments)]
async fn exercise(
    db: &Db,
    c: &Client,
    fx: &Fx,
    name: &str,
    preset: Preset,
    ip: Ipv4Addr,
    ips: &[String],
    record: Option<String>,
) -> Result<(), Err> {
    let recording = record.is_some();
    let plan = plan(name)?;
    clear_state(c, ips, &fx.email).await?;
    set_flags(c, plan.rate, recording).await?;
    let since: String = c
        .query_one("SELECT clock_timestamp()::text", &[])
        .await?
        .get(0);
    setup(c, &plan.setup, &ip.to_string(), fx).await?;
    let server = match &record {
        Some(_) => None,
        None => Some(serve(native_server(db, rust_config(db, preset, None)?).await?).await?),
    };
    let target: SocketAddr = match (&record, &server) {
        (Some(url), _) => url
            .trim_start_matches("http://")
            .trim_end_matches('/')
            .parse()?,
        (None, Some(s)) => s.addr,
        (None, None) => return Err("no target".into()),
    };
    let driven = drive(target, ip, &plan, &fx.email, recording).await;
    if let Some(s) = server {
        s.close().await;
    }
    let (replies, sent) = driven?;
    let masks = masks(&replies, &fx.email);
    let keys = keys_for(ips, &[fx.email.clone(), NOBODY.to_owned()]);
    let rates: Vec<String> = ips.iter().map(|ip| format!("auth:http:{ip}")).collect();
    let raw: String = c
        .query_one(EFFECTS, &[&ips.to_vec(), &since, &keys, &rates, &fx.a.user])
        .await?
        .get(0);
    let effects: Value = serde_json::from_str(&apply(&raw, &masks))?;
    let contract = if recording {
        &plan.go
    } else {
        plan.native.as_ref().unwrap_or(&plan.go)
    };
    check_contract(name, contract, &replies, &effects)?;
    if !recording {
        native_check(name, plan.check, &effects)?;
    }
    let mut steps = Vec::new();
    for ((step, (payload, headers)), reply) in plan.steps.iter().zip(&sent).zip(&replies) {
        steps.push(step_doc(step, payload, headers, reply, &masks)?);
    }
    let last = plan.steps.last().ok_or("empty plan")?;
    let mut actual = json!({
        "format": 1,
        "go_source": "",
        "route": format!("POST {}", last.path),
        "case": name,
        "preset": preset.name(),
        "observation": {"steps": steps, "effects": effects},
    });
    let file = corpus().join("goldens").join(format!("{name}.json"));
    if recording {
        let source = std::env::var("GOFREE_GO_SOURCE")
            .map_err(|_| "GOFREE_GO_SOURCE (the checked-out HEAD) is required to record")?;
        if source.len() != 40 || !source.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("GOFREE_GO_SOURCE must be a 40-hex commit".into());
        }
        actual["go_source"] = json!(source);
        if !file.exists() {
            std::fs::create_dir_all(file.parent().ok_or("corpus path")?)?;
            golden::record(&file, &actual)?;
            println!("GOLDEN-RECORDED {name}");
            return Ok(());
        }
    }
    if !file.exists() {
        println!("GOLDEN-PENDING {name}: contract only");
        return Ok(());
    }
    let mut expected: Value = serde_json::from_str(&std::fs::read_to_string(&file)?)?;
    actual["go_source"] = expected["go_source"].clone();
    if recording {
        golden::compare(&expected, &actual)?;
        println!("GOLDEN-REPLAY {name}");
        return Ok(());
    }
    if plan.native.is_some() {
        let got: Vec<(u64, Option<String>)> = expected["observation"]["steps"]
            .as_array()
            .ok_or("golden steps")?
            .iter()
            .map(|s| {
                (
                    s["response"]["status"].as_u64().unwrap_or(0),
                    s["response"]["headers"]["x-threat-reason"]
                        .as_str()
                        .map(str::to_owned),
                )
            })
            .collect();
        let want: Vec<(u64, Option<String>)> = plan
            .go
            .statuses
            .iter()
            .map(|(s, r)| (u64::from(*s), r.map(str::to_owned)))
            .collect();
        if got != want {
            return Err(
                format!("{name}: Go evidence golden shows {got:?}, expected {want:?}").into(),
            );
        }
        println!("GOLDEN-EVIDENCE {name}");
        return Ok(());
    }
    go_check(name, plan.check, &expected["observation"]["effects"])?;
    for pointer in plan.strip {
        strip(&mut expected, pointer);
        strip(&mut actual, pointer);
    }
    golden::compare(&expected, &actual)?;
    println!("GOLDEN-REPLAY {name}");
    Ok(())
}

async fn run(name: &'static str) -> Result<(), Err> {
    let preset = Preset::of(name);
    let record = std::env::var("GOFREE_RECORD_UPSTREAM").ok();
    if record.is_some() {
        let wanted = std::env::var("GOFREE_RECORD_AUTH_PRESET").unwrap_or_else(|_| "off".into());
        if wanted != preset.name() {
            println!(
                "SKIP {name}: the recorder runs preset {wanted}, this case needs {}",
                preset.name()
            );
            return Ok(());
        }
    }
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("GOFREE349A") else {
        return Ok(());
    };
    let c = db.connect().await?;
    c.query_one(
        "SELECT pg_advisory_lock(hashtextextended('gofree-idlogin1-oracle',0))",
        &[],
    )
    .await?;
    common::signing_key(&c).await;
    let receipts = common::receipt_ids(&c).await;
    let saved = save_flags(&c).await?;
    let fx = seed(&c).await?;
    let idx = CASES
        .iter()
        .position(|n| *n == name)
        .ok_or("case missing from CASES")?;
    let ip = Ipv4Addr::new(127, 0, 0, 40 + idx as u8);
    let ips = vec![ip.to_string(), US_IP.to_owned()];
    let result = exercise(&db, &c, &fx, name, preset, ip, &ips, record).await;
    let cleaned = cleanup(&c, &fx, &ips).await;
    let restored = restore_flags(&c, &saved).await;
    common::restore_receipts(&c, &receipts).await;
    result.and(cleaned).and(restored)
}

macro_rules! recorded {
    ($($test:ident => $case:literal;)*) => {
        const CASES: &[&str] = &[$($case),*];
        $(
            #[tokio::test]
            async fn $test() {
                run($case).await.unwrap();
            }
        )*
    };
}

recorded! {
    go_off_login_unmounted_ip_block => "off-login-unmounted-ip-block";
    go_off_refresh_unmounted_ip_block => "off-refresh-unmounted-ip-block";
    go_off_login_ip_block => "off-login-ip-block";
    go_off_login_ip_allow => "off-login-ip-allow";
    go_off_login_rate_limited => "off-login-rate-limited";
    go_off_login_success => "off-login-success";
    go_off_login_failure => "off-login-failure";
    go_off_login_csrf => "off-login-csrf";
    go_off_login_mfa_pending => "off-login-mfa-pending";
    go_off_login_force_change => "off-login-force-change";
    go_off_login_lockout => "off-login-lockout";
    go_off_login_captcha_bogus => "off-login-captcha-bogus";
    go_off_refresh_jwt_email => "off-refresh-jwt-email";
    go_off_refresh_success => "off-refresh-success";
    go_off_reset_ip_block => "off-reset-ip-block";
    go_off_reset_invalid_token => "off-reset-invalid-token";
    go_off_reset_csrf => "off-reset-csrf";
    go_off_reset_oversize => "off-reset-oversize";
    go_off_begin_decoy => "off-begin-decoy";
    go_off_begin_ip_block => "off-begin-ip-block";
    go_off_begin_captcha_bogus => "off-begin-captcha-bogus";
    go_off_begin_captcha_derived => "off-begin-captcha-derived";
    go_off_begin_lockout_divergence => "off-begin-lockout-divergence";
    go_off_verify_invalid_code => "off-verify-invalid-code";
    go_threat_login_feed => "threat-login-feed";
    go_threat_login_trusted_xff => "threat-login-trusted-xff";
    go_threat_login_spoofed_xff => "threat-login-spoofed-xff";
    go_threat_login_spray => "threat-login-spray";
    go_threat_login_captcha_needed => "threat-login-captcha-needed";
    go_threat_login_captcha_solved => "threat-login-captcha-solved";
    go_threat_login_captcha_wrong => "threat-login-captcha-wrong";
    go_threat_login_captcha_expired => "threat-login-captcha-expired";
    go_threat_login_rate_limited => "threat-login-rate-limited";
    go_geo_login_trusted_xff => "geo-login-trusted-xff";
    go_geo_login_ip_block_first => "geo-login-ip-block-first";
    go_tarpit_login_threshold => "tarpit-login-threshold";
    go_tarpit_login_high_risk => "tarpit-login-high-risk";
}

// ---------------------------------------------------------------- native-only

struct Native {
    db: Db,
    c: Client,
    fx: Fx,
    saved: String,
    receipts: Vec<String>,
}

async fn native_open(
    case: &str,
    rate: bool,
    extra: &[(&str, bool)],
) -> Result<Option<Native>, Err> {
    let Some(db) = Db::for_case(case) else {
        return Ok(None);
    };
    let c = db.connect().await?;
    c.query_one(
        "SELECT pg_advisory_lock(hashtextextended('gofree-idlogin1-oracle',0))",
        &[],
    )
    .await?;
    common::signing_key(&c).await;
    let receipts = common::receipt_ids(&c).await;
    let saved = save_flags(&c).await?;
    set_flags(&c, rate, false).await?;
    for (key, on) in extra {
        c.execute(
            "UPDATE feature_toggles SET enabled=$2 WHERE key=$1",
            &[key, on],
        )
        .await?;
    }
    let fx = seed(&c).await?;
    Ok(Some(Native {
        db,
        c,
        fx,
        saved,
        receipts,
    }))
}

async fn native_close(n: Native, ips: &[String]) -> Result<(), Err> {
    let cleaned = cleanup(&n.c, &n.fx, ips).await;
    let restored = restore_flags(&n.c, &n.saved).await;
    common::restore_receipts(&n.c, &n.receipts).await;
    cleaned.and(restored)
}

fn ip(last: u8) -> Ipv4Addr {
    Ipv4Addr::new(127, 0, 0, last)
}

async fn lockout(c: &Client, key: &str) -> Result<Option<i32>, Err> {
    Ok(c.query_opt(
        "SELECT failed_count FROM auth_lockouts WHERE lockout_key=$1",
        &[&key],
    )
    .await?
    .map(|r| r.get(0)))
}

async fn outcomes(c: &Client, source: &str) -> Result<Vec<(String, String)>, Err> {
    Ok(c
        .query(
            "SELECT outcome, target_username FROM auth_attempts WHERE source_ip=$1::text::inet ORDER BY occurred_at, id",
            &[&source],
        )
        .await?
        .iter()
        .map(|r| (r.get(0), r.get(1)))
        .collect())
}

#[tokio::test]
async fn native_missing_gate_refuses_every_349a_route() {
    let _serial = SERIAL.lock().await;
    let Some(n) = native_open("GOFREE349A-missing-gate", true, &[])
        .await
        .unwrap()
    else {
        return;
    };
    let result = async {
        let cfg = rust_config(&n.db, Preset::Off, None)?;
        let exec =
            setjoin_pg::ScopedExecutor::from_dsn(n.db.app.as_deref().unwrap_or(&n.db.dsn), 4)
                .map_err(|e| e.0)?;
        let server = AuthServer::load(exec, cfg).await?;
        for path in [LOGIN, REFRESH, RESET, BEGIN, VERIFY] {
            let reply = server
                .handle(Request::post(path).header("host", HOST).body(body("{}"))?)
                .await;
            let status = reply.status().as_u16();
            let text = String::from_utf8(reply.into_body().collect().await?.to_bytes().to_vec())?;
            if status != 503 || !text.contains("threat admission unavailable") {
                return Err(format!("{path}: {status} {text}").into());
            }
        }
        Ok::<_, Err>(())
    }
    .await;
    let closed = native_close(n, &[]).await;
    result.and(closed).unwrap();
}

async fn preflight(
    case: &str,
    flags: &[(&str, bool)],
    header: Option<(&str, &str)>,
    dpop: bool,
) -> Result<(), Err> {
    let _serial = SERIAL.lock().await;
    let Some(n) = native_open(case, true, flags).await? else {
        return Ok(());
    };
    let ips = vec!["127.0.0.90".to_owned()];
    let result = async {
        clear_state(&n.c, &ips, &n.fx.email).await?;
        let spy = spy().await?;
        let cfg = rust_config(&n.db, Preset::Off, Some(format!("http://{}", spy.server.addr)))?;
        let server = native_server(&n.db, cfg).await?;
        let raw = if dpop {
            json!({"email": n.fx.email, "password": PASSWORD, "dpop_jwk": {"kty": "EC"}})
        } else {
            json!({"email": n.fx.email, "password": PASSWORD})
        }
        .to_string();
        let mut builder = Request::post(LOGIN).header("host", HOST).header("origin", ORIGIN);
        if let Some((k, v)) = header {
            builder = builder.header(k, v);
        }
        let mut req = builder.body(body(raw.clone()))?;
        req.extensions_mut().insert(setjoin_auth::ConnectionMeta {
            peer: "127.0.0.90:40000".parse()?,
            tls: false,
        });
        let status = server.handle(req).await.status().as_u16();
        let hits = spy.hits.lock().unwrap().clone();
        spy.server.close().await;
        if status != 418 || hits != vec![raw.into_bytes()] {
            return Err(format!("expected exactly one whole forward, got {status} and {} hits", hits.len()).into());
        }
        let rows: i64 = n
            .c
            .query_one(
                "SELECT (SELECT count(*) FROM auth_attempts WHERE source_ip='127.0.0.90'::inet)+(SELECT count(*) FROM rate_limit_counters WHERE key='auth:http:127.0.0.90')",
                &[],
            )
            .await?
            .get(0);
        if rows != 0 {
            return Err("a preflight forward ran admission first (double admission, F7)".into());
        }
        Ok::<_, Err>(())
    }
    .await;
    let closed = native_close(n, &ips).await;
    result.and(closed)
}

#[tokio::test]
async fn native_dpop_preflight_forwards_before_any_admission_effect() {
    preflight(
        "GOFREE349A-dpop",
        &[("feature.token_binding", true)],
        None,
        true,
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn native_ca_preflight_forwards_before_any_admission_effect() {
    preflight(
        "GOFREE349A-ca",
        &[("feature.conditional_access", true)],
        None,
        false,
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn native_device_proof_preflight_forwards_before_any_admission_effect() {
    preflight("GOFREE349A-device", &[], Some(("x-device-id", "7")), false)
        .await
        .unwrap();
}

/// F5: a toggle read error forwards whole before admission (no row, no count).
#[tokio::test]
async fn native_ca_toggle_read_error_forwards_before_admission() {
    let _serial = SERIAL.lock().await;
    let Some(n) = native_open("GOFREE349A-ca-fault", true, &[]).await.unwrap() else {
        return;
    };
    let ips = vec!["127.0.0.106".to_owned()];
    let result = async {
        clear_state(&n.c, &ips, &n.fx.email).await?;
        let app = n.db.app.clone().unwrap_or_else(|| n.db.dsn.clone());
        let (proxied, proxy) = cuttable(&app).await?;
        let spy = spy().await?;
        let cfg = rust_config(&n.db, Preset::Off, Some(format!("http://{}", spy.server.addr)))?;
        let server = serve(gated_server(cfg, &proxied, &n.db.dsn, &n.db.dsn).await?).await?;
        proxy.cut();
        let raw = json!({"email": n.fx.email, "password": PASSWORD}).to_string().into_bytes();
        let reply = send(server.addr, ip(106), LOGIN, raw, &origin()).await;
        let hits = spy.hits.lock().unwrap().len();
        server.close().await;
        spy.server.close().await;
        if reply?.status != 418 || hits != 1 {
            return Err(format!("expected one whole forward, {hits} hits").into());
        }
        let rows: i64 = n
            .c
            .query_one(
                "SELECT (SELECT count(*) FROM auth_attempts WHERE source_ip='127.0.0.106'::inet)+(SELECT count(*) FROM rate_limit_counters WHERE key='auth:http:127.0.0.106')",
                &[],
            )
            .await?
            .get(0);
        if rows != 0 {
            return Err("admission ran before the forward".into());
        }
        Ok::<_, Err>(())
    }
    .await;
    let closed = native_close(n, &ips).await;
    result.and(closed).unwrap();
}

/// F5: with a gate pool cut, admitted routes answer Go's 403 bytes for the
/// fail-closed reason, never run the handler, never forward and write no row.
async fn pool_fault(case: &str, cut_request: bool) -> Result<(), Err> {
    let _serial = SERIAL.lock().await;
    let Some(n) = native_open(case, true, &[]).await? else {
        return Ok(());
    };
    let ips = vec!["127.0.0.105".to_owned()];
    let result = async {
        clear_state(&n.c, &ips, &n.fx.email).await?;
        let (proxied, proxy) = cuttable(&n.db.dsn).await?;
        let (request, worker) = if cut_request {
            (proxied.as_str(), n.db.dsn.as_str())
        } else {
            (n.db.dsn.as_str(), proxied.as_str())
        };
        let spy = spy().await?;
        let cfg = rust_config(&n.db, Preset::Off, Some(format!("http://{}", spy.server.addr)))?;
        let server = serve(gated_server(cfg, n.db.app.as_deref().unwrap_or(&n.db.dsn), request, worker).await?).await?;
        proxy.cut();
        let want = if cut_request { "ip_rules_unavailable" } else { "lockout_unavailable" };
        let login = json!({"email": n.fx.email, "password": PASSWORD}).to_string().into_bytes();
        let verify = json!({"email": n.fx.email, "code": "000000"}).to_string().into_bytes();
        let mut replies = Vec::new();
        for (path, raw) in [(LOGIN, login), (VERIFY, verify)] {
            replies.push((path, send(server.addr, ip(105), path, raw, &origin()).await));
        }
        let hits = spy.hits.lock().unwrap().len();
        server.close().await;
        spy.server.close().await;
        for (path, reply) in replies {
            let reply = reply?;
            let reason = reply.headers.get("x-threat-reason").and_then(Value::as_str);
            let body = format!("{{\"captcha_prompt\":\"Access denied by security policy\",\"error\":\"{want}\"}}\n");
            if reply.status != 403 || reason != Some(want) || reply.body != body || reply.elapsed > Duration::from_secs(10) {
                return Err(format!("{path}: {} {reason:?} {:?} {}", reply.status, reply.elapsed, reply.body).into());
            }
        }
        if hits != 0 {
            return Err("a fail-closed refusal reached Go".into());
        }
        let rows: i64 = n
            .c
            .query_one(
                "SELECT (SELECT count(*) FROM auth_attempts WHERE source_ip='127.0.0.105'::inet)+(SELECT count(*) FROM auth_event_log WHERE email=$1)+(SELECT count(*) FROM sessions WHERE user_id=$2)",
                &[&n.fx.email, &n.fx.a.user],
            )
            .await?
            .get(0);
        if rows != 0 {
            return Err("the handler ran or a row was written".into());
        }
        Ok::<_, Err>(())
    }
    .await;
    let closed = native_close(n, &ips).await;
    result.and(closed)
}

#[tokio::test]
async fn native_request_pool_fault_fails_closed_end_to_end() {
    pool_fault("GOFREE349A-request-fault", true).await.unwrap();
}

#[tokio::test]
async fn native_worker_pool_fault_fails_closed_end_to_end() {
    pool_fault("GOFREE349A-worker-fault", false).await.unwrap();
}

/// F6: an MFA-enrolled account and an unknown email are indistinguishable
/// through admission on begin and verify, and begin keeps its 100 ms floor.
#[tokio::test]
async fn native_forgot_password_answers_match_for_enrolled_and_unknown_accounts() {
    let _serial = SERIAL.lock().await;
    let Some(n) = native_open("GOFREE349A-enum", false, &[]).await.unwrap() else {
        return;
    };
    let ips = vec!["127.0.0.107".to_owned(), "127.0.0.108".to_owned()];
    let result = async {
        clear_state(&n.c, &ips, &n.fx.email).await?;
        n.c.execute(
            "UPDATE users SET totp_secret_enc=pgp_sym_encrypt('JBSWY3DPEHPK3PXP',$2),totp_enabled=true WHERE id=$1",
            &[&n.fx.a.user, &ENC],
        )
        .await?;
        let mut cfg = rust_config(&n.db, Preset::Off, None)?;
        cfg.db_encryption_key = ENC.into();
        let server = serve(native_server(&n.db, cfg).await?).await?;
        let mut pairs = Vec::new();
        for path in [BEGIN, VERIFY] {
            let body = |email: &str| {
                if path == BEGIN {
                    json!({ "email": email })
                } else {
                    json!({"email": email, "code": "000000"})
                }
                .to_string()
                .into_bytes()
            };
            let known = send(server.addr, ip(107), path, body(&n.fx.email), &origin()).await;
            let unknown = send(server.addr, ip(108), path, body(NOBODY), &origin()).await;
            pairs.push((path, known, unknown));
        }
        server.close().await;
        for (path, known, unknown) in pairs {
            let (known, unknown) = (known?, unknown?);
            if known.status != unknown.status || known.body != unknown.body || known.headers != unknown.headers {
                return Err(format!("{path}: {} {} vs {} {}", known.status, known.body, unknown.status, unknown.body).into());
            }
            if known.elapsed < Duration::from_millis(100) || unknown.elapsed < Duration::from_millis(100) {
                return Err(format!("{path}: floor broken {:?} {:?}", known.elapsed, unknown.elapsed).into());
            }
        }
        let shape = |rows: Vec<(String, String)>| rows.into_iter().map(|(o, _)| o).collect::<Vec<_>>();
        let (k, u) = (outcomes(&n.c, "127.0.0.107").await?, outcomes(&n.c, "127.0.0.108").await?);
        if shape(k.clone()) != shape(u.clone()) || shape(k.clone()) != vec!["success".to_owned(), "failure".to_owned()] {
            return Err(format!("attempt rows differ: {k:?} vs {u:?}").into());
        }
        let mut lock_shapes = Vec::new();
        for (source, user) in [("127.0.0.107", n.fx.email.to_lowercase()), ("127.0.0.108", NOBODY.to_owned())] {
            let mut shape = Vec::new();
            for (label, key) in [
                ("ip", format!("ip:{source}")),
                ("user", format!("user:{user}")),
                ("ip_user", format!("ip_user:{source}:{user}")),
            ] {
                shape.push((label, lockout(&n.c, &key).await?));
            }
            lock_shapes.push(shape);
        }
        if lock_shapes[0] != lock_shapes[1] {
            return Err(format!("lockout rows differ: {lock_shapes:?}").into());
        }
        Ok::<_, Err>(())
    }
    .await;
    let closed = native_close(n, &ips).await;
    result.and(closed).unwrap();
}

/// F1: a body with trailing bytes is keyed exactly as the handler reads it.
#[tokio::test]
async fn native_trailing_bytes_login_failure_escalates_all_three_keys() {
    let _serial = SERIAL.lock().await;
    let Some(n) = native_open("GOFREE349A-trailing", true, &[]).await.unwrap() else {
        return;
    };
    let ips = vec!["127.0.0.100".to_owned()];
    let result = async {
        clear_state(&n.c, &ips, &n.fx.email).await?;
        let server =
            serve(native_server(&n.db, rust_config(&n.db, Preset::Off, None)?).await?).await?;
        let raw = format!(
            r#"{{"email":{},"password":"{WRONG}"}} x"#,
            serde_json::to_string(&n.fx.email)?
        );
        let reply = send(server.addr, ip(100), LOGIN, raw.into_bytes(), &origin()).await;
        server.close().await;
        if reply?.status != 401 {
            return Err("wrong password must answer 401".into());
        }
        let user = n.fx.email.to_lowercase();
        for key in [
            "ip:127.0.0.100".to_owned(),
            format!("user:{user}"),
            format!("ip_user:127.0.0.100:{user}"),
        ] {
            if lockout(&n.c, &key).await? != Some(1) {
                return Err(format!("{key} not escalated").into());
            }
        }
        Ok::<_, Err>(())
    }
    .await;
    let closed = native_close(n, &ips).await;
    result.and(closed).unwrap();
}

/// F1: trailing bytes cannot skip a locked user, and a body without a username
/// still answers to its armed `ip:` lock.
#[tokio::test]
async fn native_trailing_bytes_cannot_skip_a_locked_user_or_armed_ip() {
    let _serial = SERIAL.lock().await;
    let Some(n) = native_open("GOFREE349A-locked", true, &[]).await.unwrap() else {
        return;
    };
    let ips = vec!["127.0.0.101".to_owned(), "127.0.0.102".to_owned()];
    let result = async {
        clear_state(&n.c, &ips, &n.fx.email).await?;
        for key in [format!("user:{}", n.fx.email.to_lowercase()), "ip:127.0.0.102".to_owned()] {
            n.c.execute(
                "INSERT INTO auth_lockouts(lockout_key,failed_count,locked_until,escalation_level,updated_at) VALUES($1,5,now()+interval '3 seconds',1,now())",
                &[&key],
            )
            .await?;
        }
        let server = serve(native_server(&n.db, rust_config(&n.db, Preset::Off, None)?).await?).await?;
        let user_locked = format!(r#"{{"email":{},"password":"{PASSWORD}"}} x"#, serde_json::to_string(&n.fx.email)?);
        let a = send(server.addr, ip(101), LOGIN, user_locked.into_bytes(), &origin()).await;
        let b = send(server.addr, ip(102), LOGIN, br#"{"password":"x"} x"#.to_vec(), &origin()).await;
        server.close().await;
        for reply in [a?, b?] {
            if reply.status != 403 || reply.headers.get("x-threat-reason").and_then(Value::as_str) != Some("lockout") {
                return Err(format!("{} {}", reply.status, reply.body).into());
            }
        }
        Ok::<_, Err>(())
    }
    .await;
    let closed = native_close(n, &ips).await;
    result.and(closed).unwrap();
}

/// F1: three trailing-bytes failures against three users from one source trip spray.
#[tokio::test]
async fn native_trailing_bytes_failures_trip_spray() {
    let _serial = SERIAL.lock().await;
    let Some(n) = native_open("GOFREE349A-spray", true, &[]).await.unwrap() else {
        return;
    };
    let ips = vec!["127.0.0.103".to_owned()];
    let users = [
        "u1-349a@gofree349a.test",
        "u2-349a@gofree349a.test",
        "u3-349a@gofree349a.test",
    ];
    let result = async {
        clear_state(&n.c, &ips, &n.fx.email).await?;
        let mut cfg = rust_config(&n.db, Preset::Threat, None)?;
        cfg.threat.rate_limit_per_min = 100;
        cfg.threat.tarpit_threshold = 10;
        let server = serve(native_server(&n.db, cfg).await?).await?;
        let mut statuses = Vec::new();
        for user in users.iter().chain(users.first()) {
            let raw = format!(r#"{{"email":"{user}","password":"{WRONG}"}} x"#);
            let reply = send(server.addr, ip(103), LOGIN, raw.into_bytes(), &origin()).await;
            statuses.push(reply.map(|r| {
                (
                    r.status,
                    r.headers
                        .get("x-threat-reason")
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                )
            }));
        }
        server.close().await;
        let statuses: Vec<_> = statuses.into_iter().collect::<Result<_, _>>()?;
        let want = vec![
            (401, None),
            (401, None),
            (401, None),
            (403, Some("spray_detected".to_owned())),
        ];
        if statuses != want {
            return Err(format!("{statuses:?}").into());
        }
        Ok::<_, Err>(())
    }
    .await;
    let mut extra = Vec::new();
    for user in users {
        extra.push(format!("user:{user}"));
        extra.push(format!("ip_user:127.0.0.103:{user}"));
    }
    let _ =
        n.c.execute(
            "DELETE FROM auth_lockouts WHERE lockout_key=ANY($1::text[])",
            &[&extra],
        )
        .await;
    let closed = native_close(n, &ips).await;
    result.and(closed).unwrap();
}

/// F2: a signed-in user's valid refresh cannot clear another user's lockout.
#[tokio::test]
async fn native_refresh_clears_only_the_verified_identity() {
    let _serial = SERIAL.lock().await;
    let Some(n) = native_open("GOFREE349A-refresh-victim", true, &[])
        .await
        .unwrap()
    else {
        return;
    };
    let ips = vec!["127.0.0.104".to_owned()];
    let result = async {
        clear_state(&n.c, &ips, &n.fx.email).await?;
        n.c.execute("SELECT lockout_escalate($1)", &[&format!("user:{VICTIM}")])
            .await?;
        let server =
            serve(native_server(&n.db, rust_config(&n.db, Preset::Off, None)?).await?).await?;
        let login = send(
            server.addr,
            ip(104),
            LOGIN,
            json!({"email": n.fx.email, "password": PASSWORD})
                .to_string()
                .into_bytes(),
            &origin(),
        )
        .await;
        let refresh = match login {
            Ok(reply) => {
                let doc: Value = serde_json::from_str(&reply.body)?;
                let token = doc["refresh_token"]
                    .as_str()
                    .ok_or("login issued no refresh token")?
                    .to_owned();
                send(
                    server.addr,
                    ip(104),
                    REFRESH,
                    json!({"email": VICTIM, "refresh_token": token})
                        .to_string()
                        .into_bytes(),
                    &origin(),
                )
                .await
            }
            Err(e) => Err(e),
        };
        server.close().await;
        if refresh?.status != 200 {
            return Err("own refresh must succeed".into());
        }
        if lockout(&n.c, &format!("user:{VICTIM}")).await? != Some(1) {
            return Err("refresh cleared the victim's lockout key".into());
        }
        let rows = outcomes(&n.c, "127.0.0.104").await?;
        let actor = n.fx.email.clone();
        if rows
            != vec![
                ("success".to_owned(), actor.clone()),
                ("success".to_owned(), actor),
            ]
        {
            return Err(format!("refresh must key the verified identity: {rows:?}").into());
        }
        Ok::<_, Err>(())
    }
    .await;
    let closed = native_close(n, &ips).await;
    result.and(closed).unwrap();
}

/// F4/V2-1: a solved token admits once (default thresholds, the tarpit is skipped),
/// only from the IP, route and username it was issued for. A token bound elsewhere
/// is a failed token: it keeps the tarpit (429 once the address has 3 failures).
#[tokio::test]
async fn native_bound_captcha_token_admits_once_and_only_where_bound() {
    let _serial = SERIAL.lock().await;
    let Some(n) = native_open("GOFREE349A-bound", true, &[]).await.unwrap() else {
        return;
    };
    let ips = vec!["127.0.0.85".to_owned(), "127.0.0.86".to_owned()];
    let result = async {
        clear_state(&n.c, &ips, &n.fx.email).await?;
        setup(&n.c, &Setup::SeedFailures(&REPEAT3), "127.0.0.85", &n.fx).await?;
        let mut cfg = rust_config(&n.db, Preset::Threat, None)?;
        cfg.threat.rate_limit_per_min = 100;
        let server = serve(native_server(&n.db, cfg).await?).await?;
        let token = bound_captcha(
            CAPTCHA_FIXTURE.as_bytes(),
            "7",
            unix_now() + 120,
            "127.0.0.85",
            LOGIN,
            &n.fx.email,
        );
        let mut headers = origin();
        headers.push(("x-captcha-token".into(), token));
        headers.push(("x-captcha-answer".into(), "7".into()));
        let good = json!({"email": n.fx.email, "password": PASSWORD})
            .to_string()
            .into_bytes();
        let decoy = json!({"email": DECOY, "password": PASSWORD})
            .to_string()
            .into_bytes();
        let begin = json!({ "email": n.fx.email }).to_string().into_bytes();
        let mut statuses = Vec::new();
        for (from, path, raw) in [
            (86, LOGIN, good.clone()),
            (85, BEGIN, begin),
            (85, LOGIN, decoy),
            (85, LOGIN, good.clone()),
            (85, LOGIN, good),
        ] {
            statuses.push(
                send(server.addr, ip(from), path, raw, &headers)
                    .await
                    .map(|r| r.status),
            );
        }
        server.close().await;
        let statuses: Vec<u16> = statuses.into_iter().collect::<Result<_, _>>()?;
        // Wrong IP (a fresh address: 403 captcha), wrong route and wrong username
        // (failed tokens keep the tarpit: 429), the solve (200), the replay (403).
        if statuses != [403, 429, 429, 200, 403] {
            return Err(format!("wrong IP, route, username, solve, replay: {statuses:?}").into());
        }
        Ok::<_, Err>(())
    }
    .await;
    let closed = native_close(n, &ips).await;
    result.and(closed).unwrap();
}

/// V2-2: a verified token on a rate-limited request is not claimed; it still
/// works once, after the limit clears, and only once.
#[tokio::test]
async fn native_rate_limited_request_consumes_no_used_set_slot() {
    let _serial = SERIAL.lock().await;
    let Some(n) = native_open("GOFREE349A-slot", true, &[]).await.unwrap() else {
        return;
    };
    let ips = vec!["127.0.0.88".to_owned()];
    let result = async {
        clear_state(&n.c, &ips, &n.fx.email).await?;
        // The preset limit is 3 a minute: a counter at 3 rate limits the next request.
        setup(&n.c, &Setup::RateCounter(3), "127.0.0.88", &n.fx).await?;
        let server =
            serve(native_server(&n.db, rust_config(&n.db, Preset::Threat, None)?).await?).await?;
        let token = bound_captcha(
            CAPTCHA_FIXTURE.as_bytes(),
            "7",
            unix_now() + 120,
            "127.0.0.88",
            LOGIN,
            &n.fx.email,
        );
        let mut headers = origin();
        headers.push(("x-captcha-token".into(), token));
        headers.push(("x-captcha-answer".into(), "7".into()));
        let good = json!({"email": n.fx.email, "password": PASSWORD})
            .to_string()
            .into_bytes();
        let mut statuses = Vec::new();
        statuses.push(
            send(server.addr, ip(88), LOGIN, good.clone(), &headers)
                .await
                .map(|r| r.status),
        );
        n.c.execute(
            "DELETE FROM rate_limit_counters WHERE key='auth:http:127.0.0.88'",
            &[],
        )
        .await?;
        for _ in 0..2 {
            statuses.push(
                send(server.addr, ip(88), LOGIN, good.clone(), &headers)
                    .await
                    .map(|r| r.status),
            );
        }
        server.close().await;
        let statuses: Vec<u16> = statuses.into_iter().collect::<Result<_, _>>()?;
        if statuses != [429, 200, 403] {
            return Err(format!("rate limited, then solve, then replay: {statuses:?}").into());
        }
        Ok::<_, Err>(())
    }
    .await;
    let closed = native_close(n, &ips).await;
    result.and(closed).unwrap();
}

/// F4: failed token checks run the pipeline, so the rate limit counts them.
#[tokio::test]
async fn native_failed_captcha_checks_are_rate_limited() {
    let _serial = SERIAL.lock().await;
    let Some(n) = native_open("GOFREE349A-bogus-rate", true, &[])
        .await
        .unwrap()
    else {
        return;
    };
    let ips = vec!["127.0.0.87".to_owned()];
    let result = async {
        clear_state(&n.c, &ips, &n.fx.email).await?;
        let mut cfg = rust_config(&n.db, Preset::Threat, None)?;
        cfg.threat.tarpit_threshold = 10;
        let server = serve(native_server(&n.db, cfg).await?).await?;
        let mut headers = origin();
        headers.push(("x-captcha-token".into(), "bogus-token".into()));
        headers.push(("x-captcha-answer".into(), "1".into()));
        let raw = json!({"email": n.fx.email, "password": PASSWORD})
            .to_string()
            .into_bytes();
        let mut statuses = Vec::new();
        for _ in 0..4 {
            statuses.push(
                send(server.addr, ip(87), LOGIN, raw.clone(), &headers)
                    .await
                    .map(|r| r.status),
            );
        }
        server.close().await;
        let statuses: Vec<u16> = statuses.into_iter().collect::<Result<_, _>>()?;
        let rows: Vec<String> = outcomes(&n.c, "127.0.0.87")
            .await?
            .into_iter()
            .map(|(o, _)| o)
            .collect();
        if statuses != [403, 403, 403, 429]
            || rows
                != [
                    "captcha_needed",
                    "captcha_needed",
                    "captcha_needed",
                    "rate_limited",
                ]
        {
            return Err(format!("{statuses:?} {rows:?}").into());
        }
        Ok::<_, Err>(())
    }
    .await;
    let closed = native_close(n, &ips).await;
    result.and(closed).unwrap();
}

/// F8: an IPv4 proxy seen as an IPv4-mapped peer still matches TRUSTED_PROXY_IP.
#[tokio::test]
async fn native_mapped_peer_matches_the_trusted_proxy() {
    let _serial = SERIAL.lock().await;
    let Some(n) = native_open("GOFREE349A-mapped-peer", true, &[])
        .await
        .unwrap()
    else {
        return;
    };
    let ips = vec!["127.0.0.109".to_owned()];
    let result = async {
        clear_state(&n.c, &ips, &n.fx.email).await?;
        let mut cfg = rust_config(&n.db, Preset::Off, None)?;
        cfg.client_proxy = "127.0.0.1".into();
        let server = native_server(&n.db, cfg).await?;
        let mut req = Request::post(LOGIN)
            .header("host", HOST)
            .header("origin", ORIGIN)
            .header("x-forwarded-for", "127.0.0.109")
            .body(body("{}"))?;
        req.extensions_mut().insert(setjoin_auth::ConnectionMeta {
            peer: "[::ffff:127.0.0.1]:40000".parse()?,
            tls: false,
        });
        let _ = server.handle(req).await;
        let count: Option<i32> =
            n.c.query_opt(
                "SELECT count FROM rate_limit_counters WHERE key='auth:http:127.0.0.109'",
                &[],
            )
            .await?
            .map(|r| r.get(0));
        if count != Some(1) {
            return Err(format!(
                "forwarded client not honoured for a mapped proxy peer: {count:?}"
            )
            .into());
        }
        Ok::<_, Err>(())
    }
    .await;
    let closed = native_close(n, &ips).await;
    result.and(closed).unwrap();
}

#[tokio::test]
async fn native_mapped_and_plain_forwarded_sources_share_one_rate_key() {
    let _serial = SERIAL.lock().await;
    let Some(n) = native_open("GOFREE349A-mapped", true, &[]).await.unwrap() else {
        return;
    };
    let ips = vec!["127.0.0.91".to_owned()];
    let result = async {
        clear_state(&n.c, &ips, &n.fx.email).await?;
        let mut cfg = rust_config(&n.db, Preset::Off, None)?;
        cfg.client_proxy = "127.0.0.1".into();
        let server = serve(native_server(&n.db, cfg).await?).await?;
        let mut statuses = Vec::new();
        for forwarded in ["::ffff:127.0.0.91", "127.0.0.91"] {
            let mut headers = origin();
            headers.push(("x-forwarded-for".to_owned(), forwarded.to_owned()));
            statuses.push(send(server.addr, Ipv4Addr::LOCALHOST, LOGIN, b"{}".to_vec(), &headers).await.map(|r| r.status));
        }
        server.close().await;
        let statuses: Vec<u16> = statuses.into_iter().collect::<Result<_, _>>()?;
        if statuses[0] != statuses[1] {
            return Err(format!("{statuses:?}").into());
        }
        let row = n
            .c
            .query_one(
                "SELECT (SELECT count FROM rate_limit_counters WHERE key='auth:http:127.0.0.91'), (SELECT count(*) FROM rate_limit_counters WHERE key LIKE 'auth:http:%ffff%'), (SELECT count(*) FROM auth_lockouts WHERE lockout_key LIKE 'ip%:127.0.0.91%'), (SELECT count(*) FROM auth_attempts WHERE source_ip='127.0.0.91'::inet AND target_username='')",
                &[],
            )
            .await?;
        let (rate, mapped, locks, attempts): (Option<i32>, i64, i64, i64) = (row.get(0), row.get(1), row.get(2), row.get(3));
        // An empty username never escalates; it is still counted and checked.
        if rate != Some(2) || mapped != 0 || locks != 0 || attempts != 2 {
            return Err(format!("rate {rate:?} mapped {mapped} locks {locks} attempts {attempts}").into());
        }
        Ok::<_, Err>(())
    }
    .await;
    let closed = native_close(n, &ips).await;
    result.and(closed).unwrap();
}

#[tokio::test]
async fn native_case_folded_duplicate_email_escalates_the_last_value() {
    let _serial = SERIAL.lock().await;
    let Some(n) = native_open("GOFREE349A-fold", true, &[]).await.unwrap() else {
        return;
    };
    let ips = vec!["127.0.0.94".to_owned()];
    let result = async {
        clear_state(&n.c, &ips, &n.fx.email).await?;
        let server =
            serve(native_server(&n.db, rust_config(&n.db, Preset::Off, None)?).await?).await?;
        let raw = format!(
            r#"{{"email":"{DECOY}","EMAIL":{},"password":"{WRONG}"}}"#,
            serde_json::to_string(&n.fx.email)?
        );
        let reply = send(server.addr, ip(94), LOGIN, raw.into_bytes(), &origin()).await;
        server.close().await;
        if reply?.status != 401 {
            return Err("wrong password must answer 401".into());
        }
        let actor = lockout(&n.c, &format!("user:{}", n.fx.email.to_lowercase())).await?;
        let decoy = lockout(&n.c, &format!("user:{DECOY}")).await?;
        if actor != Some(1) || decoy.is_some() {
            return Err(format!("actor {actor:?} decoy {decoy:?}").into());
        }
        Ok::<_, Err>(())
    }
    .await;
    let closed = native_close(n, &ips).await;
    result.and(closed).unwrap();
}

#[tokio::test]
async fn native_concurrent_tarpit_sleeps_match_the_header() {
    let _serial = SERIAL.lock().await;
    let Some(n) = native_open("GOFREE349A-tarpit", true, &[]).await.unwrap() else {
        return;
    };
    let ips = vec!["127.0.0.92".to_owned()];
    let result = async {
        clear_state(&n.c, &ips, &n.fx.email).await?;
        setup(&n.c, &Setup::SeedFailures(&REPEAT2), "127.0.0.92", &n.fx).await?;
        let server =
            serve(native_server(&n.db, rust_config(&n.db, Preset::Tarpit, None)?).await?).await?;
        let raw = json!({"email": n.fx.email, "password": WRONG})
            .to_string()
            .into_bytes();
        let headers = origin();
        let (a, b) = tokio::join!(
            send(server.addr, ip(92), LOGIN, raw.clone(), &headers),
            send(server.addr, ip(92), LOGIN, raw.clone(), &headers)
        );
        server.close().await;
        for reply in [a?, b?] {
            let delay = reply.headers.get("x-threat-delay").and_then(Value::as_str);
            if reply.status != 429
                || delay != Some("1.5s")
                || reply.elapsed < Duration::from_millis(1500)
                || reply.elapsed > Duration::from_millis(6500)
            {
                return Err(format!("{} {delay:?} {:?}", reply.status, reply.elapsed).into());
            }
        }
        Ok::<_, Err>(())
    }
    .await;
    let closed = native_close(n, &ips).await;
    result.and(closed).unwrap();
}

#[tokio::test]
async fn native_slow_body_is_cut_at_the_go_read_timeout() {
    let _serial = SERIAL.lock().await;
    let Some(n) = native_open("GOFREE349A-slow", false, &[]).await.unwrap() else {
        return;
    };
    let result = async {
        let server = serve(native_server(&n.db, rust_config(&n.db, Preset::Off, None)?).await?).await?;
        let mut stream = tokio::net::TcpStream::connect(server.addr).await?;
        stream
            .write_all(b"POST /auth/forgot-password/begin HTTP/1.1\r\nHost: auth.gofree349a.test\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{\"email\":")
            .await?;
        let started = Instant::now();
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        while let Ok(Ok(read)) = tokio::time::timeout(Duration::from_secs(25), stream.read(&mut chunk)).await {
            if read == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..read]);
            if String::from_utf8_lossy(&buf).contains("\"error\":\"invalid_body\"}\n") {
                break;
            }
        }
        let elapsed = started.elapsed();
        server.close().await;
        let text = String::from_utf8_lossy(&buf).into_owned();
        if !text.starts_with("HTTP/1.1 400")
            || !text.contains("x-threat-reason: invalid_body")
            || elapsed < Duration::from_secs(14)
            || elapsed > Duration::from_secs(20)
        {
            return Err(format!("{elapsed:?}: {text}").into());
        }
        Ok::<_, Err>(())
    }
    .await;
    let closed = native_close(n, &[]).await;
    result.and(closed).unwrap();
}

#[tokio::test]
async fn native_concurrent_admission_counts_are_atomic() {
    let _serial = SERIAL.lock().await;
    let Some(n) = native_open("GOFREE349A-race", true, &[]).await.unwrap() else {
        return;
    };
    let ips = vec!["127.0.0.97".to_owned(), "127.0.0.98".to_owned()];
    let result = async {
        clear_state(&n.c, &ips, &n.fx.email).await?;
        let server = serve(native_server(&n.db, rust_config(&n.db, Preset::Off, None)?).await?).await?;
        let addr = server.addr;
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..10 {
            tasks.spawn(async move { send(addr, ip(97), LOGIN, b"{}".to_vec(), &origin()).await.map(|r| r.status) });
        }
        let wrong = json!({"email": n.fx.email, "password": WRONG}).to_string().into_bytes();
        for _ in 0..5 {
            let wrong = wrong.clone();
            tasks.spawn(async move { send(addr, ip(98), LOGIN, wrong, &origin()).await.map(|r| r.status) });
        }
        while let Some(joined) = tasks.join_next().await {
            joined??;
        }
        server.close().await;
        let row = n
            .c
            .query_one(
                "SELECT (SELECT count FROM rate_limit_counters WHERE key='auth:http:127.0.0.97'), (SELECT failed_count FROM auth_lockouts WHERE lockout_key=$1), (SELECT locked_until>now() FROM auth_lockouts WHERE lockout_key=$1)",
                &[&format!("user:{}", n.fx.email.to_lowercase())],
            )
            .await?;
        let (rate, failed, locked): (Option<i32>, Option<i32>, Option<bool>) = (row.get(0), row.get(1), row.get(2));
        if rate != Some(10) || failed != Some(5) || locked != Some(true) {
            return Err(format!("rate {rate:?} failed {failed:?} locked {locked:?}").into());
        }
        Ok::<_, Err>(())
    }
    .await;
    let closed = native_close(n, &ips).await;
    result.and(closed).unwrap();
}

#[test]
fn native_threat_config_derives_captcha_secret_like_go() {
    use setjoin_config_secret::CryptoProfile;
    let jwt = "s".repeat(32);
    let get = |name: &str, _: &str| match name {
        "GEO_BLOCK_ENABLED" => Some("false".to_owned()),
        "THREAT_GEO_BLOCK_ENABLED" => Some("true".to_owned()),
        _ => None,
    };
    let standard = Config::threat_from_lookup(&get, &jwt, CryptoProfile::Standard).unwrap();
    assert_eq!(
        standard.overrides.get("feature.geo_block"),
        Some(&false),
        "GEO_BLOCK_ENABLED is Go's name"
    );
    assert_eq!(
        standard.overrides.get("feature.captcha"),
        Some(&true),
        "unset = Go default on"
    );
    assert_eq!(standard.captcha_secret, derived_secret(&jwt));
    let smx = Config::threat_from_lookup(&get, &jwt, CryptoProfile::Smx).unwrap();
    assert_eq!(smx.captcha_secret, derived_secret(&jwt)[..16].to_vec());
    let set = |name: &str, _: &str| (name == "CAPTCHA_SECRET").then(|| "fixed".to_owned());
    let explicit = Config::threat_from_lookup(&set, &jwt, CryptoProfile::Standard).unwrap();
    assert_eq!(explicit.captcha_secret, b"fixed".to_vec());
    // F7: never a key derived from an empty (public) secret.
    let empty = Config::threat_from_lookup(&get, "", CryptoProfile::Standard).unwrap();
    assert!(empty.captcha_secret.is_empty());
    assert!(Config::for_secret(String::new())
        .threat
        .captcha_secret
        .is_empty());
}

#[test]
fn native_outcome_stamps_and_preflight_order_are_pinned() {
    let lib = include_str!("../src/lib.rs");
    let recovery = include_str!("../src/recovery.rs");
    let section = |text: &'static str, start: &str, end: &str| -> &'static str {
        let from = text.find(start).expect(start);
        let rest = &text[from..];
        &rest[..rest.find(end).expect(end)]
    };
    assert_eq!(
        lib.matches("Self::threat_no_outcome(").count(),
        1,
        "force-change, auth.go:841"
    );
    assert_eq!(
        lib.matches("Self::threat_challenge(").count(),
        3,
        "enrollment, push, TOTP: auth.go:884/924/947"
    );
    assert_eq!(
        lib.matches("Self::threat_user(").count(),
        1,
        "login success, auth.go:958"
    );
    assert_eq!(
        recovery.matches("Self::threat_unproven(").count(),
        1,
        "begin divergence"
    );
    assert!(
        !recovery.contains("totp_ingress"),
        "recovery is admitted by http_threat"
    );
    let login = section(lib, "async fn login_admitted(", "pub struct ConnectionMeta");
    assert_eq!(
        login.matches("self.forward(").count(),
        1,
        "only the unmounted dpop handoff"
    );
    assert!(
        login.contains("if !dpop_decided"),
        "the late dpop forward never follows admission"
    );
    for (text, start, end) in [
        (lib, "async fn reset_admitted(", "async fn refresh("),
        (
            lib,
            "async fn refresh_admitted(",
            "fn presented_access_token(",
        ),
        (
            recovery,
            "async fn recovery_begin_admitted(",
            "impl AuthServer",
        ),
        (recovery, "async fn recovery_verify_admitted(", "\n}\n"),
    ] {
        assert!(
            !section(text, start, end).contains("self.forward("),
            "{start}: no forward after admission (F7)"
        );
    }
}
